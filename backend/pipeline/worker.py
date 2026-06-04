import queue
import threading
import time
import logging
from backend.config import (
    WORKER_QUEUE_MAXSIZE, WORKER_ITEM_TIMEOUT_S,
    EXTRACTION_TRIGGER_PKTS, EXTRACTION_TRIGGER_S,
    IF_SCORE_THRESHOLD_OVERRIDE,
)
from backend.models import if_pipeline, rf_pipeline, loader
from backend.pipeline.flow_tracker import tracker
from backend.pipeline.flood_prefilter import flood_filter

log = logging.getLogger(__name__)

_queue: queue.Queue = queue.Queue(maxsize=WORKER_QUEUE_MAXSIZE)
_result_callback = None


def set_result_callback(fn) -> None:
    global _result_callback
    _result_callback = fn


def submit(src_ip: str, flow_stats: dict, switch_stats: dict) -> None:
    try:
        _queue.put_nowait((src_ip, flow_stats, switch_stats, time.monotonic()))
    except queue.Full:
        pass


def _process_item(src_ip: str, flow_stats: dict,
                  switch_stats: dict, enqueued_at: float) -> None:

    # --- Skip invalid/whitelisted IPs ---
    if not src_ip or src_ip in ("0.0.0.0", ""):
        return
    _WHITELIST = {"10.0.0.20"}
    if src_ip in _WHITELIST:
        return

    # --- Skip empty flows ---
    pkt_count = int(flow_stats.get("packet_count", 0)) if flow_stats else 0
    pps       = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
    if pkt_count == 0:
        return

    # --- Flood prefilter check — was this IP flagged by burst/limit detection ---
    # is_flood_switch removed — it stamped switch-wide delta on every per-host flow
    # causing innocent hosts on the same switch to be submitted and timeout-blocked.
    # IF handles per-host anomaly correctly on its own. Only flood_filter flag matters.
    is_flagged = flood_filter.is_flagged_any(src_ip)

    # --- Skip young flows — pps unreliable until flow matures ---
    # Exemption: flood-prefilter-flagged IPs need immediate action
    flow_dur = float(flow_stats.get("flow_duration_sec", 0)) if flow_stats else 0.0
    if not is_flagged:
        if flow_dur < EXTRACTION_TRIGGER_S and pkt_count < EXTRACTION_TRIGGER_PKTS:
            tracker.invalidate_cache(src_ip)
            return

    # --- Dynamic low-rate gate using TEA baseline ---
    # Skip flows well below learned normal baseline — too slow to be an attack.
    # Falls back to pps < 0.05 floor when TEA has not learned yet.
    if not is_flagged:
        try:
            from backend.pipeline.entropy_analyzer import entropy_analyzer as _tea
            _dpid = int((switch_stats or {}).get("dpid", 0))
            # Get learned baseline pps mean from TEA — 0 if not learned yet
            _tea_pps_mean = 0.0
            if _dpid:
                with _tea._lock:
                    _sw_state = _tea._states.get(_dpid)
                    if _sw_state and _sw_state.pkt_base.is_learned:
                        _tea_pps_mean = _sw_state.pkt_base.mean
            # Dynamic threshold: 10% of learned baseline, floor at 0.05
            _dynamic_min = max(0.05, _tea_pps_mean * 0.1)
        except Exception:
            _dynamic_min = 0.05
        if pps < _dynamic_min:
            # Too slow to be an attack — count as normal without IF scoring
            if _result_callback:
                _result_callback(src_ip, 0.0, False, "Normal", 0.0,
                                 flow_stats=flow_stats, switch_stats=switch_stats,
                                 timed_out=False)
            return

    # --- Drop stale queue items ---
    # Only timeout-block IPs already flagged by flood prefilter.
    # Innocent hosts (not flagged) are silently dropped — IF never confirmed them.
    if time.monotonic() - enqueued_at > WORKER_ITEM_TIMEOUT_S:
        if is_flagged:
            log.warning("Worker timeout for %s (flagged) — pushing fallback block", src_ip)
            if _result_callback:
                _result_callback(src_ip, None, None, None, None, timed_out=True)
        else:
            log.debug("Worker timeout for %s (not flagged) — dropped silently", src_ip)
        return

    # --- Check inference cache — reuse fresh result if available ---
    cached = tracker.get_cached(src_ip)
    _prior_class = None
    _prior_conf  = 0.0

    if cached:
        from backend.mitigation.state_machine import state_machine
        ip_state       = state_machine._states.get(src_ip)
        already_banned = ip_state is not None and ip_state.phase >= 2

        # Lock: banned IP or high-confidence classification — no re-run needed
        is_locked = (
            already_banned or
            (cached.confidence >= 0.70 and cached.attack_class != "Uncertain")
        )
        if is_locked:
            if _result_callback:
                _result_callback(
                    src_ip,
                    cached.if_score, cached.is_anomaly,
                    cached.attack_class, cached.confidence,
                    flow_stats=flow_stats, switch_stats=switch_stats,
                    timed_out=False,
                )
            return

        # Uncertain or low confidence — invalidate and re-run, keep prior as fallback
        tracker.invalidate_cache(src_ip)
        _prior_class = cached.attack_class
        _prior_conf  = cached.confidence

    try:
        # --- Run Isolation Forest ---
        if_vec = if_pipeline.extract_if_features(flow_stats)
        # None = near-zero duration flow — skip scoring, treat as normal
        if if_vec is None:
            return
        if_score, is_anomaly = if_pipeline.run_if_inference(if_vec)

        # Threshold: use config override if set, else use model contract value
        _effective_threshold = (
            IF_SCORE_THRESHOLD_OVERRIDE
            if IF_SCORE_THRESHOLD_OVERRIDE is not None
            else loader.if_threshold
        )
        is_anomaly = (if_score >= _effective_threshold)

        # --- TEA feedback — teach entropy analyzer confirmed normal vs attack ---
        try:
            from backend.pipeline.entropy_analyzer import entropy_analyzer as _tea
            _dpid = int((switch_stats or {}).get("dpid", 0))
            if _dpid:
                if is_anomaly:
                    _tea.confirm_attack(_dpid)
                else:
                    _tea.confirm_normal(_dpid)
        except Exception:
            pass

        # --- Flood prefilter override — flagged IP + IF score above threshold ---
        # Flood prefilter already confirmed this IP sent a burst — trust IF score.
        if is_flagged and if_score >= _effective_threshold:
            is_anomaly = True

        # --- Run Random Forest only if IF confirmed anomaly ---
        attack_class = "Uncertain"
        confidence   = 0.0

        if is_anomaly:
            rf_switch   = dict(switch_stats) if switch_stats else {}
            _flow_proto = int((flow_stats or {}).get("ip_proto", 0))

            # Per-flow ip_proto is more reliable than switch-level proto
            if _flow_proto:
                rf_switch["ip_proto"] = _flow_proto

            rf_vec = rf_pipeline.extract_rf_features(rf_switch)
            attack_class, confidence = rf_pipeline.run_rf_inference(rf_vec)

            # Restore prior confident class if RF returns Uncertain
            if attack_class == "Uncertain" and _prior_class not in (None, "Uncertain") and _prior_conf >= 0.70:
                attack_class = _prior_class
                confidence   = _prior_conf

        # --- Log scan result ---
        pps_display  = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
        conf_display = f"{confidence*100:.1f}%" if is_anomaly else "—"

        log.info(
            "[SCAN] %-15s  pps=%7.1f  IF=%.4f(thr=%.4f)  "
            "anomaly=%-5s  RF=%-12s  conf=%s",
            src_ip, pps_display, if_score, _effective_threshold,
            str(is_anomaly), attack_class if is_anomaly else "—", conf_display
        )

        # --- Push result to decision engine ---
        try:
            from backend.pipeline.decision_engine import push_scan_result
            push_scan_result(src_ip, pps_display, 0.0,
                             if_score, _effective_threshold, is_anomaly,
                             attack_class, confidence)
        except Exception:
            pass

        # --- Update or clear inference cache ---
        if is_anomaly:
            tracker.set_cache(src_ip, if_score, is_anomaly, attack_class, confidence)
        else:
            tracker.invalidate_cache(src_ip)

        # --- Fire result callback ---
        if _result_callback:
            _result_callback(
                src_ip, if_score, is_anomaly,
                attack_class, confidence,
                flow_stats=flow_stats, switch_stats=switch_stats,
                timed_out=False,
            )

    except Exception:
        log.exception("Worker error processing %s", src_ip)


def _worker_loop() -> None:
    while True:
        try:
            item = _queue.get(timeout=1.0)
            _process_item(*item)
            _queue.task_done()
        except queue.Empty:
            # Periodic cleanup when queue is idle
            tracker.purge_expired_cache()
            flood_filter.purge_stale()


def start() -> None:
    t = threading.Thread(target=_worker_loop, name="pipeline-worker", daemon=True)
    t.start()
    log.info("Pipeline worker started (queue maxsize=%d)", WORKER_QUEUE_MAXSIZE)