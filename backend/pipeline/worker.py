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

    if not src_ip or src_ip in ("0.0.0.0", ""):
        return

    # Server is whitelisted — never score it (reply traffic causes false positives)
    _WHITELIST = {"10.0.0.20"}
    if src_ip in _WHITELIST:
        return

    pkt_count = int(flow_stats.get("packet_count", 0)) if flow_stats else 0
    pps       = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0

    if pkt_count == 0:
        return

    # Check if flood prefilter already flagged this IP for any protocol
    is_flagged       = flood_filter.is_flagged_any(src_ip)
    switch_delta_pps = float(flow_stats.get("switch_delta_pps", 0.0)) if flow_stats else 0.0
    is_flood_switch  = switch_delta_pps >= 1.0

    # Skip very young flows to avoid inflated pps readings from new OVS entries
    # Exemption: already flagged IPs and flood mode need fast action
    flow_dur = float(flow_stats.get("flow_duration_sec", 0)) if flow_stats else 0.0
    if not is_flagged and not is_flood_switch:
        if flow_dur < EXTRACTION_TRIGGER_S and pkt_count < EXTRACTION_TRIGGER_PKTS:
            tracker.invalidate_cache(src_ip)
            return

    # Low rate non-flood traffic — count as normal, skip ML
    if not is_flood_switch and pps < 0.1 and not is_flagged:
        if _result_callback:
            _result_callback(src_ip, 0.0, False, "Normal", 0.0,
                             flow_stats=flow_stats, switch_stats=switch_stats,
                             timed_out=False)
        return

    # Queue timeout — too long waiting, fallback block
    if time.monotonic() - enqueued_at > WORKER_ITEM_TIMEOUT_S:
        log.warning("Worker timeout for %s — pushing fallback block", src_ip)
        if _result_callback:
            _result_callback(src_ip, None, None, None, None, timed_out=True)
        return

    # Check inference cache — skip re-running ML if result is still fresh
    cached = tracker.get_cached(src_ip)
    _prior_class = None
    _prior_conf  = 0.0

    if cached:
        from backend.mitigation.state_machine import state_machine
        ip_state     = state_machine._states.get(src_ip)
        already_banned = ip_state is not None and ip_state.phase >= 2

        # Lock result if IP is banned or was classified with high confidence
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

        # Low confidence or Uncertain — re-run but keep prior class as fallback
        tracker.invalidate_cache(src_ip)
        _prior_class = cached.attack_class
        _prior_conf  = cached.confidence

    try:
        # --- Run Isolation Forest ---
        if_vec               = if_pipeline.extract_if_features(flow_stats)
        if_score, is_anomaly = if_pipeline.run_if_inference(if_vec)

        _effective_threshold = (
            IF_SCORE_THRESHOLD_OVERRIDE
            if IF_SCORE_THRESHOLD_OVERRIDE is not None
            else loader.if_threshold
        )
        is_anomaly = (if_score >= _effective_threshold)

        # IF feedback to TEA — teach baseline what is confirmed normal vs attack
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

        _effective_threshold = (
            IF_SCORE_THRESHOLD_OVERRIDE
            if IF_SCORE_THRESHOLD_OVERRIDE is not None
            else loader.if_threshold
        )
        is_anomaly = (if_score >= _effective_threshold)

        # Prefilter-flagged IPs with score above noise floor → treat as anomaly
        if is_flagged and if_score >= 0.58:
            is_anomaly = True

        # Last resort: extreme switch flood + score above threshold → force anomaly
        if not is_anomaly and switch_delta_pps >= 1000.0 and if_score >= _effective_threshold:
            is_anomaly = True
            log.debug("Flood bypass: %s  sw_delta=%.1f  IF=%.4f", src_ip, switch_delta_pps, if_score)

        attack_class = "Uncertain"
        confidence   = 0.0

        # --- Run Random Forest only if IF confirmed anomaly ---
        if is_anomaly:
            rf_switch   = dict(switch_stats) if switch_stats else {}
            _flow_proto = int((flow_stats or {}).get("ip_proto", 0))

            # Per-flow ip_proto is more accurate than switch-level dominant proto
            if _flow_proto:
                rf_switch["ip_proto"] = _flow_proto

            rf_vec = rf_pipeline.extract_rf_features(rf_switch)
            attack_class, confidence = rf_pipeline.run_rf_inference(rf_vec)

            # If RF returns Uncertain but we had a confident prior result, restore it
            if attack_class == "Uncertain" and _prior_class not in (None, "Uncertain") and _prior_conf >= 0.70:
                attack_class = _prior_class
                confidence   = _prior_conf

        # --- Log scan result ---
        pps_display  = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
        sw_pps       = float(flow_stats.get("switch_delta_pps", 0.0)) if flow_stats else 0.0
        conf_display = f"{confidence*100:.1f}%" if is_anomaly else "—"

        log.info(
            "[SCAN] %-15s  pps=%7.1f  sw_delta=%7.1f  IF=%.4f(thr=%.4f)  "
            "anomaly=%-5s  RF=%-12s  conf=%s",
            src_ip, pps_display, sw_pps, if_score, _effective_threshold,
            str(is_anomaly), attack_class if is_anomaly else "—", conf_display
        )

        try:
            from backend.pipeline.decision_engine import push_scan_result
            push_scan_result(src_ip, pps_display, sw_pps,
                             if_score, _effective_threshold, is_anomaly,
                             attack_class, confidence)
        except Exception:
            pass

        if is_anomaly:
            tracker.set_cache(src_ip, if_score, is_anomaly, attack_class, confidence)
        else:
            tracker.invalidate_cache(src_ip)

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
            tracker.purge_expired_cache()
            flood_filter.purge_stale()


def start() -> None:
    t = threading.Thread(target=_worker_loop, name="pipeline-worker", daemon=True)
    t.start()
    log.info("Pipeline worker started (queue maxsize=%d)", WORKER_QUEUE_MAXSIZE)