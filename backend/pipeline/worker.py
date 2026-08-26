import queue
import threading
import time
import logging
import os
from backend.config import (
    WORKER_QUEUE_MAXSIZE, WORKER_ITEM_TIMEOUT_S,
    EXTRACTION_TRIGGER_PKTS, EXTRACTION_TRIGGER_S,
    ML_ENABLED, RF_BATCH_ENABLED, RF_BATCH_WINDOW_MS,
)
from backend.models import if_pipeline, rf_pipeline, loader
from backend.pipeline.flow_tracker import tracker
from backend.pipeline.flood_prefilter import flood_filter

log = logging.getLogger(__name__)

# Lazy import for expert events
def _push_expert_worker_event(payload: dict) -> None:
    try:
        from backend.api.events import push_expert_event as _push
        _push(payload)
    except Exception:
        pass

def _record_worker_latency(latency_ms: float) -> None:
    try:
        from backend.api.expert import _record_worker_latency as _record
        _record(latency_ms)
    except Exception:
        pass

_queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=WORKER_QUEUE_MAXSIZE)
_result_callback = None

_MAX_PRIORITY_RETRIES = 1
_seq_lock = threading.Lock()
_seq_counter = 0

_drop_lock = threading.Lock()
_drop_counters = {
    "queue_full": 0,
    "requeue_full": 0,
    "retries_exhausted": 0,
    "stale_dropped": 0,
}


def _inc_drop(key: str) -> None:
    with _drop_lock:
        _drop_counters[key] += 1


def get_drop_counters() -> dict:
    with _drop_lock:
        return dict(_drop_counters)


def get_queue_depth() -> int:
    return _queue.qsize()


def set_result_callback(fn) -> None:
    global _result_callback
    _result_callback = fn


def _next_seq() -> int:
    global _seq_counter
    with _seq_lock:
        _seq_counter += 1
        return _seq_counter


def submit(src_ip: str, flow_stats: dict, switch_stats: dict) -> None:
    # priority=1 normal, priority=0 goes first. seq keeps FIFO order per priority.
    # Flagged IPs (already under quarantine/sinkhole observation) jump the
    # queue — they were waiting FIFO behind ordinary background flows,
    # which is what made live telemetry lag 10-20s behind actual detection.
    _priority = 0 if flood_filter.is_flagged_any(src_ip) else 1
    try:
        _queue.put_nowait((_priority, _next_seq(), src_ip, flow_stats, switch_stats, time.monotonic(), 0))
    except queue.Full:
        _inc_drop("queue_full")
        log.warning("Worker queue full, dropped submission for %s", src_ip)


def _requeue_priority(src_ip: str, flow_stats: dict, switch_stats: dict, retry_count: int) -> None:
    try:
        _queue.put_nowait((0, _next_seq(), src_ip, flow_stats, switch_stats, time.monotonic(), retry_count))
    except queue.Full:
        _inc_drop("requeue_full")
        log.warning("Worker queue full, priority requeue dropped for %s", src_ip)


def _infer_rf(rf_vec):
    """RF decode via the micro-batch tray when enabled; solo otherwise.

    Any batch-path failure (future exception or wait timeout) degrades to a
    solo predict so worst-case behavior equals the non-batched pipeline.
    """
    if not RF_BATCH_ENABLED:
        return rf_pipeline.run_rf_inference(rf_vec)
    from backend.pipeline import rf_batcher
    rf_batcher.ensure_started()
    fut = rf_batcher.infer(rf_vec)
    try:
        return fut.result(timeout=(RF_BATCH_WINDOW_MS / 1000.0) * 2 + 0.05)
    except Exception:
        return rf_pipeline.run_rf_inference(rf_vec)


def _process_item(priority: int, seq: int, src_ip: str, flow_stats: dict,
                  switch_stats: dict, enqueued_at: float, retry_count: int) -> None:

    # --- Skip all inference when ML is OFF ---
    # decision_engine.on_result() already handles ML OFF path.
    # No point running IF+RF — result is discarded anyway.
    if not ML_ENABLED:
        return

    # --- Skip invalid/whitelisted IPs ---
    if not src_ip or src_ip in ("0.0.0.0", ""):
        return
    _WHITELIST = {"10.0.0.20", "10.0.0.21"}
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
            from backend.pipeline.entropy_analyzer import entropy_analyzer
            _tea_mean = entropy_analyzer._global_state.size_base.mean
            _dynamic_min = max(0.05, _tea_mean * 0.1) if _tea_mean > 0 else 0.05
        except Exception:
            _dynamic_min = 0.05
        if pps < _dynamic_min:
            # Too slow to be an attack — count as normal without IF scoring
            if _result_callback:
                try:
                    _result_callback(src_ip, 0.0, False, "Normal", 0.0,
                                     flow_stats=flow_stats, switch_stats=switch_stats,
                                     timed_out=False, enqueued_at=enqueued_at)
                except Exception:
                    log.exception("Worker error in low-rate callback for %s", src_ip)
            return

    # --- Drop stale queue items ---
    # Only timeout-block IPs already flagged by flood prefilter.
    # Innocent hosts (not flagged) are silently dropped — IF never confirmed them.
    if time.monotonic() - enqueued_at > WORKER_ITEM_TIMEOUT_S:
        if is_flagged:
            if retry_count < _MAX_PRIORITY_RETRIES:
                log.warning("Worker timeout for %s (flagged) — priority retry %d", src_ip, retry_count + 1)
                _requeue_priority(src_ip, flow_stats, switch_stats, retry_count + 1)
            else:
                _inc_drop("retries_exhausted")
                log.warning("Worker timeout for %s (flagged) — retries exhausted, fallback block", src_ip)
                if _result_callback:
                    try:
                        _result_callback(src_ip, None, None, None, None, timed_out=True)
                    except Exception:
                        log.exception("Worker error in timeout-fallback callback for %s", src_ip)
        else:
            _inc_drop("stale_dropped")
            log.debug("Worker timeout for %s (not flagged) — dropped silently", src_ip)
        return

    # --- Update Flow Tracker ---
    tracker.update_flow(src_ip, flow_stats)

    # --- Check inference cache — reuse fresh result if available ---
    cached = tracker.get_cached(src_ip)
    _prior_class = None
    _prior_conf  = 0.0

    if cached:
        from backend.mitigation.state_machine import state_machine
        ip_state       = state_machine._states.get(src_ip)
        already_banned = ip_state is not None and ip_state.phase >= 2

        # Re-check banned IPs every 10s — avoids permanent wrong-class lock
        _recheck_due = (
            already_banned and ip_state.time_in_phase_sec() % 10 < 1
        )

        # Lock: banned/high-confidence — skip unless recheck window hit
        is_locked = (
            not _recheck_due and (
                already_banned or
                (cached.confidence >= 0.70 and cached.attack_class != "Uncertain")
            )
        )
        if is_locked:
            if _result_callback:
                # Wrapped — an uncaught exception here previously killed the
                # entire worker thread permanently (e.g. bad downstream call
                # in decision_engine.on_result), silently shrinking the pool
                # down to zero live workers over time.
                try:
                    _result_callback(
                        src_ip,
                        cached.if_score, cached.is_anomaly,
                        cached.attack_class, cached.confidence,
                        flow_stats=flow_stats, switch_stats=switch_stats,
                        timed_out=False, enqueued_at=enqueued_at,
                    )
                except Exception:
                    log.exception("Worker error in cached-result callback for %s", src_ip)
            return

        # Uncertain or low confidence — invalidate and re-run, keep prior as fallback
        tracker.invalidate_cache(src_ip)
        _prior_class = cached.attack_class
        _prior_conf  = cached.confidence

    # --- Run inference (IF + optional RF) ---
    try:
        # --- Run Isolation Forest ---
        _inf_start = time.monotonic()
        if_vec = if_pipeline.extract_if_features(flow_stats)
        # None = near-zero duration flow — skip scoring, treat as normal
        if if_vec is None:
            return
        if_score, is_anomaly = if_pipeline.run_if_inference(if_vec)
        _record_worker_latency((time.monotonic() - _inf_start) * 1000)

        # Threshold: use model contract value
        _effective_threshold = loader.if_threshold
        is_anomaly = (if_score >= _effective_threshold)

        # --- TEA feedback ---
        try:
            from backend.pipeline.entropy_analyzer import entropy_analyzer as _tea
            _tea.feedback(is_anomaly)
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
            # Merge flow_stats into rf_switch — RF needs per-flow fields (pps, bps etc)
            rf_switch = {}
            if switch_stats:
                rf_switch.update(switch_stats)
            if flow_stats:
                rf_switch.update(flow_stats)
            _flow_proto = int((flow_stats or {}).get("ip_proto", 0))
            if _flow_proto:
                rf_switch["ip_proto"] = _flow_proto

            rf_vec = rf_pipeline.extract_rf_features(rf_switch)
            attack_class, confidence = _infer_rf(rf_vec)

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

        # --- Expert event: live IF/RF result ---
        _push_expert_worker_event({
            "inference": {
                "src_ip": src_ip,
                "if_score": round(if_score, 4),
                "is_anomaly": is_anomaly,
                "attack_class": attack_class if is_anomaly else "Normal",
                "confidence": round(confidence, 3),
                "threshold": round(_effective_threshold, 4),
            }
        })

        # --- Fire result callback ---
        if _result_callback:
            try:
                _result_callback(
                    src_ip, if_score, is_anomaly,
                    attack_class, confidence,
                    flow_stats=flow_stats, switch_stats=switch_stats,
                    timed_out=False, enqueued_at=enqueued_at,
                )
            except Exception:
                log.exception("Worker error in result callback for %s", src_ip)

    except Exception:
        log.exception("Worker error processing %s", src_ip)


def _worker_loop() -> None:
    while True:
        try:
            item = _queue.get(timeout=1.0)
            # Outer guard — any uncaught exception anywhere in _process_item
            # (including inside callbacks it fires) used to propagate here
            # and kill the thread permanently. Now it is always caught,
            # logged, and the thread keeps consuming the queue.
            try:
                _process_item(*item)
            except Exception:
                log.exception("Unhandled worker error, thread staying alive")
            _queue.task_done()
        except queue.Empty:
            # Periodic cleanup when queue is idle
            tracker.purge_expired_cache()
            flood_filter.purge_stale()


RYU_PINNED_THREADS = 2  # Ryu pinned to 1 core; assume 2 logical threads reserved


def _default_num_workers() -> int:
    # free_threads = total logical threads - Ryu's pinned core
    # num_workers  = free_threads - 2 (headroom for API + background threads)
    total_threads = os.cpu_count() or 4
    free_threads  = max(1, total_threads - RYU_PINNED_THREADS)
    return max(1, free_threads - 2)


def start(num_workers: int = None) -> None:
    if num_workers is None:
        num_workers = _default_num_workers()
    for i in range(num_workers):
        t = threading.Thread(target=_worker_loop, name=f"pipeline-worker-{i}", daemon=True)
        t.start()