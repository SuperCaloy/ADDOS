import queue
import threading
import time
import logging
import os
from backend.config import (
    WORKER_QUEUE_MAXSIZE, WORKER_ITEM_TIMEOUT_S,
    EXTRACTION_TRIGGER_PKTS, EXTRACTION_TRIGGER_S,
    ML_ENABLED, RF_BATCH_ENABLED, RF_BATCH_WINDOW_MS,
    ADMISSION_CONTROL_ENABLED, WORKER_ADMISSION_DEPTH, HOTPATH_QUIET,
    IF_BATCH_ENABLED, IF_BATCH_WINDOW_MS,
    DEADLINE_ADMISSION_ENABLED, DEADLINE_ADMISSION_MARGIN_S,
    SVC_EMA_ALPHA, SVC_EMA_FALLBACK_MS,
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


_submit_lock = threading.Lock()
_submit_counters = {"submitted": 0, "requeued": 0}


def _inc_submit(key: str) -> None:
    with _submit_lock:
        _submit_counters[key] += 1


def get_submit_counters() -> dict:
    with _submit_lock:
        return dict(_submit_counters)


_batch_fallback_lock = threading.Lock()
_batch_fallback_counters = {"rf": 0, "if": 0}


def _inc_batch_fallback(key: str) -> None:
    with _batch_fallback_lock:
        _batch_fallback_counters[key] += 1


def get_batch_fallback_counters() -> dict:
    with _batch_fallback_lock:
        return dict(_batch_fallback_counters)


_admission_lock = threading.Lock()
_admission_counters = {"admission_dropped": 0, "admission_deadline_dropped": 0}


def _inc_admission(key: str) -> None:
    with _admission_lock:
        _admission_counters[key] += 1


def get_admission_counters() -> dict:
    with _admission_lock:
        return dict(_admission_counters)


# --- Service-time EMA (S7) ---
# Per-origin EMA over full-inference samples only; skip/cached/low-rate
# branches never update it, so it tracks real occupancy for deadline admission.
_svc_ema_lock = threading.Lock()
_svc_ema = {"full": None}


def _record_svc_ema(ms: float) -> None:
    with _svc_ema_lock:
        current = _svc_ema["full"]
        if current is None:
            _svc_ema["full"] = ms
        else:
            _svc_ema["full"] = SVC_EMA_ALPHA * ms + (1 - SVC_EMA_ALPHA) * current


def get_svc_ema_ms() -> float:
    with _svc_ema_lock:
        return _svc_ema["full"] if _svc_ema["full"] is not None \
            else SVC_EMA_FALLBACK_MS


# Worker pool size for drain math; set by start(), falls back to the
# default derivation when workers were never started (tests, dry import).
_num_workers = 0


def _effective_workers() -> int:
    return max(1, _num_workers if _num_workers > 0 else _default_num_workers())


def _is_exempt_ip(src_ip: str) -> bool:
    """Phase >= 2 IPs (Time Ban / Blackhole) bypass admission shedding so
    probation and ban-expiry keep receiving live evidence (RT-J)."""
    try:
        from backend.mitigation.state_machine import state_machine
        ip_state = state_machine._states.get(src_ip)
        return ip_state is not None and ip_state.phase >= 2
    except Exception:
        return False


_stage_lock = threading.Lock()
_stage_timers = {"service_ms_sum": 0.0, "service_n": 0}


def _record_service_time(ms: float) -> None:
    with _stage_lock:
        _stage_timers["service_ms_sum"] += ms
        _stage_timers["service_n"] += 1


def get_stage_timers() -> dict:
    with _stage_lock:
        return dict(_stage_timers)


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


def _emit_feedback(is_anomaly: bool, flow_stats: dict | None) -> None:
    """Dual TEA feedback emission.

    IF channel: per-flow, streak-only, never locks baselines.
    TEA channel: attached per-interval verdict, deduped by eval_seq so a
    cached verdict shared by N flows still counts as one interval.
    Never raises - feedback must not take down inference.
    """
    try:
        from backend.pipeline.entropy_analyzer import entropy_analyzer as _tea
        _tea.feedback_if(is_anomaly)
        fs = flow_stats or {}
        if "tea_eval_seq" in fs or "tea_attack_pattern" in fs or "tea_confidence" in fs:
            eval_seq = fs.get("tea_eval_seq")
            # P6: a malformed seq (bool, non-int, negative) could dedup-out
            # all later eval intervals; drop the TEA channel, keep IF feedback.
            seq_ok = (
                eval_seq is None
                or (not isinstance(eval_seq, bool)
                    and isinstance(eval_seq, int)
                    and eval_seq >= 0)
            )
            if seq_ok:
                _tea.feedback_tea(
                    bool(fs.get("tea_attack_pattern", False)),
                    str(fs.get("tea_confidence", "low")),
                    eval_seq=eval_seq,
                )
    except Exception:
        pass


def submit(src_ip: str, flow_stats: dict, switch_stats: dict) -> None:
    # priority=1 normal, priority=0 goes first. seq keeps FIFO order per priority.
    # Flagged IPs (under quarantine/sinkhole observation) jump the queue so
    # their live telemetry stays current instead of lagging behind new flows.
    _priority = 0 if flood_filter.is_flagged_any(src_ip) else 1
    if (ADMISSION_CONTROL_ENABLED and _priority == 1
            and not _is_exempt_ip(src_ip)):
        if DEADLINE_ADMISSION_ENABLED:
            # Deadline admission (R3b): refuse when the queue cannot drain
            # inside the freshness budget.
            drain_s = (_queue.qsize() * (get_svc_ema_ms() / 1000.0)
                       / _effective_workers())
            if drain_s > WORKER_ITEM_TIMEOUT_S - DEADLINE_ADMISSION_MARGIN_S:
                _inc_admission("admission_deadline_dropped")
                return
        elif _queue.qsize() > WORKER_ADMISSION_DEPTH:
            _inc_admission("admission_dropped")
            return
    try:
        _queue.put_nowait((_priority, _next_seq(), src_ip, flow_stats, switch_stats, time.monotonic(), 0))
        _inc_submit("submitted")
    except queue.Full:
        _inc_drop("queue_full")
        log.warning("Worker queue full, dropped submission for %s", src_ip)


def _requeue_priority(src_ip: str, flow_stats: dict, switch_stats: dict, retry_count: int) -> None:
    try:
        _queue.put_nowait((0, _next_seq(), src_ip, flow_stats, switch_stats, time.monotonic(), retry_count))
        _inc_submit("requeued")
    except queue.Full:
        _inc_drop("requeue_full")
        log.warning("Worker queue full, priority requeue dropped for %s", src_ip)


def _infer_if(if_vec):
    """IF scoring via the micro-batch tray when enabled; solo otherwise.

    Mirrors _infer_rf: any batch-path failure (future exception or wait
    timeout) degrades to a solo predict so worst-case behavior equals
    the non-batched pipeline.
    """
    if not IF_BATCH_ENABLED:
        return if_pipeline.run_if_inference(if_vec)
    from backend.pipeline import if_batcher
    if_batcher.ensure_started()
    fut = if_batcher.infer(if_vec)
    try:
        return fut.result(timeout=(IF_BATCH_WINDOW_MS / 1000.0) * 2 + 0.05)
    except Exception:
        _inc_batch_fallback("if")
        return if_pipeline.run_if_inference(if_vec)


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
        _inc_batch_fallback("rf")
        return rf_pipeline.run_rf_inference(rf_vec)


def _process_item(priority: int, seq: int, src_ip: str, flow_stats: dict,
                  switch_stats: dict, enqueued_at: float, retry_count: int) -> None:

    # ML OFF: skip all inference; on_result() handles the ML OFF path.
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
    # IF handles per-host anomaly on its own; only the flood_filter flag matters.
    is_flagged = flood_filter.is_flagged_any(src_ip)

    # Drop stale items before the young-flow/low-rate gates so backlog-drained
    # items don't record uncapped queue age as detection_ms; only flagged IPs
    # are timeout-blocked, unflagged hosts are dropped silently.
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

    # --- Skip young flows — pps unreliable until flow matures ---
    # Exemption: flood-prefilter-flagged IPs need immediate action
    flow_dur = float(flow_stats.get("flow_duration_sec", 0)) if flow_stats else 0.0
    if not is_flagged:
        if flow_dur < EXTRACTION_TRIGGER_S and pkt_count < EXTRACTION_TRIGGER_PKTS:
            tracker.invalidate_cache(src_ip)
            return

    # Dynamic low-rate gate using TEA baseline: skip flows far below the
    # learned normal baseline; falls back to a 0.05 pps floor when unlearned.
    if not is_flagged:
        try:
            from backend.pipeline.entropy_analyzer import entropy_analyzer
            _tea_mean = entropy_analyzer.mean_size_baseline()
            _dynamic_min = max(0.05, _tea_mean * 0.1) if _tea_mean > 0 else 0.05
        except Exception:
            _dynamic_min = 0.05
        if pps < _dynamic_min:
            # Too slow to be an attack — count as normal without IF scoring.
            # Feed the IF streak too, so quiet post-attack traffic doesn't
            # starve the unlock hysteresis.
            _emit_feedback(False, flow_stats)
            if _result_callback:
                try:
                    _result_callback(src_ip, 0.0, False, "Normal", 0.0,
                                     flow_stats=flow_stats, switch_stats=switch_stats,
                                     timed_out=False, enqueued_at=enqueued_at,
                                     origin="low_rate")
                except Exception:
                    log.exception("Worker error in low-rate callback for %s", src_ip)
            return

    # --- Update Flow Tracker ---
    tracker.update_flow(src_ip, flow_stats)

    # --- Check inference cache — reuse fresh result if available ---
    cached = tracker.get_cached(src_ip)
    _prior_class = None
    _prior_conf  = 0.0

    if cached:
        from backend.mitigation.state_machine import state_machine
        ip_state       = state_machine.get_state(src_ip)
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
            # Cached verdict re-served: feed both channels so streaks keep
            # moving during cache-heavy periods.
            _emit_feedback(bool(cached.is_anomaly), flow_stats)
            if _result_callback:
                # Wrapped so an uncaught exception here can never kill the
                # worker thread and silently shrink the live pool to zero.
                try:
                    _result_callback(
                        src_ip,
                        cached.if_score, cached.is_anomaly,
                        cached.attack_class, cached.confidence,
                        flow_stats=flow_stats, switch_stats=switch_stats,
                        timed_out=False, enqueued_at=enqueued_at,
                        origin="cached",
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
        if_score, is_anomaly = _infer_if(if_vec)
        _record_worker_latency((time.monotonic() - _inf_start) * 1000)

        # Threshold: use model contract value
        _effective_threshold = loader.if_threshold
        is_anomaly = (if_score >= _effective_threshold)

        # --- TEA dual feedback (IF streak + TEA verdict latch) ---
        _emit_feedback(is_anomaly, flow_stats)

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
        # HOTPATH_QUIET: the per-item [SCAN] line burns CPU under saturation;
        # quiet mode drops it from INFO so the hot path stays light.
        pps_display  = float(flow_stats.get("packet_count_per_second", 0.0)) if flow_stats else 0.0
        conf_display = f"{confidence*100:.1f}%" if is_anomaly else "—"

        if not HOTPATH_QUIET:
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
        if not HOTPATH_QUIET:
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
                    origin="full",
                )
            except Exception:
                log.exception("Worker error in result callback for %s", src_ip)

        # S7: full-inference service sample = feature extraction + IF (+RF
        # when anomalous) + telemetry + callback, i.e. true worker occupancy.
        # Single site: every full-path item passes here exactly once.
        _record_svc_ema((time.monotonic() - _inf_start) * 1000.0)

    except Exception:
        log.exception("Worker error processing %s", src_ip)


def _process_item_with_metrics(priority: int, seq: int, src_ip: str,
                               flow_stats: dict, switch_stats: dict,
                               enqueued_at: float, retry_count: int) -> None:
    """_process_item plus worker service-time accounting (dequeue to return)."""
    _t0 = time.monotonic()
    try:
        _process_item(priority, seq, src_ip, flow_stats, switch_stats,
                      enqueued_at, retry_count)
    finally:
        _record_service_time((time.monotonic() - _t0) * 1000.0)


def _worker_loop() -> None:
    while True:
        try:
            item = _queue.get(timeout=1.0)
            # Outer guard — any uncaught exception in _process_item (including
            # callbacks it fires) is caught, logged, and the thread keeps running.
            try:
                _process_item_with_metrics(*item)
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
    global _num_workers
    if num_workers is None:
        num_workers = _default_num_workers()
    _num_workers = num_workers
    for i in range(num_workers):
        t = threading.Thread(target=_worker_loop, name=f"pipeline-worker-{i}", daemon=True)
        t.start()