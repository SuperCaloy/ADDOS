import datetime
import threading
import logging
from backend.database.db import execute, executemany, query
from backend.config import ML_ENABLED

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dedup cache
# ---------------------------------------------------------------------------
_dedup_lock  = threading.Lock()
_dedup_cache: dict[tuple, float] = {}
_DEDUP_TTL   = 10.0

import time as _time

def _is_duplicate(src_ip: str, if_score: float, action_taken: str,
                  phase: str | None = None) -> bool:
    # Include phase in key so every phase transition always creates a new log
    # entry even if IF score and action_taken are the same within the TTL window.
    key = (src_ip, round(if_score, 4), action_taken, phase or "")
    now = _time.monotonic()
    with _dedup_lock:
        expired = [k for k, t in _dedup_cache.items() if now - t > _DEDUP_TTL]
        for k in expired:
            del _dedup_cache[k]
        if key in _dedup_cache:
            return True
        _dedup_cache[key] = now
    return False


# ---------------------------------------------------------------------------
# Batch buffer for traffic_summary writes — flushed every 5 seconds
# ---------------------------------------------------------------------------
_summary_lock   = threading.Lock()
_summary_buffer = {"total": 0, "threats": 0, "true_neg": 0, "fp": 0,
                   "tp": 0, "tn": 0, "fn": 0,
                   "if_tp": 0, "if_fp": 0, "if_tn": 0, "if_fn": 0,
                   "rf_tp": 0, "rf_fp": 0, "rf_tn": 0, "rf_fn": 0,
                   "rf_tp_syn": 0, "rf_fp_syn": 0, "rf_tn_syn": 0, "rf_fn_syn": 0,
                   "rf_tp_icmp":0,"rf_fp_icmp":0,"rf_tn_icmp":0,"rf_fn_icmp":0,
                   "rf_tp_udp": 0, "rf_fp_udp": 0, "rf_tn_udp": 0, "rf_fn_udp": 0,
                   "rf_syn_as_icmp": 0, "rf_syn_as_udp": 0,
                   "rf_icmp_as_syn": 0, "rf_icmp_as_udp": 0,
                   "rf_udp_as_syn":  0, "rf_udp_as_icmp": 0,
                   "held": 0, "rescored": 0, "expired_unscored": 0}


# ---------------------------------------------------------------------------
# mitigation_events
# ---------------------------------------------------------------------------

def log_mitigation_event(event: dict) -> None:
    if _is_duplicate(
        event.get("src_ip", ""),
        event.get("if_score", 0.0),
        event.get("action_taken", ""),
        event.get("phase"),
    ):
        return
    try:
        execute("""
            INSERT INTO mitigation_events
                (timestamp, src_ip, predicted_class, attack_vector,
                 confidence, priority, action_taken, if_score, phase, is_manual,
                 event_type, reason, detection_ms, mitigation_ms, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["timestamp"],
            event["src_ip"],
            event["predicted_class"],
            event["attack_vector"],
            event["confidence"],
            event["priority"],
            event["action_taken"],
            event.get("if_score"),
            event.get("phase"),
            int(event.get("is_manual", 0)),
            event.get("event_type") or "transition",
            event.get("reason"),
            event.get("detection_ms"),
            event.get("mitigation_ms"),
            event.get("session_id"),
        ))
    except Exception:
        log.exception("Failed to write mitigation event for %s", event.get("src_ip"))


def log_manual_action(src_ip: str, action: str,
                      attack_vector: str = "—",
                      confidence: float = 0.0,
                      priority: str = "—",
                      if_score: float = None,
                      phase: str = None,
                      session_id: str = None) -> None:
    """Log a manual operator action (release/block).

    Preserves the real attack_vector, confidence, priority and if_score from
    the active IpState so the PDF report shows full details — only the
    action_taken column changes to 'Manual Release' or 'Manual Block'.
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute("""
            INSERT INTO mitigation_events
                (timestamp, src_ip, predicted_class, attack_vector,
                 confidence, priority, action_taken, if_score, phase, is_manual,
                 event_type, reason, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, src_ip, "DDoS", attack_vector,
            confidence, priority,
            action.replace("_", " ").title(),
            if_score, phase, 1,
            "manual", None, session_id,
        ))
    except Exception:
        log.exception("Failed to write manual action for %s", src_ip)


# ---------------------------------------------------------------------------
# detection_features
# ---------------------------------------------------------------------------

def log_detection_features(src_ip: str, if_score: float,
                            is_anomaly: bool, attack_class: str,
                            confidence: float,
                            flow_stats: dict,
                            switch_stats: dict) -> None:
    # --- ML OFF — skip DB write to avoid polluting dataset ---
    if not ML_ENABLED:
        return
    try:
        fs  = flow_stats  or {}
        ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        eps = 1e-9

        # --- Raw flow fields ---
        flow_duration_sec        = fs.get("flow_duration_sec", 0.0)
        flow_duration_nsec       = fs.get("flow_duration_nsec", 0.0)
        idle_timeout             = fs.get("idle_timeout", 0)
        hard_timeout             = fs.get("hard_timeout", 0)
        flags                    = fs.get("flags", 0)
        packet_count             = fs.get("packet_count", 0)
        byte_count               = fs.get("byte_count", 0)
        packet_count_per_second  = fs.get("packet_count_per_second", 0.0)
        packet_count_per_nsecond = fs.get("packet_count_per_nsecond", 0.0)
        byte_count_per_second    = fs.get("byte_count_per_second", 0.0)
        byte_count_per_nsecond   = fs.get("byte_count_per_nsecond", 0.0)
        flow_duration_total_ns   = fs.get("flow_duration_total_ns",
            flow_duration_sec * 1e9 + flow_duration_nsec)
        flow_count_per_src       = fs.get("flow_count_per_src", 0.0)
        tp_src                   = fs.get("tp_src", 0)
        tp_dst                   = fs.get("tp_dst", 0)
        ip_proto                 = fs.get("ip_proto", 0)

        # --- Engineered features (raw, pre-log — match IF/RF formulas) ---
        bytes_per_packet      = byte_count / max(packet_count, 1)
        pkt_byte_rate_ratio   = packet_count_per_second / (byte_count_per_second + eps)
        flow_intensity        = packet_count * byte_count_per_second
        port_entropy          = tp_src / (tp_dst + 1)
        bytes_per_duration    = byte_count / (flow_duration_sec + eps)
        pkt_size_uniformity   = bytes_per_packet / (byte_count_per_second + 1)
        flow_src_intensity    = flow_count_per_src * packet_count_per_second
        duration_pkt_ratio    = flow_duration_total_ns / (packet_count + eps)
        pkt_rate_per_duration = packet_count / (flow_duration_total_ns + eps)

        flag_syn_flood  = 1 if attack_class == "SYN Flood"  else 0
        flag_icmp_flood = 1 if attack_class == "ICMP Flood" else 0
        flag_udp_flood  = 1 if attack_class == "UDP Flood"  else 0
        flag_normal     = 1 if not is_anomaly               else 0

        _buffer_feature_row((
            ts, src_ip, round(if_score, 6), int(is_anomaly),
            attack_class, round(confidence, 6),
            flow_duration_sec, flow_duration_nsec, idle_timeout, hard_timeout,
            flags, packet_count, byte_count,
            packet_count_per_second, packet_count_per_nsecond,
            byte_count_per_second, byte_count_per_nsecond,
            flow_duration_total_ns, bytes_per_packet, pkt_byte_rate_ratio,
            flow_count_per_src, tp_src, tp_dst, ip_proto,
            flow_intensity, port_entropy, bytes_per_duration,
            pkt_size_uniformity, flow_src_intensity,
            duration_pkt_ratio, pkt_rate_per_duration,
            flag_syn_flood, flag_icmp_flood, flag_udp_flood, flag_normal,
        ))
    except Exception:
        log.exception("Failed to write detection_features for %s", src_ip)


# ---------------------------------------------------------------------------
# detection_features batcher
# Rows buffer in arrival order and flush every cycle. Timestamps are taken at
# enqueue time (above) so stored order matches completion order.
# ---------------------------------------------------------------------------

_FEATURES_INSERT_SQL = """
    INSERT INTO detection_features (
        timestamp, src_ip, if_score, is_anomaly, attack_class, confidence,
        flow_duration_sec, flow_duration_nsec, idle_timeout, hard_timeout,
        flags, packet_count, byte_count,
        packet_count_per_second, packet_count_per_nsecond,
        byte_count_per_second,  byte_count_per_nsecond,
        flow_duration_total_ns, bytes_per_packet, pkt_byte_rate_ratio,
        flow_count_per_src, tp_src, tp_dst, ip_proto,
        flow_intensity, port_entropy, bytes_per_duration,
        pkt_size_uniformity, flow_src_intensity,
        duration_pkt_ratio, pkt_rate_per_duration,
        flag_syn_flood, flag_icmp_flood, flag_udp_flood, flag_normal
    ) VALUES (
        ?,?,?,?,?,?,
        ?,?,?,?,
        ?,?,?,
        ?,?,
        ?,?,
        ?,?,?,
        ?,?,?,?,
        ?,?,?,
        ?,?,
        ?,?,
        ?,?,?,?
    )
"""
_FEATURES_FLUSH_INTERVAL_S = 5.0
_FEATURES_BUF_CAP_DEFAULT = 2000
_FEATURES_BATCH_CHUNK = 200

_features_lock = threading.Lock()
_features_buf: list[tuple] = []
_FEATURES_BUF_CAP = _FEATURES_BUF_CAP_DEFAULT
_features_overflow_count = 0


def _buffer_feature_row(row: tuple) -> None:
    global _features_overflow_count
    with _features_lock:
        if len(_features_buf) >= _FEATURES_BUF_CAP:
            _features_buf.pop(0)
            _features_overflow_count += 1
        _features_buf.append(row)


def features_overflow_count() -> int:
    with _features_lock:
        return _features_overflow_count


def flush_detection_features() -> int:
    """Drain the feature buffer into the DB in FIFO chunks.

    A chunk-level failure falls back to per-row inserts so one bad row
    cannot lose its siblings (mirrors the old per-row swallow semantics).
    """
    flushed = 0
    while True:
        with _features_lock:
            chunk = _features_buf[:_FEATURES_BATCH_CHUNK]
            del _features_buf[:len(chunk)]
        if not chunk:
            break
        try:
            executemany(_FEATURES_INSERT_SQL, chunk)
            flushed += len(chunk)
        except Exception:
            log.exception("Feature batch insert failed; falling back to per-row")
            for row in chunk:
                try:
                    execute(_FEATURES_INSERT_SQL, row)
                    flushed += 1
                except Exception:
                    log.exception("Failed to write detection_features row for %s",
                                  row[1] if len(row) > 1 else "?")
    return flushed


# ---------------------------------------------------------------------------
# quarantine_state
# ---------------------------------------------------------------------------

def save_quarantine_state(src_ip: str, phase: int, attack_vector: str,
                          if_score: float, confidence: float,
                          action_taken: str, permanent: bool,
                          block_expires_at: str | None = None) -> None:
    """Persist quarantine state.

    H5 fix: block_expires_at (ISO timestamp string) stores TTL expiry for
    auto-blocks so it survives backend restarts.  NULL = manual permanent block.
    """
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute("""
            INSERT INTO quarantine_state
                (src_ip, phase, attack_vector, if_score, confidence,
                 action_taken, permanent, updated_at, block_expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(src_ip) DO UPDATE SET
                phase            = excluded.phase,
                attack_vector    = excluded.attack_vector,
                if_score         = excluded.if_score,
                confidence       = excluded.confidence,
                action_taken     = excluded.action_taken,
                permanent        = excluded.permanent,
                updated_at       = excluded.updated_at,
                block_expires_at = excluded.block_expires_at
        """, (src_ip, phase, attack_vector, round(if_score, 6),
              round(confidence, 6), action_taken, int(permanent), ts,
              block_expires_at))
    except Exception:
        log.exception("Failed to save quarantine state for %s", src_ip)


def delete_quarantine_state(src_ip: str) -> None:
    try:
        execute("DELETE FROM quarantine_state WHERE src_ip = ?", (src_ip,))
    except Exception:
        log.exception("Failed to delete quarantine state for %s", src_ip)


def load_quarantine_states() -> list[dict]:
    """Returns all persisted quarantine entries on startup."""
    try:
        from backend.database.db import query
        rows = query("""
            SELECT src_ip, phase, attack_vector, if_score, confidence,
                   action_taken, permanent, block_expires_at
            FROM quarantine_state
        """)
        return [dict(r) for r in rows] if rows else []
    except Exception:
        log.exception("Failed to load quarantine states")
        return []


# ---------------------------------------------------------------------------
# traffic_summary
# ---------------------------------------------------------------------------

def log_traffic_summary(total: int, threats: int,
                        true_neg: int, fp: int,
                        tp: int = 0, tn: int = 0, fn: int = 0,
                        if_tp: int = 0, if_fp: int = 0, if_tn: int = 0, if_fn: int = 0,
                        rf_tp: int = 0, rf_fp: int = 0, rf_tn: int = 0, rf_fn: int = 0,
                        rf_tp_syn: int = 0, rf_fp_syn: int = 0, rf_tn_syn: int = 0, rf_fn_syn: int = 0,
                        rf_tp_icmp: int = 0, rf_fp_icmp: int = 0, rf_tn_icmp: int = 0, rf_fn_icmp: int = 0,
                        rf_tp_udp: int = 0, rf_fp_udp: int = 0, rf_tn_udp: int = 0, rf_fn_udp: int = 0,
                        rf_syn_as_icmp: int = 0, rf_syn_as_udp: int = 0,
                        rf_icmp_as_syn: int = 0, rf_icmp_as_udp: int = 0,
                        rf_udp_as_syn:  int = 0, rf_udp_as_icmp: int = 0,
                        held: int = 0, rescored: int = 0,
                        expired_unscored: int = 0) -> None:
    # --- ML OFF — skip metric writes to keep dataset clean ---
    if not ML_ENABLED:
        return
    with _summary_lock:
        _summary_buffer["total"]    += total
        _summary_buffer["threats"]  += threats
        _summary_buffer["true_neg"] += true_neg
        _summary_buffer["fp"]       += fp
        _summary_buffer["tp"]       += tp
        _summary_buffer["tn"]       += tn
        _summary_buffer["fn"]       += fn
        _summary_buffer["if_tp"]    += if_tp
        _summary_buffer["if_fp"]    += if_fp
        _summary_buffer["if_tn"]    += if_tn
        _summary_buffer["if_fn"]    += if_fn
        _summary_buffer["rf_tp"]    += rf_tp
        _summary_buffer["rf_fp"]    += rf_fp
        _summary_buffer["rf_tn"]    += rf_tn
        _summary_buffer["rf_fn"]    += rf_fn
        _summary_buffer["rf_tp_syn"]  += rf_tp_syn
        _summary_buffer["rf_fp_syn"]  += rf_fp_syn
        _summary_buffer["rf_tn_syn"]  += rf_tn_syn
        _summary_buffer["rf_fn_syn"]  += rf_fn_syn
        _summary_buffer["rf_tp_icmp"] += rf_tp_icmp
        _summary_buffer["rf_fp_icmp"] += rf_fp_icmp
        _summary_buffer["rf_tn_icmp"] += rf_tn_icmp
        _summary_buffer["rf_fn_icmp"] += rf_fn_icmp
        _summary_buffer["rf_tp_udp"]  += rf_tp_udp
        _summary_buffer["rf_fp_udp"]  += rf_fp_udp
        _summary_buffer["rf_tn_udp"]  += rf_tn_udp
        _summary_buffer["rf_fn_udp"]  += rf_fn_udp
        _summary_buffer["rf_syn_as_icmp"] += rf_syn_as_icmp
        _summary_buffer["rf_syn_as_udp"]  += rf_syn_as_udp
        _summary_buffer["rf_icmp_as_syn"] += rf_icmp_as_syn
        _summary_buffer["rf_icmp_as_udp"] += rf_icmp_as_udp
        _summary_buffer["rf_udp_as_syn"]  += rf_udp_as_syn
        _summary_buffer["rf_udp_as_icmp"] += rf_udp_as_icmp
        _summary_buffer["held"]             += held
        _summary_buffer["rescored"]         += rescored
        _summary_buffer["expired_unscored"] += expired_unscored


def flush_summary() -> None:
    with _summary_lock:
        if not any(_summary_buffer.values()):
            return
        snapshot = _summary_buffer.copy()
        for k in _summary_buffer:
            _summary_buffer[k] = 0

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute("""
            INSERT INTO traffic_summary
                (timestamp, total_flows_observed, threats_mitigated,
                 true_negatives_passed, false_positives,
                 tp, tn, fn,
                 if_tp, if_fp, if_tn, if_fn,
                 rf_tp, rf_fp, rf_tn, rf_fn,
                 rf_tp_syn, rf_fp_syn, rf_tn_syn, rf_fn_syn,
                 rf_tp_icmp, rf_fp_icmp, rf_tn_icmp, rf_fn_icmp,
                 rf_tp_udp, rf_fp_udp, rf_tn_udp, rf_fn_udp,
                 rf_syn_as_icmp, rf_syn_as_udp,
                 rf_icmp_as_syn, rf_icmp_as_udp,
                 rf_udp_as_syn,  rf_udp_as_icmp,
                 held, rescored, expired_unscored)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, snapshot["total"], snapshot["threats"],
              snapshot["true_neg"], snapshot["fp"],
              snapshot["tp"], snapshot["tn"], snapshot["fn"],
              snapshot["if_tp"], snapshot["if_fp"], snapshot["if_tn"], snapshot["if_fn"],
              snapshot["rf_tp"], snapshot["rf_fp"], snapshot["rf_tn"], snapshot["rf_fn"],
              snapshot["rf_tp_syn"], snapshot["rf_fp_syn"], snapshot["rf_tn_syn"], snapshot["rf_fn_syn"],
              snapshot["rf_tp_icmp"], snapshot["rf_fp_icmp"], snapshot["rf_tn_icmp"], snapshot["rf_fn_icmp"],
              snapshot["rf_tp_udp"], snapshot["rf_fp_udp"], snapshot["rf_tn_udp"], snapshot["rf_fn_udp"],
              snapshot["rf_syn_as_icmp"], snapshot["rf_syn_as_udp"],
              snapshot["rf_icmp_as_syn"], snapshot["rf_icmp_as_udp"],
              snapshot["rf_udp_as_syn"],  snapshot["rf_udp_as_icmp"],
              snapshot["held"], snapshot["rescored"], snapshot["expired_unscored"]))
    except Exception:
        log.exception("Failed to flush traffic_summary")


def start_flush_thread() -> None:
    import time

    def _loop():
        while True:
            time.sleep(_FEATURES_FLUSH_INTERVAL_S)
            try:
                flush_summary()
            except Exception:
                log.exception("traffic_summary flush failed")
            try:
                flush_detection_features()
            except Exception:
                log.exception("detection_features flush failed")

    t = threading.Thread(target=_loop, name="summary-flush", daemon=True)
    t.start()


def register_exit_flush() -> None:
    """Flush both buffered tables on interpreter exit.

    Neither buffer had an exit hook before; without this every shutdown
    loses up to one flush interval of traffic_summary and detection_features
    rows (the latter being the ML training collector and TEA replay input).
    """
    import atexit

    def _final_flush():
        try:
            flush_summary()
        except Exception:
            log.exception("exit flush failed for traffic_summary")
        try:
            flush_detection_features()
        except Exception:
            log.exception("exit flush failed for detection_features")

    atexit.register(_final_flush)

# ---------------------------------------------------------------------------
# ip_attack_history — one record per IP per attack session
# ---------------------------------------------------------------------------

def log_attack_history(src_ip: str, attack_vector: str, if_score: float,
                       confidence: float, priority: str, phase_reached: int,
                       first_seen: str, unblock_reason: str,
                       ban_level: int = 0,
                       offence_count: int = 0) -> None:
    """Write a completed attack session to ip_attack_history.

    Called by state_machine._clear() (TTL expiry) and manual_release().
    first_seen: ISO timestamp when IP entered phase 1.
    unblock_reason: 'TTL Expired' | 'Manual Release' | 'Manual Block Escalation'
    """
    global _reputation_seq
    unblocked_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        first_dt   = datetime.datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
        last_dt    = datetime.datetime.strptime(unblocked_at, "%Y-%m-%d %H:%M:%S")
        duration_s = int((last_dt - first_dt).total_seconds())
    except Exception:
        duration_s = 0

    try:
        # The INSERT, its seq bump, and the cache append form ONE atomic
        # section under _reputation_lock: a concurrent first-load either
        # SELECTed before the commit (and then reloads via the seq check or
        # receives the append) or entirely after it (and loads the row), so
        # an offense can be neither omitted nor double-counted. Nesting
        # direction is always reputation-lock then db-lock, never reversed,
        # so this cannot deadlock against unlocked-reader loads.
        with _reputation_lock:
            execute("""
                INSERT INTO ip_attack_history
                    (src_ip, attack_vector, if_score, confidence, priority,
                     phase_reached, first_seen, unblocked_at, duration_sec, unblock_reason,
                     ban_level, offence_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                src_ip,
                attack_vector,
                round(if_score, 6),
                round(confidence, 6),
                priority,
                phase_reached,
                first_seen,
                unblocked_at,
                duration_s,
                unblock_reason,
                ban_level,
                offence_count,
            ))
            _reputation_seq += 1
            stamps = _reputation_cache.get(src_ip)
            if stamps is not None:
                stamps.append(unblocked_at)
    except Exception:
        log.exception("Failed to write attack history for %s", src_ip)


# ---------------------------------------------------------------------------
# Reputation timestamp-list cache (detection-time optimization, A1)
# get_offense_count ran a SELECT per call from the detection hot path. The
# cache stores the RAW unblocked_at strings per src_ip; log_attack_history
# atomically appends its just-committed row and bumps a sequence counter.
# A miss-path load reads the counter around its (unlocked) SELECT and retries
# if an offense landed mid-query, so a served value can never omit a
# committed offense. No lock is ever held across database I/O, and appends
# never block behind loads. Counts stay byte-identical: same strings,
# insertion order, formula, and round-before-clamp order as a direct SQL read.
# ---------------------------------------------------------------------------

_reputation_lock = threading.Lock()
_reputation_cache: dict[str, list[str]] = {}
_reputation_seq = 0


def get_offense_count(src_ip: str) -> float:
    # Returns weighted offense score using half-life decay (24h half-life).
    # Each offense adds +2.0, then decays: score = 2.0 * (0.5 ^ (hours_elapsed / 24))
    # All offenses for this IP are summed — recent ones weigh more than old ones.
    try:
        from backend.database.db import query

        while True:
            with _reputation_lock:
                seq0 = _reputation_seq
                cached = _reputation_cache.get(src_ip)

            if cached is not None:
                with _reputation_lock:
                    snapshot = list(cached)
                break

            rows = query(
                "SELECT unblocked_at FROM ip_attack_history "
                "WHERE src_ip = ? ORDER BY rowid",
                (src_ip,)
            )
            loaded = [r["unblocked_at"] for r in rows] if rows else []

            with _reputation_lock:
                if _reputation_seq != seq0:
                    continue  # an offense committed mid-query; reload to include it
                snapshot = list(_reputation_cache.setdefault(src_ip, loaded))
            break

        now = datetime.datetime.now()
        score = 0.0

        for ts in snapshot:
            try:
                # Parse the timestamp of each offense
                offense_dt   = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                hours_elapsed = (now - offense_dt).total_seconds() / 3600.0
                # Half-life decay: +2.0 per offense, halves every 24h
                score += 2.0 * (0.5 ** (hours_elapsed / 24.0))
            except Exception:
                continue

        return min(round(score, 4), 10.0)
    except Exception as exc:
        log.warning("writer: failed to get offense count for %s — %s", src_ip, exc)
        return 0.0


def get_offense_total_count(src_ip: str) -> int:
    # Raw count of past offenses for this IP — simple "caught N times".
    try:
        from backend.database.db import query
        rows = query(
            "SELECT COUNT(*) as cnt FROM ip_attack_history WHERE src_ip = ?",
            (src_ip,)
        )
        if rows and rows[0]["cnt"] is not None:
            return int(rows[0]["cnt"])
        return 0
    except Exception as exc:
        log.warning("writer: failed to get offense total count for %s — %s", src_ip, exc)
        return 0


def get_ban_level(src_ip: str) -> int:
    # Returns the highest ban_level ever recorded for this IP in DB.
    # Used by behavioral to set starting ban level for returning offenders.
    try:
        from backend.database.db import query
        rows = query(
            "SELECT MAX(ban_level) as max_ban FROM ip_attack_history WHERE src_ip = ?",
            (src_ip,)
        )
        if rows and rows[0]["max_ban"] is not None:
            return int(rows[0]["max_ban"])
        return 0
    except Exception as exc:
        log.warning("writer: failed to get ban level for %s — %s", src_ip, exc)
        return 0


def get_history_dates() -> list[str]:
    """Return distinct dates (YYYY-MM-DD) that have attack history records."""
    try:
        rows = query(
            "SELECT DISTINCT date(unblocked_at) AS d FROM ip_attack_history ORDER BY d ASC"
        )
        return [r["d"] for r in rows if r["d"]]
    except Exception:
        log.exception("Failed to get history dates")
        return []


# ML metrics
def get_ml_metrics(start: str, end: str) -> dict:
    """Compute Precision, Recall, F1, Accuracy, FPR, FNR, TPR, TNR from DB."""
    try:
        rows = query("""
            SELECT SUM(tp) as tp, SUM(false_positives) as fp,
                   SUM(tn) as tn, SUM(fn) as fn
            FROM traffic_summary
            WHERE timestamp >= ? AND timestamp <= ?
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))
        r  = rows[0] if rows else {}
        tp = float(r.get("tp") or 0)
        fp = float(r.get("fp") or 0)
        tn = float(r.get("tn") or 0)
        fn = float(r.get("fn") or 0)

        precision  = tp / max(tp + fp, 1)
        recall     = tp / max(tp + fn, 1)   # TPR
        f1         = 2 * precision * recall / max(precision + recall, 1e-9)
        accuracy   = (tp + tn) / max(tp + fp + tn + fn, 1)
        fpr        = fp / max(fp + tn, 1)
        fnr        = fn / max(fn + tp, 1)
        tpr        = recall
        tnr        = tn / max(tn + fp, 1)

        return {
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
            "precision": round(precision * 100, 2),
            "recall":    round(recall    * 100, 2),
            "f1":        round(f1        * 100, 2),
            "accuracy":  round(accuracy  * 100, 2),
            "fpr":       round(fpr       * 100, 2),
            "fnr":       round(fnr       * 100, 2),
            "tpr":       round(tpr       * 100, 2),
            "tnr":       round(tnr       * 100, 2),
        }
    except Exception:
        log.exception("Failed to compute ML metrics")
        return {}


def _calc_metrics(tp, fp, tn, fn) -> dict:
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy  = (tp + tn) / max(tp + fp + tn + fn, 1)
    return {
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "precision": round(precision * 100, 2),
        "recall":    round(recall    * 100, 2),
        "f1":        round(f1        * 100, 2),
        "accuracy":  round(accuracy  * 100, 2),
        "fpr":       round((fp / max(fp + tn, 1)) * 100, 2),
        "fnr":       round((fn / max(fn + tp, 1)) * 100, 2),
        "tpr":       round(recall * 100, 2),
        "tnr":       round((tn / max(tn + fp, 1)) * 100, 2),
    }


def get_if_metrics(start: str, end: str) -> dict:
    """IF-level metrics — based on if_tp/if_fp/if_tn/if_fn."""
    try:
        rows = query("""
            SELECT SUM(if_tp) as tp, SUM(if_fp) as fp,
                   SUM(if_tn) as tn, SUM(if_fn) as fn
            FROM traffic_summary
            WHERE timestamp >= ? AND timestamp <= ?
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))
        r = rows[0] if rows else {}
        return _calc_metrics(float(r.get("tp") or 0), float(r.get("fp") or 0),
                             float(r.get("tn") or 0), float(r.get("fn") or 0))
    except Exception:
        log.exception("Failed to compute IF metrics")
        return {}


def _calc_overall_from_confusion(cm: dict) -> dict:
    """Micro-averaged Precision/Recall/F1/Accuracy from a 3x3 confusion matrix.

    Standard approach for multi-class: with one predicted label per flow,
    micro precision = micro recall = micro accuracy = overall correct / total.
    """
    correct = cm["syn_as_syn"] + cm["icmp_as_icmp"] + cm["udp_as_udp"]
    total   = sum(cm.values())
    acc     = correct / max(total, 1)

    return {
        "precision": round(acc * 100, 2),
        "recall":    round(acc * 100, 2),
        "f1":        round(acc * 100, 2),
        "accuracy":  round(acc * 100, 2),
    }


def get_rf_metrics(start: str, end: str) -> dict:
    """RF-level metrics — overall + per-class (SYN/ICMP/UDP)."""
    try:
        rows = query("""
            SELECT SUM(rf_tp) as tp, SUM(rf_fp) as fp,
                   SUM(rf_tn) as tn, SUM(rf_fn) as fn,
                   SUM(rf_tp_syn)  as tp_syn,  SUM(rf_fp_syn)  as fp_syn,
                   SUM(rf_tn_syn)  as tn_syn,  SUM(rf_fn_syn)  as fn_syn,
                   SUM(rf_tp_icmp) as tp_icmp, SUM(rf_fp_icmp) as fp_icmp,
                   SUM(rf_tn_icmp) as tn_icmp, SUM(rf_fn_icmp) as fn_icmp,
                   SUM(rf_tp_udp)  as tp_udp,  SUM(rf_fp_udp)  as fp_udp,
                   SUM(rf_tn_udp)  as tn_udp,  SUM(rf_fn_udp)  as fn_udp,
                   SUM(rf_syn_as_icmp) as syn_as_icmp, SUM(rf_syn_as_udp)  as syn_as_udp,
                   SUM(rf_icmp_as_syn) as icmp_as_syn, SUM(rf_icmp_as_udp) as icmp_as_udp,
                   SUM(rf_udp_as_syn)  as udp_as_syn,  SUM(rf_udp_as_icmp) as udp_as_icmp
            FROM traffic_summary
            WHERE timestamp >= ? AND timestamp <= ?
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))
        r = rows[0] if rows else {}
        g = lambda k: float(r.get(k) or 0)

        # confusion matrix cells (3x3, classified flows only)
        cm = {
            "syn_as_syn":   int(g("tp_syn")),
            "syn_as_icmp":  int(g("syn_as_icmp")),
            "syn_as_udp":   int(g("syn_as_udp")),
            "icmp_as_syn":  int(g("icmp_as_syn")),
            "icmp_as_icmp": int(g("tp_icmp")),
            "icmp_as_udp":  int(g("icmp_as_udp")),
            "udp_as_syn":   int(g("udp_as_syn")),
            "udp_as_icmp":  int(g("udp_as_icmp")),
            "udp_as_udp":   int(g("tp_udp")),
        }

        # overall = micro-averaged directly from the matrix above
        # (correct + total classified), not from the separate rf_tp/fp/tn/fn counters
        overall = _calc_overall_from_confusion(cm)

        return {
            "overall": overall,
            "syn":     _calc_metrics(g("tp_syn"),  g("fp_syn"),  g("tn_syn"),  g("fn_syn")),
            "icmp":    _calc_metrics(g("tp_icmp"), g("fp_icmp"), g("tn_icmp"), g("fn_icmp")),
            "udp":     _calc_metrics(g("tp_udp"),  g("fp_udp"),  g("tn_udp"),  g("fn_udp")),
            "confusion": cm,
        }
    except Exception:
        log.exception("Failed to compute RF metrics")
        return {}


def get_latency_metrics(start: str, end: str) -> dict:
    """Avg Detection Time and Mitigation Response Time, in milliseconds."""
    try:
        rows = query("""
            SELECT AVG(detection_ms) as avg_detect, AVG(mitigation_ms) as avg_mitigate
            FROM mitigation_events
            WHERE timestamp >= ? AND timestamp <= ?
              AND detection_ms IS NOT NULL AND mitigation_ms IS NOT NULL
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))
        r = rows[0] if rows else {}
        return {
            "detection_ms":  round(float(r.get("avg_detect")   or 0), 2),
            "mitigation_ms": round(float(r.get("avg_mitigate") or 0), 2),
        }
    except Exception:
        log.exception("Failed to compute latency metrics")
        return {}


# system_metrics
def log_system_metrics(cpu: float, mem_mb: float, pps: float,
                       is_attack: bool = False,
                       ctrl_cpu: float = 0.0, ctrl_mem: float = 0.0,
                       is_mitigating: bool = False) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute("""
            INSERT INTO system_metrics
                (timestamp, cpu_percent, mem_mb, pps_processed, is_attack,
                 ctrl_cpu_percent, ctrl_mem_mb, is_mitigating)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, round(cpu, 2), round(mem_mb, 2), round(pps, 2),
              int(is_attack), round(ctrl_cpu, 2), round(ctrl_mem, 2),
              int(is_mitigating)))
    except Exception:
        log.exception("Failed to log system metrics")


def get_system_metrics_avg(start: str, end: str) -> dict:
    try:
        rows = query("""
            SELECT AVG(cpu_percent) as cpu, AVG(mem_mb) as mem,
                   AVG(pps_processed) as pps
            FROM system_metrics
            WHERE timestamp >= ? AND timestamp <= ?
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))
        r = rows[0] if rows else {}
        return {
            "avg_cpu":  round(float(r.get("cpu") or 0), 2),
            "avg_mem":  round(float(r.get("mem") or 0), 2),
            "avg_pps":  round(float(r.get("pps") or 0), 2),
        }
    except Exception:
        log.exception("Failed to get system metrics avg")
        return {}


def get_system_metrics_attack_vs_baseline(start: str, end: str) -> dict:
    """Returns avg Controller CPU during attack, baseline, and active mitigation."""
    try:
        attack = query("""
            SELECT AVG(ctrl_cpu_percent) as ctrl_cpu
            FROM system_metrics
            WHERE timestamp >= ? AND timestamp <= ? AND is_attack = 1
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))

        baseline = query("""
            SELECT AVG(ctrl_cpu_percent) as ctrl_cpu
            FROM system_metrics
            WHERE timestamp >= ? AND timestamp <= ? AND is_attack = 0
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))

        mitigating = query("""
            SELECT AVG(ctrl_cpu_percent) as ctrl_cpu
            FROM system_metrics
            WHERE timestamp >= ? AND timestamp <= ? AND is_mitigating = 1
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))

        a = attack[0]     if attack     else {}
        b = baseline[0]   if baseline   else {}
        m = mitigating[0] if mitigating else {}
        return {
            "attack_ctrl_cpu":     round(float(a.get("ctrl_cpu") or 0), 2),
            "baseline_ctrl_cpu":   round(float(b.get("ctrl_cpu") or 0), 2),
            "mitigation_ctrl_cpu": round(float(m.get("ctrl_cpu") or 0), 2),
        }
    except Exception:
        log.exception("Failed to get attack vs baseline metrics")
        return {}