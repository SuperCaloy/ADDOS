import datetime
import threading
import logging
from backend.database.db import execute, executemany, query

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
                   "tp": 0, "tn": 0, "fn": 0}


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
                 confidence, priority, action_taken, if_score, phase, is_manual)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        ))
    except Exception:
        log.exception("Failed to write mitigation event for %s", event.get("src_ip"))


def log_manual_action(src_ip: str, action: str,
                      attack_vector: str = "—",
                      confidence: float = 0.0,
                      priority: str = "—",
                      if_score: float = None,
                      phase: str = None) -> None:
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
                 confidence, priority, action_taken, if_score, phase, is_manual)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, src_ip, "DDoS", attack_vector,
            confidence, priority,
            action.replace("_", " ").title(),
            if_score, phase, 1,
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
    try:
        fs = flow_stats  or {}
        ss = switch_stats or {}
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        flow_duration_sec         = fs.get("flow_duration_sec", 0.0)
        flow_duration_nsec        = fs.get("flow_duration_nsec", 0.0)
        idle_timeout              = fs.get("idle_timeout", 0)
        hard_timeout              = fs.get("hard_timeout", 0)
        flags                     = fs.get("flags", 0)
        packet_count              = fs.get("packet_count", 0)
        byte_count                = fs.get("byte_count", 0)
        packet_count_per_second   = fs.get("packet_count_per_second", 0.0)
        packet_count_per_nsecond  = fs.get("packet_count_per_nsecond", 0.0)
        byte_count_per_second     = fs.get("byte_count_per_second", 0.0)
        byte_count_per_nsecond    = fs.get("byte_count_per_nsecond", 0.0)
        flow_duration_total_ns    = fs.get("flow_duration_total_ns",
            flow_duration_sec * 1e9 + flow_duration_nsec)
        bytes_per_packet          = (byte_count / max(packet_count, 1))
        pkt_byte_rate_ratio       = (packet_count_per_second /
                                     max(byte_count_per_second, 1e-9))

        disp_pakt         = ss.get("disp_pakt", 0)
        disp_byte         = ss.get("disp_byte", 0)
        mean_pkt          = ss.get("mean_pkt", 0.0)
        mean_byte         = ss.get("mean_byte", 0.0)
        avg_durat         = ss.get("avg_durat", 0.0)
        avg_flow_dst      = ss.get("avg_flow_dst", 0)
        rate_pkt_in       = ss.get("rate_pkt_in", 0.0)
        disp_interval     = ss.get("disp_interval", 1.0)
        gfe               = ss.get("gfe", 0)
        g_usip            = ss.get("g_usip", 0)
        rfip              = ss.get("rfip", 0)
        gsp               = ss.get("gsp", 0)
        ip_diversity_ratio = (g_usip / max(gfe, 1))
        byte_per_interval  = (disp_byte / max(disp_interval, 1e-9))
        pkt_per_interval   = (disp_pakt / max(disp_interval, 1e-9))
        flow_entry_ratio   = (gfe / max(gsp, 1))
        mean_pkt_byte_ratio = (mean_pkt / max(mean_byte, 1e-9))

        flag_syn_flood  = 1 if attack_class == "SYN Flood"  else 0
        flag_icmp_flood = 1 if attack_class == "ICMP Flood" else 0
        flag_udp_flood  = 1 if attack_class == "UDP Flood"  else 0
        flag_normal     = 1 if not is_anomaly               else 0

        execute("""
            INSERT INTO detection_features (
                timestamp, src_ip, if_score, is_anomaly, attack_class, confidence,
                flow_duration_sec, flow_duration_nsec, idle_timeout, hard_timeout,
                flags, packet_count, byte_count,
                packet_count_per_second, packet_count_per_nsecond,
                byte_count_per_second,  byte_count_per_nsecond,
                flow_duration_total_ns, bytes_per_packet, pkt_byte_rate_ratio,
                disp_pakt, disp_byte, mean_pkt, mean_byte, avg_durat,
                avg_flow_dst, rate_pkt_in, disp_interval, gfe, g_usip, rfip, gsp,
                ip_diversity_ratio, byte_per_interval, pkt_per_interval,
                flow_entry_ratio, mean_pkt_byte_ratio,
                flag_syn_flood, flag_icmp_flood, flag_udp_flood, flag_normal
            ) VALUES (
                ?,?,?,?,?,?,
                ?,?,?,?,
                ?,?,?,
                ?,?,
                ?,?,
                ?,?,?,
                ?,?,?,?,?,
                ?,?,?,?,?,?,?,
                ?,?,?,
                ?,?,
                ?,?,?,?
            )
        """, (
            ts, src_ip, round(if_score, 6), int(is_anomaly),
            attack_class, round(confidence, 6),
            flow_duration_sec, flow_duration_nsec, idle_timeout, hard_timeout,
            flags, packet_count, byte_count,
            packet_count_per_second, packet_count_per_nsecond,
            byte_count_per_second, byte_count_per_nsecond,
            flow_duration_total_ns, bytes_per_packet, pkt_byte_rate_ratio,
            disp_pakt, disp_byte, mean_pkt, mean_byte, avg_durat,
            avg_flow_dst, rate_pkt_in, disp_interval, gfe, g_usip, rfip, gsp,
            ip_diversity_ratio, byte_per_interval, pkt_per_interval,
            flow_entry_ratio, mean_pkt_byte_ratio,
            flag_syn_flood, flag_icmp_flood, flag_udp_flood, flag_normal,
        ))
    except Exception:
        log.exception("Failed to write detection_features for %s", src_ip)


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
                        tp: int = 0, tn: int = 0, fn: int = 0) -> None:
    with _summary_lock:
        _summary_buffer["total"]    += total
        _summary_buffer["threats"]  += threats
        _summary_buffer["true_neg"] += true_neg
        _summary_buffer["fp"]       += fp
        _summary_buffer["tp"]       += tp
        _summary_buffer["tn"]       += tn
        _summary_buffer["fn"]       += fn


def flush_summary() -> None:
    with _summary_lock:
        if not any(_summary_buffer.values()):
            return
        snapshot = _summary_buffer.copy()
        _summary_buffer.update({"total": 0, "threats": 0, "true_neg": 0, "fp": 0,
                                 "tp": 0, "tn": 0, "fn": 0})

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute("""
            INSERT INTO traffic_summary
                (timestamp, total_flows_observed, threats_mitigated,
                 true_negatives_passed, false_positives, tp, tn, fn)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, snapshot["total"], snapshot["threats"],
              snapshot["true_neg"], snapshot["fp"],
              snapshot["tp"], snapshot["tn"], snapshot["fn"]))
    except Exception:
        log.exception("Failed to flush traffic_summary")


def start_flush_thread() -> None:
    import time

    def _loop():
        while True:
            time.sleep(5.0)
            flush_summary()

    t = threading.Thread(target=_loop, name="summary-flush", daemon=True)
    t.start()

# ---------------------------------------------------------------------------
# ip_attack_history — one record per IP per attack session
# ---------------------------------------------------------------------------

def log_attack_history(src_ip: str, attack_vector: str, if_score: float,
                       confidence: float, priority: str, phase_reached: int,
                       first_seen: str, unblock_reason: str,
                       ban_level: int = 0, offence_count: int = 1) -> None:
    """Write a completed attack session to ip_attack_history.

    Called by state_machine._clear() (TTL expiry) and manual_release().
    first_seen: ISO timestamp when IP entered phase 1.
    unblock_reason: 'TTL Expired' | 'Manual Release' | 'Manual Block Escalation'
    """
    unblocked_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        first_dt   = datetime.datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
        last_dt    = datetime.datetime.strptime(unblocked_at, "%Y-%m-%d %H:%M:%S")
        duration_s = int((last_dt - first_dt).total_seconds())
    except Exception:
        duration_s = 0

    try:
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
    except Exception:
        log.exception("Failed to write attack history for %s", src_ip)


def get_offense_count(src_ip: str) -> float:
    # Returns weighted offense score using half-life decay (24h half-life).
    # Each offense adds +2.0, then decays: score = 2.0 * (0.5 ^ (hours_elapsed / 24))
    # All offenses for this IP are summed — recent ones weigh more than old ones.
    try:
        from backend.database.db import query
        rows = query(
            "SELECT unblocked_at FROM ip_attack_history WHERE src_ip = ?",
            (src_ip,)
        )
        if not rows:
            return 0.0

        import time as _t
        now = datetime.datetime.now()
        score = 0.0

        for row in rows:
            try:
                # Parse the timestamp of each offense
                offense_dt   = datetime.datetime.strptime(row["unblocked_at"], "%Y-%m-%d %H:%M:%S")
                hours_elapsed = (now - offense_dt).total_seconds() / 3600.0
                # Half-life decay: +2.0 per offense, halves every 24h
                score += 2.0 * (0.5 ** (hours_elapsed / 24.0))
            except Exception:
                continue

        return round(score, 4)
    except Exception as exc:
        log.warning("writer: failed to get offense count for %s — %s", src_ip, exc)
        return 0.0


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


# system_metrics
def log_system_metrics(cpu: float, mem_mb: float, pps: float) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        execute("""
            INSERT INTO system_metrics (timestamp, cpu_percent, mem_mb, pps_processed)
            VALUES (?, ?, ?, ?)
        """, (ts, round(cpu, 2), round(mem_mb, 2), round(pps, 2)))
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
    """Returns avg CPU/mem during attack periods vs baseline (no threats)."""
    try:
        # Attack period — timestamps that overlap with mitigation events
        attack = query("""
            SELECT AVG(s.cpu_percent) as cpu, AVG(s.mem_mb) as mem
            FROM system_metrics s
            WHERE s.timestamp >= ? AND s.timestamp <= ?
              AND EXISTS (
                SELECT 1 FROM mitigation_events m
                WHERE m.timestamp >= datetime(s.timestamp, '-10 seconds')
                  AND m.timestamp <= datetime(s.timestamp, '+10 seconds')
              )
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))

        baseline = query("""
            SELECT AVG(s.cpu_percent) as cpu, AVG(s.mem_mb) as mem
            FROM system_metrics s
            WHERE s.timestamp >= ? AND s.timestamp <= ?
              AND NOT EXISTS (
                SELECT 1 FROM mitigation_events m
                WHERE m.timestamp >= datetime(s.timestamp, '-10 seconds')
                  AND m.timestamp <= datetime(s.timestamp, '+10 seconds')
              )
        """, (f"{start} 00:00:00", f"{end} 23:59:59"))

        a = attack[0]   if attack   else {}
        b = baseline[0] if baseline else {}
        return {
            "attack_cpu":   round(float(a.get("cpu") or 0), 2),
            "attack_mem":   round(float(a.get("mem") or 0), 2),
            "baseline_cpu": round(float(b.get("cpu") or 0), 2),
            "baseline_mem": round(float(b.get("mem") or 0), 2),
        }
    except Exception:
        log.exception("Failed to get attack vs baseline metrics")
        return {}