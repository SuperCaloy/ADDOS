import time
import threading
import logging
from backend.database.db import transaction, query, execute

log = logging.getLogger(__name__)

ARCHIVE_AFTER_HOURS = 24
ARCHIVE_INTERVAL_S  = 3600   # once per hour


def _archive_old_events() -> int:
    """Move events older than ARCHIVE_AFTER_HOURS from hot table to archive.

    C3 fix: uses transaction() context manager for a real atomic operation.
    Previously execute("BEGIN") auto-committed immediately because every
    db.execute() calls conn.commit() — making the old BEGIN/ROLLBACK a no-op
    and leaving rows in both tables or losing them entirely on a mid-loop crash.

    Also prunes old detection_features rows (ip_detail only needs the latest
    per src_ip, so older rows are dead weight).
    """
    cutoff = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(time.time() - ARCHIVE_AFTER_HOURS * 3600)
    )

    old_rows = query(
        "SELECT * FROM mitigation_events WHERE timestamp < ?", (cutoff,)
    )

    deleted_events = 0
    try:
        if old_rows:
            with transaction() as conn:
                for row in old_rows:
                    conn.execute("""
                        INSERT INTO mitigation_events_archive
                            (timestamp, src_ip, predicted_class, attack_vector,
                             confidence, priority, action_taken, if_score, phase, is_manual,
                             event_type, reason)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row["timestamp"], row["src_ip"], row["predicted_class"],
                        row["attack_vector"], row["confidence"], row["priority"],
                        row["action_taken"], row.get("if_score"), row.get("phase"),
                        row.get("is_manual", 0),
                        row.get("event_type") or "transition", row.get("reason"),
                    ))
                conn.execute(
                    "DELETE FROM mitigation_events WHERE timestamp < ?", (cutoff,)
                )
            deleted_events = len(old_rows)
            log.info("Archived %d mitigation events (older than %s)",
                     deleted_events, cutoff)
    except Exception:
        log.exception("Archiver failed — rolled back")

    try:
        cur = execute(
            "DELETE FROM detection_features WHERE timestamp < ?", (cutoff,)
        )
        deleted_features = cur.rowcount
        if deleted_features:
            log.info("Pruned %d detection_features (older than %s)",
                     deleted_features, cutoff)
    except Exception:
        log.exception("detection_features prune failed")
        deleted_features = 0

    return deleted_events + deleted_features


def _archiver_loop() -> None:
    while True:
        time.sleep(ARCHIVE_INTERVAL_S)
        try:
            _archive_old_events()
        except Exception:
            log.exception("Archiver loop error")


def start() -> None:
    t = threading.Thread(target=_archiver_loop, name="db-archiver", daemon=True)
    t.start()
    log.info("DB archiver started (interval=%ds, cutoff=%dh)",
             ARCHIVE_INTERVAL_S, ARCHIVE_AFTER_HOURS)