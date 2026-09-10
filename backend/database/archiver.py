# Database maintenance daemon archiving historical security events and pruning telemetry tables.
# Maintains SQLite table performance by migrating aging rows to archive stores.

import time
import threading
import logging
from backend.database.db import transaction, query, execute

log = logging.getLogger(__name__)

ARCHIVE_AFTER_HOURS = 24
ARCHIVE_INTERVAL_S  = 3600   # once per hour


def _archive_old_events() -> int:
    # Moves events older than threshold from active mitigation table to archive table.
    # Executes atomically within a transaction and deletes expired detection features.
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
        log.exception("Archiver failed: rolled back")

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
    # Hourly background loop running database archive routines.
    while True:
        time.sleep(ARCHIVE_INTERVAL_S)
        try:
            _archive_old_events()
        except Exception:
            log.exception("Archiver loop error")


def start() -> None:
    # Starts the background database archiver daemon thread.
    t = threading.Thread(target=_archiver_loop, name="db-archiver", daemon=True)
    t.start()
    log.info("DB archiver started (interval=%ds, cutoff=%dh)",
             ARCHIVE_INTERVAL_S, ARCHIVE_AFTER_HOURS)