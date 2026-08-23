import sqlite3
import os
import threading
from contextlib import contextmanager
from backend.config import DB_PATH

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
                _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                _conn.execute("PRAGMA journal_mode=WAL")
                _conn.execute("PRAGMA synchronous=NORMAL")
                _init_schema(_conn)
                _migrate(_conn)
                _conn.commit()
    return _conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS mitigation_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            predicted_class TEXT    NOT NULL,
            attack_vector   TEXT    NOT NULL,
            confidence      REAL    NOT NULL,
            priority        TEXT    NOT NULL,
            action_taken    TEXT    NOT NULL,
            if_score        REAL,
            phase           TEXT,
            is_manual       INTEGER DEFAULT 0,
            event_type      TEXT DEFAULT 'transition',
            reason          TEXT,
            detection_ms    REAL,
            mitigation_ms   REAL
        );

        CREATE TABLE IF NOT EXISTS mitigation_events_archive (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            predicted_class TEXT    NOT NULL,
            attack_vector   TEXT    NOT NULL,
            confidence      REAL    NOT NULL,
            priority        TEXT    NOT NULL,
            action_taken    TEXT    NOT NULL,
            if_score        REAL,
            phase           TEXT,
            is_manual       INTEGER DEFAULT 0,
            event_type      TEXT DEFAULT 'transition',
            reason          TEXT
        );

        CREATE TABLE IF NOT EXISTS traffic_summary (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp             TEXT    NOT NULL,
            total_flows_observed  INTEGER DEFAULT 0,
            threats_mitigated     INTEGER DEFAULT 0,
            true_negatives_passed INTEGER DEFAULT 0,
            false_positives       INTEGER DEFAULT 0,
            tp                    INTEGER DEFAULT 0,
            tn                    INTEGER DEFAULT 0,
            fn                    INTEGER DEFAULT 0,
            -- IF-level metrics
            if_tp                 INTEGER DEFAULT 0,
            if_fp                 INTEGER DEFAULT 0,
            if_tn                 INTEGER DEFAULT 0,
            if_fn                 INTEGER DEFAULT 0,
            -- RF overall metrics
            rf_tp                 INTEGER DEFAULT 0,
            rf_fp                 INTEGER DEFAULT 0,
            rf_tn                 INTEGER DEFAULT 0,
            rf_fn                 INTEGER DEFAULT 0,
            -- RF per-class
            rf_tp_syn             INTEGER DEFAULT 0,
            rf_fp_syn             INTEGER DEFAULT 0,
            rf_tn_syn             INTEGER DEFAULT 0,
            rf_fn_syn             INTEGER DEFAULT 0,
            rf_tp_icmp            INTEGER DEFAULT 0,
            rf_fp_icmp            INTEGER DEFAULT 0,
            rf_tn_icmp            INTEGER DEFAULT 0,
            rf_fn_icmp            INTEGER DEFAULT 0,
            rf_tp_udp             INTEGER DEFAULT 0,
            rf_fp_udp             INTEGER DEFAULT 0,
            rf_tn_udp             INTEGER DEFAULT 0,
            rf_fn_udp             INTEGER DEFAULT 0,
            -- RF misclassification (off-diagonal confusion matrix)
            rf_syn_as_icmp        INTEGER DEFAULT 0,
            rf_syn_as_udp         INTEGER DEFAULT 0,
            rf_icmp_as_syn        INTEGER DEFAULT 0,
            rf_icmp_as_udp        INTEGER DEFAULT 0,
            rf_udp_as_syn         INTEGER DEFAULT 0,
            rf_udp_as_icmp        INTEGER DEFAULT 0,
            -- hold_ip stats (unscored fallback mitigation)
            held                  INTEGER DEFAULT 0,
            rescored              INTEGER DEFAULT 0,
            expired_unscored      INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts    ON mitigation_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_ip    ON mitigation_events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_summary_ts   ON traffic_summary(timestamp);
        CREATE INDEX IF NOT EXISTS idx_archive_ts   ON mitigation_events_archive(timestamp);

        CREATE TABLE IF NOT EXISTS detection_features (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            if_score    REAL    NOT NULL,
            is_anomaly  INTEGER NOT NULL,
            attack_class TEXT   NOT NULL,
            confidence  REAL    NOT NULL,

            flow_duration_sec        REAL,
            flow_duration_nsec       REAL,
            idle_timeout             INTEGER,
            hard_timeout             INTEGER,
            flags                    INTEGER,
            packet_count             INTEGER,
            byte_count               INTEGER,
            packet_count_per_second  REAL,
            packet_count_per_nsecond REAL,
            byte_count_per_second    REAL,
            byte_count_per_nsecond   REAL,
            flow_duration_total_ns   REAL,
            bytes_per_packet         REAL,
            pkt_byte_rate_ratio      REAL,

            disp_pakt            INTEGER,
            disp_byte            INTEGER,
            mean_pkt             REAL,
            mean_byte            REAL,
            avg_durat            REAL,
            avg_flow_dst         INTEGER,
            rate_pkt_in          REAL,
            disp_interval        REAL,
            gfe                  INTEGER,
            g_usip               INTEGER,
            rfip                 INTEGER,
            gsp                  INTEGER,
            ip_diversity_ratio   REAL,
            byte_per_interval    REAL,
            pkt_per_interval     REAL,
            flow_entry_ratio     REAL,
            mean_pkt_byte_ratio  REAL,

            flag_syn_flood   INTEGER NOT NULL DEFAULT 0,
            flag_icmp_flood  INTEGER NOT NULL DEFAULT 0,
            flag_udp_flood   INTEGER NOT NULL DEFAULT 0,
            flag_normal      INTEGER NOT NULL DEFAULT 0,

            -- IF/RF contract features
            flow_count_per_src    REAL,
            tp_src                INTEGER,
            tp_dst                INTEGER,
            ip_proto              INTEGER,
            flow_intensity        REAL,
            port_entropy          REAL,
            bytes_per_duration    REAL,
            pkt_size_uniformity   REAL,
            flow_src_intensity    REAL,
            duration_pkt_ratio    REAL,
            pkt_rate_per_duration REAL
        );

        CREATE INDEX IF NOT EXISTS idx_df_src_ip
            ON detection_features (src_ip);
        CREATE INDEX IF NOT EXISTS idx_df_timestamp
            ON detection_features (timestamp);
        CREATE INDEX IF NOT EXISTS idx_df_attack_class
            ON detection_features (attack_class);

        -- quarantine_state — block_expires_at TEXT added for TTL persistence.
        -- NULL = permanent (manual block). ISO timestamp = auto-block expiry.
        CREATE TABLE IF NOT EXISTS quarantine_state (
            src_ip           TEXT PRIMARY KEY,
            phase            INTEGER NOT NULL,
            attack_vector    TEXT    NOT NULL,
            if_score         REAL    NOT NULL,
            confidence       REAL    NOT NULL,
            action_taken     TEXT    NOT NULL,
            permanent        INTEGER NOT NULL DEFAULT 0,
            updated_at       TEXT    NOT NULL,
            block_expires_at TEXT
        );

        -- ip_attack_history: one row per IP per attack session.
        -- Written when an IP is unblocked (TTL expiry, manual release, or escalation).
        -- Used for history view and report generation by date range.
        CREATE TABLE IF NOT EXISTS ip_attack_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip          TEXT    NOT NULL,
            attack_vector   TEXT    NOT NULL,
            if_score        REAL    NOT NULL,
            confidence      REAL    NOT NULL,
            priority        TEXT    NOT NULL DEFAULT 'Low',
            phase_reached   INTEGER NOT NULL DEFAULT 1,
            first_seen      TEXT    NOT NULL,
            unblocked_at    TEXT    NOT NULL,
            duration_sec    INTEGER NOT NULL DEFAULT 0,
            unblock_reason  TEXT    NOT NULL,
            ban_level       INTEGER NOT NULL DEFAULT 0,
            offence_count   INTEGER NOT NULL DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_history_ip
            ON ip_attack_history (src_ip);
        CREATE INDEX IF NOT EXISTS idx_history_unblocked
            ON ip_attack_history (unblocked_at);
        CREATE INDEX IF NOT EXISTS idx_history_date
            ON ip_attack_history (date(unblocked_at));

        CREATE TABLE IF NOT EXISTS system_metrics (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            cpu_percent     REAL    NOT NULL DEFAULT 0,
            mem_mb          REAL    NOT NULL DEFAULT 0,
            pps_processed   REAL    NOT NULL DEFAULT 0,
            is_attack       INTEGER NOT NULL DEFAULT 0,
            ctrl_cpu_percent REAL   NOT NULL DEFAULT 0,
            ctrl_mem_mb     REAL    NOT NULL DEFAULT 0,
            is_mitigating   INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_sysmetrics_ts
            ON system_metrics (timestamp);

        CREATE TABLE IF NOT EXISTS global_counters (
            id               INTEGER PRIMARY KEY CHECK (id = 1),
            total_packets    INTEGER NOT NULL DEFAULT 0,
            malicious_dropped INTEGER NOT NULL DEFAULT 0,
            normal_packets   INTEGER NOT NULL DEFAULT 0,
            false_positives  INTEGER NOT NULL DEFAULT 0
        );

        INSERT OR IGNORE INTO global_counters
            (id, total_packets, malicious_dropped, normal_packets, false_positives)
        VALUES (1, 0, 0, 0, 0);
    """)


def _migrate(conn: sqlite3.Connection) -> None:
    """Safe schema migrations for existing databases.

    Each ALTER TABLE is wrapped in try/except so re-running on a fresh DB
    (which already has the column from _init_schema) is a no-op.
    """
    # H5 fix: add block_expires_at to existing quarantine_state tables.
    try:
        conn.execute("ALTER TABLE quarantine_state ADD COLUMN block_expires_at TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE ip_attack_history ADD COLUMN ban_level INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE ip_attack_history ADD COLUMN offence_count INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # controller metrics columns
    for col, typ in [("ctrl_cpu_percent", "REAL NOT NULL DEFAULT 0"),
                     ("ctrl_mem_mb",      "REAL NOT NULL DEFAULT 0"),
                     ("is_mitigating",    "INTEGER NOT NULL DEFAULT 0")]:
        try:
            conn.execute(f"ALTER TABLE system_metrics ADD COLUMN {col} {typ}")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # IF/RF split columns
    new_cols = [        "if_tp", "if_fp", "if_tn", "if_fn",
        "rf_tp", "rf_fp", "rf_tn", "rf_fn",
        "rf_tp_syn", "rf_fp_syn", "rf_tn_syn", "rf_fn_syn",
        "rf_tp_icmp","rf_fp_icmp","rf_tn_icmp","rf_fn_icmp",
        "rf_tp_udp", "rf_fp_udp", "rf_tn_udp", "rf_fn_udp",
        "rf_syn_as_icmp", "rf_syn_as_udp",
        "rf_icmp_as_syn", "rf_icmp_as_udp",
        "rf_udp_as_syn",  "rf_udp_as_icmp",
    ]
    for col in new_cols:
        try:
            conn.execute(f"ALTER TABLE traffic_summary ADD COLUMN {col} INTEGER DEFAULT 0")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # hold_ip stats columns
    for col in ("held", "rescored", "expired_unscored"):
        try:
            conn.execute(f"ALTER TABLE traffic_summary ADD COLUMN {col} INTEGER DEFAULT 0")
            conn.commit()
        except sqlite3.OperationalError:
            pass


    # latency tracking columns (Detection Time / Mitigation Response Time)
    for col in ("detection_ms", "mitigation_ms"):
        try:
            conn.execute(f"ALTER TABLE mitigation_events ADD COLUMN {col} REAL")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # lifecycle ledger columns (event_type + reason) on hot and archive tables
    for table in ("mitigation_events", "mitigation_events_archive"):
        try:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN event_type TEXT DEFAULT 'transition'")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN reason TEXT")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # IF/RF contract feature columns
    df_new_cols = [
        ("flow_count_per_src",    "REAL"),
        ("tp_src",                "INTEGER"),
        ("tp_dst",                "INTEGER"),
        ("ip_proto",              "INTEGER"),
        ("flow_intensity",        "REAL"),
        ("port_entropy",          "REAL"),
        ("bytes_per_duration",    "REAL"),
        ("pkt_size_uniformity",   "REAL"),
        ("flow_src_intensity",    "REAL"),
        ("duration_pkt_ratio",    "REAL"),
        ("pkt_rate_per_duration", "REAL"),
    ]
    for col, typ in df_new_cols:
        try:
            conn.execute(f"ALTER TABLE detection_features ADD COLUMN {col} {typ}")
            conn.commit()
        except sqlite3.OperationalError:
            pass


# ---------------------------------------------------------------------------
# C3 fix: atomic transaction context manager
# ---------------------------------------------------------------------------

@contextmanager
def transaction():
    """Context manager for multi-statement atomic transactions.

    Usage::

        with transaction() as conn:
            conn.execute("INSERT INTO ...", (...))
            conn.execute("DELETE FROM ...", (...))
        # commits on __exit__, rolls back on exception

    Holds _lock for the duration — do not nest with execute() or query().
    """
    conn = get_connection()
    with _lock:
        conn.execute("BEGIN")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    conn = get_connection()
    with _lock:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur


def executemany(sql: str, params_list: list) -> None:
    conn = get_connection()
    with _lock:
        conn.executemany(sql, params_list)
        conn.commit()


def query(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_connection()
    with _lock:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.row_factory = None
        return rows