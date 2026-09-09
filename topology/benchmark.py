"""Topology-side 5-minute benchmark mode, 5 sessions per command.

Imports no topology code (no __init__.py in topology/). All helpers are
passed in via the topology module object by topology.py.
"""
import time
import os
import threading
import sqlite3
import json
import statistics
import urllib.request
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _fetch_backend_json(url: str, timeout: float = 2.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


# Absolute 5-minute evaluated timetable (seconds from T_eval_start).
# One session: 2:00 benign, 0:30 SYN, 0:30 UDP, 0:30 ICMP, 0:30 quiet,
# 1:00 mixed. Five sessions per command = 25:00 evaluated total.
_SESSION_S = 300
_PHASES_300 = [  # (start_s, kind, action, duration_s)
    (0,   "benign", None,    120),  # T+0:00-2:00 legit hosts only
    (120, "wave",   "syn",    30),  # T+2:00-2:30 SYN h16-h19
    (150, "wave",   "udp",    30),  # T+2:30-3:00 UDP h20-h22
    (180, "wave",   "icmp",   30),  # T+3:00-3:30 ICMP h23-h25
    (210, "quiet",  None,     30),  # T+3:30-4:00 all attacks stopped
    (240, "wave",   "mixed",  60),  # T+4:00-5:00 mixed campaign
]
_WAVES = {"syn": "start_syn_flood_campaign",
          "udp": "start_udp_flood_campaign",
          "icmp": "start_icmp_flood_campaign",
          "mixed": "start_mixed_campaign"}

# Human-readable per-step labels shown in the operator progress output.
_PHASE_LABELS = {
    ("benign",  None):      "benign baseline (legit-only, FPR reference)",
    ("wave",    "syn"):     "SYN wave (4 SYN attackers)",
    ("wave",    "udp"):     "UDP wave (3 UDP attackers)",
    ("wave",    "icmp"):    "ICMP wave (3 ICMP attackers)",
    ("quiet",   None):      "quiet window (attacks stopped, settle)",
    ("wave",    "mixed"):   "mixed wave (all 10, staged SYN/UDP/ICMP)",
}

# session summary, printed at the end of every run
_SUMMARY = {}


def _default_calibration_gate(topo, cap_s: float):
# Exception-safe. Polls /api/expert/live until the model has learned (via an explicit key check, not dict truthiness) and 3 consecutive polls show no quarantine growth, or until cap_s elapses. Hard deadline prevents hangs; at least 30s is held for baseline soak.
    import json, urllib.request
    deadline = time.monotonic() + cap_s
    started = time.monotonic()
    clean = 0
    while time.monotonic() < deadline and clean < 3:
        try:
            data = _fetch_backend_json(f"{topo.BACKEND_API}/api/expert/live", timeout=2)
            learned = (data.get("tea", {}).get("global", {})
                       .get("learned") is True)
            # Clean poll: no live IpState entries and no active sinkholes.
            quarantine_empty = (not data.get("state_machine")
                                and not data.get("deception", {})
                                .get("active_sinkholes"))
            if learned and quarantine_empty:
                clean += 1
            else:
                clean = 0
        except Exception:
            clean = 0
        if clean < 3:
            time.sleep(2)
    if time.monotonic() - started < 30.0:
        time.sleep(30.0 - (time.monotonic() - started))
    status = "calibrated" if clean >= 3 else "degraded"
    _SUMMARY["calibration_status"] = status
    print(f"BENCHMARK: calibration gate '{status}' (clean_polls={clean}).")
    return status


def _clean_poll_gate(topo, limit_t: float):
    # Wait (up to `limit_t`) for the backend quarantine to be empty so the next
    # wave's first-detection is ground truth. Exception-safe, time-bounded.
    import json, urllib.request
    while time.monotonic() < limit_t:
        try:
            data = _fetch_backend_json(f"{topo.BACKEND_API}/api/expert/live", timeout=2)
            # Ground truth: empty state machine and no active sinkholes.
            if (not data.get("state_machine")
                    and not data.get("deception", {})
                    .get("active_sinkholes")):
                return
        except Exception:
            pass
        time.sleep(2)
    print("BENCHMARK: clean-poll timeout; proceeding (detection may be warm).")


def _log_tier_snapshot(topo):
    # optional telemetry before the second mixed wave; never fatal
    import json, urllib.request
    try:
        data = _fetch_backend_json(f"{topo.BACKEND_API}/api/stats", timeout=2)
        # compact slice of the response, never the whole payload
        summary = {k: data.get(k) for k in
                   ("active_threats", "malicious_dropped",
                    "normal_packets", "fp_rate")}
        print("BENCHMARK: pre-wave-B snapshot:", summary)
    except Exception:
        pass


LEDGER_TABLE = "offence_totals"  # src_ip, total_offences, last_ban_level, updated_at


def _post_json(url, payload):
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception:
        pass


def _resolve_db_path():
    # Env override wins (matches backend.config), else the fixed benchmark
    # DB: every session reuses it so the offence ledger persists across runs.
    env = os.environ.get("DDOS_DB_PATH")
    if env:
        return Path(env)
    return _project_root() / "benchmark" / "benchmark.db"


def _marker_path():
    # Same marker file backend.config reads at boot; local fallback keeps
    # this module importable even if backend code is unavailable.
    try:
        from backend.config import MARKER_PATH
        return Path(MARKER_PATH)
    except Exception:
        return _project_root() / "benchmark" / "DB_TARGET"


def _write_db_marker() -> None:
    marker = _marker_path()
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(str(_resolve_db_path()))
    # Under sudo the marker would be root-owned and unrewritable by the
    # normal user (tests, tools); give it back to the invoking user.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            rec = pwd.getpwnam(sudo_user)
            os.chown(marker, rec.pw_uid, rec.pw_gid)
        except Exception:
            pass


def _remove_db_marker() -> None:
    _marker_path().unlink(missing_ok=True)


def cleanup_stale_marker() -> bool:
    # Remove any marker left by an interrupted session so a normal backend
    # start returns to the default DB. Returns True if one was removed.
    marker = _marker_path()
    if marker.exists():
        marker.unlink()
        return True
    return False


def _await_backend_db(topo, cap_s: float) -> None:
# Poll until the backend reports it booted onto the benchmark DB, so the timeline never starts against the wrong database. On timeout it proceeds with a loud degraded warning.
    import urllib.request
    deadline = time.monotonic() + cap_s
    target = str(_resolve_db_path())
    while time.monotonic() < deadline:
        try:
            data = _fetch_backend_json(f"{topo.BACKEND_API}/api/db_path", timeout=2)
            if data.get("db_path") == target:
                print(f"BENCHMARK: backend confirmed on {target}")
                return
        except Exception:
            pass
        time.sleep(2)
    print("BENCHMARK: WARNING - backend not confirmed on the benchmark DB "
          f"within {int(cap_s)}s; survey data may not be separated. "
          "Restart the backend onto benchmark/benchmark.db.")


def _init_benchmark_db(db_path: Path) -> None:
# Create a fresh DB like the backend's own first boot (same folder autogeneration, WAL pragmas, full schema and migrations) via backend.database.db's schema code. This keeps the schema in sync, avoiding drift.
    db_path.parent.mkdir(parents=True, exist_ok=True)
    import sys
    root = str(_project_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    from backend.database import db as backend_db
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    backend_db._init_schema(conn)
    backend_db._migrate(conn)
    conn.commit()
    conn.close()
    # Under sudo the new dir/file are root-owned; give them back to the
    # invoking user so the backend (running unprivileged) can write them.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            rec = pwd.getpwnam(sudo_user)
            for target in (db_path.parent, db_path):
                os.chown(target, rec.pw_uid, rec.pw_gid)
        except Exception as e:
            print(f"BENCHMARK: ownership fixup warning: {e}")


def _reset_reputation_keep_offences(topo):
    # Roster sets hold host NUMBERS (hN); the backend schema keys rows by
    # src_ip strings, so convert via the topology's fixed 10.0.0.N mapping.
    scoped = {f"10.0.0.{n}" for n in
              (set(topo._ATTACKER_NUMS)
               | set(getattr(topo, "_RETIRED_NUMS", ()))
               | set(topo._LEGIT_NUMS))}
# Absolute path anchored to project root: the backend resolves its DB the same way, and a relative "logs/ddos.db" silently no-ops if CWD differs.
    db_path = _resolve_db_path()
    if not db_path.exists():
        print(f"BENCHMARK: no ddos.db at {db_path}; creating one with the "
              "backend schema (same as system first boot).")
        _init_benchmark_db(db_path)
    conn = sqlite3.connect(str(db_path)); conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # fewer write-lock contentions
    conn.execute("PRAGMA busy_timeout=5000")  # backend writer may hold the db
    try:
        conn.execute(f"""CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
            src_ip TEXT PRIMARY KEY, total_offences INTEGER DEFAULT 0,
            last_ban_level INTEGER DEFAULT 0, updated_at TEXT)""")
        rows = conn.execute(
            "SELECT src_ip, COUNT(*) n, MAX(ban_level) mb FROM ip_attack_history "
            "WHERE src_ip IN (%s) GROUP BY src_ip" % ",".join("?"*len(scoped)),
            list(scoped)).fetchall()
        for r in rows:
            conn.execute(
                f"INSERT INTO {LEDGER_TABLE}(src_ip,total_offences,last_ban_level,updated_at) "
                "VALUES(?,?,?,datetime('now')) ON CONFLICT(src_ip) DO UPDATE SET "
                "total_offences=total_offences+?, last_ban_level=MAX(last_ban_level,?), updated_at=datetime('now')",
                (r["src_ip"], r["n"], r["mb"], r["n"], r["mb"]))
        conn.commit()  # ledger committed BEFORE deletes
        conn.execute("DELETE FROM ip_attack_history WHERE src_ip IN (%s)"
                     % ",".join("?"*len(scoped)), list(scoped))
        # scoped: only reset our session's IPs, don't wipe unrelated state
        conn.execute("DELETE FROM quarantine_state WHERE src_ip IN (%s)"
                     % ",".join("?"*len(scoped)), list(scoped))
        conn.commit()  # incremental commit so a later failure keeps the ledger
    finally:
        conn.close()
# /api/cache/invalidate only clears the flow inference cache, not the writer/state_machine/sinkhole in-memory structures. The real reset must hit a dedicated endpoint that clears those so the next session is ground truth without a backend restart.
    _post_json(f"{topo.BACKEND_API}/api/admin/reset_reputation", {})
    print("BENCHMARK: reputation reset (DB rows + live backend caches); "
          "offences persisted in 'offence_totals'.")


def _clock_ticker(t0: float, duration_s: int, stop, interval_s: float = 5.0) -> None:
    # Live elapsed-clock heartbeat so the operator sees time move between
    # phase steps; single line updated in place every interval_s seconds.
    total_m, total_s = divmod(int(duration_s), 60)
    global _tick_active
    while not stop.wait(interval_s):
        elapsed = time.monotonic() - t0
        if elapsed >= duration_s:
            break
        m, s = divmod(int(elapsed), 60)
        with _tick_lock:
            print(f"\rBENCHMARK: T+{m:02d}:{s:02d} / {total_m:02d}:{total_s:02d}",
                  end="", flush=True)
            _tick_active = True


_tick_lock = threading.Lock()
_tick_active = False


def _status_print(msg: str) -> None:
    # Thread-safe status line that coexists with the ticker's in-place
    # updates: breaks the partial tick line first, then prints the message.
    global _tick_active
    with _tick_lock:
        print(("\n" if _tick_active else "") + msg, flush=True)
        _tick_active = False


def _iso_now() -> str:
    # Matches the backend mitigation_events timestamp format exactly so
    # window-exact TEXT comparison works lexicographically.
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _fire_phase(topo, kind: str, action):
    # Execute one phase action with no waiting. Split out so tests can
    # drive the timetable without spending wall-clock time.
    if kind == "wave":
        getattr(topo, _WAVES[action])()
        if action == "mixed":
            _log_tier_snapshot(topo)
    elif kind == "quiet":
        # calm window stops any lingering attacks (idempotent)
        topo.stop_all_attacks()
    # benign: nothing to start (baseline already running)


def _session_stats(db_path: Path, start_iso: str, end_iso: str) -> dict:
    # Window-exact per-session counts from the live table. Read-only,
    # never fatal: any failure returns zeros and the run continues.
    row = {"events": 0, "ips": 0, "det_ms": None, "mit_ms": None}
    try:
        conn = sqlite3.connect(str(db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            r = conn.execute(
                "SELECT COUNT(*) n, COUNT(DISTINCT src_ip) ips "
                "FROM mitigation_events WHERE timestamp BETWEEN ? AND ?",
                (start_iso, end_iso)).fetchone()
            row["events"], row["ips"] = r["n"], r["ips"]
            det = [x[0] for x in conn.execute(
                "SELECT detection_ms FROM mitigation_events "
                "WHERE timestamp BETWEEN ? AND ? AND detection_ms IS NOT NULL",
                (start_iso, end_iso)).fetchall()]
            mit = [x[0] for x in conn.execute(
                "SELECT mitigation_ms FROM mitigation_events "
                "WHERE timestamp BETWEEN ? AND ? AND mitigation_ms IS NOT NULL",
                (start_iso, end_iso)).fetchall()]
            if det:
                row["det_ms"] = round(statistics.median(det), 1)
            if mit:
                row["mit_ms"] = round(statistics.median(mit), 1)
        finally:
            conn.close()
    except Exception as e:
        print(f"BENCHMARK: session stats unavailable ({e})")
    return row


def _print_campaign_table(stats: list) -> None:
    # One row per session plus the cross-session median row.
    print("BENCHMARK: campaign results (per-session windows):")
    print("BENCHMARK: ses  events  ips   det_ms_med  mit_ms_med")
    dets = [s["det_ms"] for s in stats if s["det_ms"] is not None]
    mits = [s["mit_ms"] for s in stats if s["mit_ms"] is not None]
    for i, s in enumerate(stats, 1):
        print(f"BENCHMARK: {i:>3}  {s['events']:>6}  {s['ips']:>3}  "
              f"{str(s['det_ms']):>10}  {str(s['mit_ms']):>10}")
    if dets:
        print(f"BENCHMARK: median det_ms={statistics.median(dets)} "
              f"mit_ms={statistics.median(mits) if mits else None} "
              f"over {len(stats)} sessions")


def _run_single_session(topo, duration_s: int, calibration_gate,
                        reset_fn, session_idx: int, sessions: int) -> dict:
    # One 5:00 evaluated session with a hard stop at T+300. Returns the
    # wall-clock bounds for window-exact aggregation.
    tick_stop = threading.Event()
    bounds = {"start": _iso_now(), "end": None}
    try:
        calibration_gate(topo, cap_s=min(90.0, 0.25 * duration_s))
        t0 = time.monotonic()  # T_eval_start
        deadline = t0 + duration_s
        total_min, total_sec = divmod(int(duration_s), 60)
        threading.Thread(target=_clock_ticker,
                         args=(t0, duration_s, tick_stop),
                         name="benchmark-clock", daemon=True).start()

        def wait_until(target):
            target = min(target, deadline)
            while time.monotonic() < target:
                time.sleep(0.25)

        n = len(_PHASES_300)
        for i, (start_s, kind, action, _) in enumerate(_PHASES_300):
            if time.monotonic() >= deadline:
                break  # hard stop: a slow phase never stretches the session
            wait_until(t0 + start_s)
            emin, esec = divmod(int(start_s), 60)
            label = _PHASE_LABELS.get((kind, action), kind)
            _status_print(f"BENCHMARK: [session {session_idx}/{sessions}] "
                          f"[T+{emin:02d}:{esec:02d}/{total_min:02d}:{total_sec:02d}] "
                          f"step {i + 1}/{n}: {label}")
            try:
                _fire_phase(topo, kind, action)
                if kind == "quiet":
                    # clean-poll window so the mixed wave is true first detection
                    _clean_poll_gate(topo, t0 + 240)
            except Exception as e:
                # one bad wave must not abort the whole run
                _status_print(f"BENCHMARK: phase {kind}/{action} error ({e}); continuing")
            finally:
                # Re-echo the current status after the phase (noisy actions
                # bury it) so the newest line always shows the session state.
                nxt = _PHASES_300[i + 1][0] if i + 1 < n else duration_s
                nm, ns = divmod(int(nxt), 60)
                _status_print(f"BENCHMARK: (still on) step {i + 1}/{n}: "
                              f"{label} - next step at T+{nm:02d}:{ns:02d}")
    finally:
        # UNCONDITIONAL stop + reset on EVERY exit path.
        tick_stop.set()
        _status_print("BENCHMARK: session done; stopping attacks, resetting "
                      "reputation.")
        try:
            topo.stop_all_attacks()
        except Exception:
            pass
        try:
            reset_fn(topo)
        except Exception as e:
            print(f"BENCHMARK: reset warning: {e}")
        bounds["end"] = _iso_now()
    return bounds


def run(topo, net, hosts, duration_s: int = _SESSION_S, sessions: int = 5,
        calibration_gate=None, reset_fn=None, db_gate=None) -> None:
    # Timetable is fixed at 300 s per session; duration_s exists only so a
    # wrong value fails loudly instead of silently misscaling the clock.
    if duration_s != _SESSION_S and calibration_gate is None and reset_fn is None:
        raise ValueError("benchmark timetable is fixed at 300s per session")
    calibration_gate = calibration_gate or _default_calibration_gate
    reset_fn = reset_fn or _reset_reputation_keep_offences
    db_gate = db_gate or _await_backend_db
# DB switch: write the marker the backend reads at boot, then wait for the operator to restart the backend onto the benchmark DB before any counted traffic flows.
    _write_db_marker()
    _status_print("BENCHMARK: Restart the backend now so it boots onto "
                  "benchmark/benchmark.db; this run waits for confirmation.")
    stats = []
    try:
        # DB GATE FIRST, exception-safe and time-bounded, so the backend is
        # the right one before the calibration gate consumes its window.
        try:
            db_gate(topo, cap_s=min(90.0, 0.25 * _SESSION_S))
        except Exception as e:
            _status_print(f"BENCHMARK: db gate error ({e}); proceeding")
        for s in range(1, sessions + 1):
            _status_print(f"BENCHMARK: starting session {s}/{sessions}")
            bounds = _run_single_session(topo, _SESSION_S, calibration_gate,
                                         reset_fn, s, sessions)
            stats.append(_session_stats(_resolve_db_path(),
                                        bounds["start"], bounds["end"]))
            if s < sessions:
                # verify the reset left a clean backend before next session
                _clean_poll_gate(topo, time.monotonic() + 60)
        _print_campaign_table(stats)
    finally:
# Stop the restore-poller / baseline-watchdog loops first (they poll these Events) so they don't touch the hosts list while net.stop() tears it down.
        try:
            topo._RESTORE_POLLER_STOP.set()
            topo._BASELINE_WATCHDOG_STOP.set()
        except Exception:
            pass
        try:
            topo.stop_all_attacks()
        except Exception:
            pass
        # Marker removed last: the next normal backend start returns to
        # logs/ddos.db automatically, no env vars to remember.
        _remove_db_marker()
        _status_print("BENCHMARK: DB marker removed; restart the backend for "
                      "normal runs (it will boot back onto logs/ddos.db).")
        _status_print(f"BENCHMARK: session summary: {_SUMMARY}")
    raise SystemExit(0)
