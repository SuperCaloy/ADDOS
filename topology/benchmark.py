"""Topology-side 60-minute benchmark mode.

Imports no topology code (no __init__.py in topology/). All helpers are
passed in via the topology module object by topology.py.
"""
import time
import os
import threading
import sqlite3
import json
import urllib.request
from pathlib import Path

# fractions of the 60-minute evaluated window (T_eval_start relative)
_PHASES = [   # (start_frac, kind, action)
    (0/60,  "soak",    None),                       # T+0-4   baseline soak
    (4/60,  "probe",   "flash"),                    # T+4-6   flash-crowd FP probe
    (6/60,  "settle",  None),                       # T+6-9   settle/confirm
    (9/60,  "wave",    "syn"),                      # T+9-15  SYN wave
    (15/60, "quiet",   None),                       # T+15-19 quiet
    (19/60, "wave",    "icmp"),                     # T+19-25 ICMP wave
    (25/60, "quiet",   None),                       # T+25-29 quiet
    (29/60, "wave",    "udp"),                      # T+29-35 UDP wave
    (35/60, "quiet",   None),                       # T+35-39 quiet
    (39/60, "wave",    "mixed_a"),                  # T+39-47 Mixed wave A
    (47/60, "quiet",   None),                       # T+47-51 quiet
    (51/60, "wave",    "mixed_b"),                  # T+51-57 Mixed wave B
    (57/60, "recover", None),                       # T+57-60 recovery
]
_WAVES = {"syn": "start_syn_flood_campaign",
          "icmp": "start_icmp_flood_campaign",
          "udp": "start_udp_flood_campaign",
          "mixed_a": "start_mixed_campaign",
          "mixed_b": "start_mixed_campaign"}

# Human-readable per-step labels shown in the operator progress output.
_PHASE_LABELS = {
    ("soak",    None):      "baseline soak (benign-only, FPR reference)",
    ("probe",   "flash"):   "flash-crowd FP probe (2 min, clean state)",
    ("settle",  None):      "settle/confirm (waiting for empty quarantine)",
    ("wave",    "syn"):     "SYN wave (4 SYN attackers)",
    ("wave",    "icmp"):    "ICMP wave (3 ICMP attackers)",
    ("wave",    "udp"):     "UDP wave (3 UDP attackers)",
    ("wave",    "mixed_a"): "mixed wave A (all 10, staged SYN/UDP/ICMP)",
    ("wave",    "mixed_b"): "mixed wave B (all 10, repeat offenders)",
    ("quiet",   None):      "quiet window (attacks stopped, ban-expiry evidence)",
    ("recover", None):      "recovery observation (final settle)",
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
            with urllib.request.urlopen(f"{topo.BACKEND_API}/api/expert/live",
                                        timeout=2) as r:
                data = json.load(r)
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
            with urllib.request.urlopen(f"{topo.BACKEND_API}/api/expert/live",
                                        timeout=2) as r:
                data = json.load(r)
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
        with urllib.request.urlopen(f"{topo.BACKEND_API}/api/stats",
                                    timeout=2) as r:
            data = json.load(r)
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
    return Path(__file__).resolve().parents[1] / "benchmark" / "benchmark.db"


def _marker_path():
    # Same marker file backend.config reads at boot; local fallback keeps
    # this module importable even if backend code is unavailable.
    try:
        from backend.config import MARKER_PATH
        return Path(MARKER_PATH)
    except Exception:
        return Path(__file__).resolve().parents[1] / "benchmark" / "DB_TARGET"


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
            with urllib.request.urlopen(f"{topo.BACKEND_API}/api/db_path",
                                        timeout=2) as r:
                if json.load(r).get("db_path") == target:
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
    root = str(Path(__file__).resolve().parents[1])
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


def run(topo, net, hosts, duration_s: int = 3600,
        calibration_gate=None, reset_fn=None, db_gate=None) -> None:
    if duration_s < 600 and calibration_gate is None and reset_fn is None:
# Mixed-wave vector staging is fixed at ~10s, so shorter runs overlap and the ICMP wave never gets its turn. Require a sane floor unless the caller injects test doubles.
        raise ValueError("benchmark needs duration_s >= 600s")
    calibration_gate = calibration_gate or _default_calibration_gate
    reset_fn = reset_fn or _reset_reputation_keep_offences
    db_gate = db_gate or _await_backend_db
# DB switch: write the marker the backend reads at boot, then wait for the operator to restart the backend onto the benchmark DB before any counted traffic flows.
    _write_db_marker()
    _status_print("BENCHMARK: Restart the backend now so it boots onto "
                  "benchmark/benchmark.db; this run waits for confirmation.")
    tick_stop = threading.Event()
    try:
        # DB GATE FIRST, exception-safe and time-bounded, so the backend is
        # the right one before the calibration gate consumes its window.
        try:
            db_gate(topo, cap_s=min(90.0, 0.25 * duration_s))
        except Exception as e:
            _status_print(f"BENCHMARK: db gate error ({e}); proceeding")
        try:
            calibration_gate(topo, cap_s=min(90.0, 0.25 * duration_s))
        except Exception as e:
            _status_print(f"BENCHMARK: calibration gate error ({e}); proceeding degraded")

        t0 = time.monotonic()  # T_eval_start
        total_min, total_sec = divmod(int(duration_s), 60)
        threading.Thread(target=_clock_ticker,
                         args=(t0, duration_s, tick_stop),
                         name="benchmark-clock", daemon=True).start()
        def at(frac):
            return t0 + frac * duration_s
        def wait_until(target):
            while time.monotonic() < target:
                time.sleep(0.25)

        for i, (start_frac, kind, action) in enumerate(_PHASES):
            wait_until(at(start_frac))
            # Per-step progress so the operator always knows the current step
            # and its position on the eval clock while the session runs.
            emin, esec = divmod(int(round(start_frac * duration_s)), 60)
            label = _PHASE_LABELS.get((kind, action), kind)
            _status_print(f"BENCHMARK: [T+{emin:02d}:{esec:02d}/{total_min:02d}:{total_sec:02d}] "
                          f"step {i + 1}/{len(_PHASES)}: {label}")
            try:
                if kind == "probe":
                    topo._WATCHDOG_SUPPRESS.set()
                    try:
                        topo.flash_crowd(duration=int((2/60) * duration_s))
                    finally:
                        t = threading.Timer((2/60) * duration_s + 5,
                                            topo._WATCHDOG_SUPPRESS.clear)
                        t.daemon = True  # never block process exit
                        t.start()
                elif kind == "wave":
                    getattr(topo, _WAVES[action])()
                    if action == "mixed_b":
                        _log_tier_snapshot(topo)
                elif kind in ("quiet", "settle", "recover"):
                    # every calm window stops any lingering attacks (idempotent)
                    topo.stop_all_attacks()
                    if kind == "settle":
                        # clean-poll window so the SYN wave is a true first detection
                        _clean_poll_gate(topo, at(9/60))
                # soak: nothing to start (baseline already running)
            except Exception as e:
                # one bad wave must not abort the whole run
                _status_print(f"BENCHMARK: phase {kind}/{action} error ({e}); continuing")
            finally:
# Re-echo the current status after the phase (noisy actions like stop_all_attacks bury it) so the newest line always shows where the session is.
                nxt_frac = _PHASES[i + 1][0] if i + 1 < len(_PHASES) else 1.0
                nm, ns = divmod(int(round(nxt_frac * duration_s)), 60)
                _status_print(f"BENCHMARK: (still on) step {i + 1}/{len(_PHASES)}: "
                              f"{label} - next step at T+{nm:02d}:{ns:02d}")
    finally:
# UNCONDITIONAL final stop + reset on EVERY exit path. Stop the restore-poller / baseline-watchdog loops first (they poll these Events) so they don't touch the hosts list while net.stop() tears it down.
        tick_stop.set()
        _status_print("BENCHMARK: all steps done; stopping attacks, resetting "
                      "reputation, then auto-exit.")
        try:
            topo._RESTORE_POLLER_STOP.set()
            topo._BASELINE_WATCHDOG_STOP.set()
        except Exception:
            pass
        try:
            topo.stop_all_attacks()
        except Exception:
            pass
        try:
            reset_fn(topo)
        except Exception as e:
            print(f"BENCHMARK: reset warning: {e}")
        # Marker removed last: the next normal backend start returns to
        # logs/ddos.db automatically, no env vars to remember.
        _remove_db_marker()
        _status_print("BENCHMARK: DB marker removed; restart the backend for "
                      "normal runs (it will boot back onto logs/ddos.db).")
        _status_print(f"BENCHMARK: session summary: {_SUMMARY}")
    raise SystemExit(0)
