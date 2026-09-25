# Regenerate per session report PDFs from frozen session DB copies.
# Read only on evidence: each frozen benchmark.db is copied to a temp file,
# the temp copy is migrated and queried, originals are never written.
# Usage: python3 scripts/regen_session_pdfs.py [SYN|UDP|ICMP|Mixed] [session_dir...]
import json
import os
import shutil
import sqlite3
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import backend.database.db as db
from backend.api import report as report_mod


def _rows_for_window(start_iso: str, end_iso: str) -> list:
    rows = db.query("""
        SELECT timestamp, src_ip, predicted_class, attack_vector,
               confidence, priority, action_taken, is_manual
        FROM mitigation_events
        WHERE timestamp >= ? AND timestamp <= ?
        UNION ALL
        SELECT timestamp, src_ip, predicted_class, attack_vector,
               confidence, priority, action_taken, is_manual
        FROM mitigation_events_archive
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC
    """, (start_iso, end_iso, start_iso, end_iso))
    return rows


def regen_session(session_dir: str) -> str:
    with open(os.path.join(session_dir, "session.json")) as fh:
        sidecar = json.load(fh)
    bounds = sidecar.get("bounds", {})
    start_iso, end_iso = bounds["start"], bounds["end"]
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    shutil.copy2(os.path.join(session_dir, "benchmark.db"), tmp.name)
    db.DB_PATH = tmp.name
    db._conn = None
    try:
        rows = _rows_for_window(start_iso, end_iso)
        pdf_bytes = report_mod._build_pdf(start_iso, end_iso, rows)
        out = os.path.join(session_dir, "report.pdf")
        with open(out, "wb") as fh:
            fh.write(pdf_bytes)
        counts = db.query(
            "SELECT SUM(if_tp), SUM(if_fn), SUM(rf_fn) FROM traffic_summary "
            "WHERE timestamp >= ? AND timestamp <= ?",
            (start_iso, end_iso))
        return f"{session_dir}: {len(pdf_bytes)} bytes, rows={len(rows)}, sums={counts[0] if counts else None}"
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def main() -> None:
    only_type = sys.argv[1] if len(sys.argv) > 1 else None
    explicit = sys.argv[2:] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else None
    if only_type in ("SYN", "UDP", "ICMP", "Mixed") and not explicit:
        bases = [os.path.join(REPO, "benchmark", f"{only_type}_Benchmark")]
    else:
        bases = [os.path.join(REPO, "benchmark", d) for d in
                 ("SYN_Benchmark", "UDP_Benchmark", "ICMP_Benchmark", "Mixed_Benchmark")]
    targets = []
    if explicit:
        targets = explicit
    else:
        for base in bases:
            if not os.path.isdir(base):
                continue
            for name in sorted(os.listdir(base)):
                if not name.startswith("Session_"):
                    continue
                full = os.path.join(base, name)
                if (os.path.isfile(os.path.join(full, "benchmark.db"))
                        and os.path.isfile(os.path.join(full, "session.json"))):
                    targets.append(full)
    ok, failed = 0, []
    for target in targets:
        try:
            print(regen_session(target), flush=True)
            ok += 1
        except Exception as exc:  # keep going, report at the end
            failed.append((target, repr(exc)))
            print(f"{target}: FAILED {exc!r}", flush=True)
    print(f"done: {ok} ok, {len(failed)} failed")
    for target, err in failed:
        print(f"  FAIL {target}: {err}")


if __name__ == "__main__":
    main()
