"""Recompute pooled traffic_summary counters for one SQLite database.

Read only. Never writes to the database. Prints the SQL text, the source
path, and SUM(if_tp, if_fn, if_fp, if_tn, rf_tp, rf_fn) grouped output.

Usage:
    python3 scripts/recompute_pooled_tables.py <path-to-db>
"""

import argparse
import sqlite3
import sys
from pathlib import Path

POOLED_SQL = """\
SELECT
    date(timestamp) AS day,
    SUM(if_tp) AS sum_if_tp,
    SUM(if_fn) AS sum_if_fn,
    SUM(if_fp) AS sum_if_fp,
    SUM(if_tn) AS sum_if_tn,
    SUM(rf_tp) AS sum_rf_tp,
    SUM(rf_fn) AS sum_rf_fn
FROM traffic_summary
GROUP BY date(timestamp)
ORDER BY day;
"""

TOTAL_SQL = """\
SELECT
    SUM(if_tp) AS sum_if_tp,
    SUM(if_fn) AS sum_if_fn,
    SUM(if_fp) AS sum_if_fp,
    SUM(if_tn) AS sum_if_tn,
    SUM(rf_tp) AS sum_rf_tp,
    SUM(rf_fn) AS sum_rf_fn
FROM traffic_summary;
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", help="Path to a benchmark.db or fixture .db file")
    args = parser.parse_args(argv)

    source = Path(args.db_path)
    print("source_path: " + str(source))
    print("--- pooled_sql ---")
    print(POOLED_SQL.strip())
    print("--- total_sql ---")
    print(TOTAL_SQL.strip())

    if not source.is_file():
        print("error: file not found: " + str(source), file=sys.stderr)
        return 1

    conn = sqlite3.connect("file:" + str(source.resolve()) + "?mode=ro", uri=True)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if "traffic_summary" not in tables:
            print("error: traffic_summary table missing", file=sys.stderr)
            return 1
        print("--- grouped_by_day ---")
        for row in conn.execute(POOLED_SQL):
            print(row)
        print("--- grand_total ---")
        print(conn.execute(TOTAL_SQL).fetchone())
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
