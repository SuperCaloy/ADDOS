#!/usr/bin/env bash
# show_report.sh: point the backend at the benchmark DB for report viewing.
# Writes benchmark/DB_TARGET (the backend reads it at boot), then restores
# normal mode on exit so everyday runs go back to logs/ddos.db.
#
# Usage:
#   ./benchmark/show_report.sh                 # instructions, you restart the backend
#   SHOW_REPORT_BACKEND_CMD="python3 backend/main.py" ./benchmark/show_report.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKER="$ROOT/benchmark/DB_TARGET"
DB_FILE="$ROOT/benchmark/benchmark.db"
BACKEND_CMD="${SHOW_REPORT_BACKEND_CMD:-}"

if [ ! -f "$DB_FILE" ]; then
    echo "SHOW-REPORT: benchmark DB not found at $DB_FILE - nothing to report yet."
    echo "SHOW-REPORT: run 'py run_benchmark()' first."
    exit 1
fi

cleanup() {
    rm -f "$MARKER"
    echo ""
    echo "SHOW-REPORT: marker removed. Restart the backend for normal runs (it boots back onto logs/ddos.db)."
}
trap cleanup EXIT INT TERM

echo "$DB_FILE" > "$MARKER"
echo "SHOW-REPORT: marker written; a backend started now boots onto benchmark/benchmark.db."
echo "SHOW-REPORT: open the dashboard REPORT page, pick the benchmark session date, and"
echo "SHOW-REPORT: download the PDF. The report reads ONLY benchmark data while the marker exists."

if [ -n "$BACKEND_CMD" ]; then
    echo "SHOW-REPORT: starting backend: $BACKEND_CMD (Ctrl-C it when done viewing)."
    eval "$BACKEND_CMD"
else
    echo "SHOW-REPORT: restart the backend now in your own terminal."
    printf "SHOW-REPORT: press Enter here when done viewing to restore normal mode... "
    read -r _
fi
