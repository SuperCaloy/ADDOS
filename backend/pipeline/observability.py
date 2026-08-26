import logging
import threading
import time

from backend.pipeline import worker
from backend.pipeline import decision_engine

log = logging.getLogger(__name__)


def build_snapshot() -> dict:
    return {
        "detection_ms": decision_engine.latency_percentiles(),
        "queue_depth": worker.get_queue_depth(),
        "drops": worker.get_drop_counters(),
    }


def _loop(interval_s: float) -> None:
    while True:
        time.sleep(interval_s)
        try:
            snap = build_snapshot()
            dms = snap["detection_ms"]
            log.info(
                "[OBS] detection_ms p50=%.1f p95=%.1f p99=%.1f n=%d | "
                "queue=%d | drops=%s",
                dms["p50"], dms["p95"], dms["p99"], dms["n"],
                snap["queue_depth"], snap["drops"],
            )
        except Exception:
            log.exception("Observability snapshot failed")


def start(interval_s: float = 10.0) -> None:
    t = threading.Thread(target=_loop, args=(interval_s,),
                         name="observability", daemon=True)
    t.start()
    log.info("Observability reporter started (interval=%ss)", interval_s)
