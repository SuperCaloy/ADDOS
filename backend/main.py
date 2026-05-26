import logging
import threading
import time
import os

from flask import Flask
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    # --- Load all model files and JSON contracts once ---
    from backend.models import loader
    loader.load_all()
    log.info("Models loaded. IF threshold=%.6f  RF conf_gate=%.2f",
             loader.if_threshold, loader.rf_conf_gate)

    # --- Initialise database (creates tables if missing) ---
    from backend.database.db import get_connection
    get_connection()
    log.info("Database ready")

    # --- Wire commander into state machine ---
    from backend.mitigation.zmq_commander import commander
    from backend.mitigation.state_machine import state_machine, start_tick_thread
    from backend.mitigation.deception import deception
    from backend.mitigation.resource_guard import resource_guard

    state_machine.set_commander(commander)

    # Wire deception module — must happen before start_tick_thread
    deception.set_commander(commander)
    deception.set_callbacks(
        escalate_fn = lambda src_ip, if_score, attack_vector, confidence: (
            state_machine.on_detection(src_ip, if_score, attack_vector, confidence)
        ),
        release_fn  = lambda src_ip: log.info("Deception: released %s", src_ip),
    )
    state_machine.set_deception(deception)

    start_tick_thread()
    log.info("State machine started")

    # Wire resource_guard — monitors CPU/memory, clears entries under strain
    resource_guard.set_state_machine(state_machine)
    resource_guard.set_deception(deception)
    resource_guard.start()
    log.info("Resource guard started")

    # --- Start pipeline worker + decision engine ---
    from backend.pipeline import decision_engine
    decision_engine.start()

    # --- Start ZMQ telemetry receiver (resilient — ok if Ryu is offline) ---
    from backend.transport import zmq_receiver
    zmq_receiver.start()

    # --- Start database summary flush thread ---
    from backend.database.writer import start_flush_thread
    start_flush_thread()

    # --- Start database archiver (hot → archive rotation every hour) ---
    from backend.database import archiver
    archiver.start()

    # --- Register API blueprints ---
    from backend.api.stats     import bp as stats_bp
    from backend.api.graph     import bp as graph_bp
    from backend.api.events    import bp as events_bp
    from backend.api.quarantine import bp as quarantine_bp
    from backend.api.report    import bp as report_bp

    app.register_blueprint(stats_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(quarantine_bp)
    app.register_blueprint(report_bp)

    log.info("All API blueprints registered")
    return app


if __name__ == "__main__":
    from backend.config import FLASK_HOST, FLASK_PORT
    app = create_app()
    # threaded=True required for SSE streaming to work alongside other endpoints
    app.run(host=FLASK_HOST, port=FLASK_PORT, threaded=True, debug=False)