# Flask application factory and service dependency injection coordinator.
# Boots database connections, loads ML models, wires controllers, and registers API routes.

import logging

from flask import Flask
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger(__name__)


def create_app() -> Flask:
    # Initializes and wires all backend components into a cohesive Flask application.
    # Configures CORS, loads ML contracts, boots telemetry workers, and registers blueprints.
    app = Flask(__name__)
    CORS(app)

    # Load all model files and JSON contracts once
    from backend.models import loader
    loader.load_all()
    log.info("Models loaded. IF threshold=%.6f  RF conf_gate=%.2f",
             loader.if_threshold, loader.rf_conf_gate)

    # Initialise database connection and schema tables
    from backend.database.db import get_connection
    get_connection()
    log.info("Database ready")

    # Wire commander into state machine and deception subsystems
    from backend.mitigation.zmq_commander import commander
    from backend.mitigation.state_machine import state_machine, start_tick_thread
    from backend.mitigation.deception import deception
    from backend.mitigation.resource_guard import resource_guard

    state_machine.set_commander(commander)

    # Restore persisted permanent states across backend restarts
    state_machine.restore_from_db()

    # Wire deception module callbacks before starting tick thread
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

    # Wire resource guard to monitor memory pressure and throttle queues
    resource_guard.start()
    log.info("Resource guard started")

    # Start system monitor polling CPU, memory, and PPS metrics
    from backend.mitigation import monitor
    monitor.start()

    # Start pipeline worker and decision engine
    from backend.pipeline import decision_engine
    decision_engine.start()

    # Start observability reporter for latency percentiles and queues
    from backend.pipeline import observability
    observability.start()

    # Start ZMQ telemetry receiver from Ryu controller
    from backend.transport import zmq_receiver
    zmq_receiver.start()

    # Start database summary flush thread
    from backend.database.writer import start_flush_thread, register_exit_flush
    start_flush_thread()
    register_exit_flush()

    # Start database archiver for hourly history rotation
    from backend.database import archiver
    archiver.start()

    # --- Register API blueprints ---
    from backend.api.stats     import bp as stats_bp
    from backend.api.ip_detail  import bp as ip_detail_bp
    from backend.api.graph     import bp as graph_bp
    from backend.api.events    import bp as events_bp
    from backend.api.mitigation import bp as quarantine_bp
    from backend.api.report    import bp as report_bp
    from backend.api.expert    import bp as expert_bp

    app.register_blueprint(stats_bp)
    app.register_blueprint(ip_detail_bp)
    app.register_blueprint(graph_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(quarantine_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(expert_bp)

    log.info("All API blueprints registered")
    return app


if __name__ == "__main__":
    import atexit
    from backend.config import FLASK_HOST, FLASK_PORT
    app = create_app()

    def _shutdown_inference():
        try:
            from backend.pipeline.inference_process import inference_process
            inference_process.stop()
        except Exception:
            pass
    atexit.register(_shutdown_inference)

    # threaded=True required for SSE streaming to work alongside other endpoints
    app.run(host=FLASK_HOST, port=FLASK_PORT, threaded=True, debug=False)