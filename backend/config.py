import os

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# -- Model asset paths ------------------------------------------------------
IF_DIR  = os.path.join(_ROOT, "models", "isolation_forest")
RF_DIR  = os.path.join(_ROOT, "models", "random_forest")

IF_MODEL_PATH     = os.path.join(IF_DIR, "isolation_forest.pkl")
IF_SCALER_PATH    = os.path.join(IF_DIR, "scaler.pkl")
IF_QUANTILER_PATH = os.path.join(IF_DIR, "quantiler.pkl")
IF_CONTRACT_PATH  = os.path.join(IF_DIR, "feature_contract.json")

RF_MODEL_PATH    = os.path.join(RF_DIR, "random_forest_final.pkl")
RF_SCALER_PATH   = os.path.join(RF_DIR, "scaler.pkl")
RF_CONTRACT_PATH = os.path.join(RF_DIR, "rf_feature_contract.json")
RF_ENCODER_PATH  = os.path.join(RF_DIR, "label_encoder.pkl")

# -- Database ---------------------------------------------------------------
# Resolved via DDOS_DB_PATH, marker file, or default logs/ddos.db.
MARKER_PATH = (os.environ.get("DDOS_DB_MARKER")
               or os.path.join(_ROOT, "benchmark", "DB_TARGET"))


def _resolve_db_path() -> str:
    env = os.environ.get("DDOS_DB_PATH")
    if env:
        return env
    try:
        with open(MARKER_PATH) as f:
            target = f.read().strip()
        if target:
            return target if os.path.isabs(target) else os.path.join(_ROOT, target)
    except OSError:
        pass
    return os.path.join(_ROOT, "logs", "ddos.db")


DB_PATH = _resolve_db_path()

# -- Whitelist & Flow Epoch Constants ---------------------------------------
WHITELIST_IPS = {"10.0.0.26", "10.0.0.27"}
FLOW_EPOCH_S = 600

# -- ZeroMQ -----------------------------------------------------------------
ZMQ_TELEMETRY_ADDR = "tcp://127.0.0.1:5555"
ZMQ_COMMAND_ADDR   = "tcp://127.0.0.1:5556"

# -- Pipeline tuning --------------------------------------------------------
FLOW_TRACKER_CAP        = 500
INFERENCE_CACHE_TTL_S   = 1.0
WORKER_QUEUE_MAXSIZE    = 500
WORKER_ITEM_TIMEOUT_S   = 3.0
EXTRACTION_TRIGGER_PKTS = 1
EXTRACTION_TRIGGER_S    = 0.05

# -- RF/IF micro-batching ---------------------------------------------------
RF_BATCH_ENABLED   = True
RF_BATCH_MAX       = 16
RF_BATCH_WINDOW_MS = 10

IF_BATCH_ENABLED   = True
IF_BATCH_MAX       = 16
IF_BATCH_WINDOW_MS = 10

# -- Admission control ------------------------------------------------------
ADMISSION_CONTROL_ENABLED   = True
WORKER_ADMISSION_DEPTH      = 600
DEADLINE_ADMISSION_ENABLED  = True
DEADLINE_ADMISSION_MARGIN_S = 0.2
SVC_EMA_ALPHA               = 0.5
SVC_EMA_FALLBACK_MS         = 40.0

HOTPATH_QUIET = False
SIMULATION_MODE = True
ML_ENABLED = True
INFERENCE_SUBPROCESS_ENABLED = False

# -- Flood pre-filter -------------------------------------------------------
FLOOD_SYN_LIMIT     = 100
FLOOD_SYN_WINDOW_S  = 1.0

FLOOD_ICMP_LIMIT    = 50
FLOOD_ICMP_WINDOW_S = 1.0

FLOOD_UDP_LIMIT     = 50
FLOOD_UDP_WINDOW_S  = 1.0

# -- Temporal Entropy Analysis (TEA) ----------------------------------------
TEA_WINDOW_SIZE = 500
TEA_LEARN_MIN_SAMPLES = 300
TEA_LEARN_MIN_MEAN_PPS = 0.1
TEA_LEARN_CAP_FLOOR_PPS = 10.0
TEA_LEARN_CAP_FACTOR = 5.0
TEA_LEARN_VARIANCE_WINDOW_SIZE = 50
TEA_WARMUP_REJECT_FACTOR = 5.0

# -- TEA dual feedback hysteresis -------------------------------------------
TEA_IF_UNLOCK_STREAK = 5
TEA_TEA_LOCK_STREAK = 3
TEA_TEA_UNLOCK_STREAK = 60
TEA_TEA_HIGH_CONF_LOCK = True
TEA_IDLE_UNLOCK_S = 30.0
TEA_MIN_FLOWS_PER_INTERVAL = 5
TEA_IP_PROFILE_TTL_S = 60

# -- TEA uniformity gating --------------------------------------------------
TEA_UNIFORM_SHARE_SIGMA = 2.0
TEA_MECHANIZED_MIN_UNIFORM_SHARE = 0.9
TEA_UNIFORM_BACKSTOP_SHARE = 0.95
TEA_UNIFORM_BACKSTOP_MIN_IPS = 20
TEA_PPS_SURGE_SIGMA = 2.0

# -- TEA supervised relearn -------------------------------------------------
TEA_RELEARN_STABLE_INTERVALS = 8
TEA_RELEARN_MAX_DRIFT_FRAC = 0.01
TEA_RELEARN_ALPHA = 0.15
TEA_RELEARN_MIN_CONFIDENCE = "moderate"
TEA_RELEARN_MAX_IF_ANOMALY_RATE = 0.3
TEA_RELEARN_MAX_CUMULATIVE_DRIFT = 0.20
TEA_HIGH_CONFIDENCE_INTERVALS = 3
TEA_RELEARN_BASELINE_DISTANCE_MAX = 2.0
TEA_LATCH_MAX_HOLD_S = 90.0
TEA_EXTREME_Z_SIGMA = 50.0
TEA_EXTREME_Z_RESTART_INTERVALS = 60
TEA_LATCH_HOLD_IF_GRACE_S = 30.0
TEA_IF_RATE_WINDOW = 20
TEA_IF_ANOMALY_RATE_BLOCK = 0.3
TEA_EVAL_SEQ_MAX_JUMP = 1000

# -- TEA Shadow Baseline ----------------------------------------------------
TEA_SHADOW_ENABLED = True
TEA_SHADOW_MIN_SAMPLES = 60
TEA_SHADOW_MAX_AGE_S = 120.0
TEA_SHADOW_PROMOTE_MIN_CONFIDENCE = "moderate"

# -- TEA detection thresholds -----------------------------------------------
TEA_MIN_STD_FLOOR = 0.10
TEA_SURGE_MIN_MAGNITUDE = 2.0
TEA_ATTACK_SIGMA = 2.5
TEA_CROWD_SIGMA = 1.5
TEA_EMA_ALPHA_MIN = 0.02
TEA_EMA_ALPHA_MAX = 0.10
TEA_ROBUST_REJECT_SIGMA = 3.5

# -- TEA flash crowd guidance -----------------------------------------------
TEA_FLASH_CROWD_IF_THRESHOLD = 0.3
TEA_FLASH_CROWD_IF_BUFFER_SIZE = 50

TEA_TEMPORAL_WINDOW_SIZE = 50
TEA_TEMPORAL_ENTROPY_BINS = 10

TEA_MAHALANOBIS_ATTACK_THRESHOLD = 5.0
TEA_MAHALANOBIS_CROWD_THRESHOLD = 3.0
TEA_MAHALANOBIS_HISTORY_SIZE = 100

FLOW_FIELD_MAX = 1e9

# -- API & Frontend ---------------------------------------------------------
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
UI_BATCH_INTERVAL_S = 0.5
GRAPH_BUCKET_COUNT = 60