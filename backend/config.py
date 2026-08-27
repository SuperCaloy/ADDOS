import os

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# --- Model asset paths ---
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

# --- Database ---
DB_PATH = os.path.join(_ROOT, "logs", "ddos.db")

# --- ZeroMQ ---
ZMQ_TELEMETRY_ADDR = "tcp://127.0.0.1:5555"   # Ryu PUSH → Backend PULL
ZMQ_COMMAND_ADDR   = "tcp://127.0.0.1:5556"   # Backend PUSH → Ryu PULL

# --- Pipeline tuning ---
FLOW_TRACKER_CAP        = 500
INFERENCE_CACHE_TTL_S   = 1.0
WORKER_QUEUE_MAXSIZE    = 1000
WORKER_ITEM_TIMEOUT_S   = 3.0
EXTRACTION_TRIGGER_PKTS = 1
EXTRACTION_TRIGGER_S    = 0.05

# --- RF micro-batching (B1) ---
RF_BATCH_ENABLED  = True
RF_BATCH_MAX      = 16
RF_BATCH_WINDOW_MS = 50

# --- IF micro-batching (L1, conservative default off like B1 originally) ---
IF_BATCH_ENABLED  = True
IF_BATCH_MAX      = 16
IF_BATCH_WINDOW_MS = 50

# --- Worker admission control (V2) ---
ADMISSION_CONTROL_ENABLED = True
WORKER_ADMISSION_DEPTH    = 600   # PLACEHOLDER, no measured basis; see risk register

# --- Deadline-based admission (R3b, default off; measurement plan sec 12) ---
# While enabled, the deadline check replaces the static depth check:
# refuse when qsize * svc_ema / workers exceeds WORKER_ITEM_TIMEOUT_S - margin.
DEADLINE_ADMISSION_ENABLED = True
DEADLINE_ADMISSION_MARGIN_S = 0.5
SVC_EMA_ALPHA      = 0.5
SVC_EMA_FALLBACK_MS = 40.0  # near measured calm mean (38 ms); documented warmup

# --- Hot-path quiet mode (V3) ---
HOTPATH_QUIET = False

# --- Simulation mode ---
SIMULATION_MODE = True

# --- ML Engine toggle ---
ML_ENABLED = True

# --- Flood pre-filter
FLOOD_SYN_LIMIT     = 100
FLOOD_SYN_WINDOW_S  = 1.0

FLOOD_ICMP_LIMIT    = 50
FLOOD_ICMP_WINDOW_S = 1.0

FLOOD_UDP_LIMIT     = 50
FLOOD_UDP_WINDOW_S  = 1.0

# --- Temporal Entropy Analysis (TEA) ---
# Rolling window size per switch — adaptive thresholds learned from traffic
TEA_WINDOW_SIZE = 10

# --- TEA dual feedback hysteresis ---
# IF side: per-flow, streak-only, NEVER locks baselines by itself.
# Isolated anomalies halve the streak (decay) instead of zeroing it.
TEA_IF_UNLOCK_STREAK = 5
# TEA side: counts eval intervals (~0.5s each), not flows.
TEA_TEA_LOCK_STREAK = 3               # consecutive attack intervals to latch
TEA_TEA_UNLOCK_STREAK = 100           # consecutive normal intervals (~50s) to unlatch
TEA_TEA_HIGH_CONF_LOCK = True         # single "high" confidence interval latches instantly
TEA_IDLE_UNLOCK_S = 30.0              # attack-free time that force-unlocks during silence
# Degenerate interval guard: skip verdict + learning below this flow count
TEA_MIN_FLOWS_PER_INTERVAL = 5
# Per-IP profile expiry
TEA_IP_PROFILE_TTL_S = 300

# --- API ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# --- UI batching ---
UI_BATCH_INTERVAL_S = 0.5

# --- Graph history ---
GRAPH_BUCKET_COUNT = 60