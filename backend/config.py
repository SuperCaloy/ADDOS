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

# --- Simulation mode ---
SIMULATION_MODE = False

# --- Old SYN-only pre-filter (kept for backward compat, replaced by flood prefilter) ---
SYN_HALFOPEN_LIMIT  = 100
SYN_WINDOW_S        = 2.0

# --- Flood pre-filter (all protocols) ---
# Thresholds validated against Juniper Networks and Cisco ASA industry defaults.

FLOOD_SYN_LIMIT     = 1000
FLOOD_SYN_WINDOW_S  = 1.0

FLOOD_ICMP_LIMIT    = 1000
FLOOD_ICMP_WINDOW_S = 1.0

FLOOD_UDP_LIMIT     = 1000
FLOOD_UDP_WINDOW_S  = 1.0

# --- Temporal Entropy Analysis (TEA) ---
# Rolling window size per switch — adaptive thresholds learned from traffic
TEA_WINDOW_SIZE = 5
# All other TEA constants are adaptive — defined in entropy_analyzer.py

# --- API ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
IF_SCORE_THRESHOLD_OVERRIDE = None

# Minimum packet count — zero-packet flows are always dropped
MIN_FLOW_PKTS_FOR_INFERENCE = 0

# --- UI batching ---
UI_BATCH_INTERVAL_S = 0.5

# --- Graph history ---
GRAPH_BUCKET_COUNT = 60