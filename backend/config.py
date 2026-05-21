import os

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# --- Model asset paths ---
IF_DIR  = os.path.join(_ROOT, "models", "isolation_forest")
RF_DIR  = os.path.join(_ROOT, "models", "random_forest")

IF_MODEL_PATH    = os.path.join(IF_DIR, "isolation_forest.pkl")
IF_SCALER_PATH   = os.path.join(IF_DIR, "scaler.pkl")
IF_CONTRACT_PATH = os.path.join(IF_DIR, "feature_contract.json")

RF_MODEL_PATH    = os.path.join(RF_DIR, "random_forest_sdn_final.pkl")
RF_SCALER_PATH   = os.path.join(RF_DIR, "scaler.pkl")
RF_CONTRACT_PATH = os.path.join(RF_DIR, "rf_sdn_feature_contract.json")
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
# Each protocol has its own packet count limit and time window.
# When a src_ip hits the limit within the window it gets flagged immediately
# without waiting for the stats poll — this is what fixes slow UDP detection.

# SYN: keep same as before
FLOOD_SYN_LIMIT     = 100
FLOOD_SYN_WINDOW_S  = 2.0

# ICMP: lower limit because ICMP floods are high volume but easy to spot
FLOOD_ICMP_LIMIT    = 100
FLOOD_ICMP_WINDOW_S = 2.0

# UDP: lower limit so it trips fast before the 1s stats poll fires
# set to 30 so it is reachable within the controller rate limit window
FLOOD_UDP_LIMIT     = 60
FLOOD_UDP_WINDOW_S  = 2.0

# --- Temporal Entropy Analysis (TEA) ---
# How many polling intervals to keep in the rolling window per switch
TEA_WINDOW_SIZE     = 5

# Minimum entropy drop in IP diversity to consider it suspicious
# Normal flash crowd keeps high IP diversity so this stays low
# DDoS from few IPs collapses diversity — delta goes negative and large
TEA_DIVERSITY_DROP_THRESHOLD  = 0.4

# Minimum entropy rise in packet rate to consider it suspicious
# DDoS floods push packet rate entropy up sharply across all sources
TEA_PACKETRATE_RISE_THRESHOLD = 0.5

# If both diversity drop AND packet rate rise happen together → high confidence
# If only one triggers → moderate confidence, still passed to IF but flagged
TEA_FLASH_CROWD_MIN_DIVERSITY = 1.5  # flash crowd keeps diversity above this

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