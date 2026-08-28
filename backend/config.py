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
# Resolution order: DDOS_DB_PATH env var, then the benchmark marker file
# (benchmark/DB_TARGET, written by run_benchmark and removed at session
# end), then the default logs/ddos.db. MARKER_PATH is overridable via
# DDOS_DB_MARKER so tests never touch the real repo marker.
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

# --- ZeroMQ ---
ZMQ_TELEMETRY_ADDR = "tcp://127.0.0.1:5555"   # Ryu PUSH → Backend PULL
ZMQ_COMMAND_ADDR   = "tcp://127.0.0.1:5556"   # Backend PUSH → Ryu PULL

# --- Pipeline tuning ---
FLOW_TRACKER_CAP        = 500
INFERENCE_CACHE_TTL_S   = 1.0
WORKER_QUEUE_MAXSIZE    = 300
WORKER_ITEM_TIMEOUT_S   = 3.0
EXTRACTION_TRIGGER_PKTS = 1
EXTRACTION_TRIGGER_S    = 0.05

# --- RF micro-batching (B1) ---
RF_BATCH_ENABLED  = True
RF_BATCH_MAX      = 32
RF_BATCH_WINDOW_MS = 50

# --- IF micro-batching (L1, conservative default off like B1 originally) ---
IF_BATCH_ENABLED  = True
IF_BATCH_MAX      = 32
IF_BATCH_WINDOW_MS = 50

# --- Worker admission control (V2) ---
ADMISSION_CONTROL_ENABLED = True
WORKER_ADMISSION_DEPTH    = 600   # PLACEHOLDER, no measured basis; see risk register

# --- Deadline-based admission (R3b, default off; measurement plan sec 12) ---
# While enabled, the deadline check replaces the static depth check:
# refuse when qsize * svc_ema / workers exceeds WORKER_ITEM_TIMEOUT_S - margin.
DEADLINE_ADMISSION_ENABLED = True
DEADLINE_ADMISSION_MARGIN_S = 0.2
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
# 60 (~30s) instead of 100: real attacks keep the IF side of the AND-gate
# suppressed and inert moderates re-latch within 3 intervals, so a shorter
# normal-verdict streak is safe and halves post-attack recovery time.
TEA_TEA_LOCK_STREAK = 3               # consecutive attack intervals to latch
TEA_TEA_UNLOCK_STREAK = 60            # consecutive normal intervals (~30s) to unlatch
TEA_TEA_HIGH_CONF_LOCK = True         # single "high" confidence interval latches instantly
TEA_IDLE_UNLOCK_S = 30.0              # attack-free time that force-unlocks during silence
# Degenerate interval guard: skip verdict + learning below this flow count
TEA_MIN_FLOWS_PER_INTERVAL = 5
# Per-IP profile expiry. Short TTL so IP rotation within the window cannot
# keep per-IP profiles "uncertain" and hide a distributed uniform flood.
TEA_IP_PROFILE_TTL_S = 60

# --- TEA uniformity gating (P1, notes/tasks/tea-normal-fp-fix-plan.md) ---
# Uniformity-only signals (mechanized_cluster, variance/proto collapse) need
# an attack-scale volume companion before they can set an attack verdict.
TEA_UNIFORM_SHARE_SIGMA = 2.0           # was 1.5 via TEA_CROWD_SIGMA alias
TEA_MECHANIZED_MIN_UNIFORM_SHARE = 0.9  # absolute floor for mechanized_cluster
TEA_UNIFORM_BACKSTOP_SHARE = 0.95       # R1: very high uniformity ...
TEA_UNIFORM_BACKSTOP_MIN_IPS = 20       # ... from many sources still flags (moderate)
TEA_PPS_SURGE_SIGMA = 2.0               # absolute pps z-score vs learned baseline
                                        # (2.0: real floods are orders above baseline;
                                        # a 1-sigma legit traffic ramp must not latch)
# --- TEA supervised relearn (P2) ---
TEA_RELEARN_STABLE_INTERVALS = 6       # stable verdicts while latched before relearn (~3s)
TEA_RELEARN_MAX_DRIFT_FRAC = 0.10      # max per-interval baseline mean movement (10%)
TEA_RELEARN_ALPHA = 0.10               # relearn EMA alpha; the drift cap is the safety,
                                       # alpha only removes the slow EMA tail
# --- TEA latch max-hold valve (P3) ---
TEA_LATCH_MAX_HOLD_S = 90.0
TEA_LATCH_HOLD_IF_GRACE_S = 30.0
# --- TEA idle IF-rate window (P4) ---
TEA_IF_RATE_WINDOW = 20
TEA_IF_ANOMALY_RATE_BLOCK = 0.3
# --- TEA telemetry validation (P6) ---
TEA_EVAL_SEQ_MAX_JUMP = 1000            # reject absurd dedup-blackout seq jumps
FLOW_FIELD_MAX = 1e9                    # clamp ceiling for pps/bps/count fields

# --- API ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# --- UI batching ---
UI_BATCH_INTERVAL_S = 0.5

# --- Graph history ---
GRAPH_BUCKET_COUNT = 60