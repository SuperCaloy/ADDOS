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
# DB path resolution: DDOS_DB_PATH env var, else the benchmark marker file
# (benchmark/DB_TARGET), else the default logs/ddos.db. MARKER_PATH is
# overridable via DDOS_DB_MARKER so tests never touch the real repo marker.
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
RF_BATCH_MAX      = 16
RF_BATCH_WINDOW_MS = 50

# --- IF micro-batching (L1, default off) ---
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
TEA_WINDOW_SIZE = 500

TEA_LEARN_MIN_SAMPLES = 300
# Duration requirement removed: learn from sample count only (AWS: "minutes not hours")
# Old: TEA_LEARN_MIN_DURATION_S = 300.0
# Calibration validity gate (option A): the pps baseline may only finalize
# when the warmup saw real traffic. If the all-sample mean pps stays below
# this floor, the analyzer remains in shadow mode instead of calibrating
# "normal" on a near-idle window (observed: baseline learned at 0.47 pps/flow
# during a benchmark cold start, real traffic then read +170 sigma).
# Tuned to this testbed: idle ~0.2-0.5 pps/flow, active host traffic >= 1.
TEA_LEARN_MIN_MEAN_PPS = 0.1
# Dynamic flood cap for warmup volume guard: per-flow pps above the cap is
# rejected during warmup. The cap scales with observed traffic:
#   cap = max(TEA_LEARN_CAP_FLOOR_PPS, provisional_mean * TEA_LEARN_CAP_FACTOR)
# This allows flash crowds above old hardcoded 50pps while still rejecting
# attacks. The floor ensures idle-to-active transitions are not stalled.
TEA_LEARN_CAP_FLOOR_PPS = 10.0
TEA_LEARN_CAP_FACTOR = 5.0
# Recent-window size for variance computation during warmup finalize.
# Instead of computing variance over all samples (which blends idle and busy
# phases during ramping), use only the last N samples to capture the current
# traffic state. Post-learning EMA updates remain unchanged.
TEA_LEARN_VARIANCE_WINDOW_SIZE = 50
# Warmup volume guard: while learning, the pps baseline rejects interval
# means deviating more than this factor from the provisional mean, so an
# attack that starts mid-warmup cannot be absorbed (verified +38.9% baseline
# contamination without it). Applied to the pps baseline only: variance-type
# metrics are heavy-tailed at 9-flow windows (legit 5-8x swings), so a
# statistical guard there over-rejects and stalls learning.
# Ref: notes/bugs/tea-learning-phase-duration.md.
TEA_WARMUP_REJECT_FACTOR = 5.0

# --- TEA dual feedback hysteresis ---
# IF side: per-flow, streak-only, NEVER locks baselines by itself.
# Isolated anomalies halve the streak (decay) instead of zeroing it.
TEA_IF_UNLOCK_STREAK = 5
# TEA side counts eval intervals (~0.5s each), not flows. A normal-verdict
# streak of 60 (~30s) safely re-latches because real attacks keep the IF side
# of the AND-gate suppressed, halving post-attack recovery time.
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
TEA_UNIFORM_SHARE_SIGMA = 2.0           # uniformity share z-score companion threshold
TEA_MECHANIZED_MIN_UNIFORM_SHARE = 0.9  # absolute floor for mechanized_cluster
TEA_UNIFORM_BACKSTOP_SHARE = 0.95       # R1: very high uniformity ...
TEA_UNIFORM_BACKSTOP_MIN_IPS = 20       # ... from many sources still flags (moderate)
TEA_PPS_SURGE_SIGMA = 2.0               # absolute pps z-score vs learned baseline
                                        # (2.0: real floods are orders above baseline;
                                        # a 1-sigma legit traffic ramp must not latch)
# --- TEA supervised relearn (P2) ---
TEA_RELEARN_STABLE_INTERVALS = 8       # stable verdicts while latched before relearn (~4s)
TEA_RELEARN_MAX_DRIFT_FRAC = 0.01      # max per-interval baseline mean movement (1%)
TEA_RELEARN_ALPHA = 0.15               # relearn EMA alpha; the drift cap is the safety,
                                       # alpha only removes the slow EMA tail
TEA_RELEARN_MIN_CONFIDENCE = "moderate" # only relearn on moderate-confidence (not high/low)
TEA_RELEARN_MAX_IF_ANOMALY_RATE = 0.3   # block relearn if IF anomaly rate > 30%
TEA_RELEARN_MAX_CUMULATIVE_DRIFT = 0.20 # max total drift per relearn session (20%)
TEA_RELEARN_BASELINE_DISTANCE_MAX = 2.0 # reject relearn if new baseline > 2x original
# --- TEA latch max-hold valve (P3) ---
TEA_LATCH_MAX_HOLD_S = 90.0

# Extreme-z restart (option C): if a latched baseline is astronomically
# wrong (|z| >= TEA_EXTREME_Z_SIGMA sustained for TEA_EXTREME_Z_RESTART_
# INTERVALS eval intervals), wipe the baselines and restart learning from
# current traffic instead of crawling there via the 1%-per-interval drift
# cap. A correct baseline never produces 50-sigma readings even during a
# real flood; only a miscalibrated one does. An attack that sustains the
# trigger cannot poison the fresh baseline: the warmup volume guard rejects
# attack-scale samples, so calibration waits for clean traffic.
TEA_EXTREME_Z_SIGMA = 50.0
TEA_EXTREME_Z_RESTART_INTERVALS = 60
TEA_LATCH_HOLD_IF_GRACE_S = 30.0
# --- TEA idle IF-rate window (P4) ---
TEA_IF_RATE_WINDOW = 20
TEA_IF_ANOMALY_RATE_BLOCK = 0.3
# --- TEA telemetry validation (P6) ---
TEA_EVAL_SEQ_MAX_JUMP = 1000            # reject absurd dedup-blackout seq jumps

# --- TEA Shadow Baseline (dual-baseline learning) ---
TEA_SHADOW_ENABLED = True              # master switch
TEA_SHADOW_MIN_SAMPLES = 60            # shadow samples before promotion (reduced from 300)
# Duration requirement removed: learn from sample count only (same as main baselines)
# Old: TEA_SHADOW_MIN_DURATION_S = 300.0
TEA_SHADOW_MAX_AGE_S = 120.0           # discard shadow if older (reduced from 600)
TEA_SHADOW_PROMOTE_MIN_CONFIDENCE = "moderate"

# --- TEA false positive fix (Phase 1: std floor + magnitude check) ---
TEA_MIN_STD_FLOOR = 0.10        # std floor as fraction of mean (prevents tiny-variance FP)
TEA_SURGE_MIN_MAGNITUDE = 2.0   # value must be 2x baseline mean to count as surge

# --- TEA detection thresholds (moved from entropy_analyzer.py for single source of truth) ---
# z-score for attack variance collapse detection
TEA_ATTACK_SIGMA = 2.5
# z-score for flash-crowd/volume surge detection
TEA_CROWD_SIGMA = 1.5
# EMA learning rate range for baseline adaptation
TEA_EMA_ALPHA_MIN = 0.02
TEA_EMA_ALPHA_MAX = 0.10
# Robust scale estimator rejection threshold (MAD-based, 3.0-3.5; literature Apply)
TEA_ROBUST_REJECT_SIGMA = 3.5

# --- TEA flash crowd guidance (Phase 4) ---
# IF anomaly rate above this threshold overrides flash crowd detection
# (mixed-protocol attack disguised as flash crowd)
TEA_FLASH_CROWD_IF_THRESHOLD = 0.3
# Rolling window size for IF anomaly rate calculation
TEA_FLASH_CROWD_IF_BUFFER_SIZE = 50

# Temporal entropy: inter-arrival time distribution
TEA_TEMPORAL_WINDOW_SIZE = 50        # number of inter-arrival times to track
TEA_TEMPORAL_ENTROPY_BINS = 10       # number of bins for entropy calculation

# --- TEA Mahalanobis distance (multi-dimensional attack detection) ---
TEA_MAHALANOBIS_ATTACK_THRESHOLD = 5.0
TEA_MAHALANOBIS_CROWD_THRESHOLD = 3.0
TEA_MAHALANOBIS_HISTORY_SIZE = 100

FLOW_FIELD_MAX = 1e9                    # clamp ceiling for pps/bps/count fields

# --- API ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# --- UI batching ---
UI_BATCH_INTERVAL_S = 0.5

# --- Graph history ---
GRAPH_BUCKET_COUNT = 60