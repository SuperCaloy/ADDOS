---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - backend
  - ml
  - models
---

# Models

**Directory:** `models/` (artifacts), `backend/models/` (runtime code).

## Two-stage ML design

**Isolation Forest (IF)** is the unsupervised gate: binary anomaly detection. **Random Forest (RF)** is the supervised labeller: runs *only* on IF-positive flows to name the attack vector. RF never sees normal traffic, which saves compute.

## Isolation Forest: `models/if_pipeline.py`

- **16 features** (contract order, in `models/isolation_forest/feature_contract.json`):
  `flow_duration_sec`, `packet_count`, `byte_count`, `packet_count_per_second`, `byte_count_per_second`, `flow_count_per_src`, `tp_src`, `tp_dst`, `ip_proto`, `pkt_byte_rate_ratio`, `avg_bytes_per_pkt`, `flow_intensity`, `port_entropy`, `bytes_per_duration`, `pkt_size_uniformity`, `flow_src_intensity`.
- All log1p-transformed.
- **NaN/inf handling:** running-median imputation via thread-local batched accumulator (flush every 20 calls).
- **Two-stage scaling:** RobustScaler → QuantileTransformer (matches training).
- Inference: `if_score = -score_samples(...)`; `is_anomaly = if_score >= threshold` with **threshold = 0.6092241858026261**.
- Trained on **normal traffic only** (contamination `auto`).

> [!note] Threshold conventions
> `decision_engine` uses a stricter combo (`threshold * 1.2` AND confidence ≥ 0.75) for escalation; `state_machine` has a fallback threshold of `0.6004` when models aren't loaded.

## Random Forest: `models/rf_pipeline.py`

- **15 features** (in `models/random_forest/rf_feature_contract.json`):
  IF's 16 minus `tp_src`, `tp_dst`, `port_entropy`, plus `duration_pkt_ratio` and `pkt_rate_per_duration`.
- NaN → `0.0` (no median imputation). Scaled by RF scaler only.
- Classes: `SYN Flood`, `ICMP Flood`, `UDP Flood`.
- Inference: `predict_proba` + argmax; class via `label_encoder.inverse_transform` if `conf >= rf_conf_gate` else `"Uncertain"`. **confidence_gate = 0.7** in the contract.

## Loader: `models/loader.py`

- `load_all()`: reads both JSON contracts + joblib-loads 6 artifacts. Idempotent under a lock.
- Exposes: `if_model`, `if_scaler`, `if_quantiler`, `rf_model`, `rf_scaler`, `rf_encoder`, `if_features`, `if_threshold`, `rf_features`, `rf_classes`, `rf_conf_gate`.
- `require_loaded()` raises if called before `load_all()`.

## Model artifacts (`models/`)

| Path | Size | Role |
|---|---|---|
| `isolation_forest/isolation_forest.pkl` | 7.8M | IF anomaly model |
| `isolation_forest/scaler.pkl` | 1.0K | RobustScaler (stage 1) |
| `isolation_forest/quantiler.pkl` | 134K | QuantileTransformer (stage 2) |
| `random_forest/random_forest_final.pkl` | 1.4M | RF classifier |
| `random_forest/scaler.pkl` | 1.3K | RF scaler |
| `random_forest/label_encoder.pkl` | 136 B | LabelEncoder (class names) |

> [!warning] No training scripts in repo
> The `.pkl` artifacts are pinned for reproducibility, but the **offline training pipeline is not committed**: runtime code never imports `scipy`, `imbalanced-learn`, `matplotlib`, or `seaborn`. They exist only to guarantee the same model versions could be retrained.

## Related notes

- [[backend/ml-pipeline]]: how the models are driven per flow.
- [[config/config-and-dependencies]]: dependency stack and model paths.