---
created: 2026-08-19
last-updated: 2026-08-20
status: verified
tags:
  - overview
---

# Project Overview

**ADDOS** = **A**nomaly-based **D**DoS **D**etection and mitigation in **O**penFlow/**S**oftware-**D**efined Networks.

The repo implements a complete end-to-end research/testbed for detecting and mitigating DDoS attacks in SDN using **unsupervised machine learning** (Isolation Forest) gated with a supervised classifier (Random Forest) for attack-vector labelling.

## Repo name / README title

> Unsupervised-Machine-Learning-for-Anomaly-Based-DDoS-Mitigation-in-Software-Defined-Networks

## Research framing

- Detection target: SYN flood, ICMP flood, UDP flood (plus a "MIXED" SYN+UDP combo the model was never trained on).
- Core idea: **Isolation Forest** (unsupervised, trained on normal traffic only) flags anomalies; **Random Forest** (supervised, 3-class) only runs on IF-positive flows to label the attack type. This saves RF compute on normal traffic.
- Evaluation is rigorous: ground-truth attack labels are pushed to the backend, and per-class TP/FP/TN/FN + confusion matrices are persisted and rendered into a PDF report ([[config/config-and-dependencies]]).
- Latency metrics (`detection_ms`, `mitigation_ms`) are first-class citizens; clearly a thesis/paper deliverable.

## System layout (three tiers)

| Tier                   | Path          | Stack                           | Role                                                                                   |
| ---------------------- | ------------- | ------------------------------- | -------------------------------------------------------------------------------------- |
| **Topology / testbed** | `topology/`   | Mininet + hping3                | Builds the star network, generates baseline + attack traffic, drives experiments       |
| **Controller**         | `controller/` | Ryu (OpenFlow 1.3)              | Collects flow/port stats, forwards telemetry to the backend, installs mitigation rules |
| **Backend**            | `backend/`    | Flask + ZeroMQ + SQLite         | ML inference, mitigation state machine, persistence, REST/SSE API                      |
| **Frontend**           | `frontend/`   | FastAPI + Chart.js              | Monitoring dashboard (separate service, browser talks to backend directly)             |
| **Models**             | `models/`     | scikit-learn (joblib artifacts) | Trained IF + RF artifacts and feature contracts                                        |

## Key architecture decisions

1. **Two-stage ML**: IF gates, RF labels. See [[backend/models]].
2. **Sub-second detection**: a packet-level flood prefilter catches floods before the 1s stats poll. See [[backend/ml-pipeline]].
3. **TEA as a mitigation gate**: Temporal Entropy Analysis distinguishes flash crowds from real attacks so flash crowds aren't blocked. See [[backend/ml-pipeline]].
4. **Per-IP state machine**: Quarantine → Time Ban → Blackhole → Probation, never bans blindly. See [[backend/mitigation]].
5. **Persistent reputation**: repeat offenders escalate across restarts. See [[backend/mitigation]].
6. **ML is never paused**: resource guard throttles / sheds packet-ins instead of disabling detection. See [[backend/mitigation]].

## Data flow in one sentence

Mininet (hping3) → OVS → Ryu stats poll → ZMQ `5555` → backend pipeline (prefilter → IF → RF → decision engine) → state machine → ZMQ `5556` → Ryu installs OpenFlow rules → dashboard watches via REST + SSE.

Full detail in [[overview/architecture]].

## Related notes

- [[overview/architecture]]
- [[known-issues/known-issues]]