---
created: 2026-08-23
last-updated: 2026-08-23
status: draft
tags:
  - research
  - tea
  - prefilter
  - bias-reduction
  - ddos-detection
  - entropy
  - adaptive-thresholds
---

# Bias Reduction Research for DDoS Detection

> [!note] Research findings
> Academic and industry techniques applicable to reducing bias in ADDOS's TEA (Traffic Entropy Analyzer) and Flood Prefilter. Each section maps a specific bias to published solutions with citations.

## 1. TEA Biases and Applicable Techniques

### 1.1 Feature Bias (pkt_size_uniformity and flow_intensity only)

**Problem:** TEA uses only two features for variance detection, missing attacks with varied packet sizes or non-standard intensity patterns.

**Published solutions:**

- **Multi-feature joint entropy.** Mao et al. (2018) proposed joint-entropy over multiple packet header features (flow duration, source IP, packet length, destination port) rather than single-feature Shannon entropy. This detects attacks invisible to any single feature. [^mao2018]

- **Renyi joint entropy for multi-rate detection.** GEADDDC (2021) generalized Renyi joint entropy over source IP + destination IP pairs with a tunable alpha parameter. The alpha parameter lets the detector emphasize rare events (low alpha) or concentrated distributions (high alpha), making it sensitive to both low-rate and high-rate attacks. [^geadddc2021]

- **Behavioral macrostate framework.** Rahman et al. (2026) proposed moving beyond scalar entropy to a finite-dimensional "macrostate" over the Canonical Security Telemetry Substrate (CSTS). The macrostate captures activity level, distributional disorder, structural organization, temporal volatility, persistence, and deviation from benign baselines simultaneously. This outperforms Shannon-, Renyi-, and Tsallis-only baselines on benchmark datasets. [^rahman2026]

- **Conditional entropy over source+destination IPs.** Bai et al. (2026) showed that conditional entropy H(dst_ip | src_ip) is more sensitive and has a tighter fluctuation range than marginal Shannon entropy during attacks, while remaining stable during normal traffic. [^bai2026]

**Applicable to TEA:** Add proto_entropy as a third detection dimension (already computed but unused), add conditional entropy H(dst_port | src_ip), and consider tracking a behavioral state vector rather than just two variance scalars.

### 1.2 Variance-Only Detection (only detects variance collapse)

**Problem:** TEA only detects when variance collapses (attack uniformity), missing gradual attacks, low-variance attacks, or attacks that increase variance.

**Published solutions:**

- **Bidirectional entropy monitoring.** Berezinski et al. (2015) proposed monitoring entropy in both directions: decrease (concentration/attack) AND increase (dispersion/scanning). Their method uses multiple entropy types (Shannon, Renyi, Tsallis) and monitors the number of distinct elements as a separate metric, making the detector resilient to entropy deception attacks. [^berezinski2015]

- **Kullback-Leibler divergence from baseline.** Gu & McCallum (2005) used maximum-entropy estimation to characterize nominal traffic, then measured KL divergence of current traffic from that model. This detects any distributional shift, not just variance collapse. [^gu2005]

- **Information distance metrics.** Sahoo et al. (2018) used information distance (symmetric KL divergence) between current and baseline distributions for low-rate DDoS detection in SDN data centers. Information distance captures both concentration and dispersion shifts. [^sahoo2018]

**Applicable to TEA:** Track both variance collapse AND variance expansion. Add KL divergence or Jensen-Shannon divergence from the learned baseline distribution, not just variance comparison.

### 1.3 Aggregate Bias (runs on aggregate switch data)

**Problem:** Small attackers are diluted in switch-wide aggregate statistics. A single attacker sending 100 pps is invisible when the switch handles 10,000 pps total.

**Published solutions:**

- **Cross-domain confidence fusion.** Zhang et al. (2026) identified "aggregation bias" directly: in multi-controller SDN, the aggregation controller's entropy detector produces 8.87% FPR while edge controllers achieve <3.33%. Root causes: (1) OpenFlow statistics lag causes entropy distortion after attack ends, (2) unconstrained EWMA threshold drift locks threshold low. Their fix: lightweight edge-to-aggregation confidence reporting (53 bytes/report, 2.89 kb/s aggregate) with consensus-based threshold floor protection. FPR dropped from 8.87% to 1.96%. [^zhang2026]

- **Per-source entropy tracking with sketch structures.** LDDM (Liu et al. 2021) uses multidimensional sketch structures keyed on (src_ip, dst_ip) to aggregate and compress per-flow data while maintaining per-source visibility. This reduces storage cost while preserving per-attacker granularity for low-rate detection. [^liu2021]

- **Per-IP entropy profiles.** The ADDOS codebase already has `_IpEntropyProfile` class that tracks per-IP variance. Activating this for detection (not just logging) would directly address aggregate dilution.

**Applicable to TEA:** Activate per-IP entropy profiles for detection. Use sketch-based aggregation to maintain per-source visibility without linear memory cost. Add a threshold floor mechanism to prevent EWMA drift during attacks.

### 1.4 Protocol Bias (computes proto_entropy but doesn't use it)

**Problem:** TEA computes proto_entropy but only uses pkt_size_uniformity and flow_intensity for detection decisions. Attacks that don't affect packet size or intensity (e.g., protocol-specific floods with normal-looking sizes) pass undetected.

**Published solutions:**

- **Multi-dimensional entropy vectors.** Lakhina et al. (2005) showed that different anomaly types affect different traffic feature distributions. Scans affect source IP entropy, DDoS affects destination IP entropy, worms affect source port entropy. Using a vector of entropies (one per feature) allows detection of attacks invisible to any single dimension. [^lakhina2005]

- **Entropy-type diversity for deception resilience.** Berezinski et al. (2015) demonstrated that monitoring Shannon, Renyi, and Tsallis entropies simultaneously, plus the count of distinct elements, makes detection resilient to entropy deception (attackers who craft traffic to look normal under one entropy measure). [^berezinski2015]

**Applicable to TEA:** Use proto_entropy as a third detection dimension. When proto_entropy collapses (attack uses single protocol), flag even if size/intensity variance is normal.

### 1.5 Temporal Bias (1-second windows miss short attacks)

**Problem:** TEA's 1-second analysis windows miss attacks shorter than 1 second (burst attacks) and attacks spread over many seconds (slow/low-rate attacks).

**Published solutions:**

- **Multi-scale temporal analysis.** Chen & Hwang (2006) used spectral analysis (wavelet transform) at multiple time scales to detect shrew DDoS attacks. Short bursts appear at fine scales, sustained patterns appear at coarse scales. Single-scale analysis misses one or the other. [^chen2006]

- **Adaptive polling rate (3D-SNMP).** The 3D-SNMP approach (2022) dynamically scales the SNMP polling rate up when anomalies are detected and down during normal operation. This catches attacks with burst rates below the default poll rate while keeping compute costs manageable. Detection TPR of 0.87 across 3 DDoS variants including small-burst and irregular-burst patterns. [^3dsnmp2022]

- **Hierarchical window approach.** ATS-DTA (Bai et al. 2026) uses a two-stage design: a lightweight entropy trigger runs at every window, and a heavier ML classifier activates only when triggered. The trigger uses conditional entropy with adaptive thresholds for fast detection, while the ML stage confirms. This balances detection speed against compute cost. [^bai2026]

- **Sequence-aware temporal models.** Recent work (2025-2026) uses LSTM/transformer architectures to capture temporal dependencies across multiple time scales. These models can detect both burst patterns (via local attention/CNN frontends) and slow accumulation patterns (via recurrent memory or global attention). [^sequence2025]

**Applicable to TEA:** Use overlapping or nested windows (e.g., 250ms + 1s + 5s). Run variance detection at all scales and OR the results. Short attacks trigger at fine scale, slow attacks trigger at coarse scale.

### 1.6 Threshold Bias (dynamic sigma scales with CV)

**Problem:** TEA's dynamic sigma = base_sigma * (1 + CV), where CV is the coefficient of variation. In variable networks, CV is high, sigma is high, making detection harder precisely when the network is noisy.

**Published solutions:**

- **EWMA-ARIMA hybrid threshold (EWAMA).** Bai et al. (2026) proposed combining ARIMA for long-term trend forecasting with EWMA for short-term smoothing. The dynamic weight beta shifts between them based on prediction error: during stable traffic, ARIMA dominates (smooth, predictable threshold); during volatile traffic, EWMA dominates (responsive to changes). This prevents the threshold from becoming either too rigid or too loose. [^bai2026]

- **Dynamic k parameter.** Pebrianto & Suryani (2025) proposed k_dynamic that automatically adapts to traffic fluctuations instead of using a fixed sensitivity parameter k. Their method re-evaluates suspicious IPs that evade initial detection due to erratic traffic patterns, improving detection accuracy without manual tuning. [^pebrianto2025]

- **Chebyshev inequality-based thresholds.** Tsobdjou et al. (referenced in Siam & Beson 2026) used Chebyshev inequality for dynamic thresholding, which provides distribution-free bounds. This is more robust than sigma-based thresholds that assume Gaussian distributions. [^siam2026]

- **Threshold floor protection.** Zhang et al. (2026) added an edge-aware threshold floor: H_thd = max(H_thd, min(H_edge_mean, phi)). This prevents the threshold from collapsing below a healthy baseline during attacks, breaking the "threshold locked low" death spiral. [^zhang2026]

**Applicable to TEA:** Replace CV-scaled sigma with EWMA-based threshold that has a floor. Use Chebyshev inequality for distribution-free bounds. Add threshold floor protection to prevent collapse during sustained attacks.

## 2. Flood Prefilter Biases and Applicable Techniques

### 2.1 Protocol Bias (only monitors SYN/ICMP/UDP)

**Problem:** Prefilter only detects SYN, ICMP, and UDP floods. ACK floods, RST floods, and application-layer attacks (HTTP flood, Slowloris, RUDY) pass through undetected.

**Published solutions:**

- **Application-layer detection via TCP state analysis.** Kemp et al. (2023) proposed generalized detection for application-layer DoS by analyzing TCP state transition patterns rather than specific protocol signatures. This detects Slowloris, RUDY, and slow HTTP read attacks using a common framework. [^kemp2023]

- **Nonparametric CUSUM for HTTP floods.** Jazi et al. (2017) used nonparametric CUSUM (cumulative sum) for detecting HTTP-based application-layer DoS attacks. Unlike parametric methods, CUSUM does not assume a specific traffic distribution, making it effective against diverse application-layer attack patterns. [^jazi2017]

- **Multi-vector defense layers.** A10 Networks analysis (2026) recommends three layers: (1) broad-spectrum reflection filtering covering all UDP services, (2) real-time amplifier intelligence, (3) behavioral anomaly detection that is protocol-agnostic. The key insight is that persistence patterns, not burst size, reveal the real threat. [^a10_2026]

**Applicable to prefilter:** Add TCP flag analysis (ACK/RST/FIN flood detection) by monitoring TCP flag entropy. Add connection-rate tracking for application-layer detection. Use behavioral anomaly detection (rate deviation from per-IP baseline) rather than protocol-specific signatures.

### 2.2 Rate-Based Bias (only detects high-rate bursts)

**Problem:** Prefilter uses fixed rate thresholds. Low-rate attacks (below threshold) and sustained attacks (at or slightly above baseline) are invisible.

**Published solutions:**

- **Wavelet transform + behavior divergence.** Liu et al. (2021) proposed LDDM: multidimensional sketch compression + Daubechies-4 wavelet transform to calculate energy percentage of sketch divergence. A modified weighted exponential moving average constructs the dynamic threshold. A traffic freezing mechanism standardizes the threshold. This detects stealthy low-rate DDoS with lower FPR and FNR than existing methods. [^liu2021]

- **Time delay forecasting.** Savchenko et al. (2022) proposed detecting slow DDoS by analyzing and predicting host response latency rather than traffic volume. They compute individual trajectories of response time delay and detect deviations. This catches attacks that don't significantly increase traffic volume but do increase latency. [^savchenko2022]

- **Spectral analysis for shrew attacks.** Chen & Hwang (2006) used collaborative spectral analysis to detect shrew DDoS attacks. The periodic pulse pattern of shrew attacks creates distinct spectral signatures even at low average rates. [^chen2006]

- **Adaptive threshold with EWMA.** Multiple papers (Machaka et al. 2016, dynamic threshold approach 2022) use EWMA to track the baseline rate and detect deviations. The smoothing coefficient alpha controls responsiveness: high alpha for fast detection, low alpha for stability. Dual-alpha approaches switch between them based on traffic velocity. [^machaka2016] [^ewma_ddos2022]

**Applicable to prefilter:** Add EWMA-based rate tracking with dual-alpha (fast/slow). Add latency-based detection as a secondary signal. Use spectral analysis or wavelet transform to detect periodic low-rate patterns.

### 2.3 Per-IP Bias (tracks per src_ip, misses distributed/spoofed)

**Problem:** Prefilter tracks per-source-IP rates. Distributed attacks (many sources, each below threshold) and spoofed attacks (rotating source IPs) are invisible because no single IP exceeds the threshold.

**Published solutions:**

- **Aggregate + per-IP combined analysis.** Zhang et al. (2026) showed that combining per-source tracking at edge controllers with aggregate analysis at the aggregation controller eliminates both per-IP blind spots and aggregate dilution. Edge controllers track per-source confidence; aggregation controller fuses via consensus. [^zhang2026]

- **Destination-based entropy detection.** When source IPs are spoofed, destination IP entropy collapses (many flows target the same victim). Monitoring destination IP entropy catches distributed/spoofed attacks that per-source tracking misses. [^lakhina2005]

- **Ingress filtering (BCP38/BCP84).** NIST and IETF BCP38/BCP84 specify source address verification at network boundaries. While this is a network-level defense, the SDN controller can implement equivalent logic: verify that source IPs match expected ranges for each ingress port. [^nist_bcp38]

- **SAVA framework.** The SAVA (Source Address Validation Architecture) framework provides layered, multi-level source address verification throughout the packet's transmission path. [^sava2025]

- **Flow aggregation by destination.** MLDDoS (2025) uses normalized entropy of source IPs combined with large-flow information and traffic marking. By tracking destination-centric flow aggregation, it detects distributed attacks targeting a single victim even when individual sources are below threshold. [^mlddos2025]

**Applicable to prefilter:** Add destination-centric rate tracking (aggregate rate to each dst_ip/dst_port). When aggregate rate to a destination exceeds threshold, flag even if no individual source exceeds per-IP threshold. Add source IP entropy monitoring: when src_ip entropy drops sharply, it indicates concentration (fewer unique sources = less distributed).

### 2.4 No Learning (fixed thresholds, doesn't adapt)

**Problem:** Prefilter uses hardcoded rate thresholds. It doesn't learn the network's normal traffic patterns, leading to false positives during legitimate traffic spikes and false negatives when baseline shifts.

**Published solutions:**

- **EWMA-based adaptive baseline.** The most widely adopted approach. EWMA tracks the running average of a metric (rate, entropy) with exponential weighting. The threshold is set as EWMA + k * stddev. Alpha controls adaptation speed. [^machaka2016] [^ewma_ddos2022]

- **EWMA-ARIMA hybrid (EWAMA).** Bai et al. (2026) combine ARIMA for long-term trend prediction with EWMA for short-term smoothing. The dynamic weight beta shifts between them based on prediction error. Feedback from the ML detection stage adjusts thresholds: if ML confirms attack, threshold is appropriate; if ML says false positive, threshold is relaxed. [^bai2026]

- **Prefilter-to-ML feedback loop.** ATS-DTA's feedback mechanism: when the ML stage determines a prefilter trigger was a false positive, the threshold adjustment module relaxes the trigger threshold. This creates a self-tuning system. [^bai2026]

- **Dual-alpha EWMA.** Use alpha_high when traffic velocity exceeds a threshold (fast adaptation during changes) and alpha_low during stable periods (smooth baseline). This prevents the threshold from being pulled toward attack values during sustained floods. [^bai2026]

**Applicable to prefilter:** Replace fixed thresholds with EWMA-based adaptive baselines. Add feedback from IF/RF verdicts to adjust prefilter thresholds. Use dual-alpha EWMA to prevent threshold corruption during attacks.

## 3. Combined Techniques for Both TEA and Prefilter

### 3.1 Ensemble Scoring

**Approach:** Combine TEA's global entropy signal with prefilter's per-IP rate signal into a single ensemble score.

- Weighted combination: `ensemble = w1 * tea_score + w2 * prefilter_score`
- TEA provides global context (is the network under attack?), prefilter provides source attribution (which IP is attacking?)
- Anley et al. (2024) showed that adaptive transfer learning between detection stages improves robustness to evolving attack patterns. [^anley2024]

### 3.2 Two-Stage Detection with Trigger

**Approach:** Lightweight trigger (prefilter/entropy) activates heavier analysis (IF/RF/ML).

- ATS-DTA's architecture: conditional entropy trigger -> ML confirmation. The trigger runs at every window; ML only runs when triggered. This minimizes compute while maintaining detection accuracy. [^bai2026]
- The trigger threshold adapts via EWMA-ARIMA feedback from the ML stage.

### 3.3 Temporal Correlation

**Approach:** Track detection patterns over rolling windows to catch sustained attacks.

- Maintain a deque of recent detections (last 60s). If >N detections in window, escalate even if individual detections are borderline.
- This catches slow, sustained attacks that individually don't trigger but collectively indicate an ongoing campaign.

## 4. Key References

[^mao2018]: Mao, J., Deng, W., Shen, F. "DDoS flooding attack detection based on Joint-entropy with multiple traffic features." (2018), pp. 237-243.

[^geadddc2021]: "Entropy-Based Approach to Detect DDoS Attacks on Software Defined Networks." Journal of King Saud University - Computer and Information Sciences. Uses generalized Renyi joint entropy for low-rate and high-rate DDoS detection.

[^rahman2026]: Rahman, A., Bandara, E., Shetty, S. "Cyber Dynamics I: Finite Macrostates for Behavioral Anomaly Detection in Network Telemetry." arXiv:2607.07075 (2026). Proposes behavioral state-space beyond scalar entropy.

[^bai2026]: Bai, T., Liu, Y., Gao, Y. et al. "ATS-DTA: Adaptive Two-Stage DDoS Detection with Dynamic Threshold Adjustment in SDN Networks." Cybersecurity 9, 12 (2026). EWMA-ARIMA hybrid threshold, two-stage detection.

[^berezinski2015]: Berezinski, P., Jasiul, B., Szpyrka, M. "An Entropy-Based Network Anomaly Detection Method." Entropy 17(4), 2367-2408 (2015). Multiple entropy types + distinct element counting.

[^gu2005]: Gu, Y. & McCallum, A. "Detecting Anomalies in Network Traffic Using Maximum Entropy Estimation." IMC '05, USENIX. KL divergence from maximum-entropy baseline.

[^sahoo2018]: Sahoo, K.S. et al. "An Early Detection of Low Rate DDoS Attack to SDN Based Data Center Networks Using Information Distance Metrics." Future Generation Computer Systems (2018).

[^zhang2026]: Zhang, Z., Wang, S., Tao, X. "Cross-Domain Joint DDoS Detection in Multi-Controller SDN via Confidence-Based Entropy Fusion." arXiv:2608.17507v1 (Aug 2026). Identifies aggregation bias, proposes cross-domain confidence fusion. FPR 8.87% -> 1.96%.

[^liu2021]: Liu et al. "Low-rate DDoS attacks detection method using data compression and behavior divergence." Computers & Security (2021). Multidimensional sketch + wavelet transform + dynamic threshold.

[^chen2006]: Chen, Y. & Hwang, K. "Collaborative Detection and Filtering of Shrew DDoS Attacks Using Spectral Analysis." J. Parallel Distrib. Comput. 66(9), 1137-1151 (2006).

[^3dsnmp2022]: "Adaptive Polling Rate for SNMP for Detecting Elusive DDOS." Journal of Computer Networks and Communications (2022). Dynamic SNMP polling rate scaling.

[^sequence2025]: "Sequence-Aware Natural Language Processing Models for DDoS Attack Detection in Software-Defined Networking." SGS Engineering & Sciences 1(5) (2025). LSTM/transformer for multi-scale temporal detection.

[^pebrianto2025]: Pebrianto, J. & Suryani, V. "Adaptive DDoS Attack Detection: Entropy-Based Model With Dynamic Threshold and Suspicious IP Reevaluation." IEEE Access (2025). Dynamic k parameter + IP re-evaluation.

[^siam2026]: Siam, B., Beson, et al. "Entropy Based DDoS Detection and Mitigation Methods in SDN: A Survey." IEEE (2026). References Chebyshev-based dynamic thresholding.

[^kemp2023]: Kemp, C. et al. "An Approach to Application-Layer DoS Detection." (2023). Generalized application-layer DoS detection framework.

[^jazi2017]: Jazi, H.H. et al. "Detecting HTTP-based Application Layer DoS Attacks on Web Servers in the Presence of Sampling." Computer Networks (2017). Nonparametric CUSUM.

[^a10_2026]: A10 Networks. "Multi-Vector DDoS: 11 Amplification Vectors." Analysis of 126,875 attacks (2026). Three-layer defense: broad-spectrum filtering, real-time intelligence, behavioral anomaly detection.

[^machaka2016]: Machaka, J., Bagula, A. et al. "Using Exponentially Weighted Moving Average Algorithm to Defend Against DDoS Attacks." (2016). EWMA for IoT DDoS detection.

[^ewma_ddos2022]: "Dynamic Threshold-Based Approach to Detect Low-Rate DDoS Attacks on Software-Defined Networking Controller." CMC (2022). EWMA dynamic threshold for low-rate detection.

[^lakhina2005]: Lakhina, A., Crovella, M., Diot, C. "Mining Anomalies Using Traffic Feature Distributions." SIGCOMM '05, ACM. Multi-feature entropy vectors for anomaly type identification.

[^nist_bcp38]: NIST. "Advanced DDoS Mitigation Techniques." (2016). BCP38/BCP84 ingress filtering for source address verification.

[^sava2025]: "SAVA Deployment for Spoofed Source Attacks." Springer (2025). Layered source address validation architecture.

[^mlddos2025]: "MLDDoS: A Distributed Denial of Service Attack Detection Method Using Multi-Level Sketch." Journal of Supercomputing (2025). Normalized source IP entropy + large-flow information + traffic marking.

[^anley2024]: Anley, M.B. et al. "Robust DDoS Attack Detection with Adaptive Transfer Learning." Computers & Security 144, 103962 (2024). CNN + adaptive architecture + transfer learning.

[^savchenko2022]: Savchenko, V. et al. "Detection of Slow DDoS Attacks Based on Time Delay Forecasting." CEUR Workshop Proceedings (2022). Response latency prediction for slow attack detection.

[^siam2026survey]: Siam, B. et al. "Entropy Based DDoS Detection and Mitigation Methods in SDN: A Survey." IEEE (2026). Comprehensive survey of entropy-based methods.

## 5. Priority Recommendations for ADDOS

### High Priority (direct bias fixes)

| Bias | Technique | Effort | Impact |
|------|-----------|--------|--------|
| TEA protocol bias | Use proto_entropy as 3rd detection dimension | Low | High |
| TEA aggregate bias | Activate per-IP entropy profiles for detection | Low | High |
| TEA threshold bias | Add threshold floor (prevent EWMA collapse) | Low | High |
| Prefilter no learning | Replace fixed thresholds with EWMA adaptive baseline | Medium | High |
| Prefilter rate bias | Add EWMA-based rate tracking with dual-alpha | Medium | High |

### Medium Priority (architecture improvements)

| Bias | Technique | Effort | Impact |
|------|-----------|--------|--------|
| TEA feature bias | Add conditional entropy H(dst_port \| src_ip) | Medium | Medium |
| TEA variance-only | Add KL divergence from baseline | Medium | Medium |
| TEA temporal bias | Multi-scale windows (250ms + 1s + 5s) | Medium | Medium |
| Prefilter protocol bias | Add TCP flag entropy monitoring | Medium | Medium |
| Prefilter per-IP bias | Add destination-centric rate tracking | Medium | Medium |

### Low Priority (advanced techniques)

| Bias | Technique | Effort | Impact |
|------|-----------|--------|--------|
| TEA aggregate bias | Sketch-based per-source aggregation | High | Medium |
| TEA temporal bias | Spectral/wavelet analysis for periodic patterns | High | Medium |
| Prefilter rate bias | Latency-based detection as secondary signal | High | Low |
| Both | Ensemble scoring (TEA + prefilter combined) | High | High |
| Both | Prefilter-to-ML feedback for self-tuning | High | Medium |

## Related Notes

- [[known-issues/anomaly-detection-improvements]]: existing architecture improvement suggestions
- [[known-issues/known-issues]]: gaps and discrepancies
- [[bugs/tea-attacks-flagged-as-normal]]: TEA detection gaps
- [[backend/tea-analysis]]: TEA design details
- [[backend/ml-pipeline]]: full pipeline data flow
