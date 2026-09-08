/**
 * Topology stage metadata, algorithmic formulas, and stage inspection view renderer for expert mode.
 * Maintains telemetry history buffers and renders deep-dive mathematical descriptions of pipeline stages.
 */

// Global expert mode state tracking selected stage, telemetry time-series, and log queues.
var ExpertState = {
  selectedStage: 'mininet',
  ifHistory: [],
  rfHistory: [],
  logEntries: [],
  maxHistory: 60,
  maxLog: 50
};

// Structural definitions, descriptions, formulas, and I/O specifications for all pipeline stages.
var ExpertStages = {
  data: {
    mininet: {
      num: 1, color: '#14B8A6',
      title: 'Mininet Network Topology',
      file: 'topology/topology.py',
      desc: 'Software-defined network emulation comprising a core OpenFlow switch (s0) and eight edge switches (s1-s8). Fifteen legitimate hosts generate baseline TCP, UDP, and ICMP traffic at realistic intervals, while ten attacker hosts produce sustained high-volume floods. Host h26 serves as the whitelisted target server; h27 operates as a silent sinkhole for deception redirects.',
      input: '1 core switch (s0) + 8 edge switches (s1-s8)\n27 hosts total:\n  h1-h15: legitimate TCP/UDP/ICMP (3-7s intervals)\n  h16-h19: SYN flood (ports 80, 443, 5432, 3389)\n  h20-h22: UDP flood (ports 53, 123, 1900)\n  h23-h25: ICMP flood\n  h26: target server (10.0.0.26), whitelisted\n  h27: sinkhole (10.0.0.27), passive',
      output: 'Raw packets traversing OpenFlow switches'
    },
    ryu: {
      num: 2, color: '#14B8A6',
      title: 'Ryu SDN Controller',
      file: 'controller/ryu_controller.py',
      desc: 'SDN controller functioning as the network enforcement point. Polls OpenFlow switches for per-flow statistics (packet count, byte count, duration) and receives mitigation commands from the Decision Engine, installing corresponding drop rules on the switch datapath.',
      input: 'OpenFlow Packet-In events\nand per-flow stat replies',
      output: 'Structured flow statistics:\npacket_count, byte_count, duration, ports'
    },
    zmq_rx: {
      num: 3, color: '#14B8A6',
      title: 'ZeroMQ Transport',
      file: 'backend/transport/zmq_receiver.py',
      desc: 'Asynchronous message transport layer bridging the SDN controller and detection backend. Queues flow reports for non-blocking delivery, ensuring uninterrupted network operation during periods of high analytical load.',
      input: 'Serialized JSON flow\nreports from Ryu',
      output: 'Decoded flow dictionaries\npushed into the worker queue'
    },
    flood: {
      num: 4, color: '#F59E0B',
      title: 'Flood Prefilter',
      file: 'backend/pipeline/flood_prefilter.py',
      desc: 'Rate-based prefilter employing exponentially weighted moving average (EWMA) thresholds. Monitors per-source, per-protocol packet arrival rates for SYN, ICMP, and UDP traffic against dynamically learned baselines. Flags sources that exceed adaptive thresholds or exhibit sub-second burst patterns. Correlates simultaneous protocol violations to identify coordinated multi-vector attacks.',
      input: 'Per-packet protocol classification\nand source IP, on each flow arrival',
      output: 'Binary flag (exceeded or not)\nper source IP and protocol',
      formula: [
        { f: 'ewma = (1 - alpha) * ewma + alpha * current_pps', note: 'EWMA baseline learning with alpha = 0.1' },
        { f: 'threshold = max(ewma * 3.0, floor = 25)', note: 'adaptive limit with minimum floor' },
        { f: 'burst: count >= 40% of threshold in 0.1s or 0.5s', note: 'sub-second spike detection' },
        { f: 'correlation: 2+ protocols tripped simultaneously', note: 'multi-vector attack identification' }
      ]
    },
    entropy: {
      num: 5, color: '#F59E0B',
      title: 'Entropy Analyzer (TEA)',
      file: 'backend/pipeline/entropy_analyzer.py',
      desc: 'Temporal Entropy Analyzer (TEA) maintains rolling baselines of traffic diversity and intensity per switch. Computes Shannon entropy across source IP and port distributions, then applies z-score analysis against the learned baseline. A significant negative deviation indicates repetitive, low-diversity traffic characteristic of automated floods. A latch mechanism freezes the baseline during active attacks to prevent contamination.',
      input: 'Flow stream with per-switch\nrolling packet-rate baseline',
      output: 'Diversity score and pass/hold\ndecision for downstream stages',
      formula: [
        { f: 'H = -sum(p_i * log2(p_i))', note: 'Shannon entropy across source IPs and ports' },
        { f: 'mu_t = a * x_t + (1 - a) * mu_{t-1}', note: 'exponentially weighted baseline update' },
        { f: 'z = (x - mu) / sigma, flagged when z < -sigma_attack', note: 'z-score deviation over 15-interval window' }
      ]
    },
    if_node: {
      num: 6, color: '#E11D48',
      title: 'Isolation Forest',
      file: 'backend/models/if_pipeline.py',
      desc: 'Unsupervised anomaly detector trained exclusively on normal traffic patterns. Scores each flow by its average isolation path length: anomalous observations isolate quickly (shorter paths) and receive higher anomaly scores. Only flows exceeding the fixed threshold are forwarded to the Random Forest for supervised classification.',
      input: '16-feature vector per flow\n(traffic rates, ratios, timing)',
      output: 'Anomaly score (0 to 1) with\nthreshold exceedance flag',
      formula: [
        { f: 's(x, n) = 2^(-E(h(x)) / c(n))', note: 'anomaly score from average path length' }
      ]
    },
    rf: {
      num: 7, color: '#14B8A6',
      title: 'Random Forest',
      file: 'backend/models/rf_pipeline.py',
      desc: 'Supervised classifier invoked exclusively on flows flagged anomalous by the Isolation Forest. Predicts attack type (SYN Flood, ICMP Flood, or UDP Flood) through majority voting across an ensemble of decision trees. Enforcement actions are triggered only when classification confidence exceeds the configured gate threshold.',
      input: '15-feature vector, exclusively\nfor IF-flagged anomalous flows',
      output: 'Attack class (SYN/ICMP/UDP Flood)\nwith confidence score',
      formula: [
        { f: 'y_hat = mode{T_1(x), T_2(x), ..., T_k(x)}', note: 'majority vote across k decision trees' },
        { f: 'confidence = votes(y_hat) / k', note: 'acted upon when confidence >= conf_gate' }
      ]
    },
    decision: {
      num: 8, color: '#F59E0B',
      title: 'Decision + Mitigation',
      file: 'backend/pipeline/decision_engine.py',
      desc: 'Final arbitration stage that evaluates the Isolation Forest anomaly score and Random Forest classification against configured thresholds. When confidence is sufficient, issues enforcement commands to the Ryu Controller via ZeroMQ: rate limiting (Phase 1), full blocking (Phase 2), deception redirect, or clearance.',
      input: 'IF anomaly score with\nRF class and confidence',
      output: 'Enforcement commands:\nrate_limit, block, clear, redirect, proto_block'
    },
    deception: {
      num: 9, color: '#8B5CF6',
      title: 'Deception / Sinkhole',
      file: 'backend/mitigation/deception.py',
      desc: 'Redirects quarantined traffic to the sinkhole host (h27, 10.0.0.27) for controlled observation. Monitors attack persistence and classifier confidence over a 30-second observation window. Escalates to Phase 1 rate limiting if traffic persists with high confidence; otherwise releases the source.',
      input: 'Quarantined IPs with\nunresolved attack vector',
      output: 'OpenFlow redirect to sinkhole,\nescalation to Phase 1 or release'
    },
    resource_guard: {
      num: 10, color: '#EC4899',
      title: 'Resource Guard',
      file: 'backend/mitigation/resource_guard.py',
      desc: 'Monitors Ryu controller CPU and memory utilization. At HIGH tier, throttles detection rate with a 20ms processing delay. At CRIT tier, installs OpenFlow proto_block rules to shed excess Packet-In load. Automatically recovers when resource utilization normalizes.',
      input: 'Ryu CPU/memory metrics\n(polled every 2 seconds)',
      output: 'Throttle delay (20ms/50ms) and\nproto_block rules on attack protocol',
      formula: [
        { f: 'HIGH: cpu > 70% OR mem > 80%', note: 'detection throttled with 20ms delay' },
        { f: 'CRIT: cpu > 90% OR mem > 95%', note: 'proto_block rules installed on attack protocol' },
        { f: 'recovery: cpu < 50% AND mem < 60% for 10s', note: 'automatic throttle/block removal' }
      ]
    }
  },

  /**
   * Initializes the stage inspector by binding the default selected stage to the DOM.
   * Ensures the detail panel displays valid content upon initial page load.
   */
  init: function() {
    this.updateInspector(ExpertState.selectedStage);
  },

  /**
   * Updates the stage inspector pane with metadata and mathematical formulas for the given stage.
   * Reconstructs the formula list, input/output mappings, and modal explanation button.
   */
  updateInspector: function(key) {
    ExpertState.selectedStage = key;
    var s = this.data[key];
    var el = document.getElementById('expert-stage-inspector');
    if (!el || !s) return;

    var formulaHtml = '';
    if (s.formula && s.formula.length) {
      formulaHtml = '<div class="expert-formula-block show">' +
        '<span class="expert-formula-label">Formula</span>' +
        s.formula.map(function(row) {
          return '<div class="expert-formula-line">' + row.f + '<span class="note">, ' + row.note + '</span></div>';
        }).join('') +
        '</div>';
    }

    var hiwHtml = '';
    if (s.formula && s.formula.length) {
      hiwHtml = '<button class="expert-hiw-btn" onclick="ExpertModals.open(\'' + key + '\')">' +
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' +
        'How it works - see details' +
        '</button>';
    }

    el.innerHTML =
      '<div class="expert-inspector-head">' +
        '<div class="expert-stage-badge" style="background:' + s.color + '22;border:1px solid ' + s.color + '55;color:' + s.color + '">' + s.num + '</div>' +
        '<div>' +
          '<h3 class="expert-inspector-title">' + s.title + '</h3>' +
          '<div class="expert-inspector-file">' + s.file + '</div>' +
        '</div>' +
      '</div>' +
      '<p class="expert-inspector-desc">' + s.desc + '</p>' +
      formulaHtml +
      '<div class="expert-io-row">' +
        '<div class="expert-io-col input"><span class="lbl">Receives</span><div class="body">' + s.input + '</div></div>' +
        '<div class="expert-io-arrow">&rarr;</div>' +
        '<div class="expert-io-col output"><span class="lbl">Hands off</span><div class="body">' + s.output + '</div></div>' +
      '</div>' +
      hiwHtml;
  }
};

window.ExpertState = ExpertState;
window.ExpertStages = ExpertStages;
