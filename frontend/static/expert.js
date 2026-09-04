// frontend/static/expert.js
// Expert Mode: live algorithmic internals visualization

let _expertPollTimer = null;
let _expertSSE = null;
let _expertActive = false;
let _ambientTimer = null;

function toggleExpertMode() {
  const btn = document.getElementById('expert-btn');
  const panels = document.getElementById('expert-panels');
  const body = document.body;

  if (!_expertActive) {
    _expertActive = true;
    window.EXPERT_MODE = true;
    btn.classList.add('active');
    btn.setAttribute('aria-pressed', 'true');
    btn.textContent = 'Expert Mode \u2713';
    panels.classList.remove('expert-hidden');
    document.getElementById('expert-pipeline-panel').classList.remove('expert-hidden');
    body.classList.add('expert-mode');
    startExpertMode();
    localStorage.setItem('addos-expert', '1');
    if (typeof showToast === 'function') showToast('Expert Mode enabled');
  } else {
    _expertActive = false;
    window.EXPERT_MODE = false;
    btn.classList.remove('active');
    btn.setAttribute('aria-pressed', 'false');
    btn.textContent = 'Expert Mode';
    panels.classList.add('expert-hidden');
    document.getElementById('expert-pipeline-panel').classList.add('expert-hidden');
    body.classList.remove('expert-mode');
    stopExpertMode();
    localStorage.setItem('addos-expert', '0');
    if (typeof showToast === 'function') showToast('Expert Mode disabled');
  }
}

window.toggleExpertMode = toggleExpertMode;

/* Restore saved expert mode state on load — mirrors the theme toggle pattern */
window.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem('addos-expert') === '1') toggleExpertMode();
});

function startExpertMode() {
  fetchExpert();
  _expertPollTimer = setInterval(fetchExpert, window.POLL_MS || 2000);
  connectExpertSSE();

  ExpertPipeline.init();
  ExpertStages.init();
  ExpertMetrics.init();

  if (_ambientTimer) clearInterval(_ambientTimer);
  _ambientTimer = setInterval(ExpertPipeline.spawnAmbientParticle, 2000);
}

function stopExpertMode() {
  if (_expertPollTimer) { clearInterval(_expertPollTimer); _expertPollTimer = null; }
  if (_expertSSE) { _expertSSE.close(); _expertSSE = null; }
  if (_ambientTimer) { clearInterval(_ambientTimer); _ambientTimer = null; }
  ExpertPipeline.stop();
}

async function fetchExpert() {
  try {
    var r = await fetch(window.API_URL + '/api/expert/live');
    if (!r.ok) return;
    var data = await r.json();
    window._lastExpertData = data;
    renderMLPanel(data.if, data.rf, data.tea);
    renderMitigationPanel(data.state_machine, data.deception, data.resource_guard);

    ExpertMetrics.updateStats(data.pipeline, data.tea, data.if, data.state_machine);
    ExpertPipeline.updateNodeGlow(data);

    if (data.if && data.if.recent_scores && data.if.recent_scores.length > 0) {
      var latest = data.if.recent_scores[0];
      var lastIf = ExpertState.ifHistory.length > 0 ? ExpertState.ifHistory[ExpertState.ifHistory.length - 1] : -1;
      if (latest.score !== lastIf) {
        ExpertState.ifHistory.push(latest.score);
        if (ExpertState.ifHistory.length > ExpertState.maxHistory) ExpertState.ifHistory = ExpertState.ifHistory.slice(-ExpertState.maxHistory);
      }
    }
    if (data.rf && data.rf.recent_classifications && data.rf.recent_classifications.length > 0) {
      var latestRf = data.rf.recent_classifications[0];
      var lastRf = ExpertState.rfHistory.length > 0 ? ExpertState.rfHistory[ExpertState.rfHistory.length - 1] : -1;
      if (latestRf.is_anomaly && latestRf.conf > 0 && latestRf.conf !== lastRf) {
        ExpertState.rfHistory.push(latestRf.conf);
        if (ExpertState.rfHistory.length > ExpertState.maxHistory) ExpertState.rfHistory = ExpertState.rfHistory.slice(-ExpertState.maxHistory);
      }
    }
    ExpertMetrics.updateTrend(ExpertState.ifHistory, ExpertState.rfHistory);
  } catch (e) {
    console.warn('Expert fetch failed:', e);
  }
}

function connectExpertSSE() {
  if (_expertSSE) _expertSSE.close();
  _expertSSE = new EventSource(window.API_URL + '/api/events');
  _expertSSE.onopen = () => {
    var indicator = document.querySelector('.expert-pipeline-live');
    if (indicator) {
      indicator.innerHTML = '<span class="expert-pipeline-live-dot"></span>streaming';
      indicator.style.color = '';
      var dot = indicator.querySelector('.expert-pipeline-live-dot');
      if (dot) { dot.style.animation = ''; dot.style.background = ''; }
    }
  };
  _expertSSE.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      if (event.type === 'expert' && event.payload) {
        handleExpertEvent(event.payload);
      }
    } catch (_) { }
  };
  _expertSSE.onerror = () => {
    _expertSSE.close();
    _expertSSE = null;
    var indicator = document.querySelector('.expert-pipeline-live');
    if (indicator) {
      indicator.innerHTML = '<span class="expert-pipeline-live-dot" style="animation:none;background:var(--sub2)"></span>polling';
      indicator.style.color = 'var(--sub2)';
    }
    if (_expertActive) setTimeout(connectExpertSSE, 3000);
  };
}

function handleExpertEvent(payload) {
  if (payload.tea_update) {
    updateTEASwitch(payload.tea_update);
    if (payload.tea_update.is_attack) {
      ExpertMetrics.appendLog('TEA: attack detected, diversity dropping', 'warn');
    }
  }
  if (payload.inference) {
    updateIFBar(payload.inference);
    ExpertPipeline.spawnParticleFromEvent(payload.inference);
    ExpertPipeline.spawnFeedbackParticle(payload.inference.is_anomaly);
    var cls = payload.inference.attack_class || 'unknown';
    var score = (payload.inference.if_score || 0).toFixed(4);
    var conf = (payload.inference.confidence || 0).toFixed(2);
    ExpertMetrics.appendLog(
      payload.inference.src_ip + ' -> ' + cls + ' (IF=' + score + ', conf=' + conf + ')',
      payload.inference.is_anomaly ? 'danger' : 'info'
    );
  }
  if (payload.mitigation) {
    var action = payload.mitigation.action || '';
    if (action === 'block' || action === 'rate_limit' || action === 'proto_block' || action === 'clear') {
      ExpertPipeline.spawnEnforceParticle(action);
      ExpertMetrics.appendLog('Enforcement: ' + action + ' command sent to Ryu', 'warn');
    }
    if (action === 'redirect') {
      ExpertPipeline.spawnRedirectParticle();
      ExpertMetrics.appendLog('Redirect: traffic sent to sinkhole', 'warn');
    }
  }
}

/* -- Expert Pipeline: Shared State ---------------------------------------- */

var ExpertState = {
  selectedStage: 'mininet',
  ifHistory: [],
  rfHistory: [],
  logEntries: [],
  maxHistory: 60,
  maxLog: 50
};

/* -- Expert Pipeline: Stage Data + Inspector ------------------------------ */

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

  init: function() {
    this.updateInspector(ExpertState.selectedStage);
  },

  updateInspector: function(key) {
    ExpertState.selectedStage = key;
    var s = this.data[key];
    var el = document.getElementById('expert-stage-inspector');
    if (!el) return;

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

/* -- Expert Pipeline: Canvas Rendering ------------------------------------ */

var ExpertPipeline = {
  canvas: null,
  ctx: null,
  container: null,
  particles: [],
  feedbackParticles: [],
  VIRTUAL_W: 950,
  VIRTUAL_H: 560,
  reducedMotion: false,
  _animFrame: null,
  latchState: { locked: false, streak: 0 },
  _hasSinkhole: false,

  nodes: {
    mininet:  { x: 150, y: 200, label: 'Mininet' },
    ryu:      { x: 350, y: 100, label: 'Ryu Controller' },
    zmq_rx:   { x: 600, y: 100, label: 'ZMQ Transport' },
    flood:    { x: 800, y: 200, label: 'Flood Prefilter' },
    entropy:  { x: 800, y: 360, label: 'Entropy Analyzer' },
    if_node:  { x: 600, y: 460, label: 'Isolation Forest' },
    rf:       { x: 350, y: 460, label: 'Random Forest' },
    decision: { x: 150, y: 360, label: 'Decision + Mitigation' },
    deception: { x: 50, y: 480, label: 'Deception / Sinkhole' },
    resource_guard: { x: 50, y: 120, label: 'Resource Guard' }
  },

  paths: [
    { from: 'mininet', to: 'ryu', label: 'traffic data' },
    { from: 'ryu', to: 'zmq_rx', label: 'flow reports' },
    { from: 'zmq_rx', to: 'flood', label: 'flow reports' },
    { from: 'flood', to: 'entropy', label: 'flagged IPs' },
    { from: 'entropy', to: 'if_node', label: 'traffic patterns' },
    { from: 'if_node', to: 'rf', label: 'suspicious flows' },
    { from: 'rf', to: 'decision', label: 'attack type' },
    { from: 'decision', to: 'ryu', kind: 'enforce' },
    { from: 'decision', to: 'deception', kind: 'redirect' },
    { from: 'decision', to: 'resource_guard', label: 'system stats' }
  ],

  nodeGlow: {},

  init: function() {
    this.canvas = document.getElementById('expert-pipeline-canvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.container = this.canvas.parentElement;

    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.isLightMode = document.body.classList.contains('light');

    for (var key in this.nodes) {
      this.nodes[key].colorHex = ExpertStages.data[key].color;
      this.nodeGlow[key] = 0;
    }

    this.resize();
    window.addEventListener('resize', this.resize.bind(this));

    this._nodeGlows = {};
    for (var key in this.nodes) {
      var node = this.nodes[key];
      var glowCanvas = document.createElement('canvas');
      glowCanvas.width = 80;
      glowCanvas.height = 80;
      var glowCtx = glowCanvas.getContext('2d');
      glowCtx.shadowBlur = 20;
      glowCtx.shadowColor = node.colorHex;
      glowCtx.fillStyle = node.colorHex + '30';
      glowCtx.beginPath();
      glowCtx.arc(40, 40, 30, 0, Math.PI * 2);
      glowCtx.fill();
      this._nodeGlows[key] = glowCanvas;
    }

    this._particleSprites = {};
    var particleColors = ['#F59E0B', '#E11D48', '#14B8A6', '#10B981', '#8B5CF6'];
    particleColors.forEach(function(color) {
      var pCanvas = document.createElement('canvas');
      pCanvas.width = 20;
      pCanvas.height = 20;
      var pCtx = pCanvas.getContext('2d');
      pCtx.shadowBlur = 10;
      pCtx.shadowColor = color;
      pCtx.fillStyle = color;
      pCtx.beginPath();
      pCtx.arc(10, 10, 5, 0, Math.PI * 2);
      pCtx.fill();
      this._particleSprites[color] = pCanvas;
    }.bind(this));

    this._feedbackSprites = {};
    var feedbackColors = ['#E11D48', '#10B981', '#F59E0B', '#8B5CF6'];
    feedbackColors.forEach(function(color) {
      var fCanvas = document.createElement('canvas');
      fCanvas.width = 24;
      fCanvas.height = 24;
      var fCtx = fCanvas.getContext('2d');
      fCtx.shadowBlur = 12;
      fCtx.shadowColor = color;
      fCtx.fillStyle = color;
      fCtx.beginPath();
      fCtx.arc(12, 12, 5, 0, Math.PI * 2);
      fCtx.fill();
      this._feedbackSprites[color] = fCanvas;
    }.bind(this));

    this.canvas.addEventListener('click', function(e) {
      var rect = this.canvas.getBoundingClientRect();
      var cx = e.clientX - rect.left;
      var cy = e.clientY - rect.top;
      for (var key in this.nodes) {
        var c = this._coords(this.nodes[key].x, this.nodes[key].y);
        if (Math.hypot(cx - c.x, cy - c.y) < 30) {
          ExpertStages.updateInspector(key);
          break;
        }
      }
    }.bind(this));

    this._lastFrameTime = 0;
    this._frameInterval = 1000 / 20;
    this._isOffscreen = false;

    var observer = new IntersectionObserver(function(entries) {
      this._isOffscreen = entries[0].intersectionRatio === 0;
    }.bind(this), { threshold: 0 });
    observer.observe(this.canvas);

    this._animFrame = requestAnimationFrame(this.drawScene.bind(this));
  },

  resize: function() {
    if (!this.container) return;
    this.canvas.width = this.container.clientWidth;
    this.canvas.height = Math.max(380, this.container.clientHeight);
  },

  _coords: function(nx, ny) {
    return { x: nx * (this.canvas.width / this.VIRTUAL_W), y: ny * (this.canvas.height / this.VIRTUAL_H) };
  },

  spawnParticleFromEvent: function(inferencePayload) {
    if (this.reducedMotion) return;
    var isAnomaly = inferencePayload.is_anomaly;

    // Path-specific colors
    var pathColors = {
      'mininet->ryu': '#10B981',
      'ryu->zmq_rx': '#14B8A6',
      'zmq_rx->flood': '#14B8A6',
      'flood->entropy': isAnomaly ? '#F59E0B' : '#10B981',
      'entropy->if_node': '#14B8A6',
      'if_node->rf': isAnomaly ? '#E11D48' : '#10B981',
      'rf->decision': isAnomaly ? '#E11D48' : '#10B981',
      'decision->resource_guard': '#14B8A6'
    };

    var now = performance.now();
    var forwardPaths = this.paths.filter(function(p) { return !p.feedback && p.kind !== 'redirect'; });
    forwardPaths.forEach(function(path, index) {
      // Skip if there's already a recent particle on this path (avoid reset mid-flight)
      var hasRecent = this.particles.some(function(p) {
        return p.from === path.from && p.to === path.to && (now - p.spawnTime) < 800;
      });
      if (hasRecent) return;

      var key = path.from + '->' + path.to;
      var color = pathColors[key] || '#10B981';
      this.particles.push({
        from: path.from, to: path.to,
        spawnTime: now, delay: index * 60,
        speed: 1.2,
        color: color, isFeedback: false
      });
    }.bind(this));
  },

  spawnFeedbackParticle: function(isAnomaly) {
    if (this.reducedMotion) return;
    var learnPath = this.paths.find(function(p) { return p.feedback && p.kind === 'learn'; });
    if (!learnPath) return;
    var color = isAnomaly ? '#E11D48' : '#10B981';
    this.feedbackParticles.push({
      from: learnPath.from, to: learnPath.to,
      spawnTime: performance.now(), delay: 0,
      speed: 1.2 + Math.random() * 0.6,
      color: color, isFeedback: true
    });
  },

  spawnEnforceParticle: function(action) {
    if (this.reducedMotion) return;
    this.lastEnforceAction = action || 'block';
    var enforcePath = this.paths.find(function(p) { return p.feedback && p.kind === 'enforce'; });
    if (!enforcePath) return;
    this.feedbackParticles.push({
      from: enforcePath.from, to: enforcePath.to,
      spawnTime: performance.now(), delay: 0,
      speed: 1.08 + Math.random() * 0.48,
      color: '#F59E0B', isFeedback: true
    });
  },

  spawnRedirectParticle: function() {
    if (this.reducedMotion) return;
    var redirectPath = this.paths.find(function(p) { return p.feedback && p.kind === 'redirect'; });
    if (!redirectPath) return;
    this.feedbackParticles.push({
      from: redirectPath.from, to: redirectPath.to,
      spawnTime: performance.now(), delay: 0,
      speed: 0.96 + Math.random() * 0.48,
      color: '#8B5CF6', isFeedback: true
    });
  },

  spawnAmbientParticle: function() {
    if (this.reducedMotion || this.particles.length > 40) return;
    var forwardPaths = this.paths.filter(function(p) { return !p.feedback && p.kind !== 'redirect'; });
    if (!forwardPaths.length) return;
    var path = forwardPaths[Math.floor(Math.random() * forwardPaths.length)];
    var colors = ['#10B981', '#14B8A6', '#10B981'];
    this.particles.push({
      from: path.from, to: path.to,
      spawnTime: performance.now(), delay: 0,
      speed: 0.6 + Math.random() * 0.4,
      color: colors[Math.floor(Math.random() * colors.length)],
      isFeedback: false
    });
  },

  updateNodeGlow: function(pollData) {
    var flagged = (pollData.pipeline && pollData.pipeline.flood_prefilter_flagged) || 0;
    var ifAnomalies = (pollData.if && pollData.if.score_distribution) ? pollData.if.score_distribution.anomaly || 0 : 0;
    var smCount = pollData.state_machine ? Object.keys(pollData.state_machine).length : 0;
    var sinkholeCount = pollData.deception && pollData.deception.active_sinkholes ? pollData.deception.active_sinkholes.length : 0;
    var rgTier = pollData.resource_guard && pollData.resource_guard.tier ? pollData.resource_guard.tier : 'NORMAL';

    var qSize = (pollData.pipeline && pollData.pipeline.worker_queue_size) || 0;
    var activeWorkers = (pollData.pipeline && pollData.pipeline.workers_active) || 0;
    var isLive = (qSize > 0 || activeWorkers > 0);

    this.nodeGlow.mininet = isLive ? 0.6 : 0;
    this.nodeGlow.ryu = isLive ? 0.6 : 0;
    this.nodeGlow.zmq_rx = Math.min(qSize / 500, 1) || (isLive ? 0.3 : 0);
    this.nodeGlow.flood = Math.min(flagged / 10, 1);
    this.nodeGlow.if_node = Math.min(ifAnomalies / 5, 1);
    this.nodeGlow.decision = Math.min(smCount / 3, 1);
    this.nodeGlow.entropy = (pollData.tea && pollData.tea.global && pollData.tea.global.is_attack) ? 0.8 : 0;
    this.nodeGlow.rf = (pollData.rf && pollData.rf.recent_classifications && pollData.rf.recent_classifications.length > 0) ? 0.6 : 0;
    this.nodeGlow.deception = Math.min(sinkholeCount / 3, 1);
    this._hasSinkhole = sinkholeCount > 0;
    this.nodeGlow.resource_guard = rgTier === 'CRIT' ? 1 : rgTier === 'HIGH' ? 0.7 : rgTier === 'WARN' ? 0.4 : 0;

    var teaGlobal = pollData.tea && pollData.tea.global;
    if (teaGlobal) {
      this.latchState = {
        locked: !!teaGlobal._locked,
        streak: teaGlobal._fb_normal_streak || 0
      };
    }
  },

  drawScene: function(timestamp) {
    if (!timestamp) timestamp = performance.now();
    this.isLightMode = document.body.classList.contains('light');
    var elapsed = timestamp - this._lastFrameTime;
    if (elapsed < this._frameInterval) {
      this._animFrame = requestAnimationFrame(this.drawScene.bind(this));
      return;
    }
    this._lastFrameTime = timestamp - (elapsed % this._frameInterval);

    if (this._isOffscreen) {
    if (this.particles.length > 40) this.particles.splice(0, this.particles.length - 40);
      if (this.feedbackParticles.length > 30) this.feedbackParticles.splice(0, this.feedbackParticles.length - 30);
      this._animFrame = requestAnimationFrame(this.drawScene.bind(this));
      return;
    }

    var ctx = this.ctx;
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
    var scaleY = this.canvas.height / this.VIRTUAL_H;

    this.paths.forEach(function(path) {
      var start = this._coords(this.nodes[path.from].x, this.nodes[path.from].y);
      var end = this._coords(this.nodes[path.to].x, this.nodes[path.to].y);
      var isCurved = path.feedback || path.kind === 'redirect';
      var isRedirect = path.kind === 'redirect';
      var redirectActive = isRedirect && this._hasSinkhole;
      var hasKind = !!path.kind;
      ctx.beginPath();
      ctx.moveTo(start.x, start.y);
      if (isCurved) {
        var cX = (start.x + end.x) / 2;
        var cY = (start.y + end.y) / 2 + (path.curve || -80) * scaleY;
        ctx.quadraticCurveTo(cX, cY, end.x, end.y);
        if (isRedirect) {
          ctx.strokeStyle = redirectActive
            ? (this.isLightMode ? 'rgba(139,92,246,0.7)' : 'rgba(139,92,246,0.6)')
            : (this.isLightMode ? 'rgba(139,92,246,0.45)' : 'rgba(139,92,246,0.4)');
        } else {
          ctx.strokeStyle = this.isLightMode ? 'rgba(180,83,9,0.5)' : 'rgba(245,158,11,0.4)';
        }
        ctx.lineWidth = 2;
        ctx.setLineDash([5, 4]);
      } else if (hasKind) {
        ctx.lineTo(end.x, end.y);
        ctx.strokeStyle = path.kind === 'enforce'
          ? (this.isLightMode ? 'rgba(180,83,9,0.5)' : 'rgba(245,158,11,0.4)')
          : (this.isLightMode ? 'rgba(0,0,0,0.10)' : 'rgba(255,255,255,0.25)');
        ctx.lineWidth = hasKind ? 2 : 1.4;
        ctx.setLineDash(hasKind ? [5, 4] : []);
      } else {
        ctx.lineTo(end.x, end.y);
        ctx.strokeStyle = this.isLightMode ? 'rgba(20,184,166,0.2)' : 'rgba(20,184,166,0.25)';
        ctx.lineWidth = 1.4;
      }
      ctx.stroke();
      ctx.setLineDash([]);

      // Arrow heads on forward paths
      if (!hasKind && !path.feedback) {
        var angle = Math.atan2(end.y - start.y, end.x - start.x);
        var arrowLen = 10;
        var arrowAngle = 0.4;
        // Position arrow before the end node circle (node radius is 24px, add padding)
        var ax = end.x - Math.cos(angle) * 32;
        var ay = end.y - Math.sin(angle) * 32;
        ctx.beginPath();
        ctx.moveTo(ax + Math.cos(angle) * arrowLen, ay + Math.sin(angle) * arrowLen);
        ctx.lineTo(ax - arrowLen * Math.cos(angle - arrowAngle), ay - arrowLen * Math.sin(angle - arrowAngle));
        ctx.moveTo(ax + Math.cos(angle) * arrowLen, ay + Math.sin(angle) * arrowLen);
        ctx.lineTo(ax - arrowLen * Math.cos(angle + arrowAngle), ay - arrowLen * Math.sin(angle + arrowAngle));
        ctx.strokeStyle = this.isLightMode ? 'rgba(20,184,166,0.5)' : 'rgba(20,184,166,0.6)';
        ctx.lineWidth = 2.5;
        ctx.stroke();
      }

      if (hasKind) {
        var lx, ly;
        if (isCurved) {
          var cX2 = (start.x + end.x) / 2;
          var cY2 = (start.y + end.y) / 2 + (path.curve || -80) * scaleY;
          lx = 0.25 * start.x + 0.5 * cX2 + 0.25 * end.x;
          ly = 0.25 * start.y + 0.5 * cY2 + 0.25 * end.y;
        } else {
          lx = (start.x + end.x) / 2;
          ly = (start.y + end.y) / 2 - 10;
        }
        ctx.font = '600 11px "Fira Code", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        var label = path.kind === 'redirect' ? 'redirects to sinkhole' : 'Sends decisions';
        var color = path.kind === 'redirect'
          ? (this.isLightMode ? 'rgba(139,92,246,0.8)' : 'rgba(139,92,246,0.6)')
          : (this.isLightMode ? 'rgba(180,83,9,0.8)' : 'rgba(245,158,11,0.6)');
        ctx.fillStyle = color;
        ctx.fillText(label, lx, ly);
      }

      if (path.label && !path.kind) {
        var fLx = (start.x + end.x) / 2;
        var fLy = (start.y + end.y) / 2 - 10;
        ctx.font = '600 10px "Fira Code", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        var tw = ctx.measureText(path.label).width;
        var px = fLx - tw / 2 - 5;
        var py = fLy - 8;
        var pw = tw + 10;
        var ph = 15;
        var pr = 4;
        ctx.beginPath();
        ctx.moveTo(px + pr, py);
        ctx.lineTo(px + pw - pr, py);
        ctx.arcTo(px + pw, py, px + pw, py + pr, pr);
        ctx.lineTo(px + pw, py + ph - pr);
        ctx.arcTo(px + pw, py + ph, px + pw - pr, py + ph, pr);
        ctx.lineTo(px + pr, py + ph);
        ctx.arcTo(px, py + ph, px, py + ph - pr, pr);
        ctx.lineTo(px, py + pr);
        ctx.arcTo(px, py, px + pr, py, pr);
        ctx.closePath();
        ctx.fillStyle = this.isLightMode ? 'rgba(255,255,255,0.85)' : 'rgba(30,41,59,0.85)';
        ctx.fill();
        ctx.strokeStyle = this.isLightMode ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)';
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = this.isLightMode ? 'rgba(51,65,85,0.7)' : 'rgba(248,250,252,0.5)';
        ctx.fillText(path.label, fLx, fLy);
      }
    }.bind(this));

    if (this.particles.length > 40) this.particles.splice(0, this.particles.length - 40);
    var currentTime = performance.now();
    for (var i = this.particles.length - 1; i >= 0; i--) {
      var p = this.particles[i];
      var age = currentTime - p.spawnTime - p.delay;
      if (age < 0) continue;
      p.progress = (age / 1000) * p.speed;
      if (p.progress >= 1) { this.particles.splice(i, 1); continue; }
      var s = this._coords(this.nodes[p.from].x, this.nodes[p.from].y);
      var e = this._coords(this.nodes[p.to].x, this.nodes[p.to].y);
      var px = s.x + (e.x - s.x) * p.progress;
      var py = s.y + (e.y - s.y) * p.progress;

      // Trail effect
      var trailLen = 3;
      for (var t = trailLen; t >= 1; t--) {
        var trailProgress = p.progress - (t * 0.012);
        if (trailProgress < 0) continue;
        var tx = s.x + (e.x - s.x) * trailProgress;
        var ty = s.y + (e.y - s.y) * trailProgress;
        ctx.beginPath();
        ctx.arc(tx, ty, 4 - t * 0.7, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = 0.2 - t * 0.05;
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Main particle
      var sprite = this._particleSprites[p.color];
      if (sprite) {
        ctx.drawImage(sprite, px - 10, py - 10);
      } else {
        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.fill();
      }
    }

    if (this.feedbackParticles.length > 30) this.feedbackParticles.splice(0, this.feedbackParticles.length - 30);
    for (var i = this.feedbackParticles.length - 1; i >= 0; i--) {
      var fp = this.feedbackParticles[i];
      var fAge = currentTime - fp.spawnTime - fp.delay;
      if (fAge < 0) continue;
      fp.progress = (fAge / 1000) * fp.speed;
      if (fp.progress >= 1) { this.feedbackParticles.splice(i, 1); continue; }
      var s = this._coords(this.nodes[fp.from].x, this.nodes[fp.from].y);
      var e = this._coords(this.nodes[fp.to].x, this.nodes[fp.to].y);
      var path = this.paths.find(function(p) { return p.feedback && p.from === fp.from && p.to === fp.to; });
      var curve = (path ? path.curve : -60) * scaleY;
      var cX = (s.x + e.x) / 2;
      var cY = (s.y + e.y) / 2 + curve;
      var px = s.x + (cX - s.x) * fp.progress * 2;
      var py = s.y + (cY - s.y) * fp.progress * 2;
      if (fp.progress > 0.5) {
        px = cX + (e.x - cX) * (fp.progress - 0.5) * 2;
        py = cY + (e.y - cY) * (fp.progress - 0.5) * 2;
      }
      var fSprite = this._feedbackSprites[fp.color];
      if (fSprite) {
        ctx.drawImage(fSprite, px - 12, py - 12);
      } else {
        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fillStyle = fp.color;
        ctx.fill();
      }
    }

    var time = Date.now();
    var pulseAlpha = Math.sin(time / 300) * 0.3 + 0.7;

    for (var key in this.nodes) {
      var node = this.nodes[key];
      var c = this._coords(node.x, node.y);
      var isSel = ExpertState.selectedStage === key;
      var glow = this.nodeGlow[key] || 0;
      if (key === 'deception') glow = this._hasSinkhole ? glow : 0;

      if (!this.isLightMode && glow > 0.05) {
        var glowSprite = this._nodeGlows[key];
        if (glowSprite) {
          ctx.globalAlpha = glow;
          ctx.drawImage(glowSprite, c.x - 40, c.y - 40);
          ctx.globalAlpha = 1;
        }
      }

      // Selected pulsing ring
      if (isSel) {
        ctx.beginPath();
        ctx.arc(c.x, c.y, 32, 0, Math.PI * 2);
        ctx.strokeStyle = node.colorHex;
        ctx.globalAlpha = pulseAlpha;
        ctx.lineWidth = 3;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Main node circle
      ctx.beginPath();
      ctx.arc(c.x, c.y, 24, 0, Math.PI * 2);

      if (this.isLightMode) {
        // Light mode: multi-layer depth with drop shadow
        ctx.shadowColor = 'rgba(0,0,0,0.15)';
        ctx.shadowBlur = 8;
        ctx.shadowOffsetY = 2;
        ctx.fillStyle = '#FFFFFF';
        ctx.fill();
        ctx.shadowBlur = 0;
        ctx.shadowOffsetY = 0;
        ctx.strokeStyle = '#e2e8f0';
        ctx.lineWidth = 2;
        ctx.stroke();
        // Inner accent ring
        ctx.beginPath();
        ctx.arc(c.x, c.y, 22, 0, Math.PI * 2);
        ctx.strokeStyle = node.colorHex + '40';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      } else {
        // Dark mode: vibrant glow
        ctx.fillStyle = '#1e293b';
        ctx.fill();
        ctx.strokeStyle = node.colorHex;
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      // Number inside
      ctx.font = '700 14px "Fira Code", monospace';
      ctx.fillStyle = this.isLightMode ? '#1e293b' : '#F8FAFC';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(ExpertStages.data[key].num, c.x, c.y);

      // Label below
      ctx.font = '600 12px "Fira Code", monospace';
      ctx.fillStyle = this.isLightMode ? '#334155' : (isSel ? '#F8FAFC' : 'rgba(248,250,252,0.7)');
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(node.label, c.x, c.y + 42);

      // Status indicator dot
      var dotGlow = this.nodeGlow[key] || 0;
      if (key === 'deception') dotGlow = this._hasSinkhole ? dotGlow : 0;
      var dotColor = dotGlow >= 0.8 ? '#E11D48' : dotGlow >= 0.5 ? '#F59E0B' : dotGlow > 0 ? '#10B981' : '#64748B';
      var dotX = c.x + 18;
      var dotY = c.y - 18;
      ctx.beginPath();
      ctx.arc(dotX, dotY, 4, 0, Math.PI * 2);
      ctx.fillStyle = dotColor;
      ctx.fill();
      ctx.strokeStyle = this.isLightMode ? '#FFFFFF' : '#1e293b';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // Legend - top right corner
    var legendX = this.canvas.width - 196;
    var legendY = 12;
    var legendBg = this.isLightMode ? 'rgba(255,255,255,0.9)' : 'rgba(30,41,59,0.9)';
    var legendBorder = this.isLightMode ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)';
    var legendText = this.isLightMode ? '#334155' : 'rgba(248,250,252,0.7)';
    var legendSubText = this.isLightMode ? '#64748B' : 'rgba(248,250,252,0.4)';

    // Background
    ctx.fillStyle = legendBg;
    ctx.strokeStyle = legendBorder;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(legendX, legendY, 180, 78, 8);
    ctx.fill();
    ctx.stroke();

    ctx.font = '600 10px "Fira Code", monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';

    // Data flow legend
    ctx.fillStyle = '#10B981';
    ctx.beginPath();
    ctx.arc(legendX + 14, legendY + 16, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = legendText;
    ctx.fillText('Normal traffic', legendX + 26, legendY + 16);

    // Processing legend
    ctx.fillStyle = '#14B8A6';
    ctx.beginPath();
    ctx.arc(legendX + 14, legendY + 32, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = legendText;
    ctx.fillText('Data processing', legendX + 26, legendY + 32);

    // Flagged legend
    ctx.fillStyle = '#F59E0B';
    ctx.beginPath();
    ctx.arc(legendX + 14, legendY + 48, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = legendText;
    ctx.fillText('Flagged / suspicious', legendX + 26, legendY + 48);

    // Attack legend
    ctx.fillStyle = '#E11D48';
    ctx.beginPath();
    ctx.arc(legendX + 14, legendY + 64, 5, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = legendText;
    ctx.fillText('Attack detected', legendX + 26, legendY + 64);

    this._animFrame = requestAnimationFrame(this.drawScene.bind(this));
  },

  stop: function() {
    if (this._animFrame) cancelAnimationFrame(this._animFrame);
  }
};

/* -- Expert Pipeline: Metrics + Terminal ---------------------------------- */

var ExpertMetrics = {
  init: function() {
    var el = document.getElementById('expert-live-metrics');
    if (!el) return;
    el.innerHTML =
      '<div class="expert-metrics-title">Live pipeline readout</div>' +
      '<div class="expert-metrics-row">' +
        '<div class="expert-stat"><span class="lbl">Packets / sec</span><span class="val" id="ep-pps" style="color:var(--text)">0</span><span class="note">pipeline input pps</span></div>' +
        '<div class="expert-stat"><span class="lbl">Size variance</span><span class="val" id="ep-entropy" style="color:var(--text)">0.00</span><span class="note">diversity variance</span></div>' +
        '<div class="expert-stat"><span class="lbl">TEA verdict</span><span class="val" id="ep-verdict" style="color:var(--green);font-size:15px">Normal</span><span class="note">TEA global verdict</span></div>' +
      '</div>' +
      '<div class="expert-proto-row">' +
        '<span class="expert-proto-title">First Line of Defense</span>' +
        '<div class="expert-pf-stats">' +
          '<div class="expert-pf-stat"><span class="expert-pf-label">Spikes Detected</span><span class="expert-pf-val" id="ep-pf-burst" style="color:var(--amber)">0</span><span class="expert-pf-label" style="margin-top:2px;font-size:9px">total</span></div>' +
        '</div>' +
      '</div>' +
      '<div class="expert-metrics-row">' +
        '<div class="expert-stat"><span class="lbl">IF Anomaly Rate</span><span class="val" id="ep-if-rate" style="color:var(--green)">0%</span><span class="note">anomalous flows</span></div>' +
        '<div class="expert-stat"><span class="lbl">Active Mitigations</span><span class="val" id="ep-mitigations" style="color:var(--green)">0</span><span class="note">IPs in state machine</span></div>' +
      '</div>' +
      '<div class="expert-trend-block">' +
        '<span class="expert-proto-title">Detection trend</span>' +
        '<svg class="expert-trend-svg" viewBox="0 0 300 46" preserveAspectRatio="none">' +
          '<line x1="0" y1="34" x2="300" y2="34" stroke="rgba(255,255,255,0.08)" stroke-width="1"/>' +
          '<polyline id="ep-trend-if" fill="none" stroke="#E11D48" stroke-width="1.6" points=""/>' +
          '<polyline id="ep-trend-rf" fill="none" stroke="#F59E0B" stroke-width="1.6" points=""/>' +
        '</svg>' +
        '<div class="expert-trend-legend">' +
          '<span><i style="background:#E11D48"></i>Isolation Forest score</span>' +
          '<span><i style="background:#F59E0B"></i>Random Forest confidence</span>' +
        '</div>' +
      '</div>' +
      '<div class="expert-terminal" id="ep-terminal">' +
        '<div style="color:var(--blue)">[INFO] Expert pipeline visualization initialized. Awaiting telemetry.</div>' +
      '</div>';
  },

  updateStats: function(pipeline, tea, ifData, stateMachine) {
    var ppsEl = document.getElementById('ep-pps');
    var entropyEl = document.getElementById('ep-entropy');
    var verdictEl = document.getElementById('ep-verdict');
    if (!ppsEl) return;

    var pps = (pipeline && pipeline.total_pps) || 0;
    ppsEl.textContent = Number(pps).toFixed(2);

    var entropy = (tea && tea.global) ? (tea.global.size_var || 0).toFixed(2) : '0.00';
    entropyEl.textContent = entropy;

    if (tea && tea.global && tea.global.is_attack) {
      verdictEl.textContent = 'Anomaly';
      verdictEl.style.color = 'var(--red)';
    } else if (tea && tea.global && !tea.global.learned) {
      verdictEl.textContent = 'Learning';
      verdictEl.style.color = '#4a9eff';
    } else if (tea && tea.global && tea.global._locked) {
      verdictEl.textContent = 'Uncertain';
      verdictEl.style.color = 'var(--yellow)';
    } else {
      verdictEl.textContent = 'Normal';
      verdictEl.style.color = 'var(--green)';
    }

    // Prefilter breakdown - use session cumulative data
    var pfSession = (pipeline && pipeline.flood_prefilter_session) || {};
    var pfBurst = document.getElementById('ep-pf-burst');
    if (pfBurst) pfBurst.textContent = pfSession.session_spike || 0;

    // IF anomaly rate
    var ifRateEl = document.getElementById('ep-if-rate');
    if (ifRateEl && ifData && ifData.score_distribution) {
      var an = ifData.score_distribution.anomaly || 0;
      var nm = ifData.score_distribution.normal || 0;
      var total = an + nm;
      ifRateEl.textContent = total > 0 ? Math.round(an / total * 100) + '%' : '0%';
      ifRateEl.style.color = an > 0 ? 'var(--red)' : 'var(--green)';
    }

    // Active mitigations
    var mitEl = document.getElementById('ep-mitigations');
    if (mitEl && stateMachine) {
      var count = Object.keys(stateMachine).length;
      mitEl.textContent = count;
      mitEl.style.color = count > 0 ? 'var(--amber)' : 'var(--green)';
    }
  },

  updateProtoCounts: function(rfDist) {
    var synEl = document.getElementById('ep-syn');
    var icmpEl = document.getElementById('ep-icmp');
    var udpEl = document.getElementById('ep-udp');
    if (!synEl) return;

    var dist = rfDist || {};
    synEl.textContent = dist['SYN Flood'] || 0;
    icmpEl.textContent = dist['ICMP Flood'] || 0;
    udpEl.textContent = dist['UDP Flood'] || 0;
  },

  updateTrend: function(ifScores, rfConfs) {
    var ifArr = ifScores || [];
    var rfArr = rfConfs || [];

    var toPoints = function(arr) {
      return arr.map(function(v, i) {
        var x = arr.length === 1 ? 0 : (i / (arr.length - 1)) * 300;
        var y = 40 - Math.max(0, Math.min(1, v)) * 34;
        return x.toFixed(1) + ',' + y.toFixed(1);
      }).join(' ');
    };

    var ifLine = document.getElementById('ep-trend-if');
    var rfLine = document.getElementById('ep-trend-rf');
    if (ifLine) ifLine.setAttribute('points', toPoints(ifArr));
    if (rfLine) rfLine.setAttribute('points', rfArr.length > 1 ? toPoints(rfArr) : '');
  },

  appendLog: function(text, type) {
    var term = document.getElementById('ep-terminal');
    if (!term) return;

    var colors = { warn: 'var(--amber)', danger: 'var(--red)', success: 'var(--green)', info: 'var(--sub)' };
    var row = document.createElement('div');
    row.style.color = colors[type] || colors.info;
    if (type === 'danger') row.style.fontWeight = '600';
    var t = new Date().toLocaleTimeString();
    row.textContent = '[' + t + '] ' + text;
    term.appendChild(row);
    term.scrollTop = term.scrollHeight;

    ExpertState.logEntries.push(row);
    while (term.children.length > ExpertState.maxLog) {
      term.removeChild(term.firstChild);
      ExpertState.logEntries.shift();
    }
  }
};


// ── Panel 2: ML Internals ────────────────────────────────────────────────
function renderMLPanel(ifData, rfData, teaData) {
  const el = document.getElementById('expert-ml-content');
  if (!el) return;

  if (!el.dataset.init) {
    el.innerHTML = `
      <div class="ml-if-wrap"></div>
      <div class="ml-rf-wrap"></div>
      <div class="ml-tea-wrap"></div>
    `;
    el.dataset.init = '1';
  }

  const ifWrap = el.querySelector('.ml-if-wrap');
  const rfWrap = el.querySelector('.ml-rf-wrap');
  const teaWrap = el.querySelector('.ml-tea-wrap');

  // IF Anomaly Thermometer
  const thr = ifData.threshold || 0.5992;

  let highestScore = 0;
  let isAnom = false;
  if (ifData.recent_scores && ifData.recent_scores.length > 0) {
    const sorted = [...ifData.recent_scores].sort((a, b) => b.score - a.score);
    highestScore = sorted[0].score;
    isAnom = sorted[0].anomaly;
  }

  const thrPct = 50; // threshold is always at center
  const fillPct = Math.min((highestScore / (thr * 2)) * 100, 100);

  let ifHtml = `<div class="ml-section">
    <div class="ml-section-title"><span class="accent-dot if-dot"></span>Isolation Forest (IF) Threat Level</div>
    <div class="if-thermometer">
      <div class="if-thermometer-fill ${isAnom ? 'anomaly' : 'normal'}" style="width: ${fillPct}%"></div>
      <div class="if-thermometer-threshold" style="left: ${thrPct}%"></div>
    </div>
    <div class="if-stats">
      <span>Max: ${highestScore.toFixed(4)}</span>
      <span>Threshold: ${thr.toFixed(4)}</span>
    </div>
  </div>`;
  if (ifWrap) ifWrap.innerHTML = ifHtml;

  // RF Traffic Composition Bar — only SYN/ICMP/UDP (RF's actual decisions among IF-flagged anomalies)
  const dist = rfData.class_distribution || { 'SYN Flood': 0, 'ICMP Flood': 0, 'UDP Flood': 0 };
  const attackOnly = (dist['SYN Flood'] || 0) + (dist['ICMP Flood'] || 0) + (dist['UDP Flood'] || 0);
  const total = attackOnly || 1;

  const synPct = (dist['SYN Flood'] || 0) / total * 100;
  const icmpPct = (dist['ICMP Flood'] || 0) / total * 100;
  const udpPct = (dist['UDP Flood'] || 0) / total * 100;

  const hasAttacks = attackOnly > 0;

  let rfHtml = `<div class="ml-section">
    <div class="ml-section-title"><span class="accent-dot rf-dot"></span>Random Forest (RF) Composition</div>
    <div class="rf-segmented-bar">
      ${hasAttacks ? `
      ${synPct > 0 ? `<div class="rf-segment syn"    style="width: ${synPct}%">${synPct > 10 ? synPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${icmpPct > 0 ? `<div class="rf-segment icmp"   style="width: ${icmpPct}%">${icmpPct > 10 ? icmpPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${udpPct > 0 ? `<div class="rf-segment udp"    style="width: ${udpPct}%">${udpPct > 10 ? udpPct.toFixed(0) + '%' : ''}</div>` : ''}
      ` : `
      <div class="rf-segment" style="width:100%;background:var(--track-bg);color:var(--sub2)">No anomalies</div>
      `}
    </div>
    <div class="rf-legend">
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:var(--amber)"></span>SYN</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#f472b6"></span>ICMP</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#60b4ff"></span>UDP</div>
    </div>
  </div>`;
  if (rfWrap) rfWrap.innerHTML = rfHtml;

    // TEA Global Feature Entropy
    const teaGlobal = teaData.global || null;
    if (teaGlobal && Object.keys(teaGlobal).length > 0) {
      const isAttack = teaGlobal.is_attack;
      const isFlash = teaGlobal.is_flash_crowd;
      const isLearned = teaGlobal.learned;
      const isLocked = teaGlobal._locked === true;

      const statusClass = isAttack ? 'attack' : isFlash ? 'flash-crowd' : !isLearned ? 'learning' : isLocked ? 'uncertain' : 'learned';
      const statusText = isAttack ? 'ATTACK' : isFlash ? 'FLASH CROWD' : !isLearned ? 'LEARNING' : isLocked ? 'UNCERTAIN' : 'NORMAL';

      const maxSizeZ = teaGlobal.size_z || 0;
      const maxIntZ = teaGlobal.intensity_z || 0;

      // Clamp fill to [0, 100] using a -3..+3 z-score window mapped to 0..100%
      const sizeZPct = Math.min(Math.max((maxSizeZ + 3) / 6 * 100, 0), 100);
      const intZPct = Math.min(Math.max((maxIntZ + 3) / 6 * 100, 0), 100);

      // Single threshold marker position (attack sigma)
      const attackSigma = teaGlobal.dynamic_attack_sigma || 2.5;
      const thresholdPct = Math.min(Math.max((attackSigma + 3) / 6 * 100, 0), 100);

      // Learning progress
      const learningInterval = teaGlobal.learning_interval;
      const learningIntervals = teaGlobal.learning_intervals || 15;
      const learningProgress = !isLearned && learningInterval ? `${learningInterval}/${learningIntervals}` : '';

      // Baseline history for sparklines
      const sizeBaselineHist = teaGlobal.size_baseline_history || [];
      const intBaselineHist = teaGlobal.intensity_baseline_history || [];

      // Sparkline SVG generation
      function makeSparkline(data, color) {
        if (!data || data.length < 1) return '<div class="sparkline-placeholder">—</div>';
        if (data.length === 1) {
          return `<svg class="sparkline" viewBox="0 0 120 30" preserveAspectRatio="none">
            <polyline fill="none" stroke="${color}" stroke-width="1.5" points="0,15 120,15"/>
          </svg>`;
        }
        const max = Math.max(...data);
        const min = Math.min(...data);
        const range = max - min || 1;
        const w = 120, h = 30;
        // Vertical padding keeps the trace centered on its row instead of
        // riding the top/bottom edge when the data trends.
        const pad = h * 0.2;
        const usable = h - pad * 2;
        const points = data.map((v, i) => {
          const x = (i / (data.length - 1)) * w;
          const y = h - pad - ((v - min) / range) * usable;
          return `${x.toFixed(1)},${y.toFixed(1)}`;
        }).join(' ');
        return `<svg class="sparkline" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
          <polyline fill="none" stroke="${color}" stroke-width="1.5" vector-effect="non-scaling-stroke" points="${points}"/>
        </svg>`;
      }

      const existingCard = teaWrap.querySelector('.controller-tea-card');
      if (!existingCard) {
        teaWrap.innerHTML = `
          <div class="ml-section">
            <div class="ml-section-title"><span class="accent-dot tea-dot"></span>Temporal Entropy Analysis</div>
            <div class="tea-switch-card controller-tea-card">
              <div class="tea-switch-header">
                <span class="tea-switch-title">Aggregation</span>
                <span class="tea-switch-status ${statusClass}">${statusText}</span>
                ${learningProgress ? '<span class="tea-learning-progress">' + learningProgress + '</span>' : ''}
              </div>
              <div class="zscore-container">
                <div class="zscore-row" id="tea-size">
                  <div class="zscore-header">
                    <div class="zscore-label">Avg Div Entropy <span class="zscore-val">${teaGlobal.size_var.toFixed(4)}</span></div>
                  </div>
                  <div class="zscore-track">
                    <div class="zscore-midline" title="Baseline (z=0)"></div>
                    <div class="zscore-threshold" style="left: ${thresholdPct}%;" title="Attack threshold (${attackSigma.toFixed(1)}σ)"></div>
                    <div class="zscore-fill ${maxSizeZ >= 2 ? 'anomaly' : ''}" style="width: ${sizeZPct}%"></div>
                  </div>
                  <div class="zscore-stats">
                    <span>Z-score: ${maxSizeZ >= 0 ? '+' : ''}${maxSizeZ.toFixed(1)}z</span>
                  </div>
                </div>
                <div class="zscore-row" id="tea-int">
                  <div class="zscore-header">
                    <div class="zscore-label">Avg Pkt Intensity <span class="zscore-val">${teaGlobal.intensity_var.toFixed(4)}</span></div>
                  </div>
                  <div class="zscore-track">
                    <div class="zscore-midline" title="Baseline (z=0)"></div>
                    <div class="zscore-threshold" style="left: ${thresholdPct}%;" title="Attack threshold (${attackSigma.toFixed(1)}σ)"></div>
                    <div class="zscore-fill ${maxIntZ >= 2 ? 'anomaly' : ''}" style="width: ${intZPct}%"></div>
                  </div>
                  <div class="zscore-stats">
                    <span>Z-score: ${maxIntZ >= 0 ? '+' : ''}${maxIntZ.toFixed(1)}z</span>
                  </div>
                </div>
              </div>
              <div class="tea-caption">Z-score tracks: current variance vs baseline. Line = baseline (z=0). Marker = attack threshold. Fill = current z-score.</div>
              <div class="tea-sparklines">
                <div class="sparkline-row">
                  <span class="sparkline-label">Size baseline</span>
                  ${makeSparkline(sizeBaselineHist, '#14B8A6')}
                </div>
                <div class="sparkline-row">
                  <span class="sparkline-label">Intensity baseline</span>
                  ${makeSparkline(intBaselineHist, '#F59E0B')}
                </div>
              </div>
            </div>
          </div>`;
    } else {
      const statusEl = existingCard.querySelector('.tea-switch-status');
      // confidence chip removed; signal chips handled in updateTEASwitch
      const progEl = existingCard.querySelector('.tea-learning-progress');
      if (statusEl) { statusEl.className = `tea-switch-status ${statusClass}`; statusEl.textContent = statusText; }
      // signal chips are live-updated in updateTEASwitch(); nothing to patch here
      if (progEl) { progEl.textContent = learningProgress; progEl.style.display = learningProgress ? 'inline' : 'none'; }

      const sizeRow = document.getElementById('tea-size');
      if (sizeRow) {
        sizeRow.querySelector('.zscore-val').textContent = teaGlobal.size_var.toFixed(4);
        const threshold = sizeRow.querySelector('.zscore-threshold');
        if (threshold) { threshold.style.left = thresholdPct + '%'; }
      }
      const intRow = document.getElementById('tea-int');
      if (intRow) {
        intRow.querySelector('.zscore-val').textContent = teaGlobal.intensity_var.toFixed(4);
        const threshold = intRow.querySelector('.zscore-threshold');
        if (threshold) { threshold.style.left = thresholdPct + '%'; }
      }

      // Update sparklines
      const sizeSpark = existingCard.querySelector('.sparkline-row:first-child .sparkline');
      const intSpark = existingCard.querySelector('.sparkline-row:last-child .sparkline');
      if (sizeSpark) sizeSpark.outerHTML = makeSparkline(sizeBaselineHist, '#14B8A6');
      if (intSpark) intSpark.outerHTML = makeSparkline(intBaselineHist, '#F59E0B');
    }
  } else {
    if (teaWrap) teaWrap.innerHTML = '';
  }
}


function updateTEASwitch(tea) {
  // Real-time update from SSE tea_update events
  if (!tea) return;
  
  // Update latch state for feedback edge visualization
  if (ExpertPipeline.latchState) {
    if (tea._locked !== undefined) ExpertPipeline.latchState.locked = tea._locked;
    if (tea._fb_normal_streak !== undefined) ExpertPipeline.latchState.streak = tea._fb_normal_streak;
  }
  
  // Update TEA card z-score values in real-time
  const sizeRow = document.getElementById('tea-size');
  const intRow = document.getElementById('tea-int');
  
  if (sizeRow && tea.size_z != null) {
    const fill = sizeRow.querySelector('.zscore-fill');
    if (fill) {
      const pct = Math.min(Math.max((tea.size_z + 3) / 6 * 100, 0), 100);
      fill.style.width = pct + '%';
      fill.className = 'zscore-fill' + (tea.size_z >= 2 ? ' anomaly' : '');
    }
    const statsEl = sizeRow.querySelector('.zscore-stats span:first-child');
    if (statsEl) statsEl.textContent = 'Z-score: ' + (tea.size_z >= 0 ? '+' : '') + tea.size_z.toFixed(1) + 'z';
  }

  if (intRow && tea.intensity_z != null) {
    const fill = intRow.querySelector('.zscore-fill');
    if (fill) {
      const pct = Math.min(Math.max((tea.intensity_z + 3) / 6 * 100, 0), 100);
      fill.style.width = pct + '%';
      fill.className = 'zscore-fill' + (tea.intensity_z >= 2 ? ' anomaly' : '');
    }
    const statsEl = intRow.querySelector('.zscore-stats span:first-child');
    if (statsEl) statsEl.textContent = 'Z-score: ' + (tea.intensity_z >= 0 ? '+' : '') + tea.intensity_z.toFixed(1) + 'z';
  }
  
  // Update status badge
  const statusEl = document.querySelector('.tea-switch-status');
  if (statusEl) {
    if (tea.is_attack) {
      statusEl.className = 'tea-switch-status attack';
      statusEl.textContent = 'ATTACK';
    } else if (tea.is_flash_crowd) {
      statusEl.className = 'tea-switch-status flash-crowd';
      statusEl.textContent = 'FLASH CROWD';
    } else if (!tea.is_learned) {
      statusEl.className = 'tea-switch-status learning';
      statusEl.textContent = 'LEARNING';
    } else if (tea._locked === true) {
      // Latch still closed after the attack signal stopped - baselines are
      // frozen but traffic looks normal, so the verdict is not trustworthy
      // in either direction. Matches the poll path's Uncertain display.
      statusEl.className = 'tea-switch-status uncertain';
      statusEl.textContent = 'UNCERTAIN';
    } else {
      statusEl.className = 'tea-switch-status learned';
      statusEl.textContent = 'NORMAL';
    }
  }

}

function updateIFBar(inf) {
  // Real-time update from SSE inference events
  if (!inf) return;
  
  // Update IF thermometer
  const thermometer = document.querySelector('.if-thermometer-fill');
  if (thermometer) {
    const score = inf.if_score || 0;
    const threshold = 0.5992;
    const fillPct = Math.min((score / (threshold * 2)) * 100, 100);
    thermometer.style.width = fillPct + '%';
    thermometer.className = 'if-thermometer-fill' + (inf.is_anomaly ? ' anomaly' : ' normal');
  }
  
  // Update max score display
  const statsEl = document.querySelector('.if-stats span:first-child');
  if (statsEl && inf.if_score != null) {
    statsEl.textContent = 'Max: ' + inf.if_score.toFixed(4);
  }
}

// ── Panel 3: Mitigation State Machine ────────────────────────────────────
function renderMitigationPanel(smStates, deception, rg) {
  const el = document.getElementById('expert-mitigation-content');
  if (!el) return;

  const phaseCounts = { 1: 0, 2: 0, 3: 0 };
  Object.values(smStates).forEach(s => { if (s.phase) phaseCounts[s.phase] = (phaseCounts[s.phase] || 0) + 1; });

  const hasActiveFlow = Object.values(smStates).length > 0;

  if (!el.dataset.init) {
    let html = `<div class="mitigation-phases ${hasActiveFlow ? 'active-flow' : ''}">`;
    html += `
      <div class="phase-box quarantine">
        <div class="phase-label">Quarantine</div>
        <div class="phase-count" data-phase="1">${phaseCounts[1]}</div>
        <div class="phase-action">Rate Limited</div>
      </div>
      <div class="phase-box ban">
        <div class="phase-label">Time Ban</div>
        <div class="phase-count" data-phase="2">${phaseCounts[2]}</div>
        <div class="phase-action">Blocked</div>
      </div>
      <div class="phase-box blackhole">
        <div class="phase-label">Blackhole</div>
        <div class="phase-count" data-phase="3">${phaseCounts[3]}</div>
        <div class="phase-action">1h TTL</div>
      </div>
    </div>`;
    html += `<div class="ml-section"><div class="ml-section-title">Active States</div><div class="terminal-feed" id="mitigation-ip-list"></div></div>`;
    el.innerHTML = html;
    el.dataset.init = '1';
  }

  const phasesEl = el.querySelector('.mitigation-phases');
  if (phasesEl) {
    if (hasActiveFlow && !phasesEl.classList.contains('active-flow')) phasesEl.classList.add('active-flow');
    if (!hasActiveFlow && phasesEl.classList.contains('active-flow')) phasesEl.classList.remove('active-flow');
  }

  const phaseCountEls = el.querySelectorAll('.phase-count');
  phaseCountEls.forEach(phaseEl => {
    const phase = parseInt(phaseEl.dataset.phase);
    phaseEl.textContent = phaseCounts[phase];
  });

  const ipListEl = document.getElementById('mitigation-ip-list');
  if (ipListEl) {
    const activeIPs = Object.entries(smStates);
    const renderIPs = activeIPs.slice(0, 20);
    let ipHtml = '';
    renderIPs.forEach(([ip, s]) => {
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });
      const pri = s.priority || 'Low';
      const priClass = pri === 'Critical' ? 't-crit' : pri === 'High' ? 't-alert' : pri === 'Medium' ? 't-stat' : '';
      ipHtml += `
        <div class="terminal-line">
          <span class="t-time">[${now}]</span>
          <span class="t-ip">${ip}</span>
          ${priClass ? `<span class="${priClass}">${pri.toUpperCase()}</span>` : `<span class="t-stat">${pri.toUpperCase()}</span>`}
          <span class="t-crit">PHASE_${s.phase}</span>
          <span class="t-stat">IF=${s.if_score.toFixed(4)}</span>
          <span class="t-stat">PPS=${(s.recent_pps || 0).toFixed(1)}</span>
          <span class="t-alert">ACT=${s.action.toUpperCase()}</span>
          ${s.ttl_sec != null ? `<span class="t-stat">TTL=${s.ttl_sec}s</span>` : ''}
        </div>`;
    });
    ipListEl.innerHTML = ipHtml;
  }
}

function exportExpertSnapshot() {
  // Gather all expert panel data from DOM or re-fetch
  fetch(window.API_URL + '/api/expert/live')
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `addos-expert-snapshot-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      if (typeof showToast === 'function') showToast('Expert snapshot downloaded');
    })
    .catch(() => { if (typeof showToast === 'function') showToast('Export failed', true); });
}

window.exportExpertSnapshot = exportExpertSnapshot;

/* -- Expert Modals: Algorithm Detail Popups -------------------------------- */

var ExpertModals = {
  _pollTimer: null,

  open: function(stageKey) {
    var overlay = document.getElementById('expert-modal-overlay');
    var body = document.getElementById('expert-modal-body');
    var head = document.querySelector('.expert-modal-head');
    if (!overlay || !body) return;
    var s = ExpertStages.data[stageKey];
    if (!s) return;

    var badge = head.querySelector('.expert-modal-badge');
    var title = head.querySelector('.expert-modal-title');
    if (badge) {
      badge.style.background = s.color + '22';
      badge.style.borderColor = s.color + '55';
      badge.style.color = s.color;
      badge.textContent = s.num;
    }
    if (title) title.textContent = s.title;

    this._renderBody(stageKey, body);
    overlay.classList.add('open');

    var self = this;
    if (this._pollTimer) clearInterval(this._pollTimer);
    this._pollTimer = setInterval(function() {
      if (!document.getElementById('expert-modal-overlay').classList.contains('open')) {
        clearInterval(self._pollTimer);
        self._pollTimer = null;
        return;
      }
      self._renderBody(stageKey, document.getElementById('expert-modal-body'));
    }, 2000);
  },

  close: function() {
    var overlay = document.getElementById('expert-modal-overlay');
    if (overlay) overlay.classList.remove('open');
    if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
  },

  _renderBody: function(key, el) {
    var d = window._lastExpertData || {};
    if (key === 'flood') this._renderPrefilter(d, el);
    else if (key === 'entropy') this._renderTEA(d, el);
    else if (key === 'if_node') this._renderIF(d, el);
    else if (key === 'rf') this._renderRF(d, el);
  },

  _renderPrefilter: function(d, el) {
    var pf = (d.pipeline && d.pipeline.flood_prefilter_breakdown) || {};
    var pfSession = (d.pipeline && d.pipeline.flood_prefilter_session) || {};

    // Session summary
    var spikeCount = pfSession.session_spike || 0;

    // Per-protocol breakdown — session-cumulative counts (persist across attack lifecycle)
    var sessionByProto = pfSession.session_flagged_by_proto || {};
    var protoHtml = '';
    ['SYN', 'ICMP', 'UDP'].forEach(function(proto) {
      var count = sessionByProto[proto] || 0;
      var hasData = count > 0;
      protoHtml += '<div style="margin-bottom:12px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:10px">' +
        '<div style="display:flex;align-items:center;justify-content:space-between">' +
          '<span style="font-size:16px;font-weight:800;font-family:var(--mono)">' + proto + '</span>' +
          '<span style="font-size:15px;font-weight:700;color:' + (hasData ? 'var(--red)' : 'var(--green)') + '">' + count + ' flagged</span>' +
        '</div>' +
        (hasData ?
          '<div style="font-size:13px;color:var(--sub2);margin-top:4px">' + count + ' source' + (count !== 1 ? 's' : '') + ' detected this session</div>'
        : '<div style="font-size:13px;color:var(--sub2);margin-top:4px">No detections yet</div>') +
      '</div>';
    });

    // Flagged IP list - use current snapshot (live state)
    var flaggedHtml = '';
    var seen = {};
    Object.entries(pf).forEach(function(entry) {
      var proto = entry[0];
      var bd = entry[1];
      if (bd.flagged_ips_list) {
        bd.flagged_ips_list.forEach(function(item) {
          var ipAddr = typeof item === 'string' ? item : item.ip;
          if (!seen[ipAddr]) seen[ipAddr] = [];
          if (seen[ipAddr].indexOf(proto) === -1) seen[ipAddr].push(proto);
        });
      }
    });
    var entries = Object.entries(seen).slice(0, 20);
    if (entries.length === 0) {
      flaggedHtml = '<div style="font-size:15px;color:var(--sub2);padding:12px 0">No active flagged sources</div>';
    } else {
      entries.forEach(function(e) {
        var ip = e[0], protos = e[1];
        var multi = protos.length > 1 ? ' <span style="color:var(--red);font-weight:700">MULTI</span>' : '';
        flaggedHtml += '<div class="expert-modal-signal-row"><span style="font-weight:700;min-width:130px;font-family:var(--mono)">' + ip + '</span><span style="min-width:80px">' + protos.join('+') + '</span>' + multi + '</div>';
      });
    }

    el.innerHTML =
      '<div class="expert-modal-section"><div class="expert-modal-section-title">What it does</div><div class="expert-modal-desc">The first guard. It watches how many packets each source IP is sending, for each protocol (SYN, ICMP, UDP). It learns what is normal for each source over time using a moving average. If a source suddenly sends way more than usual, or if a huge burst arrives in a fraction of a second, that source gets flagged. If the same source is flagged on two or more protocols at the same time, it is likely a coordinated attack.</div></div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Session Summary</div>' +
        '<div style="display:flex;gap:12px;flex-wrap:wrap">' +
          '<span style="padding:6px 14px;border-radius:8px;font-size:16px;font-weight:700;background:rgba(245,158,11,0.15);color:var(--amber)">Spikes: ' + spikeCount + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Detection by Protocol</div>' + protoHtml + '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Currently Active (' + entries.length + ')</div>' + flaggedHtml + '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">How it decides</div><div class="expert-modal-logic">A source is flagged when: (1) its packet rate goes above 3 times what the system learned as normal for that protocol, OR (2) it sends a big burst (40% of the limit) in less than 0.1 seconds. The baseline adjusts over time. If the same source is flagged on 2+ protocols at the same time, it is marked as a coordinated multi-protocol attack.</div></div>';
  },

  _renderTEA: function(d, el) {
    var g = (d.tea && d.tea.global) || {};
    var szVar = g.size_var || 0;
    var intVar = g.intensity_var || 0;
    var szBase = g.size_baseline || 0;
    var intBase = g.intensity_baseline || 0;
    var attackSigma = g.dynamic_attack_sigma || 2.5;
    var szZ = g.size_z || 0;
    var intZ = g.intensity_z || 0;
    var szPct = Math.min(Math.max((szZ + 3) / 6 * 100, 0), 100);
    var intPct = Math.min(Math.max((intZ + 3) / 6 * 100, 0), 100);
    var thrPct = Math.min(Math.max((attackSigma + 3) / 6 * 100, 0), 100);
    var isAttack = !!g.is_attack;
    var locked = !!g._locked;
    var confidence = g.confidence || 'LOW'; // retained for other consumers; TEA UI uses detection signals below
    var learned = !!g.learned;
    var learningInterval = g.learning_interval || 0;
    var learningIntervals = g.learning_intervals || 15;
    var varClass = isAttack ? 'var(--red)' : 'var(--blue)';

    var statusText = isAttack ? 'ATTACK' : locked ? 'LOCKED' : learned ? 'NORMAL' : 'LEARNING';
    var statusColor = isAttack ? 'var(--red)' : locked ? 'var(--amber)' : learned ? 'var(--green)' : 'var(--blue)';

    var learningHtml = '';
    if (!learned) {
      var pct = Math.round(learningInterval / learningIntervals * 100);
      learningHtml = '<div style="margin-top:12px"><div style="font-size:15px;color:var(--sub2);margin-bottom:8px">Learning: ' + learningInterval + '/' + learningIntervals + ' intervals (' + pct + '%)</div>' +
        '<div class="expert-modal-gauge-track"><div class="expert-modal-gauge-fill" style="width:' + pct + '%;background:var(--blue)"></div></div></div>';
    }

    // Shadow learning
    var shadow = g.shadow || null;
    var shadowHtml = '';
    if (shadow && shadow.active) {
      var shadowReady = shadow.learned && shadow.age_s >= 300;
      var shadowStatus = shadowReady ? 'Ready for promotion' : 'Learning';
      var shadowColor = shadowReady ? 'var(--green)' : 'var(--blue)';
      var shadowPct = shadow.sample_count > 0 ? Math.min(Math.round(shadow.sample_count / 300 * 100), 100) : 0;
      shadowHtml = '<div style="margin-top:14px;padding:16px;background:var(--surface);border:1px solid var(--border);border-radius:12px">' +
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">' +
          '<span style="font-size:16px;font-weight:700">Shadow Baseline</span>' +
          '<span style="padding:4px 10px;border-radius:6px;font-size:13px;font-weight:600;background:' + shadowColor + '22;color:' + shadowColor + ';border:1px solid ' + shadowColor + '44">' + shadowStatus + '</span>' +
        '</div>' +
        '<div style="display:flex;gap:20px;font-size:15px;color:var(--sub);margin-bottom:8px">' +
          '<span>Samples: ' + shadow.sample_count + '/300</span>' +
          '<span>Age: ' + shadow.age_s.toFixed(0) + 's / 300s</span>' +
        '</div>' +
        '<div class="expert-modal-gauge-track" style="margin-bottom:8px"><div class="expert-modal-gauge-fill" style="width:' + shadowPct + '%;background:' + shadowColor + '"></div></div>' +
        (shadow.size_mean != null ? '<div style="font-size:14px;color:var(--sub2)">Shadow size mean: ' + shadow.size_mean.toFixed(4) + '</div>' : '') +
        (shadow.intensity_mean != null ? '<div style="font-size:14px;color:var(--sub2)">Shadow intensity mean: ' + shadow.intensity_mean.toFixed(4) + '</div>' : '') +
        '<div style="font-size:14px;color:var(--sub2);margin-top:8px">Learns in parallel while primary is frozen during attack. Promotes when ready to replace corrupted baseline.</div>' +
      '</div>';
    }

    el.innerHTML =
      '<div class="expert-modal-section"><div class="expert-modal-section-title">What it does</div><div class="expert-modal-desc">Measures how varied and diverse the traffic is. Normal traffic has many different source IPs, destination ports, and packet sizes. A flood is the opposite - repetitive, uniform, and predictable. When diversity drops below normal, it raises an alarm. During an attack, it freezes its memory of what normal looks like.</div></div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Diversity Tracks</div>' +
        this._teaTrack('Size Diversity', szZ, szPct, thrPct, varClass, szBase) +
        this._teaTrack('Packet Intensity', intZ, intPct, thrPct, varClass, intBase) +
        '<div style="font-size:15px;color:var(--sub2);margin-top:12px">Center line = normal baseline. Bars going left = less diversity (flood). Red line = attack threshold.</div>' +
      '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Status</div>' +
        '<div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:14px">' +
          '<span style="padding:6px 14px;border-radius:8px;font-size:15px;font-weight:700;background:' + statusColor + '22;color:' + statusColor + ';border:1px solid ' + statusColor + '44">' + statusText + '</span>' +
        '</div>' +
        (learned ?
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 24px;margin-bottom:14px">' +
            '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:14px;color:var(--sub);min-width:100px">Verdict</span><span style="padding:3px 10px;border-radius:6px;font-size:13px;font-weight:700;font-family:var(--mono);background:' + (isAttack ? 'var(--red-g)' : 'var(--green-g)') + ';color:' + (isAttack ? 'var(--red)' : 'var(--green)') + ';border:1px solid ' + (isAttack ? 'rgba(225,29,72,0.3)' : 'rgba(46,204,113,0.3)') + '">' + (isAttack ? 'ATTACK' : 'NORMAL') + '</span></div>' +
            '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:14px;color:var(--sub);min-width:100px">Size diversity</span><span style="padding:3px 10px;border-radius:6px;font-size:13px;font-weight:700;font-family:var(--mono);background:' + (g.size_surge ? 'var(--amber-g)' : 'var(--track-bg)') + ';color:' + (g.size_surge ? 'var(--amber)' : 'var(--sub2)') + ';border:1px solid ' + (g.size_surge ? 'rgba(245,158,11,0.3)' : 'var(--border2)') + '">' + (g.size_surge ? 'SURGE' : 'OK') + '</span></div>' +
            '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:14px;color:var(--sub);min-width:100px">Intensity</span><span style="padding:3px 10px;border-radius:6px;font-size:13px;font-weight:700;font-family:var(--mono);background:' + (g.intensity_surge ? 'var(--amber-g)' : 'var(--track-bg)') + ';color:' + (g.intensity_surge ? 'var(--amber)' : 'var(--sub2)') + ';border:1px solid ' + (g.intensity_surge ? 'rgba(245,158,11,0.3)' : 'var(--border2)') + '">' + (g.intensity_surge ? 'SURGE' : 'OK') + '</span></div>' +
            '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:14px;color:var(--sub);min-width:100px">PPS</span><span style="padding:3px 10px;border-radius:6px;font-size:13px;font-weight:700;font-family:var(--mono);background:' + (g.pps_surge ? 'var(--amber-g)' : 'var(--track-bg)') + ';color:' + (g.pps_surge ? 'var(--amber)' : 'var(--sub2)') + ';border:1px solid ' + (g.pps_surge ? 'rgba(245,158,11,0.3)' : 'var(--border2)') + '">' + (g.pps_surge ? 'SURGE' : 'OK') + '</span></div>' +
          '</div>'
        : '') +
        learningHtml +
        shadowHtml +
      '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">How it decides</div><div class="expert-modal-logic">Compares current traffic diversity to what it learned as normal. If the z-score drops below a negative threshold, traffic is less diverse than normal - a flood signal. The latch freezes memory during attacks so the flood does not corrupt the baseline. It unlocks only when both the anomaly detector and entropy analyzer agree traffic has returned to normal.</div></div>';
  },

  _teaTrack: function(label, z, pct, thrPct, color, baseVal) {
    return '<div style="margin-bottom:16px"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">' +
      '<span style="font-size:15px;font-weight:700">' + label + '</span>' +
      '<span style="font-size:15px;font-family:var(--mono);color:' + color + ';font-weight:600">' + (z >= 0 ? '+' : '') + z.toFixed(1) + 'z</span>' +
    '</div>' +
    '<div class="expert-modal-gauge-track">' +
      '<div class="expert-modal-gauge-fill" style="width:' + pct + '%;background:' + color + '"></div>' +
      '<div class="expert-modal-gauge-marker" style="left:50%;background:#fff"></div>' +
      '<div class="expert-modal-gauge-marker" style="left:' + thrPct + '%;background:var(--red)"></div>' +
    '</div>' +
    '<div style="font-size:14px;color:var(--sub2);margin-top:4px">baseline mean: ' + baseVal.toFixed(4) + '</div></div>';
  },

  _renderIF: function(d, el) {
    var ifData = d.if || {};
    var threshold = ifData.threshold || 0.5992;
    var recentScores = ifData.recent_scores || [];
    var dist = ifData.score_distribution || { normal: 0, anomaly: 0 };
    var total = (dist.normal || 0) + (dist.anomaly || 0);
    var anomPct = total > 0 ? Math.round((dist.anomaly || 0) / total * 100) : 0;
    var normalCount = dist.normal || 0;
    var anomalyCount = dist.anomaly || 0;
    var highestScore = 0;
    var isAnom = false;
    if (recentScores.length > 0) {
      var sorted = recentScores.slice().sort(function(a, b) { return b.score - a.score; });
      highestScore = sorted[0].score;
      isAnom = sorted[0].anomaly;
    }
    var fillPct = Math.min(highestScore / 1 * 100, 100);
    var thrPct = Math.min(threshold / 1 * 100, 100);
    var scoreColor = isAnom ? 'var(--red)' : 'var(--green)';
    var verdict = isAnom ? 'ANOMALY' : 'NORMAL';

    // Recent scores sparkline with threshold reference
    var sparkHtml = '';
    if (recentScores.length > 0) {
      var last20 = recentScores.slice(-20);
      var w = 500, h = 80;
      var pad = 10;
      var usable = h - pad * 2;
      var thrY = h - pad - (threshold / 1) * usable;
      var pts = last20.map(function(s, i) {
        var x = last20.length === 1 ? pad : pad + (i / (last20.length - 1)) * (w - pad * 2);
        var y = h - pad - (Math.min(s.score, 1) / 1) * usable;
        return x.toFixed(1) + ',' + y.toFixed(1);
      }).join(' ');
      // Threshold area fill
      var thrAreaPts = pts + ' ' + (w - pad) + ',' + thrY + ' ' + pad + ',' + thrY;
      sparkHtml = '<svg style="width:100%;height:' + h + 'px" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
        '<rect x="' + pad + '" y="0" width="' + (w - pad * 2) + '" height="' + thrY + '" fill="rgba(225,29,72,0.06)"/>' +
        '<line x1="' + pad + '" y1="' + thrY + '" x2="' + (w - pad) + '" y2="' + thrY + '" stroke="rgba(225,29,72,0.4)" stroke-width="1.5" stroke-dasharray="6,4"/>' +
        '<text x="' + (w - pad - 4) + '" y="' + (thrY - 6) + '" fill="rgba(225,29,72,0.6)" font-size="11" font-family="monospace" text-anchor="end">threshold</text>' +
        '<polyline fill="none" stroke="' + scoreColor + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" points="' + pts + '"/>' +
        last20.map(function(s, i) {
          var x = last20.length === 1 ? pad : pad + (i / (last20.length - 1)) * (w - pad * 2);
          var y = h - pad - (Math.min(s.score, 1) / 1) * usable;
          var dotColor = s.anomaly ? 'var(--red)' : 'var(--green)';
          return '<circle cx="' + x + '" cy="' + y + '" r="4" fill="' + dotColor + '" stroke="var(--card)" stroke-width="1.5"/>';
        }).join('') +
      '</svg>';
    }

    el.innerHTML =
      '<div class="expert-modal-section"><div class="expert-modal-section-title">What it does</div><div class="expert-modal-desc">Looks at every flow (a conversation between two IPs) and asks: does this look like the normal traffic I was trained on? It randomly cuts the data into pieces. Normal flows need many cuts to separate. Anomalous flows stand out quickly with fewer cuts. The fewer cuts needed, the more suspicious the flow.</div></div>' +

      '<div class="expert-modal-section"><div class="expert-modal-section-title">Current Score</div>' +
        '<div style="display:flex;align-items:baseline;gap:16px;margin-bottom:10px">' +
          '<span style="font-size:32px;font-weight:800;font-family:var(--mono);color:' + scoreColor + '">' + highestScore.toFixed(4) + '</span>' +
          '<span style="font-size:16px;font-weight:700;padding:4px 12px;border-radius:6px;background:' + scoreColor + '22;color:' + scoreColor + ';border:1px solid ' + scoreColor + '44">' + verdict + '</span>' +
        '</div>' +
        '<div class="expert-modal-gauge-track" style="height:20px">' +
          '<div class="expert-modal-gauge-fill" style="width:' + fillPct + '%;background:' + scoreColor + '"></div>' +
          '<div class="expert-modal-gauge-marker" style="left:' + thrPct + '%;background:var(--red)"></div>' +
        '</div>' +
        '<div style="display:flex;justify-content:space-between;margin-top:6px;font-size:14px;color:var(--sub2)">' +
          '<span>0 (normal)</span>' +
          '<span>threshold: ' + threshold.toFixed(4) + '</span>' +
          '<span>1 (anomalous)</span>' +
        '</div>' +
      '</div>' +

      '<div class="expert-modal-section"><div class="expert-modal-section-title">Score Distribution (last ' + total + ' flows)</div>' +
        '<div class="expert-modal-gauge-track" style="height:20px;display:flex;overflow:hidden">' +
          '<div class="expert-modal-gauge-fill" style="width:' + (100 - anomPct) + '%;background:var(--green);border-radius:' + (anomPct === 0 ? '8px' : '8px 0 0 8px') + '"></div>' +
          '<div class="expert-modal-gauge-fill" style="width:' + anomPct + '%;background:var(--red);border-radius:' + ((100 - anomPct) === 0 ? '8px' : '0 8px 8px 0') + '"></div>' +
        '</div>' +
        '<div style="display:flex;gap:24px;font-size:13px;margin-top:14px">' +
          '<span style="display:flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:var(--green);display:inline-block"></span><span style="color:var(--sub2)">' + normalCount + ' normal (' + (100 - anomPct) + '%)</span></span>' +
          '<span style="display:flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:50%;background:var(--red);display:inline-block"></span><span style="color:var(--sub2)">' + anomalyCount + ' anomalous (' + anomPct + '%)</span></span>' +
        '</div>' +
      '</div>' +

      (sparkHtml ? '<div class="expert-modal-section"><div class="expert-modal-section-title">Recent Scores (last 20)</div>' +
        '<div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px">' +
          '<div style="display:flex;gap:16px;margin-bottom:8px;font-size:13px">' +
            '<span style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:50%;background:var(--green);display:inline-block"></span> normal flow</span>' +
            '<span style="display:flex;align-items:center;gap:6px"><span style="width:10px;height:10px;border-radius:50%;background:var(--red);display:inline-block"></span> anomalous flow</span>' +
            '<span style="display:flex;align-items:center;gap:6px"><span style="width:20px;height:0;border-top:2px dashed rgba(225,29,72,0.4);display:inline-block"></span> threshold</span>' +
          '</div>' +
          sparkHtml +
        '</div>' +
      '</div>' : '') +

      '<div class="expert-modal-section"><div class="expert-modal-section-title">How it decides</div><div class="expert-modal-logic">Each flow gets a score from 0 to 1. A score near 0 looks normal. A score near 1 looks very different from normal. The threshold is set during training. If above threshold, the flow is sent to Random Forest to identify the attack type. Below threshold = normal, not forwarded.</div></div>';
  },

  _renderRF: function(d, el) {
    var rf = d.rf || {};
    var dist = rf.class_distribution || {};
    var gate = rf.conf_gate || 0.6;
    var recent = rf.recent_classifications || [];
    var attackOnly = (dist['SYN Flood'] || 0) + (dist['ICMP Flood'] || 0) + (dist['UDP Flood'] || 0);
    var total = attackOnly || 1;
    var segs = [
      { key: 'SYN Flood', color: 'var(--amber)', label: 'SYN' },
      { key: 'ICMP Flood', color: '#f472b6', label: 'ICMP' },
      { key: 'UDP Flood', color: '#60b4ff', label: 'UDP' },
    ];
    var barHtml = '';
    var legendHtml = '';
    segs.forEach(function(seg) {
      var count = dist[seg.key] || 0;
      var pct = total > 0 ? Math.round(count / total * 100) : 0;
      if (pct > 0) {
        barHtml += '<div style="width:' + pct + '%;background:' + seg.color + ';display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600;color:' + (seg.key === 'Normal' ? '#fff' : '#000') + '">' + (pct > 8 ? pct + '%' : '') + '</div>';
        legendHtml += '<span style="font-size:14px;color:' + seg.color + ';font-weight:600">' + seg.label + ': ' + pct + '%</span>';
      }
    });
    if (!barHtml) barHtml = '<div style="width:100%;background:var(--green);display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:600;color:#fff">No data</div>';

    var confPct = Math.round(gate * 100);
    var headerRow = '<div class="expert-modal-signal-row" style="border-bottom:2px solid var(--border);padding-bottom:8px;margin-bottom:4px">' +
      '<span style="font-weight:700;min-width:130px;font-size:13px;color:var(--sub2);text-transform:uppercase;letter-spacing:.06em">Source IP</span>' +
      '<span style="min-width:110px;font-size:13px;color:var(--sub2);text-transform:uppercase;letter-spacing:.06em">Classification</span>' +
      '<span style="font-size:13px;color:var(--sub2);text-transform:uppercase;letter-spacing:.06em">Confidence</span>' +
    '</div>';
    var rowsHtml = headerRow;
    var classified = recent.filter(function(c) { return c.attack_class && c.attack_class !== 'Uncertain'; });
    classified.slice(0, 10).forEach(function(c) {
      var confVal = typeof c.conf === 'number' ? (c.conf <= 1 ? (c.conf * 100).toFixed(2) : Number(c.conf).toFixed(2)) : '0.00';
      rowsHtml += '<div class="expert-modal-signal-row">' +
        '<span style="font-weight:700;min-width:130px">' + c.src_ip + '</span>' +
        '<span style="min-width:110px;color:var(--red)">' + c.attack_class + '</span>' +
        '<span>' + confVal + '%</span>' +
      '</div>';
    });
    if (classified.length === 0) rowsHtml += '<div style="font-size:15px;color:var(--sub2);padding:12px 0">Waiting for first classification...</div>';

    el.innerHTML =
      '<div class="expert-modal-section"><div class="expert-modal-section-title">What it does</div><div class="expert-modal-desc">Takes suspicious flows from the previous step and figures out what kind of attack it is. Many small decision trees each look at different features and vote on the attack type. The final answer is whichever type got the most votes.</div></div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Vote Breakdown</div>' +
        '<div class="expert-modal-gauge-track" style="height:24px;display:flex;overflow:hidden;border-radius:8px">' + barHtml + '</div>' +
        '<div style="display:flex;gap:14px;margin-top:10px;flex-wrap:wrap">' + legendHtml + '</div>' +
        '<div style="font-size:15px;color:var(--sub2);margin-top:10px">Each segment shows how many trees voted for that attack type.</div>' +
      '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Confidence Gate</div>' +
        '<div style="font-size:18px;font-weight:700">Gate threshold: ' + confPct + '%</div>' +
        '<div style="font-size:15px;color:var(--sub2);margin-top:8px">The system only acts when enough trees agree. If they disagree, it waits for more data. This prevents false alarms.</div>' +
      '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">Recent Classifications</div>' + rowsHtml + '</div>' +
      '<div class="expert-modal-section"><div class="expert-modal-section-title">How it decides</div><div class="expert-modal-logic">Each decision tree votes on the attack type. The final prediction is whichever type got the most votes. The confidence is the percentage of trees that agreed. If confidence is below the gate threshold, the system waits for more data. If above, it issues a mitigation command to block or rate-limit the source.</div></div>';
  }
};

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') ExpertModals.close();
});