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
  _ambientTimer = setInterval(ExpertPipeline.spawnAmbientParticle, 1200);
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
    renderMLPanel(data.if, data.rf, data.tea);
    renderMitigationPanel(data.state_machine, data.deception, data.resource_guard);

    ExpertMetrics.updateStats(data.pipeline, data.tea, data.if);
    ExpertMetrics.updateProtoCounts(data.rf.class_distribution);
    ExpertPipeline.updateNodeGlow(data);

    if (data.if && data.if.recent_scores) {
      var scores = data.if.recent_scores.map(function(s) { return s.score; });
      ExpertState.ifHistory = scores.slice(-ExpertState.maxHistory);
    }
    if (data.rf && data.rf.recent_classifications) {
      var confs = data.rf.recent_classifications.map(function(c) { return c.conf; });
      ExpertState.rfHistory = confs.slice(-ExpertState.maxHistory);
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
        { f: 'z = (x - mu) / sigma, flagged when z < -sigma_attack', note: 'z-score deviation over 15-interval window' },
        { f: 'confidence: HIGH (z < -3), MODERATE (z < -2), LOW', note: 'deviation severity classification' }
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
        { f: 's(x, n) = 2^(-E(h(x)) / c(n))', note: 'anomaly score from average path length' },
        { f: 'if_score = -score_samples(x)', note: 'flagged when if_score >= threshold' },
        { f: 'threshold = 0.5992 (frozen model)', note: 'fixed at training; not retrained at runtime' }
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
        { f: 'confidence = votes(y_hat) / k', note: 'acted upon when confidence >= conf_gate' },
        { f: 'conf_gate = 0.65 (frozen model)', note: 'minimum confidence for mitigation trigger' }
      ]
    },
    decision: {
      num: 8, color: '#F59E0B',
      title: 'Decision + Mitigation',
      file: 'backend/pipeline/decision_engine.py',
      desc: 'Final arbitration stage that evaluates the Isolation Forest anomaly score and Random Forest classification against configured thresholds. When confidence is sufficient, issues enforcement commands to the Ryu Controller via ZeroMQ: rate limiting (Phase 1), full blocking (Phase 2), deception redirect, or clearance.',
      input: 'IF anomaly score with\nRF class and confidence',
      output: 'Enforcement commands:\nrate_limit, block, clear, redirect, proto_block',
      formula: [
        { f: 'Phase 1: if_score >= 0.5992 AND conf >= 0.65', note: 'quarantine with rate limiting' },
        { f: 'Phase 2: escalation after persistence check', note: 'full block via OVS flow rules' },
        { f: 'Phase 3: blackhole for 3600s (1 hour)', note: 'final mitigation with TTL expiry' }
      ]
    },
    deception: {
      num: 9, color: '#8B5CF6',
      title: 'Deception / Sinkhole',
      file: 'backend/mitigation/deception.py',
      desc: 'Redirects quarantined traffic to the sinkhole host (h27, 10.0.0.27) for controlled observation. Monitors attack persistence and classifier confidence over a 30-second observation window. Escalates to Phase 1 rate limiting if traffic persists with high confidence; otherwise releases the source.',
      input: 'Quarantined IPs with\nunresolved attack vector',
      output: 'OpenFlow redirect to sinkhole,\nescalation to Phase 1 or release',
      formula: [
        { f: 'observation_window = 30s', note: 'attack persistence measurement period' },
        { f: 'escalate: persistence > 0.8 AND confidence >= 0.65', note: 'sustained attack with high RF confidence' },
        { f: 'release: persistence < 0.3 OR confidence < 0.4', note: 'traffic ceased or classifier uncertain' }
      ]
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
      '</div>';
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
    { from: 'mininet', to: 'ryu' },
    { from: 'ryu', to: 'zmq_rx' },
    { from: 'zmq_rx', to: 'flood' },
    { from: 'flood', to: 'entropy' },
    { from: 'entropy', to: 'if_node' },
    { from: 'if_node', to: 'rf' },
    { from: 'rf', to: 'decision' },
    { from: 'decision', to: 'ryu', kind: 'enforce' },
    { from: 'decision', to: 'deception', kind: 'redirect' },
    { from: 'decision', to: 'resource_guard' }
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
    var particleColors = ['#F59E0B', '#E11D48', '#14B8A6', '#94A3B8', '#10B981', '#8B5CF6'];
    particleColors.forEach(function(color) {
      var pCanvas = document.createElement('canvas');
      pCanvas.width = 20;
      pCanvas.height = 20;
      var pCtx = pCanvas.getContext('2d');
      pCtx.shadowBlur = 8;
      pCtx.shadowColor = color;
      pCtx.fillStyle = color;
      pCtx.beginPath();
      pCtx.arc(10, 10, 3.4, 0, Math.PI * 2);
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
      fCtx.arc(12, 12, 4, 0, Math.PI * 2);
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
    this._frameInterval = 1000 / 30;
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
    var attackClass = inferencePayload.attack_class || 'SYN Flood';
    var color = attackClass.indexOf('SYN') >= 0 ? '#F59E0B' :
                attackClass.indexOf('ICMP') >= 0 ? '#E11D48' :
                attackClass.indexOf('UDP') >= 0 ? '#14B8A6' : '#94A3B8';

    var now = performance.now();
    var forwardPaths = this.paths.filter(function(p) { return !p.feedback && p.kind !== 'redirect'; });
    forwardPaths.forEach(function(path, index) {
      this.particles.push({
        from: path.from, to: path.to,
        spawnTime: now, delay: index * 50,
        speed: 1.32,
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
    var colors = ['#F59E0B', '#14B8A6', '#94A3B8'];
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
      if (this.particles.length > 60) this.particles.splice(0, this.particles.length - 60);
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
        ctx.strokeStyle = this.isLightMode ? 'rgba(0,0,0,0.10)' : 'rgba(255,255,255,0.25)';
        ctx.lineWidth = 1.4;
      }
      ctx.stroke();
      ctx.setLineDash([]);

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
    }.bind(this));

    if (this.particles.length > 60) this.particles.splice(0, this.particles.length - 60);
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
      var sprite = this._particleSprites[p.color];
      if (sprite) {
        ctx.drawImage(sprite, px - 10, py - 10);
      } else {
        ctx.beginPath();
        ctx.arc(px, py, 3.4, 0, Math.PI * 2);
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
        ctx.arc(px, py, 4, 0, Math.PI * 2);
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
    }

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
        '<div class="expert-stat"><span class="lbl">Packets / sec</span><span class="val" id="ep-pps" style="color:var(--text)">0</span><span class="note">pipeline input</span></div>' +
        '<div class="expert-stat"><span class="lbl">Size variance</span><span class="val" id="ep-entropy" style="color:var(--text)">0.00</span><span class="note">diversity variance</span></div>' +
        '<div class="expert-stat"><span class="lbl">TEA verdict</span><span class="val" id="ep-verdict" style="color:var(--green);font-size:15px">Normal</span><span class="note">TEA global verdict</span></div>' +
      '</div>' +
      '<div class="expert-proto-row">' +
        '<span class="expert-proto-title">Flood Prefilter, per protocol</span>' +
        '<div class="expert-proto-items">' +
          '<div class="expert-proto-item"><span class="pk">SYN</span><span class="pv" id="ep-syn">0</span></div>' +
          '<div class="expert-proto-item"><span class="pk">ICMP</span><span class="pv" id="ep-icmp">0</span></div>' +
          '<div class="expert-proto-item"><span class="pk">UDP</span><span class="pv" id="ep-udp">0</span></div>' +
        '</div>' +
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

  updateStats: function(pipeline, tea, ifData) {
    var ppsEl = document.getElementById('ep-pps');
    var entropyEl = document.getElementById('ep-entropy');
    var verdictEl = document.getElementById('ep-verdict');
    if (!ppsEl) return;

    var pps = (pipeline && pipeline.worker_queue_size) || 0;
    ppsEl.textContent = pps;

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

  // RF Traffic Composition Bar
  const dist = rfData.class_distribution || { 'SYN Flood': 0, 'ICMP Flood': 0, 'UDP Flood': 0, 'Uncertain': 0 };
  const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;

  const synPct = (dist['SYN Flood'] || 0) / total * 100;
  const icmpPct = (dist['ICMP Flood'] || 0) / total * 100;
  const udpPct = (dist['UDP Flood'] || 0) / total * 100;
  const uncertainPct = (dist['Uncertain'] || 0) / total * 100;
  const normalPct = (dist['Normal'] || 0) / total * 100;
  const attackTotal = synPct + icmpPct + udpPct + uncertainPct;

  // Frontend-only: when IF says normal, show green Normal regardless of RF's stale Uncertain
  const showNormalIdle = !isAnom;

  let rfHtml = `<div class="ml-section">
    <div class="ml-section-title"><span class="accent-dot rf-dot"></span>Random Forest (RF) Composition</div>
    <div class="rf-segmented-bar">
      ${showNormalIdle ? `
      <div class="rf-segment normal" style="width:100%">100%</div>
      ` : attackTotal > 0 ? `
      ${synPct > 0 ? `<div class="rf-segment syn"    style="width: ${synPct}%">${synPct > 10 ? synPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${icmpPct > 0 ? `<div class="rf-segment icmp"   style="width: ${icmpPct}%">${icmpPct > 10 ? icmpPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${udpPct > 0 ? `<div class="rf-segment udp"    style="width: ${udpPct}%">${udpPct > 10 ? udpPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${uncertainPct > 0 ? `<div class="rf-segment uncertain" style="width: ${uncertainPct}%">${uncertainPct > 10 ? uncertainPct.toFixed(0) + '%' : ''}</div>` : ''}
      ` : `
      <div class="rf-segment normal" style="width:100%">${normalPct > 0 ? 'Normal' : 'No data'}</div>
      `}
    </div>
    <div class="rf-legend">
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:var(--amber)"></span>SYN</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#f472b6"></span>ICMP</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#60b4ff"></span>UDP</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:var(--sub2,#6b7280)"></span>Uncertain</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#2f9e6e"></span>Normal</div>
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

      // Confidence chip
      const confidence = teaGlobal.confidence || 'LOW';
      const confidenceClass = confidence === 'HIGH' ? 'conf-high' : confidence === 'MODERATE' ? 'conf-moderate' : 'conf-low';

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
                <span class="tea-confidence-chip ${confidenceClass}">${confidence}</span>
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
                    <span>Threshold: ${attackSigma.toFixed(1)}σ</span>
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
                    <span>Threshold: ${attackSigma.toFixed(1)}σ</span>
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
      const confEl = existingCard.querySelector('.tea-confidence-chip');
      const progEl = existingCard.querySelector('.tea-learning-progress');
      if (statusEl) { statusEl.className = `tea-switch-status ${statusClass}`; statusEl.textContent = statusText; }
      if (confEl) { confEl.className = `tea-confidence-chip ${confidenceClass}`; confEl.textContent = confidence; }
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
    const currentCount = ipListEl.children.length;
    if (currentCount !== renderIPs.length || renderIPs.length === 0) {
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