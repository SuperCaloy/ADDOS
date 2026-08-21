// frontend/static/expert.js
// Expert Mode: live algorithmic internals visualization

let _expertPollTimer = null;
let _expertSSE = null;
let _expertActive = false;

function toggleExpertMode() {
  const btn = document.getElementById('expert-btn');
  const panels = document.getElementById('expert-panels');
  const body = document.body;

  if (!_expertActive) {
    _expertActive = true;
    btn.classList.add('active');
    btn.setAttribute('aria-pressed', 'true');
    btn.textContent = '☰ Expert ✓';
    panels.classList.remove('expert-hidden');
    document.getElementById('expert-pipeline-panel').classList.remove('expert-hidden');
    body.classList.add('expert-mode');
    startExpertMode();
    localStorage.setItem('addos-expert', '1');
    if (typeof showToast === 'function') showToast('Expert Mode enabled');
  } else {
    _expertActive = false;
    btn.classList.remove('active');
    btn.setAttribute('aria-pressed', 'false');
    btn.textContent = '☰ Expert';
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
}

function stopExpertMode() {
  if (_expertPollTimer) { clearInterval(_expertPollTimer); _expertPollTimer = null; }
  if (_expertSSE) { _expertSSE.close(); _expertSSE = null; }
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
    var cls = payload.inference.attack_class || 'unknown';
    var score = (payload.inference.if_score || 0).toFixed(4);
    var conf = (payload.inference.confidence || 0).toFixed(2);
    ExpertMetrics.appendLog(
      payload.inference.src_ip + ' -> ' + cls + ' (IF=' + score + ', conf=' + conf + ')',
      payload.inference.is_anomaly ? 'danger' : 'info'
    );
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
      desc: 'This is the practice network. It emulates OpenFlow-capable virtual switches and hosts, generating ordinary IP/TCP/UDP traffic between them, or a high-volume SYN/UDP/ICMP flood from designated attacker hosts. It exists so the whole pipeline can be tested against both everyday traffic and a real flood pattern, safely, without touching a live network.',
      input: '1 core switch (s0) plus 8 edge switches\n20 hosts (h1 to h20) plus sinkhole h21\nh1 to h5: legit TCP/UDP/ICMP traffic\nh6 to h19: 14 attackers, SYN/ICMP/UDP/mixed\nh20: server (10.0.0.20), whitelisted, never scored',
      output: 'Raw packets crossing\nOpenFlow switches toward h20'
    },
    ryu: {
      num: 2, color: '#14B8A6',
      title: 'Ryu SDN Controller',
      file: 'controller/ryu_controller.py',
      desc: 'The traffic officer for the network, and the final enforcement point. It sits above the switch and speaks OpenFlow, repeatedly asking for flow statistics (packet counts, byte counts, durations) for every active connection. It also receives the block command from the Decision Coordinator and installs the actual drop rule on the switch.',
      input: 'OpenFlow Packet-In events\nplus per-flow stat replies',
      output: 'Structured flow stats:\npacket_count, byte_count, duration, ports'
    },
    zmq_rx: {
      num: 3, color: '#14B8A6',
      title: 'ZeroMQ Transport',
      file: 'backend/transport/zmq_receiver.py',
      desc: 'A fast, non-blocking delivery pipe between the controller and the detection backend. Flow reports get queued and delivered asynchronously, keeping the network running even when the analysis side is briefly busy.',
      input: 'Serialized JSON flow\nreports from Ryu',
      output: 'Decoded flow dicts pushed\ninto the worker queue'
    },
    flood: {
      num: 4, color: '#F59E0B',
      title: 'Flood Prefilter',
      file: 'backend/pipeline/flood_prefilter.py',
      desc: 'A quick first check that runs before any AI model. It tracks per-IP, per-protocol packet timing (SYN, ICMP, UDP) against configured limits, and flags a source the moment it exceeds a rate limit or a short sub-second burst.',
      input: 'Per-packet protocol plus\nsource IP, as flows arrive',
      output: 'Flag: exceeded or not, per\nsource IP and protocol',
      formula: [
        { f: 'trip if count(proto, 1.0s) >= limit', note: 'SYN 100, ICMP 50, UDP 50 per 1s window' },
        { f: 'burst if count(proto, 0.1s) >= 0.4 * limit', note: 'catches fast opening spike before full window' }
      ]
    },
    entropy: {
      num: 5, color: '#F59E0B',
      title: 'Entropy Analyzer (TEA)',
      file: 'backend/pipeline/entropy_analyzer.py',
      desc: 'Learns what normal looks like for this network over time, building a rolling baseline of packet rate and traffic diversity per switch. A sharp entropy drop below the learned baseline signals repetitive, low-diversity attack traffic.',
      input: 'Flow stream plus per-switch\nrolling packet-rate baseline',
      output: 'Diversity score plus pass or hold\ndecision on which flows continue',
      formula: [
        { f: 'H = -sum(p_i * log2(p_i))', note: 'diversity score across source IPs and ports' },
        { f: 'mu_t = a*x_t + (1-a)*mu_{t-1}', note: 'learned baseline, adapts faster when stable' },
        { f: 'z = (x - mu) / sigma, flagged when z < -sigma_attack', note: 'baseline learns over 10-interval rolling window' }
      ]
    },
    if_node: {
      num: 6, color: '#E11D48',
      title: 'Isolation Forest',
      file: 'backend/models/if_pipeline.py',
      desc: 'An unsupervised anomaly detector trained on normal traffic only. It scores each flow by how easily it can be isolated from everything else seen: unusual traffic isolates fast and scores high, giving each connection a numeric anomaly score.',
      input: '16-feature vector per flow\n(rates, ratios, timing)',
      output: 'Anomaly score (0 to 1) plus\nabove/below threshold flag',
      formula: [
        { f: 's(x, n) = 2^(-E(h(x)) / c(n))', note: 'anomaly score from average isolation path length' },
        { f: 'if_score = -score_samples(x)', note: 'flagged anomalous when if_score >= 0.609' }
      ]
    },
    rf: {
      num: 7, color: '#14B8A6',
      title: 'Random Forest',
      file: 'backend/models/rf_pipeline.py',
      desc: 'A supervised classifier that runs only on flows the Isolation Forest has already flagged as anomalous. It predicts which attack type the traffic matches along with a confidence score.',
      input: '15-feature vector, only for\nflows the IF flagged anomalous',
      output: 'One of: ICMP Flood, SYN Flood,\nUDP Flood, plus confidence',
      formula: [
        { f: 'y_hat = mode{T_1(x), T_2(x), ..., T_k(x)}', note: 'majority vote across k decision trees' },
        { f: 'confidence = votes(y_hat) / k', note: 'acted on only when confidence >= 0.70' }
      ]
    },
    decision: {
      num: 8, color: '#F59E0B',
      title: 'Decision + Mitigation',
      file: 'backend/pipeline/decision_engine.py',
      desc: 'The final judge. It weighs the Isolation Forest score and the Random Forest classification together against configured thresholds. If confident enough this is a real attack, it sends a block command back to the Ryu Controller over ZeroMQ.',
      input: 'IF anomaly score plus\nRF class and confidence',
      output: 'OpenFlow drop-rule command,\nsent back to Ryu'
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
  VIRTUAL_W: 950,
  VIRTUAL_H: 560,
  reducedMotion: false,
  _animFrame: null,

  nodes: {
    mininet:  { x: 150, y: 200, label: 'Mininet' },
    ryu:      { x: 350, y: 100, label: 'Ryu Controller' },
    zmq_rx:   { x: 600, y: 100, label: 'ZMQ Transport' },
    flood:    { x: 800, y: 200, label: 'Flood Prefilter' },
    entropy:  { x: 800, y: 360, label: 'Entropy Analyzer' },
    if_node:  { x: 600, y: 460, label: 'Isolation Forest' },
    rf:       { x: 350, y: 460, label: 'Random Forest' },
    decision: { x: 150, y: 360, label: 'Decision + Block' }
  },

  paths: [
    { from: 'mininet', to: 'ryu' },
    { from: 'ryu', to: 'zmq_rx' },
    { from: 'zmq_rx', to: 'flood' },
    { from: 'flood', to: 'entropy' },
    { from: 'entropy', to: 'if_node' },
    { from: 'if_node', to: 'rf' },
    { from: 'rf', to: 'decision' },
    { from: 'decision', to: 'ryu', feedback: true, kind: 'enforce', curve: -190 },
    { from: 'if_node', to: 'entropy', feedback: true, kind: 'learn', curve: 70 }
  ],

  nodeGlow: {},

  init: function() {
    this.canvas = document.getElementById('expert-pipeline-canvas');
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.container = this.canvas.parentElement;

    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.isLightMode = document.body.classList.contains('light') ||
      window.matchMedia('(prefers-color-scheme: light)').matches;

    for (var key in this.nodes) {
      this.nodes[key].colorHex = ExpertStages.data[key].color;
      this.nodeGlow[key] = 0;
    }

    this.resize();
    window.addEventListener('resize', this.resize.bind(this));

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

    var forwardPaths = this.paths.filter(function(p) { return !p.feedback; });
    var path = forwardPaths[Math.floor(Math.random() * forwardPaths.length)];
    this.particles.push({
      from: path.from, to: path.to, progress: 0,
      speed: 0.014 + Math.random() * 0.008,
      color: color, isFeedback: false
    });
  },

  updateNodeGlow: function(pollData) {
    var flagged = (pollData.pipeline && pollData.pipeline.flood_prefilter_flagged) || 0;
    var ifAnomalies = (pollData.if && pollData.if.score_distribution) ? pollData.if.score_distribution.anomaly || 0 : 0;
    var smCount = pollData.state_machine ? Object.keys(pollData.state_machine).length : 0;

    this.nodeGlow.flood = Math.min(flagged / 10, 1);
    this.nodeGlow.if_node = Math.min(ifAnomalies / 5, 1);
    this.nodeGlow.decision = Math.min(smCount / 3, 1);
    this.nodeGlow.entropy = (pollData.tea && pollData.tea.global && pollData.tea.global.is_attack) ? 0.8 : 0;
    this.nodeGlow.rf = (pollData.rf && pollData.rf.recent_classifications && pollData.rf.recent_classifications.length > 0) ? 0.6 : 0;
  },

  drawScene: function() {
    var ctx = this.ctx;
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    this.paths.forEach(function(path) {
      var start = this._coords(this.nodes[path.from].x, this.nodes[path.from].y);
      var end = this._coords(this.nodes[path.to].x, this.nodes[path.to].y);
      ctx.beginPath();
      ctx.moveTo(start.x, start.y);
      if (path.feedback) {
        var cX = (start.x + end.x) / 2;
        var cY = (start.y + end.y) / 2 + path.curve;
        ctx.quadraticCurveTo(cX, cY, end.x, end.y);
        ctx.strokeStyle = path.kind === 'learn'
          ? (this.isLightMode ? 'rgba(13,148,136,0.5)' : 'rgba(20,184,166,0.4)')
          : (this.isLightMode ? 'rgba(180,83,9,0.5)' : 'rgba(245,158,11,0.4)');
        ctx.lineWidth = 2;
        ctx.setLineDash([5, 4]);
      } else {
        ctx.lineTo(end.x, end.y);
        ctx.strokeStyle = this.isLightMode ? 'rgba(0,0,0,0.10)' : 'rgba(255,255,255,0.25)';
        ctx.lineWidth = 1.4;
      }
      ctx.stroke();
      ctx.setLineDash([]);

      if (path.feedback) {
        var cX2 = (start.x + end.x) / 2;
        var cY2 = (start.y + end.y) / 2 + path.curve;
        var lx = 0.25 * start.x + 0.5 * cX2 + 0.25 * end.x;
        var ly = 0.25 * start.y + 0.5 * cY2 + 0.25 * end.y;
        ctx.font = '600 9px "Fira Code", monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = path.kind === 'learn'
          ? (this.isLightMode ? 'rgba(13,148,136,0.8)' : 'rgba(20,184,166,0.6)')
          : (this.isLightMode ? 'rgba(180,83,9,0.8)' : 'rgba(245,158,11,0.6)');
        ctx.fillText(path.kind === 'learn' ? 'learns baseline' : 'sends block', lx, ly);
      }
    }.bind(this));

    for (var i = this.particles.length - 1; i >= 0; i--) {
      var p = this.particles[i];
      p.progress += p.speed;
      if (p.progress >= 1) { this.particles.splice(i, 1); continue; }
      var s = this._coords(this.nodes[p.from].x, this.nodes[p.from].y);
      var e = this._coords(this.nodes[p.to].x, this.nodes[p.to].y);
      var px = s.x + (e.x - s.x) * p.progress;
      var py = s.y + (e.y - s.y) * p.progress;
      ctx.beginPath();
      ctx.arc(px, py, 3.4, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    var time = Date.now();
    var pulseAlpha = Math.sin(time / 300) * 0.3 + 0.7;

    for (var key in this.nodes) {
      var node = this.nodes[key];
      var c = this._coords(node.x, node.y);
      var isSel = ExpertState.selectedStage === key;
      var glow = this.nodeGlow[key] || 0;

      // Glow ring (dark mode only, when active)
      if (!this.isLightMode && glow > 0.05) {
        ctx.beginPath();
        ctx.arc(c.x, c.y, 30, 0, Math.PI * 2);
        ctx.shadowBlur = 20;
        ctx.shadowColor = node.colorHex;
        var glowHex = Math.round(glow * 60).toString(16);
        if (glowHex.length < 2) glowHex = '0' + glowHex;
        ctx.fillStyle = node.colorHex + glowHex;
        ctx.fill();
        ctx.shadowBlur = 0;
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
        '<div class="expert-stat"><span class="lbl">IP entropy</span><span class="val" id="ep-entropy" style="color:var(--text)">0.00</span><span class="note">traffic diversity</span></div>' +
        '<div class="expert-stat"><span class="lbl">Model verdict</span><span class="val" id="ep-verdict" style="color:var(--green);font-size:15px">Normal</span><span class="note">IF + RF combined</span></div>' +
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
      <div class="ml-verdict-wrap"></div>
    `;
    el.dataset.init = '1';
  }

  const ifWrap = el.querySelector('.ml-if-wrap');
  const rfWrap = el.querySelector('.ml-rf-wrap');
  const teaWrap = el.querySelector('.ml-tea-wrap');
  const verdictWrap = el.querySelector('.ml-verdict-wrap');

  // IF Anomaly Thermometer
  const thr = ifData.threshold || 0.6092;

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
  const dist = rfData.class_distribution || { 'SYN Flood': 0, 'ICMP Flood': 0, 'UDP Flood': 0, 'Normal': 0 };
  const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;

  const synPct = (dist['SYN Flood'] || 0) / total * 100;
  const icmpPct = (dist['ICMP Flood'] || 0) / total * 100;
  const udpPct = (dist['UDP Flood'] || 0) / total * 100;
  const normalPct = (dist['Normal'] || 0) / total * 100;

  let rfHtml = `<div class="ml-section">
    <div class="ml-section-title"><span class="accent-dot rf-dot"></span>Random Forest (RF) Composition</div>
    <div class="rf-segmented-bar">
      ${normalPct > 0 ? `<div class="rf-segment normal" style="width: ${normalPct}%">${normalPct > 10 ? normalPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${synPct > 0 ? `<div class="rf-segment syn"    style="width: ${synPct}%">${synPct > 10 ? synPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${icmpPct > 0 ? `<div class="rf-segment icmp"   style="width: ${icmpPct}%">${icmpPct > 10 ? icmpPct.toFixed(0) + '%' : ''}</div>` : ''}
      ${udpPct > 0 ? `<div class="rf-segment udp"    style="width: ${udpPct}%">${udpPct > 10 ? udpPct.toFixed(0) + '%' : ''}</div>` : ''}
    </div>
    <div class="rf-legend">
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:var(--green)"></span>Normal</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:var(--amber)"></span>SYN</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#f472b6"></span>ICMP</div>
      <div class="rf-legend-item"><span class="rf-legend-dot" style="background:#60b4ff"></span>UDP</div>
    </div>
  </div>`;
  if (rfWrap) rfWrap.innerHTML = rfHtml;

  // TEA Global Feature Entropy
  const teaGlobal = teaData.global || null;
  if (teaGlobal && Object.keys(teaGlobal).length > 0) {
    const totalIps = teaGlobal.unique_ips || 0;

    const isAttack = teaGlobal.is_attack;
    const isFlash = teaGlobal.is_flash_crowd;
    const isLearned = teaGlobal.learned;

    const statusClass = isAttack ? 'attack' : isFlash ? 'flash-crowd' : !isLearned ? 'learning' : 'learned';
    const statusText = isAttack ? 'ATTACK' : isFlash ? 'FLASH CROWD' : !isLearned ? 'LEARNING' : 'NORMAL';

    const maxSizeZ = teaGlobal.size_z || 0;
    const maxIntZ = teaGlobal.intensity_z || 0;

    // Clamp fill to [0, 100] using a -3..+3 z-score window mapped to 0..100%
    const sizeZPct = Math.min(Math.max((maxSizeZ + 3) / 6 * 100, 0), 100);
    const intZPct = Math.min(Math.max((maxIntZ + 3) / 6 * 100, 0), 100);

    const existingCard = teaWrap.querySelector('.controller-tea-card');
    if (!existingCard) {
      teaWrap.innerHTML = `
        <div class="ml-section">
          <div class="ml-section-title"><span class="accent-dot tea-dot"></span>Temporal Entropy Analysis</div>
          <div class="tea-switch-card controller-tea-card">
            <div class="tea-switch-header">
              <span class="tea-switch-title">Aggregation <span class="tea-unique-ips"></span></span>
              <span class="tea-switch-status ${statusClass}">${statusText}</span>
            </div>
            <div class="zscore-container">
              <div class="zscore-row" id="tea-size">
                <div class="zscore-label">Avg Div Entropy <span class="zscore-val">${teaGlobal.size_var.toFixed(4)}</span></div>
                <div class="zscore-track">
                  <div class="zscore-midline"></div>
                  <div class="zscore-fill ${maxSizeZ >= 2 ? 'anomaly' : ''}" style="width: ${sizeZPct}%"></div>
                </div>
                <div class="zscore-num">${maxSizeZ >= 0 ? '+' : ''}${maxSizeZ.toFixed(1)}z<br><span style="font-size:9px;font-weight:400;color:var(--sub2)">(Max)</span></div>
              </div>
              <div class="zscore-row" id="tea-int">
                <div class="zscore-label">Avg Pkt Intensity <span class="zscore-val">${teaGlobal.intensity_var.toFixed(4)}</span></div>
                <div class="zscore-track">
                  <div class="zscore-midline"></div>
                  <div class="zscore-fill ${maxIntZ >= 2 ? 'anomaly' : ''}" style="width: ${intZPct}%"></div>
                </div>
                <div class="zscore-num">${maxIntZ >= 0 ? '+' : ''}${maxIntZ.toFixed(1)}z<br><span style="font-size:9px;font-weight:400;color:var(--sub2)">(Max)</span></div>
              </div>
            </div>
          </div>
        </div>`;
    } else {
      const titleEl = existingCard.querySelector('.tea-unique-ips');
      const statusEl = existingCard.querySelector('.tea-switch-status');
      if (titleEl) titleEl.textContent = '';
      if (statusEl) { statusEl.className = `tea-switch-status ${statusClass}`; statusEl.textContent = statusText; }

      const sizeRow = document.getElementById('tea-size');
      if (sizeRow) {
        sizeRow.querySelector('.zscore-val').textContent = teaGlobal.size_var.toFixed(4);
        const sf = sizeRow.querySelector('.zscore-fill');
        sf.className = `zscore-fill ${maxSizeZ >= 2 ? 'anomaly' : ''}`;
        sf.style.width = `${sizeZPct}%`;
        sizeRow.querySelector('.zscore-num').innerHTML = `${maxSizeZ >= 0 ? '+' : ''}${maxSizeZ.toFixed(1)}z<br><span style="font-size:9px;font-weight:400;color:var(--sub2)">(Max)</span>`;
      }
      const intRow = document.getElementById('tea-int');
      if (intRow) {
        intRow.querySelector('.zscore-val').textContent = teaGlobal.intensity_var.toFixed(4);
        const ifill = intRow.querySelector('.zscore-fill');
        ifill.className = `zscore-fill ${maxIntZ >= 2 ? 'anomaly' : ''}`;
        ifill.style.width = `${intZPct}%`;
        intRow.querySelector('.zscore-num').innerHTML = `${maxIntZ >= 0 ? '+' : ''}${maxIntZ.toFixed(1)}z<br><span style="font-size:9px;font-weight:400;color:var(--sub2)">(Max)</span>`;
      }
    }
  } else {
    if (teaWrap) teaWrap.innerHTML = '';
  }

  // TEA per-IP verdicts
  const ipVerdicts = teaData.per_ip_verdicts || {};
  let verdictHtml = '';
  if (Object.keys(ipVerdicts).length) {
    verdictHtml += '<div class="ml-section"><div class="ml-section-title">TEA Per-IP Verdicts</div><div class="tea-ip-list">';
    Object.entries(ipVerdicts).forEach(([ip, verdict]) => {
      verdictHtml += `<span class="tea-ip-pill ${verdict}">${ip} \u2192 ${verdict.toUpperCase()}</span>`;
    });
    verdictHtml += '</div></div>';
  }
  if (verdictWrap) verdictWrap.innerHTML = verdictHtml;
}


function updateTEASwitch(tea) {
  // Disabling individual switch updates via SSE because we are now rendering a global aggregation based on the REST poll.
  // The SSE payload only contains a single switch, so we can't accurately compute the global mean here without caching all switch states.
  // We rely on fetchExpert() (poll) for the controller-wide UI instead.
}

function updateIFBar(inf) {
  // Disabling individual IF updates via SSE because we are now rendering an aggregated thermometer based on the REST poll.
}

// ── Panel 3: Mitigation State Machine ────────────────────────────────────
function renderMitigationPanel(smStates, deception, rg) {
  const el = document.getElementById('expert-mitigation-content');
  if (!el) return;

  // Count IPs per phase
  const phaseCounts = { 1: 0, 2: 0, 3: 0, 4: 0 };
  Object.values(smStates).forEach(s => { if (s.phase) phaseCounts[s.phase] = (phaseCounts[s.phase] || 0) + 1; });

  const hasActiveFlow = Object.values(smStates).length > 0;

  let html = `<div class="mitigation-phases ${hasActiveFlow ? 'active-flow' : ''}">`;
  html += `
    <div class="phase-box quarantine">
      <div class="phase-label">Quarantine</div>
      <div class="phase-count">${phaseCounts[1]}</div>
      <div class="phase-action">Rate Limited</div>
    </div>
    <div class="phase-box ban">
      <div class="phase-label">Time Ban</div>
      <div class="phase-count">${phaseCounts[2]}</div>
      <div class="phase-action">Blocked</div>
    </div>
    <div class="phase-box blackhole">
      <div class="phase-label">Blackhole</div>
      <div class="phase-count">${phaseCounts[3]}</div>
      <div class="phase-action">24h TTL</div>
    </div>
    <div class="phase-box probation">
      <div class="phase-label">Probation</div>
      <div class="phase-count">${phaseCounts[4]}</div>
      <div class="phase-action">Watched</div>
    </div>
  </div>`;

  // Active IPs detail
  const activeIPs = Object.entries(smStates);
  if (activeIPs.length) {
    html += '<div class="ml-section"><div class="ml-section-title">Active States</div><div class="terminal-feed">';
    activeIPs.forEach(([ip, s]) => {
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });
      html += `
        <div class="terminal-line">
          <span class="t-time">[${now}]</span>
          <span class="t-ip">${ip}</span>
          <span class="t-crit">PHASE_${s.phase}</span>
          <span class="t-stat">IF=${s.if_score.toFixed(4)}</span>
          <span class="t-stat">PPS=${s.recent_pps.toFixed(1)}</span>
          <span class="t-alert">ACT=${s.action.toUpperCase()}</span>
          ${s.ttl_sec != null ? `<span class="t-stat">TTL=${s.ttl_sec}s</span>` : ''}
        </div>`;
    });
    html += '</div></div>';
  }

  // Deception sinkholes
  if (deception.active_sinkholes?.length) {
    html += '<div class="ml-section"><div class="ml-section-title"><span class="accent-dot tea-dot"></span>Active Sinkholes</div><div class="terminal-feed">';
    deception.active_sinkholes.forEach(sh => {
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });
      const pct = Math.min((sh.obs_sec / sh.escalate_at_sec) * 100, 100);
      html += `
        <div class="terminal-line">
          <span class="t-time">[${now}]</span>
          <span class="t-ip">${sh.src_ip}</span>
          <span class="t-alert">HONEYPOT</span>
          <span class="t-stat">VECTOR=${sh.attack_vector}</span>
          <div class="sinkhole-progress"><div class="sinkhole-progress-fill" style="width:${pct}%"></div></div>
        </div>`;
    });
    html += '</div></div>';
  }

  // Resource guard tier
  const tier = rg?.tier || 'OK';
  const tierClass = tier.toLowerCase();
  html += `
    <div class="ml-section">
      <div class="ml-section-title">Resource Guard</div>
      <div class="rg-tier ${tierClass}">${tier}</div>
    </div>
  `;

  el.innerHTML = html;
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