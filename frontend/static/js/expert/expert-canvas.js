/**
 * Interactive HTML5 Canvas visualization engine for Expert Mode.
 * Renders topology nodes, bezier data paths, particle animations, and live activity glows.
 */

/**
 * Pre-renders a radial glow sprite onto an off-screen canvas to optimize rendering performance.
 * Avoids expensive per-frame shadowBlur calculations during the main animation loop.
 */
function _createGlowSprite(size, radius, color, shadowBlur, fillStyle) {
  var c = document.createElement('canvas');
  c.width = size;
  c.height = size;
  var ctx = c.getContext('2d');
  ctx.shadowBlur = shadowBlur;
  ctx.shadowColor = color;
  ctx.fillStyle = fillStyle || color;
  ctx.beginPath();
  ctx.arc(size / 2, size / 2, radius, 0, Math.PI * 2);
  ctx.fill();
  return c;
}

// Interactive pipeline topology manager and animation state coordinator.
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
  _resizeHandler: null,
  _clickHandler: null,
  _observer: null,
  latchState: { locked: false, streak: 0 },
  _hasSinkhole: false,

  nodes: {
    mininet:        { x: 150, y: 200, label: 'Mininet' },
    ryu:            { x: 350, y: 100, label: 'Ryu Controller' },
    zmq_rx:         { x: 600, y: 100, label: 'ZMQ Transport' },
    flood:          { x: 800, y: 200, label: 'Flood Prefilter' },
    entropy:        { x: 800, y: 360, label: 'Entropy Analyzer' },
    if_node:        { x: 600, y: 460, label: 'Isolation Forest' },
    rf:             { x: 350, y: 460, label: 'Random Forest' },
    decision:       { x: 150, y: 360, label: 'Decision + Mitigation' },
    deception:      { x: 50,  y: 480, label: 'Deception / Sinkhole' },
    resource_guard: { x: 50,  y: 120, label: 'Resource Guard' }
  },

  paths: [
    { from: 'mininet',  to: 'ryu',            label: 'traffic data' },
    { from: 'ryu',      to: 'zmq_rx',         label: 'flow reports' },
    { from: 'zmq_rx',   to: 'flood',          label: 'flow reports' },
    { from: 'flood',    to: 'entropy',        label: 'flagged IPs' },
    { from: 'entropy',  to: 'if_node',        label: 'traffic patterns' },
    { from: 'if_node',  to: 'rf',             label: 'suspicious flows' },
    { from: 'rf',       to: 'decision',       label: 'attack type' },
    { from: 'decision', to: 'ryu',            kind: 'enforce',  feedback: true, curve: -60 },
    { from: 'decision', to: 'deception',      kind: 'redirect', feedback: true, curve: -80 },
    { from: 'decision', to: 'resource_guard', label: 'system stats' }
  ],

  nodeGlow: {},

  /**
   * Initializes canvas contexts, pre-renders glow sprites, and sets up observers and listeners.
   * Starts the continuous rendering cycle and binds click events for stage selection.
   */
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
    if (!this._resizeHandler) {
      this._resizeHandler = this.resize.bind(this);
      window.addEventListener('resize', this._resizeHandler);
    }

    // Pre-render glow sprites using unified helper
    this._nodeGlows = {};
    for (var nKey in this.nodes) {
      var n = this.nodes[nKey];
      this._nodeGlows[nKey] = _createGlowSprite(80, 30, n.colorHex, 20, n.colorHex + '30');
    }

    this._particleSprites = {};
    var particleColors = ['#F59E0B', '#E11D48', '#14B8A6', '#10B981', '#8B5CF6'];
    particleColors.forEach(function(color) {
      this._particleSprites[color] = _createGlowSprite(20, 5, color, 10);
    }.bind(this));

    this._feedbackSprites = {};
    var feedbackColors = ['#E11D48', '#10B981', '#F59E0B', '#8B5CF6'];
    feedbackColors.forEach(function(color) {
      this._feedbackSprites[color] = _createGlowSprite(24, 5, color, 12);
    }.bind(this));

    if (!this._clickHandler) {
      this._clickHandler = function(e) {
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
      }.bind(this);
      this.canvas.addEventListener('click', this._clickHandler);
    }

    this._lastFrameTime = 0;
    this._frameInterval = 1000 / 20;
    this._isOffscreen = false;

    if (!this._observer) {
      this._observer = new IntersectionObserver(function(entries) {
        this._isOffscreen = entries[0].intersectionRatio === 0;
      }.bind(this), { threshold: 0 });
      this._observer.observe(this.canvas);
    }

    this._animFrame = requestAnimationFrame(this.drawScene.bind(this));
  },

  /**
   * Resizes the canvas buffer to match the parent container dimensions.
   * Guarantees a minimum height while maintaining responsive scaling ratios.
   */
  resize: function() {
    if (!this.container || !this.canvas) return;
    this.canvas.width = this.container.clientWidth;
    this.canvas.height = Math.max(380, this.container.clientHeight);
  },

  /**
   * Maps virtual design coordinate space to actual rendered canvas pixel coordinates.
   * Ensures topology layout scales proportionally across varying display resolutions.
   */
  _coords: function(nx, ny) {
    return {
      x: nx * (this.canvas.width / this.VIRTUAL_W),
      y: ny * (this.canvas.height / this.VIRTUAL_H)
    };
  },

  /**
   * Spawns forward data flow particles reflecting real-time inference telemetry.
   * Staggers animation delays across pipeline stages to visualize progressive analysis.
   */
  spawnParticleFromEvent: function(inferencePayload) {
    if (this.reducedMotion) return;
    var isAnomaly = inferencePayload.is_anomaly;

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

  /**
   * Reserved feedback particle spawn handler for future inference hooks.
   * Normal telemetry avoids feedback particles, which are reserved for mitigation actions.
   */
  spawnFeedbackParticle: function() {
    // Normal inference does not emit decisions to Ryu.
    // Decisions are emitted strictly on mitigation actions via spawnEnforceParticle.
  },

  /**
   * Spawns animated feedback particles representing mitigation enforcement commands.
   * Directs particles from the Decision Engine to the Ryu controller along a curved path.
   */
  spawnEnforceParticle: function(action) {
    if (this.reducedMotion) return;
    this.lastEnforceAction = action || 'block';
    var enforcePath = this.paths.find(function(p) { return p.kind === 'enforce'; });
    if (!enforcePath) return;
    var color = action === 'block' ? '#E11D48' : action === 'clear' ? '#10B981' : '#F59E0B';
    this.feedbackParticles.push({
      from: enforcePath.from, to: enforcePath.to,
      spawnTime: performance.now(), delay: 0,
      speed: 1.08 + Math.random() * 0.48,
      color: color, isFeedback: true
    });
  },

  /**
   * Spawns animated feedback particles representing traffic redirection to the deception sinkhole.
   * Displays distinct purple particles traversing from the Decision Engine to the Deception node.
   */
  spawnRedirectParticle: function() {
    if (this.reducedMotion) return;
    var redirectPath = this.paths.find(function(p) { return p.kind === 'redirect'; });
    if (!redirectPath) return;
    this.feedbackParticles.push({
      from: redirectPath.from, to: redirectPath.to,
      spawnTime: performance.now(), delay: 0,
      speed: 0.96 + Math.random() * 0.48,
      color: '#8B5CF6', isFeedback: true
    });
  },

  /**
   * Spawns randomized ambient particles across forward pipeline stages to simulate ongoing baseline traffic.
   * Caps maximum active particles to prevent visual clutter and maintain high rendering frame rates.
   */
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

  /**
   * Calculates node activity glow intensities based on current system polling telemetry.
   * Adjusts visual highlight brightness to reflect active queue sizes, anomalies, and resource tiers.
   */
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

  /**
   * Draws connecting lines, bezier feedback curves, arrows, and path labels between stages.
   * Applies dashed formatting and distinct stroke colors according to path classifications.
   */
  _drawPaths: function(ctx, scaleY) {
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
        ctx.lineWidth = 2;
        ctx.setLineDash([5, 4]);
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
  },

  /**
   * Renders active forward and feedback particles along their paths with motion trail effects.
   * Updates particle completion progress and removes expired particles from the tracking buffer.
   */
  _drawParticles: function(ctx, currentTime, scaleY) {
    if (this.particles.length > 40) this.particles.splice(0, this.particles.length - 40);
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
      for (var t = 3; t >= 1; t--) {
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
    for (var j = this.feedbackParticles.length - 1; j >= 0; j--) {
      var fp = this.feedbackParticles[j];
      var fAge = currentTime - fp.spawnTime - fp.delay;
      if (fAge < 0) continue;
      fp.progress = (fAge / 1000) * fp.speed;
      if (fp.progress >= 1) { this.feedbackParticles.splice(j, 1); continue; }
      var fs = this._coords(this.nodes[fp.from].x, this.nodes[fp.from].y);
      var fe = this._coords(this.nodes[fp.to].x, this.nodes[fp.to].y);
      var fPath = this.paths.find(function(p) { return p.feedback && p.from === fp.from && p.to === fp.to; });
      var curve = (fPath ? fPath.curve : -60) * scaleY;
      var cX = (fs.x + fe.x) / 2;
      var cY = (fs.y + fe.y) / 2 + curve;
      var fpx = fs.x + (cX - fs.x) * fp.progress * 2;
      var fpy = fs.y + (cY - fs.y) * fp.progress * 2;
      if (fp.progress > 0.5) {
        fpx = cX + (fe.x - cX) * (fp.progress - 0.5) * 2;
        fpy = cY + (fe.y - cY) * (fp.progress - 0.5) * 2;
      }
      var fSprite = this._feedbackSprites[fp.color];
      if (fSprite) {
        ctx.drawImage(fSprite, fpx - 12, fpy - 12);
      } else {
        ctx.beginPath();
        ctx.arc(fpx, fpy, 5, 0, Math.PI * 2);
        ctx.fillStyle = fp.color;
        ctx.fill();
      }
    }
  },

  /**
   * Draws node circles, sequence numbers, labels, selection rings, and status indicators.
   * Adjusts stroke colors and shadow effects dynamically according to theme and selection state.
   */
  _drawNodes: function(ctx, pulseAlpha) {
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

      if (isSel) {
        ctx.beginPath();
        ctx.arc(c.x, c.y, 32, 0, Math.PI * 2);
        ctx.strokeStyle = node.colorHex;
        ctx.globalAlpha = pulseAlpha;
        ctx.lineWidth = 3;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      ctx.beginPath();
      ctx.arc(c.x, c.y, 24, 0, Math.PI * 2);

      if (this.isLightMode) {
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
        ctx.beginPath();
        ctx.arc(c.x, c.y, 22, 0, Math.PI * 2);
        ctx.strokeStyle = node.colorHex + '40';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      } else {
        ctx.fillStyle = '#1e293b';
        ctx.fill();
        ctx.strokeStyle = node.colorHex;
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.font = '700 14px "Fira Code", monospace';
      ctx.fillStyle = this.isLightMode ? '#1e293b' : '#F8FAFC';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(ExpertStages.data[key].num, c.x, c.y);

      ctx.font = '600 12px "Fira Code", monospace';
      ctx.fillStyle = this.isLightMode ? '#334155' : (isSel ? '#F8FAFC' : 'rgba(248,250,252,0.7)');
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(node.label, c.x, c.y + 42);

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
  },

  /**
   * Renders the visual legend panel indicating traffic state color definitions.
   * Positions a translucent pill box containing color badges and descriptive labels.
   */
  _drawLegend: function(ctx) {
    var legendX = this.canvas.width - 196;
    var legendY = 12;
    var legendBg = this.isLightMode ? 'rgba(255,255,255,0.9)' : 'rgba(30,41,59,0.9)';
    var legendBorder = this.isLightMode ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)';
    var legendText = this.isLightMode ? '#334155' : 'rgba(248,250,252,0.7)';

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

    var items = [
      { color: '#10B981', label: 'Normal traffic', y: 16 },
      { color: '#14B8A6', label: 'Data processing', y: 32 },
      { color: '#F59E0B', label: 'Flagged / suspicious', y: 48 },
      { color: '#E11D48', label: 'Attack detected', y: 64 },
    ];

    items.forEach(function(item) {
      ctx.fillStyle = item.color;
      ctx.beginPath();
      ctx.arc(legendX + 14, legendY + item.y, 5, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = legendText;
      ctx.fillText(item.label, legendX + 26, legendY + item.y);
    });
  },

  /**
   * Coordinates canvas scene rendering on each animation frame.
   * Throttles execution rate, handles offscreen pausing, and invokes individual layer renderers.
   */
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

    this._drawPaths(ctx, scaleY);
    this._drawParticles(ctx, performance.now(), scaleY);
    var pulseAlpha = Math.sin(Date.now() / 300) * 0.3 + 0.7;
    this._drawNodes(ctx, pulseAlpha);
    this._drawLegend(ctx);

    this._animFrame = requestAnimationFrame(this.drawScene.bind(this));
  },

  /**
   * Halts all canvas animation loops and unbinds registered DOM event listeners.
   * Clears internal particle arrays and releases observer resources.
   */
  stop: function() {
    if (this._animFrame) {
      cancelAnimationFrame(this._animFrame);
      this._animFrame = null;
    }
    if (this._resizeHandler) {
      window.removeEventListener('resize', this._resizeHandler);
      this._resizeHandler = null;
    }
    if (this._clickHandler && this.canvas) {
      this.canvas.removeEventListener('click', this._clickHandler);
      this._clickHandler = null;
    }
    if (this._observer) {
      this._observer.disconnect();
      this._observer = null;
    }
    this.particles = [];
    this.feedbackParticles = [];
  }
};

window.ExpertPipeline = ExpertPipeline;
