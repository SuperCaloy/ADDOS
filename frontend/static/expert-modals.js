/* expert-modals.js: Algorithm Detail Popups for Expert Mode */

var ExpertModals = {
  _pollTimer: null,

  open: function(stageKey) {
    var overlay = document.getElementById('expert-modal-overlay');
    var body = document.getElementById('expert-modal-body');
    var head = document.querySelector('.expert-modal-head');
    if (!overlay || !body) return;
    var s = (window.ExpertStages && window.ExpertStages.data) ? window.ExpertStages.data[stageKey] : null;
    if (!s) return;

    var badge = head ? head.querySelector('.expert-modal-badge') : null;
    var title = head ? head.querySelector('.expert-modal-title') : null;
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
      var modalOverlay = document.getElementById('expert-modal-overlay');
      if (!modalOverlay || !modalOverlay.classList.contains('open')) {
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
    if (!el) return;
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

    // Per-protocol breakdown: session-cumulative counts (persist across attack lifecycle)
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

    // Flagged IP list: use current snapshot (live state)
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
    var confidence = g.confidence || 'LOW';
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
      '<div class="expert-modal-section"><div class="expert-modal-section-title">What it does</div><div class="expert-modal-desc">Measures how varied and diverse the traffic is. Normal traffic has many different source IPs, destination ports, and packet sizes. A flood is the opposite: repetitive, uniform, and predictable. When diversity drops below normal, it raises an alarm. During an attack, it freezes its memory of what normal looks like.</div></div>' +
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
      '<div class="expert-modal-section"><div class="expert-modal-section-title">How it decides</div><div class="expert-modal-logic">Compares current traffic diversity to what it learned as normal. If the z-score drops below a negative threshold, traffic is less diverse than normal (a flood signal). The latch freezes memory during attacks so the flood does not corrupt the baseline. It unlocks only when both the anomaly detector and entropy analyzer agree traffic has returned to normal.</div></div>';
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

window.ExpertModals = ExpertModals;
