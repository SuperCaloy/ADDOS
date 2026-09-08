// frontend/static/expert.js
// Expert Mode: live algorithmic internals coordinator and metrics readout

let _expertPollTimer = null;
let _ambientTimer = null;

function toggleExpertMode() {
  const btn = document.getElementById('expert-btn');
  const panels = document.getElementById('expert-panels');
  const pipelinePanel = document.getElementById('expert-pipeline-panel');
  const body = document.body;
  const isCurrentlyActive = window.Store ? window.Store.isExpertActive() : (window.EXPERT_MODE || false);

  if (!isCurrentlyActive) {
    if (window.Store) window.Store.setExpertActive(true);
    window.EXPERT_MODE = true;
    if (btn) {
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
      btn.textContent = 'Expert Mode \u2713';
    }
    if (panels) panels.classList.remove('expert-hidden');
    if (pipelinePanel) pipelinePanel.classList.remove('expert-hidden');
    body.classList.add('expert-mode');
    startExpertMode();
    if (typeof showToast === 'function') showToast('Expert Mode enabled');
  } else {
    if (window.Store) window.Store.setExpertActive(false);
    window.EXPERT_MODE = false;
    if (btn) {
      btn.classList.remove('active');
      btn.setAttribute('aria-pressed', 'false');
      btn.textContent = 'Expert Mode';
    }
    if (panels) panels.classList.add('expert-hidden');
    if (pipelinePanel) pipelinePanel.classList.add('expert-hidden');
    body.classList.remove('expert-mode');
    stopExpertMode();
    if (typeof showToast === 'function') showToast('Expert Mode disabled');
  }
}

window.toggleExpertMode = toggleExpertMode;

/* Restore saved expert mode state on load: mirrors the theme toggle pattern */
window.addEventListener('DOMContentLoaded', () => {
  const shouldActivate = window.Store ? window.Store.isExpertActive() : (localStorage.getItem('addos-expert') === '1');
  if (shouldActivate) toggleExpertMode();
});

function updateStreamingIndicator(status) {
  var indicator = document.querySelector('.expert-pipeline-live');
  if (!indicator) return;
  if (status === 'connected') {
    indicator.innerHTML = '<span class="expert-pipeline-live-dot"></span>streaming';
    indicator.style.color = '';
    var dot = indicator.querySelector('.expert-pipeline-live-dot');
    if (dot) { dot.style.animation = ''; dot.style.background = ''; }
  } else {
    indicator.innerHTML = '<span class="expert-pipeline-live-dot" style="animation:none;background:var(--sub2)"></span>polling';
    indicator.style.color = 'var(--sub2)';
  }
}

function startExpertMode() {
  fetchExpert();
  _expertPollTimer = setInterval(fetchExpert, window.POLL_MS || 2000);

  if (window.EventBus) {
    window.EventBus.on('expert', handleExpertEvent);
    window.EventBus.on('statuschange', updateStreamingIndicator);
    window.EventBus.connect();
    updateStreamingIndicator(window.EventBus.getStatus());
  }

  if (window.ExpertPipeline) ExpertPipeline.init();
  if (window.ExpertStages) ExpertStages.init();
  ExpertMetrics.init();

  if (_ambientTimer) clearInterval(_ambientTimer);
  if (window.ExpertPipeline) {
    _ambientTimer = setInterval(ExpertPipeline.spawnAmbientParticle, 2000);
  }
}

function stopExpertMode() {
  if (_expertPollTimer) { clearInterval(_expertPollTimer); _expertPollTimer = null; }
  if (window.EventBus) {
    window.EventBus.off('expert', handleExpertEvent);
    window.EventBus.off('statuschange', updateStreamingIndicator);
  }
  if (_ambientTimer) { clearInterval(_ambientTimer); _ambientTimer = null; }
  if (window.ExpertPipeline) ExpertPipeline.stop();
}

async function fetchExpert() {
  try {
    var apiUrl = window.API_URL || '';
    var r = await fetch(apiUrl + '/api/expert/live');
    if (!r.ok) return;
    var data = await r.json();
    window._lastExpertData = data;

    if (typeof renderMLPanel === 'function') {
      renderMLPanel(data.if, data.rf, data.tea);
    }
    if (typeof renderMitigationPanel === 'function') {
      renderMitigationPanel(data.state_machine, data.deception, data.resource_guard);
    }

    ExpertMetrics.updateStats(data.pipeline, data.tea, data.if, data.state_machine);
    if (window.ExpertPipeline) ExpertPipeline.updateNodeGlow(data);

    if (window.ExpertState) {
      if (data.if && data.if.recent_scores && data.if.recent_scores.length > 0) {
        var latest = data.if.recent_scores[0];
        var lastIf = ExpertState.ifHistory.length > 0 ? ExpertState.ifHistory[ExpertState.ifHistory.length - 1] : -1;
        if (latest.score !== lastIf) {
          ExpertState.ifHistory.push(latest.score);
          if (ExpertState.ifHistory.length > ExpertState.maxHistory) {
            ExpertState.ifHistory = ExpertState.ifHistory.slice(-ExpertState.maxHistory);
          }
        }
      }
      if (data.rf && data.rf.recent_classifications && data.rf.recent_classifications.length > 0) {
        var latestRf = data.rf.recent_classifications[0];
        var lastRf = ExpertState.rfHistory.length > 0 ? ExpertState.rfHistory[ExpertState.rfHistory.length - 1] : -1;
        if (latestRf.is_anomaly && latestRf.conf > 0 && latestRf.conf !== lastRf) {
          ExpertState.rfHistory.push(latestRf.conf);
          if (ExpertState.rfHistory.length > ExpertState.maxHistory) {
            ExpertState.rfHistory = ExpertState.rfHistory.slice(-ExpertState.maxHistory);
          }
        }
      }
      ExpertMetrics.updateTrend(ExpertState.ifHistory, ExpertState.rfHistory);
    }
  } catch (e) {
    console.warn('Expert fetch failed:', e);
  }
}

function handleExpertEvent(payload) {
  if (!payload) return;
  if (payload.tea_update) {
    if (typeof updateTEASwitch === 'function') updateTEASwitch(payload.tea_update);
    if (payload.tea_update.is_attack) {
      ExpertMetrics.appendLog('TEA: attack detected, diversity dropping', 'warn');
    }
  }
  if (payload.inference) {
    if (typeof updateIFBar === 'function') updateIFBar(payload.inference);
    if (window.ExpertPipeline) {
      ExpertPipeline.spawnParticleFromEvent(payload.inference);
    }
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
      if (window.ExpertPipeline) ExpertPipeline.spawnEnforceParticle(action);
      ExpertMetrics.appendLog('Enforcement: ' + action + ' command sent to Ryu', 'warn');
    }
    if (action === 'redirect') {
      if (window.ExpertPipeline) ExpertPipeline.spawnRedirectParticle();
      ExpertMetrics.appendLog('Redirect: traffic sent to sinkhole', 'warn');
    }
  }
}

/* -- Expert Pipeline: Metrics and Terminal -------------------------------- */

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
    if (entropyEl) entropyEl.textContent = entropy;

    if (verdictEl) {
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
    }

    // Prefilter breakdown: session cumulative data
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

    if (window.ExpertState) {
      ExpertState.logEntries.push(row);
      while (term.children.length > ExpertState.maxLog) {
        term.removeChild(term.firstChild);
        ExpertState.logEntries.shift();
      }
    }
  }
};

function exportExpertSnapshot() {
  var apiUrl = window.API_URL || '';
  fetch(apiUrl + '/api/expert/live')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'addos-expert-snapshot-' + Date.now() + '.json';
      a.click();
      URL.revokeObjectURL(url);
      if (typeof showToast === 'function') showToast('Expert snapshot downloaded');
    })
    .catch(function() { if (typeof showToast === 'function') showToast('Export failed', true); });
}

window.exportExpertSnapshot = exportExpertSnapshot;
window.ExpertMetrics = ExpertMetrics;
window.fetchExpert = fetchExpert;