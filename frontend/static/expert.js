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
  // Initial fetch
  fetchExpert();

  // Polling at same interval as quarantine/stats
  _expertPollTimer = setInterval(fetchExpert, window.POLL_MS || 2000);

  // SSE for TEA updates
  connectExpertSSE();
}

function stopExpertMode() {
  if (_expertPollTimer) { clearInterval(_expertPollTimer); _expertPollTimer = null; }
  if (_expertSSE) { _expertSSE.close(); _expertSSE = null; }
}

async function fetchExpert() {
  try {
    const r = await fetch(window.API_URL + '/api/expert/live');
    if (!r.ok) return;
    const data = await r.json();
    renderMLPanel(data.if, data.rf, data.tea);
    renderMitigationPanel(data.state_machine, data.deception, data.resource_guard);
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
  }
  if (payload.inference) {
    updateIFBar(payload.inference);
  }
}


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