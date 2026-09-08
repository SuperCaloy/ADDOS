/**
 * Panel renderers for Machine Learning Internals and Mitigation State Machine in Expert Mode.
 * Generates SVG sparklines, score thermometers, traffic composition bars, and active state feeds.
 */

/**
 * Generates an inline SVG polyline sparkline visualizing historical telemetry trends.
 * Normalizes values across the available vertical range or outputs a fallback indicator for empty series.
 */
function makeSparkline(data, color) {
  if (!data || data.length < 1) return '<div class="sparkline-placeholder">--</div>';
  if (data.length === 1) {
    return `<svg class="sparkline" viewBox="0 0 120 30" preserveAspectRatio="none">
      <polyline fill="none" stroke="${color}" stroke-width="1.5" points="0,15 120,15"/>
    </svg>`;
  }
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const w = 120, h = 30;
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

/**
 * Renders the Machine Learning Internals panel containing IF thermometers, RF composition bars, and TEA z-scores.
 * Updates DOM elements progressively or initializes required container markup if unpopulated.
 */
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
  const thr = (ifData && ifData.threshold) || 0.5992;

  let highestScore = 0;
  let isAnom = false;
  if (ifData && ifData.recent_scores && ifData.recent_scores.length > 0) {
    const sorted = [...ifData.recent_scores].sort((a, b) => b.score - a.score);
    highestScore = sorted[0].score;
    isAnom = sorted[0].anomaly;
  }

  const thrPct = 50;
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

  // RF Traffic Composition Bar: SYN/ICMP/UDP
  const dist = (rfData && rfData.class_distribution) || { 'SYN Flood': 0, 'ICMP Flood': 0, 'UDP Flood': 0 };
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
  const teaGlobal = teaData && teaData.global ? teaData.global : null;
  if (teaGlobal && Object.keys(teaGlobal).length > 0) {
    const isAttack = teaGlobal.is_attack;
    const isFlash = teaGlobal.is_flash_crowd;
    const isLearned = teaGlobal.learned;
    const isLocked = teaGlobal._locked === true;

    const statusClass = isAttack ? 'attack' : isFlash ? 'flash-crowd' : !isLearned ? 'learning' : isLocked ? 'uncertain' : 'learned';
    const statusText = isAttack ? 'ATTACK' : isFlash ? 'FLASH CROWD' : !isLearned ? 'LEARNING' : isLocked ? 'UNCERTAIN' : 'NORMAL';

    const maxSizeZ = teaGlobal.size_z || 0;
    const maxIntZ = teaGlobal.intensity_z || 0;

    const sizeZPct = Math.min(Math.max((maxSizeZ + 3) / 6 * 100, 0), 100);
    const intZPct = Math.min(Math.max((maxIntZ + 3) / 6 * 100, 0), 100);

    const attackSigma = teaGlobal.dynamic_attack_sigma || 2.5;
    const thresholdPct = Math.min(Math.max((attackSigma + 3) / 6 * 100, 0), 100);

    const learningInterval = teaGlobal.learning_interval;
    const learningIntervals = teaGlobal.learning_intervals || 15;
    const learningProgress = !isLearned && learningInterval ? `${learningInterval}/${learningIntervals}` : '';

    const sizeBaselineHist = teaGlobal.size_baseline_history || [];
    const intBaselineHist = teaGlobal.intensity_baseline_history || [];

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
      const progEl = existingCard.querySelector('.tea-learning-progress');
      if (statusEl) { statusEl.className = `tea-switch-status ${statusClass}`; statusEl.textContent = statusText; }
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

      const sizeSpark = existingCard.querySelector('.sparkline-row:first-child .sparkline');
      const intSpark = existingCard.querySelector('.sparkline-row:last-child .sparkline');
      if (sizeSpark) sizeSpark.outerHTML = makeSparkline(sizeBaselineHist, '#14B8A6');
      if (intSpark) intSpark.outerHTML = makeSparkline(intBaselineHist, '#F59E0B');
    }
  } else {
    if (teaWrap) teaWrap.innerHTML = '';
  }
}

/**
 * Updates Temporal Entropy Analysis progress meters, z-scores, and status labels during polling loops.
 * Synchronizes global pipeline latch state with current switch telemetry.
 */
function updateTEASwitch(tea) {
  if (!tea) return;

  if (window.ExpertPipeline && window.ExpertPipeline.latchState) {
    if (tea._locked !== undefined) window.ExpertPipeline.latchState.locked = tea._locked;
    if (tea._fb_normal_streak !== undefined) window.ExpertPipeline.latchState.streak = tea._fb_normal_streak;
  }

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
      statusEl.className = 'tea-switch-status uncertain';
      statusEl.textContent = 'UNCERTAIN';
    } else {
      statusEl.className = 'tea-switch-status learned';
      statusEl.textContent = 'NORMAL';
    }
  }
}

/**
 * Updates the Isolation Forest anomaly score thermometer and maximum score reading.
 * Adjusts bar fill widths dynamically upon receiving new individual flow inference reports.
 */
function updateIFBar(inf) {
  if (!inf) return;

  const thermometer = document.querySelector('.if-thermometer-fill');
  if (thermometer) {
    const score = inf.if_score || 0;
    const threshold = 0.5992;
    const fillPct = Math.min((score / (threshold * 2)) * 100, 100);
    thermometer.style.width = fillPct + '%';
    thermometer.className = 'if-thermometer-fill' + (inf.is_anomaly ? ' anomaly' : ' normal');
  }

  const statsEl = document.querySelector('.if-stats span:first-child');
  if (statsEl && inf.if_score != null) {
    statsEl.textContent = 'Max: ' + inf.if_score.toFixed(4);
  }
}

/**
 * Renders mitigation state machine phase summaries and recent active flow telemetry feeds.
 * Displays phase counters for quarantine, time bans, and blackholes alongside IP audit logs.
 */
function renderMitigationPanel(smStates, deception, rg) {
  const el = document.getElementById('expert-mitigation-content');
  if (!el) return;

  const phaseCounts = { 1: 0, 2: 0, 3: 0 };
  if (smStates) {
    Object.values(smStates).forEach(s => { if (s.phase) phaseCounts[s.phase] = (phaseCounts[s.phase] || 0) + 1; });
  }

  const hasActiveFlow = smStates && Object.values(smStates).length > 0;

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
  if (ipListEl && smStates) {
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
          <span class="t-stat">IF=${(s.if_score || 0).toFixed(4)}</span>
          <span class="t-stat">PPS=${(s.recent_pps || 0).toFixed(1)}</span>
          <span class="t-alert">ACT=${(s.action || '').toUpperCase()}</span>
          ${s.ttl_sec != null ? `<span class="t-stat">TTL=${s.ttl_sec}s</span>` : ''}
        </div>`;
    });
    ipListEl.innerHTML = ipHtml;
  }
}

window.renderMLPanel = renderMLPanel;
window.updateTEASwitch = updateTEASwitch;
window.updateIFBar = updateIFBar;
window.renderMitigationPanel = renderMitigationPanel;
