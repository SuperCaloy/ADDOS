/* stats.js — polls /api/stats, updates metric cards, feeds live chart
 * Also fetches /api/model_info once at boot (never changes at runtime). */

/* Previous cumulative values — used to compute per-interval deltas for chart */
let prev = { t: 0, m: 0, n: 0 };

/* Shared IF threshold — set once by fetchModelInfo, read by quarantine.js */
let ifThr = 0;

/* Format cumulative change as +X.X% string */
function _pctDelta(curr, prevVal) {
  const d = ((curr - prevVal) / Math.max(prevVal, 1)) * 100;
  return (d >= 0 ? '+' : '') + d.toFixed(1) + '%';
}

/* Poll /api/stats — update cards and push one chart point */
async function fetchStats() {
  try {
    const s = await apiFetch('/api/stats');

    const ct  = s.total_packets     || 0;
    const cm  = s.malicious_dropped || 0;
    const cn  = s.normal_packets    || 0;
    const tot = Math.max(ct, 1);

    /* Update summary cards */
    set('c-total',   ct.toLocaleString());
    set('c-total-s', prev.t > 0 ? _pctDelta(ct, prev.t) : '+0.0%');
    set('c-mal',     cm.toLocaleString());
    set('c-mal-s',   `-${((cm / tot) * 100).toFixed(1)}%`);
    set('c-norm',    cn.toLocaleString());
    set('c-norm-s',  `+${((cn / tot) * 100).toFixed(1)}%`);
    set('c-thr',     (s.active_threats || 0).toString());
    set('p-rt',      `${s.avg_latency_ms || 0} ms`);

    /* FP rate card — color-coded by severity */
    const fpRate = typeof s.fp_rate === 'number' ? s.fp_rate : 0;
    const fpEl   = document.getElementById('p-fp');
    if (fpEl) {
      fpEl.textContent = `${fpRate.toFixed(1)} %`;
      fpEl.style.color = fpRate === 0 ? 'var(--ok, #00d68f)'
                       : fpRate <  1  ? 'var(--warn, #ffb300)'
                       : fpRate <  5  ? 'var(--warn, #ff8c00)'
                       : 'var(--danger, #ff3d5a)';
    }

    /* Feed live chart — compute per-interval deltas from cumulative values */
    if (range === 'Live') {
      const lm     = s.live_malicious || 0;
      const ln     = s.live_normal    || 0;
      const deltaM = prev.m > 0 ? Math.max(lm - prev.m, 0) : 0;
      const deltaN = prev.n > 0 ? Math.max(ln - prev.n, 0) : 0;
      const deltaT = deltaM + deltaN;
      const now    = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      pushChartPoint(now, deltaT, deltaM, deltaN);
    }

    /* Save for next poll delta calculation */
    prev = { t: ct, m: cm, n: cn };

  } catch (_) {}
}

/* Fetch model info once at boot — not polled, never changes at runtime */
async function fetchModelInfo() {
  try {
    const info = await apiFetch('/api/model_info');
    if (info.if_accuracy != null) set('p-if', `Anomaly detection accuracy: ${info.if_accuracy.toFixed(1)}%`);
    if (info.rf_accuracy != null) set('p-rf', `Classification accuracy: ${info.rf_accuracy.toFixed(1)}%`);
    if (info.if_threshold)        ifThr = info.if_threshold;
  } catch (_) {}
}