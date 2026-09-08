/* ui.js -- DOM utilities, tag renderers, toast, theme toggle, modal, calendar
 * No polling logic here -- pure presentation helpers used by all other modules. */

/* Set text content of element by id */
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* -- Tag renderers ----------------------------------------------------------- */

const mkTag = (cls, txt) => `<span class="tag ${cls}">${txt}</span>`;

function renderClass(v) {
  if (v === 'DDoS')    return mkTag('t-ddos',    v);
  if (v === 'Anomaly') return mkTag('t-anomaly', v);
  return `<span style="color:var(--sub2)">${v}</span>`;
}

function renderVector(v) {
  const map = { 'SYN Flood': 't-syn', 'UDP Flood': 't-udp', 'ICMP Flood': 't-icmp', 'Uncertain': 't-unc' };
  return map[v] ? mkTag(map[v], v) : `<span style="color:var(--sub2)">${v}</span>`;
}

function renderAction(v) {
  const map = { 'Quarantined': 't-q', 'Rate Limited': 't-rl', 'Time Ban': 't-ban', 'Blackhole': 't-blocked', 'Blocked': 't-blocked' };
  return map[v] ? mkTag(map[v], v) : `<span style="color:var(--sub2)">${v}</span>`;
}

function renderPriority(v) {
  const map = {
    'Critical': '<span class="p-crit">CRITICAL</span>',
    'High':     '<span class="p-high">HIGH</span>',
    'Medium':   '<span class="p-med">MEDIUM</span>',
    'Low':      '<span class="p-low">LOW</span>',
  };
  return map[v] || `<span class="p-low">${v}</span>`;
}

/* -- Toast ------------------------------------------------------------------- */

function showToast(msg, isErr = false) {
  const el     = document.createElement('div');
  el.className = 'toast';
  el.setAttribute('role', isErr ? 'alert' : 'status');
  el.setAttribute('aria-live', isErr ? 'assertive' : 'polite');
  if (isErr) el.style.borderColor = 'rgba(255,61,90,.4)';
  el.textContent = msg;
  document.getElementById('toaster').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* -- Theme toggle ------------------------------------------------------------ */

let isLight = false;

function _applyTheme(light) {
  document.body.classList.toggle('light', light);
  document.body.classList.toggle('dark', !light);
  const btn = document.getElementById('theme-btn');
  if (btn) {
    btn.innerHTML = light
      ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
      : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
  }

  const gridColor   = light ? '#d8dce8' : '#1e2235';
  const tickColor   = light ? '#6b7280' : '#5c6080';
  const legendColor = light ? '#4b5563' : '#5c6080';

  if (window._chart) {
    window._chart.options.scales.x.grid.color         = gridColor;
    window._chart.options.scales.y.grid.color         = gridColor;
    window._chart.options.scales.x.ticks.color        = tickColor;
    window._chart.options.scales.y.ticks.color        = tickColor;
    window._chart.options.plugins.legend.labels.color = legendColor;
    window._chart.options.plugins.tooltip.backgroundColor = light ? '#ffffff' : '#111320';
    window._chart.options.plugins.tooltip.titleColor      = light ? '#6b7280' : '#8890b0';
    window._chart.options.plugins.tooltip.bodyColor       = light ? '#111827' : '#e8eaf6';
    window._chart.options.plugins.tooltip.borderColor     = light ? '#d8dce8' : '#1e2235';
    window._chart.update();
  }

  if (window.ExpertPipeline && window.ExpertPipeline.canvas) {
    window.ExpertPipeline.isLightMode = light;
  }

  localStorage.setItem('adddos-theme', light ? 'light' : 'dark');
  if (window.Store) window.Store.setTheme(light);
}

function toggleTheme() {
  isLight = !isLight;
  _applyTheme(isLight);
}

/* Restore saved theme on load -- defer so window._chart exists first */
window.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('adddos-theme');
  if (saved === 'light') {
    isLight = true;
    _applyTheme(true);
  } else if (saved === 'dark') {
    isLight = false;
    _applyTheme(false);
  } else {
    _applyTheme(false);
  }
});

/* -- Report modal ------------------------------------------------------------ */

function closeModal() {
  document.getElementById('modal').classList.remove('open');
}

document.getElementById('modal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});

async function submitReport() {
  const sd  = document.getElementById('r-start').value;
  const ed  = document.getElementById('r-end').value;
  const err = document.getElementById('m-err');

  const today = (typeof _isoDate === 'function') ? _isoDate(new Date()) : new Date().toISOString().slice(0, 10);
  if (!sd || !ed) { err.textContent = 'Select both dates.'; return; }
  if (ed < sd)    { err.textContent = 'End must be after start.'; return; }
  if (ed > today) { err.textContent = 'End date cannot be in the future.'; return; }

  err.textContent = '';
  closeModal();

  try {
    const blob = await apiFetch('/api/report', {
      method:  'POST',
      body:    { start_date: sd, end_date: ed, client_today: today },
      asBlob:  true,
    });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `ddos_report_${sd}_to_${ed}.pdf`; a.click();
    URL.revokeObjectURL(url);
    showToast('Report downloaded.');
  } catch (e) {
    if (e && e.status === 404) {
      try { const j = await e.json(); showToast(j.error || 'No data.', true); return; } catch (_) {}
    }
    showToast('Failed to generate report.', true);
  }
}