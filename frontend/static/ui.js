/* ui.js — DOM utilities, tag renderers, toast, theme toggle, modal, calendar
 * No polling logic here — pure presentation helpers used by all other modules. */

/* Set text content of element by id */
function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* ── Tag renderers ─────────────────────────────────────────────────────────── */

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
  return v === 'High'
    ? '<span class="p-high">HIGH</span>'
    : '<span class="p-low">LOW</span>';
}

/* ── Toast ─────────────────────────────────────────────────────────────────── */

function showToast(msg, isErr = false) {
  const el     = document.createElement('div');
  el.className = 'toast';
  if (isErr) el.style.borderColor = 'rgba(255,61,90,.4)';
  el.textContent = msg;
  document.getElementById('toaster').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/* ── Theme toggle ──────────────────────────────────────────────────────────── */

let isLight = false;

function toggleTheme() {
  isLight = !isLight;
  document.body.classList.toggle('light', isLight);
  document.getElementById('theme-btn').textContent = isLight ? '☾ Dark Mode' : '☀ Light Mode';

  /* Update chart colors to match theme */
  const gridColor   = isLight ? '#d8dce8' : '#1e2235';
  const tickColor   = isLight ? '#6b7280' : '#5c6080';
  const legendColor = isLight ? '#4b5563' : '#5c6080';

  if (window._chart) {
    window._chart.options.scales.x.grid.color         = gridColor;
    window._chart.options.scales.y.grid.color         = gridColor;
    window._chart.options.scales.x.ticks.color        = tickColor;
    window._chart.options.scales.y.ticks.color        = tickColor;
    window._chart.options.plugins.legend.labels.color = legendColor;
    window._chart.options.plugins.tooltip.backgroundColor = isLight ? '#ffffff' : '#111320';
    window._chart.options.plugins.tooltip.titleColor      = isLight ? '#6b7280' : '#8890b0';
    window._chart.options.plugins.tooltip.bodyColor       = isLight ? '#111827' : '#e8eaf6';
    window._chart.options.plugins.tooltip.borderColor     = isLight ? '#d8dce8' : '#1e2235';
    window._chart.update();
  }

  localStorage.setItem('adddos-theme', isLight ? 'light' : 'dark');
}

/* Restore saved theme on load — defer so window._chart exists first */
window.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem('adddos-theme') === 'light') toggleTheme();
});

/* ── Report modal ──────────────────────────────────────────────────────────── */

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

  if (!sd || !ed)                                        { err.textContent = 'Select both dates.'; return; }
  if (ed < sd)                                           { err.textContent = 'End must be after start.'; return; }
  if (ed > new Date().toISOString().split('T')[0])       { err.textContent = 'End date cannot be in the future.'; return; }

  err.textContent = '';
  closeModal();

  try {
    const r = await fetch(`${API}/api/report`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ start_date: sd, end_date: ed }),
    });
    if (r.status === 404) { const j = await r.json(); showToast(j.error || 'No data.', true); return; }
    if (!r.ok)            { showToast(`Error: ${r.status}`, true); return; }

    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `ddos_report_${sd}_to_${ed}.pdf`; a.click();
    URL.revokeObjectURL(url);
    showToast('Report downloaded.');
  } catch (e) { showToast(`Failed: ${e.message}`, true); }
}

/* ── Calendar widget ───────────────────────────────────────────────────────── */

let _calDates = new Set();
let _calState = {
  start: { year: 0, month: 0, selected: '' },
  end:   { year: 0, month: 0, selected: '' },
};

function _isoDate(dt) {
  return `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}`;
}

/* Render calendar grid for 'start' or 'end' picker */
function _renderCal(which) {
  const s      = _calState[which];
  const today  = new Date();
  const todayS = _isoDate(today);
  const grid   = document.getElementById(`cal-${which}-grid`);
  const label  = document.getElementById(`cal-${which}-label`);
  if (!grid || !label) return;

  const monthNames = ['January','February','March','April','May','June',
                      'July','August','September','October','November','December'];
  label.textContent = `${monthNames[s.month]} ${s.year}`;

  const first  = new Date(s.year, s.month, 1).getDay();
  const daysIn = new Date(s.year, s.month + 1, 0).getDate();

  let html = '';
  for (let i = 0; i < first; i++) html += `<div class="cal-day cal-empty"></div>`;

  for (let d = 1; d <= daysIn; d++) {
    const ds      = _isoDate(new Date(s.year, s.month, d));
    const isFut   = ds > todayS;
    const hasData = _calDates.has(ds);
    const isSel   = ds === s.selected;
    const isToday = ds === todayS;

    let cls = 'cal-day';
    if (isFut)    cls += ' cal-disabled';
    if (hasData)  cls += ' cal-has-data';
    if (isSel)    cls += ' cal-selected';
    if (isToday)  cls += ' cal-today';

    const click = isFut ? '' : `onclick="calSelect('${which}','${ds}')"`;
    html += `<div class="${cls}" ${click}>${d}</div>`;
  }
  grid.innerHTML = html;
}

function calNav(which, dir) {
  const s = _calState[which];
  s.month += dir;
  if (s.month > 11) { s.month = 0;  s.year++; }
  if (s.month <  0) { s.month = 11; s.year--; }
  _renderCal(which);
  event.stopPropagation();
}

function calSelect(which, ds) {
  _calState[which].selected = ds;
  document.getElementById(`r-${which}`).value = ds;
  _renderCal(which);
  document.getElementById(`cal-${which}-popup`).classList.remove('open');
}

function toggleCal(which) {
  const popup = document.getElementById(`cal-${which}-popup`);
  const other = which === 'start' ? 'end' : 'start';
  document.getElementById(`cal-${other}-popup`).classList.remove('open');
  popup.classList.toggle('open');
  if (popup.classList.contains('open')) _renderCal(which);
  event.stopPropagation();
}

/* Close calendar popups on outside click */
document.addEventListener('click', () => {
  document.getElementById('cal-start-popup')?.classList.remove('open');
  document.getElementById('cal-end-popup')?.classList.remove('open');
});

/* Validate typed YYYY-MM-DD and sync calendar state */
function onDateType(which, val) {
  if (/^\d{4}-\d{2}-\d{2}$/.test(val)) {
    const dt = new Date(val + 'T00:00:00');
    if (!isNaN(dt)) {
      _calState[which].year     = dt.getFullYear();
      _calState[which].month    = dt.getMonth();
      _calState[which].selected = val;
      _renderCal(which);
    }
  }
}

async function _loadHistoryDates() {
  try {
    const r = await apiFetch('/api/history_dates');
    _calDates = new Set(r.dates || []);
  } catch (_) { _calDates = new Set(); }
}

function _initCals(startS, endS) {
  const s = new Date(startS + 'T00:00:00');
  const e = new Date(endS   + 'T00:00:00');
  _calState.start = { year: s.getFullYear(), month: s.getMonth(), selected: startS };
  _calState.end   = { year: e.getFullYear(), month: e.getMonth(), selected: endS   };
  _renderCal('start');
  _renderCal('end');
}

/* Open modal — reset fields, load history dates, init calendars */
async function openModal() {
  const today   = new Date();
  const endS    = _isoDate(today);
  const startDt = new Date(today);
  startDt.setDate(startDt.getDate() - 7);
  const startS  = _isoDate(startDt);

  document.getElementById('m-err').textContent = '';
  document.getElementById('r-start').value     = startS;
  document.getElementById('r-end').value       = endS;
  document.getElementById('modal').classList.add('open');
  await _loadHistoryDates();
  _initCals(startS, endS);
}