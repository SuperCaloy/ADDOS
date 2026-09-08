/* calendar.js: Custom date-picker calendar widget for PDF report generation */

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
  for (let i = 0; i < first; i++) html += `<div class="cal-day cal-empty" aria-hidden="true"></div>`;

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

    if (isFut) {
      html += `<button type="button" class="${cls}" disabled aria-label="${ds} (unavailable)">${d}</button>`;
    } else {
      html += `<button type="button" class="${cls}" onclick="calSelect('${which}','${ds}')" aria-label="${ds}${isSel ? ' (selected)' : ''}${hasData ? ', has data' : ''}">${d}</button>`;
    }
  }
  grid.innerHTML = html;
}

function calNav(which, dir) {
  const s = _calState[which];
  s.month += dir;
  if (s.month > 11) { s.month = 0;  s.year++; }
  if (s.month <  0) { s.month = 11; s.year--; }
  _renderCal(which);
  if (window.event) window.event.stopPropagation();
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
  document.getElementById(`cal-${other}-popup`)?.classList.remove('open');
  popup.classList.toggle('open');
  if (popup.classList.contains('open')) _renderCal(which);
  if (window.event) window.event.stopPropagation();
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

/* Open modal: reset fields, load history dates, init calendars */
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
