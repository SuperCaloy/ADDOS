// Interactive date-picker calendar widget for forensic PDF report generation.
// Visualizes dates with recorded traffic logs and enforces start and end boundary rules.

// Set of database dates with historical logs and active month-selection state for date pickers.
let _calDates = new Set();
let _calState = {
  start: { year: 0, month: 0, selected: '' },
  end:   { year: 0, month: 0, selected: '' },
};

// Converts a JavaScript Date object into an ISO YYYY-MM-DD date string.
function _isoDate(dt) {
  return `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}-${String(dt.getDate()).padStart(2,'0')}`;
}

// Generates the monthly calendar grid indicating available data days, disabled future dates, and selection states.
// Injects button elements with accessibility labels for each day of the rendered month.
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

// Navigates the month of the selected calendar picker forward or backward across year boundaries.
function calNav(which, dir) {
  const s = _calState[which];
  s.month += dir;
  if (s.month > 11) { s.month = 0;  s.year++; }
  if (s.month <  0) { s.month = 11; s.year--; }
  _renderCal(which);
  if (window.event) window.event.stopPropagation();
}

// Updates the chosen date string for a picker, synchronizes its input field, and closes the popup.
function calSelect(which, ds) {
  _calState[which].selected = ds;
  document.getElementById(`r-${which}`).value = ds;
  _renderCal(which);
  document.getElementById(`cal-${which}-popup`).classList.remove('open');
}

// Toggles visibility of the calendar popup for start or end date fields, closing the other picker.
function toggleCal(which) {
  const popup = document.getElementById(`cal-${which}-popup`);
  const other = which === 'start' ? 'end' : 'start';
  document.getElementById(`cal-${other}-popup`)?.classList.remove('open');
  popup.classList.toggle('open');
  if (popup.classList.contains('open')) _renderCal(which);
  if (window.event) window.event.stopPropagation();
}

// Closes all open calendar dropdown popups when the operator clicks outside picker boundaries.
document.addEventListener('click', () => {
  document.getElementById('cal-start-popup')?.classList.remove('open');
  document.getElementById('cal-end-popup')?.classList.remove('open');
});

// Validates manually typed ISO date strings and updates corresponding calendar state if valid.
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

// Queries the backend API for dates containing historical traffic logs to highlight in the calendar grid.
async function _loadHistoryDates() {
  try {
    const r = await apiFetch('/api/history_dates');
    _calDates = new Set(r.dates || []);
  } catch (_) { _calDates = new Set(); }
}

// Initializes calendar state objects and renders grid views for start and end date pickers.
function _initCals(startS, endS) {
  const s = new Date(startS + 'T00:00:00');
  const e = new Date(endS   + 'T00:00:00');
  _calState.start = { year: s.getFullYear(), month: s.getMonth(), selected: startS };
  _calState.end   = { year: e.getFullYear(), month: e.getMonth(), selected: endS   };
  _renderCal('start');
  _renderCal('end');
}

// Opens the PDF report modal dialog initialized to a default 7-day retrospective window.
// Queries historical date availability and renders both calendar pickers.
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

