const API     = window.API_URL;
const POLL_MS = window.POLL_MS || 2000;
const MAX_PTS = window.MAX_PTS || 30;
const MAX_LOG = window.MAX_LOG || 100;

/* ── Status pill helper ─────────────────────────────────────────────────────── */
function _setStatusPill(online) {
  const pill = document.getElementById('status-pill');
  const dot  = document.getElementById('status-dot');
  const txt  = document.getElementById('status-text');
  if (!pill) return;
  pill.style.display = 'flex';
  if (online) {
    pill.style.background = 'var(--green-g)';
    pill.style.borderColor = 'var(--green-g)';
    pill.style.color = 'var(--green)';
    if (dot)  { dot.style.background = 'var(--green)'; dot.style.boxShadow = '0 0 8px var(--green)'; }
    if (txt)  txt.textContent = 'System Online';
  } else {
    pill.style.background = 'var(--red-g)';
    pill.style.borderColor = 'var(--red-g)';
    pill.style.color = 'var(--red)';
    if (dot)  { dot.style.background = 'var(--red)'; dot.style.boxShadow = '0 0 8px var(--red)'; }
    if (txt)  txt.textContent = 'Disconnected';
  }
}

/* GET JSON from backend — throws on error; updates status pill */
async function apiFetch(path) {
  try {
    const r = await fetch(API + path);
    if (!r.ok) { _setStatusPill(false); throw r; }
    _setStatusPill(true);
    return r.json();
  } catch (e) {
    _setStatusPill(false);
    throw e;
  }
}
