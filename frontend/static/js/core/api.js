// HTTP network transport client and system status indicator.
// Provides standardized API request execution with automatic payload encoding and error handling.

// Global network coordinates and client polling limits resolved from window configuration.
const API     = window.API_URL;
const POLL_MS = window.POLL_MS || 2000;
const MAX_PTS = window.MAX_PTS || 30;
const MAX_LOG = window.MAX_LOG || 100;

// Updates the header status badge color, indicator glow, and text based on network reachability.
// Provides visual feedback reflecting continuous connectivity with the backend service.
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

// Dispatches HTTP requests to backend endpoints with automatic JSON serialization and response parsing.
// Synchronizes the system status pill with network success and propagates HTTP errors to callers.
async function apiFetch(path, options = {}) {
  try {
    const fetchOpts = { ...options };
    if (fetchOpts.body && typeof fetchOpts.body === 'object' && !(fetchOpts.body instanceof FormData)) {
      fetchOpts.headers = {
        'Content-Type': 'application/json',
        ...(fetchOpts.headers || {}),
      };
      fetchOpts.body = JSON.stringify(fetchOpts.body);
    }

    const r = await fetch(API + path, fetchOpts);
    if (!r.ok) { _setStatusPill(false); throw r; }
    _setStatusPill(true);

    if (options.asBlob) return r.blob();
    return r.json();
  } catch (e) {
    _setStatusPill(false);
    throw e;
  }
}

