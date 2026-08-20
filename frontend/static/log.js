/* log.js — SSE live events, audit log table DOM updates, recent events replay
 * Tracks rows by src_ip to detect phase escalations and update in-place. */

/* Row map — src_ip → { tr, action } — detects escalation for insert-vs-update */
const _logRows = new Map();
let logCt = 0;

/* Add or update one row in the audit log table */
function addLogRow(ev) {
  const tb          = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  const ip        = ev.src_ip     || '—';
  const newAction = ev.action_taken || '—';

  /* Append ban duration to Time Ban label if available */
  let actionLabel = newAction;
  if (/time ban/i.test(newAction) && ev.ban_duration_sec) {
    actionLabel = `Time Ban ${Math.round(ev.ban_duration_sec / 60)}m`;
  }

  const html = `
    <td class="mono">${ev.timestamp      || '—'}</td>
    <td class="ip">${ip}</td>
    <td>${renderClass(ev.predicted_class  || '—')}</td>
    <td>${renderVector(ev.attack_vector   || '—')}</td>
    <td class="mono">${ev.confidence      || '—'}</td>
    <td>${renderPriority(ev.priority      || 'Low')}</td>
    <td>${renderAction(actionLabel)}</td>`;

  /* Same IP, same action — update in-place with flash */
  if (_logRows.has(ip)) {
    const existing = _logRows.get(ip);
    if (existing.action === newAction) {
      existing.tr.dataset.ip         = ip;
      existing.tr.innerHTML          = html;
      existing.tr.style.transition   = 'background 0.3s';
      existing.tr.style.background   = 'rgba(61,108,255,0.15)';
      setTimeout(() => { existing.tr.style.background = ''; }, 600);
      return;
    }
    /* Action escalated — fall through to insert new row at top */
  }

  /* Evict oldest row if log is full */
  if (logCt >= MAX_LOG) {
    const oldest = tb.querySelector('tr:last-child');
    if (oldest) {
      const oldIp = oldest.querySelector('.ip');
      if (oldIp) _logRows.delete(oldIp.textContent.trim());
      oldest.remove();
    }
  } else {
    logCt++;
  }
  set('log-ct', logCt.toString());

  /* Insert new row at top */
  const tr      = document.createElement('tr');
  tr.className  = 'row-in tr-clickable';
  tr.dataset.ip = ip;
  tr.innerHTML  = html;
  _logRows.set(ip, { tr, action: newAction });
  tb.insertBefore(tr, tb.firstChild);
}

/* Connect SSE stream — auto-reconnects on error after 3s */
function connectSSE() {
  const es     = new EventSource(`${API}/api/events`);
  es.onmessage = e => { 
    try { 
      const parsed = JSON.parse(e.data);
      if (parsed.type === 'expert') return; // Handled by expert.js
      
      const ev = parsed.payload || parsed;
      if (ev.src_ip) addLogRow(ev); 
    } catch (_) {} 
  };
  es.onerror   = ()  => { es.close(); setTimeout(connectSSE, 3000); };
}

/* Replay last 100 events on page load so log is not empty on first visit */
async function fetchRecentEvents() {
  try {
    const events = await apiFetch('/api/recent_events?limit=100');
    events.forEach(ev => addLogRow(ev));
  } catch (_) {}
}