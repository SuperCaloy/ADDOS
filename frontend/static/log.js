/* log.js - SSE live events, audit log table DOM updates, recent events replay
 * Tracks rows by src_ip to detect phase escalations and update in-place.
 * Includes infinite scroll for loading older events seamlessly. */

/* Row map -- `${ip}|${event_type}` -> { tr, action } -- composite key so re-attacks create new rows */
const _logRows = new Map();
let logCt = 0;

/* Infinite scroll state */
let logLoading = false;
let logAllLoaded = false;
let logOldestTimestamp = null;

/* Add or update one row in the audit log table */
function addLogRow(ev) {
  const tb          = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  const ip        = ev.src_ip     || '-';
  const newAction = ev.action_taken || '-';

  /* Append ban duration to Time Ban label if available */
  let actionLabel = newAction;
  if (/time ban/i.test(newAction) && ev.ban_duration_sec) {
    actionLabel = `Time Ban ${Math.round(ev.ban_duration_sec / 60)}m`;
  }

  const html = `
    <td class="mono">${ev.timestamp      || '-'}</td>
    <td class="ip">${ip}</td>
    <td>${renderClass(ev.predicted_class  || '-')}</td>
    <td>${renderVector(ev.attack_vector   || '-')}</td>
    <td class="mono">${ev.confidence      || '-'}</td>
    <td>${renderPriority(ev.priority      || 'Low')}</td>
    <td>${renderAction(actionLabel)}</td>`;

  /* Same incident -- update in-place with flash */
  const key = ip + '|' + (ev.event_type || 'transition');
  const isRelease = ev.event_type === 'released' || (ev.event_type === 'manual' && /release/i.test(newAction));

  if (_logRows.has(key)) {
    const existing = _logRows.get(key);
    // Overwrite the existing row for the session, even if action escalates
    existing.tr.dataset.ip         = ip;
    existing.tr.innerHTML          = html;
    existing.tr.style.transition   = 'background 0.3s';
    existing.tr.style.background   = 'rgba(61,108,255,0.15)';
    setTimeout(() => { existing.tr.style.background = ''; }, 600);
    existing.action = newAction;
    
    /* Released events end an incident; clear key so next attack creates a fresh row */
    if (isRelease) {
      _logRows.delete(key);
    }
    return;
  }

  /* Evict oldest row if log is full (MAX_LOG_ROWS=0 means no limit) */
  if (MAX_LOG > 0 && logCt >= MAX_LOG) {
    const oldest = tb.querySelector('tr:last-child');
    if (oldest) {
      const oldIp = oldest.querySelector('.ip');
      if (oldIp) _logRows.delete(oldIp.textContent.trim() + '|' + (oldest.dataset.eventType || 'transition'));
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
  tr.dataset.eventType = ev.event_type || 'transition';
  tr.innerHTML  = html;
  
  if (!isRelease) {
    _logRows.set(key, { tr, action: newAction });
  }
  
  tb.insertBefore(tr, tb.firstChild);
}

/* Prepend older rows for infinite scroll (no animation, preserves scroll position) */
function prependOlderRows(events) {
  const tb = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  events.forEach(ev => {
    const ip        = ev.src_ip     || '-';
    const newAction = ev.action_taken || '-';

    let actionLabel = newAction;
    if (/time ban/i.test(newAction) && ev.ban_duration_sec) {
      actionLabel = `Time Ban ${Math.round(ev.ban_duration_sec / 60)}m`;
    }

    const html = `
      <td class="mono">${ev.timestamp      || '-'}</td>
      <td class="ip">${ip}</td>
      <td>${renderClass(ev.predicted_class  || '-')}</td>
      <td>${renderVector(ev.attack_vector   || '-')}</td>
      <td class="mono">${ev.confidence      || '-'}</td>
      <td>${renderPriority(ev.priority      || 'Low')}</td>
      <td>${renderAction(actionLabel)}</td>`;

    const key = ip + '|' + (ev.event_type || 'transition');
    const isRelease = ev.event_type === 'released' || (ev.event_type === 'manual' && /release/i.test(newAction));

    /* Skip if row already exists (dedup) */
    if (_logRows.has(key)) return;

    const tr      = document.createElement('tr');
    tr.className  = 'tr-clickable';
    tr.dataset.ip = ip;
    tr.dataset.eventType = ev.event_type || 'transition';
    tr.innerHTML  = html;

    if (!isRelease) {
      _logRows.set(key, { tr, action: newAction });
    }

    /* Append to bottom (older events go to bottom) */
    tb.appendChild(tr);
    logCt++;
  });

  set('log-ct', logCt.toString());
}

/* Connect SSE stream - auto-reconnects on error after 3s */
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
    /* Track oldest timestamp for infinite scroll */
    if (events.length > 0) {
      logOldestTimestamp = events[0].timestamp;
    }
  } catch (_) {}
}

/* Load older events for infinite scroll (Facebook/X style - seamless) */
async function loadOlderEvents() {
  if (logLoading || logAllLoaded) return;

  const logScroll = document.querySelector('#log-body').closest('.tbl-scroll');
  if (!logScroll) return;

  const { scrollTop, scrollHeight, clientHeight } = logScroll;
  if (scrollTop + clientHeight < scrollHeight - 100) return;

  logLoading = true;

  try {
    const url = logOldestTimestamp
      ? `/api/recent_events?limit=50&before=${encodeURIComponent(logOldestTimestamp)}`
      : `/api/recent_events?limit=50`;

    const olderEvents = await apiFetch(url);

    if (olderEvents.length === 0) {
      logAllLoaded = true;
    } else {
      /* Save scroll position */
      const prevScrollHeight = logScroll.scrollHeight;

      /* Prepend older rows */
      prependOlderRows(olderEvents);

      /* Update cursor to oldest loaded event */
      logOldestTimestamp = olderEvents[0].timestamp;

      /* Restore scroll position (new rows added below) */
      logScroll.scrollTop = scrollTop + (logScroll.scrollHeight - prevScrollHeight);
    }
  } finally {
    logLoading = false;
  }
}

/* Setup infinite scroll listener */
function setupInfiniteScroll() {
  const logScroll = document.querySelector('#log-body').closest('.tbl-scroll');
  if (!logScroll) return;

  logScroll.addEventListener('scroll', () => {
    loadOlderEvents();
  });
}

/* Initialize infinite scroll on DOM ready */
document.addEventListener('DOMContentLoaded', setupInfiniteScroll);
