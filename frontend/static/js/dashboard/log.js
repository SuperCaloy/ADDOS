// Security audit log manager handling real-time event streaming, table diffing, and infinite scroll.
// Deduplicates incident rows by source IP and phase type while enabling historical pagination.

// Cached row map indexed by composite IP and event key, total count, sort direction, and scroll cursor.
const _logRows = new Map();
let logCt = 0;
let logSortAsc = false;
let logLoading = false;
let logAllLoaded = false;
let logOldestTimestamp = null;

// Constructs table column HTML, composite incident key, and formatted action labels from a raw event record.
function _buildEventRowData(ev) {
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

  return { ip, newAction, html, key, isRelease };
}

// Inserts a new security event row at the top of the audit table or updates an existing row during phase escalation.
// Manages row capacity eviction when the table reaches configured buffer limits.
function addLogRow(ev) {
  const tb          = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  const { ip, newAction, html, key, isRelease } = _buildEventRowData(ev);

  if (_logRows.has(key)) {
    const existing = _logRows.get(key);
    existing.tr.innerHTML = html;
    existing.tr.style.transition = 'background 0.3s';
    existing.tr.style.background = 'rgba(61,108,255,0.15)';
    setTimeout(() => { existing.tr.style.background = ''; }, 600);
    existing.action = newAction;
    if (isRelease) _logRows.delete(key);
    return;
  }

  if (MAX_LOG > 0 && logCt >= MAX_LOG) {
    const oldest = tb.querySelector('tr:last-child');
    if (oldest) {
      if (oldest.dataset.rowKey) _logRows.delete(oldest.dataset.rowKey);
      oldest.remove();
    }
  }
  logCt++;
  set('log-ct', logCt.toString());

  const tr      = document.createElement('tr');
  tr.className  = 'row-in tr-clickable';
  tr.dataset.ip = ip;
  tr.dataset.eventType = ev.event_type || 'transition';
  tr.dataset.rowKey = key;
  tr.innerHTML  = html;
  
  if (!isRelease) {
    _logRows.set(key, { tr, action: newAction });
  }
  
  tb.insertBefore(tr, tb.firstChild);
}

// Appends historical event rows to the bottom of the table during infinite scroll without triggering entry animations.
function prependOlderRows(events) {
  const tb = document.getElementById('log-body');
  const placeholder = tb.querySelector('[colspan]');
  if (placeholder) placeholder.parentElement.remove();

  events.forEach(ev => {
    const { ip, newAction, html, key, isRelease } = _buildEventRowData(ev);

    if (_logRows.has(key)) return;

    const tr      = document.createElement('tr');
    tr.className  = 'tr-clickable';
    tr.dataset.ip = ip;
    tr.dataset.eventType = ev.event_type || 'transition';
    tr.dataset.rowKey = key;
    tr.innerHTML  = html;

    if (!isRelease) {
      _logRows.set(key, { tr, action: newAction });
    }

    tb.appendChild(tr);
    logCt++;
  });

  set('log-ct', logCt.toString());
}

// Subscribes the audit log table to live event payloads broadcast over the unified EventBus.
function connectSSE() {
  if (window.EventBus) {
    window.EventBus.on('event', ev => {
      if (ev && ev.src_ip) addLogRow(ev);
    });
    window.EventBus.connect();
  }
}

// Re-orders rendered audit log table rows by timestamp in ascending or descending order.
function sortLogRows(asc) {
  const tb = document.getElementById('log-body');
  if (!tb) return;
  const rows = Array.from(tb.querySelectorAll('tr'));
  rows.sort((a, b) => {
    const tsA = a.querySelector('td')?.textContent?.trim() || '';
    const tsB = b.querySelector('td')?.textContent?.trim() || '';
    return asc ? tsA.localeCompare(tsB) : tsB.localeCompare(tsA);
  });
  rows.forEach(tr => tb.appendChild(tr));
}

// Inverts the active timestamp sort direction and updates the header arrow glyph.
function toggleLogSort() {
  logSortAsc = !logSortAsc;
  sortLogRows(logSortAsc);
  const arrow = document.querySelector('#log-sort-arrow');
  if (arrow) arrow.textContent = logSortAsc ? '▲' : '▼';
}

// Replays the most recent security events on page load to populate the audit log before live streaming begins.
async function fetchRecentEvents() {
  try {
    const events = await apiFetch('/api/recent_events?limit=100');
    events.forEach(ev => addLogRow(ev));
    sortLogRows(false);
    if (events.length > 0) {
      logOldestTimestamp = events[0].timestamp;
    }
    set('log-ct', logCt.toString());
  } catch (_) {}
}

// Fetches the next page of historical security events when the operator scrolls near the table bottom.
// Preserves user scroll position while inserting older incident records into the DOM.
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
      const prevScrollHeight = logScroll.scrollHeight;

      prependOlderRows(olderEvents);
      sortLogRows(logSortAsc);

      logOldestTimestamp = olderEvents[0].timestamp;
      logScroll.scrollTop = scrollTop + (logScroll.scrollHeight - prevScrollHeight);
    }
  } finally {
    logLoading = false;
  }
}

// Attaches scroll boundary detection to the table container to trigger pagination.
function setupInfiniteScroll() {
  const logScroll = document.querySelector('#log-body').closest('.tbl-scroll');
  if (!logScroll) return;

  logScroll.addEventListener('scroll', () => {
    loadOlderEvents();
  });
}

document.addEventListener('DOMContentLoaded', setupInfiniteScroll);

