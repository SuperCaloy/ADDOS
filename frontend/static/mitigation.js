/* quarantine.js — polls /api/quarantine_list, DOM-diffs watchlist table,
 * handles release and blackhole button actions. */

/* Row map — src_ip → <tr> — used for in-place DOM updates (no flicker) */
const _qRows = new Map();

/* Poll /api/quarantine_list and update watchlist table */
async function fetchQuarantine() {
  try {
    const data = await apiFetch('/api/quarantine_list');
    set('q-ct', `${data.length} IP${data.length !== 1 ? 's' : ''}`);
    const tb = document.getElementById('q-body');

    /* Empty state */
    if (!data.length) {
      _qRows.clear();
      tb.innerHTML = `<tr><td colspan="7" class="q-empty">No IPs currently under active mitigation.</td></tr>`;
      return;
    }

    /* Remove rows whose IP is no longer in the list */
    const activeIps = new Set(data.map(e => e.src_ip));
    for (const [ip, tr] of _qRows) {
      if (!activeIps.has(ip)) { tr.remove(); _qRows.delete(ip); }
    }

    /* Update existing rows or insert new ones */
    data.forEach(e => {
      const sc   = e.if_score || 0;
      const ts   = e.time_in_phase_sec || 0;
      const conf = e.confidence || '—';
      const time = ts < 60 ? `${ts}s` : `${Math.floor(ts / 60)}m ${ts % 60}s`;

      /* IF score color class based on threshold */
      const scCls = !ifThr           ? 'mono'
                  : sc >= ifThr * 1.2 ? 'sc-red'
                  : sc >= ifThr       ? 'sc-amb'
                  : 'sc-grn';

      /* TTL countdown for time-ban rows */
      const ttlRemaining = e.ttl_remaining_sec != null
        ? ` <span style="color:var(--amber,#ffb300);font-size:11px;font-family:var(--mono)">[${Math.floor(e.ttl_remaining_sec/60)}m ${e.ttl_remaining_sec%60}s]</span>`
        : '';

      /* Priority badge */
      const _priMap = {
        'Critical': '<span class="p-crit">CRITICAL </span>',
        'High':     '<span class="p-high">HIGH </span>',
        'Medium':   '<span class="p-med">MEDIUM </span>',
      };
      const priBadge = _priMap[e.priority] || '';

      /* Use phase_label if available, otherwise fall back to phase */
      const phaseDisplay = e.phase_label || e.phase || '—';

      const inner = `
        <td class="ip">${e.src_ip || '—'}</td>
        <td style="color:var(--sub2);font-size:13px">${priBadge}${phaseDisplay}${ttlRemaining}</td>
        <td>${renderVector(e.attack_vector || '—')}</td>
        <td class="${scCls}">${sc.toFixed(4)}</td>
        <td class="mono">${conf}</td>
        <td style="color:var(--sub2);font-family:var(--mono);font-size:12px">${time}</td>
        <td><div style="display:flex;gap:6px">
          <button class="q-btn q-rel" onclick="event.stopPropagation();quarantineAction('release','${e.src_ip}')">Release</button>
          <button class="q-btn q-blk" onclick="event.stopPropagation();quarantineAction('block','${e.src_ip}')">Blackhole</button>
        </div></td>`;

      if (_qRows.has(e.src_ip)) {
        /* Update in-place — no DOM remove/insert, no flicker */
        const existing     = _qRows.get(e.src_ip);
        existing.dataset.ip = e.src_ip;
        existing.innerHTML  = inner;
      } else {
        /* New IP — append row */
        const tr      = document.createElement('tr');
        tr.className  = 'tr-clickable';
        tr.dataset.ip = e.src_ip;
        tr.innerHTML  = inner;
        _qRows.set(e.src_ip, tr);
        tb.appendChild(tr);
      }
    });

    /* Remove empty-state placeholder if rows now exist */
    const placeholder = tb.querySelector('[colspan]');
    if (placeholder) placeholder.parentElement.remove();

  } catch (_) {}
}

/* POST release or blackhole action for an IP */
async function quarantineAction(action, ip) {
  try {
    await fetch(`${API}/api/quarantine/${action}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ src_ip: ip }),
    });
    showToast(action === 'release' ? `Released ${ip}` : `Blocked ${ip}`);
    fetchQuarantine();
  } catch (_) {
    showToast('Request failed', true);
  }
}