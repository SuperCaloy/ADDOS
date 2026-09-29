// Watchlist controller managing active quarantine table rendering, DOM diffing, and manual enforcement actions.
// Tracks IP state transitions and presents confirmation modals for release and blackhole overrides.

// Active table row cache indexed by source IP and pending action confirmation callback.
const _qRows = new Map();
let _confirmCallback = null;

// Displays an action confirmation modal dialog with customized prompt text and execution callback.
function openConfirmModal(title, message, callback) {
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-message').textContent = message;
  _confirmCallback = callback;
  document.getElementById('confirm-modal').classList.add('open');
}

// Dismisses the confirmation modal dialog and clears pending action state.
function closeConfirmModal() {
  document.getElementById('confirm-modal').classList.remove('open');
  _confirmCallback = null;
}

// Executes the queued confirmation callback and closes the modal dialog.
function confirmAction() {
  if (_confirmCallback) _confirmCallback();
  closeConfirmModal();
}

// Polls active quarantine list from the backend and updates watchlist table rows in-place.
// Performs surgical DOM updates without full table replacement to prevent visual flickering.
async function fetchQuarantine() {
  try {
    const data = await apiFetch('/api/quarantine_list');
    set('q-ct', `${data.length} IP${data.length !== 1 ? 's' : ''}`);
    const tb = document.getElementById('q-body');

    if (!data.length) {
      _qRows.clear();
      tb.innerHTML = `<tr><td colspan="7" class="q-empty">No IPs currently under active mitigation.</td></tr>`;
      return;
    }

    const activeIps = new Set(data.map(e => e.src_ip));
    for (const [ip, tr] of _qRows) {
      if (!activeIps.has(ip)) {
        tr.remove();
        _qRows.delete(ip);
        if (window._watchlistPeaks) window._watchlistPeaks.delete(ip);
      }
    }

    window._activeBanDurations = window._activeBanDurations || new Map();
    window._watchlistPeaks = window._watchlistPeaks || new Map();
    data.forEach(e => {
      if (e.src_ip && /time\s*ban/i.test(e.phase_label || e.phase || '')) {
        const ttl = e.ttl_remaining_sec != null ? e.ttl_remaining_sec : 0;
        const tip = e.time_in_phase_sec != null ? e.time_in_phase_sec : 0;
        const total = ttl + tip;
        if (total > 0) {
          const mins = Math.max(1, Math.round(total / 60));
          window._activeBanDurations.set(e.src_ip, `${mins}m`);
        }
      }

      const rawSc   = Number(e.if_score) || 0;
      const rawConf = e.confidence != null ? Number(e.confidence) : null;
      let sc = rawSc;
      let confNum = rawConf;

      if (e.src_ip) {
        const prior = window._watchlistPeaks.get(e.src_ip) || { sc: 0, conf: 0 };
        sc = Math.max(prior.sc, rawSc);
        confNum = rawConf != null ? Math.max(prior.conf, rawConf) : prior.conf;
        window._watchlistPeaks.set(e.src_ip, { sc, conf: confNum });
      }

      const ts   = e.time_in_phase_sec || 0;
      const conf = confNum != null ? confNum.toFixed(4) : '--';
      const time = ts < 60 ? `${ts}s` : `${Math.floor(ts / 60)}m ${ts % 60}s`;

      const currentThr = window.Store ? window.Store.getIfThreshold() : ifThr;
      const scCls = !currentThr           ? 'mono'
                  : sc >= currentThr * 1.2 ? 'sc-red'
                  : sc >= currentThr       ? 'sc-amb'
                  : 'sc-grn';

      // Every phase always shows a bracketed time: the TTL countdown when the
      // backend provides one, otherwise the elapsed time in phase (permanent
      // blackholes have no TTL, but time_in_phase_sec is always present).
      const ttlSec = e.ttl_remaining_sec != null ? e.ttl_remaining_sec : ts;
      const ttlRemaining = ` <span style="color:var(--amber,#ffb300);font-size:11px;font-family:var(--mono)">[${Math.floor(ttlSec/60)}m ${ttlSec%60}s]</span>`;

      const priBadge = renderPriority(e.priority);
      // Phase 0 (sinkhole) is falsy in JS, so a bare `||` chain renders it
      // as '--'. Handle it explicitly; the backend always sends phase_label.
      const phaseDisplay = e.phase_label || (e.phase === 0 ? 'Sinkhole' : (e.phase || '--'));

      const inner = `
        <td class="ip">${e.src_ip || '--'}</td>
        <td>${priBadge}</td>
        <td style="color:var(--sub2);font-size:13px">${phaseDisplay}${ttlRemaining}</td>
        <td>${renderVector(e.attack_vector || '--')}</td>
        <td class="${scCls}">${sc.toFixed(4)}</td>
        <td class="mono">${conf}</td>
        <td style="color:var(--sub2);font-family:var(--mono);font-size:12px">${time}</td>
        <td><div style="display:flex;gap:6px">
          <button class="q-btn q-rel" onclick="event.stopPropagation();confirmQuarantineAction('release','${e.src_ip}')">Release</button>
          <button class="q-btn q-blk" onclick="event.stopPropagation();confirmQuarantineAction('block','${e.src_ip}')">Blackhole</button>
        </div></td>`;

      if (_qRows.has(e.src_ip)) {
        const existing     = _qRows.get(e.src_ip);
        existing.dataset.ip = e.src_ip;
        existing.dataset.isRelease = 'false';
        existing.innerHTML  = inner;
      } else {
        const tr      = document.createElement('tr');
        tr.className  = 'tr-clickable';
        tr.dataset.ip = e.src_ip;
        tr.dataset.isRelease = 'false';
        tr.innerHTML  = inner;
        _qRows.set(e.src_ip, tr);
        tb.appendChild(tr);
      }
    });

    const placeholder = tb.querySelector('[colspan]');
    if (placeholder) placeholder.parentElement.remove();

  } catch (_) {}
}

// Configures and displays the confirmation modal before executing a manual release or blackhole override.
function confirmQuarantineAction(action, ip) {
  const title = action === 'release' ? 'Release IP' : 'Blackhole IP';
  const msg = action === 'release'
    ? `Are you sure you want to release ${ip}?`
    : `Are you sure you want to blackhole ${ip}?`;
  const btnText = action === 'release' ? 'Release' : 'Blackhole';

  const btn = document.getElementById('confirm-btn');
  btn.textContent = btnText;
  btn.className = action === 'release' ? 'btn-primary' : 'btn-primary';
  btn.style.background = action === 'release' ? 'var(--green)' : 'var(--red)';

  openConfirmModal(title, msg, () => quarantineAction(action, ip));
}

// Sends a manual mitigation release or blackhole POST command to the backend and triggers immediate watchlist refresh.
async function quarantineAction(action, ip) {
  try {
    await apiFetch(`/api/quarantine/${action}`, {
      method: 'POST',
      body:   { src_ip: ip },
    });
    showToast(action === 'release' ? `Released ${ip}` : `Blocked ${ip}`);
    fetchQuarantine();
  } catch (_) {
    showToast('Request failed', true);
  }
}

