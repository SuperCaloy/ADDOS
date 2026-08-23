fetchStats();
fetchModelInfo();
fetchQuarantine();
fetchRecentEvents();

/* ── SSE live event stream ─────────────────────────────────────────────────── */
connectSSE();

/* ── Polling intervals ─────────────────────────────────────────────────────── */
setInterval(fetchStats,      POLL_MS);   /* stats cards + chart — every 2s */
setInterval(fetchQuarantine, POLL_MS);   /* watchlist table    — every 2s */

/* ── Row-click delegation ──────────────────────────────────────────────────── */
/* Single listener per tbody — survives innerHTML updates, skips button clicks */
(function _attachRowDelegation() {
  ['log-body', 'q-body'].forEach(tbId => {
    const tb = document.getElementById(tbId);
    if (!tb) return;

    /* Click */
    tb.addEventListener('click', function (e) {
      if (e.target.closest('button, a')) return;
      const tr = e.target.closest('tr[data-ip]');
      if (!tr) return;
      const ip = tr.dataset.ip;
      if (ip && ip !== '—') window.openIpDrawer(ip);
    });

    /* Keyboard: Enter or Space activates focused row */
    tb.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      if (e.target.closest('button, a')) return;
      const tr = e.target.closest('tr[data-ip]');
      if (!tr) return;
      e.preventDefault();
      const ip = tr.dataset.ip;
      if (ip && ip !== '—') window.openIpDrawer(ip);
    });

    /* MutationObserver — stamp tabindex="0" on every new tr[data-ip] */
    const _stampTabindex = (mutations) => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
          /* The added node itself may be a tr, or may contain trs */
          const rows = node.matches?.('tr[data-ip]')
            ? [node]
            : [...(node.querySelectorAll?.('tr[data-ip]') || [])];
          rows.forEach(tr => {
            if (!tr.hasAttribute('tabindex')) tr.setAttribute('tabindex', '0');
          });
        });
      });
    };

    new MutationObserver(_stampTabindex).observe(tb, { childList: true, subtree: true });
  });
})();