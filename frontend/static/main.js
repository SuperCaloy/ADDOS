fetchStats();
fetchModelInfo();
fetchQuarantine();
fetchRecentEvents();

/* ── SSE live event stream ─────────────────────────────────────────────────── */
connectSSE();

/* ── Polling intervals ─────────────────────────────────────────────────────── */
setInterval(fetchStats,      POLL_MS);   /* stats cards + chart — every 5s */
setInterval(fetchQuarantine, POLL_MS);   /* watchlist table    — every 5s */

/* ── Row-click delegation ──────────────────────────────────────────────────── */
/* Single listener per tbody — survives innerHTML updates, skips button clicks */
(function _attachRowDelegation() {
  ['log-body', 'q-body'].forEach(tbId => {
    const tb = document.getElementById(tbId);
    if (!tb) return;
    tb.addEventListener('click', function (e) {
      if (e.target.closest('button, a')) return;
      const tr = e.target.closest('tr[data-ip]');
      if (!tr) return;
      const ip = tr.dataset.ip;
      if (ip && ip !== '—') window.openIpDrawer(ip);
    });
  });
})();