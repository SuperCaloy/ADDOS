// Application bootstrap script initializing telemetry feeds, polling timers, and event delegation.
// Orchestrates dashboard startup across metric cards, audit tables, and interactive drawers.

// Triggers initial data queries on script execution to populate dashboard state prior to timer intervals.
fetchStats();
fetchModelInfo();
fetchQuarantine();
fetchRecentEvents();
fetchSystemMetrics();

// Initializes live streaming connection and schedules periodic background polling for metrics and tables.
connectSSE();
setInterval(fetchStats,         POLL_MS);
setInterval(fetchQuarantine,    POLL_MS);
setInterval(fetchSystemMetrics, 1000);
setInterval(pollModelInfo,      1000);

// Resets rate delta calculations when returning from an inactive browser tab.
// Prevents interval throttling from causing artificial traffic spikes in the live chart.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') _resetPrev = true;
});

// Attaches delegated click and keyboard listeners to watchlist and audit log tables.
// Opens the threat analysis drawer when selecting an incident row while ignoring direct button clicks.
(function _attachRowDelegation() {
  ['log-body', 'q-body'].forEach(tbId => {
    const tb = document.getElementById(tbId);
    if (!tb) return;

    // Dispatches click events on table rows to open the IP threat analysis drawer.
    tb.addEventListener('click', function (e) {
      if (e.target.closest('button, a')) return;
      const tr = e.target.closest('tr[data-ip]');
      if (!tr) return;
      const ip = tr.dataset.ip;
      if (ip && ip !== '--') window.openIpDrawer(ip);
    });

    // Enables keyboard activation using Enter or Space on focused table rows.
    tb.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      if (e.target.closest('button, a')) return;
      const tr = e.target.closest('tr[data-ip]');
      if (!tr) return;
      e.preventDefault();
      const ip = tr.dataset.ip;
      if (ip && ip !== '--') window.openIpDrawer(ip);
    });

    // Observes dynamic DOM insertions in table bodies to ensure newly rendered rows receive keyboard focus attributes.
    const _stampTabindex = (mutations) => {
      mutations.forEach(m => {
        m.addedNodes.forEach(node => {
          if (node.nodeType !== 1) return;
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