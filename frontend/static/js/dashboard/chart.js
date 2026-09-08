// Time-series traffic chart controller visualizing incoming, blocked, and forwarded packet rates.
// Supports real-time delta plotting and adaptive polling for historical data aggregation.

// Current time-series range view: Live streaming or historical aggregate window.
let range = 'Live';

// Instantiates the Chart.js line chart and registers it globally for theme color synchronization.
// Configures multi-line datasets for incoming, blocked, and forwarded traffic with custom tooltip formatters.
window._chart = new Chart(document.getElementById('chart').getContext('2d'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'Incoming',  data: [], borderColor: '#3d6cff', backgroundColor: 'rgba(61,108,255,.07)', borderWidth: 2, pointRadius: 0, fill: true,  tension: .4 },
      { label: 'Blocked',   data: [], borderColor: '#ff3d5a', backgroundColor: 'rgba(255,61,90,.10)',  borderWidth: 2, pointRadius: 0, fill: true,  tension: .4, borderDash: [5,3] },
      { label: 'Forwarded', data: [], borderColor: '#00d68f', backgroundColor: 'rgba(0,214,143,.05)',  borderWidth: 2, pointRadius: 0, fill: false, tension: .4 },
    ],
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: { duration: 180 },
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: {
        labels: {
          color: '#5c6080',
          font: { family: "'Fira Code', monospace", size: 10 },
          boxWidth: 12,
          usePointStyle: true,
          pointStyle: 'circle',
        },
      },
      tooltip: {
        backgroundColor: '#111320', borderColor: '#1e2235', borderWidth: 1,
        titleColor: '#8890b0', bodyColor: '#e8eaf6',
        titleFont: { family: "'Fira Code', monospace", size: 10 },
        bodyFont:  { family: "'Fira Code', monospace", size: 11 },
        callbacks: {
          labelColor: function (context) {
            const clr = context.dataset.borderColor || '#5c6080';
            return { borderColor: clr, backgroundColor: clr, borderWidth: 2, borderRadius: 2 };
          },
        },
      },
    },
    scales: {
      x: { ticks: { color: '#5c6080', font: { family: "'Fira Code', monospace", size: 11 }, maxRotation: 0 }, grid: { color: '#1e2235' } },
      y: { ticks: { color: '#5c6080', font: { family: "'Fira Code', monospace", size: 11 } }, grid: { color: '#1e2235' }, beginAtZero: true },
    },
  },
});

// Appends an interval traffic measurement to the chart and shifts the oldest entry when exceeding buffer size.
// Discards live incoming points while the user is viewing historical windows to prevent data mixing.
function pushChartPoint(label, di, db, df) {
  if (range !== 'Live') return;

  const d = window._chart.data;
  d.labels.push(label);
  d.datasets[0].data.push(di);
  d.datasets[1].data.push(db);
  d.datasets[2].data.push(df);
  if (d.labels.length > MAX_PTS) {
    d.labels.shift();
    d.datasets.forEach(ds => ds.data.shift());
  }
  window._chart.update('none');
}

// Queries aggregate historical traffic bucket statistics from the backend and updates chart series.
// Populates time-series points across the selected retrospective interval.
async function fetchHistory(r) {
  try {
    const buckets      = await apiFetch(`/api/graph_history?range=${r}`);
    const d            = window._chart.data;
    d.labels           = buckets.map(b => b.timestamp.slice(11, 16));
    d.datasets[0].data = buckets.map(b => b.incoming  || 0);
    d.datasets[1].data = buckets.map(b => b.blocked   || 0);
    d.datasets[2].data = buckets.map(b => b.forwarded || 0);
    window._chart.update();
  } catch (_) {}
}

let _historyTimer = null;

// Handles user range tab selections between real-time streaming and historical windows.
// Adjusts background polling frequency according to the selected time horizon.
document.getElementById('rtabs').addEventListener('click', e => {
  const btn = e.target.closest('.rt');
  if (!btn) return;
  document.querySelectorAll('.rt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  range = btn.dataset.r;
  if (window.Store) window.Store.setChartRange(range);
  
  if (_historyTimer) {
    clearInterval(_historyTimer);
    _historyTimer = null;
  }
  
  if (range !== 'Live') {
    fetchHistory(range);
    
    let intervalMs = 10000;
    if (range === '1h') intervalMs = 30000;
    else if (range === '24h') intervalMs = 300000;
    else if (range === '7d') intervalMs = 1800000;
    
    _historyTimer = setInterval(() => {
      if (range !== 'Live') fetchHistory(range);
    }, intervalMs);
  } else {
    const d = window._chart.data;
    d.labels = [];
    d.datasets.forEach(ds => ds.data = []);
    window._chart.update();
  }
});