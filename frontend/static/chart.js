/* chart.js — live traffic chart init, push, history fetch, range tabs
 * Exposes window._chart so theme toggle in ui.js can update chart colors. */

/* Current active range tab — 'Live' or a history range string */
let range = 'Live';

/* Init Chart.js line chart — stored on window so ui.js theme toggle can reach it */
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
      legend: { labels: { color: '#5c6080', font: { family: 'Space Mono', size: 10 }, boxWidth: 12 } },
      tooltip: {
        backgroundColor: '#111320', borderColor: '#1e2235', borderWidth: 1,
        titleColor: '#8890b0', bodyColor: '#e8eaf6',
        titleFont: { family: 'Space Mono', size: 10 },
        bodyFont:  { family: 'Space Mono', size: 11 },
      },
    },
    scales: {
      x: { ticks: { color: '#5c6080', font: { family: 'Space Mono', size: 9 }, maxRotation: 0 }, grid: { color: '#1e2235' } },
      y: { ticks: { color: '#5c6080', font: { family: 'Space Mono', size: 9 } }, grid: { color: '#1e2235' }, beginAtZero: true },
    },
  },
});

/* Append one data point, shift oldest when buffer is full */
function pushChartPoint(label, di, db, df) {
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

/* Replace chart with historical bucket data from /api/graph_history */
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

/* Range tab clicks — switch between Live and historical views */
document.getElementById('rtabs').addEventListener('click', e => {
  const btn = e.target.closest('.rt');
  if (!btn) return;
  document.querySelectorAll('.rt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  range = btn.dataset.r;
  if (range !== 'Live') fetchHistory(range);
});