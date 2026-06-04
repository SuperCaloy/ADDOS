const API     = window.API_URL;
const POLL_MS = window.POLL_MS || 2000;
const MAX_PTS = window.MAX_PTS || 30;
const MAX_LOG = window.MAX_LOG || 100;

/* GET JSON from backend — throws on error */
async function apiFetch(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw r;
  return r.json();
}
