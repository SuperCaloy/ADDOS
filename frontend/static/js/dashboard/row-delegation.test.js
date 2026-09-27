/**
 * Delegation tests: watchlist rows open the live drawer, audit rows open
 * the session-addressed historical drawer. Run:
 * node --test frontend/static/js/dashboard/
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

function loadMain() {
  const dir = __dirname;
  const listeners = {};
  const tbStub = id => ({
    addEventListener(evt, fn) { listeners[id + ':' + evt] = fn; },
  });
  const sandbox = {
    window: {},
    document: {
      getElementById(id) { return tbStub(id); },
      addEventListener() {},
    },
    MutationObserver: class { constructor() {} observe() {} },
    setInterval() { return 0; },
    POLL_MS: 2000,
    fetchStats() {},
    fetchModelInfo() {},
    fetchQuarantine() {},
    fetchRecentEvents() {},
    fetchSystemMetrics() {},
    pollModelInfo() {},
    connectSSE() {},
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  const code = fs.readFileSync(path.join(dir, 'main.js'), 'utf8');
  vm.runInContext(code, sandbox, { filename: 'main.js' });
  return { sandbox, listeners };
}

function clickOn(listeners, tbId, dataset) {
  const tr = { dataset };
  const calls = [];
  const e = {
    target: {
      closest(sel) {
        if (sel === 'button, a') return null;
        if (sel === 'tr[data-ip]') return tr;
        return null;
      },
    },
  };
  return { tr, e };
}

test('watchlist row opens live drawer with no historical flag', () => {
  const { sandbox, listeners } = loadMain();
  const calls = [];
  sandbox.window.openIpDrawer = (ip, opts) => calls.push([ip, opts]);
  const { e } = clickOn(listeners, 'q-body', { ip: '10.0.0.9' });
  listeners['q-body:click'](e);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '10.0.0.9');
  assert.equal(calls[0][1], undefined);
});

test('audit row opens session-addressed historical drawer', () => {
  const { sandbox, listeners } = loadMain();
  const calls = [];
  sandbox.window.openIpDrawer = (ip, opts) => calls.push([ip, opts]);
  const { e } = clickOn(listeners, 'log-body', {
    ip: '10.0.0.5',
    sessionId: 'sess-OLD',
    timestamp: '2026-09-21 09:00:00',
    isRelease: 'false',
  });
  listeners['log-body:click'](e);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '10.0.0.5');
  assert.equal(calls[0][1].historical, true);
  assert.equal(calls[0][1].sessionId, 'sess-OLD');
  assert.equal(calls[0][1].timestamp, '2026-09-21 09:00:00');
});
