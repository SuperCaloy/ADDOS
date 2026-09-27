const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

function loadDashboardScope() {
  const dir = __dirname;
  const stubEl = () => ({
    addEventListener() {},
    classList: { add() {}, remove() {}, toggle() {} },
    appendChild() {},
    remove() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
  });
  const sandbox = {
    window: { addEventListener() {} },
    document: {
      getElementById() { return stubEl(); },
      querySelector() { return stubEl(); },
      querySelectorAll() { return []; },
      addEventListener() {},
      body: { classList: { toggle() {} } },
    },
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  for (const file of ['ui.js', 'log.js']) {
    const code = fs.readFileSync(path.join(dir, file), 'utf8');
    vm.runInContext(code, sandbox, { filename: file });
  }

  return sandbox;
}

test('renderAction renders Time Ban with duration inside yellow t-ban tag', () => {
  const sandbox = loadDashboardScope();
  const renderAction = sandbox.renderAction;

  assert.equal(
    renderAction('Time Ban (1m)'),
    '<span class="tag t-ban">Time Ban (1m)</span>'
  );
  assert.equal(
    renderAction('Time Ban (2m)'),
    '<span class="tag t-ban">Time Ban (2m)</span>'
  );
  assert.equal(
    renderAction('Time Ban 5m'),
    '<span class="tag t-ban">Time Ban 5m</span>'
  );
});

test('renderAction defaults plain Time Ban to Time Ban (1m) inside yellow t-ban tag', () => {
  const sandbox = loadDashboardScope();
  const renderAction = sandbox.renderAction;

  assert.equal(
    renderAction('Time Ban'),
    '<span class="tag t-ban">Time Ban (1m)</span>'
  );
});

test('renderAction preserves tags for other mitigation actions', () => {
  const sandbox = loadDashboardScope();
  const renderAction = sandbox.renderAction;

  assert.equal(renderAction('Quarantined'), '<span class="tag t-q">Quarantined</span>');
  assert.equal(renderAction('Rate Limited'), '<span class="tag t-rl">Rate Limited</span>');
  assert.equal(renderAction('Blackhole'), '<span class="tag t-blocked">Blackhole</span>');
  assert.equal(renderAction('Blocked'), '<span class="tag t-blocked">Blocked</span>');
  assert.equal(renderAction('Released'), '<span style="color:var(--sub2)">Released</span>');
  assert.equal(renderAction('-'), '<span style="color:var(--sub2)">-</span>');
});

test('_resolveActionLabel and _buildEventRowData consistently attach duration', () => {
  const sandbox = loadDashboardScope();
  const _resolveActionLabel = sandbox._resolveActionLabel;
  const _buildEventRowData = sandbox._buildEventRowData;

  // With duration in action string
  assert.equal(
    _resolveActionLabel('Time Ban (2m)', '10.0.0.1', null),
    'Time Ban (2m)'
  );

  // Subsequent event for same IP with bare Time Ban remembers 2m
  assert.equal(
    _resolveActionLabel('Time Ban', '10.0.0.1', null),
    'Time Ban (2m)'
  );

  // Fallback for new IP without known duration is 1m
  assert.equal(
    _resolveActionLabel('Time Ban', '10.0.0.99', null),
    'Time Ban (1m)'
  );

  // Row builder renders t-ban tag with duration
  const rowData = _buildEventRowData({
    timestamp: '2026-09-10 19:35:00',
    src_ip: '10.0.0.5',
    action_taken: 'Time Ban (3m)',
    predicted_class: 'DDoS',
    attack_vector: 'UDP Flood',
    confidence: '95.0%',
    priority: 'High',
  });

  assert.ok(rowData.html.includes('<span class="tag t-ban">Time Ban (3m)</span>'));
});

test('watchlist preserves peak IF score and confidence across lower polls', async () => {
  const dir = __dirname;
  const stub = () => ({
    innerHTML: '',
    querySelector() { return null; },
    querySelectorAll() { return []; },
    appendChild() {},
    remove() {},
    addEventListener() {},
    classList: { add() {}, remove() {}, toggle() {} },
    dataset: {},
    style: {},
  });
  const sandbox = {
    window: { addEventListener() {} },
    document: {
      getElementById() { return stub(); },
      querySelector() { return stub(); },
      querySelectorAll() { return []; },
      createElement() { return stub(); },
      addEventListener() {},
      body: { classList: { toggle() {} } },
    },
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  for (const file of ['ui.js', 'mitigation.js']) {
    const code = fs.readFileSync(path.join(dir, file), 'utf8');
    vm.runInContext(code, sandbox, { filename: file });
  }

  // Simulate first poll: high attack severity
  const data1 = [{
    src_ip: '10.0.0.88', phase: 2, phase_label: 'Time Ban',
    attack_vector: 'UDP Flood', if_score: 0.8842, confidence: 95.5,
    time_in_phase_sec: 15, ttl_remaining_sec: 105, priority: 'High',
  }];
  sandbox.apiFetch = async () => data1;
  await vm.runInContext('fetchQuarantine()', sandbox);

  const peaks = sandbox.window._watchlistPeaks;
  assert.ok(peaks && peaks.has('10.0.0.88'));
  assert.equal(peaks.get('10.0.0.88').sc, 0.8842);
  assert.equal(peaks.get('10.0.0.88').conf, 95.5);

  // Simulate second poll: traffic calms and backend reports lower / decayed values
  const data2 = [{
    src_ip: '10.0.0.88', phase: 2, phase_label: 'Time Ban',
    attack_vector: 'UDP Flood', if_score: 0.4120, confidence: 65.0,
    time_in_phase_sec: 30, ttl_remaining_sec: 90, priority: 'High',
  }];
  sandbox.apiFetch = async () => data2;
  await vm.runInContext('fetchQuarantine()', sandbox);

  // Watchlist retains peak values
  assert.equal(peaks.get('10.0.0.88').sc, 0.8842);
  assert.equal(peaks.get('10.0.0.88').conf, 95.5);
});

test('audit row key scopes to session so re-attacks get fresh rows', () => {
  const sandbox = loadDashboardScope();
  const base = {
    timestamp: '2026-09-27 10:00:00',
    src_ip: '10.0.0.5',
    action_taken: 'Quarantined',
    predicted_class: 'attack',
    attack_vector: 'SYN Flood',
    confidence: '90.0%',
    priority: 'High',
    event_type: 'transition',
  };
  const a = sandbox._buildEventRowData({ ...base, session_id: 'sess-1' });
  const b = sandbox._buildEventRowData({ ...base, session_id: 'sess-2' });
  const c = sandbox._buildEventRowData({ ...base, session_id: 'sess-1' });
  assert.notEqual(a.key, b.key);
  assert.equal(a.key, c.key);
  assert.equal(a.sessionId, 'sess-1');
});

test('audit rows without session keep legacy ip plus event key', () => {
  const sandbox = loadDashboardScope();
  const row = sandbox._buildEventRowData({
    timestamp: '2026-09-27 10:00:00',
    src_ip: '10.0.0.5',
    action_taken: 'Quarantined',
    predicted_class: 'attack',
    attack_vector: 'SYN Flood',
    confidence: '90.0%',
    priority: 'High',
    event_type: 'transition',
  });
  assert.equal(row.key, '10.0.0.5|transition');
});

