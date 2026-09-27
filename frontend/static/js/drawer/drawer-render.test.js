/**
 * Integration test for _renderFeatureSignals wiring in ip-drawer.js.
 * Stub DOM, real signal config. Run with the signals test:
 * node --test frontend/static/js/drawer/
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

function loadDrawer() {
  const dir = __dirname;
  const sandbox = {
    window: {},
    document: { addEventListener() {} },
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  for (const file of ['drawer-signals.js', 'attack-context.js', 'ip-drawer.js']) {
    vm.runInContext(fs.readFileSync(path.join(dir, file), 'utf8'), sandbox, { filename: file });
  }
  vm.runInContext(
    ';globalThis.__drawerTest = {'
    + ' _renderFeatureSignals: (typeof _renderFeatureSignals !== "undefined" ? _renderFeatureSignals : undefined),'
    + ' _livePollPlan: (typeof _livePollPlan !== "undefined" ? _livePollPlan : undefined),'
    + ' _releaseTime: (typeof _releaseTime !== "undefined" ? _releaseTime : undefined),'
    + ' _applyPeakMl: (typeof _applyPeakMl !== "undefined" ? _applyPeakMl : undefined),'
    + ' _ipDetailQuery: (typeof _ipDetailQuery !== "undefined" ? _ipDetailQuery : undefined),'
    + ' _setBadge: (typeof _setBadge !== "undefined" ? _setBadge : undefined) };',
    sandbox
  );
  return sandbox;
}

function renderWith(features, attackClass, deviations) {
  const sandbox = loadDrawer();
  const capture = {};
  const el = id => ({
    get innerHTML() { return capture[id] || ''; },
    set innerHTML(v) { capture[id] = v; },
    textContent: '',
    style: {},
  });
  const els = {
    'idd-if-subtitle': el('idd-if-subtitle'),
    'idd-rf-subtitle': el('idd-rf-subtitle'),
    'idd-if-features': el('idd-if-features'),
    'idd-rf-features': el('idd-rf-features'),
  };
  sandbox.document.getElementById = id => els[id] || null;
  vm.runInContext(
    `_renderFeatureSignals(${JSON.stringify(features)}, ${JSON.stringify(attackClass)}, ${JSON.stringify(deviations || null)})`,
    sandbox
  );
  return { capture, els };
}

const floodFeatures = {
  pps: 22600, byte_rate: 33800, byte_count: 17825792, pkt_count: 11665,
  port_entropy: 1.0, pkt_size_uniformity: 0.01, flow_intensity: 15.2,
  bytes_per_duration: 90000, duration_sec: 198,
};

test('UDP Flood renders 4 IF and 4 RF cards plus section notes', () => {
  const { capture, els } = renderWith(floodFeatures, 'UDP Flood');
  const ifCards = (capture['idd-if-features'].match(/idd-fc/g) || []).length;
  const rfCards = (capture['idd-rf-features'].match(/idd-fc/g) || []).length;
  assert.equal(ifCards, 4);
  assert.equal(rfCards, 4);
  assert.ok(capture['idd-if-features'].includes('Top signal'));
  assert.ok(capture['idd-rf-features'].includes('Top signal'));
  assert.ok(!capture['idd-if-features'].includes('vs '));
  assert.ok(!capture['idd-rf-features'].includes('vs '));
  assert.ok(els['idd-if-subtitle'].textContent.includes('UDP Flood'));
});

test('Uncertain renders placeholder instead of a fake fourth signal', () => {
  const { capture } = renderWith({ pps: 10, byte_rate: 100, byte_count: 500, pkt_count: 5 }, 'Uncertain');
  assert.ok(capture['idd-if-features'].includes('No further distinguishing signal'));
  assert.ok(capture['idd-rf-features'].includes('No further distinguishing signal'));
});

test('calm traffic reports closest to baseline, never flagged', () => {
  const calm = { pps: 10, byte_rate: 100, byte_count: 500, pkt_count: 5, pkt_size_uniformity: 0.4 };
  const { capture } = renderWith(calm, 'SYN Flood');
  assert.ok(capture['idd-if-features'].includes('Closest to display baseline'));
  assert.ok(!capture['idd-if-features'].includes('Top signal:'));
});

test('Top signal follows served deviations, not raw magnitudes', () => {
  const devs = {
    pps: 0.5, byte_rate: 9.1, bpp: 0.2, pkt_count: 0.3,
    byte_count: 0.4, port_entropy: 0.1, flow_intensity: 0.2, bytes_per_duration: 0.3,
  };
  const { capture } = renderWith(floodFeatures, 'UDP Flood', devs);
  assert.ok(capture['idd-if-features'].includes('Top signal: Byte Rate'));
  assert.ok(!capture['idd-if-features'].includes('vs '));
});

test('poll plan keeps fast polling through transient misses', () => {
  const sandbox = loadDrawer();
  const plan = vm.runInContext(
    'globalThis.__drawerTest._livePollPlan(0, false) && JSON.stringify(globalThis.__drawerTest._livePollPlan(2, false))',
    sandbox
  );
  assert.equal(JSON.parse(plan).intervalMs, 2000);
});

test('poll plan slows down after repeated misses but never gives up on errors', () => {
  const sandbox = loadDrawer();
  const get = n => JSON.parse(vm.runInContext(
    `JSON.stringify(globalThis.__drawerTest._livePollPlan(${n}, false))`, sandbox));
  assert.equal(get(3).intervalMs, 30000);
  assert.equal(get(50).intervalMs, 30000);
  assert.ok(!('stop' in get(50)));
});

test('poll plan stops only on explicit inactive', () => {
  const sandbox = loadDrawer();
  const plan = JSON.parse(vm.runInContext(
    'JSON.stringify(globalThis.__drawerTest._livePollPlan(0, true))', sandbox));
  assert.equal(plan.stop, 'historical');
});

test('badge stamps update time and stale verdicts', () => {
  const sandbox = loadDrawer();
  let html = '';
  sandbox.document.getElementById = () => ({
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; },
  });
  vm.runInContext(
    'globalThis.__drawerTest._setBadge(true, { updated: "18:13:32", stale: true })',
    sandbox
  );
  assert.ok(html.includes('LIVE'));
  assert.ok(html.includes('18:13:32'));
  assert.ok(html.includes('STALE'));
});

test('badge renders historical with release timestamp when provided', () => {
  const sandbox = loadDrawer();
  let html = '';
  sandbox.document.getElementById = () => ({
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; },
  });
  vm.runInContext(
    'globalThis.__drawerTest._setBadge(false, { releasedAt: "18:00:00" })',
    sandbox
  );
  assert.ok(html.includes('HISTORICAL'));
  assert.ok(html.includes('as released at 18:00:00'));
});

test('badge renders historical without label when releasedAt is missing', () => {
  const sandbox = loadDrawer();
  let html = '';
  sandbox.document.getElementById = () => ({
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; },
  });
  vm.runInContext(
    'globalThis.__drawerTest._setBadge(false)',
    sandbox
  );
  assert.ok(html.includes('HISTORICAL'));
  assert.ok(!html.includes('as released at'));
});

test('releaseTime extracts HH:MM:SS from date strings', () => {
  const sandbox = loadDrawer();
  const res1 = vm.runInContext('globalThis.__drawerTest._releaseTime("2026-09-10 18:00:00")', sandbox);
  const res2 = vm.runInContext('globalThis.__drawerTest._releaseTime("18:00:00")', sandbox);
  const res3 = vm.runInContext('globalThis.__drawerTest._releaseTime(null)', sandbox);
  assert.equal(res1, '18:00:00');
  assert.equal(res2, '18:00:00');
  assert.equal(res3, '');
});

test('_applyPeakMl retains peak IF score and RF confidence when subsequent polls are lower', () => {
  const sandbox = loadDrawer();
  const applyPeak = vm.runInContext('globalThis.__drawerTest._applyPeakMl', sandbox);
  const ip = '10.0.0.99';

  // Initial peak attack
  const ml1 = { if_score: 0.89, confidence: 95.5, attack_class: 'UDP Flood' };
  const res1 = applyPeak(ip, ml1);
  assert.equal(res1.if_score, 0.89);
  assert.equal(res1.confidence, 95.5);
  assert.equal(res1.attack_class, 'UDP Flood');

  // Traffic calms or drops post-mitigation
  const ml2 = { if_score: 0.35, confidence: 65.0, attack_class: 'Normal' };
  const res2 = applyPeak(ip, ml2);
  assert.equal(res2.if_score, 0.89);
  assert.equal(res2.confidence, 95.5);
  assert.equal(res2.attack_class, 'UDP Flood');

  // Higher score arrives later
  const ml3 = { if_score: 0.94, confidence: 98.2, attack_class: 'UDP Flood' };
  const res3 = applyPeak(ip, ml3);
  assert.equal(res3.if_score, 0.94);
  assert.equal(res3.confidence, 98.2);
});

test('_ipDetailQuery builds live, historical, and session queries', () => {
  const sandbox = loadDrawer();
  const buildQuery = vm.runInContext('globalThis.__drawerTest._ipDetailQuery', sandbox);
  assert.equal(typeof buildQuery, 'function');
  assert.equal(buildQuery({}), '');
  assert.equal(buildQuery({ historical: true }), '?historical=1');
  assert.equal(
    buildQuery({ historical: true, sessionId: 'sess-OLD', timestamp: '2026-09-21 09:00:00' }),
    '?historical=1&session_id=sess-OLD&timestamp=2026-09-21%2009%3A00%3A00'
  );
});


