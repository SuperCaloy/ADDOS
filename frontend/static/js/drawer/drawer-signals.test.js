/**
 * RED tests for dynamic 4-card threat signal grids.
 * Plan: notes/tasks/dynamic-threat-signal-cards-plan.md
 * Run: node --test frontend/static/js/drawer/drawer-signals.test.js
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Loads drawer-signals.js dependency free with a window stub.
// The file only touches `window` at the bottom, so this is faithful.
function loadSignals() {
  globalThis.window = globalThis.window || {};
  const src = fs.readFileSync(path.join(__dirname, 'drawer-signals.js'), 'utf8');
  vm.runInThisContext(
    src + '\n;globalThis.__sigTest = {'
    + ' _SIGNAL_CONFIG: (typeof _SIGNAL_CONFIG !== "undefined" ? _SIGNAL_CONFIG : undefined),'
    + ' _mkSignalCard: (typeof _mkSignalCard !== "undefined" ? _mkSignalCard : undefined),'
    + ' _pickTopSignal: (typeof _pickTopSignal !== "undefined" ? _pickTopSignal : undefined) };',
    { filename: 'drawer-signals.js' }
  );
  return globalThis.__sigTest;
}

const sig = loadSignals();

const REAL_KEYS = ['ICMP Flood', 'SYN Flood', 'UDP Flood', 'Anomalous'];

test('each attack key shows 4 IF and 4 RF signal entries', () => {
  for (const key of REAL_KEYS) {
    assert.equal(sig._SIGNAL_CONFIG[key].if.length, 4, `${key} IF count`);
    assert.equal(sig._SIGNAL_CONFIG[key].rf.length, 4, `${key} RF count`);
  }
});

test('every real entry has an attack specific tip', () => {
  for (const key of REAL_KEYS) {
    for (const section of ['if', 'rf']) {
      for (const feat of sig._SIGNAL_CONFIG[key][section]) {
        assert.ok(typeof feat.key === 'string' && feat.key.length > 0, `${key}/${section} key`);
        assert.ok(typeof feat.tip === 'string' && feat.tip.length > 0, `${key}/${section}/${feat.key} tip`);
        assert.equal(typeof feat.alert, 'function', `${key}/${section}/${feat.key} alert`);
        assert.equal(typeof feat.bar, 'function', `${key}/${section}/${feat.key} bar`);
      }
    }
  }
});

test('locked 4th signals match the plan matrix', () => {
  const keys = cfg => cfg.map(f => f.key);
  assert.ok(keys(sig._SIGNAL_CONFIG['ICMP Flood'].if).includes('pkt_size_uniformity'));
  assert.ok(keys(sig._SIGNAL_CONFIG['SYN Flood'].if).includes('flow_intensity'));
  assert.ok(keys(sig._SIGNAL_CONFIG['UDP Flood'].if).includes('bpp'));
  assert.ok(keys(sig._SIGNAL_CONFIG['ICMP Flood'].rf).includes('pps'));
  assert.ok(keys(sig._SIGNAL_CONFIG['SYN Flood'].rf).includes('pkt_size_uniformity'));
  assert.ok(keys(sig._SIGNAL_CONFIG['UDP Flood'].rf).includes('port_entropy'));
});

test('Uncertain shows 3 real cards plus one honest placeholder', () => {
  const cfg = sig._SIGNAL_CONFIG['Uncertain'];
  assert.equal(cfg.if.length, 4);
  assert.equal(cfg.rf.length, 4);
  const ifPlaceholder = cfg.if.filter(f => f.placeholder);
  const rfPlaceholder = cfg.rf.filter(f => f.placeholder);
  assert.equal(ifPlaceholder.length, 1);
  assert.equal(rfPlaceholder.length, 1);
  assert.equal(ifPlaceholder[0].alert(1e12), false);
  assert.equal(rfPlaceholder[0].alert(1e12), false);
});

test('new display baselines behave', () => {
  const synIf = sig._SIGNAL_CONFIG['SYN Flood'].if;
  const flowIntensity = synIf.find(f => f.key === 'flow_intensity');
  assert.equal(flowIntensity.alert(0), false);
  assert.equal(flowIntensity.alert(1e12), true);
  assert.ok(flowIntensity.bar(1e12) <= 1);
  assert.ok(flowIntensity.bar(0) >= 0);
});

test('_pickTopSignal ranks alerted cards by bar value', () => {
  const entries = [
    { key: 'a', alert: () => true, bar: () => 0.2 },
    { key: 'b', alert: () => true, bar: () => 0.9 },
    { key: 'c', alert: () => false, bar: () => 1.0 },
  ];
  const top = sig._pickTopSignal(entries, {});
  assert.equal(top.key, 'b');
  assert.equal(top.flagged, true);
});

test('_pickTopSignal reports closest to baseline when nothing alerts', () => {
  const entries = [
    { key: 'a', alert: () => false, bar: () => 0.2 },
    { key: 'b', alert: () => false, bar: () => 0.7 },
  ];
  const top = sig._pickTopSignal(entries, {});
  assert.equal(top.key, 'b');
  assert.equal(top.flagged, false);
});

test('signal card shows Top tag when leading and no baseline comparison text', () => {
  const feat = {
    key: 'pps', label: 'Flow Rate (pps)',
    fmt: v => `${v} pkt/s`,
    alert: () => true, bar: () => 0.9,
    tip: 'Attack specific tip.',
  };
  const html = sig._mkSignalCard(feat, 22600, true, { top: true });
  assert.ok(html.includes('22,600') || html.includes('22600'));
  assert.ok(html.includes('Top signal'));
  assert.ok(!html.includes('vs '));
  assert.ok(!html.includes('baseline'));
});

test('signal card shows no why line and no Top tag when calm', () => {
  const feat = {
    key: 'pps', label: 'Flow Rate (pps)',
    fmt: v => `${v} pkt/s`,
    alert: () => false, bar: () => 0.1,
    tip: 'Attack specific tip.',
    why: () => 'never shown',
  };
  const html = sig._mkSignalCard(feat, 12, true, { top: false });
  assert.ok(!html.includes('never shown'));
  assert.ok(!html.includes('Top signal'));
});

test('_pickTopSignal ranks by served deviation when provided', () => {
  const entries = [
    { key: 'a', alert: () => true, bar: () => 0.9 },
    { key: 'b', alert: () => false, bar: () => 0.1 },
  ];
  const top = sig._pickTopSignal(entries, {}, { a: 0.5, b: 8.2 });
  assert.equal(top.key, 'b');
  assert.equal(top.flagged, true);
});

test('_pickTopSignal without deviations keeps legacy bar ranking', () => {
  const entries = [
    { key: 'a', alert: () => true, bar: () => 0.9 },
    { key: 'b', alert: () => false, bar: () => 0.1 },
  ];
  const top = sig._pickTopSignal(entries, {});
  assert.equal(top.key, 'a');
  assert.equal(top.flagged, true);
});

test('signal card honors served alerted override', () => {
  const feat = {
    key: 'x', label: 'X',
    fmt: v => String(v),
    alert: () => false, bar: () => 0.1,
    tip: 't',
  };
  const html = sig._mkSignalCard(feat, 5, true, { top: false, alerted: true });
  assert.ok(html.includes('var(--red,#ff3d5a)'));
});
