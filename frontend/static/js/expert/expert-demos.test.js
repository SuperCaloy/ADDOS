/**
 * RED tests for Expert Mode mechanism demos (schematic IF/RF/TEA/prefilter).
 * Plan: notes/tasks/expert-stage-mechanism-animations-plan.md
 * Run: node --test frontend/static/js/expert/expert-demos.test.js
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

// Loads expert-demos.js with browser globals stubbed. The module must only
// touch window/document at the bottom behind typeof guards, so this is faithful.
function loadDemos() {
  delete globalThis.__demoTest;
  const src = fs.readFileSync(path.join(__dirname, 'expert-demos.js'), 'utf8');
  vm.runInThisContext(
    src + '\n;globalThis.__demoTest = {'
    + ' demoIfSteps: (typeof demoIfSteps !== "undefined" ? demoIfSteps : undefined),'
    + ' demoIfPoints: (typeof demoIfPoints !== "undefined" ? demoIfPoints : undefined),'
    + ' demoIfForest: (typeof demoIfForest !== "undefined" ? demoIfForest : undefined),'
    + ' demoIfScore: (typeof demoIfScore !== "undefined" ? demoIfScore : undefined),'
    + ' demoTeaEntropy: (typeof demoTeaEntropy !== "undefined" ? demoTeaEntropy : undefined),'
    + ' demoEwma: (typeof demoEwma !== "undefined" ? demoEwma : undefined),'
    + ' demoThreshold: (typeof demoThreshold !== "undefined" ? demoThreshold : undefined),'
    + ' demoBurstLimit: (typeof demoBurstLimit !== "undefined" ? demoBurstLimit : undefined),'
    + ' demoRfSteps: (typeof demoRfSteps !== "undefined" ? demoRfSteps : undefined),'
    + ' demoRfTrees: (typeof demoRfTrees !== "undefined" ? demoRfTrees : undefined),'
    + ' demoTeaSteps: (typeof demoTeaSteps !== "undefined" ? demoTeaSteps : undefined),'
    + ' demoPrefilterSteps: (typeof demoPrefilterSteps !== "undefined" ? demoPrefilterSteps : undefined),'
    + ' demoGateVerdict: (typeof demoGateVerdict !== "undefined" ? demoGateVerdict : undefined),'
    + ' demoClampStep: (typeof demoClampStep !== "undefined" ? demoClampStep : undefined),'
    + ' demoEsc: (typeof demoEsc !== "undefined" ? demoEsc : undefined),'
    + ' demoShellHtml: (typeof demoShellHtml !== "undefined" ? demoShellHtml : undefined),'
    + ' ExpertDemos: (typeof ExpertDemos !== "undefined" ? ExpertDemos : undefined) };',
    { filename: 'expert-demos.js' }
  );
  return globalThis.__demoTest;
}

// ---- IF step model ----

test('IF model walks 10 granular steps from split to score', () => {
  const t = loadDemos();
  const steps = t.demoIfSteps();
  assert.equal(steps.length, 10);
  steps.forEach((s, i) => {
    assert.ok(typeof s.caption === 'string' && s.caption.length > 0, `step ${i} caption`);
  });
  assert.deepEqual(steps[0].cuts, []);
  assert.ok(steps[3].boxAnom, 'anomaly boxed mid walkthrough');
  assert.ok(steps[5].boxNorm, 'normal boxed after narrowing');
  assert.equal(steps[5].depthNorm, 7);
  assert.equal(steps[7].trees, true);
  assert.equal(steps[8].forest, true);
  assert.equal(steps[9].score, true);
  const allCuts = steps.flatMap(s => s.cuts);
  allCuts.forEach(c => {
    const vertical = c.x1 === c.x2;
    const horizontal = c.y1 === c.y2;
    assert.ok(vertical !== horizontal, 'each cut is axis aligned exactly one way');
    [c.x1, c.x2].forEach(x => assert.ok(x >= 0 && x <= 300, `x in 300 viewBox, got ${x}`));
    [c.y1, c.y2].forEach(y => assert.ok(y >= 0 && y <= 200, `y in 200 viewBox, got ${y}`));
  });
});

test('IF forest shows 8 paths with a short average and a real score', () => {
  const t = loadDemos();
  const f = t.demoIfForest();
  assert.equal(f.paths.length, 8);
  f.paths.forEach((p, i) => {
    assert.ok(p.depth >= 2 && p.depth <= 7, `path ${i} depth in range`);
    assert.ok(p.tree, `path ${i} has a tree shape`);
  });
  assert.ok(Math.abs(f.avg - 3.25) < 0.01, `average 3.25, got ${f.avg}`);
  const s = t.demoIfScore(f.avg, 13.02);
  assert.ok(s > 0.8 && s < 0.9, `anomaly score, got ${s}`);
  assert.ok(s >= 0.6092, 'clears the contract threshold');
});

test('IF point cloud is dense with a separated anomaly', () => {
  const t = loadDemos();
  const cloud = t.demoIfPoints();
  assert.ok(cloud.normals.length >= 36, `dense cloud, got ${cloud.normals.length}`);
  cloud.normals.forEach(p => {
    assert.ok(p[0] >= 0 && p[0] <= 300 && p[1] >= 0 && p[1] <= 200, 'point in bounds');
  });
  const cx = cloud.normals.reduce((a, p) => a + p[0], 0) / cloud.normals.length;
  const cy = cloud.normals.reduce((a, p) => a + p[1], 0) / cloud.normals.length;
  const dist = Math.hypot(cloud.anomaly[0] - cx, cloud.anomaly[1] - cy);
  assert.ok(dist > 80, `anomaly separated from cluster, got ${dist.toFixed(1)}`);
});

// ---- RF step model ----

const CLASSES = ['SYN Flood', 'ICMP Flood', 'UDP Flood'];

test('RF outcome A gives winner 7 of 10 meeting the gate', () => {
  const t = loadDemos();
  for (const winner of CLASSES) {
    const m = t.demoRfSteps(winner, 'A', 20);
    assert.equal(m.votes.length, 20, `${winner} vote count`);
    assert.equal(m.votes.filter(v => v === winner).length, 14, `${winner} count`);
    const others = CLASSES.filter(c => c !== winner);
    assert.equal(m.votes.filter(v => v === others[0]).length, 4, `${others[0]} count`);
    assert.equal(m.votes.filter(v => v === others[1]).length, 2, `${others[1]} count`);
    assert.equal(m.winner, winner);
    assert.equal(m.pct, 70);
    assert.equal(m.outcome, 'A');
    assert.equal(m.count, 20);
    assert.deepEqual(
      m.tallies[m.tallies.length - 1],
      { [winner]: 14, [others[0]]: 4, [others[1]]: 2 }
    );
    assert.equal(t.demoGateVerdict(m.pct, 0.7), 'act');
  }
});

test('RF outcome B splits below the gate so the system waits', () => {
  const t = loadDemos();
  for (const winner of CLASSES) {
    const m = t.demoRfSteps(winner, 'B', 20);
    assert.equal(m.votes.length, 20, `${winner} vote count`);
    assert.equal(m.votes.filter(v => v === winner).length, 10, `${winner} count`);
    const others = CLASSES.filter(c => c !== winner);
    assert.equal(m.votes.filter(v => v === others[0]).length, 6, `${others[0]} count`);
    assert.equal(m.votes.filter(v => v === others[1]).length, 4, `${others[1]} count`);
    assert.equal(m.pct, 50);
    assert.equal(m.outcome, 'B');
    assert.deepEqual(
      m.tallies[m.tallies.length - 1],
      { [winner]: 10, [others[0]]: 6, [others[1]]: 4 }
    );
    assert.equal(t.demoGateVerdict(m.pct, 0.7), 'wait');
  }
});

test('RF 16-tree fallback keeps A above gate and B below', () => {
  const t = loadDemos();
  const a = t.demoRfSteps('SYN Flood', 'A', 16);
  assert.equal(a.votes.length, 16);
  assert.equal(a.votes.filter(v => v === 'SYN Flood').length, 12);
  assert.equal(a.pct, 75);
  assert.equal(t.demoGateVerdict(a.pct, 0.7), 'act');
  const b = t.demoRfSteps('SYN Flood', 'B', 16);
  assert.equal(b.votes.filter(v => v === 'SYN Flood').length, 8);
  assert.equal(b.pct, 50);
  assert.equal(t.demoGateVerdict(b.pct, 0.7), 'wait');
});

test('RF steps default to outcome A at the locked forest size', () => {
  const t = loadDemos();
  const m = t.demoRfSteps('SYN Flood');
  assert.equal(m.outcome, 'A');
  assert.ok(m.count === 20 || m.count === 16, `locked size, got ${m.count}`);
});

test('RF final captions state winner share of the locked forest with act or wait', () => {
  const t = loadDemos();
  const D = t.ExpertDemos;
  const m = t.demoRfSteps('SYN Flood');
  const a = D.stepCaption('rf', 5, { outcome: 'A', winner: 'SYN Flood', gate: 0.7 });
  assert.ok(a.includes(`wins ${m.votes.filter(v => v === 'SYN Flood').length} of ${m.count} (${m.pct}%)`), `A caption, got ${a}`);
  assert.ok(a.includes('acts'), 'A acts');
  const b = D.stepCaption('rf', 5, { outcome: 'B', winner: 'UDP Flood', gate: 0.7 });
  assert.ok(b.includes('of ' + m.count), `B caption, got ${b}`);
  assert.ok(b.includes('waits'), 'B waits');
});

test('outcome switch resets to step 0 and rejects junk', () => {
  const t = loadDemos();
  const D = t.ExpertDemos;
  D.resetStage('rf');
  D.stageState('rf').step = 4;
  D.setOutcome('rf', 'B');
  assert.equal(D.stageState('rf').outcome, 'B');
  assert.equal(D.stageState('rf').step, 0);
  D.setOutcome('rf', 'Z');
  assert.equal(D.stageState('rf').outcome, 'B');
  D.setOutcome('rf', 'A');
  assert.equal(D.stageState('rf').outcome, 'A');
});

test('RF forest exposes one branch tree shape per tree', () => {
  const t = loadDemos();
  const trees = t.demoRfTrees();
  assert.equal(trees.length, 10);
  trees.forEach((tr, i) => {
    const ids = Object.keys(tr.nodes);
    assert.ok(ids.length >= 5, `tree ${i} nodes`);
    assert.ok(Array.isArray(tr.edges) && tr.edges.length >= 4, `tree ${i} edges`);
    assert.ok(Array.isArray(tr.taken) && tr.taken.length >= 3, `tree ${i} taken path`);
    tr.taken.forEach(k => assert.ok(ids.includes(k), `tree ${i} taken node exists`));
    ids.forEach(k => {
      const n = tr.nodes[k];
      assert.ok(n[0] >= 0 && n[0] <= 120 && n[1] >= 0 && n[1] <= 110, `tree ${i} node in 120x110 box`);
    });
    const leaf = tr.taken[tr.taken.length - 1];
    assert.ok(tr.nodes[leaf], `tree ${i} vote leaf exists`);
  });
});

test('RF gate verdict waits below gate and acts at or above it', () => {
  const t = loadDemos();
  assert.equal(t.demoGateVerdict(60, 0.7), 'wait');
  assert.equal(t.demoGateVerdict(69.9, 0.7), 'wait');
  assert.equal(t.demoGateVerdict(70, 0.7), 'act');
  assert.equal(t.demoGateVerdict(100, 0.7), 'act');
  assert.equal(t.demoGateVerdict(0, 0.7), 'wait');
});

// ---- shared helpers ----

test('every step caption carries explicit Step N of M sequencing', () => {
  const t = loadDemos();
  const D = t.ExpertDemos;
  const counts = { flood: 6, entropy: 6, if_node: 10, rf: 6 };
  for (const stage of STAGES) {
    for (let i = 0; i < counts[stage]; i++) {
      const cap = D.stepCaption(stage, i, { outcome: 'A', winner: 'SYN Flood' });
      assert.ok(cap.indexOf(`Step ${i + 1} of ${counts[stage]}:`) === 0, `${stage} step ${i} prefix, got ${cap.slice(0, 24)}`);
    }
  }
});

test('step clamp pins out of range indexes', () => {
  const t = loadDemos();
  assert.equal(t.demoClampStep(-1, 4), 0);
  assert.equal(t.demoClampStep(0, 4), 0);
  assert.equal(t.demoClampStep(2, 4), 2);
  assert.equal(t.demoClampStep(3, 4), 3);
  assert.equal(t.demoClampStep(99, 4), 3);
});

test('escaper neutralizes attribute breaking characters', () => {
  const t = loadDemos();
  assert.equal(t.demoEsc('a"b<c>d&e'), 'a&quot;b&lt;c&gt;d&amp;e');
});

// ---- TEA step model ----

test('TEA entropy math matches Shannon on a fixed mix', () => {
  const t = loadDemos();
  const h = t.demoTeaEntropy([0.5, 0.25, 0.125, 0.125]);
  assert.ok(Math.abs(h - 1.75) < 0.01, `H 1.75 bits, got ${h}`);
  assert.equal(t.demoTeaEntropy([1]), 0);
});

test('TEA walkthrough has 6 calc steps with live bound finale', () => {
  const t = loadDemos();
  const steps = t.demoTeaSteps();
  assert.equal(steps.length, 6);
  assert.equal(steps[0].kind, 'inputs');
  assert.equal(steps[1].kind, 'entropy');
  assert.equal(steps[2].kind, 'baseline');
  assert.equal(steps[3].kind, 'zscore');
  assert.equal(steps[4].kind, 'confidence');
  assert.equal(steps[5].kind, 'latch');
  steps.forEach((s, i) => {
    assert.ok(typeof s.caption === 'string' && s.caption.length > 0, `step ${i} caption`);
  });
  assert.ok(steps[5].caption.includes('5') && steps[5].caption.includes('60'), 'unlock streaks named');
});

// ---- prefilter step model ----

test('prefilter EWMA and threshold math match backend constants', () => {
  const t = loadDemos();
  assert.equal(t.demoEwma(40, 60, 0.1), 42);
  assert.equal(t.demoThreshold(42, 3.0, 25), 126);
  assert.equal(t.demoThreshold(5, 3.0, 25), 25);
  assert.equal(t.demoBurstLimit(126, 0.4), 50.4);
});

test('prefilter walkthrough has 6 calc steps ending flagged plus multi', () => {
  const t = loadDemos();
  const steps = t.demoPrefilterSteps();
  assert.equal(steps.length, 6);
  assert.equal(steps[0].flagged, false);
  assert.equal(steps[5].flagged, true);
  assert.equal(steps[5].multi, true);
  const dotMax = Math.max(...steps.map(s => s.dots.length));
  assert.ok(dotMax <= 12, `dot budget 12 visible at once, got ${dotMax}`);
});

// ---- shell HTML contract ----

const STAGES = ['flood', 'entropy', 'if_node', 'rf'];

test('shell carries details block, stable ids, actions, live region, footnote', () => {
  const t = loadDemos();
  const dotsFor = { flood: 6, entropy: 6, if_node: 10, rf: 6 };
  for (const stage of STAGES) {
    const html = t.demoShellHtml(stage, { step: 0 }, {});
    assert.ok(html.includes('<details'), `${stage} details`);
    assert.ok(html.includes('data-demo-action="play"'), `${stage} play action`);
    assert.ok(html.includes('data-demo-action="replay"'), `${stage} replay action`);
    assert.ok(html.includes(`id="expert-demo-play-${stage}"`), `${stage} play id`);
    assert.ok(html.includes(`id="expert-demo-cap-${stage}"`), `${stage} caption id`);
    assert.ok(html.includes('aria-live="polite"'), `${stage} live region`);
    assert.ok(html.includes('aria-atomic="true"'), `${stage} atomic`);
    if (stage === 'rf') {
      assert.ok(html.includes('expert-demo-forest'), 'rf forest grid');
      assert.ok(html.includes('expert-demo-tree'), 'rf branch trees');
    } else {
      assert.ok(html.includes('viewBox="0 0 300 200"'), `${stage} fluid viewBox`);
    }
    assert.ok(html.toLowerCase().includes('schematic'), `${stage} schematic label`);
    assert.ok(!html.includes('style="width:') && !html.includes('style="left:'),
      `${stage} no layout animated inline styles`);
    const dots = html.match(/data-demo-action="goto"/g) || [];
    assert.equal(dots.length, dotsFor[stage], `${stage} step dot count`);
    if (stage === 'rf') {
      assert.ok(html.includes('data-demo-action="outcome"'), 'rf outcome switcher');
      assert.ok(html.includes('Example A: meets gate'), 'rf outcome A label');
      assert.ok(html.includes('Example B: falls short'), 'rf outcome B label');
    }
  }
});

// ---- player timer wiring with stubbed globals ----

test('play advances steps on a 900ms interval then stops at the end', () => {
  const t = loadDemos();
  const realSet = globalThis.setInterval;
  const realClear = globalThis.clearInterval;
  let captured = null;
  let cleared = [];
  let intervalMs = 0;
  globalThis.setInterval = (fn, ms) => { captured = fn; intervalMs = ms; return 42; };
  globalThis.clearInterval = id => { cleared.push(id); };
  try {
    const D = t.ExpertDemos;
    D.resetStage('flood');
    D.play('flood');
    assert.ok(captured !== null, 'interval installed');
    assert.equal(intervalMs, 900);
    assert.equal(D.stageState('flood').playing, true);
    captured(); captured(); captured(); captured(); captured();
    assert.equal(D.stageState('flood').step, 5);
    captured();
    assert.equal(D.stageState('flood').playing, false);
    assert.ok(cleared.includes(42), 'timer cleared at final step');
  } finally {
    globalThis.setInterval = realSet;
    globalThis.clearInterval = realClear;
  }
});

test('stopAll clears every playing stage', () => {
  const t = loadDemos();
  const realSet = globalThis.setInterval;
  const realClear = globalThis.clearInterval;
  let cleared = [];
  globalThis.setInterval = () => 7;
  globalThis.clearInterval = id => { cleared.push(id); };
  try {
    const D = t.ExpertDemos;
    D.resetStage('if_node');
    D.resetStage('flood');
    D.play('if_node');
    D.play('flood');
    D.stopAll();
    assert.equal(D.stageState('if_node').playing, false);
    assert.equal(D.stageState('flood').playing, false);
    assert.ok(cleared.length >= 2, 'both timers cleared');
  } finally {
    globalThis.setInterval = realSet;
    globalThis.clearInterval = realClear;
  }
});

// ---- syncLive writes only, never reads layout ----

function stubNode() {
  return { textContent: '', _style: {}, style: {}, setAttribute() {} };
}

test('syncLive patches text and transform without layout reads', () => {
  const t = loadDemos();
  const nodes = {};
  globalThis.document = {
    getElementById: id => (nodes[id] = nodes[id] || stubNode())
  };
  try {
    t.ExpertDemos.syncLive('rf', {
      rf: {
        conf_gate: 0.7,
        recent_classifications: [{ attack_class: 'UDP Flood', conf: 0.83 }]
      }
    });
    const status = nodes['expert-demo-status-rf'];
    assert.ok(status && status.textContent.length > 0, 'summary status written');
    assert.ok(status.textContent.includes('UDP Flood'), 'winner seed reflected');
  } finally {
    delete globalThis.document;
  }
});

// ---- detach and reattach preserve node identity ----

function fakeEl(id) {
  return {
    id, children: [], parentNode: null, _attrs: {},
    getAttribute(k) { return this._attrs[k] !== undefined ? this._attrs[k] : null; },
    setAttribute(k, v) { this._attrs[k] = String(v); },
    appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
    removeChild(c) {
      this.children = this.children.filter(k => k !== c);
      c.parentNode = null;
      return c;
    },
    querySelector(sel) {
      const want = sel.replace('#', '');
      const walk = n => {
        if (n.id === want) return n;
        for (const k of n.children || []) { const f = walk(k); if (f) return f; }
        return null;
      };
      return walk(this);
    }
  };
}

test('detach keeps the mount node and reattach restores the same node', () => {
  const t = loadDemos();
  const D = t.ExpertDemos;
  const body = fakeEl('expert-modal-body');
  const slot = fakeEl('expert-demo-slot');
  const mount = fakeEl('expert-demo-mount');
  mount._attrs['data-stage'] = 'rf';
  body.appendChild(slot);
  slot.appendChild(mount);
  const kept = D.detachDemo(body);
  assert.equal(kept.node, mount, 'same node kept');
  assert.equal(kept.stage, 'rf', 'stage recorded');
  assert.equal(slot.children.length, 0, 'slot emptied');
  globalThis.document = { getElementById: () => null };
  try {
    D.restoreDemo(body, 'rf', {});
    assert.equal(slot.children[0], mount, 'identical node reattached, not rebuilt');
  } finally {
    delete globalThis.document;
  }
});
