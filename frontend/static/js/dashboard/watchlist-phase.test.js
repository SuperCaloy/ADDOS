/**
 * Watchlist Phase column must render sinkhole rows as "Sinkhole", not "--".
 * Numeric phase 0 is falsy in JS, so `label || phase || '--'` collapses it.
 * Run: node --test frontend/static/js/dashboard/
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const { test } = require('node:test');
const assert = require('node:assert/strict');

function loadMitigation(rows) {
  const dir = __dirname;
  const trStubs = [];
  const tbStub = {
    kids: [],
    innerHTML: '',
    appendChild(el) { this.kids.push(el); },
    querySelector() { return null; },
  };
  const sandbox = {
    window: {},
    ifThr: 0.6,
    apiFetch: async () => rows,
    set: () => {},
    renderPriority: (v) => v,
    renderVector: (v) => v,
    showToast: () => {},
    confirmQuarantineAction: () => {},
    document: {
      getElementById: (id) => (id === 'q-body' ? tbStub : { textContent: '' }),
      createElement: () => {
        const tr = { className: '', dataset: {}, innerHTML: '' };
        trStubs.push(tr);
        return tr;
      },
    },
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  const code = fs.readFileSync(path.join(dir, 'mitigation.js'), 'utf8');
  vm.runInContext(code, sandbox, { filename: 'mitigation.js' });
  return { sandbox, tbStub, trStubs };
}

const sinkholeRow = {
  src_ip: '10.0.0.25',
  phase: 0,
  phase_label: 'Sinkhole',
  attack_vector: 'Uncertain',
  if_score: 0.7,
  confidence: 64.6,
  time_in_phase_sec: 4,
  ttl_remaining_sec: 16,
  priority: 'Low',
};

test('sinkhole row renders Sinkhole phase, never --', async () => {
  const { sandbox, trStubs } = loadMitigation([sinkholeRow]);
  await sandbox.fetchQuarantine();
  assert.equal(trStubs.length, 1);
  assert.match(trStubs[0].innerHTML, /Sinkhole/);
  assert.doesNotMatch(trStubs[0].innerHTML, />--</);
});

test('phase 0 without a label still renders Sinkhole, never --', async () => {
  const { phase_label, ...unlabeled } = sinkholeRow;
  const { sandbox, trStubs } = loadMitigation([unlabeled]);
  await sandbox.fetchQuarantine();
  assert.equal(trStubs.length, 1);
  assert.match(trStubs[0].innerHTML, /Sinkhole/);
  assert.doesNotMatch(trStubs[0].innerHTML, />--</);
});

test('sinkhole row shows the observe countdown bracket', async () => {
  const { sandbox, trStubs } = loadMitigation([sinkholeRow]);
  await sandbox.fetchQuarantine();
  assert.match(trStubs[0].innerHTML, /\[0m 16s\]/);
});
