/**
 * Schematic mechanism demos for Expert Mode (IF, RF, TEA, Flood Prefilter).
 * Fixed step choreography plus live framing values from the 2s expert poll.
 * Plan: notes/tasks/expert-stage-mechanism-animations-plan.md
 *
 * Conventions: one shared player timer for the whole module, transitions on
 * transform/opacity only, syncLive performs writes and never reads layout.
 */

var DEMO_STEP_MS = 2500;
var DEMO_VIEW_W = 300;
var DEMO_VIEW_H = 200;

var DEMO_SUMMARY = {
  flood: 'See filtering in action',
  entropy: 'See diversity collapse',
  if_node: 'See isolation in action',
  rf: 'See voting in action'
};

var DEMO_STEP_COUNT = { flood: 6, entropy: 8, if_node: 12, rf: 7 };

// Forest size, locked by fit test (harness renders of both candidates at
// 360px dark: 20 trees lay out 2 per row over 10 rows with zero x-overflow
// and legible labels; 16 also fits but shows less majority. So 20 wins.)
var DEMO_RF_COUNT = 20;

var DEMO_CLASSES = ['SYN Flood', 'ICMP Flood', 'UDP Flood'];
var DEMO_CLASS_KEY = { 'SYN Flood': 'syn', 'ICMP Flood': 'icmp', 'UDP Flood': 'udp', 'Anomaly': 'anom', 'Normal': 'norm' };

// Fixed IF scatter: dense normal cloud plus two separated anomalies.
// Points are seeded so every render is identical.
var DEMO_IF_ANOMALIES = [[255, 45], [45, 30]];

function demoRng(seed) {
  var s = seed;
  return function() {
    s |= 0; s = (s + 0x6D2B79F5) | 0;
    var t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Dense normal cloud (40 points) with two separated anomalies.
 */
function demoIfPoints() {
  var rng = demoRng(42);
  var normals = [];
  for (var i = 0; i < 40; i++) {
    normals.push([
      Math.round(30 + rng() * 90),
      Math.round(100 + rng() * 80)
    ]);
  }
  return { normals: normals, anomalies: DEMO_IF_ANOMALIES };
}

/**
 * Normal point nearest the anchor, boxed by four derived cuts.
 */
function demoIfNormalTarget() {
  var pts = demoIfPoints().normals;
  var best = pts[0];
  var bestD = Infinity;
  pts.forEach(function(p) {
    var d = Math.hypot(p[0] - 95, p[1] - 150);
    if (d < bestD) { bestD = d; best = p; }
  });
  var x0 = Math.max(best[0] - 28, 2);
  var y0 = Math.max(best[1] - 16, 102);
  return { point: best, box: { x: x0, y: y0, w: 56, h: 36 } };
}

/**
 * Eleven granular IF steps: two anomalies tracked throughout, random split
 * idea, outlier separation twice, crowded narrowing, both boxes, path
 * length meaning, trees pair, forest average, score formula, why fast.
 * Coordinates live in the 300x200 viewBox.
 */
function demoIfSteps() {
  var norm = demoIfNormalTarget();
  var b = norm.box;
  var base = [
    { x1: 150, y1: 0, x2: 150, y2: 200 },
    { x1: 150, y1: 100, x2: 300, y2: 100 }
  ];
  var extra = [
    { x1: b.x + b.w, y1: 100, x2: b.x + b.w, y2: 200 },
    { x1: b.x, y1: 100, x2: b.x, y2: 200 },
    { x1: 40, y1: b.y, x2: 150, y2: b.y },
    { x1: 40, y1: b.y + b.h, x2: 150, y2: b.y + b.h }
  ];
  var anomBox = { x: 225, y: 20, w: 60, h: 50 };
  var anomBoxB = { x: 12, y: 6, w: 70, h: 52 };
  var cutsB = [
    { x1: 0, y1: 60, x2: 150, y2: 60 },
    { x1: 85, y1: 0, x2: 85, y2: 100 }
  ];
  var plain = { cuts: [], boxAnom: null, boxAnomB: null, depthAnomB: 0, boxNorm: null, depthNorm: 0, bars: false, trees: false, forest: false, score: false, isolated: false };
  function step(patch) {
    var s = {};
    Object.keys(plain).forEach(function(k) { s[k] = plain[k]; });
    Object.keys(patch).forEach(function(k) { s[k] = patch[k]; });
    return s;
  }
  return [
    step({ caption: 'Two suspicious flows sit apart from a crowd of forty normal flows. Watch what random cuts do to each.' }),
    step({ caption: 'A random split: pick a feature, pick a random value, divide everything in two.', cuts: base.slice(0, 1) }),
    step({ caption: 'Each split divides whichever region still holds the point you follow.', cuts: base }),
    step({ caption: 'The first outlier separates after 3 splits: nothing else shares its corner.', cuts: base, boxAnom: anomBox, isolated: true }),
    step({ caption: 'A second outlier needs only 2 splits. Fast again, not a one-off.', cuts: base.concat(cutsB), boxAnom: anomBox, boxAnomB: anomBoxB, depthAnomB: 2, isolated: true }),
    step({ caption: 'A normal point hides in the crowd: splits keep landing on groups around it, not on the point itself.', cuts: base.concat(cutsB, extra.slice(0, 2)), boxAnom: anomBox, boxAnomB: anomBoxB, depthAnomB: 2, isolated: true }),
    step({ caption: 'The same tree needs 7 splits to box one normal point.', cuts: base.concat(cutsB, extra), boxAnom: anomBox, boxAnomB: anomBoxB, depthAnomB: 2, boxNorm: b, depthNorm: 7, isolated: true }),
    step({ caption: 'Path length is the split count from root to leaf: 2 to 3 for the outliers, 7 for the normal point.', cuts: base.concat(cutsB, extra), boxAnom: anomBox, boxAnomB: anomBoxB, depthAnomB: 2, boxNorm: b, depthNorm: 7, isolated: true }),
    step({ caption: 'Two isolation paths compared: short red paths isolate outliers, one long green path isolates the normal point.', trees: true, depthNorm: 7, isolated: true }),
    step({ caption: 'Sixteen trees isolate the same anomaly differently. Average path: 3.5 splits. The production forest holds 150 trees, all reaching depth 10.', forest: true, depthNorm: 7, isolated: true }),
    step({ caption: 's = 2^(-3.5/13.0) = 0.83, above threshold: ANOMALY. Averaging 150 shallow trees needs no distance computation, which is why Isolation Forest is fast.', score: true, depthNorm: 7, isolated: true }),
    step({ caption: 'Anomaly confirmed. Sending flow features to Random Forest.', handoff: true, depthNorm: 7, isolated: true })
  ];
}

/**
 * Seeded isolation tree shape with a genuine branching structure: a taken
 * root to leaf path of exactly `depth` edges plus one dead-end leaf per
 * level on the opposite side. The lean varies per seed so each tree has
 * its own silhouette. Fits the 120x110 box.
 */
function demoIfBranchTree(depth, seed) {
  var rng = demoRng(seed);
  var nodes = { root: [60, 4] };
  var edges = [];
  var taken = ['root'];
  var px = 60;
  var prev = 'root';
  for (var i = 1; i <= depth; i++) {
    var y = 4 + Math.round(i * (92 / depth));
    var lean = rng() < 0.5 ? -1 : 1;
    if (px < 30) lean = 1;
    if (px > 90) lean = -1;
    var dx = 14 + Math.round(rng() * 12);
    var x = Math.max(12, Math.min(108, px + lean * dx));
    if (i === depth) x = Math.max(20, Math.min(100, 60 + lean * 10));
    var id = 'n' + i;
    nodes[id] = [x, y];
    edges.push([prev, id]);
    var sx = Math.max(10, Math.min(110, px - lean * (18 + Math.round(rng() * 10))));
    var sid = 's' + i;
    nodes[sid] = [sx, y - 2];
    edges.push([prev, sid]);
    taken.push(id);
    prev = id;
    px = x;
  }
  return { nodes: nodes, edges: edges, taken: taken };
}

/**
 * Sixteen seeded isolation paths per scenario from the generator.
 * Scenario A mixes mostly shallow anomaly paths with one slower tree
 * (average 3.5); scenario B mixes deep normal paths with one faster
 * tree (average 9.5). Every tree gets its own silhouette.
 */
var DEMO_IF_DEPTHS_A = [6, 3, 3, 4, 2, 5, 3, 4, 2, 3, 3, 4, 2, 5, 3, 4];
var DEMO_IF_DEPTHS_B = [10, 9, 10, 10, 7, 10, 9, 10, 10, 9, 10, 10, 9, 10, 10, 9];

function demoIfForest(scenario) {
  var isB = scenario === 'B';
  var depths = isB ? DEMO_IF_DEPTHS_B : DEMO_IF_DEPTHS_A;
  var base = isB ? 1000 : 0;
  var paths = depths.map(function(depth, i) {
    return { depth: depth, tree: demoIfBranchTree(depth, base + i * 17 + depth) };
  });
  var avg = paths.reduce(function(a, p) { return a + p.depth; }, 0) / paths.length;
  return { paths: paths, avg: avg };
}

/**
 * IF anomaly score from average path length E(h) and normalizer c(n).
 * s(x, n) = 2^(-E(h(x)) / c(n)). Rounded to 2 decimals like the panel.
 */
function demoIfScore(avgPath, cn) {
  return Math.round(Math.pow(2, -avgPath / cn) * 100) / 100;
}

/**
 * Shannon entropy in bits for a share mix. H = -sum(p * log2(p)).
 */
function demoTeaEntropy(shares) {
  var h = 0;
  shares.forEach(function(p) {
    if (p > 0) h -= p * (Math.log(p) / Math.LN2);
  });
  return Math.round(h * 100) / 100;
}

/**
 * EWMA baseline update: (1 - alpha) * previous + alpha * current.
 * Matches backend DynamicThreshold with alpha 0.1. Rounded to 1 decimal.
 */
function demoEwma(previous, current, alpha) {
  return Math.round(((1 - alpha) * previous + alpha * current) * 10) / 10;
}

/**
 * Prefilter threshold: max(EWMA * multiplier, floor). Integer math.
 */
function demoThreshold(ewma, multiplier, floor) {
  return Math.max(Math.round(ewma * multiplier), floor);
}

/**
 * Burst trip limit: fraction of the threshold inside a sub second window.
 */
function demoBurstLimit(threshold, fraction) {
  return Math.round(threshold * fraction * 10) / 10;
}

/**
 * Vote multiset for a seeded winner at a given forest size. Outcome A
 * concentrates (70 or 75 percent, meets the gate) and outcome B splits
 * (50 percent, falls short), both interleaved so the tally converges.
 * Tallies are cumulative. Sizes: 20 (A 14-4-2, B 10-6-4) or 16 (A 12-3-1,
 * B 8-5-3, since exactly 70 percent of 16 is not a whole tree).
 */
function demoRfSteps(winner, outcome, count) {
  var others = DEMO_CLASSES.filter(function(c) { return c !== winner; });
  var W = winner, O1 = others[0], O2 = others[1];
  var votes;
  if ((count || DEMO_RF_COUNT) === 16) {
    votes = outcome === 'B'
      ? [W, O1, W, O2, W, O1, W, W, O2, O1, W, O2, W, O1, W, O1]
      : [W, W, O1, W, W, W, O2, W, W, O1, W, W, W, O1, W, W];
  } else {
    votes = outcome === 'B'
      ? [W, O1, W, O2, W, O1, W, O2, W, O1].concat([W, O1, W, O2, W, O1, W, O2, W, O1])
      : [W, W, O1, W, O2, W, W, O1, W, W].concat([W, W, O1, W, O2, W, W, O1, W, W]);
  }
  var tallies = [];
  var tally = {};
  DEMO_CLASSES.forEach(function(c) { tally[c] = 0; });
  votes.forEach(function(v) {
    tally[v] += 1;
    var snap = {};
    DEMO_CLASSES.forEach(function(c) { snap[c] = tally[c]; });
    tallies.push(snap);
  });
  var top = votes.filter(function(v) { return v === winner; }).length;
  return {
    votes: votes, tallies: tallies, winner: winner,
    pct: Math.round(top / votes.length * 100),
    outcome: outcome === 'B' ? 'B' : 'A', count: votes.length
  };
}

/**
 * Ten branch tree shapes in a 120x110 box, cycling three variants so the
 * forest does not look cloned. Each shape names its taken root to leaf
 * path; the vote leaf is the last taken node.
 */
function demoRfTrees(count) {
  var vLeft = {
    nodes: { root: [60, 10], L: [32, 40], R: [88, 40], LL: [16, 70], LR: [48, 70] },
    edges: [['root', 'L'], ['root', 'R'], ['L', 'LL'], ['L', 'LR']],
    taken: ['root', 'L', 'LL']
  };
  var vRight = {
    nodes: { root: [60, 10], L: [32, 40], R: [88, 40], RL: [72, 70], RR: [104, 70] },
    edges: [['root', 'L'], ['root', 'R'], ['R', 'RL'], ['R', 'RR']],
    taken: ['root', 'R', 'RR']
  };
  var vDeep = {
    nodes: { root: [60, 8], L: [32, 36], R: [88, 36], LL: [20, 62], LR: [44, 62], LLL: [20, 88] },
    edges: [['root', 'L'], ['root', 'R'], ['L', 'LL'], ['L', 'LR'], ['LL', 'LLL']],
    taken: ['root', 'L', 'LL', 'LLL']
  };
  var shapes = [vLeft, vRight, vDeep];
  var trees = [];
  var total = count || 10;
  for (var i = 0; i < total; i++) trees.push(shapes[i % 3]);
  return trees;
}

/**
 * Gate verdict from demo tally percent against the live confidence gate.
 * Acts at or above the gate, waits below it.
 */
function demoGateVerdict(pct, gate) {
  return pct >= gate * 100 ? 'act' : 'wait';
}

/**
 * Eight plain TEA steps following the real pipeline: count the window,
 * turn counts into shares, work the entropy arithmetic, compare high
 * against low entropy, learn the baseline, score z against live sigma,
 * stack live surges into confidence, then latch with dual streaks.
 */
function demoTeaSteps() {
  return [
    { kind: 'inputs', caption: 'Count one window of traffic: who sent how much.', diversity: 0.92, z: 0.2, locked: false },
    { kind: 'shares', caption: 'Turn counts into shares: half the packets came from one talker, the rest split up.', diversity: 0.9, z: 0.1, locked: false },
    { kind: 'entropy', caption: 'Entropy turns shares into one number: H = 1.75 bits here. Spread-out traffic scores high.', diversity: 0.88, z: -0.4, locked: false },
    { kind: 'compare', caption: 'Same math on flood traffic gives 0.62 bits. Low entropy means predictable, likely automated.', diversity: 0.31, z: -2.6, locked: false },
    { kind: 'baseline', caption: 'The system learns normal entropy over 15 calm intervals. The live baseline values appear beside the diagram.', diversity: 0.6, z: -1.2, locked: false },
    { kind: 'zscore', caption: 'How far is current traffic from normal? z is the difference divided by the spread, checked against the live sigma line.', diversity: 0.31, z: -2.6, locked: false },
    { kind: 'confidence', caption: 'Three warning lights: size, intensity, packet rate. Two or more lit, plus machine-like traffic, means HIGH confidence.', diversity: 0.28, z: -2.7, locked: false },
    { kind: 'latch', caption: 'The memory of normal stays frozen during attacks. It reopens only after 5 clean IF checks and 60 clean TEA checks.', diversity: 0.28, z: -2.7, locked: true }
  ];
}

/**
 * Six fixed prefilter steps following the real pipeline: count per source
 * and protocol, learn the EWMA baseline, apply the threshold, check the
 * burst rule, show an unambiguous extreme flood, flag the source.
 * Single protocol throughout: no cross protocol correlation claimed.
 */
function demoPrefilterSteps() {
  var calm = [{ x: 30, y: 70, lane: 0 }, { x: 70, y: 72, lane: 0 }, { x: 110, y: 68, lane: 0 }];
  var burst = [
    { x: 150, y: 55, lane: 0 }, { x: 175, y: 40, lane: 0 }, { x: 200, y: 28, lane: 0 },
    { x: 225, y: 22, lane: 0 }, { x: 250, y: 20, lane: 0 }
  ];
  var extreme = [
    { x: 150, y: 30, lane: 0 }, { x: 170, y: 24, lane: 0 }, { x: 190, y: 20, lane: 0 },
    { x: 210, y: 16, lane: 0 }, { x: 230, y: 14, lane: 0 }, { x: 250, y: 12, lane: 0 },
    { x: 265, y: 10, lane: 0 }, { x: 278, y: 10, lane: 0 }
  ];
  return [
    { kind: 'count', caption: 'Count packets per second for each source IP and protocol. Live flagged counts appear beside the diagram.', dots: calm, lines: 0, flagged: false },
    { kind: 'baseline', caption: 'EWMA baseline learns normal: 0.9 × 40 + 0.1 × 60 = 42.0 pps.', dots: calm, lines: 1, flagged: false },
    { kind: 'threshold', caption: 'Threshold = max(42 × 3, 25) = 126 pps. Never below the 25 floor.', dots: calm, lines: 2, flagged: false },
    { kind: 'burst', caption: 'Burst rule: 40% of 126 is about 50 packets inside 0.1s or 0.5s.', dots: calm.concat(burst), lines: 2, flagged: false },
    { kind: 'extreme', caption: 'Obvious attack: about 10,400 pps against a 126 limit, over 80 times the threshold. No borderline call needed.', dots: calm.concat(extreme), lines: 2, flagged: false, spikePps: 10400 },
    { kind: 'flag', caption: 'A source crossing its line is flagged for that protocol.', dots: calm.concat(burst), lines: 2, flagged: true }
  ];
}

/**
 * Pins a step index into range.
 */
function demoClampStep(i, n) {
  if (typeof i !== 'number' || isNaN(i)) return 0;
  return Math.max(0, Math.min(n - 1, Math.floor(i)));
}

/**
 * Escapes attribute breaking characters in tooltip and label copy.
 */
function demoEsc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function demoMaxStep(stage) {
  return (DEMO_STEP_COUNT[stage] || 4) - 1;
}

// ---- live value extraction (defaults when the poll has not landed) ----

function demoLiveValues(stage, d) {
  d = d || {};
  if (stage === 'if_node') {
    var ifData = d.if || {};
    var thr = typeof ifData.threshold === 'number' ? ifData.threshold : 0.6092;
    var best = null;
    (ifData.recent_scores || []).forEach(function(s) {
      if (!best || s.score > best.score) best = s;
    });
    return {
      threshold: thr,
      score: best ? best.score : 0,
      anomaly: best ? !!best.anomaly : false
    };
  }
  if (stage === 'rf') {
    var rf = d.rf || {};
    var gate = typeof rf.conf_gate === 'number' ? rf.conf_gate : 0.7;
    var winner = 'SYN Flood';
    var conf = 0;
    (rf.recent_classifications || []).forEach(function(c) {
      if (winner === 'SYN Flood' && c.attack_class && c.attack_class !== 'Uncertain') {
        winner = c.attack_class;
        conf = typeof c.conf === 'number' ? c.conf : 0;
      }
    });
    var ifData = d.if || {};
    var ifScores = ifData.recent_scores || [];
    var ifBest = null;
    ifScores.forEach(function(s) {
      if (!ifBest || s.score > ifBest.score) ifBest = s;
    });
    return {
      gate: gate, winner: winner, conf: conf,
      ifScore: ifBest ? ifBest.score : 0,
      ifThr: typeof ifData.threshold === 'number' ? ifData.threshold : 0.6092,
      hasIf: ifScores.length > 0
    };
  }
  if (stage === 'entropy') {
    var g = (d.tea && d.tea.global) || {};
    return {
      sizeZ: typeof g.size_z === 'number' ? g.size_z : 0,
      intZ: typeof g.intensity_z === 'number' ? g.intensity_z : 0,
      sigma: typeof g.dynamic_attack_sigma === 'number' ? g.dynamic_attack_sigma : 2.5,
      locked: !!g._locked,
      attack: !!g.is_attack,
      sizeSurge: !!g.size_surge,
      intSurge: !!g.intensity_surge,
      ppsSurge: !!g.pps_surge,
      confidence: g.confidence || 'LOW'
    };
  }
  var sess = (d.pipeline && d.pipeline.flood_prefilter_session) || {};
  var byProto = sess.session_flagged_by_proto || {};
  return {
    spike: sess.session_spike || 0,
    syn: byProto.SYN || 0,
    icmp: byProto.ICMP || 0,
    udp: byProto.UDP || 0
  };
}

function demoSummaryStatus(stage, live) {
  if (stage === 'if_node') {
    return 'score ' + live.score.toFixed(4) + ' · ' + (live.anomaly ? 'ANOMALY' : 'NORMAL');
  }
  if (stage === 'rf') {
    return live.winner + ' · gate ' + Math.round(live.gate * 100) + '%';
  }
  if (stage === 'entropy') {
    return (live.attack ? 'ATTACK' : (live.locked ? 'LOCKED' : 'NORMAL')) + ' · z ' + live.sizeZ.toFixed(1);
  }
  var total = live.syn + live.icmp + live.udp;
  return total + ' flagged · ' + live.spike + ' spikes';
}

// ---- diagram builders (SVG uses attributes only, never layout CSS) ----

function demoSvgOpen() {
  return '<svg class="expert-demo-svg" viewBox="0 0 ' + DEMO_VIEW_W + ' ' + DEMO_VIEW_H + '" role="img">';
}

/**
 * Closing frame: the IF to RF handoff, or the cleared end card for the
 * normal example. No feature counts, only flow features in general.
 */
function demoIfHandoffHtml(scenario) {
  if (scenario === 'B') {
    return '<div class="expert-demo-handoff">'
      + '<span class="expert-demo-stagechip expert-demo-stage-clear">Cleared</span>'
      + '</div>';
  }
  return '<div class="expert-demo-handoff">'
    + '<span class="expert-demo-stagechip expert-demo-stage-if">Isolation Forest</span>'
    + '<svg class="expert-demo-arrow" viewBox="0 0 48 16" aria-hidden="true">'
    + '<line x1="2" y1="8" x2="38" y2="8" class="expert-demo-arrowline"/>'
    + '<path d="M30 2 L44 8 L30 14" class="expert-demo-arrowhead"/></svg>'
    + '<span class="expert-demo-stagechip expert-demo-stage-rf">Random Forest</span>'
    + '</div>';
}

function demoIfDiagram(step, live, scenario) {
  var s = demoIfSteps()[step];
  var sc = scenario === 'B' ? 'B' : 'A';
  var cloud = demoIfPoints();
  if (s.handoff) return demoIfHandoffHtml(sc);
  if (s.trees) return demoIfTreesSvg();
  if (s.forest) return demoIfForestHtml(sc);
  if (s.score) return demoIfScoreHtml();
  var h = demoSvgOpen();
  cloud.normals.forEach(function(p) {
    h += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="4" class="expert-demo-dot"/>';
  });
  cloud.anomalies.forEach(function(a) {
    h += '<circle cx="' + a[0] + '" cy="' + a[1] + '" r="5" class="expert-demo-anom"/>';
    h += '<circle cx="' + a[0] + '" cy="' + a[1] + '" r="9" class="expert-demo-anomring"/>';
  });
  var normgg = demoIfNormalTarget();
  h += '<circle cx="' + normgg.point[0] + '" cy="' + normgg.point[1] + '" r="9" class="expert-demo-normring"/>';
  s.cuts.forEach(function(c) {
    h += '<line x1="' + c.x1 + '" y1="' + c.y1 + '" x2="' + c.x2 + '" y2="' + c.y2 + '" class="expert-demo-cut"/>';
  });
  if (s.boxAnom) {
    h += '<rect x="' + s.boxAnom.x + '" y="' + s.boxAnom.y + '" width="' + s.boxAnom.w + '" height="' + s.boxAnom.h + '" class="expert-demo-box"/>';
    h += '<text x="' + (s.boxAnom.x + s.boxAnom.w / 2) + '" y="' + (s.boxAnom.y - 6) + '" text-anchor="middle" class="expert-demo-depthtag">depth 3</text>';
  }
  if (s.boxAnomB) {
    h += '<rect x="' + s.boxAnomB.x + '" y="' + s.boxAnomB.y + '" width="' + s.boxAnomB.w + '" height="' + s.boxAnomB.h + '" class="expert-demo-box"/>';
    h += '<text x="' + (s.boxAnomB.x + s.boxAnomB.w / 2) + '" y="' + (s.boxAnomB.y + s.boxAnomB.h + 14) + '" text-anchor="middle" class="expert-demo-depthtag">depth 2</text>';
  }
  if (s.boxNorm) {
    var norm = demoIfNormalTarget();
    h += '<rect x="' + s.boxNorm.x + '" y="' + s.boxNorm.y + '" width="' + s.boxNorm.w + '" height="' + s.boxNorm.h + '" class="expert-demo-boxnorm"/>';
    h += '<circle cx="' + norm.point[0] + '" cy="' + norm.point[1] + '" r="5" class="expert-demo-normmark"/>';
    h += '<text x="' + (s.boxNorm.x + s.boxNorm.w / 2) + '" y="' + (s.boxNorm.y + s.boxNorm.h + 14) + '" text-anchor="middle" class="expert-demo-depthtag">depth 7</text>';
  }
  return h + '</svg>';
}

/**
 * Eight mini isolation trees for the same anomaly point, each with its
 * depth label, plus the ensemble average. Reuses the forest vocabulary
 * with a red anomaly vote on every taken leaf.
 */
function demoIfForestHtml(scenario) {
  var f = demoIfForest(scenario);
  var isB = scenario === 'B';
  var h = '<div class="expert-demo-forest">';
  f.paths.forEach(function(p) {
    h += '<div class="expert-demo-iftree">' + demoRfTreeSvg(p.tree, isB ? 'Normal' : 'Anomaly', true, true)
      + '<div class="expert-demo-tdepth">depth ' + p.depth + '</div></div>';
  });
  h += '</div>';
  return h;
}

/**
 * Score card: the panel formula in symbolic form. The worked values and
 * the verdict live in the step caption, so no banner repeats them here.
 */
function demoIfScoreHtml() {
  return '<div class="expert-demo-formula">s(x, n) = 2<sup>(-E(h(x)) / c(n))</sup></div>';
}
function demoIfTreesSvg() {
  var h = demoSvgOpen();
  h += '<g>'
    + '<line x1="75" y1="14" x2="45" y2="42" class="expert-demo-tedge on expert-demo-voteline-anom"/>'
    + '<line x1="75" y1="14" x2="105" y2="42" class="expert-demo-tedge"/>'
    + '<line x1="45" y1="42" x2="30" y2="70" class="expert-demo-tedge on expert-demo-voteline-anom"/>'
    + '<line x1="45" y1="42" x2="60" y2="70" class="expert-demo-tedge"/>'
    + '<circle cx="75" cy="14" r="4.5" class="expert-demo-tnode on"/>'
    + '<circle cx="45" cy="42" r="4.5" class="expert-demo-tnode on"/>'
    + '<circle cx="105" cy="42" r="4.5" class="expert-demo-tnode"/>'
    + '<circle cx="30" cy="70" r="5" class="expert-demo-tnode on expert-demo-votedot-anom"/>'
    + '<circle cx="60" cy="70" r="4.5" class="expert-demo-tnode"/>'
    + '<text x="67" y="95" text-anchor="middle" class="expert-demo-tlabel">anomaly · depth 3</text>'
    + '</g>';
  var chain = [[225, 10], [205, 28], [245, 46], [205, 64], [245, 82], [205, 100], [245, 118], [225, 136]];
  var stubs = [[245, 28], [225, 46], [225, 64], [225, 82], [225, 100], [225, 118]];
  h += '<g>';
  for (var i = 0; i < chain.length - 1; i++) {
    h += '<line x1="' + chain[i][0] + '" y1="' + chain[i][1] + '" x2="' + chain[i + 1][0] + '" y2="' + chain[i + 1][1] + '" class="expert-demo-tedge on expert-demo-voteline-norm"/>';
    if (stubs[i]) {
      h += '<line x1="' + chain[i][0] + '" y1="' + chain[i][1] + '" x2="' + stubs[i][0] + '" y2="' + stubs[i][1] + '" class="expert-demo-tedge"/>';
    }
  }
  stubs.forEach(function(p) {
    h += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="3" class="expert-demo-tnode"/>';
  });
  for (var j = 0; j < chain.length - 1; j++) {
    h += '<circle cx="' + chain[j][0] + '" cy="' + chain[j][1] + '" r="4.5" class="expert-demo-tnode on"/>';
  }
  var tip = chain[chain.length - 1];
  h += '<circle cx="' + tip[0] + '" cy="' + tip[1] + '" r="5" class="expert-demo-tnode on expert-demo-votedot-norm"/>';
  h += '<text x="225" y="160" text-anchor="middle" class="expert-demo-tlabel">normal · depth 7</text>';
  h += '</g>';
  h += '<text x="10" y="186" class="expert-demo-ztxt">short path = high score = cheap to average</text>';
  return h + '</svg>';
}

function demoTeaDiagram(step, live) {
  var s = demoTeaSteps()[step];
  live = live || {};
  var h = demoSvgOpen();
  if (s.kind === 'inputs' || s.kind === 'entropy' || s.kind === 'shares') {
    var shares = [['IP-A', 50], ['IP-B', 25], ['IP-C', 12.5], ['IP-D', 12.5]];
    shares.forEach(function(sh, i) {
      var w = Math.round(sh[1] / 100 * 240);
      h += '<text x="10" y="' + (34 + i * 34) + '" class="expert-demo-lane">' + sh[0] + '</text>';
      h += '<rect x="48" y="' + (20 + i * 34) + '" width="' + w + '" height="16" class="expert-demo-meter"/>';
      h += '<text x="' + (56 + w) + '" y="' + (33 + i * 34) + '" class="expert-demo-ztxt">' + sh[1] + '%</text>';
    });
    var foot = s.kind === 'entropy' ? 'H = 1.75 bits'
      : (s.kind === 'shares' ? 'shares: 50 / 25 / 12.5 / 12.5' : '200 packets, one window');
    h += '<text x="10" y="180" class="expert-demo-ztxt">' + foot + '</text>';
    return h + '</svg>';
  }
  if (s.kind === 'compare') {
    var normW = Math.round(1.75 / 2 * 240);
    var floodW = Math.round(0.62 / 2 * 240);
    h += '<text x="10" y="40" class="expert-demo-lane">normal traffic</text>';
    h += '<rect x="10" y="50" width="260" height="16" class="expert-demo-track"/>';
    h += '<rect x="10" y="50" width="' + normW + '" height="16" class="expert-demo-meter"/>';
    h += '<text x="10" y="92" class="expert-demo-ztxt">H = 1.75 bits: varied, healthy</text>';
    h += '<text x="10" y="122" class="expert-demo-lane">flood traffic</text>';
    h += '<rect x="10" y="132" width="260" height="16" class="expert-demo-track"/>';
    h += '<rect x="10" y="132" width="' + floodW + '" height="16" class="expert-demo-glyph-flat"/>';
    h += '<text x="10" y="174" class="expert-demo-ztxt">H = 0.62 bits: uniform, suspect</text>';
    return h + '</svg>';
  }
  if (s.kind === 'confidence') {
    var rows = [
      ['size surge', !!live.sizeSurge],
      ['intensity surge', !!live.intSurge],
      ['packet surge', !!live.ppsSurge]
    ];
    var onCount = rows.filter(function(r) { return r[1]; }).length;
    var conf = onCount >= 2 ? 'HIGH' : (onCount === 1 ? 'MODERATE' : 'LOW');
    var list = '<div class="expert-demo-checks">';
    rows.forEach(function(r) {
      list += '<div class="expert-demo-checkrow' + (r[1] ? ' on' : '') + '">'
        + '<span class="expert-demo-checkdot"></span>' + demoEsc(r[0]) + '</div>';
    });
    list += '<div class="expert-demo-checkconf">confidence: ' + conf + ' (live)</div></div>';
    return list;
  }
  var meterW = Math.round(s.diversity * 260);
  h += '<rect x="10" y="70" width="260" height="14" class="expert-demo-track"/>';
  h += '<rect x="10" y="70" width="' + meterW + '" height="14" class="expert-demo-meter"/>';
  var sigma = typeof live.sigma === 'number' ? live.sigma : 2.5;
  var thrX = Math.round((3 - Math.min(Math.max(sigma, 2.0), 2.8)) / 6 * 260) + 10;
  h += '<line x1="' + thrX + '" y1="60" x2="' + thrX + '" y2="94" class="expert-demo-thr"/>';
  if (s.locked) {
    h += '<g class="expert-demo-lock"><rect x="128" y="120" width="44" height="34" rx="6"/><path d="M138 120 v-8 a12 12 0 0 1 24 0 v8"/></g>';
  }
  var zTxt = (s.z >= 0 ? '+' : '') + s.z.toFixed(1) + 'z';
  h += '<text x="10" y="180" class="expert-demo-ztxt">' + zTxt + (s.locked ? ' · FROZEN' : '') + '</text>';
  return h + '</svg>';
}

function demoPrefilterDiagram(step) {
  var s = demoPrefilterSteps()[step];
  var h = demoSvgOpen();
  var lanes = [
    { label: 'SYN', y: 50 }, { label: 'ICMP', y: 105 }, { label: 'UDP', y: 160 }
  ];
  lanes.forEach(function(lane) {
    h += '<text x="4" y="' + (lane.y + 4) + '" class="expert-demo-lane">' + lane.label + '</text>';
    if (s.lines >= 1 && lane.y === 50) {
      h += '<line x1="34" y1="140" x2="286" y2="140" class="expert-demo-base"/>';
    }
    if (s.lines >= 2 && lane.y === 50) {
      h += '<line x1="34" y1="45" x2="286" y2="45" class="expert-demo-thrline"/>';
    }
  });
  s.dots.forEach(function(dt) {
    var y = dt.lane === 0 ? dt.y : dt.y + 55;
    h += '<circle cx="' + dt.x + '" cy="' + y + '" r="5" class="expert-demo-pkt"/>';
  });
  if (s.flagged) {
    h += '<text x="286" y="30" text-anchor="end" class="expert-demo-flag">FLAGGED</text>';
  }
  if (s.spikePps) {
    h += '<text x="150" y="185" text-anchor="middle" class="expert-demo-ztxt">about ' + s.spikePps.toLocaleString('en-US') + ' pps vs 126 limit</text>';
  }
  return h + '</svg>';
}

function demoRfTreeSvg(shape, vote, revealed, small) {
  var cls = vote ? (DEMO_CLASS_KEY[vote] || 'syn') : 'none';
  var r = small ? 3 : 4.5;
  var h = '<svg class="expert-demo-tree" viewBox="0 0 120 110" role="img">';
  shape.edges.forEach(function(e) {
    var a = shape.nodes[e[0]];
    var b = shape.nodes[e[1]];
    var on = revealed && shape.taken.indexOf(e[0]) !== -1 && shape.taken.indexOf(e[1]) !== -1;
    h += '<line x1="' + a[0] + '" y1="' + a[1] + '" x2="' + b[0] + '" y2="' + b[1] + '" class="expert-demo-tedge' + (on ? ' on expert-demo-voteline-' + cls : '') + '"/>';
  });
  Object.keys(shape.nodes).forEach(function(k) {
    var p = shape.nodes[k];
    var isLeaf = shape.taken[shape.taken.length - 1] === k;
    var on = revealed && shape.taken.indexOf(k) !== -1;
    h += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="' + (on && isLeaf ? r + 0.5 : r) + '" class="expert-demo-tnode' + (on ? ' on' : '') + (on && isLeaf ? ' expert-demo-votedot-' + cls : '') + '"/>';
  });
  var label = revealed ? vote.replace(' Flood', '') : '?';
  h += '<text x="60" y="104" text-anchor="middle" class="expert-demo-tlabel' + (revealed ? ' expert-demo-votetext-' + cls : '') + '">' + demoEsc(label) + '</text>';
  return h + '</svg>';
}

/**
 * Opening frame: the IF to RF handoff rule. It states unconditionally
 * that only flows scoring at or above the live IF bar reach Random
 * Forest for classification, and never claims anything about one
 * specific live flow score.
 */
function demoRfHandoffInHtml() {
  return '<div class="expert-demo-handoff">'
    + '<span class="expert-demo-stagechip expert-demo-stage-if">Isolation Forest</span>'
    + '<svg class="expert-demo-arrow" viewBox="0 0 48 16" aria-hidden="true">'
    + '<line x1="2" y1="8" x2="38" y2="8" class="expert-demo-arrowline"/>'
    + '<path d="M30 2 L44 8 L30 14" class="expert-demo-arrowhead"/></svg>'
    + '<span class="expert-demo-stagechip expert-demo-stage-rf">Random Forest</span>'
    + '</div>';
}

/**
 * Closing frame: above the gate the class goes to Decision + Mitigation
 * for enforcement; below the gate the flow waits under sinkhole
 * observation with no enforcement. No stage numbers, only stage names.
 */
function demoRfHandoffOutHtml(live, outcome) {
  var m = demoRfSteps(live.winner || 'SYN Flood', outcome || 'A', DEMO_RF_COUNT);
  var verdict = demoGateVerdict(m.pct, live.gate);
  if (verdict !== 'act') {
    return '<div class="expert-demo-handoff">'
      + '<span class="expert-demo-stagechip expert-demo-stage-rf">Random Forest</span>'
      + '<svg class="expert-demo-arrow" viewBox="0 0 48 16" aria-hidden="true">'
      + '<line x1="2" y1="8" x2="38" y2="8" class="expert-demo-arrowline"/>'
      + '<path d="M30 2 L44 8 L30 14" class="expert-demo-arrowhead"/></svg>'
      + '<span class="expert-demo-stagechip expert-demo-stage-sinkhole">Sinkhole</span>'
      + '</div>';
  }
  return '<div class="expert-demo-handoff">'
    + '<span class="expert-demo-stagechip expert-demo-stage-rf">Random Forest</span>'
    + '<svg class="expert-demo-arrow" viewBox="0 0 48 16" aria-hidden="true">'
    + '<line x1="2" y1="8" x2="38" y2="8" class="expert-demo-arrowline"/>'
    + '<path d="M30 2 L44 8 L30 14" class="expert-demo-arrowhead"/></svg>'
    + '<span class="expert-demo-stagechip expert-demo-stage-decision">Decision + Mitigation</span>'
    + '</div>';
}

function demoRfDiagram(step, live, outcome) {
  if (step === 0) return demoRfHandoffInHtml();
  if (step >= 6) return demoRfHandoffOutHtml(live, outcome || 'A');
  var count = DEMO_RF_COUNT;
  var m = demoRfSteps(live.winner || 'SYN Flood', outcome || 'A', count);
  var trees = demoRfTrees(count);
  var revealed = step >= 5 ? count : Math.round(step / 5 * count);
  var h = '<div class="expert-demo-forest">';
  for (var i = 0; i < count; i++) {
    h += demoRfTreeSvg(trees[i], m.votes[i], i < revealed);
  }
  h += '</div>';
  var zero = { 'SYN Flood': 0, 'ICMP Flood': 0, 'UDP Flood': 0 };
  var tally = revealed > 0 ? m.tallies[revealed - 1] : zero;
  h += '<div class="expert-demo-tally">';
  DEMO_CLASSES.forEach(function(c) {
    h += '<div class="expert-demo-tally-seg expert-demo-vote-' + DEMO_CLASS_KEY[c] + '" style="flex-grow:' + tally[c] + '"></div>';
  });
  h += '</div>';
  return h;
}

function demoDiagramHtml(stage, step, live, outcome, scenario) {
  if (stage === 'rf') return demoRfDiagram(step, live, outcome);
  if (stage === 'entropy') return demoTeaDiagram(step, live);
  if (stage === 'flood') return demoPrefilterDiagram(step);
  return demoIfDiagram(step, live, scenario);
}

/**
 * Full step caption with explicit sequence numbering. ctx carries
 * { outcome, winner, gate } for the RF final frame.
 */
function demoStepCaption(stage, step, ctx) {
  ctx = ctx || {};
  var n = DEMO_STEP_COUNT[stage] || 4;
  var base;
  if (stage === 'rf') {
    var outcome = ctx.outcome === 'B' ? 'B' : 'A';
    var total = DEMO_RF_COUNT;
    if (step >= 6) {
      var fm = demoRfSteps(ctx.winner || 'SYN Flood', outcome, total);
      var fgate = typeof ctx.gate === 'number' ? ctx.gate : 0.7;
      if (demoGateVerdict(fm.pct, fgate) !== 'act') {
        base = 'Class ' + fm.winner + ' at ' + fm.pct + '% stays below the gate, so the flow waits in the sinkhole for observation. No enforcement until confidence returns.';
      } else {
        base = 'Class ' + fm.winner + ' at ' + fm.pct + '% goes to Decision + Mitigation, which picks the enforcement: rate limit, block, clear, redirect, or proto_block.';
      }
    }
    else if (step >= 5) {
      var m = demoRfSteps(ctx.winner || 'SYN Flood', outcome, total);
      var gate = typeof ctx.gate === 'number' ? ctx.gate : 0.7;
      var verdict = demoGateVerdict(m.pct, gate);
      var topCount = m.votes.filter(function(v) { return v === m.winner; }).length;
      base = 'Majority wins ' + topCount + ' of ' + total + ' (' + m.pct + '%). '
        + (verdict === 'act'
          ? 'At or above the gate, so the system acts.'
          : 'Below the gate, so the system waits for more data.')
        + ' The production ensemble holds 300 trees at mean depth 7.6; ' + total + ' are shown here.';
    }
    else if (step === 0) base = 'Only flows scoring at or above the ' + Number(ctx.ifThr > 0 ? ctx.ifThr : 0.6092).toFixed(4) + ' Isolation Forest bar reach this panel for classification.';
    else {
      var rm = demoRfSteps(ctx.winner || 'SYN Flood', outcome, total);
      var shown = Math.min(Math.round(step / 5 * total), total);
      var rt = shown > 0 ? rm.tallies[shown - 1] : { 'SYN Flood': 0, 'ICMP Flood': 0, 'UDP Flood': 0 };
      var parts = [];
      DEMO_CLASSES.forEach(function(c) {
        if (rt[c] > 0) parts.push(c.replace(' Flood', '') + ' ' + rt[c]);
      });
      base = 'Trees 1 to ' + shown + ' of ' + total + ' have voted'
        + (parts.length ? ': ' + parts.join(', ') + '.' : '.');
    }
  }
  else if (stage === 'entropy') base = demoTeaSteps()[step].caption;
  else if (stage === 'flood') base = demoPrefilterSteps()[step].caption;
  else {
    base = demoIfSteps()[step].caption;
    if ((ctx.scenario || 'A') === 'B') {
      if (step === 9) base = 'Sixteen trees isolate a normal flow differently. Average path: 9.5 splits.';
      else if (step === 10) base = 's = 2^(-9.5/13.0) = 0.60. Below its threshold: NORMAL. No handoff needed.';
      else if (step === 11) base = 'Below threshold: flow cleared here. Random Forest never sees it.';
    }
  }
  return 'Step ' + (step + 1) + ' of ' + n + ': ' + base;
}

// ---- shell builder (static skeleton plus poster frame) ----

function demoShellHtml(stage, state, live) {
  var step = demoClampStep(state && typeof state.step === 'number' ? state.step : 0, DEMO_STEP_COUNT[stage] || 4);
  var vals = demoLiveValues(stage, live);
  var n = DEMO_STEP_COUNT[stage] || 4;
  var outcome = (state && (state.outcome === 'A' || state.outcome === 'B')) ? state.outcome : 'A';
  var scenario = (state && state.scenario === 'B') ? 'B' : 'A';
  var ctx = { outcome: outcome, winner: vals.winner, gate: vals.gate, scenario: scenario, hasIf: !!vals.hasIf, ifScore: vals.ifScore, ifThr: vals.ifThr };
  var dots = '';
  for (var i = 0; i < n; i++) {
    dots += '<button type="button" class="expert-demo-dotbtn' + (i === step ? ' on' : '') + '"'
      + ' id="expert-demo-dot-' + stage + '-' + i + '"'
      + ' data-demo-action="goto" data-demo-stage="' + stage + '" data-demo-step="' + i + '"'
      + ' aria-label="Go to step ' + (i + 1) + ' of ' + n + '"'
      + (i === step ? ' aria-current="true"' : '') + '></button>';
  }
  var outcomeHtml = '';
  if (stage === 'rf') {
    outcomeHtml = '<div class="expert-demo-outcomes" role="group" aria-label="Voting outcome example">'
      + '<button type="button" class="expert-demo-outbtn' + (outcome === 'A' ? ' on' : '') + '"'
      + ' data-demo-action="outcome" data-demo-stage="rf" data-demo-outcome="A"'
      + (outcome === 'A' ? ' aria-pressed="true"' : '') + '>Example A: meets gate</button>'
      + '<button type="button" class="expert-demo-outbtn' + (outcome === 'B' ? ' on' : '') + '"'
      + ' data-demo-action="outcome" data-demo-stage="rf" data-demo-outcome="B"'
      + (outcome === 'B' ? ' aria-pressed="true"' : '') + '>Example B: falls short</button>'
      + '</div>';
  }
  if (stage === 'if_node') {
    outcomeHtml = '<div class="expert-demo-outcomes" role="group" aria-label="Flow outcome example">'
      + '<button type="button" class="expert-demo-outbtn' + (scenario === 'A' ? ' on' : '') + '"'
      + ' data-demo-action="scenario" data-demo-stage="if_node" data-demo-scenario="A"'
      + (scenario === 'A' ? ' aria-pressed="true"' : '') + '>Example A: anomaly</button>'
      + '<button type="button" class="expert-demo-outbtn' + (scenario === 'B' ? ' on' : '') + '"'
      + ' data-demo-action="scenario" data-demo-stage="if_node" data-demo-scenario="B"'
      + (scenario === 'B' ? ' aria-pressed="true"' : '') + '>Example B: normal</button>'
      + '</div>';
  }
  return '<details class="expert-demo" id="expert-demo-mount" data-stage="' + stage + '">'
    + '<summary class="expert-demo-sum" id="expert-demo-sum-' + stage + '">'
    + '<span class="expert-demo-sumlabel">' + demoEsc(DEMO_SUMMARY[stage] || 'See it in action') + '</span>'
    + '<span class="expert-demo-status" id="expert-demo-status-' + stage + '">' + demoEsc(demoSummaryStatus(stage, vals)) + '</span>'
    + '</summary>'
    + '<div class="expert-demo-live" id="expert-demo-live-' + stage + '">' + demoLiveStripHtml(stage, vals) + '</div>'
    + outcomeHtml
    + '<div class="expert-demo-diagram" id="expert-demo-diagram-' + stage + '">' + demoDiagramHtml(stage, step, vals, outcome, scenario) + '</div>'
    + '<div class="expert-demo-cap" id="expert-demo-cap-' + stage + '" aria-live="polite" aria-atomic="true">' + demoEsc(demoStepCaption(stage, step, ctx)) + '</div>'
    + '<div class="expert-demo-controls">'
    + '<button type="button" class="expert-demo-btn" id="expert-demo-play-' + stage + '" data-demo-action="play" data-demo-stage="' + stage + '">Play</button>'
    + '<button type="button" class="expert-demo-btn" id="expert-demo-replay-' + stage + '" data-demo-action="replay" data-demo-stage="' + stage + '">Replay</button>'
    + '<span class="expert-demo-dots">' + dots + '</span>'
    + '</div>'
    + '</details>';
}

function demoLiveStripHtml(stage, live) {
  if (stage === 'if_node') {
    var pct = Math.round(Math.min(Math.max(live.score, 0), 1) * 100);
    var thr = Math.round(Math.min(Math.max(live.threshold, 0), 1) * 100);
    return '<div class="expert-demo-strip"><span class="expert-demo-stripval">score ' + live.score.toFixed(4)
      + ' · threshold ' + live.threshold.toFixed(4) + '</span>'
      + '<svg class="expert-demo-mini" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">'
      + '<rect x="0" y="0" width="100" height="10" class="expert-demo-minitrack"/>'
      + '<rect x="0" y="0" width="' + pct + '" height="10" class="expert-demo-minifill"/>'
      + '<line x1="' + thr + '" y1="0" x2="' + thr + '" y2="10" class="expert-demo-minimark"/>'
      + '</svg></div>';
  }
  if (stage === 'rf') {
    return '<div class="expert-demo-strip"><span class="expert-demo-stripval">' + demoEsc(live.winner)
      + ' · confidence gate ' + Math.round(live.gate * 100) + '%</span></div>';
  }
  if (stage === 'entropy') {
    return '<div class="expert-demo-strip"><span class="expert-demo-stripval">z ' + (live.sizeZ >= 0 ? '+' : '') + live.sizeZ.toFixed(1)
      + ' · sigma ' + live.sigma.toFixed(1) + ' · ' + (live.locked ? 'baseline frozen' : 'learning active') + '</span></div>';
  }
  return '<div class="expert-demo-strip"><span class="expert-demo-stripval">SYN ' + live.syn + ' · ICMP ' + live.icmp
    + ' · UDP ' + live.udp + ' · spikes ' + live.spike + '</span></div>';
}

// ---- player state and runtime (DOM touches guarded) ----

function demoDoc() {
  return (typeof document !== 'undefined') ? document : null;
}

var ExpertDemos = {
  _st: {},
  _kept: { node: null, stage: null },

  stageState: function(stage) {
    if (!this._st[stage]) this._st[stage] = { step: 0, playing: false, timer: null, outcome: null, scenario: null };
    return this._st[stage];
  },

  stepCaption: function(stage, step, ctx) {
    return demoStepCaption(stage, demoClampStep(step, DEMO_STEP_COUNT[stage] || 4), ctx);
  },

  resetStage: function(stage) {
    this.stop(stage);
    this._st[stage] = { step: 0, playing: false, timer: null, outcome: null, scenario: null };
  },

  /**
   * Switches the RF outcome example. Resets to step 0; the user presses
   * Play to watch the newly seeded vote. Junk values are ignored.
   */
  setOutcome: function(stage, outcome) {
    if (outcome !== 'A' && outcome !== 'B') return;
    var st = this.stageState(stage);
    st.outcome = outcome;
    st.step = 0;
    this.refresh(stage);
  },

  /**
   * Switches the IF scenario example (A anomaly, B normal). Resets to
   * step 0; the user presses Play. Junk values are ignored.
   */
  setScenario: function(stage, scenario) {
    if (scenario !== 'A' && scenario !== 'B') return;
    var st = this.stageState(stage);
    st.scenario = scenario;
    st.step = 0;
    this.refresh(stage);
  },

  demoScenario: function(stage) {
    var st = this.stageState(stage);
    return st.scenario === 'B' ? 'B' : 'A';
  },

  demoOutcome: function(stage) {
    var st = this.stageState(stage);
    return st.outcome === 'B' ? 'B' : 'A';
  },

  reducedMotion: function() {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return !!window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  },

  play: function(stage) {
    var st = this.stageState(stage);
    if (st.playing) {
      this.pause(stage);
      return;
    }
    var max = demoMaxStep(stage);
    if (this.reducedMotion()) {
      st.step = max;
      this.refresh(stage);
      return;
    }
    if (st.step >= max) st.step = 0;
    st.playing = true;
    this.refresh(stage);
    var self = this;
    st.timer = setInterval(function() { self._tick(stage); }, DEMO_STEP_MS);
  },

  /**
   * Pauses in place: timer cleared, step kept, Play button shows Pause
   * state until resumed. Resume continues from the kept step.
   */
  pause: function(stage) {
    var st = this.stageState(stage);
    if (st.timer !== null && typeof clearInterval !== 'undefined') clearInterval(st.timer);
    st.timer = null;
    st.playing = false;
    this.refresh(stage);
  },

  replay: function(stage) {
    this.stop(stage);
    this.stageState(stage).step = 0;
    this.play(stage);
  },

  goToStep: function(stage, i) {
    var st = this.stageState(stage);
    st.step = demoClampStep(i, DEMO_STEP_COUNT[stage] || 4);
    this.refresh(stage);
  },

  stop: function(stage) {
    var st = this.stageState(stage);
    if (st.timer !== null && typeof clearInterval !== 'undefined') clearInterval(st.timer);
    st.timer = null;
    st.playing = false;
  },

  stopAll: function() {
    var self = this;
    Object.keys(this._st).forEach(function(stage) { self.stop(stage); });
  },

  _tick: function(stage) {
    var st = this.stageState(stage);
    var max = demoMaxStep(stage);
    if (st.step >= max) {
      this.stop(stage);
      return;
    }
    st.step += 1;
    this.refresh(stage);
  },

  refresh: function(stage) {
    var doc = demoDoc();
    if (!doc) return;
    var mount = null;
    if (doc.querySelectorAll) {
      var mounts = doc.querySelectorAll('#expert-demo-mount');
      for (var m = 0; m < mounts.length; m++) {
        if (mounts[m].getAttribute && mounts[m].getAttribute('data-stage') === stage) {
          mount = mounts[m];
          break;
        }
      }
    } else {
      mount = doc.getElementById('expert-demo-mount');
    }
    if (!mount || (mount.getAttribute && mount.getAttribute('data-stage') !== stage)) return;
    var st = this.stageState(stage);
    var live = st.live || demoLiveValues(stage, {});
    var outcome = st.outcome === 'B' ? 'B' : 'A';
    var diagram = doc.getElementById('expert-demo-diagram-' + stage);
    var cap = doc.getElementById('expert-demo-cap-' + stage);
    if (diagram) diagram.innerHTML = demoDiagramHtml(stage, st.step, live, outcome, st.scenario === 'B' ? 'B' : 'A');
    if (cap) cap.textContent = demoStepCaption(stage, st.step, { outcome: outcome, winner: live.winner, gate: live.gate, scenario: st.scenario === 'B' ? 'B' : 'A', hasIf: !!live.hasIf, ifScore: live.ifScore, ifThr: live.ifThr });
    var playBtn = doc.getElementById('expert-demo-play-' + stage);
    if (playBtn) {
      playBtn.textContent = st.playing ? 'Pause' : 'Play';
      if (st.playing) playBtn.setAttribute('aria-pressed', 'true');
      else playBtn.removeAttribute('aria-pressed');
    }
    var dots = mount.querySelectorAll('[data-demo-action="goto"]');
    for (var i = 0; i < dots.length; i++) {
      var on = parseInt(dots[i].getAttribute('data-demo-step'), 10) === st.step;
      if (on) dots[i].setAttribute('aria-current', 'true');
      else dots[i].removeAttribute('aria-current');
      if (dots[i].classList) dots[i].classList.toggle('on', on);
    }
    var outs = mount.querySelectorAll('[data-demo-action="outcome"]');
    for (var k = 0; k < outs.length; k++) {
      var active = outs[k].getAttribute('data-demo-outcome') === outcome;
      if (outs[k].classList) outs[k].classList.toggle('on', active);
      if (active) outs[k].setAttribute('aria-pressed', 'true');
      else outs[k].removeAttribute('aria-pressed');
    }
    var scens = mount.querySelectorAll('[data-demo-action="scenario"]');
    var scenVal = st.scenario === 'B' ? 'B' : 'A';
    for (var q = 0; q < scens.length; q++) {
      var sactive = scens[q].getAttribute('data-demo-scenario') === scenVal;
      if (scens[q].classList) scens[q].classList.toggle('on', sactive);
      if (sactive) scens[q].setAttribute('aria-pressed', 'true');
      else scens[q].removeAttribute('aria-pressed');
    }
  },

  /**
   * Detaches the live demo mount before a body rewrite so the node,
   * its step state, focus, and transitions survive the tick.
   */
  detachDemo: function(bodyEl) {
    this._kept = { node: null, stage: null };
    if (!bodyEl || !bodyEl.querySelector) return this._kept;
    var mount = bodyEl.querySelector('#expert-demo-mount');
    if (!mount) return this._kept;
    var stage = mount.getAttribute ? mount.getAttribute('data-stage') : null;
    if (mount.parentNode) mount.parentNode.removeChild(mount);
    this._kept = { node: mount, stage: stage };
    return this._kept;
  },

  /**
   * Restores the kept mount into the fresh slot, or builds it when the
   * stage changed. Always finishes with a live sync.
   */
  restoreDemo: function(bodyEl, stage, d) {
    if (!bodyEl || !bodyEl.querySelector) return;
    var slot = bodyEl.querySelector('#expert-demo-slot');
    if (!slot) return;
    if (this._kept.node && this._kept.stage === stage) {
      slot.appendChild(this._kept.node);
      this._kept = { node: null, stage: null };
    } else {
      this.stop(stage);
      this._kept = { node: null, stage: null };
      slot.innerHTML = demoShellHtml(stage, this.stageState(stage), d);
    }
    this.syncLive(stage, d);
  },

  /**
   * Writes only live bound nodes. Never reads layout, never restarts play.
   */
  syncLive: function(stage, d) {
    var doc = demoDoc();
    if (!doc) return;
    var live = demoLiveValues(stage, d);
    var st = this.stageState(stage);
    st.live = live;
    if (stage === 'rf' && st.outcome === null && d && d.rf && (d.rf.recent_classifications || []).length) {
      var top = null;
      (d.rf.recent_classifications || []).forEach(function(c) {
        if (!top && c.attack_class && c.attack_class !== 'Uncertain') top = c;
      });
      var conf = top && typeof top.conf === 'number' ? top.conf : 0;
      st.outcome = conf >= live.gate ? 'A' : 'B';
    }
    var status = doc.getElementById('expert-demo-status-' + stage);
    if (status) status.textContent = demoSummaryStatus(stage, live);
    var strip = doc.getElementById('expert-demo-live-' + stage);
    if (strip) strip.innerHTML = demoLiveStripHtml(stage, live);
  }
};

if (typeof window !== 'undefined') {
  window.ExpertDemos = ExpertDemos;
  if (typeof document !== 'undefined' && document.addEventListener && !window.__expertDemosWired) {
    window.__expertDemosWired = true;
    document.addEventListener('click', function(e) {
      var t = e.target && e.target.closest ? e.target.closest('[data-demo-action]') : null;
      if (!t) return;
      var action = t.getAttribute('data-demo-action');
      var stage = t.getAttribute('data-demo-stage');
      if (!action || !stage) return;
      if (action === 'play') ExpertDemos.play(stage);
      else if (action === 'replay') ExpertDemos.replay(stage);
      else if (action === 'outcome') ExpertDemos.setOutcome(stage, t.getAttribute('data-demo-outcome'));
      else if (action === 'scenario') ExpertDemos.setScenario(stage, t.getAttribute('data-demo-scenario'));
      else if (action === 'goto') ExpertDemos.goToStep(stage, parseInt(t.getAttribute('data-demo-step'), 10));
    });
    document.addEventListener('visibilitychange', function() {
      if (document.hidden) ExpertDemos.stopAll();
    });
    window.addEventListener('beforeprint', function() {
      document.querySelectorAll('details.expert-demo').forEach(function(d) {
        d.setAttribute('open', '');
      });
    });
  }
}
