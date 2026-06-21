// Plain-language explanations — no jargon, for non-technical users
const _FEAT_TOOLTIPS = {
  "Flow Rate (pps)": "Packets transmitted per second for this flow. Flood attacks are characterized by abnormally high packet rates compared to legitimate traffic baselines.",
  "Byte Rate":       "Volume of data transmitted per second. A sharp increase indicates potential bandwidth exhaustion, a primary goal of volumetric DDoS attacks.",
  "Bytes / Packet":  "Average packet size (byte count ÷ packet count). Each attack type tends to produce a consistent packet size signature, useful for classification.",
  "Port Entropy":    "Ratio of source port activity to destination port activity. UDP floods often spray traffic across many ports, producing a distinct ratio compared to normal traffic.",
  "Pkt Size Uniformity": "A model-derived measure of how consistent packet sizes are within this flow. SYN packets carry no payload, so a SYN flood produces near-identical packet sizes, a low, tightly clustered value here.",
  "Packet Count":    "Cumulative packets observed in this flow. Rapid accumulation within a short window is a strong indicator of flooding behavior.",
  "Byte Count":      "Cumulative data volume observed in this flow, in bytes.",
};

// ── Attack summaries — plain language, per attack type ─────
const _ATTACK_CONTEXT = {
  "ICMP Flood": {
    color: 'var(--red,#ff3d5a)',
    desc: 'An ICMP Flood overwhelms the target with a high volume of ping (echo request) packets, consuming bandwidth and processing resources until legitimate traffic can no longer be served.',
    rows: [
      ['Flow Rate (pps)', 'Very high', 'Sending way more pings than normal'],
      ['Byte Rate',       'Moderate',  'Small messages, but a lot of them'],
      ['Bytes / Packet',  'Fixed size','Matches a typical ping packet'],
    ],
  },
  "SYN Flood": {
    color: 'var(--red,#ff3d5a)',
    desc: 'A SYN Flood exploits the TCP three-way handshake by initiating many connections without completing them, exhausting the server\'s connection table and denying service to legitimate users.',
    rows: [
      ['Flow Rate (pps)', 'Very high', 'Opening connections rapidly'],
      ['Bytes / Packet',  'Small',     'Just a connection request, no data'],
      ['Byte Rate',       'Low',       'Small packets despite the high rate'],
    ],
  },
  "UDP Flood": {
    color: 'var(--amber,#ffb02e)',
    desc: 'A UDP Flood sends a high volume of connectionless packets to random or targeted ports, forcing the target to process and respond to traffic that consumes bandwidth with no legitimate purpose.',
    rows: [
      ['Byte Rate',       'Very high', 'Sending a lot of data quickly'],
      ['Bytes / Packet',  'Large',     'Each message carries more data'],
      ['Flow Rate (pps)', 'High',      'Frequent messages'],
    ],
  },
  "Anomalous": {
    color: 'var(--sub2,#8890b0)',
    desc: 'Traffic deviates from the established normal baseline but does not match a known attack signature with sufficient confidence for classification.',
    rows: [
      ['Flow Rate (pps)', 'Elevated',  'Higher than typical traffic'],
    ],
  },
  "Uncertain": {
    color: 'var(--sub,#5c6080)',
    desc: 'The anomaly detector flagged this traffic, but classifier confidence fell below the threshold required to assign a specific attack label.',
    rows: [],
  },
};

// ── Build drawer DOM ──────────────────────────────────────────────────────────
(function _initDrawerDOM() {
  const overlay = document.createElement('div');
  overlay.id = 'ip-drawer-overlay';
  overlay.onclick = () => closeIpDrawer();
  overlay.style.cssText = [
    'display:none','position:fixed','top:0','left:0','right:0','bottom:0',
    'z-index:9990','background:rgba(0,0,0,0.45)',
    'backdrop-filter:blur(4px)','-webkit-backdrop-filter:blur(4px)',
  ].join(';');
  document.body.appendChild(overlay);

  const drawer = document.createElement('div');
  drawer.id = 'ip-drawer';
  drawer.setAttribute('aria-hidden', 'true');
  drawer.style.cssText = [
    'position:fixed','top:50%','left:50%',
    'transform:translate(-50%,-48%) scale(0.97)',
    'width:700px','max-height:88vh','z-index:9991',
    'display:flex','flex-direction:column','overflow:hidden',
    'transition:opacity 0.2s ease, transform 0.2s ease',
    'opacity:0','pointer-events:none',
    /* Theme-aware: uses CSS vars, falls back to dark */
    'background:var(--card,#fff)',
    'border:1px solid var(--border2,#e2e4ed)',
    'border-radius:16px',
    'box-shadow:0 24px 80px rgba(0,0,0,0.18)',
  ].join(';');

  drawer.innerHTML = `
    <!-- Header -->
    <div id="idd-head" style="display:flex;align-items:flex-start;justify-content:space-between;
         padding:20px 22px 14px;border-bottom:1px solid var(--border,#eef0f6);flex-shrink:0">
      <div style="display:flex;flex-direction:column;gap:5px">
        <div style="font-size:10px;font-weight:700;letter-spacing:.14em;color:var(--sub,#9499b7);
             font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase">Threat Analysis</div>
        <div style="display:flex;align-items:center;gap:10px">
          <div id="idd-ip" style="font-family:var(--mono,'Space Mono',monospace);font-size:21px;
               font-weight:700;color:var(--text,#1a1d2e);letter-spacing:-.3px">--</div>
          <div id="idd-status-badge"></div>
        </div>
      </div>
      <button id="idd-close-btn"
        style="background:none;border:1px solid var(--border2,#e2e4ed);color:var(--sub,#9499b7);
               border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:14px;
               display:flex;align-items:center;justify-content:center;flex-shrink:0;
               margin-top:2px;font-family:monospace;line-height:1;padding:0;transition:all .15s"
        onmouseover="this.style.borderColor='var(--red,#ff3d5a)';this.style.color='var(--red,#ff3d5a)'"
        onmouseout="this.style.borderColor='var(--border2,#e2e4ed)';this.style.color='var(--sub,#9499b7)'"
        onclick="closeIpDrawer()" title="Close (Esc)">x</button>
    </div>

    <!-- Loading -->
    <div id="idd-loading" style="display:none;flex:1;align-items:center;justify-content:center;
         gap:12px;color:var(--sub,#9499b7);font-size:12px;
         font-family:var(--mono,'Space Mono',monospace);padding:32px">
      <div id="idd-spinner" style="width:16px;height:16px;border:2px solid var(--border2,#e2e4ed);
           border-top-color:var(--blue,#3d6cff);border-radius:50%;
           animation:idd-spin .7s linear infinite;flex-shrink:0"></div>
      <span>Fetching data...</span>
    </div>

    <!-- Error -->
    <div id="idd-error" style="display:none;flex:1;flex-direction:column;align-items:center;
         justify-content:center;padding:32px;gap:12px;text-align:center">
      <div style="font-size:24px;color:var(--red,#ff3d5a);font-weight:700">!</div>
      <div id="idd-error-msg"
           style="font-family:var(--mono,'Space Mono',monospace);font-size:11px;
                  color:var(--red,#ff3d5a);line-height:1.8;white-space:pre-wrap;text-align:left;
                  background:rgba(255,61,90,.06);border:1px solid rgba(255,61,90,.2);
                  border-radius:10px;padding:14px 18px;max-width:340px">
        No data available for this IP.
      </div>
    </div>

    <!-- Content -->
    <div id="idd-content" style="display:none;flex:1;overflow-y:auto;padding:18px 22px 36px">

      <!-- Verdict banner -->
      <div id="idd-verdict" style="border-radius:9px;padding:11px 15px;margin-bottom:8px;
           font-size:12px;font-family:var(--mono,'Space Mono',monospace);font-weight:700;
           display:flex;align-items:center;gap:8px;letter-spacing:.02em"></div>

      <!-- Attack description -->
      <div id="idd-desc" style="font-size:12px;line-height:1.6;color:var(--sub2,#6b7190);
           margin-bottom:16px"></div>

      <!-- State pills -->
      <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#9499b7);
           font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;
           margin-bottom:9px">State</div>
      <div id="idd-history" style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:16px;
           padding-bottom:14px;border-bottom:1px solid var(--border,#eef0f6)"></div>

      <!-- IF model signal cards -->
      <div id="idd-if-header" style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
              padding:2px 8px;border-radius:4px;
              background:rgba(61,108,255,.1);color:var(--blue,#3d6cff);
              border:1px solid rgba(61,108,255,.25);
              font-family:var(--mono,'Space Mono',monospace)">IF Model Signals</span>
        <span id="idd-if-subtitle" style="font-size:10px;color:var(--sub,#9499b7);
              font-family:var(--mono,'Space Mono',monospace)"></span>
      </div>
      <div id="idd-if-features" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:7px;margin-bottom:16px"></div>

      <!-- RF model signal cards -->
      <div id="idd-rf-header" style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
              padding:2px 8px;border-radius:4px;
              background:rgba(255,176,46,.1);color:var(--amber,#ffb02e);
              border:1px solid rgba(255,176,46,.25);
              font-family:var(--mono,'Space Mono',monospace)">RF Model Signals</span>
        <span id="idd-rf-subtitle" style="font-size:10px;color:var(--sub,#9499b7);
              font-family:var(--mono,'Space Mono',monospace)"></span>
      </div>
      <div id="idd-rf-features" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:7px;margin-bottom:16px"></div>

      <!-- ML evaluation bars -->
      <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#9499b7);
           font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;
           margin-bottom:9px">ML Evaluation</div>
      <div id="idd-ml" style="display:flex;flex-direction:column;gap:12px;margin-bottom:16px"></div>

      <!-- Mitigation pipeline -->
      <div style="font-size:10px;font-weight:700;letter-spacing:.12em;color:var(--sub,#9499b7);
           font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;
           margin-bottom:9px">Mitigation Pipeline</div>
      <div id="idd-pipeline" style="margin-bottom:14px"></div>

    </div>`;

  document.body.appendChild(drawer);

  /* Shared tooltip singleton */
  const tip = document.createElement('div');
  tip.id = 'idd-tooltip';
  tip.style.cssText = [
    'position:fixed','z-index:9999','pointer-events:none',
    'background:var(--card,#fff)','border:1px solid var(--border2,#e2e4ed)',
    'border-radius:8px','padding:9px 13px','max-width:240px',
    'font-size:11px','line-height:1.55','color:var(--sub2,#6b7190)',
    'font-family:var(--mono,monospace)','display:none',
    'box-shadow:0 6px 20px rgba(0,0,0,0.12)','white-space:pre-line',
  ].join(';');
  document.body.appendChild(tip);

  /* Inject keyframes + utility classes */
  if (!document.getElementById('idd-style')) {
    const st = document.createElement('style');
    st.id = 'idd-style';
    st.textContent = `
      @keyframes idd-spin { to { transform:rotate(360deg) } }
      @keyframes idd-pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
      #ip-drawer-overlay { cursor:pointer }
      .idd-fc { cursor:help; transition:border-color .14s, box-shadow .14s }
      .idd-fc:hover { border-color:var(--blue,#3d6cff) !important;
                      box-shadow:0 0 0 2px rgba(61,108,255,.12) !important }
      #ip-drawer { scrollbar-width:thin; scrollbar-color:var(--border2,#e2e4ed) transparent }
    `;
    document.head.appendChild(st);
  }
})();

// ── State ─────────────────────────────────────────────────────────────────────
let _drawerCurrentIp = null;
let _drawerLiveTimer = null;
let _drawerIsLive    = false;

// ── Public API ────────────────────────────────────────────────────────────────
function openIpDrawer(ip) {
  if (!ip || ip === '--') return;
  _drawerCurrentIp = ip;
  document.getElementById('idd-ip').textContent = ip;
  document.getElementById('idd-status-badge').innerHTML = '';
  _iddShow('loading');

  const overlay = document.getElementById('ip-drawer-overlay');
  const drawer  = document.getElementById('ip-drawer');
  overlay.style.display      = 'block';
  drawer.style.pointerEvents = 'all';
  drawer.style.opacity       = '1';
  drawer.style.transform     = 'translate(-50%,-50%) scale(1)';
  drawer.setAttribute('aria-hidden', 'false');

  _fetchIpDetail(ip);
}

function closeIpDrawer() {
  _stopLivePolling();
  _drawerCurrentIp = null;
  const overlay = document.getElementById('ip-drawer-overlay');
  const drawer  = document.getElementById('ip-drawer');
  if (overlay) overlay.style.display = 'none';
  if (drawer) {
    drawer.style.opacity       = '0';
    drawer.style.transform     = 'translate(-50%,-48%) scale(0.97)';
    drawer.style.pointerEvents = 'none';
    drawer.setAttribute('aria-hidden', 'true');
  }
  const tip = document.getElementById('idd-tooltip');
  if (tip) tip.style.display = 'none';
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && _drawerCurrentIp) closeIpDrawer();
});

window.openIpDrawer  = openIpDrawer;
window.closeIpDrawer = closeIpDrawer;

// ── Live polling ──────────────────────────────────────────────────────────────

function _startLivePolling(ip) {
  _stopLivePolling();
  _drawerIsLive = true;
  _drawerLiveTimer = setInterval(async () => {
    if (_drawerCurrentIp !== ip) { _stopLivePolling(); return; }
    try {
      const r = await fetch(window.API_URL + `/api/ip_detail/${encodeURIComponent(ip)}/live`);
      if (r.status === 404) {
        /* IP released — switch to historical */
        _stopLivePolling();
        _setBadge(false);
        if (typeof showToast === 'function') showToast(`${ip} released`);
        const full = await fetch(window.API_URL + `/api/ip_detail/${encodeURIComponent(ip)}`);
        if (full.ok) _renderIpDetail(await full.json());
        return;
      }
      if (!r.ok) return;
      const data = await r.json();
      if (_drawerCurrentIp !== ip) return;
      _updateLiveSection(data);
    } catch (_) {}
  }, 2000);
}

function _stopLivePolling() {
  if (_drawerLiveTimer) { clearInterval(_drawerLiveTimer); _drawerLiveTimer = null; }
  _drawerIsLive = false;
}

// ── Fetch & render ────────────────────────────────────────────────────────────

async function _fetchIpDetail(ip) {
  try {
    const r = await fetch(window.API_URL + `/api/ip_detail/${encodeURIComponent(ip)}`);
    if (!r.ok) throw r;
    const data = await r.json();
    if (_drawerCurrentIp !== ip) return;
    _renderIpDetail(data);
    if (data.is_live) _startLivePolling(ip);
  } catch (err) {
    if (_drawerCurrentIp !== ip) return;

    /* DOM fallback from quarantine table rows */
    const qRow = typeof _qRows !== 'undefined' ? _qRows.get(ip) : null;
    if (qRow) {
      const cells = qRow.querySelectorAll('td');
      const fallback = {
        src_ip: ip, is_live: false,
        features: { pkt_count:0, pps:0, byte_rate:0, duration_sec:0,
                    byte_count:0, port_entropy:0 },
        ml:    { if_score: parseFloat(cells[3]?.textContent)||0,
                 is_anomaly: true,
                 attack_class: cells[2]?.textContent.trim()||'--',
                 confidence: parseFloat(cells[4]?.textContent)||0 },
        state: { phase:'--', priority:'--', action_taken:'Quarantined',
                 offence_count:0, reputation_score:0, ban_level:0, first_seen:null },
        thresholds: { if_threshold:null, rf_conf_gate:null },
        phase_history: [],
      };
      if (typeof showToast === 'function') showToast(`Cached data for ${ip}`);
      _renderIpDetail(fallback);
      return;
    }

    const status = err && err.status;
    document.getElementById('idd-error-msg').textContent = status === 404
      ? `404 - No data found for ${ip}\nFlow data expired or IP was released.`
      : status
        ? `HTTP ${status} - /api/ip_detail/${ip}`
        : `Network error - is Flask running?`;
    _iddShow('error');
    if (typeof showToast === 'function')
      showToast(`Drawer: ${status ? 'HTTP '+status : 'network error'} for ${ip}`, true);
  }
}

// ── Badge helpers ─────────────────────────────────────────────────────────────

function _setBadge(isLive) {
  const el = document.getElementById('idd-status-badge');
  if (!el) return;
  if (isLive) {
    el.innerHTML = `
      <span style="display:inline-flex;align-items:center;gap:5px;
           background:rgba(0,214,143,.1);border:1px solid rgba(0,214,143,.28);
           border-radius:5px;padding:3px 8px;font-size:10px;font-weight:700;
           font-family:var(--mono,monospace);color:var(--green,#00d68f);letter-spacing:.08em">
        <span style="width:5px;height:5px;border-radius:50%;background:var(--green,#00d68f);
             animation:idd-pulse 1.4s ease-in-out infinite;display:inline-block"></span>
        LIVE
      </span>`;
  } else {
    el.innerHTML = `
      <span style="display:inline-flex;align-items:center;
           background:rgba(148,153,183,.08);border:1px solid rgba(148,153,183,.22);
           border-radius:5px;padding:3px 8px;font-size:10px;font-weight:700;
           font-family:var(--mono,monospace);color:var(--sub,#9499b7);letter-spacing:.08em">
        HISTORICAL
      </span>`;
  }
}

// ── Live section partial update ───────────────────────────────────────────────

function _updateLiveSection(data) {
  /* Only refresh parts that change — pipeline/history are static per session */
  const f  = data.features || {};
  const ml = data.ml       || {};
  const st = data.state    || {};
  _renderFeatureSignals(f, ml.attack_class);
  _renderMlBars(ml, data.thresholds || {});
  _renderHistoryPills(st);
}

// ── Full render ───────────────────────────────────────────────────────────────

function _renderIpDetail(d) {
  const f  = d.features   || {};
  const ml = d.ml         || {};
  const st = d.state      || {};
  const th = d.thresholds || {};

  _setBadge(!!d.is_live);

  /* Verdict banner */
  const isAnomaly = ml.is_anomaly;
  const acColor   = isAnomaly ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)';
  const verdict   = document.getElementById('idd-verdict');
  verdict.style.cssText = `border-radius:9px;padding:11px 15px;margin-bottom:8px;font-size:12px;
    font-family:var(--mono,'Space Mono',monospace);font-weight:700;
    display:flex;align-items:center;gap:8px;letter-spacing:.02em;
    background:${isAnomaly ? 'rgba(255,61,90,.07)' : 'rgba(0,214,143,.07)'};
    border:1px solid ${isAnomaly ? 'rgba(255,61,90,.22)' : 'rgba(0,214,143,.2)'};
    color:${acColor}`;
  verdict.innerHTML = isAnomaly
    ? `<span style="font-size:12px;font-weight:900;letter-spacing:.06em">ANOMALY</span>
       <span style="color:var(--sub,#9499b7);font-weight:400">|</span>
       ${ml.attack_class || 'Unknown'}`
    : `<span style="font-size:12px;font-weight:900;letter-spacing:.06em">NORMAL TRAFFIC</span>`;

  /* Attack description line */
  const descEl = document.getElementById('idd-desc');
  const ctx = _ATTACK_CONTEXT[ml.attack_class];
  descEl.textContent = isAnomaly && ctx ? ctx.desc : '';

  _renderFeatureSignals(f, ml.attack_class);
  _renderMlBars(ml, th);
  _renderPipeline(d, ml, st, isAnomaly);
  _renderHistoryPills(st);

  _iddShow('content');
}

// ── IF/RF signal thresholds per attack class (based on Juniper + research) ────

// ── Feature thresholds per attack type ──────────────────────
// Each entry: which raw value to read, how to format it, and
// when to flag it red (alert). No subtext — keep cards simple.
const _SIGNAL_CONFIG = {
  "ICMP Flood": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,   bar: v => Math.min(v/50000,1) },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 51200, bar: v => Math.min(v/1e7,1)   },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => v > 0 && v < 100, bar: v => Math.min(v/1500,1) },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => v > 0 && v < 100, bar: v => Math.min(v/1500,1) },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000,        bar: v => Math.min(v/1e6,1)  },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,          bar: v => Math.min(v/1e9,1)  },
    ],
  },
  "SYN Flood": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,  bar: v => Math.min(v/50000,1) },
      { key:'pkt_size_uniformity', label:'Pkt Size Uniformity', fmt: v => v.toFixed(3), alert: v => v < 0.05, bar: v => Math.min(v/0.5,1) },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 5120, bar: v => Math.min(v/1e7,1)   },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => v > 0 && v < 70, bar: v => Math.min(v/1500,1) },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000,       bar: v => Math.min(v/1e6,1)  },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,         bar: v => Math.min(v/1e9,1)  },
    ],
  },
  "UDP Flood": {
    if: [
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 512000, bar: v => Math.min(v/1e7,1)   },
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,    bar: v => Math.min(v/50000,1) },
      { key:'port_entropy', label:'Port Entropy',    fmt: v => v.toFixed(2),                                                     alert: v => v > 1,      bar: v => Math.min(v/5,1)     },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => v > 200,   bar: v => Math.min(v/1500,1) },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000, bar: v => Math.min(v/1e6,1)  },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,   bar: v => Math.min(v/1e9,1)  },
    ],
  },
  "Anomalous": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,   bar: v => Math.min(v/50000,1) },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => false,     bar: v => Math.min(v/1500,1)  },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 51200, bar: v => Math.min(v/1e7,1)   },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => false,     bar: v => Math.min(v/1500,1) },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000, bar: v => Math.min(v/1e6,1)  },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,   bar: v => Math.min(v/1e9,1)  },
    ],
  },
  "Uncertain": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,   bar: v => Math.min(v/50000,1) },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 51200, bar: v => Math.min(v/1e7,1)   },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => false,     bar: v => Math.min(v/1500,1)  },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => false,     bar: v => Math.min(v/1500,1) },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000, bar: v => Math.min(v/1e6,1)  },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,   bar: v => Math.min(v/1e9,1)  },
    ],
  },
};

/* Renders one feature card for IF or RF row */
function _mkSignalCard(feat, val, isIF) {
  const isAlert  = feat.alert(val);
  const barPct   = (feat.bar(val) * 100).toFixed(1);
  const accentCol = isIF ? 'var(--blue,#3d6cff)' : 'var(--amber,#ffb02e)';
  const valCol   = isAlert ? 'var(--red,#ff3d5a)' : accentCol;
  const borderCol = isAlert ? 'var(--red,#ff3d5a)' : accentCol;
  const glowRgb  = isAlert ? '255,61,90' : (isIF ? '61,108,255' : '255,176,46');
  const tag      = isAlert
    ? `<span style="font-size:8px;font-weight:700;color:var(--red,#ff3d5a);
            background:rgba(255,61,90,.1);border:1px solid rgba(255,61,90,.3);
            border-radius:3px;padding:1px 4px;flex-shrink:0">ALERT</span>`
    : `<span style="font-size:8px;font-weight:700;color:var(--green,#00d68f);
            background:rgba(0,214,143,.08);border:1px solid rgba(0,214,143,.25);
            border-radius:3px;padding:1px 4px;flex-shrink:0">OK</span>`;
  const tip = (_FEAT_TOOLTIPS[feat.label] || '').replace(/'/g,"&#39;");
  return `
    <div class="idd-fc"
         style="background:var(--surface,#f7f8fc);border-radius:9px;padding:10px 13px;
                border:1px solid ${borderCol};box-shadow:0 0 0 2px rgba(${glowRgb},.1)"
         data-tip="${tip}"
         onmouseenter="_iddShowTip(event,this.dataset.tip)"
         onmouseleave="_iddHideTip()">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px">
        <div style="font-size:9px;color:var(--sub,#9499b7);
             font-family:var(--mono,'Space Mono',monospace);
             white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:70%">${feat.label}</div>
        ${tag}
      </div>
      <div style="font-family:var(--mono,'Space Mono',monospace);font-size:13px;font-weight:700;
           color:${valCol};margin-bottom:6px">${feat.fmt(val)}</div>
      <div style="height:2px;background:var(--border2,#e2e4ed);border-radius:1px;overflow:hidden">
        <div style="height:100%;width:${barPct}%;
             background:${isAlert ? 'var(--red,#ff3d5a)' : accentCol};
             transition:width .4s;border-radius:1px"></div>
      </div>
    </div>`;
}

/* Main entry: renders both IF and RF signal rows */
function _renderFeatureSignals(f, attackClass) {
  const pktCount = f.pkt_count  || 0;
  const bytCount = f.byte_count || 0;
  const bpp      = pktCount > 0 ? bytCount / pktCount : 0;

  /* Flat feature lookup by key */
  const vals = {
    pps:         f.pps          || 0,
    byte_rate:   f.byte_rate    || 0,
    duration_sec:f.duration_sec || 0,
    pkt_count:   pktCount,
    byte_count:  bytCount,
    bpp:         bpp,
    port_entropy:f.port_entropy || 0,
    pkt_size_uniformity: f.pkt_size_uniformity || 0,
  };

  const cfg = _SIGNAL_CONFIG[attackClass] || _SIGNAL_CONFIG['Uncertain'];

  /* subtitle shows attack class name */
  const subtitle = attackClass && attackClass !== '--' ? `Key features for ${attackClass}` : 'Key features';
  const ifSub = document.getElementById('idd-if-subtitle');
  const rfSub = document.getElementById('idd-rf-subtitle');
  if (ifSub) ifSub.textContent = subtitle;
  if (rfSub) rfSub.textContent = subtitle;

  const ifEl = document.getElementById('idd-if-features');
  const rfEl = document.getElementById('idd-rf-features');
  if (ifEl) ifEl.innerHTML = cfg.if.map(feat => _mkSignalCard(feat, vals[feat.key], true)).join('');
  if (rfEl) rfEl.innerHTML = cfg.rf.map(feat => _mkSignalCard(feat, vals[feat.key], false)).join('');
}

// ── ML evaluation bars ────────────────────────────────────────────────────────

function _renderMlBars(ml, th) {
  const ifScore  = ml.if_score   || 0;
  const rfConf   = ml.confidence || 0;
  const ifThrVal = th.if_threshold  != null ? th.if_threshold  : null;
  const rfGate   = th.rf_conf_gate  != null ? th.rf_conf_gate  : null;

  const ifPct  = ifThrVal ? Math.min((ifScore / Math.max(ifThrVal * 2, 1)) * 100, 100)
                           : Math.min(ifScore * 100, 100);
  const rfPct  = Math.min(rfConf, 100);
  const ifOver = ifThrVal != null ? ifScore >= ifThrVal : false;
  const rfOver = rfGate   != null ? rfConf  >= rfGate * 100 : false;

  const ifThrLabel = ifThrVal != null
    ? `Threshold ${ifThrVal.toFixed(4)} ${ifOver ? '— score exceeds threshold' : '— score below threshold'}`
    : 'Threshold: not available';
  const rfThrLabel = rfGate != null
    ? `Threshold ${(rfGate * 100).toFixed(0)}% ${rfOver ? '— confirms attack class' : '— below confirmation threshold'}`
    : 'Threshold: not available';

  /* IF bar: scale so threshold sits at 50% visual position */
  const ifScale  = ifThrVal ? ifThrVal * 2 : 1;
  const ifBarPct = Math.min((ifScore / ifScale) * 100, 100);
  const ifThrPct = ifThrVal ? Math.min((ifThrVal / ifScale) * 100, 100) : 50;

  document.getElementById('idd-ml').innerHTML = `
    <div>
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px">
        <span style="font-size:11px;color:var(--sub2,#6b7190);
              font-family:var(--mono,'Space Mono',monospace)">Isolation Forest (Anomaly Score)</span>
        <span style="font-family:var(--mono,'Space Mono',monospace);font-size:13px;font-weight:700;
              color:${ifOver ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)'}">${ifScore.toFixed(4)}</span>
      </div>
      <div style="height:5px;background:var(--border2,#e2e4ed);border-radius:3px;
           overflow:visible;margin-bottom:4px;position:relative">
        <div style="height:100%;width:${ifBarPct}%;background:${ifOver ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)'};
             transition:width .5s;border-radius:3px"></div>
        ${ifThrVal != null ? `<div style="position:absolute;top:-4px;left:${ifThrPct}%;
             width:2px;height:13px;background:rgba(255,61,90,.7);border-radius:1px;
             transform:translateX(-50%)"></div>` : ''}
      </div>
      <div style="font-size:10px;color:${ifOver ? 'var(--red,#ff3d5a)' : 'var(--sub,#9499b7)'};
           font-family:var(--mono,'Space Mono',monospace)">${ifThrLabel}</div>
    </div>
    <div>
      <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px">
        <span style="font-size:11px;color:var(--sub2,#6b7190);
              font-family:var(--mono,'Space Mono',monospace)">Random Forest (Attack Probability)</span>
        <span style="font-family:var(--mono,'Space Mono',monospace);font-size:13px;font-weight:700;
              color:${rfOver ? 'var(--red,#ff3d5a)' : 'var(--amber,#ffb02e)'}">${rfConf.toFixed(1)}%</span>
      </div>
      <div style="height:5px;background:var(--border2,#e2e4ed);border-radius:3px;
           overflow:visible;margin-bottom:4px;position:relative">
        <div style="height:100%;width:${rfPct}%;background:${rfOver ? 'var(--red,#ff3d5a)' : 'var(--amber,#ffb02e)'};
             transition:width .5s;border-radius:3px"></div>
        ${rfGate != null ? `<div style="position:absolute;top:-4px;left:50%;
             width:2px;height:13px;background:rgba(255,61,90,.7);border-radius:1px;
             transform:translateX(-50%)"></div>` : ''}
      </div>
      <div style="font-size:10px;color:${rfOver ? 'var(--red,#ff3d5a)' : 'var(--sub,#9499b7)'};
           font-family:var(--mono,'Space Mono',monospace)">${rfThrLabel}</div>
    </div>`;
}

// ── Mitigation pipeline ───────────────────────────────────────────────────────

function _actionColor(a) {
  if (/blackhole|block/i.test(a))  return 'var(--red,#ff3d5a)';
  if (/ban/i.test(a))              return 'var(--amber,#ffb02e)';
  if (/quarantine/i.test(a))       return 'var(--amber,#ffb02e)';
  if (/rate.limit/i.test(a))       return 'var(--blue,#3d6cff)';
  return 'var(--sub2,#6b7190)';
}

function _renderPipeline(d, ml, st, isAnomaly) {
  const phaseHistory = d.phase_history || [];
  const pipelineEl   = document.getElementById('idd-pipeline');

  /* Fixed first 3 steps — always the same */
  const baseSteps = [
    { label:'SDN Switch',    sub:'Traffic Ingress',   color:'var(--blue,#3d6cff)' },
    { label:ml.attack_class||'--', sub:'Feature Extractor', color:'var(--blue,#3d6cff)' },
    { label:isAnomaly ? 'Anomalous' : 'Normal',
      sub:'Decision Engine',
      color:isAnomaly ? 'var(--red,#ff3d5a)' : 'var(--green,#00d68f)' },
  ];

  /* Step 4 = current/latest phase only — never add more */
  let step4 = null;
  if (d.is_live) {
    /* Live: show current phase as the live step */
    step4 = {
      label: st.action_taken || '--',
      sub:   st.phase        || 'Active',
      color: _actionColor(st.action_taken || ''),
      ts:    '',
      live:  true,
    };
  } else if (phaseHistory.length) {
    /* Historical: show only the LATEST phase entry */
    const last = phaseHistory[phaseHistory.length - 1];
    step4 = {
      label: last.action_taken || '--',
      sub:   last.phase ? `Phase ${last.phase}` : 'Action',
      color: _actionColor(last.action_taken || ''),
      ts:    last.timestamp ? last.timestamp.slice(11, 19) : '',
      live:  false,
    };
  } else if (st.action_taken && st.action_taken !== '--') {
    step4 = {
      label: st.action_taken,
      sub:   st.phase || 'Action',
      color: _actionColor(st.action_taken),
      ts:    '',
      live:  false,
    };
  }

  const allSteps = step4 ? [...baseSteps, step4] : baseSteps;

  /* Render as a clean 4-step horizontal track */
  pipelineEl.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:0;overflow-x:auto;
         padding-bottom:4px;scrollbar-width:none">
      ${allSteps.map((s, i) => {
        const isLast = i === allSteps.length - 1;
        const isLive = s.live;
        return `
          <div style="display:flex;align-items:flex-start;flex:1;min-width:0">
            <div style="display:flex;flex-direction:column;align-items:center;
                 flex:1;min-width:60px;padding:0 4px">
              <!-- Circle -->
              <div style="position:relative;width:32px;height:32px;border-radius:50%;
                   border:2px solid ${s.color};
                   display:flex;align-items:center;justify-content:center;
                   font-family:var(--mono,'Space Mono',monospace);font-size:11px;font-weight:700;
                   color:${s.color};flex-shrink:0;margin-bottom:5px;
                   ${isLive ? `box-shadow:0 0 0 3px ${s.color}22;animation:idd-pulse 2s ease-in-out infinite` : ''}">
                ${i + 1}
                ${isLive ? `<div style="position:absolute;top:-2px;right:-2px;
                     width:8px;height:8px;border-radius:50%;background:${s.color};
                     animation:idd-pulse 1s ease-in-out infinite;
                     border:2px solid var(--card,#fff)"></div>` : ''}
              </div>
              <!-- Sub label (stage name) -->
              <div style="font-size:9px;color:var(--sub,#9499b7);
                   font-family:var(--mono,'Space Mono',monospace);
                   margin-bottom:2px;text-align:center;white-space:nowrap">${s.sub}</div>
              <!-- Main label (action/class) -->
              <div style="font-size:10px;font-weight:700;color:${s.color};
                   font-family:var(--mono,'Space Mono',monospace);
                   white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
                   max-width:80px;text-align:center">${s.label}</div>
              ${s.ts ? `<div style="font-size:9px;color:var(--sub,#9499b7);
                   font-family:var(--mono,'Space Mono',monospace);margin-top:2px">${s.ts}</div>` : ''}
            </div>
            <!-- Connector line between steps -->
            ${!isLast ? `<div style="height:1px;background:var(--border2,#e2e4ed);
                 flex-shrink:0;width:16px;margin-top:16px;align-self:flex-start"></div>` : ''}
          </div>`;
      }).join('')}
    </div>`;
}

// ── State pills ───────────────────────────────────────────────────────────────

function _renderHistoryPills(st) {
  const hist  = document.getElementById('idd-history');
  const pills = [];

  if (st.phase    && st.phase    !== '--') pills.push(['Phase',    st.phase,    'var(--blue,#3d6cff)']);
  if (st.priority && st.priority !== '--') pills.push(['Priority', st.priority, 'var(--amber,#ffb02e)']);

  /* offence_count: always show numeric value even if 0 */
  pills.push(['Offences', String(st.offence_count != null ? st.offence_count : 0), 'var(--red,#ff3d5a)']);

  /* reputation_score: decay-weighted risk score, always show */
  const rep = st.reputation_score != null ? st.reputation_score : 0;
  pills.push(['Reputation', rep.toFixed(2), 'var(--purple,#a855f7)']);

  if (st.action_taken && st.action_taken !== '--')
                     pills.push(['Action',     st.action_taken,        'var(--sub2,#6b7190)']);

  /* first_seen: date + year + time */
  const tsFirst = _fmtTs(st.first_seen);
  if (tsFirst && tsFirst !== '--') pills.push(['First Seen', tsFirst, 'var(--sub,#9499b7)']);

  /* last_seen: date + year + time */
  const tsLast = _fmtTs(st.last_seen);
  if (tsLast && tsLast !== '--') pills.push(['Last Seen', tsLast, 'var(--sub,#9499b7)']);

  hist.innerHTML = pills.map(([k, v, c]) => `
    <div style="background:var(--surface,#f7f8fc);border:1px solid var(--border,#eef0f6);
         border-radius:7px;padding:6px 11px;display:flex;flex-direction:column;gap:2px">
      <div style="font-size:9px;color:var(--sub,#9499b7);font-family:var(--mono,'Space Mono',monospace);
           text-transform:uppercase;letter-spacing:.08em">${k}</div>
      <div style="font-size:12px;font-weight:700;color:${c};
           font-family:var(--mono,'Space Mono',monospace)">${v}</div>
    </div>`).join('');
}

// ── Tooltip ───────────────────────────────────────────────────────────────────

function _iddShowTip(e, text) {
  if (!text) return;
  const tip = document.getElementById('idd-tooltip');
  if (!tip) return;
  tip.textContent = text;
  tip.style.display = 'block';
  _iddMoveTip(e);
}

function _iddMoveTip(e) {
  const tip = document.getElementById('idd-tooltip');
  if (!tip || tip.style.display === 'none') return;
  const x  = e.clientX + 14;
  const y  = e.clientY - 10;
  const tw = tip.offsetWidth || 240;
  tip.style.left = (x + tw > window.innerWidth ? x - tw - 20 : x) + 'px';
  tip.style.top  = Math.max(4, y) + 'px';
}

function _iddHideTip() {
  const tip = document.getElementById('idd-tooltip');
  if (tip) tip.style.display = 'none';
}

document.addEventListener('mousemove', e => {
  if (document.getElementById('idd-tooltip')?.style.display !== 'none') _iddMoveTip(e);
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function _iddShow(which) {
  const map = { loading:'flex', error:'flex', content:'block' };
  ['loading','error','content'].forEach(s => {
    const el = document.getElementById(`idd-${s}`);
    if (el) el.style.display = (s === which) ? map[s] : 'none';
  });
}

function _fmtBytes(b) {
  if (b >= 1e6) return `${(b/1e6).toFixed(2)} MB/s`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB/s`;
  return `${b.toFixed(0)} B/s`;
}

function _fmtTs(ts) {
  /* Guard against null, 0, NaN, negative, or non-numeric values */
  if (!ts || isNaN(ts) || ts <= 0) return '--';
  try {
    const d = new Date(ts * 1000);
    if (isNaN(d.getTime())) return '--';
    /* Format: Jun 4 2026, 17:24:08 */
    const datePart = d.toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
    const timePart = d.toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false });
    return `${datePart}, ${timePart}`;
  } catch { return '--'; }
}