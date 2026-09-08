// Feature signal evaluation rules, numeric normalization, and interactive metric card renderers.
// Powers visual analysis and telemetry breakdown in the threat analysis drawer.

// Formats numerical byte values into human-readable data rate strings with B/s, KB/s, or MB/s units.
function _fmtBytes(b) {
  if (b >= 1e6) return `${(b/1e6).toFixed(2)} MB/s`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB/s`;
  return `${b.toFixed(0)} B/s`;
}

// Converts a Unix timestamp in seconds into a localized date and time string.
function _fmtTs(ts) {
  if (!ts || isNaN(ts) || ts <= 0) return '--';
  try {
    const d = new Date(ts * 1000);
    if (isNaN(d.getTime())) return '--';
    const datePart = d.toLocaleDateString(undefined, { month:'short', day:'numeric', year:'numeric' });
    const timePart = d.toLocaleTimeString(undefined, { hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false });
    return `${datePart}, ${timePart}`;
  } catch { return '--'; }
}

// Configuration dictionary defining relevant telemetry features, anomaly threshold alerts, and bar scales per attack type.
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

// Generates an interactive telemetry signal card with custom bar scaling, threshold alert styling, and tooltip bindings.
// Visually highlights deviating features for Isolation Forest and Random Forest evaluations.
function _mkSignalCard(feat, val, isIF) {
  const isAlert   = feat.alert(val);
  const barPct    = (feat.bar(val) * 100).toFixed(1);
  const accentCol = isIF ? 'var(--blue,#3d6cff)' : 'var(--amber,#ffb02e)';
  const borderCol = isAlert ? 'var(--red,#ff3d5a)' : 'var(--border,#1e2235)';
  const valCol    = isAlert ? 'var(--red,#ff3d5a)' : 'var(--text,#e8eaf6)';
  const tooltips  = window._FEAT_TOOLTIPS || (typeof _FEAT_TOOLTIPS !== 'undefined' ? _FEAT_TOOLTIPS : {});
  const tipText   = (tooltips[feat.label] || '').replace(/'/g,"&#39;");
  const tip       = tipText.replace(/"/g, '&quot;');
  return `
    <div class="idd-fc"
         style="background:var(--surface,#f7f8fc);border-radius:12px;padding:18px 20px;
                border:1px solid ${borderCol}"
         data-tip="${tip}"
         tabindex="0"
         role="button"
         aria-label="${feat.label} - press for details"
         onmouseenter="_iddShowTip(event,this.dataset.tip)"
         onmouseleave="_iddHideTip()"
         onfocus="_iddShowTipEl(this)"
         onblur="_iddHideTip()">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:9px">
        <div style="font-size:13px;color:var(--sub,#9499b7);
             font-family:var(--mono,'Space Mono',monospace);
             white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:90%;
             padding-top:1px">${feat.label}</div>
      </div>
      <div style="font-family:var(--mono,'Space Mono',monospace);font-size:26px;font-weight:700;
           color:${valCol};margin-bottom:11px">${feat.fmt(val)}</div>
      <div style="height:4px;background:var(--border2,#e2e4ed);border-radius:2px;overflow:hidden">
        <div style="height:100%;width:${barPct}%;
             background:${isAlert ? 'var(--red,#ff3d5a)' : accentCol};
             transition:width .4s;border-radius:2px"></div>
      </div>
    </div>`;
}

// Renders a compact feature telemetry card for detailed algorithmic trace views.
function _renderDrawerFeatureCard(feat, val) {
  const fmtVal = feat.fmt(val);
  return `
    <div style="background:var(--surface,#f7f8fc);border:1px solid var(--border,#eef0f6);border-radius:8px;padding:12px 14px;">
      <div style="font-size:10px;color:var(--sub,#9499b7);font-family:var(--mono,'Space Mono',monospace);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">${feat.label}</div>
      <div style="font-family:var(--mono,'Space Mono',monospace);font-size:15px;font-weight:700;color:var(--text,#1a1d2e);margin-bottom:4px">${fmtVal}</div>
      <div style="font-size:10px;color:var(--sub2);font-family:var(--mono);line-height:1.4">${feat.desc || ''}</div>
    </div>`;
}

window._fmtBytes = _fmtBytes;
window._fmtTs = _fmtTs;
window._SIGNAL_CONFIG = _SIGNAL_CONFIG;
window._mkSignalCard = _mkSignalCard;
window._renderDrawerFeatureCard = _renderDrawerFeatureCard;

