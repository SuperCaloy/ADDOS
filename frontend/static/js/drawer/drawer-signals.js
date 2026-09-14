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
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,   bar: v => Math.min(v/50000,1),
        tip:'Packet rate for this flow. ICMP floods send echo requests far above the normal baseline, so a very high rate is the primary flood tell for this vector.' },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 51200, bar: v => Math.min(v/1e7,1),
        tip:'Data throughput for this flow. ICMP packets are small, so byte rate stays moderate next to the packet rate. High aggregate volume still points at bandwidth exhaustion.' },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => v > 0 && v < 100, bar: v => Math.min(v/1500,1),
        tip:'Average packet size. ICMP echo requests have a characteristic fixed size, so a small stable value matches this vector profile.' },
      { key:'pkt_size_uniformity', label:'Pkt Size Uniformity', fmt: v => v.toFixed(3), alert: v => v < 0.05, bar: v => Math.min(v/0.5,1),
        tip:'Consistency of packet sizes in this flow. Flood generators emit near identical echo requests, so a value near zero fits scripted ICMP flood traffic.' },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => v > 0 && v < 100, bar: v => Math.min(v/1500,1),
        tip:'Average packet size. Fixed size echo requests are the ICMP signature the classifier matches against.' },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000,        bar: v => Math.min(v/1e6,1),
        tip:'Total packets observed. Rapid accumulation inside a short window is the volume evidence for this classification.' },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,          bar: v => Math.min(v/1e9,1),
        tip:'Total data volume observed. Large totals from many small packets confirm a sustained echo flood rather than a burst.' },
      { key:'pps',        label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500, bar: v => Math.min(v/50000,1),
        tip:'Packet rate paired with fixed size packets. Very high rate plus small uniform size is the ICMP pair the classifier keys on.' },
    ],
  },
  "SYN Flood": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,  bar: v => Math.min(v/50000,1),
        tip:'Connection initiation rate. SYN floods open handshake after handshake without completing them, so initiation rate far above normal is the primary tell.' },
      { key:'pkt_size_uniformity', label:'Pkt Size Uniformity', fmt: v => v.toFixed(3), alert: v => v < 0.05, bar: v => Math.min(v/0.5,1),
        tip:'Consistency of packet sizes. SYN only packets carry no payload and are near identical in size, so a value near zero fits this vector.' },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 5120, bar: v => Math.min(v/1e7,1),
        tip:'Data throughput. SYN traffic is minimal per packet, so byte volume stays low even while packet rate spikes. Low bytes beside high rate is itself the tell.' },
      { key:'flow_intensity', label:'Flow Intensity', fmt: v => v.toFixed(2), alert: v => v > 12, bar: v => Math.min(v/30,1),
        tip:'Composite log metric of packet count times byte rate. Catches aggressive sources whose single rates look borderline on their own.' },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => v > 0 && v < 70, bar: v => Math.min(v/1500,1),
        tip:'Average packet size. SYN only headers with no payload are small, so a small value is the strongest SYN classifier cue.' },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000,       bar: v => Math.min(v/1e6,1),
        tip:'Total handshake attempts observed. Fast accumulation shows connection table exhaustion pressure.' },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,         bar: v => Math.min(v/1e9,1),
        tip:'Total data volume. Stays modest for SYN floods, which is consistent with header only traffic at high packet counts.' },
      { key:'pkt_size_uniformity', label:'Pkt Size Uniformity', fmt: v => v.toFixed(3), alert: v => v < 0.05, bar: v => Math.min(v/0.5,1),
        tip:'Consistency of packet sizes. Uniform header only packets confirm scripted SYN generation rather than mixed normal traffic.' },
    ],
  },
  "UDP Flood": {
    if: [
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 512000, bar: v => Math.min(v/1e7,1),
        tip:'Data throughput for this flow. UDP floods push high volume with substantial payloads, so byte rate is the lead volumetric tell for this vector.' },
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,    bar: v => Math.min(v/50000,1),
        tip:'Packet transmission rate. Elevated rate beside high byte rate confirms a sustained connectionless flood rather than a short burst.' },
      { key:'port_entropy', label:'Port Entropy',    fmt: v => v.toFixed(2),                                                     alert: v => v > 1,      bar: v => Math.min(v/5,1),
        tip:'Spread of traffic across ports. UDP floods spray packets at many destination ports, producing markedly higher entropy than single session traffic.' },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => v > 200,   bar: v => Math.min(v/1500,1),
        tip:'Average payload per packet. UDP floods carry substantial payloads, so a large value separates this vector from header only floods.' },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => v > 200,   bar: v => Math.min(v/1500,1),
        tip:'Average payload per packet. Large payloads are the UDP signature the classifier matches against.' },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000, bar: v => Math.min(v/1e6,1),
        tip:'Total packets observed. Rapid accumulation confirms flooding behavior behind this classification.' },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,   bar: v => Math.min(v/1e9,1),
        tip:'Total data volume observed. High totals from large payload packets confirm bandwidth exhaustion pressure.' },
      { key:'port_entropy', label:'Port Entropy', fmt: v => v.toFixed(2),       alert: v => v > 1,     bar: v => Math.min(v/5,1),
        tip:'Spread of traffic across ports. Multi port spray is the UDP tell. Shown as supporting context from the anomaly inputs.' },
    ],
  },
  "Anomalous": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,   bar: v => Math.min(v/50000,1),
        tip:'Packet rate for this flow. Elevated rate exceeds typical volume for this source, though no known signature matched.' },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => false,     bar: v => Math.min(v/1500,1),
        tip:'Average packet size, shown for context. No signature matched, so this card never flags on its own.' },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 51200, bar: v => Math.min(v/1e7,1),
        tip:'Data throughput for this flow. Sustained elevation supports the anomaly verdict in a generic sense.' },
      { key:'bytes_per_duration', label:'Bytes / Duration', fmt: v => _fmtBytes(v), alert: v => v > 51200, bar: v => Math.min(v/1e7,1),
        tip:'Sustained throughput over flow lifetime. High values mean the volume persisted rather than spiking once. Hedged cue for unknown vectors.' },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => false,     bar: v => Math.min(v/1500,1),
        tip:'Average packet size, shown for context. Classifier confidence was too low to assign a vector, so this card never flags.' },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000, bar: v => Math.min(v/1e6,1),
        tip:'Total packets observed. Volume evidence behind the anomaly flag.' },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,   bar: v => Math.min(v/1e9,1),
        tip:'Total data volume observed. Volume evidence behind the anomaly flag.' },
      { key:'flow_intensity', label:'Flow Intensity', fmt: v => v.toFixed(2), alert: v => v > 12, bar: v => Math.min(v/30,1),
        tip:'Composite log metric of packet count times byte rate. Generic volume cue for unknown vectors, hedged by design.' },
    ],
  },
  "Uncertain": {
    if: [
      { key:'pps',          label:'Flow Rate (pps)', fmt: v => `${v.toLocaleString(undefined,{maximumFractionDigits:1})} pkt/s`, alert: v => v > 500,   bar: v => Math.min(v/50000,1),
        tip:'Packet rate for this flow. The anomaly detector flagged the traffic but classifier confidence was too low to name a vector.' },
      { key:'byte_rate',    label:'Byte Rate',       fmt: v => _fmtBytes(v),                                                     alert: v => v > 51200, bar: v => Math.min(v/1e7,1),
        tip:'Data throughput for this flow, shown for context while classification remains uncertain.' },
      { key:'bpp',          label:'Bytes / Packet',  fmt: v => v.toFixed(1)+' B',                                                alert: v => false,     bar: v => Math.min(v/1500,1),
        tip:'Average packet size, shown for context. This card never flags while classification is uncertain.' },
      { placeholder:true,   label:'No further distinguishing signal',
        fmt: () => '--', alert: () => false, bar: () => 0,
        tip:'Classifier confidence fell below the gate, so no fourth distinguishing signal is claimed for this state.' },
    ],
    rf: [
      { key:'bpp',        label:'Bytes / Packet', fmt: v => v.toFixed(1)+' B',  alert: v => false,     bar: v => Math.min(v/1500,1),
        tip:'Average packet size, shown for context. This card never flags while classification is uncertain.' },
      { key:'pkt_count',  label:'Packet Count',   fmt: v => v.toLocaleString(), alert: v => v > 10000, bar: v => Math.min(v/1e6,1),
        tip:'Total packets observed. Volume evidence behind the anomaly flag.' },
      { key:'byte_count', label:'Byte Count',     fmt: v => _fmtBytes(v),       alert: v => v > 1e6,   bar: v => Math.min(v/1e9,1),
        tip:'Total data volume observed. Volume evidence behind the anomaly flag.' },
      { placeholder:true,   label:'No further distinguishing signal',
        fmt: () => '--', alert: () => false, bar: () => 0,
        tip:'Classifier confidence fell below the gate, so no fourth distinguishing signal is claimed for this state.' },
    ],
  },
};

// Deviation alert rule, mirrors backend ALERT_DEVIATION in
// backend/models/baselines.py. Served deviations at or above this many
// training IQRs mark a card red. Legacy alert() cutoffs apply only when
// the response carries no deviations (offline fallback path).
const _DEVIATION_ALERT = 3;

// Picks the leading signal for a section. Served deviations rank first
// when provided, otherwise alerted cards rank by bar value. Without any
// alert the highest ranker is reported as closest to baseline.
// Returns { key, feat, val, flagged }. Pure function, no DOM.
function _pickTopSignal(feats, vals, devs) {
  const scored = feats
    .filter(f => !f.placeholder)
    .map(f => {
      const v = vals != null && vals[f.key] != null ? vals[f.key] : 0;
      const dev = devs != null && devs[f.key] != null ? devs[f.key] : null;
      if (dev != null) {
        return { feat: f, val: v, alerted: dev >= _DEVIATION_ALERT, bar: dev };
      }
      return { feat: f, val: v, alerted: !!f.alert(v), bar: f.bar(v) };
    });
  if (!scored.length) return null;
  const alerted = scored.filter(s => s.alerted).sort((a, b) => b.bar - a.bar);
  const rest = scored.slice().sort((a, b) => b.bar - a.bar);
  const best = alerted[0] || rest[0];
  return { key: best.feat.key, feat: best.feat, val: best.val, flagged: best.alerted };
}

// Generates an interactive telemetry signal card with custom bar scaling, threshold alert styling, and tooltip bindings.
// Visually highlights deviating features for Isolation Forest and Random Forest evaluations.
// opts.top adds a Top signal tag for the section leader. opts.alerted overrides
// the legacy alert() cutoff with a served deviation verdict. Placeholder entries
// render muted with no alert behavior.
function _mkSignalCard(feat, val, isIF, opts) {
  const showTop = !!(opts && opts.top);
  const forcedAlert = opts && opts.alerted != null ? !!opts.alerted : null;
  if (feat.placeholder) {
    return `
    <div class="idd-fc"
         style="background:var(--surface,#f7f8fc);border-radius:12px;padding:18px 20px;
                border:1px dashed var(--border,#1e2235);opacity:.75"
         data-tip="${(feat.tip || '').replace(/"/g, '&quot;')}"
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
           color:var(--sub,#9499b7);margin-bottom:11px">${feat.fmt(val)}</div>
    </div>`;
  }
  const isAlert   = forcedAlert != null ? forcedAlert : feat.alert(val);
  const barPct    = (feat.bar(val) * 100).toFixed(1);
  const accentCol = isIF ? 'var(--blue,#3d6cff)' : 'var(--amber,#ffb02e)';
  const borderCol = isAlert ? 'var(--red,#ff3d5a)' : 'var(--border,#1e2235)';
  const valCol    = isAlert ? 'var(--red,#ff3d5a)' : 'var(--text,#e8eaf6)';
  const tooltips  = window._FEAT_TOOLTIPS || (typeof _FEAT_TOOLTIPS !== 'undefined' ? _FEAT_TOOLTIPS : {});
  const tipRaw    = feat.tip || tooltips[feat.label] || '';
  const tipText   = tipRaw.replace(/'/g,"&#39;");
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
        ${showTop ? `<div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
             padding:2px 7px;border-radius:4px;white-space:nowrap;
             background:${isAlert ? 'rgba(255,61,90,.1)' : 'rgba(148,153,183,.1)'};
             color:${isAlert ? 'var(--red,#ff3d5a)' : 'var(--sub,#9499b7)'};
             border:1px solid ${isAlert ? 'rgba(255,61,90,.3)' : 'rgba(148,153,183,.25)'};
             font-family:var(--mono,'Space Mono',monospace)">Top signal</div>` : ''}
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
window._pickTopSignal = _pickTopSignal;
window._renderDrawerFeatureCard = _renderDrawerFeatureCard;

