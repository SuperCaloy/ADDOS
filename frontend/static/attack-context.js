/* attack-context.js: Domain encyclopedia and attack descriptions for IP Threat Drawer */

const _FEAT_TOOLTIPS = {
  "Flow Rate (pps)": "Packet rate for this flow, measured in packets per second (pps). Significantly elevated rates relative to normal baselines are indicative of flood-based attacks.",
  "Byte Rate":       "Data throughput for this flow, measured in bytes per second. Sharp increases may indicate volumetric attacks targeting bandwidth exhaustion.",
  "Bytes / Packet":  "Average packet size (byte count divided by packet count). Different attack types produce characteristic packet size signatures, aiding classification.",
  "Port Entropy":    "Quantifies the distribution of traffic across source and destination ports. UDP flood attacks typically spray packets across many destination ports, producing a markedly higher entropy value than legitimate single-session traffic.",
  "Pkt Size Uniformity": "Measures the consistency of packet sizes within this flow. Lower values indicate highly uniform packets, as expected from SYN flood traffic where packets carry no payload and are constructed with near-identical sizes.",
  "Packet Count":    "Total number of packets observed in this flow. Rapid accumulation within a short observation window is a strong indicator of flooding behavior.",
  "Byte Count":      "Total data volume observed in this flow, measured in bytes.",
};

const _ATTACK_CONTEXT = {
  "ICMP Flood": {
    color: 'var(--red,#ff3d5a)',
    desc: 'An ICMP Flood saturates the target with a high volume of ICMP Echo Request packets, consuming bandwidth and host processing resources to the point that legitimate traffic is denied service.',
    rows: [
      ['Flow Rate (pps)', 'Very high', 'Packet rate significantly exceeds normal baseline'],
      ['Byte Rate',       'Moderate',  'Low per-packet volume, high aggregate count'],
      ['Bytes / Packet',  'Fixed size','Consistent with standard ICMP Echo Request size'],
    ],
  },
  "SYN Flood": {
    color: 'var(--red,#ff3d5a)',
    desc: 'A SYN Flood exploits the TCP three-way handshake by initiating a high volume of connection requests without completing them, exhausting the server connection table and denying service to legitimate clients.',
    rows: [
      ['Flow Rate (pps)', 'Very high', 'Connection initiation rate far above normal'],
      ['Bytes / Packet',  'Small',     'TCP SYN only, no payload data'],
      ['Byte Rate',       'Low',       'Minimal byte volume despite elevated packet rate'],
    ],
  },
  "UDP Flood": {
    color: 'var(--amber,#ffb02e)',
    desc: 'A UDP Flood transmits a high volume of connectionless packets to random or targeted ports, forcing the target to process and respond to traffic that consumes bandwidth without legitimate purpose.',
    rows: [
      ['Byte Rate',       'Very high', 'High data throughput in short duration'],
      ['Bytes / Packet',  'Large',     'Substantial payload per packet'],
      ['Flow Rate (pps)', 'High',      'Elevated packet transmission rate'],
    ],
  },
  "Anomalous": {
    color: 'var(--sub2,#8890b0)',
    desc: 'Traffic deviates significantly from the established normal baseline but does not match a known attack signature with sufficient confidence for definitive classification.',
    rows: [
      ['Flow Rate (pps)', 'Elevated',  'Exceeds typical traffic volume for this source'],
    ],
  },
  "Uncertain": {
    color: 'var(--sub,#5c6080)',
    desc: 'The anomaly detector flagged this traffic as suspicious, but classifier confidence fell below the threshold required to assign a specific attack type.',
    rows: [],
  },
};

window._FEAT_TOOLTIPS = _FEAT_TOOLTIPS;
window._ATTACK_CONTEXT = _ATTACK_CONTEXT;
