def compute_raw_features(
    byte_count: float,
    packet_count: float,
    byte_count_per_second: float,
    packet_count_per_second: float,
    flow_duration_sec: float,
    flow_duration_total_ns: float,
    flow_count_per_src: float,
    tp_src: float,
    tp_dst: float,
    eps: float = 1e-6,
) -> dict:
    bytes_per_packet = byte_count / max(packet_count, 1)
    pkt_byte_rate_ratio = packet_count_per_second / (byte_count_per_second + eps)
    flow_intensity = packet_count * byte_count_per_second
    port_entropy = tp_src / (tp_dst + 1)
    bytes_per_duration = byte_count / (flow_duration_sec + eps)
    pkt_size_uniformity = bytes_per_packet / (byte_count_per_second + 1)
    flow_src_intensity = flow_count_per_src * packet_count_per_second
    duration_pkt_ratio = flow_duration_total_ns / (packet_count + eps)
    pkt_rate_per_duration = packet_count / (flow_duration_total_ns + eps)

    return {
        "bytes_per_packet": bytes_per_packet,
        "pkt_byte_rate_ratio": pkt_byte_rate_ratio,
        "flow_intensity": flow_intensity,
        "port_entropy": port_entropy,
        "bytes_per_duration": bytes_per_duration,
        "pkt_size_uniformity": pkt_size_uniformity,
        "flow_src_intensity": flow_src_intensity,
        "duration_pkt_ratio": duration_pkt_ratio,
        "pkt_rate_per_duration": pkt_rate_per_duration,
    }
