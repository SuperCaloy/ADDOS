"""Tests for payload size ranges in topology profiles.

Verifies that TCP/UDP size ranges match the structured payloads implemented
in Tasks 1-2 and realistic HTTP traffic sizes.
"""
import sys
import os
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from topology.topology import (
    _TCP_PROFILES,
    _UDP_PROFILES,
    _ICMP_CONTINUOUS,
)


# --- TCP profile tests ---

def test_tcp_profiles_ports():
    """TCP profiles cover the three expected ports."""
    assert set(_TCP_PROFILES.keys()) == {80, 443, 8080}


def test_tcp_profiles_realistic_http_sizes():
    """TCP sizes should reflect realistic HTTP request/response traffic."""
    for port, (size_min, size_max, _, _) in _TCP_PROFILES.items():
        assert size_min >= 200, (
            f"TCP port {port}: size_min {size_min} too small for HTTP"
        )
        assert size_max <= 1400, (
            f"TCP port {port}: size_max {size_max} exceeds MTU"
        )
        assert size_min <= size_max, (
            f"TCP port {port}: size_min {size_min} > size_max {size_max}"
        )


def test_tcp_profiles_timing():
    """TCP sleep ranges should be 5-10s (background web traffic)."""
    for port, (_, _, sleep_min, sleep_max) in _TCP_PROFILES.items():
        assert sleep_min == 5.0, f"TCP port {port}: sleep_min != 5.0"
        assert sleep_max == 10.0, f"TCP port {port}: sleep_max != 10.0"


# --- UDP profile tests ---

def test_udp_profiles_ports():
    """UDP profiles cover the five structured-payload ports."""
    assert set(_UDP_PROFILES.keys()) == {53, 123, 161, 514, 1900}


def test_udp_structured_payloads_fixed_size():
    """Structured UDP payloads should have min == max (fixed size)."""
    expected_sizes = {
        53:  33,   # DNS: 12-byte header + 21-byte query
        123: 48,   # NTP: 48-byte struct
        161: 40,   # SNMP: 40-byte hardcoded
        514: 58,   # syslog: 58 bytes
        1900: 94,  # SSDP M-SEARCH: 94 bytes
    }
    for port, expected in expected_sizes.items():
        size_min, size_max, _, _ = _UDP_PROFILES[port]
        assert size_min == expected, (
            f"UDP port {port}: size_min {size_min} != expected {expected}"
        )
        assert size_max == expected, (
            f"UDP port {port}: size_max {size_max} != expected {expected}"
        )
        assert size_min == size_max, (
            f"UDP port {port}: min {size_min} != max {size_max}, "
            "should be fixed for structured payload"
        )


def test_udp_dns_payload_size_matches_struct():
    """DNS payload size should match the actual struct.pack output."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    query = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    total = len(header) + len(query)
    assert total == 33, f"DNS payload calc: {total} != 33"
    assert _UDP_PROFILES[53][0] == total


def test_udp_ntp_payload_size_matches_struct():
    """NTP payload size should match the actual struct.pack output."""
    ntp = struct.pack(">BBBBIIIQQQQ", 0x23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    assert len(ntp) == 48, f"NTP payload calc: {len(ntp)} != 48"
    assert _UDP_PROFILES[123][0] == len(ntp)


def test_udp_snmp_payload_size():
    """SNMP payload should be 40 bytes."""
    snmp = bytes([
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62,
        0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30,
        0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
    ])
    assert len(snmp) == 40, f"SNMP payload calc: {len(snmp)} != 40"
    assert _UDP_PROFILES[161][0] == len(snmp)


def test_udp_syslog_payload_size():
    """Syslog payload should be 58 bytes."""
    msg = b"<13>Sep  2 12:00:00 h514 kernel: [12345.678] eth0: link up"
    assert len(msg) == 58, f"syslog payload calc: {len(msg)} != 58"
    assert _UDP_PROFILES[514][0] == len(msg)


def test_udp_ssdp_payload_size():
    """SSDP M-SEARCH payload should be 94 bytes."""
    msg = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 3\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )
    assert len(msg) == 94, f"SSDP payload calc: {len(msg)} != 94"
    assert _UDP_PROFILES[1900][0] == len(msg)


# --- ICMP profile tests (unchanged, sanity check) ---

def test_icmp_profiles_unchanged():
    """ICMP profiles should remain at 56 bytes (standard ping)."""
    for dtype, (size_min, size_max, _, _) in _ICMP_CONTINUOUS.items():
        assert size_min == 56, f"ICMP type {dtype}: size_min != 56"
        assert size_max == 56, f"ICMP type {dtype}: size_max != 56"


# --- Run all tests if executed directly ---

if __name__ == "__main__":
    passed = 0
    failed = 0
    errors = []
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            try:
                func()
                passed += 1
                print(f"  PASS  {name}")
            except AssertionError as e:
                failed += 1
                errors.append((name, e))
                print(f"  FAIL  {name}: {e}")
            except Exception as e:
                failed += 1
                errors.append((name, e))
                print(f"  ERROR {name}: {e}")
    print(f"\n{passed} passed, {failed} failed")
    if errors:
        sys.exit(1)
