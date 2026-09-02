"""Tests for UDP host single-port slot fix.

Verifies that UDP hosts (h6-h10) use exactly one port per host to prevent
port-entropy false positives in the detection model.
"""
import sys
import os
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from topology.topology import _HOST_SLOTS, _post_idle_slots


def test_udp_hosts_have_single_slot():
    """Each UDP host (6-10) should have exactly 1 slot in _HOST_SLOTS."""
    for num in range(6, 11):
        slots = _HOST_SLOTS[num]
        assert len(slots) == 1, (
            f"h{num} has {len(slots)} slots, expected 1"
        )


def test_udp_host_slot_type_is_udp():
    """All UDP host slots should be ('udp', port)."""
    for num in range(6, 11):
        slots = _HOST_SLOTS[num]
        slot_type, _ = slots[0]
        assert slot_type == "udp", (
            f"h{num} slot type is '{slot_type}', expected 'udp'"
        )


def test_udp_hosts_use_unique_ports():
    """Each UDP host should use a different port to avoid overlap."""
    udp_ports = [_HOST_SLOTS[num][0][1] for num in range(6, 11)]
    assert len(udp_ports) == len(set(udp_ports)), (
        f"Duplicate UDP ports found: {udp_ports}"
    )


def test_udp_ports_are_known_services():
    """UDP ports should be from the recognized service set."""
    valid_ports = {53, 123, 161, 514, 1900}
    for num in range(6, 11):
        port = _HOST_SLOTS[num][0][1]
        assert port in valid_ports, (
            f"h{num} uses port {port}, not in valid set {valid_ports}"
        )


def test_udp_post_idle_returns_single_slot():
    """_post_idle_slots should return single slot for UDP hosts."""
    for num in range(6, 11):
        slots = _post_idle_slots(num)
        assert len(slots) == 1, (
            f"h{num}: _post_idle_slots returned {len(slots)} slots, expected 1"
        )


def test_udp_slot_always_same_port():
    """Multiple calls to _post_idle_slots should return the same port."""
    for num in range(6, 11):
        first = _post_idle_slots(num)
        for _ in range(10):
            current = _post_idle_slots(num)
            assert current == first, (
                f"h{num}: _post_idle_slots returned inconsistent results"
            )


def test_tcp_hosts_unchanged():
    """TCP hosts (1-5) should still have 3 slots each."""
    for num in range(1, 6):
        slots = _HOST_SLOTS[num]
        assert len(slots) == 3, (
            f"h{num} has {len(slots)} slots, expected 3"
        )


def test_icmp_hosts_unchanged():
    """ICMP hosts (11-15) should still have 3 slots each."""
    for num in range(11, 16):
        slots = _HOST_SLOTS[num]
        assert len(slots) == 3, (
            f"h{num} has {len(slots)} slots, expected 3"
        )


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
