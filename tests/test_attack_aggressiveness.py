"""Tests for increased attack aggressiveness (Task 9).

Verifies:
- UDP payload increased from 1400 to 1472 bytes (max before fragmentation)
- ICMP payload increased from 512 to 1400 bytes
- UDP instances increased from 1 to 2 per attacker
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from topology.topology import (
    _ALL_VARIANTS,
    _ATTACK_TYPE_FLAGS,
    _flood_spawn_count,
    _ATTACKER_NUMS,
)


# --- UDP payload size tests ---

def test_udp_payload_1472_bytes():
    """UDP attack variants should use 1472-byte payload (max before fragmentation)."""
    for num in sorted(_ATTACKER_NUMS):
        atype, flags, _, _ = _ALL_VARIANTS[num]
        if atype == "UDP":
            assert "--data 1472" in flags, (
                f"h{num}: UDP flags '{flags}' missing '--data 1472'"
            )


def test_udp_no_1400_payload():
    """UDP attack variants should NOT use old 1400-byte payload."""
    for num in sorted(_ATTACKER_NUMS):
        atype, flags, _, _ = _ALL_VARIANTS[num]
        if atype == "UDP":
            assert "--data 1400" not in flags, (
                f"h{num}: UDP flags still contain old '--data 1400'"
            )


def test_udp_attack_type_flag_1472():
    """_ATTACK_TYPE_FLAGS UDP should use 1472-byte payload."""
    assert "--data 1472" in _ATTACK_TYPE_FLAGS["UDP"], (
        f"UDP attack type flag missing '--data 1472': {_ATTACK_TYPE_FLAGS['UDP']}"
    )


# --- ICMP payload size tests ---

def test_icmp_payload_1400_bytes():
    """ICMP attack variants should use 1400-byte payload."""
    for num in sorted(_ATTACKER_NUMS):
        atype, flags, _, _ = _ALL_VARIANTS[num]
        if atype == "ICMP":
            assert "--data 1400" in flags, (
                f"h{num}: ICMP flags '{flags}' missing '--data 1400'"
            )


def test_icmp_no_512_payload():
    """ICMP attack variants should NOT use old 512-byte payload."""
    for num in sorted(_ATTACKER_NUMS):
        atype, flags, _, _ = _ALL_VARIANTS[num]
        if atype == "ICMP":
            assert "--data 512" not in flags, (
                f"h{num}: ICMP flags still contain old '--data 512'"
            )


def test_icmp_attack_type_flag_1400():
    """_ATTACK_TYPE_FLAGS ICMP should use 1400-byte payload."""
    assert "--data 1400" in _ATTACK_TYPE_FLAGS["ICMP"], (
        f"ICMP attack type flag missing '--data 1400': {_ATTACK_TYPE_FLAGS['ICMP']}"
    )


# --- Flood spawn count tests ---

def test_udp_flood_spawn_count_2():
    """UDP attackers should spawn 2 parallel hping3 instances."""
    assert _flood_spawn_count("UDP") == 2, (
        f"UDP flood spawn count is {_flood_spawn_count('UDP')}, expected 2"
    )


def test_syn_flood_spawn_count_unchanged():
    """SYN flood spawn count should remain 2 (unchanged)."""
    assert _flood_spawn_count("SYN") == 2, (
        f"SYN flood spawn count is {_flood_spawn_count('SYN')}, expected 2"
    )


def test_icmp_flood_spawn_count_1():
    """ICMP flood spawn count should remain 1."""
    assert _flood_spawn_count("ICMP") == 1, (
        f"ICMP flood spawn count is {_flood_spawn_count('ICMP')}, expected 1"
    )


# --- SYN unchanged sanity tests ---

def test_syn_payload_unchanged():
    """SYN attack variants should remain unchanged (no --data flag)."""
    for num in sorted(_ATTACKER_NUMS):
        atype, flags, _, _ = _ALL_VARIANTS[num]
        if atype == "SYN":
            assert "--data" not in flags, (
                f"h{num}: SYN flags unexpectedly contain '--data'"
            )
            assert "-S" in flags, (
                f"h{num}: SYN flags missing '-S' (SYN flag)"
            )


def test_syn_attack_type_flag_unchanged():
    """_ATTACK_TYPE_FLAGS SYN should remain unchanged."""
    assert _ATTACK_TYPE_FLAGS["SYN"] == "-S -p {port} --flood", (
        f"SYN attack type flag changed unexpectedly: {_ATTACK_TYPE_FLAGS['SYN']}"
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
