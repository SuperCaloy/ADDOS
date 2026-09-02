"""T2: UDP scripts must emit protocol-valid queries, not raw os.urandom().

The task requires that benign UDP traffic sends structured protocol queries
for DNS (port 53), NTP (port 123), SNMP (port 161), syslog (port 514),
and SSDP (port 1900). Unknown ports fall back to random bytes.
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest import mock
import io

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_topology():
    mn = types.ModuleType("mininet")
    for sub in ("log", "net", "node", "cli", "link"):
        m = types.ModuleType(f"mininet.{sub}")
        if sub == "log":
            m.info = lambda *a, **k: None
            m.setLogLevel = lambda *a, **k: None
        elif sub == "net":
            m.Mininet = object
        elif sub == "node":
            m.RemoteController = object
            m.OVSKernelSwitch = object
        elif sub == "cli":
            m.CLI = object
        elif sub == "link":
            m.Link = object
        sys.modules.setdefault(f"mininet.{sub}", m)
        setattr(mn, sub, m)
    sys.modules.setdefault("mininet", mn)

    spec = importlib.util.spec_from_file_location(
        "topo_udp_test", str(REPO_ROOT / "topology" / "topology.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["topo_udp_test"] = mod
    spec.loader.exec_module(mod)
    return mod


topo = _load_topology()


def _get_script_code(slot_type, slot_key, size, dst):
    """Call _write_slot_script, capture the code that would be written."""
    captured = {}
    real_open = open

    def fake_open(path, mode="r", *args, **kwargs):
        if mode == "w":
            buf = io.StringIO()
            original_write = buf.write
            def capturing_write(s):
                captured["content"] = captured.get("content", "") + s
                return original_write(s)
            buf.write = capturing_write
            buf.close = lambda: None
            return buf
        return real_open(path, mode, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=fake_open):
        result_path = topo._write_slot_script(slot_type, slot_key, size, dst)
    return captured.get("content", "")


# --- DNS (port 53) ---

def test_dns_script_contains_struct_pack():
    """DNS script must use struct.pack for the header."""
    code = _get_script_code("udp", 53, 40, "10.0.0.1")
    assert "struct.pack" in code


def test_dns_script_has_valid_header():
    """DNS script must pack a 12-byte header with transaction ID 0x1234."""
    code = _get_script_code("udp", 53, 40, "10.0.0.1")
    assert "0x1234" in code
    assert "0x0100" in code


def test_dns_script_queries_example_com():
    """DNS script must include www.example.com in the query."""
    code = _get_script_code("udp", 53, 40, "10.0.0.1")
    assert "example" in code


def test_dns_script_uses_DGRAM():
    """DNS script must use SOCK_DGRAM."""
    code = _get_script_code("udp", 53, 40, "10.0.0.1")
    assert "SOCK_DGRAM" in code


def test_dns_script_sends_to_port_53():
    """DNS script must send to port 53."""
    code = _get_script_code("udp", 53, 40, "10.0.0.1")
    assert "sendto" in code
    assert "53" in code


def test_dns_script_no_random_fallback():
    """DNS script must not use os.urandom for payload."""
    code = _get_script_code("udp", 53, 40, "10.0.0.1")
    assert "os.urandom" not in code


# --- NTP (port 123) ---

def test_ntp_script_contains_struct_pack():
    """NTP script must use struct.pack for the 48-byte header."""
    code = _get_script_code("udp", 123, 48, "10.0.0.1")
    assert "struct.pack" in code


def test_ntp_script_has_li_vn_mode():
    """NTP script must set LI=0, VN=4, Mode=3 (0x23 = 0b00100011)."""
    code = _get_script_code("udp", 123, 48, "10.0.0.1")
    assert "0x23" in code


def test_ntp_script_uses_48_bytes():
    """NTP script must pack exactly 48 bytes (11 fields of 4 bytes each)."""
    code = _get_script_code("udp", 123, 48, "10.0.0.1")
    assert ">BBBBIIIIIIII" in code


def test_ntp_script_sends_to_port_123():
    """NTP script must send to port 123."""
    code = _get_script_code("udp", 123, 48, "10.0.0.1")
    assert "123" in code


def test_ntp_script_no_random_fallback():
    """NTP script must not use os.urandom for payload."""
    code = _get_script_code("udp", 123, 48, "10.0.0.1")
    assert "os.urandom" not in code


# --- SNMP (port 161) ---

def test_snmp_script_has_asn1_header():
    """SNMP script must contain ASN.1/BER encoded SNMP GetRequest."""
    code = _get_script_code("udp", 161, 40, "10.0.0.1")
    assert "0x30" in code


def test_snmp_script_has_community_public():
    """SNMP script must use 'public' community string."""
    code = _get_script_code("udp", 161, 40, "10.0.0.1")
    assert "0x70,0x75,0x62,0x6c,0x69,0x63" in code


def test_snmp_script_sends_to_port_161():
    """SNMP script must send to port 161."""
    code = _get_script_code("udp", 161, 40, "10.0.0.1")
    assert "161" in code


def test_snmp_script_no_random_fallback():
    """SNMP script must not use os.urandom for payload."""
    code = _get_script_code("udp", 161, 40, "10.0.0.1")
    assert "os.urandom" not in code


# --- Syslog (port 514) ---

def test_syslog_script_has_rfc3164_format():
    """Syslog script must send a message in RFC 3164 format."""
    code = _get_script_code("udp", 514, 80, "10.0.0.1")
    assert "<13>" in code


def test_syslog_script_has_timestamp():
    """Syslog script must include a timestamp."""
    code = _get_script_code("udp", 514, 80, "10.0.0.1")
    assert "Sep" in code


def test_syslog_script_sends_to_port_514():
    """Syslog script must send to port 514."""
    code = _get_script_code("udp", 514, 80, "10.0.0.1")
    assert "514" in code


def test_syslog_script_no_random_fallback():
    """Syslog script must not use os.urandom for payload."""
    code = _get_script_code("udp", 514, 80, "10.0.0.1")
    assert "os.urandom" not in code


# --- SSDP (port 1900) ---

def test_ssdp_script_has_m_search():
    """SSDP script must send M-SEARCH request."""
    code = _get_script_code("udp", 1900, 120, "10.0.0.1")
    assert "M-SEARCH" in code


def test_ssdp_script_has_host_header():
    """SSDP script must target the SSDP multicast address."""
    code = _get_script_code("udp", 1900, 120, "10.0.0.1")
    assert "239.255.255.250" in code


def test_ssdp_script_has_ssdp_discover():
    """SSDP script must include ssdp:discover MAN header."""
    code = _get_script_code("udp", 1900, 120, "10.0.0.1")
    assert "ssdp:discover" in code


def test_ssdp_script_sends_to_port_1900():
    """SSDP script must send to port 1900."""
    code = _get_script_code("udp", 1900, 120, "10.0.0.1")
    assert "1900" in code


def test_ssdp_script_no_random_fallback():
    """SSDP script must not use os.urandom for payload."""
    code = _get_script_code("udp", 1900, 120, "10.0.0.1")
    assert "os.urandom" not in code


# --- Fallback for unknown ports ---

def test_unknown_port_falls_back_to_random():
    """Unknown UDP ports must fall back to os.urandom (random bytes)."""
    code = _get_script_code("udp", 9999, 512, "10.0.0.1")
    assert "os.urandom" in code
    assert "SOCK_DGRAM" in code


def test_unknown_port_sends_to_correct_dst():
    """Fallback script must still send to the correct destination."""
    code = _get_script_code("udp", 9999, 512, "10.0.0.5")
    assert "10.0.0.5" in code
    assert "9999" in code


# --- All UDP scripts use SOCK_DGRAM ---

def test_all_known_ports_use_dgram():
    """All known UDP protocol scripts must use SOCK_DGRAM."""
    for port in (53, 123, 161, 514, 1900):
        code = _get_script_code("udp", port, 48, "10.0.0.1")
        assert "SOCK_DGRAM" in code, f"Port {port} missing SOCK_DGRAM"


def test_all_known_ports_have_close():
    """All known UDP protocol scripts must close the socket."""
    for port in (53, 123, 161, 514, 1900):
        code = _get_script_code("udp", port, 48, "10.0.0.1")
        assert "close" in code, f"Port {port} missing socket close"
