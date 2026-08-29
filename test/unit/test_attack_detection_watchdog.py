"""Attack-detection fallback: watchdog + verify + stop settle.

Pins: an attacker whose hping3 is alive but that the backend never shows in
/state_machine or /deception gets poked (hping3 killed; the existing worker
restart loop relaunches it) so a fresh table-miss reinstalls the forward
rule and flow_stats resume.
"""
import time
from unittest import mock


def _mk_payload(*state_ips, sinkholes=()):
    return {
        "state_machine": {ip: {} for ip in state_ips},
        "deception": {"active_sinkholes": [{"src_ip": ip} for ip in sinkholes]},
    }


def test_needs_poke_core_rule():
    import topology.topology as t
    assert t._needs_poke(ip="10.0.0.7", alive=True,
                         seen=set(), active={"10.0.0.7"}) is True
    assert t._needs_poke(ip="10.0.0.7", alive=True,
                         seen={"10.0.0.7"}, active={"10.0.0.7"}) is False
    assert t._needs_poke(ip="10.0.0.8", alive=True,
                         seen=set(), active={"10.0.0.7"}) is False
    assert t._needs_poke(ip="10.0.0.7", alive=False,
                         seen=set(), active={"10.0.0.7"}) is False


def test_evidence_ips_union_of_state_machine_and_sinkholes():
    import topology.topology as t
    payload = _mk_payload("10.0.0.6", "10.0.0.7", sinkholes=["10.0.0.22"])
    assert t._evidence_ips(payload) == {"10.0.0.6", "10.0.0.7", "10.0.0.22"}


def test_watchdog_pokes_unseen_alive_and_skips_others():
    import topology.topology as t
    poked = []
    evidence = iter([
        _mk_payload("10.0.0.6"),            # first pass: only h6 seen
        _mk_payload("10.0.0.6", "10.0.0.7"),  # second: h7 seen too
    ])
    seen = {"10.0.0.6", "10.0.0.7", "10.0.0.8"}

    def fake_evidence():
        return next(evidence, _mk_payload())

    class FakeStop:
        def __init__(self):
            self.n = 0
        def is_set(self):
            self.n += 1
            return self.n > 2   # run two passes then stop

    def fake_alive(ip):
        return ip in seen

    t._attack_watchdog_loop(
        active_ips={"10.0.0.6", "10.0.0.7", "10.0.0.8"},
        stop=FakeStop(),
        interval_s=0.0, window_s=999.0,
        evidence_fn=fake_evidence, alive_fn=fake_alive,
        poke_fn=lambda ip: poked.append(ip),
        now_fn=lambda: 100.0,  # fixed clock: window never expires
    )
    assert "10.0.0.7" in poked          # unseen+alive on pass 1 -> poked
    assert poked.count("10.0.0.8") == 2  # unseen on BOTH passes -> poked twice
    assert "10.0.0.6" not in poked       # seen on pass 1 -> never poked


def test_watchdog_skips_poke_when_backend_down():
    import topology.topology as t
    poked = []

    class FakeStop:
        def __init__(self):
            self.n = 0
        def is_set(self):
            self.n += 1
            return self.n > 1   # single pass, then stop

    t._attack_watchdog_loop(
        active_ips={"10.0.0.7"},
        stop=FakeStop(),
        interval_s=0.0, window_s=999.0,
        evidence_fn=lambda: None,  # backend offline: cannot verify
        alive_fn=lambda ip: True,
        poke_fn=lambda ip: poked.append(ip),
        now_fn=lambda: 100.0,
    )
    assert poked == []


def test_watchdog_stops_when_window_expires():
    import topology.topology as t
    poked = []
    clock = {"now": 0.0}

    class FakeStop:
        def is_set(self):
            return False   # stop only via window expiry

    def fake_now():
        clock["now"] += 200.0   # first pass at 0, next at 200 > window 90
        return clock["now"]

    t._attack_watchdog_loop(
        active_ips={"10.0.0.7"},
        stop=FakeStop(),
        interval_s=0.0, window_s=90.0,
        evidence_fn=lambda: _mk_payload(),
        alive_fn=lambda ip: True,
        poke_fn=lambda ip: poked.append(ip),
        now_fn=fake_now,
    )
    assert poked == []   # window expired before a poke could matter


def test_post_stop_settle_sleeps_constant():
    import topology.topology as t
    slept = []
    with mock.patch.object(t.time, "sleep", lambda s: slept.append(s)):
        t._post_stop_settle()
    assert slept == [t._STOP_SETTLE_S]


def test_poke_attacker_kills_hping3_only():
    import topology.topology as t
    host = mock.MagicMock()
    with mock.patch.object(t, "net") as net, \
         mock.patch.object(t, "_nsrun") as nsrun:
        net.get.return_value = host
        t._poke_attacker(7)
    net.get.assert_called_once_with("h7")
    nsrun.assert_called_once()
    cmd = nsrun.call_args[0][1]
    assert "pkill -9 -x hping3" in cmd