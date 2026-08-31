"""T3: ban-expiry safety net truth table.

_handle_ban_expiry must map (recent_pps, if_score, reputation) to exactly:
re-ban / blackhole / release. These outcomes are the reason cadence changes
to banned-IP rescoring were rejected; this test pins them.
"""
import time

import pytest

from backend.database import writer
from backend.mitigation.state_machine import IpState, StateMachine
from backend.mitigation import behavioral


@pytest.fixture()
def sm(temp_db, monkeypatch):
    machine = StateMachine()
    events = []
    monkeypatch.setattr(writer, "log_mitigation_event",
                        lambda event: events.append(event))
    return machine, events


def _ban_state(src_ip, recent_pps, if_score):
    st = IpState(
        src_ip=src_ip,
        phase=2,
        attack_vector="SYN Flood",
        if_score=if_score,
        confidence=0.9,
        priority="High",
        action_taken="Time Ban",
        ban_level=1,
    )
    st.ttl_expires_at = time.monotonic() - 1.0
    st.recent_pps = recent_pps
    return st


def _seed_reputation_over_threshold(ip):
    # 7 offenses at confidence=0.9: 7 * 2.0 * 0.9^2 = 11.34 >= 10.0
    for _ in range(7):
        behavioral.record_offense(
            src_ip=ip, attack_vector="SYN Flood", if_score=0.9,
            confidence=0.9, priority="High", phase_reached=2,
            first_seen="2026-08-25 10:00:00", unblock_reason="Test",
            ban_level=1, offence_count=1,
        )


def test_quiet_low_score_expiry_releases_and_records_offense(sm):
    machine, events = sm
    st = _ban_state("10.0.0.31", recent_pps=0.0, if_score=0.9)
    machine._states[st.src_ip] = st
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.src_ip not in machine._states
    released = [e for e in events if e["event_type"] == "released"
                and e["src_ip"] == st.src_ip]
    assert len(released) == 1
    # Offense recorded so a returning attacker routes through on_reoffence.
    assert writer.get_offense_total_count(st.src_ip) == 1


def test_still_flooding_with_clean_record_rebans(sm):
    machine, events = sm
    st = _ban_state("10.0.0.32", recent_pps=50.0, if_score=0.9)
    machine._states[st.src_ip] = st
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.phase == 2
    assert st.ttl_expires_at is not None and st.ttl_expires_at > time.monotonic()
    assert st.action_taken.startswith("Time Ban")


def test_still_flooding_with_blackhole_reputation_escalates_to_phase3(sm):
    machine, events = sm
    st = _ban_state("10.0.0.33", recent_pps=50.0, if_score=0.9)
    machine._states[st.src_ip] = st
    _seed_reputation_over_threshold(st.src_ip)
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.phase == 3
    assert st.action_taken == "Blackhole"
    assert st.permanent is True


def test_stopped_traffic_never_escalates_even_with_bad_reputation(sm):
    machine, events = sm
    st = _ban_state("10.0.0.34", recent_pps=0.0, if_score=0.9)
    machine._states[st.src_ip] = st
    _seed_reputation_over_threshold(st.src_ip)
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.src_ip not in machine._states
    assert any(e["event_type"] == "released" and e["src_ip"] == st.src_ip
               for e in events)


def test_weak_score_blocks_escalation_even_while_flooding(sm):
    # pps elevated but if_score far below thr*0.8 -> score_near False -> release.
    machine, events = sm
    st = _ban_state("10.0.0.35", recent_pps=50.0, if_score=0.1)
    machine._states[st.src_ip] = st
    _seed_reputation_over_threshold(st.src_ip)
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.src_ip not in machine._states
