"""T23: benign transient recovery (benign-hour-drift-false-positive P3/P4).

P3: state.if_score must no longer be an upward-only ratchet. A stale peak
decays 5% per live poll so a single benign post-reset transient (score
~0.608-0.66 vs thr 0.6092) cannot freeze an elevated score forever, while a
continuously elevated live score re-pins the peak every poll (no FNR).
Applies at BOTH ratchet sites: update_observation (every-poll path) and
on_detection (anomaly-poll path).

P4: a fully clean ban expiry (recent_pps <= 1.0 AND decayed score below
thr*0.8) must record no behavioral offense, so one benign transient cannot
accumulate toward the 10.0 blackhole line. A release with either signal
still elevated keeps recording (returning-attacker routing preserved).
"""
import time

import pytest

from backend.database import writer
from backend.mitigation.state_machine import IpState, StateMachine


DECAY = 0.95


@pytest.fixture()
def sm(temp_db, monkeypatch):
    machine = StateMachine()
    events = []
    monkeypatch.setattr(writer, "log_mitigation_event",
                        lambda event: events.append(event))
    return machine, events


def _tracked_state(src_ip, if_score, phase=1):
    st = IpState(
        src_ip=src_ip,
        phase=phase,
        attack_vector="SYN Flood",
        if_score=if_score,
        confidence=0.9,
        priority="Low",
        action_taken="Time Ban" if phase == 2 else "Quarantined",
        ban_level=1 if phase == 2 else 0,
    )
    st.ttl_expires_at = time.monotonic() - 1.0
    return st


# ── P3: update_observation decay (every-poll path) ────────────────────────

def test_update_observation_decays_stale_peak(sm):
    machine, _ = sm
    st = _tracked_state("10.0.0.41", if_score=0.66)
    machine._states[st.src_ip] = st
    machine.update_observation(st.src_ip, 0.30, "Normal", 0.5, 0.5)
    assert st.if_score == pytest.approx(0.66 * DECAY)


def test_update_observation_repeated_decay_clears_transient(sm):
    machine, _ = sm
    st = _tracked_state("10.0.0.42", if_score=0.66)
    machine._states[st.src_ip] = st
    for _ in range(10):
        machine.update_observation(st.src_ip, 0.30, "Normal", 0.5, 0.5)
    assert st.if_score < 0.66 * DECAY ** 10 + 1e-9
    # Below the thr*0.8 re-ban net (0.8 * 0.6092) after ~10 quiet polls.
    assert st.if_score < 0.487


def test_update_observation_sustained_attack_holds_score(sm):
    machine, _ = sm
    st = _tracked_state("10.0.0.43", if_score=0.80)
    machine._states[st.src_ip] = st
    for _ in range(20):
        machine.update_observation(st.src_ip, 0.80, "SYN Flood", 0.95, 50.0)
    assert st.if_score == pytest.approx(0.80)


def test_update_observation_lower_live_score_never_raises_peak(sm):
    machine, _ = sm
    st = _tracked_state("10.0.0.46", if_score=0.30)
    machine._states[st.src_ip] = st
    machine.update_observation(st.src_ip, 0.10, "Normal", 0.5, 0.5)
    assert st.if_score == pytest.approx(0.30 * DECAY)


# ── P3: on_detection decay (anomaly-poll path, second ratchet) ────────────

def test_on_detection_existing_state_decays_stale_peak(sm):
    machine, _ = sm
    st = _tracked_state("10.0.0.44", if_score=0.66)
    machine._states[st.src_ip] = st
    machine.on_detection(st.src_ip, 0.30, "Normal", 0.5)
    assert st.if_score == pytest.approx(0.66 * DECAY)


def test_on_detection_higher_score_still_raises(sm):
    machine, _ = sm
    st = _tracked_state("10.0.0.47", if_score=0.55)
    machine._states[st.src_ip] = st
    machine.on_detection(st.src_ip, 0.75, "SYN Flood", 0.95)
    assert st.if_score == pytest.approx(0.75)


# ── P4: clean-release offence gate ────────────────────────────────────────

def test_clean_ban_expiry_records_no_offense(sm):
    # pps low AND score decayed below thr*0.8: fully clean release.
    machine, events = sm
    st = _tracked_state("10.0.0.45", if_score=0.05, phase=2)
    st.recent_pps = 0.0
    machine._states[st.src_ip] = st
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.src_ip not in machine._states
    released = [e for e in events if e["event_type"] == "released"
                and e["src_ip"] == st.src_ip]
    assert len(released) == 1
    assert writer.get_offense_total_count(st.src_ip) == 0


def test_score_elevated_release_still_records_offense(sm):
    # Score still >= thr*0.8 at expiry (traffic stopped, no decay polls):
    # release keeps recording so a returning attacker routes through
    # on_reoffence (pins test_t3's first case).
    machine, _ = sm
    st = _tracked_state("10.0.0.48", if_score=0.9, phase=2)
    st.recent_pps = 0.0
    machine._states[st.src_ip] = st
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.src_ip not in machine._states
    assert writer.get_offense_total_count(st.src_ip) == 1


def test_pps_elevated_release_still_records_offense(sm):
    # pps > 1.0 but score below thr*0.8 (t3 weak-score case): release
    # happens, offense still recorded.
    machine, _ = sm
    st = _tracked_state("10.0.0.49", if_score=0.1, phase=2)
    st.recent_pps = 50.0
    machine._states[st.src_ip] = st
    machine._handle_ban_expiry(st.src_ip, st)
    assert st.src_ip not in machine._states
    assert writer.get_offense_total_count(st.src_ip) == 1
