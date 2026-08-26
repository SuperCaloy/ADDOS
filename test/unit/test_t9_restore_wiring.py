"""T9: restore_from_db wiring and the Phase 2 action map (plan BFA-P2).

restore_from_db is currently dead code: nothing calls it, and its action
map would downgrade a surviving Time Ban (phase 2) to rate_limit while live
escalation sends block. This pins both halves of the agreed fix: the map
must send block for phase 2 with the remaining ttl, and create_app must
actually call restore_from_db.
"""
import datetime
import time
from pathlib import Path

from backend.database import writer
from backend.mitigation.state_machine import StateMachine

REPO_ROOT = Path(__file__).resolve().parents[2]


def _row(expires_in_s):
    exp = datetime.datetime.now() + datetime.timedelta(seconds=expires_in_s)
    return {
        "src_ip": "10.0.0.66",
        "phase": 2,
        "attack_vector": "SYN Flood",
        "if_score": 0.9,
        "confidence": 0.9,
        "action_taken": "Time Ban",
        "permanent": 1,
        "block_expires_at": exp.strftime("%Y-%m-%d %H:%M:%S"),
    }


def test_restore_phase2_pushes_block_with_remaining_ttl(temp_db, monkeypatch):
    machine = StateMachine()
    sent = []

    class FakeCommander:
        def send(self, cmd):
            sent.append(cmd)

    machine._commander = FakeCommander()
    monkeypatch.setattr(writer, "load_quarantine_states", lambda: [_row(120)])

    machine.restore_from_db()

    assert len(sent) == 1
    cmd = sent[0]
    assert cmd["action"] == "block"
    assert cmd["src_ip"] == "10.0.0.66"
    assert 60 <= cmd["ttl"] <= 120


def test_main_wires_restore_from_db():
    src = (REPO_ROOT / "backend" / "main.py").read_text(encoding="utf-8")
    assert "restore_from_db" in src
