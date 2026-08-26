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


def test_restore_hold_pushes_rate_limit(temp_db, monkeypatch):
    """Unscored hold rows persist as phase 2 permanent, but live as
    throttles; restoring them as block would hard-drop a host that was only
    being held (BFA-P2, F5)."""
    machine = StateMachine()
    sent = []

    class FakeCommander:
        def send(self, cmd):
            sent.append(cmd)

    machine._commander = FakeCommander()
    row = _row(120)
    row["action_taken"] = "Holding (unscored, queue overload)"
    monkeypatch.setattr(writer, "load_quarantine_states", lambda: [row])

    machine.restore_from_db()

    assert len(sent) == 1
    assert sent[0]["action"] == "rate_limit"
    assert sent[0]["src_ip"] == "10.0.0.66"


def test_main_wires_restore_from_db():
    """restore_from_db must be called inside create_app, after the DB is
    initialized and before the tick thread starts."""
    src = (REPO_ROOT / "backend" / "main.py").read_text(encoding="utf-8")
    create_app = src.split("def create_app()", 1)[1]
    assert create_app.index("get_connection()") < \
        create_app.index("restore_from_db") < \
        create_app.index("start_tick_thread()")
