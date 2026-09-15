from unittest import mock
import sqlite3


def _seed(db):
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE ip_attack_history(src_ip TEXT, ban_level INT)")
    conn.execute("CREATE TABLE quarantine_state(src_ip TEXT)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.16',2)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.17',3)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.99',1)")
    conn.execute("INSERT INTO quarantine_state VALUES('10.0.0.16')")
    conn.commit()
    conn.close()


def _mk_topo():
    topo = mock.MagicMock()
    topo._ATTACKER_NUMS = {16, 17}
    topo._RETIRED_NUMS = set()
    topo._LEGIT_NUMS = set()
    topo.BACKEND_API = "http://127.0.0.1:5000"
    return topo


def test_reset_session_keep_ledger(tmp_path):
    import topology.benchmark as b
    db = tmp_path / "ddos.db"
    _seed(db)
    with mock.patch("topology.benchmark._post_json"):
        b._reset_session_keep_ledger(_mk_topo(), db)
    c = sqlite3.connect(str(db))
    c.row_factory = sqlite3.Row
    hist = c.execute(
        "SELECT COUNT(*) n FROM ip_attack_history "
        "WHERE src_ip IN ('10.0.0.16','10.0.0.17')").fetchone()["n"]
    quar = c.execute("SELECT COUNT(*) n FROM quarantine_state").fetchone()["n"]
    led = c.execute(
        "SELECT total_offences t FROM offence_totals "
        "WHERE src_ip='10.0.0.16'").fetchone()
    out = c.execute(
        "SELECT COUNT(*) n FROM ip_attack_history "
        "WHERE src_ip='10.0.0.99'").fetchone()["n"]
    c.close()
    assert hist == 0
    assert quar == 0
    assert led["t"] == 1
    assert out == 1


def test_reset_session_never_raises_without_db(tmp_path):
    import topology.benchmark as b
    with mock.patch("topology.benchmark._post_json"):
        b._reset_session_keep_ledger(_mk_topo(), tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()
