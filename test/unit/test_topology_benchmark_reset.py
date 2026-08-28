from unittest import mock
import sqlite3


def test_reset_keeps_offences_and_clears_reputation(tmp_path):
    import topology.benchmark as b
    db = tmp_path / "ddos.db"
    conn = sqlite3.connect(str(db)); conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE ip_attack_history(src_ip TEXT, ban_level INT)")
    conn.execute("CREATE TABLE quarantine_state(src_ip TEXT)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.10',3)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.11',3)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.99',1)")
    conn.execute("INSERT INTO quarantine_state VALUES('10.0.0.10')")
    conn.commit(); conn.close()

    topo = mock.MagicMock(); topo._ATTACKER_NUMS={10,11}; topo._RETIRED_NUMS=set()
    topo._LEGIT_NUMS=set(); topo.BACKEND_API="http://127.0.0.1:5000"
    with mock.patch("topology.benchmark._post_json"):
        # redirect connect to the tmp db
        real = sqlite3.connect
        with mock.patch("topology.benchmark.sqlite3.connect",
                        side_effect=lambda p, *a, **k: real(str(db), *a, **k)):
            with mock.patch("topology.benchmark.Path.exists", return_value=True):
                b._reset_reputation_keep_offences(topo)

    c = sqlite3.connect(str(db)); c.row_factory = sqlite3.Row
    hist_left = c.execute("SELECT COUNT(*) n FROM ip_attack_history WHERE src_ip IN ('10.0.0.10','10.0.0.11')").fetchone()["n"]
    quar = c.execute("SELECT COUNT(*) n FROM quarantine_state").fetchone()["n"]
    ledger = c.execute("SELECT total_offences FROM offence_totals WHERE src_ip='10.0.0.10'").fetchone()
    out_of_scope = c.execute("SELECT COUNT(*) n FROM ip_attack_history WHERE src_ip='10.0.0.99'").fetchone()["n"]
    c.close()
    assert hist_left == 0
    assert quar == 0
    assert ledger["total_offences"] == 1
    assert out_of_scope == 1
