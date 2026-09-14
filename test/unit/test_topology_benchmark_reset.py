from unittest import mock
import sqlite3


def test_reset_preserves_history_all_modes(tmp_path):
    import topology.benchmark as b
    db = tmp_path / "ddos.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE ip_attack_history(src_ip TEXT, ban_level INT)")
    conn.execute("CREATE TABLE quarantine_state(src_ip TEXT)")
    conn.execute("INSERT INTO ip_attack_history VALUES('10.0.0.16',2)")
    conn.execute("INSERT INTO quarantine_state VALUES('10.0.0.16')")
    conn.commit()
    conn.close()

    topo = mock.MagicMock()
    topo._ATTACKER_NUMS = {16}
    topo._RETIRED_NUMS = set()
    topo._LEGIT_NUMS = set()
    with mock.patch("topology.benchmark._post_json"):
        with mock.patch("topology.benchmark._resolve_db_path",
                        return_value=db):
            b._reset_preserve_history(topo)

    c = sqlite3.connect(str(db))
    left = c.execute("SELECT COUNT(*) FROM ip_attack_history").fetchone()[0]
    c.close()
    assert left == 1
    topo.stop_all_attacks.assert_called_once()
