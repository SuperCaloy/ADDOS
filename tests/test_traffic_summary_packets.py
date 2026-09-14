"""RED tests: packet volumes must reach traffic_summary packet columns.

Root cause: flush_summary INSERT omits total_packets, malicious_dropped,
normal_packets, so graph_history sums zeros and range tabs render flat.
Run: python3 -m pytest tests/test_traffic_summary_packets.py -v
"""
import pytest

from backend.database import writer


@pytest.fixture()
def clean_buffer():
    writer._drain_summary_buffer()
    yield
    writer._drain_summary_buffer()


def test_flush_writes_packet_columns(clean_buffer, monkeypatch):
    captured = {}

    def _capture(sql, params):
        captured['sql'] = sql
        captured['params'] = params

    monkeypatch.setattr(writer, 'ML_ENABLED', True)
    monkeypatch.setattr(writer, 'execute', _capture)
    writer.log_traffic_summary(total=1, threats=1, true_neg=0, fp=0,
                               pkt_total=5000, pkt_dropped=5000, pkt_normal=0)
    writer.flush_summary()
    assert 'total_packets' in captured['sql']
    assert 'malicious_dropped' in captured['sql']
    assert 'normal_packets' in captured['sql']
    params = list(captured['params'])
    assert params[1] == 5000
    assert params[2] == 5000
    assert params[3] == 0


def test_packet_keys_accumulate_in_buffer(clean_buffer, monkeypatch):
    monkeypatch.setattr(writer, 'ML_ENABLED', True)
    monkeypatch.setattr(writer, 'execute', lambda sql, params: None)
    writer.log_traffic_summary(total=1, threats=0, true_neg=1, fp=0,
                               pkt_total=100, pkt_dropped=0, pkt_normal=100)
    writer.log_traffic_summary(total=1, threats=0, true_neg=1, fp=0,
                               pkt_total=200, pkt_dropped=0, pkt_normal=200)
    snapshot = writer._drain_summary_buffer()
    assert snapshot['pkt_total'] == 300
    assert snapshot['pkt_normal'] == 300


def test_bucket_rows_sum_packet_columns():
    from backend.api import graph
    import datetime
    now = datetime.datetime.now()
    rows = [
        {'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
         'total_packets': 1000, 'malicious_dropped': 800, 'normal_packets': 200},
    ]
    buckets = graph._bucket_rows(rows, now - datetime.timedelta(hours=1), now, 60)
    assert sum(b['incoming'] for b in buckets) == 1000
    assert sum(b['blocked'] for b in buckets) == 800
    assert sum(b['forwarded'] for b in buckets) == 200
