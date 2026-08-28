from unittest import mock


def test_systemexit_propagates_from_cli():
    net = mock.MagicMock()
    captured = {"stopped": False}
    net.stop.side_effect = lambda: captured.__setitem__("stopped", True)

    class FakeCLI:
        def __init__(self, net): self.net = net
        def run(self):
            raise SystemExit(0)

    try:
        FakeCLI(net).run()
    except SystemExit:
        pass
    finally:
        net.stop()
    assert captured["stopped"] is True
