# ZeroMQ command transmitter sending mitigation actions to the OpenFlow Ryu controller.
# Provides a non-blocking push socket with automatic reconnect handling.

import zmq
import json
import time
import threading
import logging
from backend.config import ZMQ_COMMAND_ADDR

log = logging.getLogger(__name__)

_RECONNECT_DELAY_S = 3.0
_SEND_TIMEOUT_MS   = 500


class ZmqCommander:
    # Sends OpenFlow commands to Ryu over a ZeroMQ PUSH socket.
    # Drops commands with a warning if the controller is offline and retries on reconnect.

    def __init__(self):
        self._lock  = threading.Lock()
        self._ctx   = zmq.Context.instance()
        self._sock  = None
        self._connect()

    def _connect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = self._ctx.socket(zmq.PUSH)
        self._sock.setsockopt(zmq.SNDTIMEO, _SEND_TIMEOUT_MS)
        self._sock.setsockopt(zmq.LINGER, 0)
        self._sock.connect(ZMQ_COMMAND_ADDR)
        log.info("ZMQ commander connected to %s", ZMQ_COMMAND_ADDR)

    def send(self, command: dict) -> None:
        # Sends a command dictionary to Ryu without blocking.
        # Drops payloads safely if socket buffer is full or controller is unreachable.
        payload = json.dumps(command).encode()
        with self._lock:
            try:
                self._sock.send(payload, zmq.NOBLOCK)
                try:
                    from backend.api.events import push_expert_event as _push
                    _push({
                        "mitigation": {
                            "action": command.get("action", "unknown"),
                            "src_ip": command.get("src_ip", ""),
                            "ts": time.strftime("%H:%M:%S"),
                        }
                    })
                except Exception:
                    pass
            except zmq.Again:
                log.debug("ZMQ command dropped (Ryu unavailable): %s", command)
            except zmq.ZMQError as e:
                log.warning("ZMQ send error: %s: reconnecting", e)
                self._reconnect_safe()

    def _reconnect_safe(self) -> None:
        # Re-establishes ZeroMQ socket connection after transport errors.
        # Must be invoked while instance lock is acquired.
        try:
            time.sleep(_RECONNECT_DELAY_S)
            self._connect()
        except Exception as exc:
            log.warning("ZMQ commander reconnect failed: %s", exc)

    def close(self) -> None:
        # Closes the ZeroMQ socket gracefully.
        with self._lock:
            if self._sock:
                self._sock.close()


# Module-level singleton instance wired into state machine and mitigation handlers.
commander = ZmqCommander()