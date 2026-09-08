import zmq as _zmq

COMMAND_ADDR = "tcp://127.0.0.1:5556"


def send_ryu_command(payload: dict, addr: str = COMMAND_ADDR) -> None:
    # Push a controller command to Ryu via ZMQ.
    ctx = _zmq.Context.instance()
    sock = ctx.socket(_zmq.PUSH)
    sock.setsockopt(_zmq.LINGER, 0)
    sock.setsockopt(_zmq.SNDTIMEO, 500)
    sock.connect(addr)
    sock.send_json(payload)
    sock.close()
