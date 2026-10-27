import json
import socket
import struct

from common.protocol import validate_message
from config.settings import (
    MAX_MESSAGE_SIZE
)

_HEADER = struct.Struct("!I")

def recv_exact(sock: socket.socket, length: int) -> bytes:
    # TODO: implement read exactly length bytes or raise ConnectionError if peer disconnects
    chunks = []
    remaining = length

    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Peer closes connection")

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)

def send_json(sock: socket.socket, message: dict) -> None:
    # TODO: serialize a JSON object and send it with a 4-byte length prefix
    # struct pack is !I
    payload = json.dumps(message, separators=(",",":"), ensure_ascii=True).encode("ascii")

    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("message exceeded MAX_MESSAGE_SIZE")

    sock.sendall(_HEADER.pack(len(payload)) + payload)

def recv_json(sock: socket.socket) -> dict:
    # TODO: receive one length-prefixed JSON object
    # struct pack is !I
    (length, ) = _HEADER.unpack(recv_exact(sock, _HEADER.size))

    if length == 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError("invalid message length")

    payload = recv_exact(sock, length)

    return validate_message(json.loads(payload.decode("ascii")))

def create_tcp_server(host: str, port: int, backlog: int = 5) -> socket.socket:
    # TODO: crate and return a listening TCP socket, caller owns its lifecycle
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(backlog)
    except OSError:
        server.close()
        raise
    return server

def connect_tcp(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    # TODO: connect to a TCP endpoint and return the connected server
    return socket.create_connection((host, port), timeout=timeout)
