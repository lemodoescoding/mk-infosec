import json
import socket
import struct

from config.settings import (
    MAX_MESSAGE_SIZE
)

def recv_exact(sock: socket.socket, length: int) -> bytes:
    # TODO: implement read exactly length bytes or raise ConnectionError if peer disconnects
    return b""

def send_json(sock: socket.socket, message: dict) -> None:
    # TODO: serialize a JSON object and send it with a 4-byte length prefix
    # struct pack is !I
    return

def recv_json(sock: socket.socket) -> dict:
    # TODO: receive one length-prefixed JSON object
    # struct pack is !I

    return json.loads(b"".decode("utf-8"))

def create_tcp_server(host: str, port: int, backlog: int = 5) -> socket.socket:
    # TODO: crate and return a listening TCP socket, caller owns its lifecycle
    return socket.socket()

def connect_tcp(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    # TODO: connect to a TCP endpoint and return the connected server
    return socket.socket()
