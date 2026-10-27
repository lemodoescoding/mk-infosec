"""Minimal client for entities.aes_server (quiet: no AES trace).

  python -m entities.aes_client "hello world" [--host 127.0.0.1] [--port 6000] [--mode CBC]
"""
import argparse
import os

from config.settings import SOCKET_TIMEOUT
from common.network import connect_tcp, send_json, recv_json
from common.protocol import CHAT_MESSAGE, create_message
from common.utils import key_from_ascii
from crypto.modes import encrypt_text, decrypt_text

DEMO_KEY = "demo-aes-key-123"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("message")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--mode", default="CBC", choices=["ECB", "CBC"])
    args = parser.parse_args()

    key = key_from_ascii(os.environ.get("AES_SERVER_KEY", DEMO_KEY))
    with connect_tcp(args.host, args.port, SOCKET_TIMEOUT) as sock:
        send_json(sock, create_message(CHAT_MESSAGE, payload=encrypt_text(key, args.message, args.mode)))
        reply = recv_json(sock)

    if "payload" in reply:
        print("server says:", decrypt_text(key, reply["payload"]))
    else:
        print("server error:", reply)


if __name__ == "__main__":
    main()
