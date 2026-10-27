"""Basic AES TCP echo server.

Receives CHAT_MESSAGE, decrypts it (printing every AES step in hex), then
replies with CHAT_RESPONSE = AES-encrypt("ECHO: <plaintext>") (also traced).

  python -m entities.aes_server_test [--host 127.0.0.1] [--port 6000] [--matrix]

Key (16 ASCII chars) comes from env AES_SERVER_KEY; a demo key is used if unset.
Message format (ASCII JSON, length-prefixed, see common/network.py):
  {"type": "CHAT_MESSAGE", "payload": {"mode": "CBC", "iv": "<hex>", "ciphertext": "<hex>"}}
"""
import argparse
import os
import socket

from config.settings import SOCKET_TIMEOUT
from common.network import create_tcp_server, recv_json, send_json
from common.protocol import CHAT_MESSAGE, CHAT_RESPONSE, ERROR, create_message
from common.utils import key_from_ascii
from crypto.aes_trace_test import TracedAES, traced_encrypt_text, traced_decrypt_text

DEMO_KEY = "demo-aes-key-123"  # demo only, never use a hardcoded key for real


def _valid_payload(payload) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("mode") not in ("ECB", "CBC"):
        return False
    if not isinstance(payload.get("ciphertext"), str):
        return False
    if payload["mode"] == "CBC" and not isinstance(payload.get("iv"), str):
        return False
    return True


def handle_client(conn: socket.socket, address, aes: TracedAES) -> None:
    conn.settimeout(SOCKET_TIMEOUT)
    print(f"\n[SERVER] Connection from {address}")
    try:
        while True:
            try:
                message = recv_json(conn)
            except ConnectionError:
                break  # client closed the connection

            if message.get("type") != CHAT_MESSAGE or not _valid_payload(message.get("payload")):
                send_json(conn, create_message(ERROR, reason="Bad message"))
                continue

            payload = message["payload"]
            print(f"[SERVER] Received: {payload}")
            try:
                plaintext = traced_decrypt_text(aes, payload)
            except ValueError as exc:
                print(f"[SERVER] Decrypt failed: {exc}")
                send_json(conn, create_message(ERROR, reason="Decryption failed"))
                continue

            reply = traced_encrypt_text(aes, f"ECHO: {plaintext}", payload["mode"])
            send_json(conn, create_message(CHAT_RESPONSE, payload=reply))
            print(f"[SERVER] Sent: {reply}")
    except (OSError, ValueError) as exc:
        print(f"[SERVER] Client {address} error: {exc}")
    finally:
        conn.close()
        print(f"[SERVER] Connection {address} closed")


def main() -> None:
    parser = argparse.ArgumentParser(description="AES TCP echo server (with hex trace)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--matrix", action="store_true", help="also print the 4x4 state grid")
    args = parser.parse_args()

    key = key_from_ascii(os.environ.get("AES_SERVER_KEY", DEMO_KEY))
    aes = TracedAES(key, matrix=args.matrix)  # prints the key schedule once

    with create_tcp_server(args.host, args.port) as server:
        print(f"[SERVER] Listening on {args.host}:{args.port}")
        while True:
            conn, address = server.accept()
            handle_client(conn, address, aes)


if __name__ == "__main__":
    main()
