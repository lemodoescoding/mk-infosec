import json
import os
import socket

from config.settings import (
    AES_MODE,
    BOB_HOST,
    BOB_PORT,
    SOCKET_TIMEOUT,
)

from common.network import create_tcp_server, recv_json, send_json
from common.protocol import (
    CHAT_MESSAGE,
    CHAT_RESPONSE,
    ERROR,
    SESSION_CONFIRM,
    SESSION_TICKET,
    create_message,
)
from common.utils import key_from_ascii
from crypto.modes import decrypt_text, encrypt_text

DEFAULT_KEYS = {
    "Alice": "alice-master-key",
    "Bob": "bob---master-key",
}


def _load_master_key(identity: str) -> bytes:
    env_name = f"KDC_KEY_{identity.upper()}"
    value = os.environ.get(env_name, DEFAULT_KEYS[identity])
    return key_from_ascii(value)


def _split_ticket(ticket_plaintext: str) -> tuple[str, str]:
    parts = ticket_plaintext.split("||")
    if len(parts) != 2:
        raise ValueError("Ticket does not contain session key and requester")
    session_key_hex, requester = parts
    if not session_key_hex or not requester:
        raise ValueError("Ticket fields are missing")
    return session_key_hex, requester


def handle_alice(conn: socket.socket, address: str) -> None:
    conn.settimeout(SOCKET_TIMEOUT)
    try:
        message = recv_json(conn)
        if message.get("type") != SESSION_TICKET:
            send_json(conn, create_message(ERROR, reason="Expected session ticket"))
            return

        ticket = message.get("ticket")
        if not isinstance(ticket, dict):
            raise ValueError("Session ticket payload missing")

        ticket_plaintext = decrypt_text(_load_master_key("Bob"), ticket)
        session_key_hex, requester = _split_ticket(ticket_plaintext)

        if requester != "Alice":
            raise ValueError("Ticket requester mismatch")

        session_key = bytes.fromhex(session_key_hex)
        if len(session_key) not in (16, 24, 32):
            raise ValueError("Session key size is invalid")

        send_json(conn, create_message(
            SESSION_CONFIRM,
            status="ok",
            requester="Bob",
            target="Alice",
            session_key=session_key.hex(),
        ))

        while True:
            message = recv_json(conn)
            if message.get("type") == CHAT_MESSAGE:
                payload = message.get("payload")
                if not isinstance(payload, dict):
                    raise ValueError("Missing chat payload")
                plaintext = decrypt_text(session_key, payload)
                response_payload = encrypt_text(session_key, f"ECHO: {plaintext}", AES_MODE)
                send_json(conn, create_message(CHAT_RESPONSE, payload=response_payload))
                continue

            if message.get("type") == ERROR:
                print(f"[Bob] Alice closed the chat: {message.get('reason', 'unknown error')}")
                return

            send_json(conn, create_message(ERROR, reason="Unexpected message type"))
            return

    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[Bob] Client {address} error: {exc}")
        try:
            send_json(conn, create_message(ERROR, reason=str(exc)))
        except (ConnectionError, OSError, ValueError):
            pass
    finally:
        conn.close()


def main() -> None:
    host = os.environ.get("BOB_HOST", BOB_HOST)
    port = int(os.environ.get("BOB_PORT", BOB_PORT))
    with create_tcp_server(host, port) as server:
        print(f"[Bob] Listening on {host}:{port}")
        while True:
            conn, address = server.accept()
            handle_alice(conn, address)


if __name__ == "__main__":
    main()
