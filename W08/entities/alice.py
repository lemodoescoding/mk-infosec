import json
import os
import secrets

from config.settings import (
    AES_MODE,
    BOB_HOST,
    BOB_PORT,
    KDC_HOST,
    KDC_PORT,
    SOCKET_TIMEOUT,
)

from common.network import connect_tcp, recv_json, send_json
from common.protocol import (
    CHAT_MESSAGE,
    CHAT_RESPONSE,
    ERROR,
    KEY_REQUEST,
    KEY_RESPONSE,
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


def _generate_nonce() -> str:
    return secrets.token_hex(8)


def request_session_from_kdc() -> dict:
    nonce = _generate_nonce()
    with connect_tcp(os.environ.get("KDC_HOST", KDC_HOST), int(os.environ.get("KDC_PORT", KDC_PORT)), SOCKET_TIMEOUT) as sock:
        send_json(sock, create_message(
            KEY_REQUEST,
            requester="Alice",
            target="Bob",
            nonce=nonce,
        ))
        response = recv_json(sock)

    if response.get("type") == ERROR:
        raise ValueError(response.get("reason", "KDC rejected key request"))
    if response.get("type") != KEY_RESPONSE or "response" not in response:
        raise ValueError("Unexpected KDC response")

    protected = response["response"]
    inner = json.loads(decrypt_text(_load_master_key("Alice"), protected))

    if inner.get("requester") != "Alice" or inner.get("target") != "Bob":
        raise ValueError("KDC response does not match Alice/Bob session")
    if inner.get("nonce") != nonce:
        raise ValueError("KDC response nonce mismatch")
    if not isinstance(inner.get("ticket"), dict):
        raise ValueError("KDC response does not include a valid ticket")

    session_key = bytes.fromhex(inner["session_key"])
    if len(session_key) not in (16, 24, 32):
        raise ValueError("Session key length is invalid")

    return {**inner, "session_key": session_key}


def chat_loop(session_key: bytes, ticket: dict | None = None) -> None:
    if ticket is None:
        raise ValueError("Ticket is required before chat begins")

    with connect_tcp(os.environ.get("BOB_HOST", BOB_HOST), int(os.environ.get("BOB_PORT", BOB_PORT)), SOCKET_TIMEOUT) as sock:
        send_json(sock, create_message(SESSION_TICKET, ticket=ticket))
        confirm = recv_json(sock)

        if confirm.get("type") == ERROR:
            raise ValueError(confirm.get("reason", "Bob rejected session ticket"))
        if confirm.get("type") != SESSION_CONFIRM:
            raise ValueError(f"Unexpected Bob response: {confirm.get('type')}")

        print("[Alice] Bob accepted the session ticket.")

        while True:
            try:
                message = input("Alice> ")
            except EOFError:
                break

            if not message or message.lower() in {"exit", "quit"}:
                break

            payload = encrypt_text(session_key, message, AES_MODE)
            send_json(sock, create_message(CHAT_MESSAGE, payload=payload))

            reply = recv_json(sock)
            if reply.get("type") == ERROR:
                print(f"[Alice] Bob error: {reply.get('reason', 'unknown error')}")
                continue
            if reply.get("type") != CHAT_RESPONSE:
                print(f"[Alice] Unexpected reply type: {reply.get('type')}")
                continue

            plaintext = decrypt_text(session_key, reply["payload"])
            print(f"[Bob] {plaintext}")


def main() -> None:
    response = request_session_from_kdc()
    print(f"[Alice] KDC response type: {response.get('type')}")
    print(f"[Alice] Session established with {response.get('requester')} -> {response.get('target')}")
    chat_loop(response["session_key"], response["ticket"])


if __name__ == "__main__":
    main()
