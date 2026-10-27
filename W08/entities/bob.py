import json
import os
import select
import socket
import sys

from config.settings import (
    AES_MODE,
    BOB_HOST,
    BOB_PORT,
    SOCKET_TIMEOUT,
)

from common.network import create_tcp_server, recv_json, send_json
from common.protocol import (
    CHAT_MESSAGE,
    ERROR,
    SESSION_CONFIRM,
    SESSION_TICKET,
    create_message,
)
from common.utils import key_from_ascii, validate_aes_key
from crypto.modes import decrypt_text, encrypt_text

# identifer for both client/server -> alice for server, bob for client
NAME = "Bob"
PEER = "Alice"

EXIT_WORDS = {"/exit", "/quit"}

COMMAND_PREFIX = "/"

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


def _describe_key(key: bytes) -> str:
    return f"{key.hex()}  (AES-{8 * len(key)}, {len(key)} bytes)"


def _parse_key_argument(value: str) -> bytes:
    # accepts either a literal ASCII key (16/24/32 chars, same shape as DEFAULT_KEYS / KDC_KEY_*) or a hex-encoded key via "0x..." / "hex:...
    value = value.strip()
    if not value:
        raise ValueError("no key value given")

    lowered = value.lower()
    if lowered.startswith("0x") or lowered.startswith("hex:"):
        hex_part = value.split(":", 1)[1] if ":" in value else value[2:]
        try:
            key = bytes.fromhex(hex_part)
        except ValueError as exc:
            raise ValueError(f"invalid hex key: {exc}") from exc
        validate_aes_key(key)
        return key

    return key_from_ascii(value)


def _print_help() -> None:
    print(f"[{NAME}] Runtime commands:")
    print("  /key                 show the active AES session key")
    print("  /key <ascii-key>     switch to a new 16/24/32-character ASCII key")
    print("  /key 0x<hex>         switch to a new key given as hex (32/48/64 hex chars)")
    print("  /help                show this message")
    print("  exit | quit          close the chat")


def _handle_command(text: str, session_key: bytes) -> bytes:
    # handle command does not touch the tcp communication part, so changing key is safe (hopefully)

    parts = text[len(COMMAND_PREFIX):].split(maxsplit=1)
    command = parts[0].lower() if parts else ""
    argument = parts[1] if len(parts) > 1 else ""

    if command == "key":
        if not argument:
            print(f"[{NAME}] Active session key: {_describe_key(session_key)}")
            return session_key

        try:
            new_key = _parse_key_argument(argument)
        except (ValueError, TypeError) as exc:
            print(f"[{NAME}] Could not change key: {exc}")
            print(f"[{NAME}] Use /help for the accepted key formats.")
            return session_key

        print(f"[{NAME}] Session key changed -> {_describe_key(new_key)}")
        print(f"[{NAME}] Note: {PEER} must switch to the same key (/key) for messages to decrypt correctly.")
        return new_key

    if command in ("help", "?"):
        _print_help()
        return session_key

    print(f"[{NAME}] Unknown command: {COMMAND_PREFIX}{command}. Type /help for options.")
    return session_key


def _accept_session_ticket(conn: socket.socket) -> bytes:
    message = recv_json(conn)
    if message.get("type") != SESSION_TICKET:
        send_json(conn, create_message(ERROR, reason="Expected session ticket"))
        raise ValueError("Expected session ticket")

    ticket = message.get("ticket")
    if not isinstance(ticket, dict):
        raise ValueError("Session ticket payload missing")

    ticket_plaintext = decrypt_text(_load_master_key(NAME), ticket)
    session_key_hex, requester = _split_ticket(ticket_plaintext)

    if requester != PEER:
        raise ValueError("Ticket requester mismatch")

    session_key = bytes.fromhex(session_key_hex)
    if len(session_key) not in (16, 24, 32):
        raise ValueError("Session key size is invalid")

    send_json(conn, create_message(
        SESSION_CONFIRM,
        status="ok",
        requester=NAME,
        target=PEER,
        session_key=session_key.hex(),
    ))

    print(f"[{NAME}] Session ticket accepted. Secure chat established with {PEER}.")
    return session_key


def _send_chat_message(sock: socket.socket, session_key: bytes, text: str) -> None:
    print(f"[{NAME}] Encrypting message...")

    payload = encrypt_text(session_key, text, AES_MODE)

    if payload.get("iv"):
        print(f"IV: {payload['iv']}")

    send_json(sock, create_message(CHAT_MESSAGE, payload=payload))

    ciphertext = payload["ciphertext"]
    print(f"[{NAME}] Encrypted and sent the message to {PEER}.")
    print(f"Sending ciphertext ({len(ciphertext) // 2} bytes):\n{ciphertext}")


def _receive_chat_message(sock: socket.socket, session_key: bytes) -> str | None:
    message = recv_json(sock)

    if message.get("type") == ERROR:
        print(f"[{NAME}] {PEER} reported an error: {message.get('reason', 'unknown error')}")
        return None

    if message.get("type") != CHAT_MESSAGE:
        print(f"[{NAME}] Unexpected message type from {PEER}: {message.get('type')}")
        return None

    payload = message.get("payload")
    if not isinstance(payload, dict):
        print(f"[{NAME}] Malformed chat payload from {PEER}.")
        return None

    ciphertext = payload.get("ciphertext", "")
    print(f"\n[{NAME}] Received ciphertext ({len(ciphertext) // 2} bytes):\n{ciphertext}")
    if payload.get("iv"):
        print(f"Recv IV: {payload['iv']}")

    print(f"[{NAME}] Decrypting message...")
    try:
        plaintext = decrypt_text(session_key, payload)
    except (ValueError, UnicodeDecodeError) as exc:
        # most likely cause during a demo: the key was just changed on one side only
        # the other side must retype the key, the current implementation 
        # keep the chat alive so the operator can fix it with /key and try again
        print(f"[{NAME}] Failed to decrypt message from {PEER}: {exc}")
        print(f"[{NAME}] Hint: the session key may not match {PEER}'s. Check with /key.")
        return ""

    print(f"[{PEER}] > {plaintext}")

    return plaintext


def chat_loop(sock: socket.socket, session_key: bytes) -> None:
    # two-way chat loop using select.select for client/server TCP chat
    """
    session_key is a local variable here (not a module-level constant), so
    the /key command can reassign it on the fly: every subsequent send/
    receive picks up the new value immediately, with no restart needed."""

    print(f"[{NAME}] Active session key: {_describe_key(session_key)}")
    print(f"[{NAME}] Type /help for runtime commands (e.g. changing the AES key without restarting).")
    print(f"[{NAME}] > ", end="", flush=True)

    while True:
        readable, _, _ = select.select([sys.stdin, sock], [], [])

        if sys.stdin in readable:
            line = sys.stdin.readline()
            if not line:
                break

            text = line.rstrip("\n")
            if not text:
                print(f"[{NAME}] > ", end="", flush=True)
                continue

            if text.lower() in EXIT_WORDS:
                break

            if text.startswith(COMMAND_PREFIX):
                session_key = _handle_command(text, session_key)
                print(f"[{NAME}] > ", end="", flush=True)
                continue

            _send_chat_message(sock, session_key, text)


            print(f"\n[{NAME}] > ", end="", flush=True)

        if sock in readable:
            try:
                plaintext = _receive_chat_message(sock, session_key)
            except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
                print(f"\n[{NAME}] Connection to {PEER} lost: {exc}")
                break

            if plaintext is None:
                break

            if plaintext == "":
                # decrypt failure was already reported inside
                # _receive_chat_message; stay in the chat so /key can fix it.
                print(f"\n[{NAME}] > ", end="", flush=True)
                continue

            if plaintext.lower() in EXIT_WORDS:
                break

            print(f"\n[{NAME}] > ", end="", flush=True)


def handle_alice(conn: socket.socket, address) -> None:
    conn.settimeout(SOCKET_TIMEOUT)
    try:
        session_key = _accept_session_ticket(conn)

        # handshake is done, rely on select() in the chat loop instead of
        # a short handshake timeout
        conn.settimeout(None)
        chat_loop(conn, session_key)
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[{NAME}] Client {address} error: {exc}")
        try:
            send_json(conn, create_message(ERROR, reason=str(exc)))
        except (ConnectionError, OSError, ValueError):
            pass
    finally:
        conn.close()
        print(f"[{NAME}] Connection with {address} closed.\n")


def main() -> None:
    host = os.environ.get("BOB_HOST", BOB_HOST)
    port = int(os.environ.get("BOB_PORT", BOB_PORT))

    with create_tcp_server(host, port) as server:
        print(f"[{NAME}] Listening on {host}:{port}")
        while True:
            conn, address = server.accept()
            print(f"[{NAME}] {PEER} connected from {address[0]}:{address[1]}")
            handle_alice(conn, address)


if __name__ == "__main__":
    main()
