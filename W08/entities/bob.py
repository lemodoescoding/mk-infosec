import argparse
import hashlib
import hmac
import json
import os
import queue
import select
import socket
import sys
import threading

from typing import Optional

from config.settings import (
    AES_MODE,
    BOB_HOST,
    BOB_PORT,
    SOCKET_TIMEOUT,
)

from common.network import create_tcp_server, recv_json, send_json
from common.protocol import (
    AUTH_CHALLENGE,
    AUTH_RESPONSE,
    CHAT_MESSAGE,
    ERROR,
    SESSION_CONFIRM,
    SESSION_TICKET,
    create_message,
)
from common.utils import key_from_ascii, validate_aes_key,nonce_response, generate_random_bytes
from crypto.modes import decrypt_text, encrypt_text
from crypto.aes_trace import TracedAES, traced_decrypt_text, traced_encrypt_text

# identifer for both client/server -> alice for server, bob for client
NAME = "Bob"
PEER = "Alice"

EXIT_WORDS = {"/exit", "/quit"}

COMMAND_PREFIX = "/"

DEFAULT_KEYS = {
    "Alice": "alice-master-key",
    "Bob": "bob---master-key",
}

_master_key_override: Optional[bytes] = None

def _set_master_key_override(key: Optional[bytes]) -> None:
    global _master_key_override
    _master_key_override = key

def _load_master_key(identity: str) -> bytes:
    if identity == NAME and _master_key_override is not None:
        return _master_key_override

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


def _choose_options(mode: Optional[str], key_size: Optional[int]) -> tuple[str, int]:
    if mode is None:
        while True:
            answer = input(f"[{NAME}] AES mode [ECB/CBC] (default {AES_MODE}): ").strip().upper()
            mode = answer or AES_MODE.upper()
            if mode in {"ECB", "CBC"}:
                break
            print(f"[{NAME}] Choose ECB or CBC.")

    if key_size is None:
        while True:
            answer = input(f"[{NAME}] AES key size [128/192/256] (default 128): ").strip()
            try:
                key_size = int(answer or "128")
            except ValueError:
                print(f"[{NAME}] Choose 128, 192, or 256.")
                continue
            if key_size in {128, 192, 256}:
                break
            print(f"[{NAME}] Choose 128, 192, or 256.")

    return mode, key_size


def _derive_key_size(key_seed: bytes, key_size: int) -> bytes:
    context = b"mk-infosec runtime AES key size v1:" + str(key_size).encode("ascii")
    return hmac.new(key_seed, context, hashlib.sha256).digest()[:key_size // 8]


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

def _display_configuration(session_key: bytes, mode: str, debug_enabled: bool) -> None:
    # Session keys are usually random bytes, so the ASCII view escapes non-printable
    # and non-ASCII bytes instead of silently replacing them.
    ascii_view = session_key.decode("ascii", errors="backslashreplace")
    print(f"[{NAME}] Current local configuration:")
    print(f"  Key (ASCII/escaped): {ascii_view!r}")
    print(f"  Key (hex):           {session_key.hex()}")
    print(f"  Key size:            AES-{len(session_key) * 8} ({len(session_key)} bytes)")
    print(f"  Mode:                {mode.upper()}")
    print(f"  Debug tracing:       {'ON' if debug_enabled else 'OFF'}")


def _print_help() -> None:
    print(f"[{NAME}] Runtime commands:")
    print("  /key                 show the active AES session key")
    print("  /key <ascii-key>     switch to a new 16/24/32-character ASCII key")
    print("  /key 0x<hex>         switch to a new key given as hex (32/48/64 hex chars)")
    print("  /keysize <bits>      switch to AES-128, AES-192, or AES-256")
    print(f"  /masterkey           show the master key {NAME} shares with the KDC")
    print("  /masterkey <value>   change it (ascii or 0x<hex>); applies to the NEXT incoming")
    print("  /mode <ECB|CBC>      select the mode used for outgoing messages")
    print("  /debug               toggle detailed AES encryption/decryption tracing")
    print("  /config              show this side's current key, key size, and mode")
    print("  /help                show this message")
    print("  /exit | /quit        close the chat")


def _handle_command(
    text: str,
    session_key: bytes,
    key_seed: bytes,
    mode: str,
) -> tuple[bytes, str]:
    # handle command does not touch the tcp communication part, so changing key is safe (hopefully)

    parts = text[len(COMMAND_PREFIX):].split(maxsplit=1)
    command = parts[0].lower() if parts else ""
    argument = parts[1] if len(parts) > 1 else ""

    if command == "key":
        if not argument:
            print(f"[{NAME}] Active session key: {_describe_key(session_key)}")
            return session_key, mode

        try:
            new_key = _parse_key_argument(argument)
        except (ValueError, TypeError) as exc:
            print(f"[{NAME}] Could not change key: {exc}")
            print(f"[{NAME}] Use /help for the accepted key formats.")
            return session_key, mode

        print(f"[{NAME}] Session key changed -> {_describe_key(new_key)}")
        print(f"[{NAME}] Note: {PEER} must switch to the same key (/key) for messages to decrypt correctly.")
        return new_key, mode

    if command == "keysize":
        try:
            key_size = int(argument)
        except ValueError:
            print(f"[{NAME}] Use /keysize 128, /keysize 192, or /keysize 256.")
            return session_key, mode
        if key_size not in {128, 192, 256}:
            print(f"[{NAME}] Use /keysize 128, /keysize 192, or /keysize 256.")
            return session_key, mode
        new_key = _derive_key_size(key_seed, key_size)
        print(f"[{NAME}] Session key changed -> {_describe_key(new_key)}")
        print(f"[{NAME}] {PEER} must run /keysize {key_size} too before sending messages.")
        return new_key, mode

    if command == "mode":
        selected_mode = argument.upper()
        if selected_mode not in {"ECB", "CBC"}:
            print(f"[{NAME}] Use /mode ECB or /mode CBC.")
            return session_key, mode
        print(f"[{NAME}] Outgoing AES mode set to {selected_mode}.")
        return session_key, selected_mode

    if command == "masterkey":
        if not argument:
            current = _load_master_key(NAME)
            print(f"[{NAME}] Active master key (shared with the KDC): {_describe_key(current)}")
            return session_key, mode
 
        try:
            new_master_key = _parse_key_argument(argument)
        except (ValueError, TypeError) as exc:
            print(f"[{NAME}] Could not change master key: {exc}")
            print(f"[{NAME}] Use /help for the accepted key formats.")
            return session_key, mode
 
        _set_master_key_override(new_master_key)
        print(f"[{NAME}] Master key changed -> {_describe_key(new_master_key)}")
        print(f"[{NAME}] This applies to the NEXT incoming connection, not the current chat with {PEER}.")
        print(f"[{NAME}] The KDC's copy of {NAME}'s key must be rotated to match (its own /key command).")
        return session_key, mode

    if command in ("help", "?"):
        _print_help()
        return session_key, mode

    print(f"[{NAME}] Unknown command: {COMMAND_PREFIX}{command}. Type /help for options.")
    return session_key, mode


def _authenticate_alice(conn: socket.socket, session_key: bytes, mode: str) -> None:
    # (4) B -> A : E(Ks, N2)
    # (5) A -> B : E(Ks, f(N2))
    # this proves Alice actually holds Ks (not just that she could forward a ticket she can't read), guarding against a replayed/stolen ticket
    nonce = generate_random_bytes(8).hex()
    send_json(conn, create_message(
        AUTH_CHALLENGE,
        payload=encrypt_text(session_key, nonce, mode),
    ))

    response = recv_json(conn)
    if response.get("type") == ERROR:
        raise ValueError(response.get("reason", f"{PEER} rejected auth challenge"))
    if response.get("type") != AUTH_RESPONSE:
        raise ValueError(f"Unexpected {PEER} response: {response.get('type')}")

    payload = response.get("payload")
    if not isinstance(payload, dict):
        raise ValueError(f"{PEER} sent a malformed auth response")

    try:
        received = decrypt_text(session_key, payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not decrypt {PEER}'s auth response: {exc}") from exc

    if received != nonce_response(nonce):
        raise ValueError(f"{PEER} failed the mutual authentication challenge")

    print(f"[{NAME}] {PEER} proved possession of the session key (steps 4/5 complete).")

def _accept_session_ticket(conn: socket.socket, expected_key_size: Optional[int] = None, mode: str = AES_MODE) -> bytes:
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

    base_session_key = bytes.fromhex(session_key_hex)
    if len(base_session_key) not in (16, 24, 32):
        raise ValueError("Session key size is invalid")

    key_setup = message.get("key_setup")
    if key_setup is None:
        session_key = base_session_key
    else:
        if not isinstance(key_setup, dict):
            raise ValueError("Session key setup payload is invalid")
        setup = json.loads(decrypt_text(base_session_key, key_setup))
        if not isinstance(setup, dict):
            raise ValueError("Session key setup must be a JSON object")
        selected_key_size = setup.get("key_size")
        if isinstance(selected_key_size, bool) or selected_key_size not in (128, 192, 256):
            raise ValueError("Selected AES key size is invalid")
        session_key_hex = setup.get("session_key")
        if not isinstance(session_key_hex, str):
            raise ValueError("Selected AES key is missing")
        session_key = bytes.fromhex(session_key_hex)
        if len(session_key) * 8 != selected_key_size:
            raise ValueError("Selected AES key does not match its declared size")

    if expected_key_size is not None and len(session_key) * 8 != expected_key_size:
        raise ValueError(
            f"Alice selected AES-{len(session_key) * 8}, but Bob is configured for AES-{expected_key_size}"
        )

    send_json(conn, create_message(
        SESSION_CONFIRM,
        status="ok",
        requester=NAME,
        target=PEER,
        key_size=len(session_key) * 8,
    ))

    print(f"[{NAME}] Session ticket accepted. Secure chat established with {PEER} using AES-{len(session_key) * 8}.")

    _authenticate_alice(conn, session_key, mode)
    return session_key


def _send_chat_message(sock: socket.socket, session_key: bytes, text: str, mode: str, debug_enabled: bool = False) -> None:
    print(f"[{NAME}] Encrypting message...")

    if debug_enabled:
        print(f"[{NAME}] DEBUG tracing is ON: showing AES key expansion, padding, mode operations, and every AES round.")
        traced_aes = TracedAES(session_key)
        payload = traced_encrypt_text(traced_aes, text, mode)
    else:
        payload = encrypt_text(session_key, text, mode)

    if payload.get("iv"):
        print(f"IV: {payload['iv']}")

    send_json(sock, create_message(CHAT_MESSAGE, payload=payload))

    ciphertext = payload["ciphertext"]
    print(f"[{NAME}] Encrypted and sent the message to {PEER}.")
    print(f"Sending ciphertext ({len(ciphertext) // 2} bytes):\n{ciphertext}")


def _receive_chat_message(sock: socket.socket, session_key: bytes, mode: str = AES_MODE, debug_enabled: bool = False) -> Optional[str]:
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

    incoming_mode = payload.get("mode")
    if not isinstance(incoming_mode, str) or incoming_mode.upper() != mode.upper():
        print(
            f"[{NAME}] Rejected message from {PEER}: shared mode is {mode.upper()}, "
            f"but the message declares {incoming_mode!r}."
        )
        return ""

    print(f"[{NAME}] Decrypting message...")
    try:
        if debug_enabled:
            print(f"[{NAME}] DEBUG tracing is ON: showing AES key expansion, mode operations, and every inverse AES round.")
            traced_aes = TracedAES(session_key)
            plaintext = traced_decrypt_text(traced_aes, payload)
        else:
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


def _read_console(lines: queue.Queue[Optional[str]]) -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            lines.put(None)
            return
        lines.put(line.rstrip("\r\n"))


def chat_loop(
    sock: socket.socket,
    session_key: bytes,
    mode: str = AES_MODE,
    key_seed: Optional[bytes] = None,
) -> None:
    # Watch the socket with select; a background reader handles console input on Windows.
    """
    session_key is a local variable here (not a module-level constant), so
    the /key command can reassign it on the fly: every subsequent send/
    receive picks up the new value immediately, with no restart needed."""

    # here for toggleable debug
    debug_enabled = False

    key_seed = session_key if key_seed is None else key_seed
    print(f"[{NAME}] Active session key: {_describe_key(session_key)}")
    print(f"[{NAME}] Outgoing AES mode: {mode}")
    print(f"[{NAME}] Type /help for runtime commands (e.g. changing the AES key without restarting).")
    lines: queue.Queue[Optional[str]] = queue.Queue()
    threading.Thread(target=_read_console, args=(lines,), daemon=True).start()
    print(f"[{NAME}] > ", end="", flush=True)

    while True:
        readable, _, _ = select.select([sock], [], [], 0.1)

        try:
            text = lines.get_nowait()
        except queue.Empty:
            pass
        else:
            if text is None:
                break
            if not text:
                print(f"[{NAME}] > ", end="", flush=True)
            elif text.lower() in EXIT_WORDS:
                break
            elif text.startswith(COMMAND_PREFIX):
                command_parts = text[len(COMMAND_PREFIX):].split(maxsplit=1)
                command = command_parts[0].lower() if command_parts else ""
                if command == "debug":
                    if len(command_parts) > 1:
                        print(f"[{NAME}] Usage: /debug (toggle tracing on/off).")
                    else:
                        debug_enabled = not debug_enabled
                        print(f"[{NAME}] Detailed AES tracing {'ENABLED' if debug_enabled else 'DISABLED'}.")
                elif command == "config":
                    if len(command_parts) > 1:
                        print(f"[{NAME}] Usage: /config")
                    else:
                        _display_configuration(session_key, mode, debug_enabled)
                else:
                    session_key, mode = _handle_command(text, session_key, key_seed, mode)
                print(f"[{NAME}] > ", end="", flush=True)
            else:
                _send_chat_message(sock, session_key, text, mode, debug_enabled)
                print(f"\n[{NAME}] > ", end="", flush=True)

        if readable:
            try:
                plaintext = _receive_chat_message(sock, session_key, mode, debug_enabled)
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


def handle_alice(conn: socket.socket, address, expected_key_size: Optional[int] = None, mode: str = AES_MODE) -> None:
    conn.settimeout(SOCKET_TIMEOUT)
    try:
        session_key = _accept_session_ticket(conn, expected_key_size, mode)
        key_seed = session_key

        # handshake is done, rely on select() in the chat loop instead of
        # a short handshake timeout
        conn.settimeout(None)
        chat_loop(conn, session_key, mode, key_seed)
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
    parser = argparse.ArgumentParser(description="Bob secure chat server")
    parser.add_argument("--mode", type=str.upper, choices=("ECB", "CBC"))
    parser.add_argument("--key-size", type=int, choices=(128, 192, 256))
    args = parser.parse_args()
    mode, key_size = _choose_options(args.mode, args.key_size)

    host = os.environ.get("BOB_HOST", BOB_HOST)
    port = int(os.environ.get("BOB_PORT", BOB_PORT))

    with create_tcp_server(host, port) as server:
        print(f"[{NAME}] Listening on {host}:{port}; outgoing AES mode is {mode}, expected key size is AES-{key_size}.")
        while True:
            conn, address = server.accept()
            print(f"[{NAME}] {PEER} connected from {address[0]}:{address[1]}")
            handle_alice(conn, address, key_size, mode)


if __name__ == "__main__":
    main()
