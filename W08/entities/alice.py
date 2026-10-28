import argparse
import hashlib
import hmac
import json
import os
import queue
import secrets
import select
import socket
import sys
import threading

from typing import Optional

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
    ERROR,
    KEY_REQUEST,
    KEY_RESPONSE,
    SESSION_CONFIRM,
    SESSION_TICKET,
    create_message,
)
from common.utils import key_from_ascii, validate_aes_key
from crypto.modes import decrypt_text, encrypt_text
from crypto.aes_trace import TracedAES, traced_decrypt_text, traced_encrypt_text

# identifer for both client/server -> alice for server, bob for client
NAME = "Alice"
PEER = "Bob"

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


def _generate_nonce() -> str:
    return secrets.token_hex(8)


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
    # accepts either a literal ASCII key (16/24/32 chars, same shape as DEFAULT_KEYS / KDC_KEY_*) 
    # or a hex-encoded key via "0x..." / "hex:..."
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
    # and non-ASCII bytes instead of silently replacing them
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
    print("  /masterkey <value>   change it (ascii or 0x<hex>); the KDC must match it too")
    print(f"  /rekey               reconnect to {PEER} with a fresh KDC handshake")
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
        print(f"[{NAME}] This only affects the NEXT KDC handshake -- run /rekey to actually use it.")
        print(f"[{NAME}] The KDC's copy of {NAME}'s key must be rotated to match (its own /key command).")
        return session_key, mode

    if command in ("help", "?"):
        _print_help()
        return session_key, mode

    print(f"[{NAME}] Unknown command: {COMMAND_PREFIX}{command}. Type /help for options.")
    return session_key, mode


def request_session_from_kdc() -> dict:
    nonce = _generate_nonce()
    kdc_host = os.environ.get("KDC_HOST", KDC_HOST)
    kdc_port = int(os.environ.get("KDC_PORT", KDC_PORT))

    print(f"[{NAME}] Requesting a session key with {PEER} from the KDC at {kdc_host}:{kdc_port}...")

    with connect_tcp(kdc_host, kdc_port, SOCKET_TIMEOUT) as sock:
        send_json(sock, create_message(
            KEY_REQUEST,
            requester=NAME,
            target=PEER,
            nonce=nonce,
        ))
        response = recv_json(sock)

    if response.get("type") == ERROR:
        raise ValueError(response.get("reason", "KDC rejected key request"))
    if response.get("type") != KEY_RESPONSE or "response" not in response:
        raise ValueError("Unexpected KDC response")

    protected = response["response"]
    inner = json.loads(decrypt_text(_load_master_key(NAME), protected))

    if inner.get("requester") != NAME or inner.get("target") != PEER:
        raise ValueError(f"KDC response does not match {NAME}/{PEER} session")
    if inner.get("nonce") != nonce:
        raise ValueError("KDC response nonce mismatch")
    if not isinstance(inner.get("ticket"), dict):
        raise ValueError("KDC response does not include a valid ticket")

    session_key = bytes.fromhex(inner["session_key"])
    if len(session_key) not in (16, 24, 32):
        raise ValueError("Session key length is invalid")

    print(f"[{NAME}] KDC issued a session key for {NAME} <-> {PEER}.")

    return {**inner, "session_key": session_key}


def establish_session(
    ticket: dict,
    base_session_key: bytes,
    mode: str,
    key_size: int,
) -> tuple[socket.socket, bytes]:
    bob_host = os.environ.get("BOB_HOST", BOB_HOST)
    bob_port = int(os.environ.get("BOB_PORT", BOB_PORT))

    print(f"[{NAME}] Connecting to {PEER} at {bob_host}:{bob_port}...")
    sock = connect_tcp(bob_host, bob_port, SOCKET_TIMEOUT)
    session_key = secrets.token_bytes(key_size // 8)
    key_setup = encrypt_text(
        base_session_key,
        json.dumps(
            {"key_size": key_size, "session_key": session_key.hex()},
            separators=(",", ":"),
        ),
        mode,
    )

    try:
        send_json(sock, create_message(
            SESSION_TICKET,
            ticket=ticket,
            key_setup=key_setup,
        ))
        confirm = recv_json(sock)

        if confirm.get("type") == ERROR:
            raise ValueError(confirm.get("reason", f"{PEER} rejected session ticket"))
        if confirm.get("type") != SESSION_CONFIRM:
            raise ValueError(f"Unexpected {PEER} response: {confirm.get('type')}")
        if confirm.get("key_size") != key_size:
            raise ValueError(f"{PEER} confirmed a different AES key size")
    except Exception:
        sock.close()
        raise

    print(f"[{NAME}] {PEER} accepted the ticket. Secure chat established with AES-{key_size}.")

    # the handshake is done, fall back to blocking reads gated by select()
    # in the chat loop instead of a short handshake timeout
    sock.settimeout(None)
    return sock, session_key

def _rekey(old_sock: socket.socket, mode: str, key_size: int) -> tuple[socket.socket, bytes]:
    # this does closes the current connection and performs a brand-new KDC request + ticket handshake from scratch 
    print(f"[{NAME}] Rekeying: closing the current connection and requesting a fresh session from the KDC...")
 
    try:
        old_sock.close()
    except OSError:
        pass
 
    response = request_session_from_kdc()
    new_sock, new_session_key = establish_session(
        response["ticket"],
        response["session_key"],
        mode,
        key_size,
    )
    return new_sock, new_session_key


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

                elif command == "rekey":
                        if len(command_parts) > 1:
                            print(f"[{NAME}] Usage: /rekey (reconnect to {PEER} using the active master key).")
                        else:
                            try:
                                sock, session_key = _rekey(sock, mode, len(session_key) * 8)
                                key_seed = session_key
                                print(f"[{NAME}] Rekey complete; chatting with {PEER} on the new session.")
                            except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
                                print(f"[{NAME}] Rekey failed: {exc}")
                                print(f"[{NAME}] The old connection is closed; ending the chat.")
                                return

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Alice secure chat client")
    parser.add_argument("--mode", type=str.upper, choices=("ECB", "CBC"))
    parser.add_argument("--key-size", type=int, choices=(128, 192, 256))
    args = parser.parse_args()
    mode, key_size = _choose_options(args.mode, args.key_size)

    print(f"[{NAME}] Starting secure chat client...")

    response = request_session_from_kdc()
    base_session_key = response["session_key"]

    sock, session_key = establish_session(
        response["ticket"],
        base_session_key,
        mode,
        key_size,
    )
    try:
        chat_loop(sock, session_key, mode)
    finally:
        sock.close()
        print(f"\n[{NAME}] Connection closed.")


if __name__ == "__main__":
    main()
