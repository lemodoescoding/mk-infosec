import socket
import os
import re
import json
from collections import OrderedDict
import sys
import threading

from config.settings import (
    KDC_HOST, 
    KDC_PORT, 
    SOCKET_TIMEOUT,
    AES_MODE
)

from config.constants import (
    MAX_SEEN_NONCES,
    SEPARATOR,
    SESSION_KEY_SIZE
)

from common.network import (
    create_tcp_server, 
    recv_json, 
    send_json
)

from common.protocol import (
    KEY_REQUEST, 
    KEY_RESPONSE, 
    ERROR, 
    create_message
)

from common.utils import (
    generate_random_bytes,
    key_from_ascii,
    serialize_payload,
    validate_aes_key
)

from crypto.modes import encrypt_text

MASTER_KEY_ENV = {
    "Alice": "KDC_KEY_ALICE",
    "Bob": "KDC_KEY_BOB",
}


class KDCError(Exception):
    """raised when bad request on KDC is occured"""

def load_master_keys() -> dict[str, bytes]:
    # loads and validate long-term aes keys from the env variable (for now)
    keys = {}
    for name, env_var in MASTER_KEY_ENV.items():
        # TODO: make the AES keys to be configurable when running the application
        value = os.environ.get(env_var)
        if value is None:
            raise RuntimeError(f"[KDC] missing env environment variable {env_var}")
        keys[name] = key_from_ascii(value)

    return keys

_master_keys_lock = threading.Lock()

def _describe_key(key: bytes) -> str:
    return f"{key.hex()}  (AES-{8 * len(key)}, {len(key)} bytes)"

def _parse_key_argument(value: str) -> bytes:
    # accepts either a literal ASCII key (16/24/32 chars, same shape as KDC_KEY_ALICE / KDC_KEY_BOB) or
    # a hex-encoded key via "0x..." / "hex:..." (the same implementation on alice and bob)
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

def _print_console_help() -> None:
    print("[KDC] Runtime commands:")
    print("  /key                      show both master keys")
    print("  /key <Alice|Bob>          show one identity's master key")
    print("  /key <Alice|Bob> <ascii>  change that identity's master key (16/24/32 ASCII chars)")
    print("  /key <Alice|Bob> 0x<hex>  change that identity's master key (hex form)")
    print("  /help                     show this message")

def _handle_console_command(text: str, master_keys: dict[str, bytes]) -> None:
    # never touches master_keys variable, and never the socket itself, hence safe to run on this background thread while the main thread is blocked in server.accept().
    parts = text[1:].split(maxsplit=2)
    command = parts[0].lower() if parts else ""
 
    if command == "key":
        identity_arg = parts[1] if len(parts) > 1 else None
        value_arg = parts[2] if len(parts) > 2 else ""
 
        if identity_arg is None:
            with _master_keys_lock:
                for name, key in master_keys.items():
                    print(f"[KDC] {name}: {_describe_key(key)}")
            return
 
        identity = identity_arg.strip().capitalize()
        if identity not in master_keys:
            print(f"[KDC] Unknown identity: {identity_arg!r}. Expected Alice or Bob.")
            return
 
        if not value_arg:
            with _master_keys_lock:
                print(f"[KDC] {identity}: {_describe_key(master_keys[identity])}")
            return
 
        try:
            new_key = _parse_key_argument(value_arg)
        except (ValueError, TypeError) as exc:
            print(f"[KDC] Could not change {identity}'s master key: {exc}")
            print("[KDC] Use /help for the accepted key formats.")
            return
 
        with _master_keys_lock:
            master_keys[identity] = new_key
 
        print(f"[KDC] {identity}'s master key changed -> {_describe_key(new_key)}")
        print(f"[KDC] {identity} must set the matching key too (their own /masterkey command) before the next handshake.")
        return
 
    if command in ("help", "?"):
        _print_console_help()
        return
 
    print(f"[KDC] Unknown command: /{command}. Type /help for options.")
 
 
def _console_loop(master_keys: dict[str, bytes]) -> None:
    # runs on a daemon thread so the main thread can keep blocking on server.accept()
    # this lets a master key be rotated without restarting the KDC
 
    print("[KDC] Type /help for runtime commands (e.g. rotating a master key without restarting).")
    while True:
        line = sys.stdin.readline()
        if not line:
            return
 
        text = line.strip()
        if not text:
            continue
 
        if text.startswith("/"):
            _handle_console_command(text, master_keys)
        else:
            print("[KDC] Unrecognized input. Commands start with /. Type /help for options.")

NONCE_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")
_seen_nonces: dict[str, OrderedDict[str, None]] = {}

def _remember_nonce(requester: str, nonce: str) -> None:
    # TODO: reject reused nonce value and retain previously accepted values
    seen = _seen_nonces.setdefault(requester, OrderedDict())
    if nonce in seen:
        raise KDCError("replayed nonce")
    if len(seen) >= MAX_SEEN_NONCES:
        # TODO: implement basic nonce tracking based on timestamp of creation
        seen.popitem(last=False)

    seen[nonce] = None

def validate_request(request: dict, master_keys: dict[str, bytes]) -> tuple[str, str, str]:
    if not isinstance(request, dict):
        raise KDCError("request must be dict type")
    requester = request.get("requester")
    target = request.get("target")
    nonce = request.get("nonce")

    for field, value in (("requester", requester), ("target", target), ("nonce", nonce)):
        if not isinstance(value, str):
            raise KDCError(f"field {field} is missing or not a string")

    # if not isinstance(requester, str) or not isinstance(target, str) or not isinstance(nonce, str) or not requester or not target or not nonce:
    #     raise KDCError("request object is missing one of the 3 properties needed")
    assert isinstance(requester, str) and isinstance(target, str) and isinstance(nonce, str)

    if requester not in master_keys:
        raise KDCError("unknown requester")
    if target not in master_keys:
        raise KDCError("unknown target")
    if requester == target:
        raise KDCError("requester and target must different")
    if not NONCE_RE.fullmatch(nonce):
        raise KDCError("nonce must be consist of alphanumeric only and between 1-64 len")

    # for identity, key in master_keys.items():
    #     if not isinstance(key, bytes) or len(key) != 16:
    #         raise KDCError(f"invalid AES-128 master key for {identity}")

    return requester, target, nonce

def build_key_response(
    request: dict,
    master_keys: dict[str, bytes],
    mode: str = AES_MODE,
) -> dict:
    requester, target, nonce = validate_request(request, master_keys)
    _remember_nonce(requester, nonce)
 
    ks_hex = generate_random_bytes(SESSION_KEY_SIZE).hex()  # Ks

    with _master_keys_lock:
        target_key = master_keys[target]
        requester_key = master_keys[requester]
 
    # E(Ka, [Ks || ID_A || ID_B || N1])
    # E(Kb, [Ks || ID_A])  -> Bob's ticket
    
    # Ticket encrypted with the target's long-term master key.
    # The target decrypts this ticket; the requester cannot read its contents.

    # E(Kb, [Ks || ID_A]): only the target can open the ticket
    ticket = encrypt_text(
        target_key,
        SEPARATOR.join((ks_hex, requester)),
        mode,
    )

    # E(Ka, [Ks || ID_A || ID_B || N1])
    # E(Ka, {...}): only the requester can open this, and it carries the ticket
    protected_response = encrypt_text(
        requester_key,
        serialize_payload({
            "session_key": ks_hex,
            "requester": requester,
            "target": target,
            "nonce": nonce,
            "ticket": ticket,
        }),
        mode,
    )
 
    return create_message(KEY_RESPONSE, response=protected_response)


def handle_client(conn: socket.socket, address: str, master_keys: dict[str, bytes]) -> None:
    # TODO: 1. authenticate/identify the requester according to the assigned protocol.
    #       2. validate all message fields.
    #       3. generate/select a session key.
    #       4. protect key material and create Bob's ticket as specified by the protocol.
    #       5. never send a raw long-term master key to a participant.

    conn.settimeout(SOCKET_TIMEOUT)
    try:
        request = recv_json(conn)

        if request.get("type") != KEY_REQUEST:
            send_json(conn, create_message(ERROR, reason="Unexpected message type"))
            return

        # TODO: implement the lecturer's KDC protocol here.
        try:
            response = build_key_response(request, master_keys)
        except KDCError as exc:
            print(f"[KDC] rejected req from {address}: {exc}")
            send_json(conn, create_message(
                ERROR,
                reason=str(exc)
            ))
            return

        send_json(conn, response)
        print(f"[KDC] issued session key {request['requester']} <-> {request['target']} for {address}")
    except (ConnectionError, OSError) as exc:
        print(f"[KDC] Client {address} connection error: {exc}")
    except ValueError as exc:
        print(f"[KDC] Client {address} error: {exc}")

        try:
            send_json(
                conn,
                create_message(ERROR, reason="Invalid request"),
            )
        except (ConnectionError, OSError, ValueError):
            pass
    finally:
        conn.close()


def main() -> None:
    validate_aes_key(bytes(SESSION_KEY_SIZE))
    master_keys = load_master_keys()

    threading.Thread(target=_console_loop, args=(master_keys,), daemon=True).start()

    with create_tcp_server(KDC_HOST, KDC_PORT) as server:
        print(f"[KDC] Listening on {KDC_HOST}:{KDC_PORT}")
        while True:
            conn, address = server.accept()
            handle_client(conn, address, master_keys)


if __name__ == "__main__":
    main()
