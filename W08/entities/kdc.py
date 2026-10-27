import socket
import os
import re
import json
from collections import OrderedDict

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
 
    # E(Ka, [Ks || ID_A || ID_B || N1])
    # E(Kb, [Ks || ID_A])  -> Bob's ticket
    
    # Ticket encrypted with the target's long-term master key.
    # The target decrypts this ticket; the requester cannot read its contents.

    # E(Kb, [Ks || ID_A]): only the target can open the ticket
    ticket = encrypt_text(
        master_keys[target],
        SEPARATOR.join((ks_hex, requester)),
        mode,
    )

    # E(Ka, [Ks || ID_A || ID_B || N1])
    # E(Ka, {...}): only the requester can open this, and it carries the ticket
    protected_response = encrypt_text(
        master_keys[requester],
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
    with create_tcp_server(KDC_HOST, KDC_PORT) as server:
        print(f"[KDC] Listening on {KDC_HOST}:{KDC_PORT}")
        while True:
            conn, address = server.accept()
            handle_client(conn, address, master_keys)


if __name__ == "__main__":
    main()
