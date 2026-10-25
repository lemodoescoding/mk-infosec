from config.settings import (
    KDC_HOST,
    KDC_PORT,
    BOB_HOST,
    BOB_PORT,
    SOCKET_TIMEOUT
)

from common.network import (
    connect_tcp, 
    send_json, 
    recv_json)
from common.protocol import (
    CHAT_MESSAGE,
    KEY_REQUEST,
    KEY_RESPONSE,
    create_message
)

from crypto.aes import AES

def request_session_from_kdc() -> dict:
    # TODO: complete the request/response flow exactly as required by the assigned protocol
    with connect_tcp(KDC_HOST, KDC_PORT, SOCKET_TIMEOUT) as sock:
        send_json(sock, create_message(
            KEY_REQUEST,
            requester="Alice",
            target="Bob"
        ))

        return recv_json(sock)

def chat_loop(session_key: bytes) -> None:
    # TODO: 1. implement the agreed session/ticket confirmation flow
    #       2. implement the selected AES mode outside AES block operations
    #       3. define message format, IV handling and responce validation
    
    aes = AES(session_key)
    print("[Alice] AES instance initialized; chat transport is not implemented.")
    _ = aes
    _ = (BOB_HOST, BOB_PORT, CHAT_MESSAGE)

def main() -> None:
    response = request_session_from_kdc()
    print(f"[Alice] KDC response type: {response.get('type')}")

    # TODO: extract/validate session material only after implementing the protocol.
    print("[Alice] Session establishment is not implemented yet.")

if __name__ == "__main__":
    main()
