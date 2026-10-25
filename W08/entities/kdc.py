import socket
from config.settings import (
    KDC_HOST, 
    KDC_PORT, 
    SOCKET_TIMEOUT
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


def handle_client(conn: socket.socket, address: str) -> None:
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
        send_json(conn, create_message(
            ERROR,
            reason="KDC protocol is not implemented yet",
        ))
    except (ConnectionError, OSError, ValueError) as exc:
        print(f"[KDC] Client {address} error: {exc}")
    finally:
        conn.close()


def main() -> None:
    with create_tcp_server(KDC_HOST, KDC_PORT) as server:
        print(f"[KDC] Listening on {KDC_HOST}:{KDC_PORT}")
        while True:
            conn, address = server.accept()
            handle_client(conn, address)


if __name__ == "__main__":
    main()
