import socket

from config.settings import (
    BOB_PORT, BOB_HOST, SOCKET_TIMEOUT
)

from common.network import (
    create_tcp_server,
    recv_json,
    send_json
)

from common.protocol import (
    SESSION_CONFIRM,
    SESSION_TICKET,
    CHAT_MESSAGE,
    ERROR,
    create_message
)

from crypto.aes import AES

def handle_alice(conn: socket.socket, address: str) -> None:
    # TODO: 1. receive and validate the session ticket
    #       2. recover the session key using bob's pre-shared KDC key and the assigned protocol
    #       3. complete any required mutual/session confirmation
    #       4. receive and decrypt chat messages, encrypt replies
    conn.settimeout(SOCKET_TIMEOUT)
    try:
        message = recv_json(conn)
        if message.get("type") != SESSION_TICKET:
            send_json(conn, create_message(ERROR, reason="Expected session ticket"))
            return
        
        # TODO: validate/decrypt ticket according to the specified protocl.
        send_json(conn, create_message(
            ERROR,
            reason="Bob session protocol is not implemented yet"
        ))
    except (ConnectionError, OSError, ValueError) as exc:
        print(f"[Bob] Cliennt {address} error: {exc}")
    finally:
        conn.close()

def main() -> None:
    with create_tcp_server(BOB_HOST, BOB_PORT) as server:
        print(f"[Bob] Listening on {BOB_HOST}:{BOB_PORT}")
        while True:
            conn, address = server.accept()
            handle_alice(conn, address)

if __name__ == "__main__":
    main()
