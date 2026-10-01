#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "protocol.h"


/*
 * send() is allowed to send fewer bytes than requested.
 *
 */
static int send_all(
    int sock_fd,
    const void *data,
    size_t length
)
{
    const char *ptr = data;

    size_t total_sent = 0;

    while (total_sent < length) {

        ssize_t sent = send(
            sock_fd,
            ptr + total_sent,
            length - total_sent,
            0
        );

        if (sent <= 0)
            return -1;

        total_sent += sent;
    }

    return 0;
}


/*
 * recv() is also allowed to return fewer bytes than requested.
 * Keep calling recv() until exactly 'length' bytes are received.
 */
static int recv_all(
    int sock_fd,
    void *data,
    size_t length
)
{
    char *ptr = data;

    size_t total_received = 0;

    while (total_received < length) {

        ssize_t received = recv(
            sock_fd,
            ptr + total_received,
            length - total_received,
            0
        );

        if (received <= 0)
            return -1;

        total_received += received;
    }

    return 0;
}


int send_message(
    int sock_fd,
    const char *message,
    size_t length
)
{
    // Our protocol uses a 32-bit length field.
    if (length > UINT32_MAX)
        return -1;

    /*
     * Convert host byte order to network byte order.
     */
    uint32_t network_length =
        htonl((uint32_t)length);

    // Sends >I of message byte length
    if (send_all(
            sock_fd,
            &network_length,
            sizeof(network_length)
        ) < 0) {

        return -1;
    }

    // sends the message
    if (send_all(
            sock_fd,
            message,
            length
        ) < 0) {

        return -1;
    }

    return 0;
}


char *receive_message(
    int sock_fd,
    size_t *length
)
{
    uint32_t network_length;

    // receives the first 4-byte message length
    if (recv_all(
            sock_fd,
            &network_length,
            sizeof(network_length)
        ) < 0) {

        return NULL;
    }

    // convert network byte order back to host byte order.
    uint32_t message_length =
        ntohl(network_length);

    // protect from memory / malloc overflow
    if (message_length > MAX_MESSAGE_SIZE)
        return NULL;

    // allocate space for message + NULL
    char *message =
        malloc((size_t)message_length + 1);

    if (message == NULL)
        return NULL;

    // receive from other side of message_length bytes exact
    if (recv_all(
            sock_fd,
            message,
            message_length
        ) < 0) {

        free(message);
        return NULL;
    }

    // construct the C string, append the NULL at the end to terminate
    message[message_length] = '\0';

    if (length != NULL)
        *length = message_length;

    return message;
}
