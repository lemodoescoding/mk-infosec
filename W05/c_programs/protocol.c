#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "protocol.h"


// wrapper for repeated block and send() is also allowed to return fewer bytes than requested.
// keep calling send() until exactly 'length' bytes are transmitted to the sock_fd.

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


// wrapper for repeated block and recv() is also allowed to return fewer bytes than requested.
// keep calling recv() until exactly 'length' bytes are received.
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

// for generating iv when sending the message and for each round and repeated block
int generate_iv(char iv[IV_SIZE + 1]) {
    FILE *f = fopen("/dev/urandom", "rb");

    if (f == NULL) {
        return -1;
    }

    size_t i = 0;
    while(i < IV_SIZE) {
        int byte = fgetc(f);

        if(byte == EOF) {
            fclose(f);
            return -1;
        }

        if (byte != 0x0){
            iv[i++] = (char)byte;
        }
    }

    iv[IV_SIZE] = '\0';
    fclose(f);
    return 0;
}

// send message to the sock_fd along with the IV byte
int send_message(
    int sock_fd,
    const char *iv,
    const char *message,
    size_t length
)
{
    // body size is IV_SIZE + the length
    size_t body_length = IV_SIZE + length;

    // the protocol uses a 32-bit length field.
    if (body_length > UINT32_MAX || body_length > MAX_MESSAGE_SIZE)
        return -1;

    // convert host byte order to network byte order.
    uint32_t network_length =
        htonl((uint32_t)body_length);

    // Sends >I of message byte length
    if (send_all(
            sock_fd,
            &network_length,
            sizeof(network_length)
        ) < 0) {

        return -1;
    }

    // sends the IV (8 raw bytes)
    if (send_all(
            sock_fd,
            iv,
            IV_SIZE
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

// receive message from the sock_fd
char *receive_message(
    int sock_fd,
    char iv[IV_SIZE + 1],
    size_t *length
)
{
    uint32_t network_length;
 
    // receives the first 4-byte body length
    if (recv_all(
            sock_fd,
            &network_length,
            sizeof(network_length)
        ) < 0) {
 
        return NULL;
    }
 
    // convert network byte order back to host byte order.
    uint32_t body_length =
        ntohl(network_length);
 
    // protect from memory / malloc overflow
    if (body_length > MAX_MESSAGE_SIZE)
        return NULL;
 
    // body must contain the IV plus at least one ciphertext byte
    if (body_length <= IV_SIZE)
        return NULL;
 
    // receive the IV
    if (recv_all(
            sock_fd,
            iv,
            IV_SIZE
        ) < 0) {
 
        return NULL;
    }
 
    // a 0x00 byte would truncate the IV, reject as malformed
    if (memchr(iv, '\0', IV_SIZE) != NULL)
        return NULL;
 
    iv[IV_SIZE] = '\0';
 
    size_t ciphertext_length =
        (size_t)body_length - IV_SIZE;
 
    // allocate space for ciphertext + NULL
    char *message =
        malloc(ciphertext_length + 1);
 
    if (message == NULL)
        return NULL;
 
    // receive the remaining ciphertext bytes exactly
    if (recv_all(
            sock_fd,
            message,
            ciphertext_length
        ) < 0) {
 
        free(message);
        return NULL;
    }
 
    // construct the C string, append the NULL at the end to terminate
    message[ciphertext_length] = '\0';
 
    if (length != NULL)
        *length = ciphertext_length;
 
    return message;
}
 

