#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>

#define HEADER_SIZE 4
#define MAX_MESSAGE_SIZE 4096

/*
 * >I + Message
 */
int send_message(
    int sock_fd,
    const char *message,
    size_t length
);

/*
 * Receive one complete application message. The returned buffer is allocated with malloc()
 * caller must free() after use.
 */
char *receive_message(
    int sock_fd,
    size_t *length
);

#endif
