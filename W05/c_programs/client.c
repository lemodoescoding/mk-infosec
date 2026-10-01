#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "des_functions.h"
#include "protocol.h"

#define PORT 8080
#define BUFFER_SIZE 4096

int main(void)
{
    int sock_fd;

    char buffer[BUFFER_SIZE];

    struct sockaddr_in server_addr;

    char des_key[64];
    char server_ip[INET_ADDRSTRLEN];

    printf("Server IP address: ");

    if (fgets(
        server_ip,
        sizeof(server_ip),
        stdin) == NULL) {

        return 1;
    }

    server_ip[strcspn(server_ip, "\n")] = '\0';

    printf("DES key: ");

    if (fgets(
            des_key,
            sizeof(des_key),
            stdin) == NULL) {

        return 1;
    }

    des_key[strcspn(des_key, "\n")] = '\0';

    // create the AF_INET ipv4 socket using SOCK_STREAM or TCP
    sock_fd =
        socket(AF_INET, SOCK_STREAM, 0);

    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    // sets the server address
    memset(
        &server_addr,
        0,
        sizeof(server_addr)
    );

    server_addr.sin_family =
        AF_INET;

    server_addr.sin_port =
        htons(PORT);

    // sets the server as localhost
    if (inet_pton(
        AF_INET,
        server_ip,
        &server_addr.sin_addr
    ) <= 0) {

        perror("inet_pton");

        close(sock_fd);
        return 1;
    }

    // connects to the server by the server addr set before
    if (connect(
            sock_fd,
            (struct sockaddr *)&server_addr,
            sizeof(server_addr)) < 0) {

        perror("connect");

        close(sock_fd);
        return 1;
    }

    printf(
        "Connected to encrypted TCP server.\n"
    );

    // chat loop
    // chat loop
    while (1) {

        fd_set read_fds;

        FD_ZERO(&read_fds);

        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(sock_fd, &read_fds);

        int max_fd = sock_fd;

        if (select(
                max_fd + 1,
                &read_fds,
                NULL,
                NULL,
                NULL
            ) < 0) {

            perror("select");
            break;
        }


        // User typed something
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {

            printf("You: ");
            fflush(stdout);

            if (fgets(
                    buffer,
                    sizeof(buffer),
                    stdin
                ) == NULL) {

                break;
            }

            buffer[strcspn(
                buffer,
                "\n"
            )] = '\0';


            // encrypt the message before sending 
            char *encrypted =
                des_encrypt_message(
                    buffer,
                    des_key
                );

            if (encrypted == NULL) {

                printf(
                    "Encryption failed.\n"
                );

                break;
            }


            size_t encrypted_length =
                strlen(encrypted);


            printf(
                "Encrypted sending: %s\n",
                encrypted
            );


            // [4-byte length][ciphertext]
            if (send_message(
                    sock_fd,
                    encrypted,
                    encrypted_length
                ) < 0) {

                perror("send_message");

                free(encrypted);
                break;
            }


            free(encrypted);


            // handles when typed "exit"
            if (strcmp(buffer, "exit") == 0) {
                break;
            }
        }

        // when server sends something
        if (FD_ISSET(sock_fd, &read_fds)) {

            size_t encrypted_response_length;

            char *encrypted_response =
                receive_message(
                    sock_fd,
                    &encrypted_response_length
                );

            if (encrypted_response == NULL) {

                printf(
                    "Server disconnected or invalid message.\n"
                );

                break;
            }


            printf(
                "\nEncrypted received (%zu bytes):\n%s\n",
                encrypted_response_length,
                encrypted_response
            );


            // decrypt the DES encrypted message
            char *plaintext =
                des_decrypt_message(
                    encrypted_response,
                    des_key
                );

            free(encrypted_response);


            if (plaintext == NULL) {

                printf(
                    "Decryption failed.\n"
                );

                break;
            }


            printf(
                "Server: %s\n",
                plaintext
            );


            // handles when typed "exit"
            if (strcmp(plaintext, "exit") == 0) {

                free(plaintext);
                break;
            }


            free(plaintext);
        }
    }

    close(sock_fd);

    return 0;
}
