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

int main(void)
{
    int server_fd;
    int client_fd;

    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;


    char server_ip[INET_ADDRSTRLEN];
    char des_key[64];

    /*
     * Get configuration from user
     */
    printf("Server IP address [0.0.0.0]: ");
    if (fgets(server_ip, sizeof(server_ip), stdin) == NULL) {
        return 1;
    }

    server_ip[strcspn(server_ip, "\n")] = '\0';

    /*
     * Empty input means listen on all interfaces.
     */
    if (strlen(server_ip) == 0) {
        strcpy(server_ip, "0.0.0.0");
    }

    printf("DES key: ");
    if (fgets(des_key, sizeof(des_key), stdin) == NULL) {
        return 1;
    }

    des_key[strcspn(des_key, "\n")] = '\0';


    socklen_t client_addr_len =
        sizeof(client_addr);

    // opens TCP IPv4 socket using the standard socket and SOCK_STREAM
    server_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    // allow for SO_REUSEADDR to be true
    int opt = 1;

    if (setsockopt(
            server_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            sizeof(opt)
        ) < 0) {

        perror("setsockopt");

        close(server_fd);
        return 1;
    }

    // set the IPv4 address for the server
    memset(
        &server_addr,
        0,
        sizeof(server_addr)
    );

    server_addr.sin_family =
        AF_INET;

    if (inet_pton(
        AF_INET,
        server_ip,
        &server_addr.sin_addr
        ) <= 0) {

        printf("Invalid server IP address: %s\n", server_ip);

        close(server_fd);
        return 1;
    }

    server_addr.sin_port =
    htons(PORT);

    // Binds the socket to the server address to the socket
    if (bind(
            server_fd,
            (struct sockaddr *)&server_addr,
            sizeof(server_addr)
        ) < 0) {

        perror("bind");

        close(server_fd);
        return 1;
    }

    // after bind, listen to the network
    if (listen(server_fd, 1) < 0) {

        perror("listen");

        close(server_fd);
        return 1;
    }

    printf(
        "DES TCP server listening on port %d...\n",
        PORT
    );

    // when there is connection incoming or from the client
    client_fd = accept(
        server_fd,
        (struct sockaddr *)&client_addr,
        &client_addr_len
    );

    if (client_fd < 0) {

        perror("accept");

        close(server_fd);
        return 1;
    }

    printf(
        "Client connected from %s:%d\n",
        inet_ntoa(client_addr.sin_addr),
        ntohs(client_addr.sin_port)
    );

    // the chat loop until typed exit.
    while (1) {
        fd_set read_fds;

        FD_ZERO(&read_fds);

        FD_SET(STDIN_FILENO, &read_fds);
        FD_SET(client_fd, &read_fds);

        int max_fd = client_fd;

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


        // when server wants to send a message
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {

            char input[4096];

            printf("You: ");
            fflush(stdout);

            if (fgets(
                    input,
                    sizeof(input),
                    stdin
                ) == NULL) {

                break;
            }

            input[strcspn(
                input,
                "\n"
            )] = '\0';


            // encrypt the server messsage before send
            char *encrypted_response =
                des_encrypt_message(
                    input,
                    des_key
                );

            if (encrypted_response == NULL) {

                printf(
                    "DES encryption failed.\n"
                );

                break;
            }


            size_t encrypted_response_length =
                strlen(encrypted_response);


            printf(
                "Sending ciphertext (%zu bytes):\n%s\n",
                encrypted_response_length,
                encrypted_response
            );


            // sends packet structure [4-byte length][ciphertext]
            if (send_message(
                    client_fd,
                    encrypted_response,
                    encrypted_response_length
                ) < 0) {

                perror("send_message");

                free(encrypted_response);
                break;
            }


            free(encrypted_response);

            // handles when typed exit
            if (strcmp(input, "exit") == 0) {
                break;
            }
        }

        // when client sent a message received by server
        if (FD_ISSET(client_fd, &read_fds)) {

            size_t encrypted_length;

            char *encrypted =
                receive_message(
                    client_fd,
                    &encrypted_length
                );

            if (encrypted == NULL) {

                printf(
                    "Client disconnected or invalid message.\n"
                );

                break;
            }


            printf(
                "\nReceived ciphertext (%zu bytes):\n%s\n",
                encrypted_length,
                encrypted
            );

            // decrypt the DES encrypted message
            char *plaintext =
                des_decrypt_message(
                    encrypted,
                    des_key
                );

            free(encrypted);


            if (plaintext == NULL) {

                printf(
                    "DES decryption failed.\n"
                );

                break;
            }


            printf(
                "Client: %s\n",
                plaintext
            );

            // handles when typed exit
            if (strcmp(plaintext, "exit") == 0) {

                free(plaintext);
                break;
            }


            free(plaintext);
        }
    }

    close(client_fd);
    close(server_fd);

    return 0;
}
