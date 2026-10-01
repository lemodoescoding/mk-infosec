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

    char des_key[9];
    char server_ip[INET_ADDRSTRLEN];

    printf("Server IP address: ");

    if (fgets(
        server_ip,
        sizeof(server_ip),
        stdin) == NULL) {

        return 1;
    }

    server_ip[strcspn(server_ip, "\n")] = '\0';

    printf("Enter DES key (8 ASCII characters): ");

    if (fgets(des_key, sizeof(des_key), stdin) == NULL) {
        return 1;
    }

    des_key[strcspn(des_key, "\n")] = '\0';

    if (strlen(des_key) != 8) {
        fprintf(
            stderr,
            "Error: DES key must be exactly 8 ASCII characters.\n"
        );
        return 1;
    }


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

    printf("[Client] > ");
    fflush(stdout);

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

            if (strlen(buffer) == 0) {
                printf("[Server] > ");
                fflush(stdout);
                continue;
            }

            printf("[Client] Encrypting message...\n");

            char iv[IV_SIZE + 1];
            if(generate_iv(iv) < 0) {
                printf("IV generation failed.");
                break;
            }

            printf("IV: %s\n", iv);

            // encrypt the message before sending 
            char *encrypted =
                des_cbc_encrypt(
                    buffer,
                    des_key,
                    iv
                );

            if (encrypted == NULL) {

                printf(
                    "Encryption failed.\n"
                );

                break;
            }


            size_t encrypted_length =
                strlen(encrypted);


            /* printf( */
            /*     "Encrypted sending: %s\n", */
            /*     encrypted */
            /* ); */
            printf("[Client] Encrypting message...\n");
            printf("Sending to server: %s\n", encrypted);

            // [4-byte length][ciphertext]
            if (send_message(
                    sock_fd,
                    iv,
                    encrypted,
                    encrypted_length
                ) < 0) {

                perror("send_message");

                free(encrypted);
                break;
            }

            printf("[Client] Message Encrypted and sent.\n");
            free(encrypted);


            // handles when typed "exit"
            if (strcmp(buffer, "exit") == 0) {
                break;
            }

            printf("[Client] > ");
            fflush(stdout);
        }

        // when server sends something
        else if (FD_ISSET(sock_fd, &read_fds)) {

            size_t encrypted_response_length;

            char recv_iv[IV_SIZE + 1];

            char *encrypted_response =
                receive_message(
                    sock_fd,
                    recv_iv,
                    &encrypted_response_length
                );

            if (encrypted_response == NULL) {

                printf(
                    "\nServer disconnected or invalid message.\n"
                );

                break;
            }


            printf(
                "\n[Client] Encrypted received (%zu bytes):\n%s\n",
                encrypted_response_length,
                encrypted_response
            );

            printf("Recv IV: %s\n", recv_iv);


            // decrypt the DES encrypted message
            char *plaintext =
                des_cbc_decrypt(
                    encrypted_response,
                    des_key,
                    recv_iv
                );

            free(encrypted_response);


            if (plaintext == NULL) {

                printf(
                    "Decryption failed.\n"
                );

                break;
            }


            printf(
                "[Server] > %s\n",
                plaintext
            );


            // handles when typed "exit"
            if (strcmp(plaintext, "exit") == 0) {

                free(plaintext);
                break;
            }


            free(plaintext);

            printf("[Client] > ");
            fflush(stdout);
        }
    }

    close(sock_fd);

    return 0;
}
