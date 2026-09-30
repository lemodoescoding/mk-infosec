#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* #include "keygen.h" */
/* #include "util.h" */
#include "des_functions.h"

#define DES_BLOCK_SIZE 8
#define DES_KEY "AABB09182736CCDD"

int main(void)
{
    char input[1024];

    printf("Enter plaintext: ");

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "Failed to read input.\n");
        return 1;
    }

    /*
     * Remove newline added by fgets().
     */
    input[strcspn(input, "\n")] = '\0';

    size_t plaintext_len = strlen(input);

    /*
     * PKCS#7 padding.
     *
     * Even if the plaintext is already exactly 8 bytes,
     * we add a complete 8-byte padding block.
     */
    size_t padding = DES_BLOCK_SIZE - (plaintext_len % DES_BLOCK_SIZE);

    size_t padded_len = plaintext_len + padding;

    char *padded_plaintext = malloc(padded_len);

    if (padded_plaintext == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }

    /*
     * Copy original plaintext.
     */
    memcpy(padded_plaintext, input, plaintext_len);

    /*
     * Add PKCS#7 padding.
     */
    for (size_t i = plaintext_len; i < padded_len; i++) {
        padded_plaintext[i] = (char)padding;
    }

    /*
     * Each plaintext block produces 16 hexadecimal
     * characters of ciphertext.
     */
    size_t ciphertext_len = padded_len * 2;

    char *ciphertext = malloc(ciphertext_len + 1);

    if (ciphertext == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(padded_plaintext);
        return 1;
    }

    ciphertext[0] = '\0';

    /*
     * Encrypt every 8-byte block.
     */
    printf("\n=== Encryption ===\n");

    for (size_t offset = 0;
         offset < padded_len;
         offset += DES_BLOCK_SIZE) {

        char block[DES_BLOCK_SIZE + 1];

        memcpy(block,
               padded_plaintext + offset,
               DES_BLOCK_SIZE);

        block[DES_BLOCK_SIZE] = '\0';

        /*
         * Encrypt exactly one 8-byte block.
         */
        char *encrypted_block =
            des_encrypt_block(block, DES_KEY);

        if (encrypted_block == NULL) {
            fprintf(stderr, "Encryption failed.\n");

            free(padded_plaintext);
            free(ciphertext);

            return 1;
        }

        /*
         * Append the 16-character hexadecimal ciphertext.
         */
        strcat(ciphertext, encrypted_block);

        printf("Block %zu: ", offset / DES_BLOCK_SIZE);
        printf("'%s' -> %s\n",
               block,
               encrypted_block);

        free(encrypted_block);
    }

    printf("\nCiphertext: %s\n", ciphertext);


    /*
     * ============================
     * DECRYPTION
     * ============================
     */

    printf("\n=== Decryption ===\n");

    /*
     * Every encrypted DES block is represented by
     * 16 hexadecimal characters.
     */
    size_t ciphertext_chars = strlen(ciphertext);

    char *decrypted_padded = malloc(padded_len + 1);

    if (decrypted_padded == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");

        free(padded_plaintext);
        free(ciphertext);

        return 1;
    }

    size_t decrypted_offset = 0;

    for (size_t offset = 0;
         offset < ciphertext_chars;
         offset += 16) {

        char cipher_block[17];

        /*
         * Copy one 16-character hexadecimal block.
         */
        memcpy(cipher_block,
               ciphertext + offset,
               16);

        cipher_block[16] = '\0';

        /*
         * Decrypt one block.
         */
        char *decrypted_block =
            des_decrypt_block(cipher_block, DES_KEY);

        if (decrypted_block == NULL) {
            fprintf(stderr, "Decryption failed.\n");

            free(padded_plaintext);
            free(ciphertext);
            free(decrypted_padded);

            return 1;
        }

        /*
         * Copy decrypted 8 bytes into the
         * complete decrypted buffer.
         */
        memcpy(decrypted_padded + decrypted_offset,
               decrypted_block,
               DES_BLOCK_SIZE);

        decrypted_offset += DES_BLOCK_SIZE;

        printf("Block %zu: %s -> '%s'\n",
               offset / 16,
               cipher_block,
               decrypted_block);

        free(decrypted_block);
    }

    decrypted_padded[decrypted_offset] = '\0';


    /*
     * ============================
     * REMOVE PKCS#7 PADDING
     * ============================
     */

    unsigned char padding_value =
        (unsigned char)decrypted_padded[decrypted_offset - 1];

    /*
     * Basic padding validation.
     */
    if (padding_value < 1 ||
        padding_value > DES_BLOCK_SIZE ||
        padding_value > decrypted_offset) {

        fprintf(stderr, "Invalid padding.\n");

        free(padded_plaintext);
        free(ciphertext);
        free(decrypted_padded);

        return 1;
    }

    /*
     * Remove padding.
     */
    size_t decrypted_len =
        decrypted_offset - padding_value;

    decrypted_padded[decrypted_len] = '\0';

    printf("\nDecrypted plaintext: %s\n",
           decrypted_padded);


    /*
     * Cleanup.
     */
    free(padded_plaintext);
    free(ciphertext);
    free(decrypted_padded);

    return 0;
}
