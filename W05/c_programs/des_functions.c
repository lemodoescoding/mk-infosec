#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des_functions.h"
#include "constant.h"
#include "keygen.h"
#include "util.h"

#define DES_BLOCK_SIZE 8
#define DES_HEX_BLOCK_SIZE 16

static char *xor_hex_blocks(const char *a, const char *b);
static char *des_encrypt_hex_block(const char *plaintext_hex, const char *key);
static char *des_decrypt_hex_block(const char *ciphertext_hex, const char *key);

// XOR two 16-character hexadecimal DES blocks.
static char *xor_hex_blocks(
    const char *a,
    const char *b
)
{
    if (strlen(a) != DES_HEX_BLOCK_SIZE ||
        strlen(b) != DES_HEX_BLOCK_SIZE) {
        return NULL;
    }

    char *result =
        malloc(DES_HEX_BLOCK_SIZE + 1);

    if (result == NULL)
        return NULL;

    for (int i = 0; i < DES_HEX_BLOCK_SIZE; i++) {
        unsigned int x;
        unsigned int y;

        if (sscanf(&a[i], "%1x", &x) != 1 ||
            sscanf(&b[i], "%1x", &y) != 1) {

            free(result);
            return NULL;
        }

        result[i] =
            "0123456789ABCDEF"[x ^ y];
    }

    result[DES_HEX_BLOCK_SIZE] = '\0';

    return result;
}


// function to encrypt one hexadecimal DES block in CBC mode.
// The input and output are both hexadecimal.
static char *des_encrypt_hex_block(
    const char *plaintext_hex,
    const char *key
)
{
    char *rkb[16];
    char *rk[16];

    generate_round_keys(key, rkb, rk);

    char *cipher_bin =
        encrypt(plaintext_hex, rkb, rk);

    if (cipher_bin == NULL) {
        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    char *cipher_hex =
        bin2hex(cipher_bin);

    free(cipher_bin);

    for (int i = 0; i < 16; i++) {
        free(rkb[i]);
        free(rk[i]);
    }

    return cipher_hex;
}

// function to decrypt one hexadecimal DES block in CBC mode.
// The input and output are both hexadecimal.
static char *des_decrypt_hex_block(
    const char *ciphertext_hex,
    const char *key
)
{
    char *rkb[16];
    char *rk[16];

    generate_round_keys(key, rkb, rk);

    /*
     * Reverse the round keys for DES decryption.
     */
    char *rkb_rev[16];
    char *rk_rev[16];

    for (int i = 0; i < 16; i++) {
        rkb_rev[i] = rkb[15 - i];
        rk_rev[i] = rk[15 - i];
    }

    char *plaintext_bin =
        encrypt(ciphertext_hex, rkb_rev, rk_rev);

    if (plaintext_bin == NULL) {
        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    char *plaintext_hex =
        bin2hex(plaintext_bin);

    free(plaintext_bin);

    for (int i = 0; i < 16; i++) {
        free(rkb[i]);
        free(rk[i]);
    }

    return plaintext_hex;
}

char *des_cbc_encrypt(
    const char *plaintext,
    const char *key,
    const char *iv
)
{
    size_t plaintext_len = strlen(plaintext);

    // DES block size = 8 bytes.
    // PKCS#7 padding:
    // 8-byte plaintext -> 8 bytes padding
    // 7-byte plaintext -> 1 byte padding
    // etc.
    size_t padding =
        DES_BLOCK_SIZE -
        (plaintext_len % DES_BLOCK_SIZE);

    size_t padded_len =
        plaintext_len + padding;

    char *padded =
        malloc(padded_len);

    if (padded == NULL)
        return NULL;

    memcpy(
        padded,
        plaintext,
        plaintext_len
    );

    for (size_t i = plaintext_len;
         i < padded_len;
         i++) {
        padded[i] = (char)padding;
    }

    // CBC IV length must be exactly 8 ASCII bytes.
    if (strlen(iv) != DES_BLOCK_SIZE) {
        free(padded);
        return NULL;
    }

    // convert IV from ASCII -> hexadecimal.
    // Example: "12345678"
    // becomes: 3132333435363738
    char *previous =
        ascii2hex(iv);

    if (previous == NULL) {
        free(padded);
        return NULL;
    }

    // for each 8-byte plaintext block becomes 16 hexadecimal ciphertext characters.
    char *ciphertext =
        malloc(padded_len * 2 + 1);

    if (ciphertext == NULL) {
        free(padded);
        free(previous);
        return NULL;
    }

    ciphertext[0] = '\0';

    for (size_t offset = 0;
         offset < padded_len;
         offset += DES_BLOCK_SIZE) {

        
        // convert plaintext block to hexadecimal .
        char block[DES_BLOCK_SIZE + 1];

        memcpy(
            block,
            padded + offset,
            DES_BLOCK_SIZE
        );

        block[DES_BLOCK_SIZE] = '\0';

        char *block_hex =
            ascii2hex(block);

        if (block_hex == NULL) {
            free(padded);
            free(previous);
            free(ciphertext);
            return NULL;
        }

        // CBC:
        // P[i] XOR C[i-1]
        //where C[-1] = IV
        char *xored =
            xor_hex_blocks(
                block_hex,
                previous
            );

        free(block_hex);

        if (xored == NULL) {
            free(padded);
            free(previous);
            free(ciphertext);
            return NULL;
        }

        // using CBC mode enryption DES( P[i] XOR previous ) function
        char *encrypted =
            des_encrypt_hex_block(
                xored,
                key
            );

        free(xored);

        if (encrypted == NULL) {
            free(padded);
            free(previous);
            free(ciphertext);
            return NULL;
        }

        // append ciphertext block.
        strcat(ciphertext, encrypted);

        // C[i] becomes the previous block for the next iteration.
        free(previous);

        previous = encrypted;
    }

    free(previous);
    free(padded);

    return ciphertext;
}

char *des_cbc_decrypt(
    const char *ciphertext,
    const char *key,
    const char *iv
)
{
    size_t ciphertext_len =
        strlen(ciphertext);

    // ciphertext sent by client/server must consist of complete 8-byte DES blocks.
    // 8 bytes = 16 hexadecimal characters.
    if (ciphertext_len == 0 ||
        ciphertext_len % DES_HEX_BLOCK_SIZE != 0) {
        return NULL;
    }

    // checks the IV must be exactly 8 ASCII bytes.
    if (strlen(iv) != DES_BLOCK_SIZE) {
        return NULL;
    }

    size_t number_of_blocks =
        ciphertext_len /
        DES_HEX_BLOCK_SIZE;

    size_t plaintext_size =
        number_of_blocks *
        DES_BLOCK_SIZE;

    /*
     * This temporarily stores the plaintext
     * including PKCS#7 padding.
     */
    char *plaintext =
        malloc(plaintext_size + 1);

    if (plaintext == NULL)
        return NULL;

    // previous ciphertext block starts as IV for the first block sent.
    char *previous =
        ascii2hex(iv);

    if (previous == NULL) {
        free(plaintext);
        return NULL;
    }

    size_t plaintext_offset = 0;

    for (size_t offset = 0;
         offset < ciphertext_len;
         offset += DES_HEX_BLOCK_SIZE) {

        // extract C[i] from the cipher block.
        char cipher_block[
            DES_HEX_BLOCK_SIZE + 1
        ];

        memcpy(
            cipher_block,
            ciphertext + offset,
            DES_HEX_BLOCK_SIZE
        );

        cipher_block[
            DES_HEX_BLOCK_SIZE
        ] = '\0';

        // using the CBC mode decryption function util DES_DECRYPT(C[i])
        char *decrypted =
            des_decrypt_hex_block(
                cipher_block,
                key
            );

        if (decrypted == NULL) {
            free(previous);
            free(plaintext);
            return NULL;
        }

        // CBC:
        // P[i] =
        // DES_DECRYPT(C[i]) XOR C[i-1]
        // where C[-1] = IV
        char *plain_hex =
            xor_hex_blocks(
                decrypted,
                previous
            );

        free(decrypted);

        if (plain_hex == NULL) {
            free(previous);
            free(plaintext);
            return NULL;
        }

        // converts the resulting 8-byte block from hexadecimal -> ASCII.
        char *plain_block =
            hex2ascii(plain_hex);

        free(plain_hex);

        if (plain_block == NULL) {
            free(previous);
            free(plaintext);
            return NULL;
        }

        memcpy(
            plaintext + plaintext_offset,
            plain_block,
            DES_BLOCK_SIZE
        );

        plaintext_offset += DES_BLOCK_SIZE;

        free(plain_block);

        // C[i] becomes C[i-1] for the next iteration.
        free(previous);

        previous =
            malloc(DES_HEX_BLOCK_SIZE + 1);

        if (previous == NULL) {
            free(plaintext);
            return NULL;
        }

        strcpy(previous, cipher_block);
    }

    free(previous);

    plaintext[plaintext_offset] = '\0';

    // removes the PKCS#7 padding.
    unsigned char padding =
        (unsigned char)
        plaintext[plaintext_offset - 1];

    if (padding < 1 ||
        padding > DES_BLOCK_SIZE ||
        padding > plaintext_offset) {

        free(plaintext);
        return NULL;
    }

    // verify all padding bytes.
    for (size_t i = 0;
         i < padding;
         i++) {

        if ((unsigned char)
            plaintext[
                plaintext_offset - 1 - i
            ] != padding) {

            free(plaintext);
            return NULL;
        }
    }

    // remove padding to get the plaintext.
    plaintext[
        plaintext_offset - padding
    ] = '\0';

    return plaintext;
}

char *encrypt(const char *pt, char *rkb[16], char *rk[16])
{
    // Hexadecimal -> binary
    char *pt_bin = hex2bin(pt);

    // Initial Permutation (IP)
    char *permuted = permute(pt_bin, initial_perm, 64);

    printf("After initial permutation %s\n", bin2hex(permuted));

    free(pt_bin);

    // Splitting to L and R (32-byte each)
    char left[33];
    char right[33];

    memcpy(left, permuted, 32);
    left[32] = '\0';

    memcpy(right, permuted + 32, 32);
    right[32] = '\0';

    free(permuted);

    for (int i = 0; i < 16; i++) {

        // Expansion D-box (64 -> 48)
        char *right_expanded = permute(right, exp_d, 48);

        // XOR RoundKey[i] and right_expanded
        char *xor_x = xor_bits(right_expanded, rkb[i]);

        free(right_expanded);

        // S-box
        char sbox_str[33];
        int sbox_pos = 0;

        for (int j = 0; j < 8; j++) {

            /*
             * Python:
             *
             * row = bin2dec(
             *     int(xor_x[j * 6] + xor_x[j * 6 + 5])
             * )
             *
             * row consists of:
             *   bit 1 and bit 6
             */

            int row =
                (xor_x[j * 6] - '0') * 2 +
                (xor_x[j * 6 + 5] - '0');

            /*
             * Python:
             *
             * col = bin2dec(
             *     int(xor_x[j * 6 + 1]
             *       + xor_x[j * 6 + 2]
             *       + xor_x[j * 6 + 3]
             *       + xor_x[j * 6 + 4])
             * )
             */

            int col =
                (xor_x[j * 6 + 1] - '0') * 8 +
                (xor_x[j * 6 + 2] - '0') * 4 +
                (xor_x[j * 6 + 3] - '0') * 2 +
                (xor_x[j * 6 + 4] - '0');

            int val = sbox[j][row][col];

            /*
             * dec2bin() gives us a 4-bit string.
             *
             * Example:
             * 5 -> "0101"
             */
            char *sbox_bin = dec2bin(val);

            memcpy(sbox_str + sbox_pos, sbox_bin, 4);
            sbox_pos += 4;

            free(sbox_bin);
        }

        sbox_str[32] = '\0';

        free(xor_x);

        // Straight D-box
        char *permuted_sbox = permute(sbox_str, per, 32);

        // XOR left and sbox_str
        char *result = xor_bits(left, permuted_sbox);

        free(permuted_sbox);

        /*
         * Python:
         *
         * left = result
         */
        strcpy(left, result);

        free(result);

        /*
         * Swapper
         *
         * if (i != 15):
         *     left, right = right, left
         */
        if (i != 15) {
            char temp[33];

            strcpy(temp, left);
            strcpy(left, right);
            strcpy(right, temp);
        }

        char *left_hex = bin2hex(left);
        char *right_hex = bin2hex(right);

        printf(
            "Round %d %s %s %s\n",
            i + 1,
            left_hex,
            right_hex,
            rk[i]
        );

        free(left_hex);
        free(right_hex);
    }

    // Combination
    char combine[65];

    strcpy(combine, left);
    strcat(combine, right);

    printf("\n");
    printf("Combination before final permutation:\n");
    printf("%s\n", bin2hex(combine));

    // Final permutation
    char *cipher_text = permute(combine, final_perm, 64);

    printf("Final permutation:\n");
    printf("%s\n", bin2hex(cipher_text));

    return cipher_text;
}

// EBC mode encryption block (per round it is independent and doesnt use IV)
char *des_encrypt_block(const char *plaintext, const char *key)
{
    // convert from ASCII -> hexadecimal
    // 8 ASCII bytes become 16 hexadecimal characters.
    char *plaintext_hex = ascii2hex(plaintext);

    if (plaintext_hex == NULL)
        return NULL;

    // generate the DES round keys.
    char *rkb[16];
    char *rk[16];

    generate_round_keys(key, rkb, rk);

    // doing the encryption for one DES block.
    char *cipher_bin = encrypt(plaintext_hex, rkb, rk);

    if (cipher_bin == NULL) {
        free(plaintext_hex);

        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    // converts the cipher binary -> hexadecimal.
    char *cipher_hex = bin2hex(cipher_bin);

    free(plaintext_hex);
    free(cipher_bin);

    for (int i = 0; i < 16; i++) {
        free(rkb[i]);
        free(rk[i]);
    }

    return cipher_hex;
}

// EBC mode decryption block (each round computed independently)
char *des_decrypt_block(const char *ciphertext, const char *key)
{
    // generate DES round keys.
    char *rkb[16];
    char *rk[16];

    generate_round_keys(key, rkb, rk);

    // get the reverse from the round keys for DES decryption.
    char *rkb_rev[16];
    char *rk_rev[16];

    for (int i = 0; i < 16; i++) {
        rkb_rev[i] = rkb[15 - i];
        rk_rev[i] = rk[15 - i];
    }

    // DES encryption function with reversed keys performs decryption.
    char *decrypted_bin = encrypt(ciphertext, rkb_rev, rk_rev);

    if (decrypted_bin == NULL) {
        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    // converts from binary -> hexadecimal.
    char *decrypted_hex = bin2hex(decrypted_bin);

    if (decrypted_hex == NULL) {
        free(decrypted_bin);

        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    // conver from hexadecimal -> ASCII.
    char *decrypted_ascii = hex2ascii(decrypted_hex);

    // cleanup the pointer
    free(decrypted_bin);
    free(decrypted_hex);

    for (int i = 0; i < 16; i++) {
        free(rkb[i]);
        free(rk[i]);
    }

    return decrypted_ascii;
}

// EBC mode wrapper when doing message encryption from the input user
// added the PKCS#7 padding and sending the DES block
char *des_encrypt_message(const char *plaintext, const char *key)
{
    size_t plaintext_len = strlen(plaintext);

    //calculates the offset for PKCS#7 padding.
    size_t padding =
        DES_BLOCK_SIZE - (plaintext_len % DES_BLOCK_SIZE);

    size_t padded_len =
        plaintext_len + padding;

    // allocates space just as much for the pkcs and the DES block
    char *padded = malloc(padded_len);

    if (padded == NULL)
        return NULL;

    memcpy(padded, plaintext, plaintext_len);

    for (size_t i = plaintext_len; i < padded_len; i++)
        padded[i] = (char)padding;

    // each 8-byte block produces 16 hex characters.
    size_t output_size =
        padded_len * 2;

    char *ciphertext =
        malloc(output_size + 1);

    if (ciphertext == NULL) {
        free(padded);
        return NULL;
    }

    ciphertext[0] = '\0';

    // encrypt each DES block.
    for (size_t offset = 0;
         offset < padded_len;
         offset += DES_BLOCK_SIZE) {

        char block[DES_BLOCK_SIZE + 1];

        memcpy(
            block,
            padded + offset,
            DES_BLOCK_SIZE
        );

        block[DES_BLOCK_SIZE] = '\0';

        // using the EBC wrapper
        char *encrypted =
            des_encrypt_block(block, key);

        if (encrypted == NULL) {
            free(padded);
            free(ciphertext);
            return NULL;
        }

        strcat(ciphertext, encrypted);

        free(encrypted);
    }

    free(padded);

    return ciphertext;
}

// EBC mode wrapper when doing message decryption from the other side (client/server)
// added the PKCS#7 padding and sending the DES block
char *des_decrypt_message(const char *ciphertext, const char *key)
{
    size_t ciphertext_len =
        strlen(ciphertext);

    //Every DES block is 16 hexadecimal characters.
    if (ciphertext_len == 0 ||
        ciphertext_len % DES_HEX_BLOCK_SIZE != 0) {

        return NULL;
    }

    size_t number_of_blocks =
        ciphertext_len / DES_HEX_BLOCK_SIZE;

    size_t plaintext_size =
        number_of_blocks * DES_BLOCK_SIZE;

    // allocates just as much space needed to send the blocks
    char *plaintext =
        malloc(plaintext_size + 1);

    if (plaintext == NULL)
        return NULL;

    size_t plaintext_offset = 0;

    //Decrypt every block.
    for (size_t offset = 0;
         offset < ciphertext_len;
         offset += DES_HEX_BLOCK_SIZE) {

        char cipher_block[DES_HEX_BLOCK_SIZE + 1];

        memcpy(
            cipher_block,
            ciphertext + offset,
            DES_HEX_BLOCK_SIZE
        );

        cipher_block[DES_HEX_BLOCK_SIZE] = '\0';

        // using the EBC wraper per block
        char *decrypted =
            des_decrypt_block(cipher_block, key);

        if (decrypted == NULL) {
            free(plaintext);
            return NULL;
        }

        memcpy(
            plaintext + plaintext_offset,
            decrypted,
            DES_BLOCK_SIZE
        );

        plaintext_offset += DES_BLOCK_SIZE;

        free(decrypted);
    }

    plaintext[plaintext_offset] = '\0';

    // removes PKCS#7 padding
    unsigned char padding =
        (unsigned char)plaintext[plaintext_offset - 1];

    if (padding < 1 ||
        padding > DES_BLOCK_SIZE ||
        padding > plaintext_offset) {

        free(plaintext);
        return NULL;
    }

    // verifies every padding byte.
    for (size_t i = 0; i < padding; i++) {

        if ((unsigned char)
            plaintext[plaintext_offset - 1 - i]
            != padding) {

            free(plaintext);
            return NULL;
        }
    }

    plaintext[plaintext_offset - padding] = '\0';

    return plaintext;
}
