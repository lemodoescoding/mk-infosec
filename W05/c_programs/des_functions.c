#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des_functions.h"
#include "constant.h"
#include "keygen.h"
#include "util.h"

char *encrypt(const char *pt, char *rkb[16], char *rk[16])
{
    // Hexadecimal -> binary
    char *pt_bin = hex2bin(pt);

    // Initial Permutation
    char *permuted = permute(pt_bin, initial_perm, 64);

    printf("After initial permutation %s\n", bin2hex(permuted));

    free(pt_bin);

    // Splitting
    char left[33];
    char right[33];

    memcpy(left, permuted, 32);
    left[32] = '\0';

    memcpy(right, permuted + 32, 32);
    right[32] = '\0';

    free(permuted);

    for (int i = 0; i < 16; i++) {

        // Expansion D-box
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

    // Final permutation
    char *cipher_text = permute(combine, final_perm, 64);

    return cipher_text;
}

char *des_encrypt_block(const char *plaintext, const char *key)
{
    /*
     * ASCII → hexadecimal
     *
     * 8 ASCII bytes become 16 hexadecimal characters.
     */
    char *plaintext_hex = ascii2hex(plaintext);

    if (plaintext_hex == NULL)
        return NULL;

    /*
     * Generate DES round keys.
     */
    char *rkb[16];
    char *rk[16];

    generate_round_keys(key, rkb, rk);

    /*
     * Encrypt one DES block.
     */
    char *cipher_bin = encrypt(plaintext_hex, rkb, rk);

    if (cipher_bin == NULL) {
        free(plaintext_hex);

        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    /*
     * Binary → hexadecimal.
     */
    char *cipher_hex = bin2hex(cipher_bin);

    /*
     * Cleanup.
     */
    free(plaintext_hex);
    free(cipher_bin);

    for (int i = 0; i < 16; i++) {
        free(rkb[i]);
        free(rk[i]);
    }

    return cipher_hex;
}


char *des_decrypt_block(const char *ciphertext, const char *key)
{
    /*
     * Generate DES round keys.
     */
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

    /*
     * DES encryption function with reversed keys
     * performs decryption.
     */
    char *decrypted_bin = encrypt(ciphertext, rkb_rev, rk_rev);

    if (decrypted_bin == NULL) {
        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    /*
     * Binary → hexadecimal.
     */
    char *decrypted_hex = bin2hex(decrypted_bin);

    if (decrypted_hex == NULL) {
        free(decrypted_bin);

        for (int i = 0; i < 16; i++) {
            free(rkb[i]);
            free(rk[i]);
        }

        return NULL;
    }

    /*
     * Hexadecimal → ASCII.
     */
    char *decrypted_ascii = hex2ascii(decrypted_hex);

    /*
     * Cleanup.
     */
    free(decrypted_bin);
    free(decrypted_hex);

    for (int i = 0; i < 16; i++) {
        free(rkb[i]);
        free(rk[i]);
    }

    return decrypted_ascii;
}
