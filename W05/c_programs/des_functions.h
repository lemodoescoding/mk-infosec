#ifndef DES_FUNCTIONS_H
#define DES_FUNCTIONS_H

char *encrypt(
    const char *pt,
    char *rkb[16],
    char *rk[16]
);

// static char *xor_hex_blocks(const char *a, const char *b);
// static char *des_encrypt_hex_block(const char *plaintext_hex, const char *key);
// static char *des_decrypt_hex_block(const char *ciphertext_hex, const char *key);

char *des_cbc_encrypt(const char *plaintext, const char *key, const char *iv);
char *des_cbc_decrypt(const char *ciphertext, const char *key, const char *iv);

char *des_encrypt_block(const char *plaintext, const char *key);
char *des_decrypt_block(const char *ciphertext, const char *key);

char *des_encrypt_message(const char *plaintext, const char *key);
char *des_decrypt_message(const char *ciphertext, const char *key);


#endif
