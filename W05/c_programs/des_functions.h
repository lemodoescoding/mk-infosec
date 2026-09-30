#ifndef DES_FUNCTIONS_H
#define DES_FUNCTIONS_H

char *encrypt(
    const char *pt,
    char *rkb[16],
    char *rk[16]
);

char *des_encrypt_block(const char *plaintext, const char *key);

char *des_decrypt_block(const char *ciphertext, const char *key);

#endif
