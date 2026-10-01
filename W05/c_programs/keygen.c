#include <stdlib.h>
#include <string.h>

#include "keygen.h"
#include "constant.h"
#include "util.h"

void generate_round_keys(
    const char *key_ascii,
    char *rkb[16],
    char *rk[16]
)
{
    char *key = ascii2bin(key_ascii);

    char *permuted_key = permute(key, keyp, 56);

    free(key);

    char left[29];
    char right[29];

    memcpy(left, permuted_key, 28);
    left[28] = '\0';

    memcpy(right, permuted_key + 28, 28);
    right[28] = '\0';

    free(permuted_key);

    for (int i = 0; i < 16; i++) {

        char *new_left =
            shift_left(left, shift_table[i]);

        char *new_right =
            shift_left(right, shift_table[i]);

        strcpy(left, new_left);
        strcpy(right, new_right);

        free(new_left);
        free(new_right);

        char combined[57];

        strcpy(combined, left);
        strcat(combined, right);

        rkb[i] =
            permute(combined, key_comp, 48);

        rk[i] =
            bin2hex(rkb[i]);
    }
}
