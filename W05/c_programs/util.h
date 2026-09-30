#ifndef UTIL_H
#define UTIL_H

char *hex2bin(const char *s);
char *bin2hex(const char *s);

int bin2dec(unsigned long binary);
char *dec2bin(unsigned int num);

char *permute(const char *k, const int *arr, int n);
char *shift_left(const char *k, int nth_shifts);

char *xor_bits(const char *a, const char *b);

char *ascii2hex(const char *ascii);

char *hex2ascii(const char *hex);

#endif
