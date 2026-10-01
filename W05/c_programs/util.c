#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

/* def hex2bin(s): */
/* 	mp = {'0': "0000", */
/* 		'1': "0001", */
/* 		'2': "0010", */
/* 		'3': "0011", */
/* 		'4': "0100", */
/* 		'5': "0101", */
/* 		'6': "0110", */
/* 		'7': "0111", */
/* 		'8': "1000", */
/* 		'9': "1001", */
/* 		'A': "1010", */
/* 		'B': "1011", */
/* 		'C': "1100", */
/* 		'D': "1101", */
/* 		'E': "1110", */
/* 		'F': "1111"} */
/* 	bin = "" */
/* 	for i in range(len(s)): */
/* 		bin = bin + mp[s[i]] */
/* 	return bin */

char *hex2bin(const char *s) {
    const char* map[] = {
        "0000",
        "0001",
        "0010",
        "0011",
        "0100",
        "0101",
        "0110",
        "0111",
        "1000",
        "1001",
        "1010",
        "1011",
        "1100",
        "1101",
        "1110",
        "1111"
    };

    size_t len = strlen(s);
    char *bin = malloc(len * 4 + 1); // 1 hex == 4 bit
    if(bin == NULL) {
        return NULL;
    }

    bin[0] = '\0';

    for(size_t i = 0; i < len; i++) {
        char c = s[i];
        int index;

        if(c >= '0' && c <= '9') {
            index = c - '0';
        } else if (c >= 'A' && c <= 'F') {
            index = c - 'A' + 10;
        } else if (c >= 'a' && c <= 'c') {
            index = c - 'a' + 10;
        } else {
            free(bin);
            return NULL;
        }

        strcat(bin, map[index]);
    }
    
    return bin;
}

/* # Binary to hexadecimal conversion */
/**/
/**/
/* def bin2hex(s): */
/* 	mp = {"0000": '0', */
/* 		"0001": '1', */
/* 		"0010": '2', */
/* 		"0011": '3', */
/* 		"0100": '4', */
/* 		"0101": '5', */
/* 		"0110": '6', */
/* 		"0111": '7', */
/* 		"1000": '8', */
/* 		"1001": '9', */
/* 		"1010": 'A', */
/* 		"1011": 'B', */
/* 		"1100": 'C', */
/* 		"1101": 'D', */
/* 		"1110": 'E', */
/* 		"1111": 'F'} */
/* 	hex = "" */
/* 	for i in range(0, len(s), 4): */
/* 		ch = "" */
/* 		ch = ch + s[i] */
/* 		ch = ch + s[i + 1] */
/* 		ch = ch + s[i + 2] */
/* 		ch = ch + s[i + 3] */
/* 		hex = hex + mp[ch] */
/**/
/* 	return hex */
/**/

char* bin2hex(const char *s) {
    const char *map = "0123456789ABCDEF";
    size_t len = strlen(s);

    if(len % 4 != 0) {
        return NULL;
    }

    char *hex = malloc(len / 4 + 1); // 1 hex == 4 bit
    if(hex == NULL) {
        return NULL;
    }

    for(size_t i = 0; i < len; i+=4) {
        int value = 0;

        value = value * 2 + (s[i] - '0');
        value = value * 2 + (s[i + 1] - '0');
        value = value * 2 + (s[i + 2] - '0');
        value = value * 2 + (s[i + 3] - '0');

        hex[i / 4] = map[value];
    }

    hex[len / 4] = '\0';
    return hex;
}
/* # Binary to decimal conversion */
/**/
/**/
/* def bin2dec(binary): */
/**/
/* 	binary1 = binary */
/* 	decimal, i, n = 0, 0, 0 */
/* 	while(binary != 0): */
/* 		dec = binary % 10 */
/* 		decimal = decimal + dec * pow(2, i) */
/* 		binary = binary//10 */
/* 		i += 1 */
/* 	return decimal */
/**/
int bin2dec(unsigned long binary) {
    int decimal = 0;
    int i = 0;

    while(binary != 0) {
        int dec = binary % 10;

        decimal = decimal + dec * (1 << i);
        binary = binary / 10;

        i++;
    }

    return decimal;
}

/* # Decimal to binary conversion */
/**/
/**/
/* def dec2bin(num): */
/* 	res = bin(num).replace("0b", "") */
/* 	if(len(res) % 4 != 0): */
/* 		div = len(res) / 4 */
/* 		div = int(div) */
/* 		counter = (4 * (div + 1)) - len(res) */
/* 		for i in range(0, counter): */
/* 			res = '0' + res */
/* 	return res */
/**/
char *dec2bin(unsigned int num) {
    char temp[33];
    int pos = 0;

    do {
        temp[pos++] = (num & 1) + '0';
        num >>= 1;
    } while (num != 0);

    int padded_length = ((pos + 3) / 4) * 4;

    char *result = malloc(padded_length + 1);
    if(result == NULL) {
        return NULL;
    }

    for(int i = 0; i < padded_length; i++) {
        if(i < padded_length - pos) {
            result[i] = '0';
        } else {
            result[i] = temp[pos - 1 - (i - (padded_length - pos))];
        }
    }

    result[padded_length] = '\0';
    return result;
}

/* # Permute function to rearrange the bits */
/**/
/**/
/* def permute(k, arr, n): */
/* 	permutation = "" */
/* 	for i in range(0, n): */
/* 		permutation = permutation + k[arr[i] - 1] */
/* 	return permutation */
/**/

char *permute(const char *k, const int *arr, int n) {
    char *permutation = malloc(n + 1);
    if(permutation == NULL) {
        return NULL;
    }

    for (int i = 0; i < n; i++) {
        permutation[i] = k[arr[i] - 1];
    }

    permutation[n] = '\0';

    return permutation;
}

/* # shifting the bits towards left by nth shifts */
/**/
/**/
/* def shift_left(k, nth_shifts): */
/* 	s = "" */
/* 	for i in range(nth_shifts): */
/* 		for j in range(1, len(k)): */
/* 			s = s + k[j] */
/* 		s = s + k[0] */
/* 		k = s */
/* 		s = "" */
/* 	return k */
/**/
char *shift_left(const char *k, int nth_shifts) {
    int len = strlen(k);
    char *result = malloc(len + 1);
    if(result == NULL) {
        return NULL;
    }

    strcpy(result, k);
    for(int i = 0; i < nth_shifts; i++) {
        char first = result[0];

        for(int j = 0; j < len - 1; j++) {
            result[j] = result[j + 1];
        }

        result[len - 1] = first;
    }

    result[len] = '\0';
    return result;
}

/* # calculating xow of two strings of binary number a and b */
/**/
/**/
/* def xor(a, b): */
/* 	ans = "" */
/* 	for i in range(len(a)): */
/* 		if a[i] == b[i]: */
/* 			ans = ans + "0" */
/* 		else: */
/* 			ans = ans + "1" */
/* 	return ans */

char *xor_bits(const char *a, const char *b) {
    size_t len = strlen(a);
    if(strlen(b) != len) {
        return NULL;
    }

    char *ans = malloc(len + 1);
    if(ans == NULL) {
        return NULL;
    }

    for(size_t i = 0; i < len; i++) {
        if(a[i] == b[i]) {
            ans[i] = '0';
        } else {
            ans[i] = '1';
        }
    }

    ans[len] = '\0';
    return ans;
}

// converts ASCII input to its hex output representation
char *ascii2hex(const char *ascii)
{
    size_t len = strlen(ascii);

    char *hex = malloc(len * 2 + 1);
    if (hex == NULL)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(&hex[i * 2], "%02X", (unsigned char)ascii[i]);
    }

    hex[len * 2] = '\0';

    return hex;
}

// converts hex input to its ASCII string output representation (reverse)
char *hex2ascii(const char *hex)
{
    size_t len = strlen(hex);

    if (len % 2 != 0)
        return NULL;

    char *ascii = malloc(len / 2 + 1);
    if (ascii == NULL)
        return NULL;

    for (size_t i = 0; i < len; i += 2) {
        unsigned int value;

        if (sscanf(&hex[i], "%2x", &value) != 1) {
            free(ascii);
            return NULL;
        }

        ascii[i / 2] = (char)value;
    }

    ascii[len / 2] = '\0';

    return ascii;
}

// helper for converting ASCII string to its binary representation
char *ascii2bin(const char *ascii)
{
    size_t len = strlen(ascii);
    char *binary = malloc(len * 8 + 1);

    if (binary == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)ascii[i];

        for (int j = 7; j >= 0; j--) {
            binary[i * 8 + (7 - j)] =
                ((c >> j) & 1) ? '1' : '0';
        }
    }

    binary[len * 8] = '\0';

    return binary;
}
