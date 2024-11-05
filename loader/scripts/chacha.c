#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "../include/obfuscation/chacha.h"

void sanitize_filename(char* dest, const char* src) {
    size_t j = 0;
    for (size_t i = 0; i < strlen(src); i++) {
        if (isalnum(src[i])) {
            dest[j++] = src[i];
        }
    }
    dest[j] = '\0';
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <string_to_encrypt>\n", argv[0]);
        return 1;
    }

    UCHAR ChaKey[CHACHA_KEYLEN] = { 0 };
    UCHAR ChaIV[CHACHA_IVLEN]   = { 0 };

    memset(ChaKey, 0x5, CHACHA_KEYLEN);
    memset(ChaIV,  0xff, CHACHA_IVLEN);

    UCHAR fvck[256];
    strncpy(fvck, argv[1], sizeof(fvck) - 1);
    fvck[sizeof(fvck) - 1] = '\0';

    char varName[256];
    sanitize_filename(varName, argv[1]);
    strcat(varName, "Enc");

    chacha_memory(ChaKey, sizeof(ChaKey), 20, ChaIV, sizeof(ChaIV), 1, fvck, strlen(fvck), &fvck);

    printf("UCHAR %s[] = { ", varName);
    for (size_t i = 0; i < strlen(fvck); i++) {
        printf("0x%02X", fvck[i]);
        if (i < strlen(fvck) - 1) {
            printf(", ");
        }
    }
    printf(" };\n");

    return 0;
}
