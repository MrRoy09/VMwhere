#include <stdlib.h>
#include <stdint.h>

char* decrypt_string(char* encrypted, size_t len, uint8_t key) {
    char* decrypted = (char*)malloc(len + 1);
    if (!decrypted) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ key;
    }
    decrypted[len] = '\0';
    
    return decrypted;
}