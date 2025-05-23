#include <stdlib.h>
#include <stdint.h>

// Runtime function to decrypt strings that were encrypted at compile time using XOR
char* decrypt_string(char* encrypted, size_t len, uint8_t key) {
    
    char* decrypted = (char*)malloc(len + 1);
    if (!decrypted) return NULL;

    // XOR each byte with the key to recover the original string
    for (size_t i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ key;
    }
    decrypted[len] = '\0';
    
    return decrypted;
}