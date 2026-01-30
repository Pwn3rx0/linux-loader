#include "decrypt.h"
static void xor_decrypt_internal(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

void triple_xor_decrypt(unsigned char* data, size_t size) {
    #include "../payload/payload.h"
    xor_decrypt_internal(data, size, KEY1);
    xor_decrypt_internal(data, size, KEY2);
    xor_decrypt_internal(data, size, KEY3);
}

void xor_decrypt(unsigned char* data, size_t size, unsigned char key) {
    xor_decrypt_internal(data, size, key);
}