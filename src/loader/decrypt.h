#ifndef DECRYPT_H
#define DECRYPT_H

#include <stddef.h>
void triple_xor_decrypt(unsigned char* data, size_t size);
void xor_decrypt(unsigned char* data, size_t size, unsigned char key);

#endif // DECRYPT_H