#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>


size_t get_page_size_obfuscated(void) {
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = sysconf(_SC_PAGESIZE);
        if (page_size == -1) {
            page_size = 4096; 
        }
    }
    return page_size;
}

size_t calculate_aligned_size(size_t size) {
    size_t page_size = get_page_size_obfuscated();
    return ((size + page_size - 1) / page_size) * page_size;
}

void* allocate_executable_memory(size_t size) {
    size_t aligned_size = calculate_aligned_size(size);
    
    // PROT_READ|PROT_WRITE = 0x3, MAP_PRIVATE|MAP_ANONYMOUS = 0x22
    void* ptr = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return ptr;
}

int protect_memory(void* addr, size_t size, int prot) {
    size_t aligned_size = calculate_aligned_size(size);
    
    return mprotect(addr, aligned_size, prot);
}

size_t manual_strlen(const char* str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

void manual_memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
}
