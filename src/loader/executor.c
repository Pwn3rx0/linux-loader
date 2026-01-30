#include "executor.h"
#include <sys/mman.h>

typedef int (*shellcode_func)(void);

static void clear_stack(void) {
    __asm__ volatile (
        "mov $0, %%rax\n\t"
        "mov $0, %%rbx\n\t"
        "mov $0, %%rcx\n\t"
        "mov $0, %%rdx"
        : : : "rax", "rbx", "rcx", "rdx"
    );
}

void execute_shellcode(void* shellcode_mem) {
    shellcode_func func = (shellcode_func)shellcode_mem;
    
    // Clear some more registers
    __asm__ volatile (
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "xor %%r10, %%r10\n\t"
        "xor %%r11, %%r11"
        : : : "r8", "r9", "r10", "r11"
    );    
    func();
}