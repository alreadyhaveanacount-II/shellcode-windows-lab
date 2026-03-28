#define ROR13(x) (((x) >> 13) | ((x) << (32 - 13)))

typedef unsigned int uint64_t __attribute__((mode(DI)));
typedef unsigned int uint32_t __attribute__((mode(SI)));
typedef int int32_t __attribute__((mode(SI)));
typedef unsigned int uint16_t __attribute__((mode(HI)));
typedef unsigned int uint8_t __attribute__((mode(QI)));

typedef struct {
    void* DLLBase;
    void* ExportTable;
    void* NtFreeVirtualMemory;
    void* NtAllocateVirtualMemory;
    void* NtCreateUserProcess;
    void* NtProtectVirtualMemory;
    void* NtFlushInstructionCache;
} PEB_Scavenger;

int get_ssn(void* nt_func_ptr) {
    unsigned int curr_pos = 0;
    unsigned char* func_bytes = (unsigned char*) nt_func_ptr;

    if(func_bytes[0] != 0x4C) {
        // something wrong is not right
        return -1;
    }

    for(;;) {
        if(func_bytes[curr_pos] == 0x0F && func_bytes[curr_pos+1] == 0x05) {
            break;
        }

        ++curr_pos;
    }

    for(;curr_pos >= 0;) {
        --curr_pos;

        if(func_bytes[curr_pos] == 0xB8) {
            return ((uint32_t)func_bytes[curr_pos+4] << 24) | ((uint32_t)func_bytes[curr_pos+3] << 16) | ((uint32_t)func_bytes[curr_pos+2] << 8) | (uint32_t)func_bytes[curr_pos+1];
        }
    }

    return 0;
}

uint32_t ror13_string(uint16_t* name, uint16_t length) {
    uint32_t acc = 0;

    for(uint16_t i=0; i < length; i++) {
        acc = ROR13(acc);
        acc += name[i];
    }

    return acc;
}

uint32_t ror13_ascii(uint8_t* name) {
    uint32_t acc = 0;
    uint16_t indx = 0;

    while(1) {
        unsigned char curr = name[indx];

        if(curr == 0) return acc;

        acc = ROR13(acc);
        acc += curr;

        indx++;
    }
}

void* find_ntdll(void* dll_list_ptr) {
    uint16_t* name_buffer;
    uint16_t stringlen;

    __asm__ __volatile__ (
        "movq 0x60(%2), %0\n" // BaseDllName.Buffer
        "movw 0x58(%2), %1"    // BaseDllName.Length
        : "=r" (name_buffer), "=r" (stringlen)
        : "r" (dll_list_ptr)
    );

    if(ror13_string(name_buffer, stringlen >> 1) == 0xCEF6E822) {
        return dll_list_ptr;
    }
    
    void* next_dll;
    __asm__ __volatile__ (
        "movq (%1), %0"
        : "=r" (next_dll)
        : "r" (dll_list_ptr)
    );

    return find_ntdll(next_dll);
}

uint64_t find_func_indx(void* names_table, void* dllbase, uint32_t* hashes, uint64_t* counters, uint64_t amount) {
    uint64_t ctr = 0;
    uint64_t added = 0;
    uint8_t* curr_name;

    while(added < amount) {
        // NtCreateUserProcess - F4F14F30
        // NtAllocateVirtualMemory - D33BCABD
        // NtFreeVirtualMemory - DB63B5AB
        // NtProtectVirtualMemory - 8C394D89
        // NtFlushInstructionCache - 534C0AB8

        __asm__ __volatile__ (
            "movl (%1, %2, 4), %%eax\n" // eax = RVA
            "addq %3, %%rax\n"          // rax = RVA + dllbase
            "movq %%rax, %0"            // curr_name = rax
            : "=r" (curr_name)          // %0
            : "r" (names_table),        // %1
              "r" (ctr),                // %2
              "r" (dllbase)             // %3
            : "rax", "memory"
        );

        uint32_t hashed = ror13_ascii(curr_name);

        // char* comparer = "NtFlushInstructionCache";
        // bool is_equal = true;

        // for(int i=0; i < strlen(comparer); i++) {
        //     if(curr_name[i] != comparer[i]) {
        //         is_equal = false;
        //         break;
        //     }
        // }

        // if(is_equal) printf("%s - %X\n", curr_name, hashed);

        for(size_t i=0; i < amount; i++) {
            if(hashes[i] == hashed) {
                counters[i] = ctr;
                added++;
            }
        }
        
        ctr++;
    }

    return ctr;
}

void find_func_pointer(void** functions, uint64_t* indexes, uint64_t amount, void* ordinals_table, void* functions_table, void* dllbase) {
    for(unsigned int i=0; i < amount; i++) {
        uint64_t curr_indx = indexes[i];
        void* curr_func;

        __asm__ __volatile__ (
            "movzwl  (%1, %4, 2), %%eax\n"  // ax = correct ordinal
            "movl (%2, %%rax, 4), %%edi\n" // edi = RVA of the correct function
            "addq %3, %%rdi\n"
            "movq %%rdi, %0"
            : "=r" (curr_func)          // %0
            : "r" (ordinals_table),     // %1
              "r" (functions_table),    // %2
              "r" (dllbase),            // %3
              "r" (curr_indx)           // %4
            : "rax", "rdi", "memory"
        );

        functions[i] = curr_func;
    }
}


void load_functions(PEB_Scavenger* scavenger) {
    void* names_table_offset;
    void* ordinals_table_offset;
    void* functions_table_offset;

    __asm__ __volatile__ (
        "movl 0x20(%1), %%eax\n"
        "addq %2, %%rax\n"
        "movq %%rax, %0"
        : "=r" (names_table_offset)
        : "r" (scavenger->ExportTable), "r" (scavenger->DLLBase)
        : "memory", "%rax"
    );

    __asm__ __volatile__ (
        "movl 0x24(%1), %%eax\n"
        "addq %2, %%rax\n"
        "movq %%rax, %0"
        : "=r" (ordinals_table_offset)
        : "r" (scavenger->ExportTable), "r" (scavenger->DLLBase)
        : "memory", "%rax"
    );

    __asm__ __volatile__ (
        "movl 0x1c(%1), %%eax\n"
        "addq %2, %%rax\n"
        "movq %%rax, %0"
        : "=r" (functions_table_offset)
        : "r" (scavenger->ExportTable), "r" (scavenger->DLLBase)
        : "memory", "%rax"
    );

// NtCreateUserProcess, NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory, NtFlushInstructionCache
    uint32_t hashes[5] = {0xF4F14F30,0xD33BCABD, 0xDB63B5AB, 0x8C394D89, 0x534C0AB8};
    uint64_t counters[5];

    find_func_indx(names_table_offset, scavenger->DLLBase, hashes, counters, 5);

    void* functions[5];

    find_func_pointer(functions, counters, 5, ordinals_table_offset, functions_table_offset, scavenger->DLLBase);

    scavenger->NtCreateUserProcess = functions[0];
    scavenger->NtAllocateVirtualMemory = functions[1];
    scavenger->NtFreeVirtualMemory = functions[2];
    scavenger->NtProtectVirtualMemory = functions[3];
    scavenger->NtFlushInstructionCache = functions[4];
}

PEB_Scavenger init_scavenger() {
    PEB_Scavenger s;

    __asm__ __volatile__ (
        "movq %%gs:0x60, %0\n" // %0 = PEB VA
        "movq 0x18(%0), %0\n" // %0 = LDR VA
        "movq 0x10(%0), %0" // %0 = InLoadOrderModuleList VA
        : "+r" (s.DLLBase)
        :
        : "memory"
    );

    s.DLLBase = find_ntdll(s.DLLBase);

    __asm__ __volatile__ (
        "movq 0x30(%2), %%rbx\n"    // rbx = DllBase (Offset 0x30 da LDR_ENTRY)
        "movl 0x3c(%%rbx), %%eax\n" // eax = e_lfanew
        "addq %%rbx, %%rax\n"       // rax = NT_HEADER VA
        
        "movl 0x88(%%rax), %%edi\n" // edi = Export Table RVA
        "addq %%rbx, %%rdi\n"       // rdi = Export Table VA (Absolute)

        "movq %%rbx, %0\n"          // s.DLLBase = rbx
        "movq %%rdi, %1\n"          // s.ExportTable = rdi
        : "=r" (s.DLLBase),         // %0
          "=r" (s.ExportTable)      // %1
        : "r" (s.DLLBase)           // %2 (Entrada da lista vinda do find_kernel32)
        : "rax", "rbx", "rdi", "memory"
    );

    load_functions(&s);

    return s;
}
