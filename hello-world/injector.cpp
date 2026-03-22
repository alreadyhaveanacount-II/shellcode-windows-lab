#include <iostream>
#include <windows.h>
#include <cstdlib>

int main() {
    unsigned char shellcode[] = {0X9C, 0X50, 0X51, 0X52, 0X53, 0X56, 0X57, 0X41, 0X50, 0X41, 0X51, 0X41, 0X52, 0X41, 0X53, 0X41, 0X54, 0X41, 0X55, 0X41, 0X56, 0X41, 0X57, 0X55, 0X48, 0X89, 0XE5, 0X48, 0X83, 0XE4, 0XF0, 0X65, 0X48, 0X8B, 0X04, 0X25, 0X60, 0X00, 0X00, 0X00, 0X48, 0X8B, 0X40, 0X18, 0X48, 0X8B, 0X40, 0X10, 0X48, 0XB9, 0X4B, 0X00, 0X45, 0X00, 0X52, 0X00, 0X4E, 0X00, 0X48, 0X8B, 0X70, 0X60, 0X48, 0X3B, 0X0E, 0X74, 0X3D, 0X48, 0X8B, 0X00, 0XEB, 0XF2, 0XC3, 0X44, 0X8B, 0X14, 0X8F, 0X49, 0X01, 0XC2, 0X4D, 0X3B, 0X0A, 0X74, 0XF3, 0X48, 0XFF, 0XC1, 0XEB, 0XEF, 0X8B, 0X7E, 0X20, 0X48, 0X01, 0XC7, 0XE8, 0XE4, 0XFF, 0XFF, 0XFF, 0X44, 0X8B, 0X46, 0X24, 0X49, 0X01, 0XC0, 0X49, 0X0F, 0XB7, 0X0C, 0X48, 0X44, 0X8B, 0X46, 0X1C, 0X49, 0X01, 0XC0, 0X45, 0X8B, 0X04, 0X88, 0X49, 0X01, 0XC0, 0XC3, 0X48, 0X8B, 0X40, 0X30, 0X8B, 0X70, 0X3C, 0X48, 0X01, 0XC6, 0X8B, 0XB6, 0X88, 0X00, 0X00, 0X00, 0X48, 0X01, 0XC6, 0X49, 0XB9, 0X4C, 0X6F, 0X61, 0X64, 0X4C, 0X69, 0X62, 0X72, 0X48, 0X31, 0XC9, 0XE8, 0XB5, 0XFF, 0XFF, 0XFF, 0X4D, 0X89, 0XC6, 0X49, 0XB9, 0X47, 0X65, 0X74, 0X50, 0X72, 0X6F, 0X63, 0X41, 0X48, 0X31, 0XC9, 0XE8, 0XA0, 0XFF, 0XFF, 0XFF, 0X4D, 0X89, 0XC5, 0XB8, 0X6C, 0X6C, 0X00, 0X00, 0X50, 0X48, 0XB8, 0X75, 0X73, 0X65, 0X72, 0X33, 0X32, 0X2E, 0X64, 0X50, 0X48, 0X8D, 0X0C, 0X24, 0X48, 0X83, 0XEC, 0X20, 0X41, 0XFF, 0XD6, 0X48, 0X83, 0XC4, 0X30, 0X49, 0X89, 0XC4, 0XB8, 0X6F, 0X78, 0X41, 0X00, 0X50, 0X48, 0XB8, 0X4D, 0X65, 0X73, 0X73, 0X61, 0X67, 0X65, 0X42, 0X50, 0X48, 0X8D, 0X14, 0X24, 0X48, 0X83, 0XEC, 0X20, 0X4C, 0X89, 0XE1, 0X41, 0XFF, 0XD5, 0X48, 0X83, 0XC4, 0X30, 0X49, 0X89, 0XC4, 0XB8, 0X72, 0X6C, 0X64, 0X21, 0X50, 0X48, 0XB8, 0X48, 0X65, 0X6C, 0X6C, 0X6F, 0X20, 0X57, 0X6F, 0X50, 0X48, 0X8D, 0X14, 0X24, 0X48, 0XB8, 0X61, 0X77, 0X65, 0X73, 0X6F, 0X6D, 0X65, 0X00, 0X50, 0X48, 0XB8, 0X54, 0X68, 0X69, 0X73, 0X20, 0X69, 0X73, 0X20, 0X50, 0X4C, 0X8D, 0X04, 0X24, 0X48, 0X83, 0XEC, 0X20, 0X48, 0X31, 0XC9, 0X4D, 0X31, 0XC9, 0X41, 0XFF, 0XD4, 0X48, 0X89, 0XEC, 0X5D, 0X41, 0X5F, 0X41, 0X5E, 0X41, 0X5D, 0X41, 0X5C, 0X41, 0X5B, 0X41, 0X5A, 0X41, 0X59, 0X41, 0X58, 0X5F, 0X5E, 0X5B, 0X5A, 0X59, 0X58, 0X9D, 0XC3 };

    size_t codesize = sizeof(shellcode);

    // Allocating the memory for the shellcode
    LPVOID dynMemory = VirtualAlloc(NULL, codesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copying the shellcode onto the allocated memory
    memcpy(dynMemory, shellcode, codesize);

    // Change memory protection to read/execute
    DWORD oldProtection;
    if (!VirtualProtect(dynMemory, codesize, PAGE_EXECUTE_READ, &oldProtection))
    {
        std::cerr << "Memory protection change failed: " << GetLastError() << std::endl;
        VirtualFree(dynMemory, 0, MEM_RELEASE);
        return 1;
    }

    // Ensure instruction cache coherency after running the code
    FlushInstructionCache(GetCurrentProcess(), dynMemory, codesize);

    // Execute the code by casting the memory pointer to a function pointer type and calling it
    typedef int(*FuncPtr)();
    FuncPtr RunInMemoryCode = (FuncPtr)dynMemory;
    int result = RunInMemoryCode();

    std::cout << "Executed code in RAM\n";

    if (!VirtualFree(dynMemory, 0, MEM_RELEASE)) {
        std::cerr << "Memory deallocation failed: " << GetLastError() << std::endl;
        return 1;
    }

    return EXIT_SUCCESS;
}
