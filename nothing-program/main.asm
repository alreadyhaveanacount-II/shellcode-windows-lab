bits 64
default rel

segment .text
    global _start

; this might BSOD your computer, so run it in a VM, i don't trust myself as a coder
; nvm it works perfectly

_start:
    push rbp
    mov  rbp, rsp
    mov rax, [gs:0x60] ; PEB address
    mov rax, [rax+0x18] ; PEB_LDR_DATA address
    mov rax, [rax+0x10] ; InLoadOrderModuleList address
    mov rcx, 0x004E00520045004B  ; kern in UTF-16

search_name:
    mov rsi, [rax+0x60] ; rsi now stores the address of the UTF-16 buffer for DLLNAME (ex: user32.dll)
    cmp rcx, [rsi] ; loads the first 8 bytes(4 chars) of the address in rsi and compares it to "kern"
    je find_dll_data ; found a match
    mov rax, [rax] ; next dll
    jmp search_name ; back to loop start

find_dll_data:
    mov rax, [rax+0x30] ; rax now stores the address of DLLBASE ( DON'T REPLACE )
    movzx rsi, dword [rax+0x3c] ; rsi now stores e_lfanew
    add rsi, rax ; rsi now stores the address of IMAGE_NT_HEADERS64
    movzx rsi, dword [rsi + 0x88] ; rsi now stores RVA of export table
    add rsi, rax ; rsi now points to the export table
    mov r8d, [rsi + 0x20] ; r8 now contains the RVA to address of names table
    add r8, rax ; r8 now points to address of names
    mov r9, 0x636F725074697845

    xor rcx, rcx ; rcx will be used as the index counter 

search_function_indx:
    movzx r10, dword [r8 + rcx * 4] ; r10 now is the RVA to the pointer of the current name
    add r10, rax ; r10 is now the pointer to the current string

    cmp r9, [r10] ; compares 
    je find_function

    inc rcx ; increment the counter
    jmp search_function_indx

find_function:
    ; rcx is now the index of the function
    movzx r8, dword [rsi + 0x24] ; rsi now contains the RVA to the ordinals table
    add r8, rax ; r8 now points to the ordinals table
    movzx rcx, word [r8 + rcx * 2] ; r9 now contains the correct ordinal

    movzx r8, dword [rsi + 0x1c] ; rsi now contains the RVA to the functions table
    add r8, rax ; r8 now points to the ordinals table

    movzx r9, dword [r8 + rcx * 4] ; r9 now contains the RVA of the correct function
    add r9, rax ; r9 is the pointer to the correct function

    xor rcx, rcx ; zeroes rcx for return code 0
    sub rsp, 32 ; allocates space in the stack for function call
    call r9 ; calls ExitProcess
