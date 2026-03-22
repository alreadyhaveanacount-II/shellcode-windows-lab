bits 64
default rel

segment .text:
    global _start

segment .data:
    user32_str db "user32.dll", 0
    msgbox_str db "MessageBoxA", 0
    mainmsg db "Hello World!", 0
    msgcaption db "This is awesome", 0

PEB_TEB_OFFSET equ 0x60
PEB_LDR_OFFSET equ 0x18
LOAD_LIST_OFFSET equ 0x10
KERNEL32_FIRST_CHARS equ 0x004E00520045004B
DLLNAME_BUFFER_OFFSET equ 0x60
DLLBASE_OFFSET equ 0x30
E_LFANEW_OFFSET equ 0x3c
EXPORT_TABLE_RVA_OFFSET equ 0x88
EXITPROC_VAL equ 0x636F725074697845
LOADLIB_VAL   equ 0x7262694C64616F4C 
GETPROC_VAL   equ 0x41636F7250746547 
NAMES_TABLE_OFFSET equ 0x20
FUNCTIONS_TABLE_OFFSET equ 0x1c
ORDINALS_TABLE_OFFSET equ 0x24

_start:
    ; setup
    push rbp
    mov rbp, rsp

    ; finding InLoadOrderMemoryList and loading PEB_LDR_DATA
    mov rax, [gs:PEB_TEB_OFFSET]
    mov rax, [rax + PEB_LDR_OFFSET]
    mov rax, [rax + LOAD_LIST_OFFSET] ; now rax has the addr that points to InLoadOrderMemoryList
    mov rcx, KERNEL32_FIRST_CHARS

search_kernel32:
    mov rsi, [rax+DLLNAME_BUFFER_OFFSET]
    cmp rcx, [rsi]
    je found_kernel32
    mov rax, [rax]
    jmp search_kernel32

found:
    ret

find_function_index:
    movzx r10, dword [rdi + 4*rcx] ; stores the RVA to the current function name 
    add r10, rax ; gets the address of the curr function name

    cmp r9, [r10] ; compares the first characters of the function name with the content on r10
    je found
    
    inc rcx
    jmp find_function_index

search_funcname:
    ; a function to find the address of any given function and store it in r8, reads the bytes in r9
    ; assumes rax points to DLLBASE of the dll and rsi points to the export table
    ; uses rcx as a counter and stores the current table in rdi
    ; overwrites rdi and r10
    movzx rdi, dword [rsi + NAMES_TABLE_OFFSET]
    add rdi, rax

    call find_function_index ; now rcx contains the index of the correct function

    movzx r8, dword [rsi + ORDINALS_TABLE_OFFSET] ; r8 now contains the RVA of the ordinals table
    add r8, rax ; r8 now points to the ordinals table
    
    movzx rcx, word [r8 + rcx * 2] ; rcx now contains the correct ordinal

    movzx r8, dword [rsi + FUNCTIONS_TABLE_OFFSET] ; r8 now contains the RVA to the functions table
    add r8, rax ; r8 now points to the ordinals table

    movzx r8, dword [r8 + rcx * 4] ; r9 now contains the RVA of the correct function
    add r8, rax ; r9 is the pointer to the correct function
    ret

found_kernel32:
    ; Setting up essentials
    mov rax, [rax+DLLBASE_OFFSET] ; rax now equals DLLBASE
    movzx rsi, dword [rax+E_LFANEW_OFFSET] ; rsi now equals e_lfanew
    add rsi, rax ; rsi now points to IMAGE_NT_HEADERS64
    movzx rsi, dword [rsi+EXPORT_TABLE_RVA_OFFSET] ; rsi now equals the RVA of the offset table
    add rsi, rax ; rsi now points to the export table

    ; For ExitProcess
    mov r9, EXITPROC_VAL
    xor rcx, rcx
    call search_funcname
    mov r15, r8

    ; For LoadLibraryA
    mov r9, LOADLIB_VAL
    xor rcx, rcx
    call search_funcname
    mov r14, r8 ; stores the LoadLib function

    ; For GetProcessAddress
    mov r9, GETPROC_VAL
    xor rcx, rcx
    call search_funcname
    mov r13, r8 ; stores the GetProc function

msg_box:
    ; Loading user32.dll
    sub rsp, 32            
    lea rcx, [user32_str]  
    call r14               
    add rsp, 32
    
    ; Saves the handle of user32.dll in r12 (non-volatile)
    mov r12, rax

    ; Gets the address of MessageBoxA in user32.dll
    sub rsp, 32
    mov rcx, r12          
    lea rdx, [msgbox_str] 
    call r13               
    add rsp, 32

    ; Actually showing the message
    sub rsp, 32
    xor rcx, rcx           ; Null handle
    lea rdx, [mainmsg]     ; Main message
    lea r8, [msgcaption]   ; Box title
    xor r9, r9             ; uType - 0 for default
    call rax              ; Calls MessageBoxA
    add rsp, 32

    ; Finishing the program
    and rsp, -16
    sub rsp, 32
    xor rcx, rcx ; zeroes rcx for return code 0
    call r15
