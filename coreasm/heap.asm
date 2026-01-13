; heap.asm - Heap memory management for English Compiler

section .bss
    alloc_table: resq 256
    alloc_sizes: resq 256
    alloc_count: resq 1

section .text

%macro HEAP_ALLOC 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    
    mov rsi, %1
    add rsi, 4095
    and rsi, ~4095
    
    mov rax, 9
    mov rdi, 0
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    syscall
    
    cmp rax, -1
    je %%alloc_failed
    
    push rax
    mov rcx, [alloc_count]
    cmp rcx, 256
    jge %%skip_track
    
    lea rdi, [alloc_table]
    mov [rdi + rcx * 8], rax
    lea rdi, [alloc_sizes]
    mov [rdi + rcx * 8], rsi
    inc qword [alloc_count]
    
%%skip_track:
    pop rax
    jmp %%alloc_done
    
%%alloc_failed:
    xor rax, rax
    
%%alloc_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

%macro HEAP_FREE 1
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r11
    
    mov rdi, %1
    
    mov rcx, [alloc_count]
    test rcx, rcx
    jz %%free_done
    
    lea r8, [alloc_table]
    xor rbx, rbx
    
%%find_loop:
    cmp rbx, rcx
    jge %%free_done
    
    cmp [r8 + rbx * 8], rdi
    je %%found_alloc
    
    inc rbx
    jmp %%find_loop
    
%%found_alloc:
    lea rsi, [alloc_sizes]
    mov rsi, [rsi + rbx * 8]
    
    mov rax, 11
    syscall
    
    dec qword [alloc_count]
    mov rcx, [alloc_count]
    
    lea r8, [alloc_table]
    mov rax, [r8 + rcx * 8]
    mov [r8 + rbx * 8], rax
    
    lea r8, [alloc_sizes]
    mov rax, [r8 + rcx * 8]
    mov [r8 + rbx * 8], rax
    
%%free_done:
    pop r11
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro
