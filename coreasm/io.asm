; io.asm - Input/Output macros for English Compiler

section .data
    newline_char: db 10
    int_buffer: times 21 db 0

section .text

%macro PRINT_STR 2
    mov rax, 1
    mov rdi, 1
    lea rsi, [%1]
    mov rdx, %2
    syscall
%endmacro

%macro PRINT_NEWLINE 0
    mov rax, 1
    mov rdi, 1
    lea rsi, [newline_char]
    mov rdx, 1
    syscall
%endmacro

; Print null-terminated string (C-string) - pointer in register
%macro PRINT_CSTR 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1
    call _print_cstr_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

_print_cstr_impl:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rsi, rdi          ; string pointer
    xor rcx, rcx          ; length counter
    
.count_loop:
    mov al, [rsi + rcx]
    test al, al
    jz .do_print
    inc rcx
    jmp .count_loop
    
.do_print:
    mov rax, 1            ; sys_write
    mov rdx, rcx          ; length
    mov rdi, 1            ; stdout
    syscall
    
    pop rbx
    leave
    ret

%macro PRINT_INT 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rax, %1
    mov rdi, rax
    call _print_int_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

_print_int_impl:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rax, rdi
    mov rcx, 0
    mov r8, 0
    
    test rax, rax
    jns .positive
    neg rax
    mov r8, 1
    
.positive:
    lea rdi, [int_buffer + 20]
    mov byte [rdi], 0
    
    test rax, rax
    jnz .convert_loop
    dec rdi
    mov byte [rdi], '0'
    inc rcx
    jmp .print_number
    
.convert_loop:
    test rax, rax
    jz .check_negative
    
    mov rdx, 0
    mov rbx, 10
    div rbx
    
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc rcx
    jmp .convert_loop
    
.check_negative:
    test r8, r8
    jz .print_number
    dec rdi
    mov byte [rdi], '-'
    inc rcx
    
.print_number:
    mov rax, 1
    mov rsi, rdi
    mov rdx, rcx
    mov rdi, 1
    syscall
    
    leave
    ret
