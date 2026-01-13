; core.asm - Core macros for English Compiler
; Always included - provides essential functionality

; Global error flag - set by runtime checks (bounds, syscalls, etc.)
; This is always available so bounds checks can set it
section .bss
    _last_error: resq 1      ; 0 = no error, non-zero = error code

section .text

%macro EXIT 1
    mov rax, 60
    mov rdi, %1
    syscall
%endmacro

%macro SYSCALL1 2
    mov rax, %1
    mov rdi, %2
    syscall
%endmacro

%macro SYSCALL2 3
    mov rax, %1
    mov rdi, %2
    mov rsi, %3
    syscall
%endmacro

%macro SYSCALL3 4
    mov rax, %1
    mov rdi, %2
    mov rsi, %3
    mov rdx, %4
    syscall
%endmacro
