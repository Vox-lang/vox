; core.asm - Core macros for Vox Compiler
; Always included - provides essential functionality

; Global error flag - set by runtime checks (bounds, syscalls, etc.)
; This is always available so bounds checks can set it
section .bss
    _last_error: resq 1      ; 0 = no error, non-zero = error code
    _call_depth: resq 1      ; current function call depth (recursion guard)

section .data
    _max_call_depth: dq 10000          ; maximum recursion depth
    _stack_overflow_msg: db "Error: stack overflow (recursion depth exceeded)", 10, 0
    _stack_overflow_msg_len: equ $ - _stack_overflow_msg - 1

section .text

; _check_call_depth - increment call depth and abort if exceeded
; Called at function entry. Clobbers rax only.
_check_call_depth:
    mov rax, [rel _call_depth]
    inc rax
    mov [rel _call_depth], rax
    cmp rax, [rel _max_call_depth]
    jg .stack_overflow
    ret
.stack_overflow:
    ; Print error message to stderr and exit with code 1
    mov rax, 1              ; SYS_WRITE
    mov rdi, 2              ; stderr
    lea rsi, [rel _stack_overflow_msg]
    mov rdx, _stack_overflow_msg_len
    syscall
    mov rax, 60             ; SYS_EXIT
    mov rdi, 1              ; exit code 1 (not a segfault)
    syscall

; _dec_call_depth - decrement call depth on function return
_dec_call_depth:
    dec qword [rel _call_depth]
    ret

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
