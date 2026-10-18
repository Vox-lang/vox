section .note.GNU-stack noalloc noexec nowrite progbits
section .data
message: db "hi"
message_end: equ message + 2
section .text
global _start
_start:
    mov rax, 60
    syscall
