section .note.GNU-stack noalloc noexec nowrite progbits
section .data
half: db 1.5
section .text
global _start
_start:
    mov rax, 60
    syscall
