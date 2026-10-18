section .note.GNU-stack noalloc noexec nowrite progbits
section .text
global _start
_start:
    mov rax, xmm0
    mov rax, 60
    syscall
