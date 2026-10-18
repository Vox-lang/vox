section .note.GNU-stack noalloc noexec nowrite progbits
section .bss
counter: dq 0
section .text
global _start
_start:
    mov rax, 60
    syscall
