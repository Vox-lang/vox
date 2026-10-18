section .note.GNU-stack noalloc noexec nowrite progbits
section .data
count: db 3
padding: times count db 0
section .text
global _start
_start:
    mov rax, 60
    syscall
