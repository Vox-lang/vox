section .note.GNU-stack noalloc noexec nowrite progbits
section .data
size: db 3
section .bss
room: resb size
section .text
global _start
_start:
    mov rax, 60
    syscall
