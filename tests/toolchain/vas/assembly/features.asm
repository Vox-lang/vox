; A program built from the constructs the passes handle that the corpus
; programs do not all use: default rel, an equ used before it is defined,
; $, times, align in a data section, floating-point dq items, and all four
; sections. It writes a line and exits with 0 when the doubles vas laid
; down hold the bits nasm gives them, and with the number of the first that
; does not otherwise.
default rel
section .note.GNU-stack noalloc noexec nowrite progbits

section .text
global _start
_start:
    mov rdx, message_length
    lea rsi, [message]
    mov rdi, 1
    mov rax, 1
    syscall
    mov rdi, 1
    mov rax, [one_and_a_half]
    mov rbx, 0x3FF8000000000000
    cmp rax, rbx
    jne .finish
    mov rdi, 2
    mov rax, [ten_to_the_twenty_two]
    mov rbx, 0x4480F0CF064DD592
    cmp rax, rbx
    jne .finish
    mov rdi, 3
    mov rax, [minus_two_and_a_half]
    mov rbx, 0xC004000000000000
    cmp rax, rbx
    jne .finish
    mov rdi, 4
    cmp byte [stars + stars_length - 1], '*'
    jne .finish
    xor rdi, rdi
.finish:
    mov [exit_status], rdi
    mov rdi, [exit_status]
    mov rax, 60
    syscall

section .rodata
message: db "the passes agree", 10
message_length: equ $ - message

section .data
stars: times 3 db '*'
stars_length: equ $ - stars
align 8
one_and_a_half: dq 1.5
ten_to_the_twenty_two: dq 1.0e22
minus_two_and_a_half: dq -2.5

section .bss
exit_status: resq 1
