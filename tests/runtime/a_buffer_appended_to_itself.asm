; A buffer appended to itself, across a growth that moves it.
;
; Growth can move a buffer and release the block it grew out of, so an append
; whose source is the destination (or bytes inside the destination's own
; data) must read the source from the moved block. Reached in Vox through
; `append hold to hold.` for the buffer routine; the raw-bytes routine is
; checked here directly, with bytes taken from the destination's own data.
; Exit 0 = pass; each failed check exits with its own number.

%include "coreasm/x86_64/core.asm"
%include "coreasm/x86_64/io.asm"
%include "coreasm/x86_64/string.asm"
%include "coreasm/x86_64/resource_fd.asm"
%include "coreasm/x86_64/resource_buffer.asm"

section .data
    pattern: db "abcdefgh"

section .text
global _start

; Fill the buffer in r12 with 512 copies of "abcdefgh" (4096 bytes, its
; whole first capacity). Leaves the buffer in r12.
fill:
    mov r13, 512
.fill_more:
    mov rdi, r12
    lea rsi, [rel pattern]
    mov rdx, 8
    call _buffer_append_bytes
    mov r12, rax
    dec r13
    jnz .fill_more
    ret

; Check the buffer in r12 holds r14 bytes of the repeating pattern.
; Sets ZF on success.
check:
    cmp [r12 + BUF_LENGTH], r14
    jne .check_done
    xor rcx, rcx
.check_byte:
    cmp rcx, r14
    je .check_done_equal
    mov rax, rcx
    and rax, 7
    lea rdx, [rel pattern]
    mov al, [rdx + rax]
    cmp al, [r12 + BUF_DATA + rcx]
    jne .check_done
    inc rcx
    jmp .check_byte
.check_done_equal:
    cmp rax, rax
.check_done:
    ret

_start:
    ; 1. The buffer routine: the buffer appended to itself.
    call _alloc_buffer
    mov r12, rax
    call fill
    mov rdi, r12
    mov rsi, r12
    call _buffer_append
    mov r12, rax
    mov r14, 8192
    call check
    jne .fail_1

    ; 2. The raw-bytes routine: the destination's own data as the source.
    call _alloc_buffer
    mov r12, rax
    call fill
    mov rdi, r12
    lea rsi, [r12 + BUF_DATA]
    mov rdx, 4096
    call _buffer_append_bytes
    mov r12, rax
    mov r14, 8192
    call check
    jne .fail_2

    EXIT 0
.fail_1:
    EXIT 1
.fail_2:
    EXIT 2
