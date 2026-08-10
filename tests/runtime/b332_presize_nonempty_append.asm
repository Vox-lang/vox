; Track B3: pre-sizing must NOT fire when the destination buffer already holds
; data.
;
; Not expressible in Vox: the only file-read-into-buffer statement (Read from)
; resets the buffer length to 0 before calling _read_into_buffer, so no Vox
; program can hand _read_into_buffer a populated buffer. The guard is reached
; only by a direct caller, so this test calls the runtime directly.
;
; A 4-byte regular file "WXYZ" is read into a buffer already holding "PRE:".
; Pre-sizing must skip (BUF_LENGTH != 0), so capacity stays 4096 (no grow
; happens) and the file bytes are appended after the prefix, yielding
; "PRE:WXYZ" of length 8. If the guard were missing, pre-sizing would
; reallocate to st_size+1 = 5 and capacity would not be 4096. Exit 0 = pass.

%include "coreasm/x86_64/core.asm"
%include "coreasm/x86_64/io.asm"
%include "coreasm/x86_64/string.asm"
%include "coreasm/x86_64/file.asm"
%include "coreasm/x86_64/resource.asm"

%define O_RDONLY 0
%define O_WRONLY 1
%define O_CREAT  0x40
%define O_TRUNC  0x200

section .data
    path:     db "/tmp/vox_b332_test.txt", 0
    prefix:   db "PRE:", 0
    fcontent: db "WXYZ", 0
    expect:   db "PRE:WXYZ", 0

section .text
global _start

_start:
    ; --- create a 4-byte regular file "WXYZ" ---
    mov rax, 2              ; SYS_OPEN
    lea rdi, [rel path]
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 420            ; 0644
    syscall
    cmp rax, 0
    jl .fail
    mov r12, rax            ; wf fd (callee-saved)

    mov rax, 1              ; SYS_WRITE
    mov rdi, r12
    lea rsi, [rel fcontent]
    mov rdx, 4
    syscall
    cmp rax, 4
    jne .fail

    mov rax, 3              ; SYS_CLOSE
    mov rdi, r12
    syscall

    ; --- empty dynamic buffer, then pre-fill it with "PRE:" ---
    call _alloc_buffer
    test rax, rax
    jz .fail
    mov r12, rax            ; r12 = buffer (callee-saved across calls)

    lea rsi, [rel prefix]
    lea rdi, [r12 + BUF_DATA]
    mov rcx, 4
    rep movsb
    mov qword [r12 + BUF_LENGTH], 4

    ; --- open the file for reading ---
    mov rax, 2
    lea rdi, [rel path]
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall
    cmp rax, 0
    jl .fail
    mov r13, rax            ; rf fd (callee-saved)

    ; --- _read_into_buffer(fd, buf): buf length=4 -> pre-size must skip ---
    mov rdi, r13
    mov rsi, r12
    call _read_into_buffer
    ; rax = bytes read, rsi = (possibly new) buffer ptr
    mov r12, rsi            ; update buffer pointer

    ; --- assertions ---
    cmp qword [r12 + BUF_LENGTH], 8
    jne .fail
    cmp qword [r12 + BUF_CAPACITY], 4096   ; pre-size skipped -> no grow
    jne .fail
    cmp rax, 4                             ; bytes read == file size
    jne .fail

    ; content == "PRE:WXYZ"
    lea rsi, [rel expect]
    lea rdi, [r12 + BUF_DATA]
    mov rcx, 8
    repe cmpsb
    jne .fail

    mov rax, 87             ; SYS_UNLINK
    lea rdi, [rel path]
    syscall
    EXIT 0

.fail:
    mov rax, 87
    lea rdi, [rel path]
    syscall
    EXIT 1