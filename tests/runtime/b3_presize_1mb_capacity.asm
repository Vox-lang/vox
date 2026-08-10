; Track B3: pre-sizing a regular-file slurp must allocate exactly st_size+1,
; not double. A 1 MB regular file (1048576 bytes) is read into an empty dynamic
; buffer; the buffer must end at length 1048576 and capacity 1048577 - i.e.
; capacity <= file_size + 1 (the "small margin" is the single null-terminator
; byte). The old doubling path would land at capacity 2097152 (> file_size +
; any small margin), so this asserts the exact-sizing path, which also copies
; zero bytes (the buffer was empty) instead of the ~2 MB of copies the doubling
; path accumulated. Exit 0 = pass.

%include "coreasm/x86_64/core.asm"
%include "coreasm/x86_64/io.asm"
%include "coreasm/x86_64/string.asm"
%include "coreasm/x86_64/file.asm"
%include "coreasm/x86_64/resource.asm"

%define O_RDONLY 0
%define O_WRONLY 1
%define O_CREAT  0x40
%define O_TRUNC  0x200

%define FILE_SIZE 1048576       ; 1 MB
%define CHUNK     4096
%define CHUNKS    256           ; FILE_SIZE / CHUNK

section .data
    path:  db "/tmp/vox_b3_1mb_test.txt", 0

section .bss
    chunk: resb CHUNK

section .text
global _start

_start:
    ; --- create a 1 MB regular file, all 'A' ---
    mov rax, 2              ; SYS_OPEN
    lea rdi, [rel path]
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 420            ; 0644
    syscall
    cmp rax, 0
    jl .fail
    mov r12, rax            ; wf fd

    ; fill chunk with 'A'
    lea rdi, [rel chunk]
    mov rcx, CHUNK
    mov al, 0x41
    rep stosb

    mov r13, CHUNKS         ; remaining chunks (callee-saved)
.write_loop:
    mov rax, 1              ; SYS_WRITE
    mov rdi, r12
    lea rsi, [rel chunk]
    mov rdx, CHUNK
    syscall
    cmp rax, CHUNK
    jne .fail
    dec r13
    jnz .write_loop

    mov rax, 3              ; SYS_CLOSE
    mov rdi, r12
    syscall

    ; --- empty dynamic buffer, then read the file in ---
    call _alloc_buffer
    test rax, rax
    jz .fail
    mov rbx, rax            ; rbx = buffer (callee-saved across the read call)

    mov rax, 2
    lea rdi, [rel path]
    mov rsi, O_RDONLY
    xor rdx, rdx
    syscall
    cmp rax, 0
    jl .fail
    mov r12, rax            ; rf fd

    mov rdi, r12
    mov rsi, rbx
    call _read_into_buffer
    ; rax = bytes read, rsi = (possibly new) buffer ptr
    mov rbx, rsi            ; update buffer pointer (it moved: pre-size grew it)

    ; --- assertions ---
    cmp rax, FILE_SIZE
    jne .fail
    cmp qword [rbx + BUF_LENGTH], FILE_SIZE
    jne .fail
    ; exact sizing: capacity == file_size + 1 (<= file_size + small margin)
    cmp qword [rbx + BUF_CAPACITY], FILE_SIZE + 1
    jne .fail

    ; first and last bytes are 'A'
    movzx rax, byte [rbx + BUF_DATA]
    cmp rax, 0x41
    jne .fail
    movzx rax, byte [rbx + BUF_DATA + FILE_SIZE - 1]
    cmp rax, 0x41
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