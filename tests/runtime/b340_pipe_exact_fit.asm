; Regression for issue #8 (track B4): reading from a pipe into a fixed buffer
; that fills exactly must not lose a byte and must not signal a spurious
; overflow error.
;
; Not expressible in Vox: there is no pipe() primitive, so no Vox program can
; hand _read_into_buffer an unseekable fd with known, ordered content. The
; runtime is exercised directly here, the way tests/runtime/*.asm does for
; every other invariant no Vox program can express.
;
; Before track B4, _read_into_buffer probed for "more data" after an exact fill
; with read(fd, &scratch, 1) + lseek(fd, -1, SEEK_CUR). On a pipe the probe
; consumed one byte that lseek could not put back (ESPIPE), so the byte was
; lost and _last_error was set to 1 (overflow) even though the caller had not
; asked for more than the buffer's capacity. With 32 bytes written to a 16-byte
; fixed buffer, the old code lost byte 17 and errored on the very first fill.
;
; Exit 0 = pass, 1 = fail.

%include "coreasm/x86_64/core.asm"
%include "coreasm/x86_64/resource.asm"

%define SYS_WRITE 1
%define SYS_CLOSE 3
%define SYS_PIPE  22

section .data
    payload:     db "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"   ; 32 bytes, in order
    payload_len: equ $ - payload

section .bss
    ; pipe(2) fills an int[2]: read end at offset 0, write end at offset 4
    ; (4 bytes each - NOT qwords). Loading them as dwords avoids reading the
    ; other fd into the high bits of the register.
    pipe_fds: resd 2           ; [0]=read end (dword), [4]=write end (dword)
    ; Fixed buffer struct: [capacity:8][length:8][flags:8][data...]. The data
    ; area is oversized vs the 16-byte capacity so _read_into_buffer's null
    ; terminator (written at data+length, i.e. data+16 when full) lands inside
    ; the allocation, not in recv.
    pbuf:      resq 3           ; capacity@0, length@8, flags@16 (24 bytes)
    pbuf_data: resb 32          ; data area @ offset 24, capacity 16 (+ slack)
    recv:      resb 32          ; accumulator for every byte read, in order

section .text
global _start

_start:
    ; --- create the pipe ---
    mov rax, SYS_PIPE
    lea rdi, [rel pipe_fds]
    syscall
    test rax, rax
    jnz .fail

    ; --- write 32 bytes to the write end ---
    mov rax, SYS_WRITE
    mov edi, [rel pipe_fds + 4]      ; write end = pipe_fds[1] (dword)
    lea rsi, [rel payload]
    mov rdx, payload_len
    syscall
    cmp rax, payload_len
    jne .fail

    ; --- close the write end so the reader sees EOF ---
    mov rax, SYS_CLOSE
    mov edi, [rel pipe_fds + 4]      ; write end (dword)
    syscall
    test rax, rax
    jnz .fail

    ; --- register the read end (caches S_IFIFO / st_size=0) ---
    mov edi, [rel pipe_fds]          ; read end = pipe_fds[0] (dword)
    call _register_fd

    ; --- set up a 16-byte fixed buffer ---
    mov qword [rel pbuf + BUF_CAPACITY], 16
    mov qword [rel pbuf + BUF_LENGTH], 0
    mov qword [rel pbuf + BUF_FLAGS], BUF_FLAG_FIXED

    ; --- drain the pipe through the fixed buffer into recv ---
    xor r13, r13                     ; total bytes received
    mov qword [rel _last_error], 0    ; a pipe must never signal overflow here
.read_loop:
    mov qword [rel pbuf + BUF_LENGTH], 0   ; read replaces, it does not append
    mov edi, [rel pipe_fds]                ; read end (dword)
    lea rsi, [rel pbuf]
    call _read_into_buffer
    ; rax = bytes read this call (0 = EOF). _read_into_buffer preserves
    ; callee-saved r13 (total) and r15 (recv base) across the call.
    test rax, rax
    jz .read_done
    ; An unseekable fd that fills a fixed buffer exactly is an exact fit, not
    ; overflow - a spurious error here is the bug we are guarding against.
    cmp qword [rel _last_error], 0
    jne .fail
    ; copy the rax bytes just read into recv[r13]
    mov rcx, rax
    lea rsi, [rel pbuf + BUF_DATA]
    lea rdi, [rel recv]
    add rdi, r13
.copy_byte:
    test rcx, rcx
    jz .copy_done
    mov r8b, [rsi]
    mov [rdi], r8b
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_byte
.copy_done:
    add r13, rax
    jmp .read_loop

.read_done:
    ; --- assert every byte arrived ---
    cmp r13, payload_len
    jne .fail
    ; --- assert no error was ever signalled ---
    cmp qword [rel _last_error], 0
    jne .fail
    ; --- assert the bytes arrived in order ---
    lea rsi, [rel recv]
    lea rdi, [rel payload]
    mov rcx, payload_len
.cmp_byte:
    test rcx, rcx
    jz .pass
    mov r8b, [rsi]
    cmp r8b, [rdi]
    jne .fail
    inc rsi
    inc rdi
    dec rcx
    jmp .cmp_byte

.pass:
    EXIT 0

.fail:
    EXIT 1