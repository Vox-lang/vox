; resource_readahead.asm - Read-ahead cache + line/byte seek
; Split from resource.asm (audit rec 1). _get_readahead_slot,
; _read_line_into_buffer, and _seek_fd_{byte,line} live here. Gated
; separately from the fd/buffer core (uses_readline || uses_seek): a
; buffer-only program that never reads lines or seeks never pulls this
; module.
;
; Depends on resource_fd.asm (ra_* bss + READAHEAD_* defines +
; _flush_readahead_fd, which moved to fd so _unregister_fd stays
; self-contained) and resource_buffer.asm (BUF_* offsets, _grow_buffer).
; Both are included before this module.

section .bss
    ; Note: _last_error is defined in core.asm (always available)
    line_read_tmp: resb 1
    line_read_fallback_tmp: resb 1

section .text
; Find or assign read-ahead slot for fd
; Args: fd in rdi
; Returns: slot index in rax, or -1 if no slot available
; Clobbers: rcx, rdx
_get_readahead_slot:
    push rbx
    push r12
    push r13
    push r14

    ; Hoist one RIP-relative base per read-ahead table: each is indexed by
    ; the same slot in rcx, and the bases never change across the routine.
    lea rbx, [rel ra_used]
    lea r12, [rel ra_fd]
    lea r13, [rel ra_pos]
    lea r14, [rel ra_filled]
    xor rcx, rcx
    mov rdx, -1                 ; first free slot (or -1)

.slot_scan:
    cmp rcx, READAHEAD_SLOTS
    jge .slot_done_scan

    movzx eax, byte [rbx + rcx]
    test eax, eax
    jz .slot_is_free

    mov rax, [r12 + rcx*8]
    cmp rax, rdi
    je .slot_found_existing

    inc rcx
    jmp .slot_scan

.slot_is_free:
    cmp rdx, -1
    jne .slot_continue_scan
    mov rdx, rcx

.slot_continue_scan:
    inc rcx
    jmp .slot_scan

.slot_found_existing:
    mov rax, rcx
    jmp .epilogue

.slot_done_scan:
    cmp rdx, -1
    je .slot_none

    mov rcx, rdx
    mov byte [rbx + rcx], 1
    mov [r12 + rcx*8], rdi
    mov qword [r13 + rcx*8], 0
    mov qword [r14 + rcx*8], 0
    mov rax, rcx
    jmp .epilogue

.slot_none:
    mov rax, -1

.epilogue:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; Read a single line from fd into buffer (stops at '\n' or EOF)
; Args: fd in rdi, buffer pointer in rsi
; Returns: bytes read in rax (including newline when present), updated buffer pointer in rsi
; Behavior:
;   - Newline is preserved in the destination buffer
;   - Buffer is always null-terminated
;   - Fixed buffer overflow truncates line, sets error, and drains remainder of the line
global _read_line_into_buffer
_read_line_into_buffer:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                 ; fd
    mov r13, rsi                 ; buffer
    xor r14, r14                 ; bytes read this call
    mov r15, [rsi + BUF_FLAGS]   ; buffer flags

    ; Acquire read-ahead slot. If unavailable, fall back to byte reads.
    mov rdi, r12
    call _get_readahead_slot
    cmp rax, -1
    je .line_loop_fallback

    ; Slot-backed mode setup
    mov rbx, rax
    lea r8, [rel ra_pos]              ; &ra_pos[slot]
    lea r8, [r8 + rbx*8]
    lea r9, [rel ra_filled]           ; &ra_filled[slot]
    lea r9, [r9 + rbx*8]

    mov rax, rbx
    imul rax, READAHEAD_BUF_SIZE
    lea r10, [rel ra_data]            ; slot data pointer
    lea r10, [r10 + rax]

.line_loop_slot:
    ; Ensure at least 1 byte of data capacity remains
    mov rax, [r13 + BUF_CAPACITY]
    sub rax, [r13 + BUF_LENGTH]
    cmp rax, 1
    jge .slot_have_space

    ; Need more space - grow if dynamic, otherwise truncate safely
    test r15, BUF_FLAG_FIXED
    jnz .fixed_overflow_slot

    mov rdi, r13
    mov rsi, [r13 + BUF_CAPACITY]
    shl rsi, 1
    cmp rsi, 1
    jge .slot_grow_ok
    mov rsi, 1
.slot_grow_ok:
    call _grow_buffer
    mov r13, rax

    ; _grow_buffer may clobber caller-saved registers; rebuild slot pointers.
    lea r8, [rel ra_pos]
    lea r8, [r8 + rbx*8]
    lea r9, [rel ra_filled]
    lea r9, [r9 + rbx*8]
    mov rax, rbx
    imul rax, READAHEAD_BUF_SIZE
    lea r10, [rel ra_data]
    lea r10, [r10 + rax]

    jmp .line_loop_slot

.slot_have_space:
    ; Ensure cached bytes are available; refill if exhausted.
    mov rax, [r8]
    cmp rax, [r9]
    jl .slot_consume_byte

    mov rax, 0                    ; SYS_READ
    mov rdi, r12
    mov rsi, r10
    mov rdx, READAHEAD_BUF_SIZE
    syscall

    cmp rax, 0
    je .line_done
    js .line_read_error

    mov qword [r8], 0
    mov [r9], rax

.slot_consume_byte:
    mov rcx, [r8]
    movzx edx, byte [r10 + rcx]
    inc rcx
    mov [r8], rcx

    cmp dl, 10                    ; '\n'
    jne .store_byte_slot

    ; Preserve newline in output.
    lea rcx, [r13 + BUF_DATA]
    add rcx, [r13 + BUF_LENGTH]
    mov byte [rcx], 10
    inc qword [r13 + BUF_LENGTH]
    inc r14
    jmp .line_done

.store_byte_slot:
    lea rcx, [r13 + BUF_DATA]
    add rcx, [r13 + BUF_LENGTH]
    mov [rcx], dl
    inc qword [r13 + BUF_LENGTH]
    inc r14
    jmp .line_loop_slot

.fixed_overflow_slot:
    ; Truncated line in fixed-size buffer: set overflow error and drain until newline/EOF
    mov qword [rel _last_error], 1

.drain_line_slot:
    ; Consume cached bytes first; refill when exhausted.
    mov rax, [r8]
    cmp rax, [r9]
    jl .drain_cached_byte_slot

    mov rax, 0                    ; SYS_READ
    mov rdi, r12
    mov rsi, r10
    mov rdx, READAHEAD_BUF_SIZE
    syscall

    cmp rax, 0
    je .line_done
    js .line_read_error

    mov qword [r8], 0
    mov [r9], rax
    jmp .drain_line_slot

.drain_cached_byte_slot:
    mov rcx, [r8]
    movzx edx, byte [r10 + rcx]
    inc rcx
    mov [r8], rcx
    cmp dl, 10
    jne .drain_line_slot
    jmp .line_done

.line_loop_fallback:
    ; Ensure at least 1 byte of data capacity remains
    mov rax, [r13 + BUF_CAPACITY]
    sub rax, [r13 + BUF_LENGTH]
    cmp rax, 1
    jge .do_read_byte_fallback

    ; Need more space - grow if dynamic, otherwise truncate safely
    test r15, BUF_FLAG_FIXED
    jnz .fixed_overflow_fallback

    mov rdi, r13
    mov rsi, [r13 + BUF_CAPACITY]
    shl rsi, 1
    cmp rsi, 1
    jge .grow_ok
    mov rsi, 1
.grow_ok:
    call _grow_buffer
    mov r13, rax
    jmp .line_loop_fallback

.do_read_byte_fallback:
    mov rax, 0                   ; SYS_READ
    mov rdi, r12
    lea rsi, [rel line_read_fallback_tmp]
    mov rdx, 1
    syscall

    ; rax == 0 => EOF, rax < 0 => read error
    cmp rax, 0
    je .line_done
    js .line_read_error

    movzx ebx, byte [rel line_read_fallback_tmp]
    cmp bl, 10                   ; '\n'
    jne .store_byte_fallback

    ; Preserve newline in output so line-based read/write can round-trip file content.
    ; Ensure one byte can be stored.
    mov rax, [r13 + BUF_CAPACITY]
    sub rax, [r13 + BUF_LENGTH]
    cmp rax, 1
    jl .fixed_overflow_fallback

    lea rcx, [r13 + BUF_DATA]
    add rcx, [r13 + BUF_LENGTH]
    mov byte [rcx], 10
    inc qword [r13 + BUF_LENGTH]
    inc r14
    jmp .line_done

.store_byte_fallback:
    ; Store non-newline byte
    lea rcx, [r13 + BUF_DATA]
    add rcx, [r13 + BUF_LENGTH]
    mov [rcx], bl
    inc qword [r13 + BUF_LENGTH]
    inc r14
    jmp .line_loop_fallback

.fixed_overflow_fallback:
    ; Truncated line in fixed-size buffer: set overflow error and drain until newline/EOF
    mov qword [rel _last_error], 1

.drain_line_fallback:
    mov rax, 0                   ; SYS_READ
    mov rdi, r12
    lea rsi, [rel line_read_fallback_tmp]
    mov rdx, 1
    syscall

    cmp rax, 0
    je .line_done
    js .line_read_error

    movzx ebx, byte [rel line_read_fallback_tmp]
    cmp bl, 10
    jne .drain_line_fallback
    jmp .line_done

.line_read_error:
    mov qword [rel _last_error], 2

.line_done:
    ; Always null-terminate
    lea rax, [r13 + BUF_DATA]
    add rax, [r13 + BUF_LENGTH]
    mov byte [rax], 0

    mov rax, r14
    mov rsi, r13

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; Seek fd to a 1-indexed byte position (byte 1 = file offset 0)
; Args: fd in rdi, byte position in rsi
; Returns: resulting offset in rax, or -1 on error
global _seek_fd_byte
_seek_fd_byte:
    push rbx

    ; Seek invalidates any cached read-ahead for this fd.
    call _flush_readahead_fd

    cmp rsi, 1
    jl .seek_byte_error

    dec rsi                      ; convert 1-indexed -> 0-indexed offset
    mov rax, 8                   ; SYS_LSEEK
    mov rdx, 0                   ; SEEK_SET
    syscall

    test rax, rax
    js .seek_byte_error

    pop rbx
    ret

.seek_byte_error:
    mov qword [rel _last_error], 2
    mov rax, -1
    pop rbx
    ret

; Seek fd to a 1-indexed line position (line 1 = start of file)
; Args: fd in rdi, line number in rsi
; Returns: resulting offset in rax, or -1 on error
global _seek_fd_line
_seek_fd_line:
    push rbx
    push rcx
    push rdx
    push r12
    push r13

    mov r12, rdi                 ; fd
    mov r13, rsi                 ; target line

    ; Seek invalidates any cached read-ahead for this fd.
    mov rdi, r12
    call _flush_readahead_fd

    cmp r13, 1
    jl .seek_line_error

    ; Rewind to start first
    mov rax, 8                   ; SYS_LSEEK
    mov rdi, r12
    xor rsi, rsi                 ; offset 0
    mov rdx, 0                   ; SEEK_SET
    syscall
    test rax, rax
    js .seek_line_error

    cmp r13, 1
    je .seek_line_done_offset    ; already at line 1

    ; Need to cross (target_line - 1) newlines.
    ; The counter must live somewhere the kernel will not touch: `syscall`
    ; overwrites rcx (and r11) with the return address, so a counter kept in
    ; rcx became a code address on the very first read - the compare below
    ; then failed immediately and the scan stopped at the first newline,
    ; landing every target of 2 or more on line 2 and never reaching EOF
    ; (bug #47). rbx is callee-saved, already pushed above, and otherwise
    ; free, so the counter lives there and the newline test reads the byte
    ; straight out of memory rather than borrowing a register for it.
    mov rbx, 1                   ; current line index

.seek_line_scan:
    mov rax, 0                   ; SYS_READ
    mov rdi, r12
    lea rsi, [rel line_read_tmp]
    mov rdx, 1
    syscall

    cmp rax, 0
    je .seek_line_error          ; hit EOF before requested line
    js .seek_line_error

    cmp byte [rel line_read_tmp], 10   ; newline?
    jne .seek_line_scan

    inc rbx
    cmp rbx, r13
    jl .seek_line_scan

.seek_line_done_offset:
    ; Query resulting file offset with lseek(fd, 0, SEEK_CUR)
    mov rax, 8                   ; SYS_LSEEK
    mov rdi, r12
    xor rsi, rsi
    mov rdx, 1                   ; SEEK_CUR
    syscall
    test rax, rax
    js .seek_line_error

    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

.seek_line_error:
    mov qword [rel _last_error], 2
    mov rax, -1
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret
