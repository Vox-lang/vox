; resource.asm - Runtime resource tracking for automatic cleanup
; Tracks file descriptors and buffers for safe cleanup on exit

; Maximum tracked resources
%define MAX_FDS 64
%define MAX_BUFFERS 64
%define READAHEAD_SLOTS 8
%define READAHEAD_BUF_SIZE 8192

; Buffer structure offsets
%define BUF_CAPACITY 0      ; 8 bytes: allocated size
%define BUF_LENGTH   8      ; 8 bytes: used length
%define BUF_FLAGS    16     ; 8 bytes: flags (bit 0 = fixed size)
%define BUF_DATA     24     ; data starts here

; Buffer flags
%define BUF_FLAG_FIXED 1    ; Buffer has fixed size, no growing allowed

; Initial buffer capacity
%define INITIAL_BUF_CAP 4096

section .bss
    ; File descriptor tracking table
    ; Each entry: 8 bytes (fd value, 0 = unused)
    fd_table: resq MAX_FDS
    fd_count: resq 1
    
    ; Buffer tracking table
    ; Each entry: 8 bytes (pointer to buffer struct, 0 = unused)
    buf_table: resq MAX_BUFFERS
    buf_count: resq 1
    
    ; Note: _last_error is defined in core.asm (always available)
    line_read_tmp: resb 1
    line_read_fallback_tmp: resb 1
    fmt_i64_buf: resb 128

    ; Read-ahead cache for line reading
    ; Slots are assigned per-fd on demand.
    ra_used: resb READAHEAD_SLOTS
    ra_fd: resq READAHEAD_SLOTS
    ra_pos: resq READAHEAD_SLOTS
    ra_filled: resq READAHEAD_SLOTS
    ra_data: resb READAHEAD_SLOTS * READAHEAD_BUF_SIZE

section .text

; Register a file descriptor for tracking
; Args: fd in rdi
; Clobbers: rax, rcx
global _register_fd
_register_fd:
    push rbx
    push rcx
    
    ; Find empty slot
    xor rcx, rcx
.find_slot:
    cmp rcx, MAX_FDS
    jge .table_full
    
    mov rax, [fd_table + rcx*8]
    test rax, rax
    jz .found_slot
    
    inc rcx
    jmp .find_slot
    
.found_slot:
    mov [fd_table + rcx*8], rdi
    inc qword [fd_count]
    
.table_full:
    pop rcx
    pop rbx
    ret

; Find or assign read-ahead slot for fd
; Args: fd in rdi
; Returns: slot index in rax, or -1 if no slot available
; Clobbers: rcx, rdx
_get_readahead_slot:
    xor rcx, rcx
    mov rdx, -1                 ; first free slot (or -1)

.slot_scan:
    cmp rcx, READAHEAD_SLOTS
    jge .slot_done_scan

    movzx eax, byte [ra_used + rcx]
    test eax, eax
    jz .slot_is_free

    mov rax, [ra_fd + rcx*8]
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
    ret

.slot_done_scan:
    cmp rdx, -1
    je .slot_none

    mov rcx, rdx
    mov byte [ra_used + rcx], 1
    mov [ra_fd + rcx*8], rdi
    mov qword [ra_pos + rcx*8], 0
    mov qword [ra_filled + rcx*8], 0
    mov rax, rcx
    ret

.slot_none:
    mov rax, -1
    ret

; Flush read-ahead state for a specific fd
; Args: fd in rdi
; Clobbers: rax, rcx
_flush_readahead_fd:
    xor rcx, rcx

.flush_scan:
    cmp rcx, READAHEAD_SLOTS
    jge .flush_done

    movzx eax, byte [ra_used + rcx]
    test eax, eax
    jz .flush_next

    mov rax, [ra_fd + rcx*8]
    cmp rax, rdi
    jne .flush_next

    mov byte [ra_used + rcx], 0
    mov qword [ra_fd + rcx*8], 0
    mov qword [ra_pos + rcx*8], 0
    mov qword [ra_filled + rcx*8], 0

.flush_next:
    inc rcx
    jmp .flush_scan

.flush_done:
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
    lea r8, [ra_pos + rbx*8]      ; &ra_pos[slot]
    lea r9, [ra_filled + rbx*8]   ; &ra_filled[slot]

    mov rax, rbx
    imul rax, READAHEAD_BUF_SIZE
    lea r10, [ra_data + rax]      ; slot data pointer

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
    lea r8, [ra_pos + rbx*8]
    lea r9, [ra_filled + rbx*8]
    mov rax, rbx
    imul rax, READAHEAD_BUF_SIZE
    lea r10, [ra_data + rax]

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

    ; Need to cross (target_line - 1) newlines
    mov rcx, 1                   ; current line index

.seek_line_scan:
    mov rax, 0                   ; SYS_READ
    mov rdi, r12
    lea rsi, [rel line_read_tmp]
    mov rdx, 1
    syscall

    cmp rax, 0
    je .seek_line_error          ; hit EOF before requested line
    js .seek_line_error

    movzx ebx, byte [rel line_read_tmp]
    cmp bl, 10                   ; newline?
    jne .seek_line_scan

    inc rcx
    cmp rcx, r13
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

; Unregister a file descriptor (on close)
; Args: fd in rdi
; Clobbers: rax, rcx
global _unregister_fd
_unregister_fd:
    push rbx
    push rcx

    ; Closing/unregistering an fd must drop cached read-ahead state.
    call _flush_readahead_fd
    
    xor rcx, rcx
.find_fd:
    cmp rcx, MAX_FDS
    jge .not_found
    
    mov rax, [fd_table + rcx*8]
    cmp rax, rdi
    je .found_fd
    
    inc rcx
    jmp .find_fd
    
.found_fd:
    mov qword [fd_table + rcx*8], 0
    dec qword [fd_count]
    
.not_found:
    pop rcx
    pop rbx
    ret

; Close all tracked file descriptors
; Called before program exit
global _cleanup_fds
_cleanup_fds:
    push rbx
    push r12            ; use callee-saved register for loop counter
    push r13
    
    xor r12, r12        ; r12 = loop counter
.close_loop:
    cmp r12, MAX_FDS
    jge .done
    
    mov rdi, [fd_table + r12*8]
    test rdi, rdi
    jz .next
    
    ; Don't close stdin/stdout/stderr
    cmp rdi, 3
    jl .next
    
    ; Close this fd
    mov rax, 3          ; SYS_CLOSE
    syscall
    
    mov qword [fd_table + r12*8], 0
    
.next:
    inc r12
    jmp .close_loop
    
.done:
    mov qword [fd_count], 0
    pop r13
    pop r12
    pop rbx
    ret

; Allocate a new dynamic buffer
; Returns: pointer to buffer struct in rax (or 0 on failure)
global _alloc_buffer
_alloc_buffer:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    
    ; Allocate: header (16 bytes) + initial capacity + 1 for null terminator
    mov rsi, INITIAL_BUF_CAP + BUF_DATA + 1
    
    ; mmap anonymous memory
    mov rax, 9              ; SYS_MMAP
    xor rdi, rdi            ; addr = NULL
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 34             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1              ; fd = -1
    xor r9, r9              ; offset = 0
    syscall
    
    ; Check for error
    cmp rax, -1
    je .failed
    
    ; Initialize buffer header (dynamic buffer)
    mov qword [rax + BUF_CAPACITY], INITIAL_BUF_CAP
    mov qword [rax + BUF_LENGTH], 0
    mov qword [rax + BUF_FLAGS], 0       ; dynamic (not fixed)
    
    ; Register buffer for tracking
    push rax
    mov rdi, rax
    call _register_buffer
    pop rax
    
    jmp .done
    
.failed:
    xor rax, rax
    
.done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Allocate a fixed-size buffer (no auto-grow, bounds checked)
; Args: size in rdi
; Returns: pointer to buffer struct in rax (or 0 on failure)
global _alloc_buffer_sized
_alloc_buffer_sized:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    
    mov r12, rdi            ; save requested size
    
    ; Allocate: header (24 bytes) + requested size + 1 for null terminator
    mov rsi, rdi
    add rsi, BUF_DATA + 1
    
    ; mmap anonymous memory
    mov rax, 9              ; SYS_MMAP
    xor rdi, rdi            ; addr = NULL
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 34             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1              ; fd = -1
    xor r9, r9              ; offset = 0
    syscall
    
    ; Check for error
    cmp rax, -1
    je .sized_failed
    
    ; Initialize buffer header (fixed size buffer)
    mov [rax + BUF_CAPACITY], r12
    mov qword [rax + BUF_LENGTH], 0
    mov qword [rax + BUF_FLAGS], BUF_FLAG_FIXED  ; fixed size, no growing
    
    ; Register buffer for tracking
    push rax
    mov rdi, rax
    call _register_buffer
    pop rax
    
    jmp .sized_done
    
.sized_failed:
    xor rax, rax
    
.sized_done:
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Register a buffer for tracking
; Args: buffer pointer in rdi
global _register_buffer
_register_buffer:
    push rbx
    push rcx
    
    xor rcx, rcx
.find_slot:
    cmp rcx, MAX_BUFFERS
    jge .table_full
    
    mov rax, [buf_table + rcx*8]
    test rax, rax
    jz .found_slot
    
    inc rcx
    jmp .find_slot
    
.found_slot:
    mov [buf_table + rcx*8], rdi
    inc qword [buf_count]
    
.table_full:
    pop rcx
    pop rbx
    ret

; Unregister a buffer from tracking (without freeing)
; Args: buffer pointer in rdi
global _unregister_buffer
_unregister_buffer:
    push rbx
    push rcx
    
    xor rcx, rcx
.find_unreg:
    cmp rcx, MAX_BUFFERS
    jge .not_found_unreg
    
    mov rax, [buf_table + rcx*8]
    cmp rax, rdi
    je .found_unreg
    
    inc rcx
    jmp .find_unreg
    
.found_unreg:
    mov qword [buf_table + rcx*8], 0
    dec qword [buf_count]
    
.not_found_unreg:
    pop rcx
    pop rbx
    ret

; Free a buffer and unregister it
; Args: buffer pointer in rdi
global _free_buffer
_free_buffer:
    push rbx
    push rcx
    push rsi
    
    ; Find and remove from table
    xor rcx, rcx
.find_buf:
    cmp rcx, MAX_BUFFERS
    jge .not_found
    
    mov rax, [buf_table + rcx*8]
    cmp rax, rdi
    je .found_buf
    
    inc rcx
    jmp .find_buf
    
.found_buf:
    mov qword [buf_table + rcx*8], 0
    dec qword [buf_count]
    
    ; munmap the buffer
    mov rsi, [rdi + BUF_CAPACITY]
    add rsi, BUF_DATA           ; total size
    mov rax, 11                 ; SYS_MUNMAP
    syscall
    
.not_found:
    pop rsi
    pop rcx
    pop rbx
    ret

; Free all tracked buffers
; Called before program exit
global _cleanup_buffers
_cleanup_buffers:
    push rbx
    push r12            ; use r12 for loop counter (preserved across syscall)
    push r13
    push r14
    
    xor r12, r12        ; r12 = loop counter
.free_loop:
    cmp r12, MAX_BUFFERS
    jge .done
    
    mov rdi, [buf_table + r12*8]
    test rdi, rdi
    jz .next
    
    ; Save buffer pointer before syscall clobbers registers
    mov r13, rdi
    
    ; Get size and munmap (+1 for null terminator)
    mov rsi, [rdi + BUF_CAPACITY]
    add rsi, BUF_DATA + 1
    mov rax, 11             ; SYS_MUNMAP
    syscall
    
    mov qword [buf_table + r12*8], 0
    
.next:
    inc r12
    jmp .free_loop
    
.done:
    mov qword [buf_count], 0
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Grow buffer to at least new_size
; Args: buffer pointer in rdi, required size in rsi
; Returns: new buffer pointer in rax (may be different!)
global _grow_buffer
_grow_buffer:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    
    mov r12, rdi            ; save old buffer
    mov r13, rsi            ; save required size
    
    ; Calculate new capacity (double until >= required)
    mov rax, [rdi + BUF_CAPACITY]
.double_loop:
    shl rax, 1              ; double it
    cmp rax, r13
    jl .double_loop
    
    ; Save new capacity in r14 (callee-saved, survives syscall)
    push r14
    mov r14, rax            ; new capacity
    
    ; Allocate new buffer (+1 for null terminator)
    add rax, BUF_DATA + 1   ; total allocation size
    mov rsi, rax
    mov rax, 9              ; SYS_MMAP
    xor rdi, rdi
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 34             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall
    
    cmp rax, -1
    je .failed_pop_r14
    
    mov rbx, rax            ; new buffer
    
    ; Initialize new header (use r14 which survived syscall)
    mov [rbx + BUF_CAPACITY], r14
    mov rax, [r12 + BUF_LENGTH]
    mov [rbx + BUF_LENGTH], rax
    
    ; Copy old data to new buffer
    mov rdi, rbx
    add rdi, BUF_DATA       ; dest
    mov rsi, r12
    add rsi, BUF_DATA       ; src
    mov rcx, [r12 + BUF_LENGTH]
    rep movsb
    
    ; Update buffer table entry
    xor rcx, rcx
.find_entry:
    cmp rcx, MAX_BUFFERS
    jge .no_entry
    mov rax, [buf_table + rcx*8]
    cmp rax, r12
    je .update_entry
    inc rcx
    jmp .find_entry
.update_entry:
    mov [buf_table + rcx*8], rbx
.no_entry:
    
    ; Free old buffer (+1 for null terminator)
    mov rdi, r12
    mov rsi, [r12 + BUF_CAPACITY]
    add rsi, BUF_DATA + 1
    mov rax, 11             ; SYS_MUNMAP
    syscall
    
    mov rax, rbx            ; return new buffer
    jmp .done
    
.failed_pop_r14:
    pop r14                 ; balance the push
.failed:
    mov rax, r12            ; return old buffer on failure
    jmp .done_no_pop_r14
    
.done:
    pop r14                 ; pop the r14 we pushed for capacity
.done_no_pop_r14:
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; Read from fd into buffer, growing as needed (or error if fixed)
; Args: fd in rdi, buffer pointer in rsi
; Returns: bytes read in rax, updated buffer pointer in rsi
;          Returns -1 in rax if fixed buffer overflow attempted
global _read_into_buffer
_read_into_buffer:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi            ; fd
    mov r13, rsi            ; buffer
    xor r14, r14            ; total bytes read
    mov r15, [rsi + BUF_FLAGS]  ; save buffer flags
    
.read_loop:
    ; Calculate available space
    mov rax, [r13 + BUF_CAPACITY]
    sub rax, [r13 + BUF_LENGTH]
    
    ; If less than 1KB available, need more space
    cmp rax, 1024
    jge .do_read
    
    ; Check if buffer is fixed size
    test r15, BUF_FLAG_FIXED
    jnz .check_remaining     ; fixed buffer, check if any space left
    
    ; Dynamic buffer - grow it
    mov rdi, r13
    mov rsi, [r13 + BUF_CAPACITY]
    shl rsi, 1              ; double capacity
    call _grow_buffer
    mov r13, rax            ; update buffer pointer
    jmp .do_read

.check_remaining:
    ; Fixed buffer with less than 1KB - only read what fits
    mov rax, [r13 + BUF_CAPACITY]
    sub rax, [r13 + BUF_LENGTH]
    cmp rax, 0
    jle .overflow_error     ; no space left, error
    
.do_read:
    ; Read into buffer at current position
    mov rax, 0              ; SYS_READ
    mov rdi, r12            ; fd
    mov rsi, r13
    add rsi, BUF_DATA
    add rsi, [r13 + BUF_LENGTH]  ; read position
    mov rdx, [r13 + BUF_CAPACITY]
    sub rdx, [r13 + BUF_LENGTH]  ; available space
    syscall
    
    ; Check result
    cmp rax, 0
    jle .done               ; EOF or error
    
    ; Update length
    add [r13 + BUF_LENGTH], rax
    add r14, rax
    
    ; If we filled the available space, there might be more
    mov rcx, [r13 + BUF_CAPACITY]
    sub rcx, [r13 + BUF_LENGTH]
    cmp rcx, 0
    jne .done               ; still have space, we're done
    
    ; Buffer full - check if fixed
    test r15, BUF_FLAG_FIXED
    jnz .fixed_full         ; fixed buffer full, stop reading (not error)
    jmp .read_loop          ; dynamic buffer, might have more data
    
.fixed_full:
    ; Fixed buffer is full - set error flag and stop reading
    mov qword [rel _last_error], 1  ; buffer overflow error
    jmp .done
    
.overflow_error:
    ; Fixed buffer has no space - set error and return 0 bytes read
    mov qword [rel _last_error], 1  ; buffer overflow error
    mov rax, 0              ; return 0 (no bytes read)
    mov rsi, r13            ; return buffer pointer unchanged
    jmp .exit
    
.done:
    ; Null-terminate
    mov rax, r13
    add rax, BUF_DATA
    add rax, [r13 + BUF_LENGTH]
    mov byte [rax], 0
    
    mov rax, r14            ; return total bytes read
    mov rsi, r13            ; return (possibly new) buffer pointer
    
.exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; Get data pointer from buffer
; Args: buffer pointer in rdi
; Returns: data pointer in rax
global _buffer_data
_buffer_data:
    lea rax, [rdi + BUF_DATA]
    ret

; Get buffer length
; Args: buffer pointer in rdi
; Returns: length in rax
global _buffer_length
_buffer_length:
    mov rax, [rdi + BUF_LENGTH]
    ret

; Append source buffer into destination buffer
; Args: destination buffer in rdi, source buffer in rsi
; Returns: destination buffer pointer in rax (may be reallocated)
global _buffer_append
_buffer_append:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                    ; destination buffer
    mov r13, rsi                    ; source buffer

    mov r14, [r12 + BUF_LENGTH]     ; destination length (original)
    mov r15, [r13 + BUF_LENGTH]     ; source length
    test r15, r15
    jz .append_done

    mov rax, r14
    add rax, r15                    ; required size

    test qword [r12 + BUF_FLAGS], BUF_FLAG_FIXED
    jnz .append_fixed

    cmp rax, [r12 + BUF_CAPACITY]
    jle .append_have_space

    mov rdi, r12
    mov rsi, rax
    call _grow_buffer
    test rax, rax
    jz .append_grow_failed
    mov r12, rax

.append_have_space:
    lea rdi, [r12 + BUF_DATA]
    add rdi, r14                    ; destination write pointer

    cmp r12, r13
    jne .append_copy_external

    ; Self-append: source starts at destination buffer start.
    lea rsi, [r12 + BUF_DATA]
    mov rcx, r15
    rep movsb
    jmp .append_finish_update

.append_copy_external:
    lea rsi, [r13 + BUF_DATA]
    mov rcx, r15
    rep movsb
    jmp .append_finish_update

.append_fixed:
    mov rdx, [r12 + BUF_CAPACITY]
    sub rdx, r14                    ; available space
    cmp rdx, 0
    jle .append_fixed_no_space

    cmp r15, rdx
    jle .append_fixed_fit

    ; Truncate append for fixed-size destination.
    mov qword [rel _last_error], 1
    mov r15, rdx

.append_fixed_fit:
    lea rdi, [r12 + BUF_DATA]
    add rdi, r14

    cmp r12, r13
    jne .append_fixed_external

    lea rsi, [r12 + BUF_DATA]
    mov rcx, r15
    rep movsb
    jmp .append_finish_update

.append_fixed_external:
    lea rsi, [r13 + BUF_DATA]
    mov rcx, r15
    rep movsb
    jmp .append_finish_update

.append_fixed_no_space:
    mov qword [rel _last_error], 1
    jmp .append_done

.append_finish_update:
    add r14, r15
    mov [r12 + BUF_LENGTH], r14
    lea rax, [r12 + BUF_DATA]
    add rax, r14
    mov byte [rax], 0

.append_done:
    mov rax, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

.append_grow_failed:
    mov qword [rel _last_error], 1
    jmp .append_done

; Append raw bytes into destination buffer
; Args: destination buffer in rdi, source ptr in rsi, source length in rdx
; Returns: destination buffer pointer in rax (may be reallocated)
global _buffer_append_bytes
_buffer_append_bytes:
    push rbx
    push rcx
    push r8
    push r9
    push r12
    push r13
    push r14

    mov r12, rdi                    ; destination buffer
    mov r13, rsi                    ; source bytes pointer
    mov r14, rdx                    ; source length

    test r14, r14
    jz .append_bytes_done

    mov r8, [r12 + BUF_LENGTH]      ; destination length
    mov rax, r8
    add rax, r14                    ; required size

    test qword [r12 + BUF_FLAGS], BUF_FLAG_FIXED
    jnz .append_bytes_fixed

    cmp rax, [r12 + BUF_CAPACITY]
    jle .append_bytes_have_space

    mov rdi, r12
    mov rsi, rax
    call _grow_buffer
    test rax, rax
    jz .append_bytes_grow_failed
    mov r12, rax

.append_bytes_have_space:
    lea rdi, [r12 + BUF_DATA]
    add rdi, r8
    mov rsi, r13
    mov rcx, r14
    rep movsb
    jmp .append_bytes_finish

.append_bytes_fixed:
    mov r9, [r12 + BUF_CAPACITY]
    sub r9, r8
    cmp r9, 0
    jle .append_bytes_no_space

    cmp r14, r9
    jle .append_bytes_fixed_fit

    mov qword [rel _last_error], 1
    mov r14, r9

.append_bytes_fixed_fit:
    lea rdi, [r12 + BUF_DATA]
    add rdi, r8
    mov rsi, r13
    mov rcx, r14
    rep movsb
    jmp .append_bytes_finish

.append_bytes_no_space:
    mov qword [rel _last_error], 1
    jmp .append_bytes_done

.append_bytes_finish:
    add r8, r14
    mov [r12 + BUF_LENGTH], r8
    lea rax, [r12 + BUF_DATA]
    add rax, r8
    mov byte [rax], 0

.append_bytes_done:
    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop r9
    pop r8
    pop rcx
    pop rbx
    ret

.append_bytes_grow_failed:
    mov qword [rel _last_error], 1
    jmp .append_bytes_done

; Append null-terminated C-string into destination buffer
; Args: destination buffer in rdi, source C-string ptr in rsi
; Returns: destination buffer pointer in rax
global _buffer_append_cstr
_buffer_append_cstr:
    push rcx
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi
    xor rcx, rcx

.append_cstr_len:
    cmp byte [r13 + rcx], 0
    je .append_cstr_have_len
    inc rcx
    jmp .append_cstr_len

.append_cstr_have_len:
    mov rdi, r12
    mov rsi, r13
    mov rdx, rcx
    call _buffer_append_bytes

    pop r13
    pop r12
    pop rcx
    ret

; Append formatted integer into destination buffer
; Args:
;   rdi = destination buffer
;   rsi = value (i64)
;   rdx = width (0 means no minimum width)
;   rcx = zero_pad flag (0/1)
;   r8  = base (0=decimal, 1=hex, 2=binary, 3=octal)
;   r9  = uppercase (hex only, 0/1)
; Returns: destination buffer pointer in rax
global _buffer_append_formatted_int
_buffer_append_formatted_int:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                    ; destination buffer
    mov r13, rsi                    ; value
    mov r14, rdx                    ; width
    mov r15, rcx                    ; zero_pad flag
    mov r10, r8                     ; base selector
    mov r11, r9                     ; uppercase flag

    lea rbp, [rel fmt_i64_buf]
    lea r8, [rel fmt_i64_buf + 127] ; write pointer (backwards)
    xor r9, r9                      ; digits length
    xor rbx, rbx                    ; sign flag for decimal

    cmp r10, 0
    jne .fmt_non_decimal

.fmt_decimal:

    ; Decimal conversion (signed)
    mov rax, r13
    test rax, rax
    jns .fmt_dec_positive
    neg rax
    mov bl, 1

.fmt_dec_positive:
    test rax, rax
    jnz .fmt_dec_loop
    dec r8
    mov byte [r8], '0'
    inc r9
    jmp .fmt_dec_done

.fmt_dec_loop:
    xor rdx, rdx
    mov rcx, 10
    div rcx
    add dl, '0'
    dec r8
    mov [r8], dl
    inc r9
    test rax, rax
    jnz .fmt_dec_loop

.fmt_dec_done:
    test bl, bl
    jz .fmt_digits_ready
    dec r8
    mov byte [r8], '-'
    inc r9
    jmp .fmt_digits_ready

.fmt_non_decimal:
    mov rax, r13
    cmp r10, 1
    je .fmt_hex_loop_entry
    cmp r10, 2
    je .fmt_binary_loop_entry
    cmp r10, 3
    je .fmt_octal_loop_entry
    jmp .fmt_decimal

.fmt_hex_loop_entry:
    test rax, rax
    jnz .fmt_hex_loop
    dec r8
    mov byte [r8], '0'
    inc r9
    jmp .fmt_digits_ready

.fmt_hex_loop:
    mov rdx, rax
    and rdx, 0xF
    cmp dl, 9
    jle .fmt_hex_digit_num
    test r11, r11
    jz .fmt_hex_digit_lower
    add dl, 'A' - 10
    jmp .fmt_hex_store

.fmt_hex_digit_lower:
    add dl, 'a' - 10
    jmp .fmt_hex_store

.fmt_hex_digit_num:
    add dl, '0'

.fmt_hex_store:
    dec r8
    mov [r8], dl
    inc r9
    shr rax, 4
    test rax, rax
    jnz .fmt_hex_loop
    jmp .fmt_digits_ready

.fmt_binary_loop_entry:
    test rax, rax
    jnz .fmt_binary_loop
    dec r8
    mov byte [r8], '0'
    inc r9
    jmp .fmt_digits_ready

.fmt_binary_loop:
    mov rdx, rax
    and rdx, 1
    add dl, '0'
    dec r8
    mov [r8], dl
    inc r9
    shr rax, 1
    test rax, rax
    jnz .fmt_binary_loop
    jmp .fmt_digits_ready

.fmt_octal_loop_entry:
    test rax, rax
    jnz .fmt_octal_loop
    dec r8
    mov byte [r8], '0'
    inc r9
    jmp .fmt_digits_ready

.fmt_octal_loop:
    mov rdx, rax
    and rdx, 7
    add dl, '0'
    dec r8
    mov [r8], dl
    inc r9
    shr rax, 3
    test rax, rax
    jnz .fmt_octal_loop

.fmt_digits_ready:
    ; Left pad to width (if needed)
    mov rax, r14
    sub rax, r9
    jle .fmt_append_digits

    mov byte [rbp], ' '
    test r15, r15
    jz .fmt_pad_loop
    mov byte [rbp], '0'

.fmt_pad_loop:
    test rax, rax
    jz .fmt_append_digits
    push rax
    mov rdi, r12
    lea rsi, [rbp]
    mov rdx, 1
    call _buffer_append_bytes
    mov r12, rax
    pop rax
    dec rax
    jmp .fmt_pad_loop

.fmt_append_digits:
    mov rdi, r12
    mov rsi, r8
    mov rdx, r9
    call _buffer_append_bytes

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Copy source buffer into destination buffer (clobber destination contents)
; Args: destination buffer in rdi, source buffer in rsi
; Returns: destination buffer pointer in rax (may be reallocated)
global _buffer_copy
_buffer_copy:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14

    mov r12, rdi                    ; destination buffer
    mov r13, rsi                    ; source buffer
    mov r14, [r13 + BUF_LENGTH]     ; source length

    test qword [r12 + BUF_FLAGS], BUF_FLAG_FIXED
    jnz .copy_fixed

    cmp r14, [r12 + BUF_CAPACITY]
    jle .copy_have_space

    mov rdi, r12
    mov rsi, r14
    call _grow_buffer
    test rax, rax
    jz .copy_grow_failed
    mov r12, rax

.copy_have_space:
    lea rdi, [r12 + BUF_DATA]
    lea rsi, [r13 + BUF_DATA]
    mov rcx, r14
    rep movsb
    jmp .copy_set_length

.copy_fixed:
    mov rcx, [r12 + BUF_CAPACITY]
    cmp r14, rcx
    jle .copy_fixed_fit

    ; Truncate copy for fixed-size destination.
    mov qword [rel _last_error], 1
    mov r14, rcx

.copy_fixed_fit:
    lea rdi, [r12 + BUF_DATA]
    lea rsi, [r13 + BUF_DATA]
    mov rcx, r14
    rep movsb

.copy_set_length:
    mov [r12 + BUF_LENGTH], r14
    lea rax, [r12 + BUF_DATA]
    add rax, r14
    mov byte [rax], 0

    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

.copy_grow_failed:
    mov qword [rel _last_error], 1
    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; Clear buffer contents
; Args: buffer pointer in rdi
; Returns: same buffer pointer in rax
global _buffer_clear
_buffer_clear:
    mov qword [rdi + BUF_LENGTH], 0
    mov byte [rdi + BUF_DATA], 0
    mov rax, rdi
    ret

; Reallocate buffer to new size
; Args: buffer pointer in rdi, new size in rsi
; Returns: new buffer pointer in rax
; Note: For fixed buffers, this changes capacity. Data is preserved up to min(old_len, new_size)
global _realloc_buffer
_realloc_buffer:
    push rbx
    push r12
    push r13
    push r14
    
    mov r12, rdi            ; old buffer pointer
    mov r13, rsi            ; new size
    
    ; Get old length (to preserve data)
    mov r14, [r12 + BUF_LENGTH]
    
    ; Allocate new buffer with new size
    mov rdi, r13
    call _alloc_buffer_sized
    mov rbx, rax            ; new buffer pointer
    
    ; Calculate bytes to copy: min(old_length, new_capacity)
    mov rcx, r14            ; old length
    cmp rcx, r13
    jle .copy_size_ok
    mov rcx, r13            ; use new size if smaller
.copy_size_ok:
    
    ; Copy data from old buffer to new buffer
    test rcx, rcx
    jz .skip_copy
    
    lea rsi, [r12 + BUF_DATA]   ; source: old buffer data
    lea rdi, [rbx + BUF_DATA]   ; dest: new buffer data
    ; Copy rcx bytes
.copy_loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .copy_loop
    
.skip_copy:
    ; Set new buffer length to copied amount
    mov rcx, r14
    cmp rcx, r13
    jle .set_len
    mov rcx, r13
.set_len:
    mov [rbx + BUF_LENGTH], rcx
    
    ; Free old buffer (unregister from tracking)
    mov rdi, r12
    call _unregister_buffer
    
    ; Free old buffer memory
    mov rax, 11             ; sys_munmap
    mov rdi, r12
    mov rsi, [r12 + BUF_CAPACITY]
    add rsi, BUF_DATA       ; total size including header
    syscall
    
    ; Return new buffer pointer
    mov rax, rbx
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Print last error to stderr (for auto error catching)
; No args, uses _last_error global
global _print_last_error
_print_last_error:
    push rbx
    
    mov rax, [rel _last_error]
    cmp rax, 1
    je .buffer_overflow
    cmp rax, 2
    je .file_error
    jmp .done
    
.buffer_overflow:
    ; Write "Error: Buffer overflow\n" to stderr
    mov rax, 1              ; sys_write
    mov rdi, 2              ; stderr
    lea rsi, [rel .err_buf_overflow]
    mov rdx, 23             ; length including newline
    syscall
    jmp .done
    
.file_error:
    ; Write "Error: File operation failed\n" to stderr
    mov rax, 1              ; sys_write
    mov rdi, 2              ; stderr
    lea rsi, [rel .err_file]
    mov rdx, 29             ; length
    syscall
    jmp .done
    
.done:
    pop rbx
    ret

section .rodata
.err_buf_overflow: db "Error: Buffer overflow", 10
.err_file: db "Error: File operation failed", 10

section .text

; Cleanup all resources - call before exit
global _cleanup_all
_cleanup_all:
    call _cleanup_fds
    call _cleanup_buffers
    ret

; ============================================================================
; File property functions using fstat syscall
; stat struct offsets (x86_64 Linux):
;   st_dev     = 0   (8 bytes)
;   st_ino     = 8   (8 bytes)
;   st_nlink   = 16  (8 bytes)
;   st_mode    = 24  (4 bytes) - permissions
;   st_uid     = 28  (4 bytes)
;   st_gid     = 32  (4 bytes)
;   pad        = 36  (4 bytes)
;   st_rdev    = 40  (8 bytes)
;   st_size    = 48  (8 bytes) - file size
;   st_blksize = 56  (8 bytes)
;   st_blocks  = 64  (8 bytes)
;   st_atime   = 72  (8 bytes) - access time
;   st_atime_n = 80  (8 bytes)
;   st_mtime   = 88  (8 bytes) - modify time
;   st_mtime_n = 96  (8 bytes)
;   st_ctime   = 104 (8 bytes)
;   st_ctime_n = 112 (8 bytes)
; Total size: 144 bytes
; ============================================================================

section .bss
    stat_buf: resb 144   ; Buffer for fstat result

section .text

; Get file size from fd
; Args: fd in rdi
; Returns: size in rax (or -1 on error)
global _file_size
_file_size:
    push rbx
    
    ; fstat(fd, stat_buf)
    mov rax, 5              ; sys_fstat
    lea rsi, [rel stat_buf]
    syscall
    
    test rax, rax
    js .error
    
    ; Return st_size (offset 48)
    lea rax, [rel stat_buf]
    mov rax, [rax + 48]
    pop rbx
    ret
    
.error:
    mov rax, -1
    pop rbx
    ret

; Get file modified time (mtime) from fd
; Args: fd in rdi
; Returns: mtime in rax (unix timestamp, or -1 on error)
global _file_modified
_file_modified:
    push rbx
    
    mov rax, 5              ; sys_fstat
    lea rsi, [rel stat_buf]
    syscall
    
    test rax, rax
    js .error
    
    ; Return st_mtime (offset 88)
    lea rax, [rel stat_buf]
    mov rax, [rax + 88]
    pop rbx
    ret
    
.error:
    mov rax, -1
    pop rbx
    ret

; Get file access time (atime) from fd
; Args: fd in rdi
; Returns: atime in rax (unix timestamp, or -1 on error)
global _file_accessed
_file_accessed:
    push rbx
    
    mov rax, 5              ; sys_fstat
    lea rsi, [rel stat_buf]
    syscall
    
    test rax, rax
    js .error
    
    ; Return st_atime (offset 72)
    lea rax, [rel stat_buf]
    mov rax, [rax + 72]
    pop rbx
    ret
    
.error:
    mov rax, -1
    pop rbx
    ret

; Get file permissions from fd
; Args: fd in rdi
; Returns: mode bits in rax (or -1 on error)
global _file_permissions
_file_permissions:
    push rbx
    
    mov rax, 5              ; sys_fstat
    lea rsi, [rel stat_buf]
    syscall
    
    test rax, rax
    js .error
    
    ; Return st_mode (offset 24, 4 bytes) masked to just permission bits
    lea rax, [rel stat_buf]
    movzx eax, word [rax + 24]
    and eax, 0o7777         ; Keep only permission bits
    pop rbx
    ret
    
.error:
    mov rax, -1
    pop rbx
    ret
