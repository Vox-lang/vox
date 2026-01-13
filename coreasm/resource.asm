; resource.asm - Runtime resource tracking for automatic cleanup
; Tracks file descriptors and buffers for safe cleanup on exit

; Maximum tracked resources
%define MAX_FDS 64
%define MAX_BUFFERS 64

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

; Unregister a file descriptor (on close)
; Args: fd in rdi
; Clobbers: rax, rcx
global _unregister_fd
_unregister_fd:
    push rbx
    push rcx
    
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
