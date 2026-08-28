; resource_buffer.asm - Dynamic buffer lifecycle + accessors
; Split from resource.asm (audit rec 1). Allocation, registration,
; growth, read-into-buffer, append/copy/clear, and the formatted-int
; append live here. The buffer-structure offsets (BUF_*) and the mremap
; growth constants are owned here because _read_line_into_buffer (the
; read-ahead module) also reads them - that module is included after this
; one, so the %defines are visible at its assembly point.
;
; Co-included with resource_fd.asm whenever the resource runtime is
; present: _read_into_buffer reads the fd seekability cache, and
; _cleanup_all (fd) calls _cleanup_buffers. The two share the
; (uses_buffers || uses_files || uses_floats) gate.
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
; mremap syscall + flag for the no-copy growth path. Defined locally here
; (not imported from file.asm) because resource.asm is included for
; buffer-only programs where file.asm is absent - see the codegen include
; gating (uses_buffers || uses_files || uses_floats vs uses_files only).
%define SYS_MREMAP     25
%define MREMAP_MAYMOVE 1

section .bss
    ; Buffer tracking table
    ; Each entry: 8 bytes (pointer to buffer struct, 0 = unused)
    buf_table: resq MAX_BUFFERS
    buf_count: resq 1
    ; Scratch buffer for _buffer_append_formatted_int (backwards decimal conversion)
    fmt_i64_buf: resb 128

section .text
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
    
    ; Check for error (raw mmap returns -errno in [-4095,-1])
    cmp rax, -4096
    ja .failed
    
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
    
    ; Check for error (raw mmap returns -errno in [-4095,-1])
    cmp rax, -4096
    ja .sized_failed
    
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

    lea rbx, [rel buf_table]
    xor rcx, rcx
.find_slot:
    cmp rcx, MAX_BUFFERS
    jge .table_full

    mov rax, [rbx + rcx*8]
    test rax, rax
    jz .found_slot

    inc rcx
    jmp .find_slot

.found_slot:
    mov [rbx + rcx*8], rdi
    inc qword [rel buf_count]

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

    lea rbx, [rel buf_table]
    xor rcx, rcx
.find_unreg:
    cmp rcx, MAX_BUFFERS
    jge .not_found_unreg

    mov rax, [rbx + rcx*8]
    cmp rax, rdi
    je .found_unreg

    inc rcx
    jmp .find_unreg

.found_unreg:
    mov qword [rbx + rcx*8], 0
    dec qword [rel buf_count]
    
.not_found_unreg:
    pop rcx
    pop rbx
    ret

; Free a buffer and unregister it.
; Args: buffer pointer in rdi
;
; Always munmaps, whether or not the buffer is currently in buf_table - a
; buffer allocated past MAX_BUFFERS live ones is never registered
; (_register_buffer's .table_full silently skips it), so gating the munmap
; on table presence left every such buffer mapped forever
; (docs/BUGS_FOUND.md #108). Unregistering FIRST when it is found still
; keeps the exit sweep (_cleanup_buffers) from touching this struct again.
global _free_buffer
_free_buffer:
    push rbx
    push rcx
    push rsi

    lea rbx, [rel buf_table]
    ; Find and remove from table, if tracked
    xor rcx, rcx
.find_buf:
    cmp rcx, MAX_BUFFERS
    jge .munmap_buf

    mov rax, [rbx + rcx*8]
    cmp rax, rdi
    je .found_buf

    inc rcx
    jmp .find_buf

.found_buf:
    mov qword [rbx + rcx*8], 0
    dec qword [rel buf_count]

.munmap_buf:
    mov rsi, [rdi + BUF_CAPACITY]
    add rsi, BUF_DATA           ; total size
    mov rax, 11                 ; SYS_MUNMAP
    syscall

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

    lea rbx, [rel buf_table]
    xor r12, r12        ; r12 = loop counter
.free_loop:
    cmp r12, MAX_BUFFERS
    jge .done

    mov rdi, [rbx + r12*8]
    test rdi, rdi
    jz .next

    ; Save buffer pointer before syscall clobbers registers
    mov r13, rdi

    ; Get size and munmap (+1 for null terminator). rbx (table base) and
    ; r12 (index) both survive the syscall: only rax/rcx/r11 are clobbered.
    mov rsi, [rdi + BUF_CAPACITY]
    add rsi, BUF_DATA + 1
    mov rax, 11             ; SYS_MUNMAP
    syscall

    mov qword [rbx + r12*8], 0

.next:
    inc r12
    jmp .free_loop
    
.done:
    mov qword [rel buf_count], 0
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Reallocate a buffer to an EXACT new capacity (no doubling).
; Args: rdi = buffer pointer, rsi = exact new capacity (must be >= BUF_LENGTH)
; Returns: new buffer pointer in rax (the OLD pointer on mmap failure, with
;          _last_error set to 1). The buffer may move.
; Copies the existing BUF_LENGTH bytes, updates the buffer-table entry to the
; new pointer, and frees the old allocation. The flags field is not copied: the
; new region is freshly mmapped (zeroed), so it is a dynamic buffer (flags 0),
; matching what _grow_buffer always produced.
global _reallocate_buffer
_reallocate_buffer:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    mov r12, rdi            ; old buffer
    mov r14, rsi            ; new (exact) capacity

    ; --- Try mremap first when growing: remap the existing mapping in place
    ; (or move it), avoiding the rep movsb copy and the old-buffer munmap.
    ; Falls back to the original mmap + copy + munmap path on any mremap
    ; error (e.g. ENOMEM) or when shrinking.
    mov rax, [r12 + BUF_CAPACITY]   ; old_capacity
    cmp r14, rax
    jle .mmap_alloc             ; not growing -> mmap path

    mov rsi, rax
    add rsi, BUF_DATA + 1           ; old_total_size
    mov rdx, r14
    add rdx, BUF_DATA + 1           ; new_total_size
    mov rdi, r12                    ; old_addr
    mov r10, MREMAP_MAYMOVE         ; flags
    mov rax, SYS_MREMAP             ; 25
    syscall
    cmp rax, -4096
    ja .mmap_alloc                  ; mremap failed -> mmap path

    ; mremap succeeded: rax = (possibly moved) buffer pointer. The existing
    ; header bytes - including BUF_LENGTH and BUF_FLAGS - move with the
    ; mapping, so only BUF_CAPACITY needs updating.
    mov rbx, rax
    mov [rbx + BUF_CAPACITY], r14
    ; The old mapping was consumed by mremap - do NOT munmap it. Update
    ; buf_table only if the pointer actually moved.
    cmp rbx, r12
    je .mremap_done
    lea r11, [rel buf_table]
    xor rcx, rcx
.mremap_find_entry:
    cmp rcx, MAX_BUFFERS
    jge .mremap_no_entry
    mov rax, [r11 + rcx*8]
    cmp rax, r12
    je .mremap_update_entry
    inc rcx
    jmp .mremap_find_entry
.mremap_update_entry:
    mov [r11 + rcx*8], rbx
.mremap_no_entry:
.mremap_done:
    mov rax, rbx            ; return new buffer
    jmp .done

.mmap_alloc:
    ; Allocate new buffer (+ header + 1 for null terminator)
    mov rax, 9              ; SYS_MMAP
    mov rsi, r14
    add rsi, BUF_DATA + 1   ; total allocation size
    xor rdi, rdi
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 34             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall

    ; Check for error (raw mmap returns -errno in [-4095,-1])
    cmp rax, -4096
    ja .failed

    mov rbx, rax            ; new buffer

    ; Initialize new header (r14 survived the syscall)
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

    ; Update buffer table entry. No syscall between the lea and the uses
    ; below, so a caller-saved scratch (r11) holds the base safely.
    lea r11, [rel buf_table]
    xor rcx, rcx
.find_entry:
    cmp rcx, MAX_BUFFERS
    jge .no_entry
    mov rax, [r11 + rcx*8]
    cmp rax, r12
    je .update_entry
    inc rcx
    jmp .find_entry
.update_entry:
    mov [r11 + rcx*8], rbx
.no_entry:

    ; Free old buffer (+1 for null terminator)
    mov rdi, r12
    mov rsi, [r12 + BUF_CAPACITY]
    add rsi, BUF_DATA + 1
    mov rax, 11             ; SYS_MUNMAP
    syscall

    mov rax, rbx            ; return new buffer
    jmp .done

.failed:
    mov qword [rel _last_error], 1
    mov rax, r12            ; return old buffer on failure

.done:
    pop r14
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

; Grow buffer to at least new_size (doubles current capacity until >= required,
; then delegates to _reallocate_buffer for the exact-sized move).
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
    ; A capacity of 0 never doubles (0 << 1 == 0) and would spin here
    ; forever - e.g. a dynamic buffer resized down to 0. Floor it at 1
    ; so the loop terminates and yields a capacity > 0 instead of
    ; looping or being left at 0 (which would SIGSEGV on the copy).
    test rax, rax
    jnz .cap_floor_ok
    mov rax, 1
.cap_floor_ok:
.double_loop:
    shl rax, 1              ; double it
    cmp rax, r13
    jl .double_loop

    ; rax = new capacity (>= required). Delegate the move to the exact
    ; reallocator. r14 is not used here, so it is preserved across this
    ; function (the call's callee preserves it too).
    mov rsi, rax            ; new capacity
    mov rdi, r12            ; old buffer
    call _reallocate_buffer
    ; rax = new buffer (or old on failure, _last_error already set)

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
    xor ebx, ebx            ; initial fd offset (used only for fixed regular files)

    ; --- B3: pre-size reads from regular files (dynamic buffers only) ---
    ; When the destination is an empty dynamic buffer and the fd is a regular
    ; file, fstat once and grow directly to st_size + 1 before the first read.
    ; This avoids the log2(N/4096) mmap/munmap/copy cycles (and the ~2N bytes
    ; of copying) the doubling path incurs for a file slurp. Every other case
    ; - fixed buffers, non-empty buffers, pipes, sockets, /proc files, empty
    ; files, fstat failure, a file that grows after fstat - falls through to
    ; the existing doubling loop unchanged.
    test r15, BUF_FLAG_FIXED
    jnz .after_presize            ; fixed: keep exact capacity + overflow semantics
    cmp qword [r13 + BUF_LENGTH], 0
    jne .after_presize            ; non-empty: preserve append semantics. (Read
                                  ; from itself resets length to 0 first, but a
                                  ; direct caller may pass a populated buffer.)

    ; fstat the fd into a stack-local struct stat (144 bytes on x86-64). On
    ; any failure or non-regular/zero-size file, restore the stack and fall
    ; back to the doubling loop without touching _last_error - the first
    ; read(2) will surface the proper file error if there is one.
    sub rsp, 144
    mov rax, SYS_FSTAT
    mov rdi, r12                  ; fd
    mov rsi, rsp
    syscall
    test rax, rax
    jnz .presize_restore          ; fstat failed - fall back, no error

    mov rax, [rsp + STAT_MODE_OFFSET]
    and rax, S_IFMT
    cmp rax, S_IFREG
    jne .presize_restore          ; not a regular file - fall back
    mov rax, [rsp + STAT_SIZE_OFFSET]
    test rax, rax
    jz .presize_restore           ; st_size == 0 - fall back

    ; target_capacity = st_size + 1 (the +1 is for the null terminator the
    ; .done path writes). Use a caller-saved scratch (rax): r14 holds the
    ; running byte counter and must not be clobbered here.
    lea rax, [rax + 1]
    cmp rax, [r13 + BUF_CAPACITY]
    jbe .presize_restore          ; already big enough - skip pre-sizing

    ; Grow to exactly target_capacity (no doubling overshoot) so a regular
    ; file slurp allocates one buffer and copies zero bytes. On mmap failure
    ; _reallocate_buffer returns the old pointer and sets _last_error; keep
    ; that pointer and continue to the loop so the first read can still
    ; proceed with whatever capacity exists.
    mov rsi, rax                  ; exact new capacity
    mov rdi, r13                  ; buffer
    call _reallocate_buffer
    mov r13, rax                  ; update buffer pointer (old ptr on failure)

.presize_restore:
    add rsp, 144

.after_presize:

    ; --- B4: seekability setup for fixed buffers ---
    ; For a regular file, record the current offset once with
    ; lseek(fd, 0, SEEK_CUR) so a later exact-fill read can decide overflow
    ; vs exact-fit from the cached st_size, without a one-byte probe that
    ; would consume (and lose) a byte on unseekable fds. Dynamic buffers
    ; skip this entirely.
    test r15, BUF_FLAG_FIXED
    jz .read_loop

    ; Look up the fd's cached st_mode (set by _register_fd's fstat). An
    ; untracked fd, or anything that is not a regular file, has no offset to
    ; record - it is handled as an exact fit at fill time.
    xor rcx, rcx
    lea rdx, [rel fd_table]
.entry_scan:
    cmp rcx, MAX_FDS
    jge .read_loop
    mov rax, [rdx + rcx*8]
    cmp rax, r12
    je .entry_found
    inc rcx
    jmp .entry_scan
.entry_found:
    lea rdx, [rel fd_mode_table]
    mov eax, [rdx + rcx*4]          ; cached st_mode (dword, zero-extended)
    and rax, S_IFMT
    cmp rax, S_IFREG
    jne .read_loop                  ; not a regular file -> nothing to record
    mov rax, SYS_LSEEK
    mov rdi, r12
    xor rsi, rsi
    mov rdx, SEEK_CUR
    syscall
    test rax, rax
    js .read_loop                   ; lseek failed (should not for a regular file)
    mov rbx, rax                    ; initial_position, reused at exact-fill

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
    jl .read_error          ; negative = syscall error
    je .done                ; EOF, success

    ; Update length
    add [r13 + BUF_LENGTH], rax
    add r14, rax

    ; If we filled the available space, there might be more
    mov rcx, [r13 + BUF_CAPACITY]
    sub rcx, [r13 + BUF_LENGTH]
    cmp rcx, 0
    jne .done               ; still have space, we're done

    ; Buffer full after a successful read. Dynamic buffers loop to read any
    ; remaining data. Fixed buffers decide overflow vs exact-fit from the
    ; cached stat metadata (track B4): a regular file with bytes still ahead
    ; is genuine overflow; everything else (pipe, socket, character device,
    ; untracked fd, or a size-0 snapshot) is an exact fit. This replaces the
    ; old one-byte read+lseek probe, which consumed a byte that lseek could
    ; not put back on unseekable fds, silently losing data (issue #8).
    test r15, BUF_FLAG_FIXED
    jz .read_loop            ; dynamic buffer, might have more data

    ; Look up the fd's cached st_mode/st_size (set by _register_fd's fstat).
    xor rcx, rcx
    lea rdx, [rel fd_table]
.fill_scan:
    cmp rcx, MAX_FDS
    jge .exact_fit_success       ; fd untracked -> unknown -> treat as success
    mov rax, [rdx + rcx*8]
    cmp rax, r12
    je .fill_found
    inc rcx
    jmp .fill_scan
.fill_found:
    lea rax, [rel fd_mode_table]
    mov r8d, [rax + rcx*4]        ; cached st_mode
    lea rax, [rel fd_size_table]
    mov r9, [rax + rcx*8]         ; cached st_size
    ; Only a regular file with a non-zero cached size can be queried for
    ; "more data ahead". Anything else is an exact fit (no probe, no loss).
    mov r10, r8
    and r10, S_IFMT
    cmp r10, S_IFREG
    jne .exact_fit_success
    test r9, r9
    jz .exact_fit_success
    ; current_position = initial_offset (rbx) + bytes read this call (r14)
    mov rax, rbx
    add rax, r14
    cmp rax, r9
    jb .exact_fill_overflow       ; current_position < st_size -> more data -> overflow
    ; current_position >= st_size -> no more data -> exact fit, no error
.exact_fit_success:
    jmp .done

.exact_fill_overflow:
    mov qword [rel _last_error], 1  ; buffer overflow - data was truncated
    jmp .done

.read_error:
    ; Read syscall failed - set error so On error handlers fire.
    mov qword [rel _last_error], 2  ; file operation error
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
    ; Hex and octal get the same "0x"/"0o" prefix Print emits: prefix
    ; first, then padding, then digits, with width counting the digits
    ; only - exactly mirroring the print-side formatters. Runs before
    ; any _buffer_append_bytes call can clobber r10 (the base selector).
    cmp r10, 1
    je .fmt_prefix_hex
    cmp r10, 3
    je .fmt_prefix_octal
    jmp .fmt_no_prefix

.fmt_prefix_hex:
    mov byte [rbp+2], 'x'
    jmp .fmt_emit_prefix

.fmt_prefix_octal:
    mov byte [rbp+2], 'o'

.fmt_emit_prefix:
    mov byte [rbp+1], '0'
    mov rdi, r12
    lea rsi, [rbp+1]
    mov rdx, 2
    call _buffer_append_bytes
    mov r12, rax

.fmt_no_prefix:
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

    ; --- Growing only: try mremap first (no copy, no munmap). Shrinking or an
    ; mremap failure falls back to the original alloc + copy path. ---
    mov rax, [r12 + BUF_CAPACITY]   ; old_capacity
    cmp r13, rax                     ; new_size > old_capacity ?
    jle .realloc_fallback            ; not growing -> alloc + copy path
    mov rsi, rax
    add rsi, BUF_DATA + 1            ; old_total_size = old_capacity + BUF_DATA + 1
    mov rdx, r13
    add rdx, BUF_DATA + 1            ; new_total_size = new_size + BUF_DATA + 1
    mov rdi, r12                      ; old_addr
    mov r10, MREMAP_MAYMOVE          ; flags
    mov rax, SYS_MREMAP              ; 25
    syscall
    cmp rax, -4096
    ja .realloc_fallback             ; mremap failed -> alloc + copy path
    ; mremap succeeded: rax = (possibly moved) pointer. BUF_LENGTH (old_len,
    ; which is <= old_capacity < new_size) and BUF_FLAGS are preserved by
    ; mremap - only BUF_CAPACITY changes.
    mov rbx, rax
    mov [rbx + BUF_CAPACITY], r13
    ; The old mapping was consumed by mremap - do NOT unregister_buffer or
    ; munmap it. Update buf_table only if the pointer moved.
    cmp rbx, r12
    je .realloc_mremap_return
    lea r11, [rel buf_table]
    xor rcx, rcx
.realloc_find_entry:
    cmp rcx, MAX_BUFFERS
    jge .realloc_mremap_return
    mov rax, [r11 + rcx*8]
    cmp rax, r12
    je .realloc_update_entry
    inc rcx
    jmp .realloc_find_entry
.realloc_update_entry:
    mov [r11 + rcx*8], rbx
.realloc_mremap_return:
    mov rax, rbx
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.realloc_fallback:
    ; Not growing (shrink/equal) or mremap failed: original alloc + copy path.
    mov rdi, r13
    call _alloc_buffer_sized
    mov rbx, rax            ; new buffer pointer

    ; _alloc_buffer_sized returns 0 on mmap failure. A null new buffer
    ; would make the rep movsb below write through BUF_DATA (address 24)
    ; and SIGSEGV. Bail out leaving the original buffer intact and
    ; report a generic error, rather than copying into a null block.
    test rbx, rbx
    jz .realloc_failed

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
    rep movsb                   ; copy rcx bytes
    
.skip_copy:
    ; Set new buffer length to copied amount
    mov rcx, r14
    cmp rcx, r13
    jle .set_len
    mov rcx, r13
.set_len:
    mov [rbx + BUF_LENGTH], rcx

    ; Preserve the original fixed/dynamic flag. Resizing a dynamic buffer
    ; must not convert it to fixed-size (it must keep auto-grow behavior).
    mov rdx, [r12 + BUF_FLAGS]
    mov [rbx + BUF_FLAGS], rdx

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

.realloc_failed:
    ; Allocation failed: report a generic error and return the original
    ; buffer unchanged (still tracked, not freed).
    mov qword [rel _last_error], 1
    mov rax, r12            ; return original buffer, intact
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
