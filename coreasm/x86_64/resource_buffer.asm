; resource_buffer.asm - Dynamic buffer lifecycle + accessors
; Split from resource.asm (audit rec 1). Allocation, registration,
; growth, read-into-buffer, append/copy/clear, and the formatted-int
; append live here. The buffer-structure offsets (BUF_*) and the mremap
; growth constants are owned here because _read_line_into_buffer (the
; read-ahead module) also reads them - that module is included after this
; one, so the %defines are visible at its assembly point.
;
; Co-included with resource_fd.asm whenever the resource runtime is
; present: _read_into_buffer reads the fd seekability cache, and a library's
; `_unload_library` (below) calls `_cleanup_all` (fd). The two share the
; (uses_buffers || uses_files || uses_floats) gate.
;
; The buffer record. Each module (a program, or each `.so`) records the
; buffers its own `_alloc_buffer*` mapped, in `buf_table`, so that a library
; unloaded by a host that keeps running (`dlclose`, which runs `.fini_array`)
; gives them back (`_sweep_buffer_record`). A buffer can be grown or freed by
; ANOTHER module's code (a buffer parameter is the caller's buffer), so every
; buffer carries the way back to its entry: the word just before its header,
; BUF_RECORD, holds the ADDRESS of the `buf_table` entry that records it (0
; when the table was full). Growth that moves the buffer writes the new
; pointer through that address, and `Free` clears the entry through it, in
; the same routine, whichever module runs it. No routine searches a table.
; The pointer every name holds still points at BUF_CAPACITY, so only the
; routines that map, move or unmap a buffer know the word is there: the
; mapping starts BUF_PREFIX bytes earlier.
%define MAX_BUFFERS 64
; Buffer structure offsets
%define BUF_RECORD   -8     ; 8 bytes: address of this buffer's record entry, or 0
%define BUF_PREFIX   8      ; bytes mapped before BUF_CAPACITY (the record word)
%define BUF_CAPACITY 0      ; 8 bytes: allocated size
%define BUF_LENGTH   8      ; 8 bytes: used length
%define BUF_FLAGS    16     ; 8 bytes: flags (bit 0 = fixed size)
%define BUF_DATA     24     ; data starts here
; Buffer flags
%define BUF_FLAG_FIXED 1    ; Buffer has fixed size, no growing allowed
%define BUF_FLAG_RELEASED 2 ; The released header: `Free` was here

; Initial buffer capacity
%define INITIAL_BUF_CAP 4096
; mremap syscall + flag for the no-copy growth path. Defined locally here
; (not imported from file.asm) because resource.asm is included for
; buffer-only programs where file.asm is absent - see the codegen include
; gating (uses_buffers || uses_files || uses_floats vs uses_files only).
%define SYS_MREMAP     25
%define MREMAP_MAYMOVE 1

section .data
    ; The shared header `Free` points a released buffer's variable at
    ; (docs/BUGS_FOUND.md #107, the `Free` statement): capacity 0, length
    ; 0, BUF_FLAG_FIXED set, one reserved NUL-terminator byte - the same
    ; shape `_alloc_buffer_sized(0)` produces (bug #78's size guard), just
    ; static instead of mmap'd - plus BUF_FLAG_RELEASED, which is how
    ; `_free_buffer` and `_realloc_buffer`/`_reallocate_buffer` below
    ; recognise it before touching memory. A real buffer can legitimately
    ; reach capacity 0 + BUF_FLAG_FIXED too (bug #78), so the shape alone
    ; is not enough; and each library has its own copy of this header, so
    ; its address is not enough either: a buffer freed on one side of a
    ; `.so` boundary must be recognised on the other. Its record word is 0.
                              dq 0
    _released_buffer_header: dq 0, 0, BUF_FLAG_FIXED | BUF_FLAG_RELEASED
                              db 0

section .bss
    ; The buffer record: each entry holds a buffer this module mapped (0 =
    ; unused), and that buffer's BUF_RECORD word holds the entry's address.
    buf_table: resq MAX_BUFFERS
    ; Scratch buffer for _buffer_append_formatted_int (backwards decimal conversion)
    fmt_i64_buf: resb 128
    ; The buffer `Print` renders a padded float into before padding it
    ; (_fmt_scratch_buffer below); 0 until the first such Print.
    _fmt_pad_scratch: resq 1

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
    
    ; Allocate: record word + header + initial capacity + 1 for null terminator
    mov rsi, INITIAL_BUF_CAP + BUF_DATA + 1 + BUF_PREFIX
    
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
    add rax, BUF_PREFIX     ; the buffer pointer is past the record word
    
    ; Initialize buffer header (dynamic buffer)
    mov qword [rax + BUF_CAPACITY], INITIAL_BUF_CAP
    mov qword [rax + BUF_LENGTH], 0
    mov qword [rax + BUF_FLAGS], 0       ; dynamic (not fixed)
    
    ; Record it in this module's table
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
    
    ; Allocate: record word + header (24 bytes) + requested size + 1 for
    ; the null terminator
    mov rsi, rdi
    add rsi, BUF_DATA + 1 + BUF_PREFIX
    
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
    add rax, BUF_PREFIX     ; the buffer pointer is past the record word
    
    ; Initialize buffer header (fixed size buffer)
    mov [rax + BUF_CAPACITY], r12
    mov qword [rax + BUF_LENGTH], 0
    mov qword [rax + BUF_FLAGS], BUF_FLAG_FIXED  ; fixed size, no growing
    
    ; Record it in this module's table
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

; Record a buffer this module just mapped: take a free entry of buf_table,
; store the buffer there, and store the entry's address in the buffer's
; BUF_RECORD word. A full table records nothing (BUF_RECORD = 0): that
; buffer is simply not given back at unload, the cap the table always had.
; Args: buffer pointer in rdi. Clobbers rax.
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
    lea rax, [rbx + rcx*8]
    mov [rdi + BUF_RECORD], rax
    jmp .registered

.table_full:
    mov qword [rdi + BUF_RECORD], 0

.registered:
    pop rcx
    pop rbx
    ret

; Clear a buffer's record entry, through its own BUF_RECORD word, so it
; works whichever module recorded the buffer and whichever module runs it.
; Args: buffer pointer in rdi. Clobbers rax.
global _unregister_buffer
_unregister_buffer:
    mov rax, [rdi + BUF_RECORD]
    test rax, rax
    jz .not_recorded
    mov qword [rax], 0
    mov qword [rdi + BUF_RECORD], 0
.not_recorded:
    ret

; Free a buffer and clear its record entry.
; Args: buffer pointer in rdi
;
; Always munmaps, recorded or not - a buffer allocated past MAX_BUFFERS live
; ones is never recorded, and gating the munmap on the record left every
; such buffer mapped forever (docs/BUGS_FOUND.md #108).
global _free_buffer
_free_buffer:
    ; Refuse a released buffer (a double `Free`) before touching anything:
    ; BUF_FLAG_RELEASED marks every module's released header, so a caller
    ; that skips its own check (codegen keeps none; see `emit_free_buffer`)
    ; is still safe.
    test qword [rdi + BUF_FLAGS], BUF_FLAG_RELEASED
    jz .free_buf_live
    SET_LAST_ERROR 1  ; already freed
    ret

.free_buf_live:
    push rcx
    push rsi

    call _unregister_buffer

    mov rsi, [rdi + BUF_CAPACITY]
    add rsi, BUF_DATA + 1 + BUF_PREFIX  ; the whole mapping
    sub rdi, BUF_PREFIX                 ; which starts at the record word
    mov rax, 11                         ; SYS_MUNMAP
    syscall
    add rdi, BUF_PREFIX
    CLEAR_LAST_ERROR  ; released

    pop rsi
    pop rcx
    ret

; Give back every buffer this module's record still holds. Run only when a
; library is unloaded (`_unload_library`, the `.fini_array` entry of a
; `--shared` build): at process exit the kernel takes every mapping back
; anyway, so a program's exit does not sweep.
global _sweep_buffer_record
_sweep_buffer_record:
    push rbx
    push r12

    lea rbx, [rel buf_table]
    xor r12, r12        ; r12 = index (rbx and r12 survive the syscall)
.sweep_loop:
    cmp r12, MAX_BUFFERS
    jge .sweep_done

    mov rdi, [rbx + r12*8]
    test rdi, rdi
    jz .sweep_next

    mov rsi, [rdi + BUF_CAPACITY]
    add rsi, BUF_DATA + 1 + BUF_PREFIX
    sub rdi, BUF_PREFIX
    mov rax, 11             ; SYS_MUNMAP
    syscall

    mov qword [rbx + r12*8], 0

.sweep_next:
    inc r12
    jmp .sweep_loop

.sweep_done:
    pop r12
    pop rbx
    ret

; The `.fini_array` entry of a `--shared` library: what a host's `dlclose`
; (or its exit through libc) runs. Close and flush the library's files, then
; give back the buffers the library made.
global _unload_library
_unload_library:
    call _cleanup_all
    call _sweep_buffer_record
    ret

; Reallocate a buffer to an EXACT new capacity (no doubling).
; Args: rdi = buffer pointer, rsi = exact new capacity (must be >= BUF_LENGTH)
; Returns: new buffer pointer in rax (the OLD pointer on mmap failure, with
;          _last_error set to 1). The buffer may move.
; Copies the existing BUF_LENGTH bytes, writes the new pointer into the
; buffer's record entry (through BUF_RECORD), and frees the old allocation.
; The flags field is not copied: the new region is freshly mmapped (zeroed),
; so it is a dynamic buffer (flags 0), matching what _grow_buffer always
; produced.
global _reallocate_buffer
_reallocate_buffer:
    ; Same guard as _free_buffer/_realloc_buffer, and for the same reason
    ; (docs/BUGS_FOUND.md #107): every existing caller already filters a
    ; BUF_FLAG_FIXED pointer out before reaching here (the released header
    ; is always fixed), so this is a belt-and-suspenders check for any
    ; future caller that does not.
    mov rax, rdi
    test qword [rdi + BUF_FLAGS], BUF_FLAG_RELEASED
    jz .reallocate_buffer_live
    SET_LAST_ERROR 1  ; refused: this buffer is freed
    ret               ; rax holds the header - unchanged

.reallocate_buffer_live:
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
    add rsi, BUF_DATA + 1 + BUF_PREFIX  ; old_total_size
    mov rdx, r14
    add rdx, BUF_DATA + 1 + BUF_PREFIX  ; new_total_size
    lea rdi, [r12 - BUF_PREFIX]         ; old_addr: the mapping's start
    mov r10, MREMAP_MAYMOVE         ; flags
    mov rax, SYS_MREMAP             ; 25
    syscall
    cmp rax, -4096
    ja .mmap_alloc                  ; mremap failed -> mmap path

    ; mremap succeeded: rax = the (possibly moved) mapping. The record word
    ; and the header bytes - including BUF_LENGTH and BUF_FLAGS - move with
    ; it, so only BUF_CAPACITY needs updating.
    lea rbx, [rax + BUF_PREFIX]
    mov [rbx + BUF_CAPACITY], r14
    ; The old mapping was consumed by mremap - do NOT munmap it. The record
    ; entry follows the buffer if it moved.
    cmp rbx, r12
    je .mremap_done
    mov rax, [rbx + BUF_RECORD]
    test rax, rax
    jz .mremap_done
    mov [rax], rbx
.mremap_done:
    mov rax, rbx            ; return new buffer
    jmp .done

.mmap_alloc:
    ; Allocate new buffer (+ record word + header + 1 for null terminator)
    mov rax, 9              ; SYS_MMAP
    mov rsi, r14
    add rsi, BUF_DATA + 1 + BUF_PREFIX  ; total allocation size
    xor rdi, rdi
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 34             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall

    ; Check for error (raw mmap returns -errno in [-4095,-1])
    cmp rax, -4096
    ja .failed

    lea rbx, [rax + BUF_PREFIX]  ; new buffer

    ; Initialize new header (r14 survived the syscall). The buffer keeps its
    ; record entry: the new block takes the old one's record word, and the
    ; entry is pointed at the new block.
    mov rax, [r12 + BUF_RECORD]
    mov [rbx + BUF_RECORD], rax
    test rax, rax
    jz .reallocate_unrecorded
    mov [rax], rbx
.reallocate_unrecorded:
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

    ; Free old buffer (+ record word + 1 for null terminator)
    lea rdi, [r12 - BUF_PREFIX]
    mov rsi, [r12 + BUF_CAPACITY]
    add rsi, BUF_DATA + 1 + BUF_PREFIX
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

    ; A buffer appended to itself: growth can move it and release the old
    ; block, so whether the source IS the destination is decided now, and
    ; after the growth the source is the moved block too.
    xor ebx, ebx
    cmp r12, r13
    sete bl
    mov rdi, r12
    mov rsi, rax
    call _grow_buffer
    test rax, rax
    jz .append_grow_failed
    mov r12, rax
    test bl, bl
    jz .append_have_space
    mov r13, r12                    ; the source moved with the destination

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

    ; Bytes that lie inside the destination's own data (a buffer's text
    ; appended to that buffer) move with it: growth can release the old
    ; block, so their offset is taken now and applied to the moved block.
    ; rbx = offset into the data area, or -1 when the bytes are elsewhere.
    mov rbx, -1
    lea r9, [r12 + BUF_DATA]
    cmp r13, r9
    jb .append_bytes_grow
    lea rcx, [r9 + r8]
    cmp r13, rcx
    ja .append_bytes_grow
    mov rbx, r13
    sub rbx, r9
.append_bytes_grow:
    mov rdi, r12
    mov rsi, rax
    call _grow_buffer
    test rax, rax
    jz .append_bytes_grow_failed
    mov r12, rax
    cmp rbx, -1
    je .append_bytes_have_space
    lea r13, [r12 + BUF_DATA]
    add r13, rbx                    ; the same bytes, in the moved block

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

; Right-align the value just appended to a buffer within a width
; (docs/BUGS_FOUND.md #148): `{price:8}` and `{name:8}` in a text, a
; buffer, a `write` or any other sink but Print. The value is appended
; first by its own routine, then moved right and the fill written in
; front of it, so a float, a text and a buffer share one padder.
; Args: rdi = buffer, rsi = the buffer's length before the value was
;       appended, rdx = width, rcx = fill: 0 spaces, 1 zeros, 2 zeros
;       after a leading '-' (the sign comes first, as a number's does).
; Returns: rax = the buffer (possibly reallocated). A value already as
; wide as the width is left as it is. Where the padded value does not fit
; (a fixed buffer, or memory that cannot grow) what fits is kept and the
; error flag is set, as an append does.
global _buffer_pad_tail
_buffer_pad_tail:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                    ; buffer
    mov r13, rsi                    ; where the value starts
    mov r14, [r12 + BUF_LENGTH]
    sub r14, r13                    ; the value's length
    mov r8b, ' '
    test rcx, rcx
    jz .pad_fill_known
    mov r8b, '0'
    cmp rcx, 2
    jne .pad_fill_known
    test r14, r14
    jz .pad_fill_known
    cmp byte [r12 + BUF_DATA + r13], '-'
    jne .pad_fill_known
    inc r13                         ; the sign stays in front of the zeros
    dec r14
    dec rdx
.pad_fill_known:
    mov r15, rdx
    sub r15, r14                    ; fill characters owed
    jle .pad_done

    ; r9 = the length once padded. A width past 2^46 cannot be held in
    ; memory, and the sum would overflow before the capacity test.
    mov rax, 1 << 46
    cmp r15, rax
    ja .pad_short
    mov r9, [r12 + BUF_LENGTH]
    add r9, r15
    cmp r9, [r12 + BUF_CAPACITY]
    jle .pad_have_room
    test qword [r12 + BUF_FLAGS], BUF_FLAG_FIXED
    jnz .pad_short
    mov rdi, r12
    mov rsi, r9
    call _grow_buffer
    mov r12, rax
    cmp r9, [r12 + BUF_CAPACITY]    ; a failed growth hands back the old one
    jle .pad_have_room
.pad_short:
    mov qword [rel _last_error], 1
    mov r9, [r12 + BUF_CAPACITY]

.pad_have_room:
    ; Move the value's bytes that still fit after the fill, last byte first
    ; (the two ranges overlap).
    mov rcx, r9
    sub rcx, r13
    sub rcx, r15
    cmp rcx, r14
    jle .pad_move_counted
    mov rcx, r14
.pad_move_counted:
    test rcx, rcx
    jle .pad_fill
    lea rsi, [r12 + BUF_DATA + r13 - 1]
    add rsi, rcx
    lea rdi, [rsi + r15]
    std
    rep movsb
    cld

.pad_fill:
    mov rcx, r9
    sub rcx, r13
    cmp rcx, r15
    jle .pad_fill_counted
    mov rcx, r15
.pad_fill_counted:
    lea rdi, [r12 + BUF_DATA + r13]
    movzx eax, r8b
    rep stosb
    mov [r12 + BUF_LENGTH], r9
    mov byte [r12 + BUF_DATA + r9], 0

.pad_done:
    mov rax, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; The buffer `Print` renders a padded float into, emptied (#148): Print
; writes straight to stdout, so the float's characters are counted here
; before the fill goes out in front of them. Allocated on the first such
; Print and reused by every later one; it is tracked like every buffer and
; freed at exit.
; Returns: rdi = the empty scratch buffer. Every other register is kept.
global _fmt_scratch_buffer
_fmt_scratch_buffer:
    push rax
    mov rdi, [rel _fmt_pad_scratch]
    test rdi, rdi
    jnz .scratch_ready
    call _alloc_buffer
    mov [rel _fmt_pad_scratch], rax
    mov rdi, rax
.scratch_ready:
    mov qword [rdi + BUF_LENGTH], 0
    mov byte [rdi + BUF_DATA], 0
    pop rax
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

; A new buffer holding the same bytes as the one in rdi (docs/BUGS_FOUND.md
; #103): what a thing's buffer field becomes in a copy of the thing, so the
; copy and the original never share one. A fixed buffer's copy is fixed at
; the same capacity; any other is a growing buffer.
; Args: rdi = buffer. Returns: rax = the new buffer, or the shared released
; header with the error flag set when no memory could be had for it.
global _buffer_duplicate
_buffer_duplicate:
    push rdi
    push rsi
    push r12
    mov r12, rdi
    ; A copy of a released buffer is a fresh, empty, growing buffer of its
    ; own, as a named copy of one is: it was never freed, so it takes
    ; writes. (The released header is fixed at capacity 0, so without this
    ; the copy would be a fixed buffer with no room at all.)
    test qword [r12 + BUF_FLAGS], BUF_FLAG_RELEASED
    jz .duplicate_live
    call _alloc_buffer
    test rax, rax
    jnz .duplicate_done
    mov qword [rel _last_error], 1
    lea rax, [rel _released_buffer_header]
    jmp .duplicate_done
.duplicate_live:
    test qword [r12 + BUF_FLAGS], BUF_FLAG_FIXED
    jz .duplicate_growing
    mov rdi, [r12 + BUF_CAPACITY]
    call _alloc_buffer_sized
    jmp .duplicate_allocated
.duplicate_growing:
    call _alloc_buffer
.duplicate_allocated:
    test rax, rax
    jnz .duplicate_fill
    mov qword [rel _last_error], 1
    lea rax, [rel _released_buffer_header]
    jmp .duplicate_done
.duplicate_fill:
    mov rdi, rax
    mov rsi, r12
    call _buffer_copy
.duplicate_done:
    pop r12
    pop rsi
    pop rdi
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
    ; Refuse a released buffer the same way _free_buffer does: `Resize`d,
    ; it would fall through to the alloc+copy fallback below and munmap a
    ; static header, and the fallback would also hand back a freshly mmap'd
    ; buffer, silently resurrecting a variable `Free` emptied
    ; (docs/BUGS_FOUND.md #107).
    mov rax, rdi
    test qword [rdi + BUF_FLAGS], BUF_FLAG_RELEASED
    jz .realloc_buffer_live
    SET_LAST_ERROR 1  ; refused: this buffer is freed
    ret               ; rax holds the header - unchanged

.realloc_buffer_live:
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
    add rsi, BUF_DATA + 1 + BUF_PREFIX  ; old_total_size, from the record word
    mov rdx, r13
    add rdx, BUF_DATA + 1 + BUF_PREFIX  ; new_total_size
    lea rdi, [r12 - BUF_PREFIX]         ; old_addr: the mapping's start
    mov r10, MREMAP_MAYMOVE          ; flags
    mov rax, SYS_MREMAP              ; 25
    syscall
    cmp rax, -4096
    ja .realloc_fallback             ; mremap failed -> alloc + copy path
    ; mremap succeeded: rax = the (possibly moved) mapping. The record word,
    ; BUF_LENGTH (old_len, which is <= old_capacity < new_size) and
    ; BUF_FLAGS are preserved by mremap - only BUF_CAPACITY changes.
    lea rbx, [rax + BUF_PREFIX]
    mov [rbx + BUF_CAPACITY], r13
    ; The old mapping was consumed by mremap - do NOT unregister_buffer or
    ; munmap it. The record entry follows the buffer if it moved.
    cmp rbx, r12
    je .realloc_mremap_return
    mov rax, [rbx + BUF_RECORD]
    test rax, rax
    jz .realloc_mremap_return
    mov [rax], rbx
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

    ; Free old buffer (clear its record entry; the new one has its own)
    mov rdi, r12
    call _unregister_buffer
    
    ; Free old buffer memory, from its record word
    mov rax, 11             ; sys_munmap
    lea rdi, [r12 - BUF_PREFIX]
    mov rsi, [r12 + BUF_CAPACITY]
    add rsi, BUF_DATA + 1 + BUF_PREFIX
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
