; resource_fd.asm - File-descriptor tracking + read-ahead flush state
; Split from resource.asm (audit rec 1). The fd table, its seekability
; cache, and the read-ahead slot state plus _flush_readahead_fd live here
; so _unregister_fd's close-time flush resolves WITHOUT the line-reading
; module (which is gated on uses_readline/uses_seek). _cleanup_all and the
; (currently unreferenced) _print_last_error stayed with the fd core.
;
; This is the FIRST resource module included, so it owns the
; __RESOURCE_ASM_INCLUDED__ define that io.asm's RENDER_* macros and
; list.asm/map.asm test (they are included after the resource block).
; Maximum tracked resources
%define MAX_FDS 64
%define READAHEAD_SLOTS 8
%define READAHEAD_BUF_SIZE 8192
; Tested by io.asm's RENDER_* macros and by list.asm/map.asm: the collection
; renderers can only append to a buffer when the buffer runtime is present,
; and this file is included after io.asm but before both of them.
%define __RESOURCE_ASM_INCLUDED__
; fstat(2), lseek(2), and struct stat constants (Linux x86-64). Used by the
; pre-size path in _read_into_buffer (track B3) and by the seekability cache
; and exact-fill decision (track B4). Defined locally here so these paths do
; not depend on file.asm's include order/gating - resource.asm is included for
; buffer-only programs where file.asm is absent.
%define SYS_FSTAT 5
%define SYS_LSEEK 8
%define SEEK_CUR 1
%define S_IFMT  0xF000           ; 0o170000 - bit mask for the file type field
%define S_IFREG 0x8000           ; 0o100000 - regular file
%define STAT_MODE_OFFSET 24      ; mode_t st_mode (4 bytes) - used by B3
%define STAT_SIZE_OFFSET 48      ; off_t st_size (8 bytes) - used by B3
%define STAT_ST_MODE 24          ; st_mode offset in struct stat (4 bytes) - used by B4
%define STAT_ST_SIZE 48          ; st_size offset in struct stat (8 bytes) - used by B4

section .bss
    ; File descriptor tracking table
    ; Each entry: 8 bytes (fd value, 0 = unused)
    fd_table: resq MAX_FDS
    fd_count: resq 1

    ; Seekability cache (track B4): per-slot st_mode (dword) and st_size
    ; (qword), populated by _register_fd's fstat at open time. A mode of 0
    ; means "unknown / not regular", so _read_into_buffer treats an exact fill
    ; as success without probing - unseekable fds never lose a byte. Slot
    ; indices match fd_table 1:1; reuse re-fstats, so no stale data leaks.
    fd_mode_table: resd MAX_FDS
    fd_size_table: resq MAX_FDS
    ; Read-ahead cache for line reading
    ; Slots are assigned per-fd on demand.
    ra_used: resb READAHEAD_SLOTS
    ra_fd: resq READAHEAD_SLOTS
    ra_pos: resq READAHEAD_SLOTS
    ra_filled: resq READAHEAD_SLOTS
    ra_data: resb READAHEAD_SLOTS * READAHEAD_BUF_SIZE
    ; Idempotency guard for _cleanup_all: the .fini_array path (C/Rust host)
    ; and an explicit pre-exit call (Vox host) can both fire; this prevents a
    ; double-close / double-munmap. Reset to 0 each time the .so is loaded.
    cleanup_done: resb 1

section .text
; Register a file descriptor for tracking
; Args: fd in rdi
; Clobbers: rax, rcx, rdx, rsi (and r12, saved+restored)
; As of track B4, also caches the fd's seekability metadata (st_mode/st_size)
; via fstat(2) so _read_into_buffer can decide exact-fill without a probe.
global _register_fd
_register_fd:
    push rbx
    push rcx
    push rdx
    push rsi
    push r12

    lea rbx, [rel fd_table]
    ; Find empty slot
    xor rcx, rcx
.find_slot:
    cmp rcx, MAX_FDS
    jge .table_full

    mov rax, [rbx + rcx*8]
    test rax, rax
    jz .found_slot

    inc rcx
    jmp .find_slot

.found_slot:
    mov [rbx + rcx*8], rdi      ; store fd (rdi still holds it)
    inc qword [rel fd_count]
    mov r12, rcx                ; save slot across the fstat syscall (rcx clobbered)

    ; fstat(fd, &buf) on the stack, then cache st_mode/st_size for this slot.
    ; On fstat failure, leave mode 0 so _read_into_buffer treats an exact fill
    ; as success (no consuming probe) - the safe choice for unseekable fds.
    sub rsp, 144                ; struct stat (144 bytes), 16-aligned
    mov rax, SYS_FSTAT
    mov rdi, [rbx + r12*8]      ; fd (reload from the table)
    mov rsi, rsp
    syscall
    test rax, rax
    jnz .fstat_failed
    lea rdx, [rel fd_mode_table]
    mov eax, [rsp + STAT_ST_MODE]
    mov [rdx + r12*4], eax
    lea rdx, [rel fd_size_table]
    mov rax, [rsp + STAT_ST_SIZE]
    mov [rdx + r12*8], rax
    add rsp, 144
    jmp .table_full

.fstat_failed:
    lea rdx, [rel fd_mode_table]
    mov dword [rdx + r12*4], 0
    lea rdx, [rel fd_size_table]
    mov qword [rdx + r12*8], 0
    add rsp, 144

.table_full:
    pop r12
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret
; Flush read-ahead state for a specific fd
; Args: fd in rdi
; Clobbers: rax, rcx
_flush_readahead_fd:
    push rbx
    push r12
    push r13
    push r14

    lea rbx, [rel ra_used]
    lea r12, [rel ra_fd]
    lea r13, [rel ra_pos]
    lea r14, [rel ra_filled]
    xor rcx, rcx

.flush_scan:
    cmp rcx, READAHEAD_SLOTS
    jge .flush_done

    movzx eax, byte [rbx + rcx]
    test eax, eax
    jz .flush_next

    mov rax, [r12 + rcx*8]
    cmp rax, rdi
    jne .flush_next

    mov byte [rbx + rcx], 0
    mov qword [r12 + rcx*8], 0
    mov qword [r13 + rcx*8], 0
    mov qword [r14 + rcx*8], 0

.flush_next:
    inc rcx
    jmp .flush_scan

.flush_done:
    pop r14
    pop r13
    pop r12
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

    lea rbx, [rel fd_table]
    xor rcx, rcx
.find_fd:
    cmp rcx, MAX_FDS
    jge .not_found

    mov rax, [rbx + rcx*8]
    cmp rax, rdi
    je .found_fd

    inc rcx
    jmp .find_fd

.found_fd:
    mov qword [rbx + rcx*8], 0
    dec qword [rel fd_count]

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

    lea rbx, [rel fd_table]
    xor r12, r12        ; r12 = loop counter
.close_loop:
    cmp r12, MAX_FDS
    jge .done

    mov rdi, [rbx + r12*8]
    test rdi, rdi
    jz .next

    ; Don't close stdin/stdout/stderr
    cmp rdi, 3
    jl .next

    ; Close this fd. rbx (the table base) survives the syscall: only
    ; rax/rcx/r11 are clobbered, and r12 (the index) is callee-saved.
    mov rax, 3          ; SYS_CLOSE
    syscall

    mov qword [rbx + r12*8], 0

.next:
    inc r12
    jmp .close_loop

.done:
    mov qword [rel fd_count], 0
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

; Cleanup all resources - call before exit. Idempotent: the .fini_array
; path (C/Rust host, run by _dl_fini) and an explicit pre-exit call (Vox
; host, which exits via sys_exit and so never reaches _dl_fini) can both
; fire for one load; the guard byte keeps the second call a no-op.
global _cleanup_all
_cleanup_all:
    cmp byte [rel cleanup_done], 0
    jne .done
    mov byte [rel cleanup_done], 1
    call _cleanup_fds
    call _cleanup_buffers
.done:
    ret
