; file.asm - File I/O macros for Vox Compiler
; Provides file operations: open, read, write, close, delete, exists
; Filesystem only - process control (fork/mount/reboot/exec/mknod) moved to proc.asm (audit rec 2).

; Linux x86_64 syscall numbers
%define SYS_READ    0
%define SYS_WRITE   1
%define SYS_OPEN    2
%define SYS_CLOSE   3
%define SYS_MMAP    9
%define SYS_MUNMAP  11
%define SYS_ACCESS  21
%define SYS_UNLINK  87
%define SYS_MKDIR   83
%define SYS_RMDIR   84
%define SYS_CHDIR   80
%define SYS_SYMLINK 88

; Open flags
%define O_RDONLY    0
%define O_WRONLY    1
%define O_RDWR      2
%define O_CREAT     64
%define O_TRUNC     512
%define O_APPEND    1024

; File permissions (0644)
%define FILE_PERMS  420

; Standard file descriptors
%define STDIN       0
%define STDOUT      1
%define STDERR      2

; Access check modes
%define F_OK        0

; MMAP flags
%define PROT_READ   1
%define PROT_WRITE  2
%define MAP_PRIVATE 2
%define MAP_ANONYMOUS 32

; Allocate a buffer of N bytes using mmap
; Args: size (bytes)
; Returns: pointer in rax (or -1 on error)
%macro ALLOC_BUFFER 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    
    mov rax, SYS_MMAP
    xor rdi, rdi                    ; addr = NULL (let kernel choose)
    mov rsi, %1                     ; length = size
    mov rdx, PROT_READ | PROT_WRITE ; prot = read|write
    mov r10, MAP_PRIVATE | MAP_ANONYMOUS ; flags
    mov r8, -1                      ; fd = -1 (anonymous)
    xor r9, r9                      ; offset = 0
    syscall
    
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Free a buffer allocated with ALLOC_BUFFER
; Args: pointer, size
%macro FREE_BUFFER 2
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_MUNMAP
    mov rdi, %1                     ; addr
    mov rsi, %2                     ; length
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Open file for reading
; Args: path in rdi (null-terminated string pointer)
; Returns: fd in rax (or negative error)
%macro FILE_OPEN_READ 1
    push rbx
    push rcx
    push rdx
    push rsi
    
    ; rdi already contains path pointer
    mov rax, SYS_OPEN
    mov rsi, O_RDONLY               ; flags
    xor rdx, rdx                    ; mode (unused for read)
    syscall
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Open file for writing (create/truncate)
; Args: path in rdi (null-terminated string pointer)
; Returns: fd in rax (or negative error)
%macro FILE_OPEN_WRITE 1
    push rbx
    push rcx
    push rdx
    push rsi
    
    ; rdi already contains path pointer
    mov rax, SYS_OPEN
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC  ; flags
    mov rdx, FILE_PERMS             ; mode = 0644
    syscall
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Open file for appending
; Args: path in rdi (null-terminated string pointer)
; Returns: fd in rax (or negative error)
%macro FILE_OPEN_APPEND 1
    push rbx
    push rcx
    push rdx
    push rsi
    
    ; rdi already contains path pointer
    mov rax, SYS_OPEN
    mov rsi, O_WRONLY | O_CREAT | O_APPEND  ; flags
    mov rdx, FILE_PERMS             ; mode = 0644
    syscall
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Close file descriptor
; Args: fd
%macro FILE_CLOSE 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_CLOSE
    mov rdi, %1                     ; fd
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Read from file descriptor into buffer
; Args: fd, buffer, max_size
; Returns: bytes read in rax (or negative error)
%macro FILE_READ 3
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_READ
    mov rdi, %1                     ; fd
    mov rsi, %2                     ; buffer
    mov rdx, %3                     ; count
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Write buffer to file descriptor
; Args: fd, buffer, size
; Returns: bytes written in rax (or negative error)
%macro FILE_WRITE 3
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_WRITE
    mov rdi, %1                     ; fd
    mov rsi, %2                     ; buffer
    mov rdx, %3                     ; count
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Record the outcome of a write(2) in _last_error, so `On error` can see a
; write that did not happen. Before this the three write macros issued the
; syscall and never looked at rax, which made a failed write indistinguishable
; from a successful one from inside Vox (bug #48).
; Expects: rax = the syscall's return value
;          rdx = the byte count that was asked for (syscall preserves rdx;
;                only rax, rcx and r11 are clobbered)
; Leaves rax untouched, the way FORK does, so a caller that wants the count
; still has it.
; A short write is a failure too: Vox does not retry, so the missing bytes are
; simply lost. The kernel gives no errno for one, so it is recorded as EIO (5).
%macro RECORD_WRITE_RESULT 0
    test rax, rax
    js %%write_failed
    cmp rax, rdx
    jl %%write_short
    mov qword [rel _last_error], 0
    jmp %%write_done
%%write_failed:
    push rax
    neg rax                         ; -errno -> errno
    mov [rel _last_error], rax
    pop rax
    jmp %%write_done
%%write_short:
    mov qword [rel _last_error], 5  ; EIO - fewer bytes written than asked for
%%write_done:
%endmacro

; Write null-terminated string to file descriptor
; Args: fd, string_ptr
%macro FILE_WRITE_STR 2
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Save fd and string ptr first (before we clobber registers)
    mov r12, %1
    mov r13, %2
    
    ; Calculate string length
    mov rdi, r13
    xor rcx, rcx
%%strlen_loop:
    cmp byte [rdi + rcx], 0
    je %%strlen_done
    inc rcx
    jmp %%strlen_loop
%%strlen_done:
    
    ; Write the string
    mov rax, SYS_WRITE
    mov rdi, r12                    ; fd (saved earlier)
    mov rsi, r13                    ; buffer (saved earlier)
    mov rdx, rcx                    ; count = strlen
    syscall
    RECORD_WRITE_RESULT

    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Write buffer struct contents to file descriptor
; Args: fd, buffer_struct_ptr
; Buffer struct: [capacity:8][length:8][flags:8][data...]
%macro FILE_WRITE_BUF 2
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, SYS_WRITE
    mov rdi, %1                     ; fd
    mov rsi, %2                     ; buffer struct pointer
    mov rdx, [rsi + 8]              ; length from struct offset 8
    add rsi, BUF_DATA               ; data starts at BUF_DATA
    syscall
    RECORD_WRITE_RESULT

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Write newline to file descriptor
; Args: fd
%macro FILE_WRITE_NEWLINE 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    ; Push newline character onto stack
    push 10
    
    mov rax, SYS_WRITE
    mov rdi, %1                     ; fd
    mov rsi, rsp                    ; buffer = stack (newline char)
    mov rdx, 1                      ; count = 1
    syscall
    RECORD_WRITE_RESULT

    add rsp, 8                      ; clean up stack
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Check if file exists
; Args: path (null-terminated string)
; Returns: 0 in rax if exists, -1 if not
%macro FILE_EXISTS 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1                     ; pathname (load BEFORE rax: %1 may BE rax)
    mov rax, SYS_ACCESS
    mov rsi, F_OK                   ; mode = existence check
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Create a directory
; Args: path (null-terminated string)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro MKDIR 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rdi, %1                     ; pathname (load BEFORE rax: %1 may BE rax)
    mov rax, SYS_MKDIR
    mov rsi, 493                    ; mode 0755 (rwxr-xr-x)
    syscall

    test rax, rax
    jns %%mkdir_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%mkdir_done
%%mkdir_ok:
    mov qword [rel _last_error], 0
%%mkdir_done:

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Remove a directory
; Args: path (null-terminated string)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro RMDIR 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rdi, %1                     ; pathname (load BEFORE rax: %1 may BE rax)
    mov rax, SYS_RMDIR
    syscall

    test rax, rax
    jns %%rmdir_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%rmdir_done
%%rmdir_ok:
    mov qword [rel _last_error], 0
%%rmdir_done:

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Change current working directory
; Args: path (null-terminated string)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro CHDIR 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rdi, %1                     ; pathname (load BEFORE rax: %1 may BE rax)
    mov rax, SYS_CHDIR
    syscall

    test rax, rax
    jns %%chdir_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%chdir_done
%%chdir_ok:
    mov qword [rel _last_error], 0
%%chdir_done:

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Create a symbolic link
; Args: rdi = target path, rsi = linkpath (both pre-loaded by codegen)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro SYMLINK 0
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rax, SYS_SYMLINK
    syscall

    test rax, rax
    jns %%symlink_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%symlink_done
%%symlink_ok:
    mov qword [rel _last_error], 0
%%symlink_done:

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Check file/path availability (boolean semantics for Vox's "is available")
; Input: rax = path pointer
; Returns: rax = 1 if the path exists/is available, 0 otherwise. Does not touch _last_error.
%macro FILE_AVAILABLE 0
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rdi, rax                    ; path pointer
    mov rax, SYS_ACCESS
    mov rsi, F_OK
    syscall

    test rax, rax
    setz al                         ; 1 if access() returned 0 (available)
    movzx rax, al

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Delete file
; Args: path (null-terminated string)
; Returns: 0 in rax on success, negative on error
%macro FILE_DELETE 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rdi, %1                     ; pathname (load BEFORE rax: %1 may BE rax)
    mov rax, SYS_UNLINK
    syscall

    cmp rax, 0
    jge %%.file_delete_done
    mov qword [rel _last_error], 2  ; file operation error
%%.file_delete_done:

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; (File-handle property accessors below moved from resource.asm - audit rec 1/2.)
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
