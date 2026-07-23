; file.asm - File I/O macros for Vox Compiler
; Provides file operations: open, read, write, close, delete, exists

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
%define SYS_MKNOD   133
%define SYS_MOUNT   165
%define SYS_PIVOT_ROOT 155
%define SYS_EXECVE  59

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
    add rsi, 24                     ; data starts at offset 24
    syscall
    
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
    
    mov rax, SYS_ACCESS
    mov rdi, %1                     ; pathname
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

    mov rax, SYS_MKDIR
    mov rdi, %1                     ; pathname
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

    mov rax, SYS_RMDIR
    mov rdi, %1                     ; pathname
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

    mov rax, SYS_CHDIR
    mov rdi, %1                     ; pathname
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

; Create a device node (character or block special file)
; Args: rdi = path, rsi = mode (S_IFCHR/S_IFBLK | perms), rdx = dev (major<<8 | minor)
; (all pre-loaded by codegen)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro MKNOD 0
    push rbx
    push rcx

    mov rax, SYS_MKNOD
    syscall

    test rax, rax
    jns %%mknod_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%mknod_done
%%mknod_ok:
    mov qword [rel _last_error], 0
%%mknod_done:

    pop rcx
    pop rbx
%endmacro

; Mount a filesystem
; Args (pre-loaded by codegen): rdi = source, rsi = target, rdx = fstype
; (or NULL), r10 = mountflags, r8 = data/options (or NULL)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro MOUNT 0
    push rbx
    push rcx
    push r9

    mov rax, SYS_MOUNT
    syscall

    test rax, rax
    jns %%mount_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%mount_done
%%mount_ok:
    mov qword [rel _last_error], 0
%%mount_done:

    pop r9
    pop rcx
    pop rbx
%endmacro

; Switch the root filesystem (used during initramfs -> real root handoff)
; Args (pre-loaded by codegen): rdi = new_root, rsi = put_old
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro PIVOT_ROOT 0
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov rax, SYS_PIVOT_ROOT
    syscall

    test rax, rax
    jns %%pivot_root_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%pivot_root_done
%%pivot_root_ok:
    mov qword [rel _last_error], 0
%%pivot_root_done:

    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Replace the current process image
; Args (pre-loaded by codegen): rdi = path, rsi = argv, rdx = envp
; execve() only ever returns on failure (the process image is replaced on
; success, so there is no "success" path to preserve registers for).
; Returns: negative errno in rax (only reachable on error). Sets _last_error.
%macro EXECVE 0
    mov rax, SYS_EXECVE
    syscall

    ; Only reachable if execve failed
    neg rax
    mov [rel _last_error], rax
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
    
    mov rax, SYS_UNLINK
    mov rdi, %1                     ; pathname
    syscall
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro
