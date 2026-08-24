; proc.asm - Process / system-control macros
; Split from file.asm (audit rec 2). fork/wait4/kill/execve/mount/umount/
; reboot/pivot_root/mknod live here so a program that only does filesystem
; I/O (open/read/write/close/delete/mkdir/rmdir/chdir/symlink) no longer
; drags these syscall numbers and register layouts into its binary.
;
; Gated on uses_proc (set by the Mount/Reboot/Halt/Shutdown/Unmount/
; PivotRoot/Execute/SendSignal/Mknod statements). Those statements also
; set uses_files, so file.asm is included before this module and its
; syscall defines are visible; the process-control defines are duplicated
; here so proc.asm is self-contained for its own macros.
; Linux x86_64 syscall numbers (process control)
%define SYS_MKNOD   133
%define SYS_MOUNT   165
%define SYS_UMOUNT2 166
%define SYS_PIVOT_ROOT 155
%define SYS_SYNC    162
%define SYS_REBOOT  169
%define SYS_FORK    57
%define SYS_WAIT4   61
%define SYS_KILL    62
; reboot(2) magic values (see linux/reboot.h)
%define LINUX_REBOOT_MAGIC1 0xFEE1DEAD
%define LINUX_REBOOT_MAGIC2 672274793
%define SYS_EXECVE  59

section .text

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

; Unmount a filesystem
; Args (pre-loaded by codegen): rdi = target path, rsi = flags
; (0 = normal, 2 = MNT_DETACH / lazy)
; Returns: 0 in rax on success, negative on error. Sets _last_error.
%macro UMOUNT 0
    push rbx
    push rcx
    push rdx

    mov rax, SYS_UMOUNT2
    syscall

    test rax, rax
    jns %%umount_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%umount_done
%%umount_ok:
    mov qword [rel _last_error], 0
%%umount_done:

    pop rdx
    pop rcx
    pop rbx
%endmacro

; Reboot / power off / halt the machine via reboot(2).
; Arg: %1 = LINUX_REBOOT_CMD_* command constant.
; Flushes filesystem buffers with sync(2) first so nothing in the page
; cache is lost. Requires CAP_SYS_BOOT (root). On success POWER_OFF/
; RESTART/HALT do not return; if the call fails (e.g. not privileged) it
; returns -errno, which is recorded in _last_error so `On error` works.
%macro REBOOT_CMD 1
    ; sync() - no error path, returns void
    mov rax, SYS_SYNC
    syscall

    mov rax, SYS_REBOOT
    mov rdi, LINUX_REBOOT_MAGIC1
    mov rsi, LINUX_REBOOT_MAGIC2
    mov rdx, %1
    xor r10, r10                    ; arg = NULL
    syscall

    ; Only reached on failure
    neg rax
    mov [rel _last_error], rax
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

; Create a new process (fork(2))
; Returns: rax = 0 in the child, the child's pid in the parent, negative
; on error. This IS the expression's result (used directly in comparisons
; like "if pid is less than 0"), so unlike the error-only macros above we
; preserve the original value in rax while still setting _last_error.
%macro FORK 0
    mov rax, SYS_FORK
    syscall

    cmp rax, 0
    jl %%fork_error
    mov qword [rel _last_error], 0
    jmp %%fork_done
%%fork_error:
    push rax
    neg rax
    mov [rel _last_error], rax
    pop rax
%%fork_done:
%endmacro

; Reap a child process (wait4(2)), capturing the raw exit-status word.
; Input: rdi = pid to wait for (-1 = any child), pre-loaded by codegen.
;         %1 = options (0 = blocking, 1 = WNOHANG/non-blocking)
; Returns: rax = the reaped child's pid, 0 if WNOHANG and no child finished
;          yet (NOT an error), or negative on error - this IS the
;          expression's result, preserved the same way as FORK above.
; The kernel writes the raw status word to _reaped_status only when a child
; is actually reaped (rax > 0). With WNOHANG returning 0 (nothing finished
; yet) or on error (rax < 0), the status pointer is left untouched, so the
; previous value is preserved - "nothing reaped" never disturbs the status.
%macro REAP_CHILD 1
    lea rsi, [rel _reaped_status]  ; status pointer -> raw wait4 status word (plan 311)
    mov rdx, %1                    ; options (0 = blocking, 1 = WNOHANG)
    xor r10, r10                   ; rusage = NULL
    mov rax, SYS_WAIT4
    syscall

    cmp rax, 0
    jl %%reap_error
    ; rax > 0: a child was reaped, and the kernel wrote the low 32 bits of
    ; _reaped_status (its `int status` is 4 bytes). The high dword is stale
    ; (e.g. the -1 sentinel's 0xFFFFFFFF), so a 64-bit read would be wrong -
    ; zero-extend the 32-bit word into the full 64-bit global now. rax (the
    ; pid, the expression result) is preserved; rcx is already clobbered by
    ; the syscall itself.
    ; rax == 0 (WNOHANG, nothing finished yet): the kernel did not write
    ; status, so leave _reaped_status untouched - "nothing reaped" never
    ; disturbs the previous value.
    test rax, rax
    jz %%reap_nothing
    mov ecx, [rel _reaped_status]
    mov [rel _reaped_status], rcx
%%reap_nothing:
    mov qword [rel _last_error], 0
    jmp %%reap_done
%%reap_error:
    push rax
    neg rax
    mov [rel _last_error], rax
    pop rax
%%reap_done:
%endmacro

; Send a signal to a process (kill(2)).
; Args (pre-loaded by codegen): rdi = pid, rsi = signal.
; Returns: 0 in rax on success, negative on error. Sets _last_error on
; failure (ESRCH, EINVAL, EPERM) and clears it on success, exactly like
; the other syscall statements. This is a statement, not an expression,
; so rax is not consumed afterwards - but the registers the surrounding
; code may hold values in are preserved across the syscall.
%macro SEND_SIGNAL 0
    push rbx
    push rcx
    push rdx

    mov rax, SYS_KILL
    syscall

    test rax, rax
    jns %%kill_ok
    neg rax
    mov [rel _last_error], rax
    jmp %%kill_done
%%kill_ok:
    mov qword [rel _last_error], 0
%%kill_done:

    pop rdx
    pop rcx
    pop rbx
%endmacro
