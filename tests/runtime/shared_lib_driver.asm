; Phase 2 cross-boundary driver for libmath.so (built from
; tests/shared/libmath.vox with `vox --shared`).
;
; Links against the shared library and calls its three exports through the
; PLT, proving the Vox calling convention survives the .so boundary and that
; the library's own coreasm runtime works when driven from a foreign host:
;
;   add_two(40) -> 42        arithmetic; one scalar arg in rdi, result in rax
;   makebuf()    -> 5        buffer registration via resource.asm (Phase 1 PIC
;                            tables) — the case that could not relocate before
;                            the lea [rel] rewrite
;   greet()      prints      "hello from libmath" (io/format includes)
;
; The library carries its own runtime; the driver references only the three
; exported labels (the version script keeps every coreasm symbol local, so
; nothing else is even visible to link against). Exit 0 = pass, 1 = fail.
;
; nasm + ld only — no C, no libc — so this always runs and can never silently
; skip the way a `command -v cc` guarded dlopen driver would. Follows the
; tests/runtime/map_key_ownership.asm pattern.

global _start

extern add_two
extern greet
extern makebuf

section .text
_start:
    ; Force 16-byte stack alignment before calling into the .so. At process
    ; entry the loader's alignment is not guaranteed for SysV calls, and the
    ; Vox prologue (push rbp) assumes the caller honoured it.
    and rsp, -16

    ; add_two(40) == 42 — proves a scalar arg crosses the boundary and the
    ; result returns in rax.
    mov rdi, 40
    call add_two
    cmp rax, 42
    jne .fail

    ; makebuf() == 5 — creates a buffer inside the library, registering it in
    ; buf_table. This is the resource.asm access that was 34 absolute
    ; relocations before Phase 1; if the PIC rewrite is wrong the library
    ; traps here.
    call makebuf
    cmp rax, 5
    jne .fail

    ; greet() prints the line; the harness compares the driver's stdout.
    call greet

    ; Exit 0 (SYS_exit). No libc, so no EXIT wrapper — raw syscall.
    mov rax, 60
    xor rdi, rdi
    syscall

.fail:
    mov rax, 60
    mov rdi, 1
    syscall