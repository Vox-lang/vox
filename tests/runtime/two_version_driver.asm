; Plan 230 stage A2 cross-boundary driver for libflags.so, built from
; tests/shared/flags_0_1.vox and tests/shared/flags_1_0.vox with
; `vox flags_0_1.vox flags_1_0.vox --shared -o libflags.so`.
;
; Both inputs define `hasflag`, but they are different versions of the same
; library, so the mangling keeps them apart as distinct dynamic symbols:
;
;   flags_0_1_hasflag(5) -> 6    version 0.1 returns n add 1
;   flags_1_0_hasflag(5) -> 105  version 1.0 returns n add 100
;
; This is the backwards-compatibility case the entire multi-version design
; exists for: an old program linked against 0.1 and a new program linked against
; 1.0 can both be satisfied by ONE .so carrying both. The driver calls both and
; asserts each result, so a regression that collapses the two versions back
; onto a single body (the A1 collision: name-keyed tables letting the second
; library's signature overwrite the first's) fails here instead of shipping.
;
; Exit 0 = pass; 2 = version 0.1 returned the wrong value; 3 = version 1.0 did
; — so test.sh can name which assertion broke. nasm + ld only, no libc; the
; library carries its own coreasm runtime, the driver references only the two
; exported labels (the version script hides everything else).

global _start

extern flags_0_1_hasflag
extern flags_1_0_hasflag

section .text
_start:
    ; Force 16-byte stack alignment before calling into the .so (the loader's
    ; entry alignment is not guaranteed for SysV calls).
    and rsp, -16

    ; flags_0_1_hasflag(5) == 6 — the 0.1 version of the library.
    mov rdi, 5
    call flags_0_1_hasflag
    cmp rax, 6
    jne .fail_v0_1

    ; flags_1_0_hasflag(5) == 105 — the 1.0 version. A collision that let the
    ; second library's body overwrite the first's (or vice versa) makes one of
    ; these two calls return the other's value, so both are checked.
    mov rdi, 5
    call flags_1_0_hasflag
    cmp rax, 105
    jne .fail_v1_0

    ; Exit 0 (SYS_exit). No libc, so raw syscall.
    mov rax, 60
    xor rdi, rdi
    syscall

.fail_v0_1:
    mov rax, 60
    mov rdi, 2
    syscall
.fail_v1_0:
    mov rax, 60
    mov rdi, 3
    syscall