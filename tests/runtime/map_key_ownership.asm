; Map keys must be owned by the map, not borrowed from the caller.
;
; Not expressible in Vox: the analyzer rejects a buffer as a map key, and a
; quoted name in key position is read literally, so no Vox program can hand
; _map_insert memory it later mutates. A JSON parser will - it slices keys out
; of the input buffer it is decoding - so the invariant is checked here by
; calling the runtime directly.
;
; Before the key copy, overwriting the caller's buffer made the entry
; unreachable by ANY key: "alpha" no longer matched the (now mutated) stored
; pointer, and "ZZZZZ" hashed to a different bucket than the entry was filed
; under. Exit 0 = pass, 1 = fail.

%define __MAP_ASM_INCLUDED__
%include "coreasm/x86_64/core.asm"
%include "coreasm/x86_64/io.asm"
%include "coreasm/x86_64/string.asm"
%include "coreasm/x86_64/list.asm"
%include "coreasm/x86_64/map.asm"

section .data
    k_alpha:  db "alpha", 0
    k_zzzzz:  db "ZZZZZ", 0

section .bss
    scratch:  resb 32          ; caller memory the map must not depend on

section .text
global _start

; Copy a NUL-terminated literal into `scratch`. rsi = source.
%macro FILL_SCRATCH 1
    lea rsi, [rel %1]
    lea rdi, [rel scratch]
    call _copy_cstr
%endmacro

_start:
    ; m = _map_new(8)
    mov rdi, 8
    call _map_new
    mov r12, rax                    ; r12 = map

    ; scratch = "alpha"; insert it, keyed by the scratch pointer
    FILL_SCRATCH k_alpha
    mov rdi, r12
    lea rsi, [rel scratch]
    mov rdx, 111                    ; value
    xor rcx, rcx                    ; tag = integer
    call _map_insert
    mov r12, rax

    ; Reuse the buffer, exactly as a parser decoding the next token would.
    FILL_SCRATCH k_zzzzz

    ; The original key must still resolve, to its original value.
    mov qword [rel _last_error], 0
    mov rdi, r12
    lea rsi, [rel k_alpha]
    call _map_lookup
    cmp rax, 111
    jne .fail
    cmp qword [rel _last_error], 0
    jne .fail

    ; The mutated text must NOT have become a key.
    mov qword [rel _last_error], 0
    mov rdi, r12
    lea rsi, [rel k_zzzzz]
    call _map_lookup
    cmp qword [rel _last_error], 0
    je .fail                        ; a hit here means the key aliased

    EXIT 0

.fail:
    EXIT 1

; Copy a NUL-terminated string. rsi = src, rdi = dest. Clobbers rax, rsi, rdi.
_copy_cstr:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .done
    inc rsi
    inc rdi
    jmp _copy_cstr
.done:
    ret
