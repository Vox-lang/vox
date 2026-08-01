; string.asm - String operations for Vox Compiler

section .text

%macro STR_LEN 1
    push rdi
    push rcx
    
    mov rdi, %1
    xor rcx, rcx
    
%%len_loop:
    cmp byte [rdi + rcx], 0
    je %%len_done
    inc rcx
    jmp %%len_loop
    
%%len_done:
    mov rax, rcx
    
    pop rcx
    pop rdi
%endmacro

%macro STR_COPY 2
    push rax
    push rdi
    push rsi
    
    mov rdi, %1
    mov rsi, %2
    
%%copy_loop:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz %%copy_done
    inc rsi
    inc rdi
    jmp %%copy_loop
    
%%copy_done:
    pop rsi
    pop rdi
    pop rax
%endmacro

%macro STR_CMP 2
    push rdi
    push rsi
    push rbx
    
    mov rdi, %1
    mov rsi, %2
    
%%cmp_loop:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne %%cmp_diff
    test al, al
    jz %%cmp_equal
    inc rdi
    inc rsi
    jmp %%cmp_loop
    
%%cmp_diff:
    movzx rax, al
    movzx rbx, bl
    sub rax, rbx
    jmp %%cmp_done
    
%%cmp_equal:
    xor rax, rax
    
%%cmp_done:
    pop rbx
    pop rsi
    pop rdi
%endmacro


; String equality function (callable)
; Args: rdi = string1, rsi = string2
; Returns: rax = 1 if equal, 0 if not
; NULL-safe: a NULL pointer represents a legitimately absent value (e.g.
; `arguments's first` when no user argument was given returns NULL, not an
; empty string) and must compare as not-equal to any real string rather
; than being dereferenced. Identical pointers (including both NULL) are
; trivially equal without touching memory.
global _str_eq
_str_eq:
    push rbx
    cmp rdi, rsi
    je .equal
    test rdi, rdi
    jz .not_equal
    test rsi, rsi
    jz .not_equal
.loop:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne .not_equal
    test al, al
    jz .equal
    inc rdi
    inc rsi
    jmp .loop
.not_equal:
    xor rax, rax
    pop rbx
    ret
.equal:
    mov rax, 1
    pop rbx
    ret

; Copy a string, bounded by an explicit max length rather than scanning
; indefinitely for a NUL terminator. Needed for buffer content:
; _buffer_clear only zeroes the buffer's first byte (a cheap "empty"
; marker), not the whole allocation, so a buffer that held a longer
; value before being cleared and rewritten with something shorter can
; have stale non-NUL bytes sitting right after its new logical content
; - an unbounded copy would read straight through those stale bytes.
; Still stops early at a genuine NUL within the bound, and the result
; is always NUL-terminated.
; Args: rdi = source pointer, rsi = max length in bytes (e.g. the
; buffer's own tracked length via _buffer_length)
; Returns: rax = pointer to a freshly allocated, NUL-terminated copy
; (or 0 on allocation failure)
global _strdup_bounded
_strdup_bounded:
    push rbx
    push r12
    push r13

    mov r12, rdi            ; save source pointer

    ; Find the actual length to copy: stop at max_len OR an early NUL,
    ; whichever comes first.
    xor rcx, rcx
.strdupb_len:
    cmp rcx, rsi
    jge .strdupb_len_done
    cmp byte [rdi + rcx], 0
    je .strdupb_len_done
    inc rcx
    jmp .strdupb_len
.strdupb_len_done:
    mov r13, rcx             ; save actual length (not including NUL)

    ; Allocate memory via mmap (actual length + 1 for NUL terminator)
    mov rax, 9               ; sys_mmap
    mov rdi, 0               ; addr = NULL
    mov rsi, r13
    inc rsi                  ; +1 for NUL terminator
    add rsi, 4095
    and rsi, ~4095           ; page-align
    mov rdx, 3               ; PROT_READ | PROT_WRITE
    mov r10, 0x22            ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1               ; fd = -1
    mov r9, 0                ; offset = 0
    syscall

    cmp rax, -4096           ; raw mmap returns -errno in [-4095,-1]
    ja .strdupb_fail

    mov rbx, rax             ; save dest pointer

    xor rcx, rcx
.strdupb_copy:
    cmp rcx, r13
    jge .strdupb_terminate
    mov al, [r12 + rcx]
    mov [rbx + rcx], al
    inc rcx
    jmp .strdupb_copy

.strdupb_terminate:
    mov byte [rbx + r13], 0  ; NUL-terminate the copy

    mov rax, rbx             ; return new string pointer
    pop r13
    pop r12
    pop rbx
    ret

.strdupb_fail:
    xor rax, rax
    pop r13
    pop r12
    pop rbx
    ret

; Compare two byte sequences of known lengths for equality. Used for
; buffer-vs-buffer and buffer-vs-string comparison where one or both
; sides may have stale bytes beyond the logical content.
; Args: rdi = ptr1, rsi = ptr2, rdx = len1, rcx = len2
; Returns: rax = 1 if equal, 0 if not equal
; (Two sequences are equal iff they have the same length AND identical bytes.)
global _mem_eq
_mem_eq:
    push rbx
    push r8
    push r9

    ; Unequal lengths -> immediately not equal
    cmp rdx, rcx
    jne .mem_not_equal

    ; Zero length -> equal (both empty)
    test rdx, rdx
    jz .mem_equal

    xor r8, r8              ; byte index

.mem_loop:
    cmp r8, rdx
    jge .mem_equal
    mov al, [rdi + r8]
    mov bl, [rsi + r8]
    cmp al, bl
    jne .mem_not_equal
    inc r8
    jmp .mem_loop

.mem_equal:
    mov rax, 1
    pop r9
    pop r8
    pop rbx
    ret

.mem_not_equal:
    xor rax, rax
    pop r9
    pop r8
    pop rbx
    ret

; Get the length of a NUL-terminated string (strlen equivalent).
; Args: rdi = string pointer
; Returns: rax = length (not including the NUL terminator)
global _str_len
_str_len:
    push rcx
    xor rax, rax
.strlen_loop:
    cmp byte [rdi + rax], 0
    je .strlen_done
    inc rax
    jmp .strlen_loop
.strlen_done:
    pop rcx
    ret

; Convert a NUL-terminated text string to a boolean value.
; Returns 1 if the string equals "true" (case-insensitive), 0 otherwise.
; "false" and any other string therefore produce 0, matching the only
; text-to-boolean case documented in LANGUAGE.md.
global _text_to_boolean
_text_to_boolean:
    push rbx

    test rdi, rdi
    jz .tb_false

    mov rbx, rdi

    ; Must be exactly 4 characters followed by NUL.
    cmp byte [rbx + 4], 0
    jne .tb_false

    mov al, [rbx]
    or al, 0x20
    cmp al, 't'
    jne .tb_false

    mov al, [rbx + 1]
    or al, 0x20
    cmp al, 'r'
    jne .tb_false

    mov al, [rbx + 2]
    or al, 0x20
    cmp al, 'u'
    jne .tb_false

    mov al, [rbx + 3]
    or al, 0x20
    cmp al, 'e'
    jne .tb_false

    mov rax, 1
    pop rbx
    ret

.tb_false:
    xor rax, rax
    pop rbx
    ret
