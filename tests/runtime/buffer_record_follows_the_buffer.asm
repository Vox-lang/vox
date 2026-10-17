; The buffer record follows each buffer, whichever module moves or frees it,
; and a released list or buffer is recognised by its mark, whichever module's
; released header it is.
;
; Not expressible in one Vox program: the record and the released headers
; are per module (a program and each `.so` have their own), and what matters
; is how one module's runtime treats ANOTHER module's buffer or header. This
; driver plays the other module itself: `foreign_entry` stands for an entry
; of another module's buffer table, and the two `foreign_released_*` headers
; stand for another module's released headers (same shape, different
; address). Exit 0 = pass; each failed check exits with its own number.

%include "coreasm/x86_64/core.asm"
%include "coreasm/x86_64/io.asm"
%include "coreasm/x86_64/string.asm"
%include "coreasm/x86_64/resource_fd.asm"
%include "coreasm/x86_64/resource_buffer.asm"
%include "coreasm/x86_64/resource_render.asm"
%include "coreasm/x86_64/list.asm"

section .data
    ; Another module's released headers: the record word (0), then the header.
                                dq 0
    foreign_released_buffer:    dq 0, 0, BUF_FLAG_FIXED | BUF_FLAG_RELEASED
                                db 0
    foreign_released_list:      dq 0, 0, 0

section .bss
    foreign_entry: resq 1

section .text
global _start

_start:
    ; 1. A new buffer is recorded in this module's table, and its record
    ;    word names the entry that holds it.
    call _alloc_buffer
    mov r12, rax
    mov rbx, [r12 + BUF_RECORD]
    test rbx, rbx
    jz .fail_1
    cmp [rbx], r12
    jne .fail_1

    ; 2. Hand the buffer to "another module": its entry is now foreign_entry.
    mov qword [rbx], 0
    mov [rel foreign_entry], r12
    lea rax, [rel foreign_entry]
    mov [r12 + BUF_RECORD], rax

    ; 3. Moved by the copy path (an exact reallocation to the same capacity
    ;    always maps a new block): the other module's entry follows it.
    mov rdi, r12
    mov rsi, 4096
    call _reallocate_buffer
    cmp rax, r12
    je .fail_3                       ; the copy path always moves
    mov r12, rax
    cmp [rel foreign_entry], r12
    jne .fail_3
    lea rax, [rel foreign_entry]
    cmp [r12 + BUF_RECORD], rax
    jne .fail_3

    ; 4. Grown far past its capacity (mremap, which may move it): the entry
    ;    still names the buffer.
    mov rdi, r12
    mov rsi, 1048576
    call _grow_buffer
    mov r12, rax
    cmp qword [r12 + BUF_CAPACITY], 1048576
    jl .fail_4
    cmp [rel foreign_entry], r12
    jne .fail_4

    ; 5. Resized by `Resize` (shrinking takes the alloc-and-copy path): the
    ;    old entry is cleared, and the new buffer is recorded by the module
    ;    that mapped it, this one.
    mov rdi, r12
    mov rsi, 16
    call _realloc_buffer
    mov r12, rax
    cmp qword [rel foreign_entry], 0
    jne .fail_5
    mov rbx, [r12 + BUF_RECORD]
    test rbx, rbx
    jz .fail_5
    cmp [rbx], r12
    jne .fail_5

    ; 6. Freed: its entry is cleared.
    mov rdi, r12
    call _free_buffer
    cmp qword [rbx], 0
    jne .fail_6
    cmp qword [rel _last_error], 0
    jne .fail_6

    ; 7. Another module's released buffer is refused by Free, Resize and
    ;    growth, each with the error flag, and nothing is unmapped (the
    ;    header is still readable afterwards).
    lea rdi, [rel foreign_released_buffer]
    call _free_buffer
    cmp qword [rel _last_error], 1
    jne .fail_7
    CLEAR_LAST_ERROR
    lea rdi, [rel foreign_released_buffer]
    mov rsi, 64
    call _realloc_buffer
    lea rcx, [rel foreign_released_buffer]
    cmp rax, rcx
    jne .fail_7
    cmp qword [rel _last_error], 1
    jne .fail_7
    CLEAR_LAST_ERROR
    lea rdi, [rel foreign_released_buffer]
    mov rsi, 64
    call _reallocate_buffer
    lea rcx, [rel foreign_released_buffer]
    cmp rax, rcx
    jne .fail_7
    cmp qword [rel _last_error], 1
    jne .fail_7
    CLEAR_LAST_ERROR

    ; 8. Another module's released list is refused by append and by Free.
    lea rdi, [rel foreign_released_list]
    mov rsi, 7
    xor edx, edx
    call _list_append
    lea rcx, [rel foreign_released_list]
    cmp rax, rcx
    jne .fail_8
    cmp qword [rel _last_error], 1
    jne .fail_8
    CLEAR_LAST_ERROR
    mov qword [rel _free_visited_count], 0
    lea rdi, [rel foreign_released_list]
    call _free_list
    cmp qword [rel _last_error], 1
    jne .fail_8
    CLEAR_LAST_ERROR

    ; 9. A copy of a released list is a live, empty list of its own: element
    ;    size 8, and an append to it works.
    lea rdi, [rel foreign_released_list]
    call _copy_list
    mov r12, rax
    cmp qword [r12 + LIST_ELEMSIZE_OFFSET], 8
    jne .fail_9
    cmp qword [r12 + LIST_LENGTH_OFFSET], 0
    jne .fail_9
    mov rdi, r12
    mov rsi, 7
    xor edx, edx
    call _list_append
    cmp qword [rel _last_error], 0
    jne .fail_9
    cmp qword [rax + LIST_LENGTH_OFFSET], 1
    jne .fail_9

    ; 10. The unload sweep empties this module's record.
    call _alloc_buffer
    call _alloc_buffer
    call _sweep_buffer_record
    lea rbx, [rel buf_table]
    xor rcx, rcx
.check_swept:
    cmp rcx, MAX_BUFFERS
    jge .pass
    cmp qword [rbx + rcx*8], 0
    jne .fail_10
    inc rcx
    jmp .check_swept

.pass:
    EXIT 0
.fail_1:
    EXIT 1
.fail_3:
    EXIT 3
.fail_4:
    EXIT 4
.fail_5:
    EXIT 5
.fail_6:
    EXIT 6
.fail_7:
    EXIT 7
.fail_8:
    EXIT 8
.fail_9:
    EXIT 9
.fail_10:
    EXIT 10
