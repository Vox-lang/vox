; int.asm - Integer operations for Vox Compiler
; x86-64 implementation

section .text

; Integer arithmetic - operates on rax and rbx, result in rax
%macro INT_ADD 0
    add rax, rbx
%endmacro

%macro INT_SUB 0
    sub rax, rbx
%endmacro

%macro INT_MUL 0
    imul rax, rbx
%endmacro

%macro INT_DIV 0
    test rbx, rbx
    jz %%div_zero
    mov qword [rel _last_error], 0
    cqo
    idiv rbx
    jmp %%div_done
%%div_zero:
    xor rax, rax
    mov qword [rel _last_error], 1
%%div_done:
%endmacro

%macro INT_MOD 0
    test rbx, rbx
    jz %%mod_zero
    mov qword [rel _last_error], 0
    cqo
    idiv rbx
    mov rax, rdx
    jmp %%mod_done
%%mod_zero:
    xor rax, rax
    mov qword [rel _last_error], 1
%%mod_done:
%endmacro

; Integer comparisons - compares rax with rbx, result (0 or 1) in rax
%macro INT_EQ 0
    cmp rax, rbx
    sete al
    movzx rax, al
%endmacro

%macro INT_NE 0
    cmp rax, rbx
    setne al
    movzx rax, al
%endmacro

%macro INT_LT 0
    cmp rax, rbx
    setl al
    movzx rax, al
%endmacro

%macro INT_LE 0
    cmp rax, rbx
    setle al
    movzx rax, al
%endmacro

%macro INT_GT 0
    cmp rax, rbx
    setg al
    movzx rax, al
%endmacro

%macro INT_GE 0
    cmp rax, rbx
    setge al
    movzx rax, al
%endmacro

; Boolean operations
%macro INT_AND 0
    and rax, rbx
%endmacro

%macro INT_OR 0
    or rax, rbx
%endmacro

%macro INT_NOT 0
    test rax, rax
    setz al
    movzx rax, al
%endmacro

; Negate integer in rax
%macro INT_NEG 0
    neg rax
%endmacro

; dl = the byte %1 places ahead of rbx, or 0 when the text has ended there.
; r10 holds how many bytes are left to read (-1: read up to the NUL).
%macro NUMBER_TEXT_BYTE 1
    xor edx, edx
    cmp r10, %1
    jbe %%past_the_end
    mov dl, [rbx + %1]
%%past_the_end:
%endmacro

; Read a text as a number (LANGUAGE.md "Casting Rules"). Every text and
; buffer cast to a number, a number flag and a `value` holding text comes
; through here, by way of the four entry points below.
;
; The text is a number exactly when the WHOLE of it could be written as a
; number literal in Vox source, after one optional '-':
;   - base 0 (no radix word): decimal digits with an optional fractional
;     part ("0234" is 234; "4.8" is 4, the fraction dropped as a float cast
;     to a number drops it), or a whole number after 0x, 0b or 0o;
;   - base 2-36 (a radix cast): only digits of that base, after the base's
;     own prefix when it has one (0x for 16, 0o for 8, 0b for 2).
; No space, '+' or exponent is read, and nothing may follow the number.
;
; The magnitude is built with `mul`, whose high half reports a product
; past 64 bits, and a carry out of the add does the same (sticky in r12).
; After the digits it is range-checked against the sign: at most i64::MAX
; for a positive number, at most 2^63 (i64::MIN's magnitude) for a
; negative one.
;
; Args: rdi = text, rsi = most bytes to read (-1: up to the NUL; a buffer
;       passes its length, since bytes past it may be stale), rdx = base
; Returns: rax = the number, and _last_error = 0; or rax = 0 and
;          _last_error = 1 when the text is not a number
global _read_number_text
_read_number_text:
    push rbx
    push rcx
    push rdx
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12

    mov rbx, rdi                ; reading position
    mov r10, rsi                ; bytes left
    mov r8, rdx                 ; base, 0 for any number literal
    xor r9, r9                  ; 1 when the text opens with '-'
    xor r11, r11                ; digits read
    xor r12, r12                ; overflow (sticky)
    xor rax, rax                ; magnitude

    NUMBER_TEXT_BYTE 0
    cmp dl, '-'
    jne .rnt_prefix
    mov r9, 1
    inc rbx
    dec r10

.rnt_prefix:
    NUMBER_TEXT_BYTE 0
    cmp dl, '0'
    jne .rnt_no_prefix
    NUMBER_TEXT_BYTE 1
    or dl, 0x20                 ; X, B, O read as x, b, o
    mov rcx, 16
    cmp dl, 'x'
    je .rnt_prefix_base
    mov rcx, 2
    cmp dl, 'b'
    je .rnt_prefix_base
    mov rcx, 8
    cmp dl, 'o'
    jne .rnt_no_prefix
.rnt_prefix_base:
    test r8, r8
    jz .rnt_take_prefix         ; no radix word: any of the three
    cmp r8, rcx
    jne .rnt_no_prefix          ; another base's prefix: read as digits
.rnt_take_prefix:
    mov r8, rcx
    add rbx, 2
    sub r10, 2
    xor esi, esi                ; a prefixed number has no fraction
    jmp .rnt_digits

.rnt_no_prefix:
    xor esi, esi
    test r8, r8
    jnz .rnt_digits
    mov r8, 10
    mov rsi, 1                  ; a decimal may have a fractional part

.rnt_digits:
    NUMBER_TEXT_BYTE 0
    cmp dl, '0'
    jb .rnt_digits_read
    cmp dl, '9'
    ja .rnt_letter
    movzx rcx, dl
    sub rcx, '0'
    jmp .rnt_digit
.rnt_letter:
    or dl, 0x20                 ; A-Z read as a-z
    cmp dl, 'a'
    jb .rnt_digits_read
    cmp dl, 'z'
    ja .rnt_digits_read
    movzx rcx, dl
    sub rcx, 'a' - 10
.rnt_digit:
    cmp rcx, r8                 ; a digit of the base, or the digits end
    jae .rnt_digits_read
    mul r8                      ; rdx:rax = rax * base (unsigned)
    or r12, rdx                 ; high half set: past 64 bits
    add rax, rcx
    adc r12, 0                  ; carry out: past 64 bits
    inc rbx
    dec r10
    inc r11
    jmp .rnt_digits

.rnt_digits_read:
    test r11, r11
    jz .rnt_not_a_number
    test rsi, rsi
    jz .rnt_at_the_end
    NUMBER_TEXT_BYTE 0
    cmp dl, '.'
    jne .rnt_at_the_end
    NUMBER_TEXT_BYTE 1          ; a fractional part needs a digit
    cmp dl, '0'
    jb .rnt_not_a_number
    cmp dl, '9'
    ja .rnt_not_a_number
    inc rbx
    dec r10
.rnt_fraction:
    NUMBER_TEXT_BYTE 0
    cmp dl, '0'
    jb .rnt_at_the_end
    cmp dl, '9'
    ja .rnt_at_the_end
    inc rbx
    dec r10
    jmp .rnt_fraction

.rnt_at_the_end:
    NUMBER_TEXT_BYTE 0          ; nothing may follow the number
    test dl, dl
    jnz .rnt_not_a_number
    test r12, r12
    jnz .rnt_not_a_number
    test r9, r9
    jnz .rnt_negative
    test rax, rax               ; positive: at most i64::MAX
    js .rnt_not_a_number
    jmp .rnt_a_number
.rnt_negative:
    mov rdx, 0x8000000000000000 ; negative: at most i64::MIN's magnitude
    cmp rax, rdx
    ja .rnt_not_a_number
    neg rax
.rnt_a_number:
    mov qword [rel _last_error], 0
    jmp .rnt_done
.rnt_not_a_number:
    xor eax, eax
    mov qword [rel _last_error], 1

.rnt_done:
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; The entry points codegen calls. Each passes its text, its length bound
; and its base on to _read_number_text, and keeps rsi and rdx as they were.

; `as a number` of a text. Args: rdi = text
global _parse_i64
_parse_i64:
    push rsi
    push rdx
    mov rsi, -1
    xor edx, edx
    call _read_number_text
    pop rdx
    pop rsi
    ret

; `as a hex/octal/binary/base N number` of a text.
; Args: rdi = text, rsi = base (2-36)
global _parse_int_radix
_parse_int_radix:
    push rsi
    push rdx
    mov rdx, rsi
    mov rsi, -1
    call _read_number_text
    pop rdx
    pop rsi
    ret

; `as a number` of a buffer. Args: rdi = bytes, rsi = the buffer's length
global _parse_i64_bounded
_parse_i64_bounded:
    push rsi
    push rdx
    xor edx, edx
    call _read_number_text
    pop rdx
    pop rsi
    ret

; `as a hex/octal/binary/base N number` of a buffer.
; Args: rdi = bytes, rsi = base (2-36), rdx = the buffer's length
global _parse_int_radix_bounded
_parse_int_radix_bounded:
    push rsi
    push rdx
    xchg rsi, rdx
    call _read_number_text
    pop rdx
    pop rsi
    ret
