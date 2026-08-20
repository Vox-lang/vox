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

; Parse signed integer from string
; Args: rdi = string pointer
; Returns: rax = parsed integer (0 on empty/invalid prefix, or a wrapped
; value on magnitude overflow - the error flag is authoritative, not rax)
;
; The accumulator is built as an unsigned magnitude via `mul` (which
; reports a truncated 64-bit product through a nonzero high half),
; unlike the old `imul` which silently wrapped. A sticky flag alone is
; not enough, though: 2^63 (9223372036854775808) fits in 64 unsigned
; bits without tripping it, yet is only a valid i64 as the MAGNITUDE of
; i64::MIN, not as a positive value. So after the loop the magnitude is
; range-checked against the sign: <= i64::MAX for a positive number,
; <= 2^63 (i64::MIN's magnitude) for a negative one. Either check
; failing, or the sticky flag, sets the error flag - this range check
; is what bug #35 was missing entirely.
global _parse_i64
_parse_i64:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    xor rax, rax              ; accumulator (unsigned magnitude)
    xor rcx, rcx               ; sign flag (0=+,1=-)
    xor r8, r8                ; parsed-a-digit flag
    xor r9, r9                 ; overflow-sticky flag
    mov r11, 10                 ; base-10 multiplier for `mul`
    mov rbx, rdi

    mov r10b, [rbx]
    cmp r10b, '-'
    jne .pi64_loop
    mov rcx, 1
    inc rbx

.pi64_loop:
    mov r10b, [rbx]
    test r10b, r10b
    jz .pi64_done
    cmp r10b, '0'
    jl .pi64_done
    cmp r10b, '9'
    jg .pi64_done
    sub r10b, '0'
    movzx r10, r10b

    mul r11                   ; rdx:rax = rax * 10 (unsigned)
    or r9, rdx                 ; sticky: high bits nonzero -> overflow
    add rax, r10
    adc r9, 0                   ; sticky: carry out of the add -> overflow

    inc rbx
    mov r8, 1
    jmp .pi64_loop

.pi64_done:
    test r8, r8
    jz .pi64_no_digits
    test rcx, rcx
    jnz .pi64_check_neg
    test rax, rax              ; positive: magnitude must fit under i64::MAX
    js .pi64_set_overflow
    jmp .pi64_range_ok
.pi64_check_neg:
    mov r10, 0x8000000000000000   ; negative: magnitude may reach i64::MIN's
    cmp rax, r10
    ja .pi64_set_overflow
    jmp .pi64_range_ok
.pi64_set_overflow:
    mov r9, 1
.pi64_range_ok:
    test r9, r9
    jnz .pi64_overflow_err
    mov qword [rel _last_error], 0
    jmp .pi64_sign
.pi64_no_digits:
    mov qword [rel _last_error], 1
    jmp .pi64_sign
.pi64_overflow_err:
    mov qword [rel _last_error], 1
.pi64_sign:
    test rcx, rcx
    jz .pi64_ret
    neg rax

.pi64_ret:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a signed integer from a string in an arbitrary base (2-36).
; Supports both cases of alphabetic digits (a-z / A-Z, values 10-35).
; Backs "as a hex/octal/binary/base N number" casts - _parse_i64 above
; remains the dedicated base-10 path and is untouched.
; Args: rdi = string pointer, rsi = base (2-36)
; Returns: rax = parsed integer (0 on empty/invalid prefix, or a wrapped
; value on magnitude overflow - the error flag is authoritative, not rax)
; See _parse_i64 above for the overflow-detection rationale; this is the
; same sticky-flag-plus-sign-aware-range-check design, generalised to an
; arbitrary base via `mul r8` instead of a fixed multiplier register.
global _parse_int_radix
_parse_int_radix:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    mov r8, rsi                ; base
    xor rax, rax               ; accumulator
    xor r9, r9                  ; sign flag (0=+, 1=-)
    xor r10, r10                ; parsed-a-digit flag
    xor r11, r11                 ; overflow-sticky flag
    mov rbx, rdi

    mov dl, [rbx]
    cmp dl, '-'
    jne .pir_loop
    mov r9, 1
    inc rbx

.pir_loop:
    mov dl, [rbx]
    test dl, dl
    jz .pir_done

    cmp dl, '0'
    jl .pir_done
    cmp dl, '9'
    jg .pir_alpha
    movzx rcx, dl
    sub rcx, '0'
    jmp .pir_check

.pir_alpha:
    mov cl, dl
    or cl, 0x20               ; fold to lowercase (a-z / A-Z -> a-z)
    cmp cl, 'a'
    jl .pir_done
    cmp cl, 'z'
    jg .pir_done
    movzx rcx, cl
    sub rcx, 'a'
    add rcx, 10

.pir_check:
    cmp rcx, r8                ; digit value must be < base, else stop
    jge .pir_done

    mul r8                     ; rdx:rax = rax * base (unsigned)
    or r11, rdx                 ; sticky: high bits nonzero -> overflow
    add rax, rcx
    adc r11, 0                   ; sticky: carry out of the add -> overflow

    inc rbx
    mov r10, 1
    jmp .pir_loop

.pir_done:
    test r10, r10
    jz .pir_no_digits
    test r9, r9
    jnz .pir_check_neg
    test rax, rax               ; positive: magnitude must fit under i64::MAX
    js .pir_set_overflow
    jmp .pir_range_ok
.pir_check_neg:
    mov rdx, 0x8000000000000000    ; negative: magnitude may reach i64::MIN's
    cmp rax, rdx
    ja .pir_set_overflow
    jmp .pir_range_ok
.pir_set_overflow:
    mov r11, 1
.pir_range_ok:
    test r11, r11
    jnz .pir_overflow_err
    mov qword [rel _last_error], 0
    jmp .pir_sign
.pir_no_digits:
    mov qword [rel _last_error], 1
    jmp .pir_sign
.pir_overflow_err:
    mov qword [rel _last_error], 1
.pir_sign:
    test r9, r9
    jz .pir_ret
    neg rax

.pir_ret:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a signed base-10 integer from a LENGTH-BOUNDED byte range,
; rather than scanning for a NUL terminator. Needed for buffer content:
; _buffer_clear only zeroes the buffer's first byte (a cheap "empty"
; marker), not the whole allocation - so a buffer that held a longer
; value before being cleared and rewritten with something shorter can
; have stale non-NUL bytes sitting right after its new logical content.
; A NUL-scanning parse would read straight through those stale bytes.
; Args: rdi = pointer, rsi = max length in bytes (e.g. buffer's own
; tracked length via _buffer_length)
; Returns: rax = parsed integer (0 on empty/invalid prefix, or a wrapped
; value on magnitude overflow - the error flag is authoritative, not rax)
; See _parse_i64 above for the overflow-detection rationale.
global _parse_i64_bounded
_parse_i64_bounded:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12

    xor rax, rax               ; accumulator
    xor rcx, rcx                ; sign flag (0=+, 1=-)
    xor r9, r9                  ; parsed-a-digit flag
    xor r11, r11                 ; overflow-sticky flag
    mov r12, 10                   ; base-10 multiplier for `mul`
    mov rbx, rdi
    mov r8, rsi                ; remaining length

    test r8, r8
    jz .pi64b_no_digits

    mov r10b, [rbx]
    cmp r10b, '-'
    jne .pi64b_loop
    mov rcx, 1
    inc rbx
    dec r8

.pi64b_loop:
    test r8, r8
    jz .pi64b_done
    mov r10b, [rbx]
    test r10b, r10b
    jz .pi64b_done
    cmp r10b, '0'
    jl .pi64b_done
    cmp r10b, '9'
    jg .pi64b_done
    sub r10b, '0'
    movzx r10, r10b

    mul r12                    ; rdx:rax = rax * 10 (unsigned)
    or r11, rdx                  ; sticky: high bits nonzero -> overflow
    add rax, r10
    adc r11, 0                    ; sticky: carry out of the add -> overflow

    inc rbx
    dec r8
    mov r9, 1
    jmp .pi64b_loop

.pi64b_done:
    test r9, r9
    jz .pi64b_no_digits
    test rcx, rcx
    jnz .pi64b_check_neg
    test rax, rax                ; positive: magnitude must fit under i64::MAX
    js .pi64b_set_overflow
    jmp .pi64b_range_ok
.pi64b_check_neg:
    mov r10, 0x8000000000000000     ; negative: magnitude may reach i64::MIN's
    cmp rax, r10
    ja .pi64b_set_overflow
    jmp .pi64b_range_ok
.pi64b_set_overflow:
    mov r11, 1
.pi64b_range_ok:
    test r11, r11
    jnz .pi64b_overflow_err
    mov qword [rel _last_error], 0
    jmp .pi64b_sign
.pi64b_no_digits:
    mov qword [rel _last_error], 1
    jmp .pi64b_sign
.pi64b_overflow_err:
    mov qword [rel _last_error], 1
.pi64b_sign:
    test rcx, rcx
    jz .pi64b_ret
    neg rax

.pi64b_ret:
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse an integer from a LENGTH-BOUNDED byte range, in an arbitrary
; base (2-36), rather than scanning for a NUL terminator. Same
; buffer-reuse safety rationale as _parse_i64_bounded above.
; Args: rdi = pointer, rsi = base (2-36), rdx = max length in bytes
; Returns: rax = parsed integer (0 on empty/invalid prefix, or a wrapped
; value on magnitude overflow - the error flag is authoritative, not rax)
; See _parse_i64 above for the overflow-detection rationale.
global _parse_int_radix_bounded
_parse_int_radix_bounded:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push r12

    mov r8, rsi                 ; base
    mov r10, rdx                ; remaining length
    xor rax, rax
    xor r9, r9                   ; sign flag
    xor r11, r11                  ; parsed-a-digit flag
    xor r12, r12                   ; overflow-sticky flag
    mov rbx, rdi

    test r10, r10
    jz .pirb_no_digits

    mov dl, [rbx]
    cmp dl, '-'
    jne .pirb_loop
    mov r9, 1
    inc rbx
    dec r10

.pirb_loop:
    test r10, r10
    jz .pirb_done
    mov dl, [rbx]
    test dl, dl
    jz .pirb_done

    cmp dl, '0'
    jl .pirb_done
    cmp dl, '9'
    jg .pirb_alpha
    movzx rcx, dl
    sub rcx, '0'
    jmp .pirb_check

.pirb_alpha:
    mov cl, dl
    or cl, 0x20
    cmp cl, 'a'
    jl .pirb_done
    cmp cl, 'z'
    jg .pirb_done
    movzx rcx, cl
    sub rcx, 'a'
    add rcx, 10

.pirb_check:
    cmp rcx, r8
    jge .pirb_done

    mul r8                        ; rdx:rax = rax * base (unsigned)
    or r12, rdx                     ; sticky: high bits nonzero -> overflow
    add rax, rcx
    adc r12, 0                       ; sticky: carry out of the add -> overflow

    inc rbx
    dec r10
    mov r11, 1
    jmp .pirb_loop

.pirb_done:
    test r11, r11
    jz .pirb_no_digits
    test r9, r9
    jnz .pirb_check_neg
    test rax, rax                   ; positive: magnitude must fit under i64::MAX
    js .pirb_set_overflow
    jmp .pirb_range_ok
.pirb_check_neg:
    mov rdx, 0x8000000000000000        ; negative: magnitude may reach i64::MIN's
    cmp rax, rdx
    ja .pirb_set_overflow
    jmp .pirb_range_ok
.pirb_set_overflow:
    mov r12, 1
.pirb_range_ok:
    test r12, r12
    jnz .pirb_overflow_err
    mov qword [rel _last_error], 0
    jmp .pirb_sign
.pirb_no_digits:
    mov qword [rel _last_error], 1
    jmp .pirb_sign
.pirb_overflow_err:
    mov qword [rel _last_error], 1
.pirb_sign:
    test r9, r9
    jz .pirb_ret
    neg rax

.pirb_ret:
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret
