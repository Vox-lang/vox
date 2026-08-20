; float.asm - Floating point operations for Vox Compiler
; Uses SSE2 instructions (available on all x86-64 CPUs)

; Guard tested by list.asm: _list_print's float-tag branch uses PRINT_FLOAT,
; so that branch is assembled only when this file has been included. A
; program with no floats (uses_floats == false) can never produce a
; float-tagged list slot, so omitting the branch is safe. list.asm is
; included after float.asm, so this define is visible.
%define __FLOAT_ASM_INCLUDED__

; 2^63 exactly, as an f64 bit pattern. The dividing line above which
; cvttsd2si's truncating float-to-int64 conversion saturates instead of
; truncating (docs/BUGS_FOUND.md #34) - _print_float and
; _buffer_append_float compare a value's magnitude against this before
; deciding which integer-part routine to use.
section .data
align 8
_float_int64_boundary: dq 9223372036854775808.0

section .text

; Float arithmetic - operates on xmm0 and xmm1, result in xmm0
%macro FLOAT_ADD 0
    addsd xmm0, xmm1
%endmacro

%macro FLOAT_SUB 0
    subsd xmm0, xmm1
%endmacro

%macro FLOAT_MUL 0
    mulsd xmm0, xmm1
%endmacro

%macro FLOAT_DIV 0
    divsd xmm0, xmm1
%endmacro

; Float modulo: a - floor(a/b) * b (xmm0 = a, xmm1 = b, result in xmm0)
%macro FLOAT_MOD 0
    movsd xmm2, xmm0         ; save a
    divsd xmm0, xmm1         ; a/b
    roundsd xmm0, xmm0, 1    ; floor
    mulsd xmm0, xmm1         ; floor(a/b) * b
    subsd xmm2, xmm0         ; a - floor(a/b) * b
    movsd xmm0, xmm2
%endmacro

; Move float bits from rax to xmm0
%macro RAX_TO_XMM0 0
    movq xmm0, rax
%endmacro

; Move float bits from rax to xmm1
%macro RAX_TO_XMM1 0
    movq xmm1, rax
%endmacro

; Move float bits from xmm0 to rax
%macro XMM0_TO_RAX 0
    movq rax, xmm0
%endmacro

; Float comparisons - compares xmm0 with xmm1, result (0 or 1) in rax
%macro FLOAT_EQ 0
    xor eax, eax
    ucomisd xmm0, xmm1
    sete al
    setnp bl
    and al, bl
    movzx rax, al
%endmacro

%macro FLOAT_NE 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setne al
    setp bl
    or al, bl
    movzx rax, al
%endmacro

%macro FLOAT_LT 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setb al
    setnp bl
    and al, bl
    movzx rax, al
%endmacro

%macro FLOAT_LE 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setbe al
    setnp bl
    and al, bl
    movzx rax, al
%endmacro

%macro FLOAT_GT 0
    xor eax, eax
    ucomisd xmm0, xmm1
    seta al
    setnp bl
    and al, bl
    movzx rax, al
%endmacro

%macro FLOAT_GE 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setae al
    setnp bl
    and al, bl
    movzx rax, al
%endmacro

; Load float from memory into xmm0. %1 is a data-section label; the
; reference is RIP-relative.
%macro FLOAT_LOAD 1
    movsd xmm0, [rel %1]
%endmacro

; Store xmm0 to memory. %1 is a data-section label; the reference is
; RIP-relative.
%macro FLOAT_STORE 1
    movsd [rel %1], xmm0
%endmacro

; Convert integer in rax to float in xmm0
%macro INT_TO_FLOAT 0
    cvtsi2sd xmm0, rax
%endmacro

; Convert float in xmm0 to integer in rax (truncate)
%macro FLOAT_TO_INT 0
    cvttsd2si rax, xmm0
%endmacro

; Absolute value of float in xmm0
%macro FLOAT_ABS 0
    ; Clear sign bit (bit 63)
    mov rax, 0x7FFFFFFFFFFFFFFF
    movq xmm1, rax
    andpd xmm0, xmm1
%endmacro

; Check if float in xmm0 is zero, result in rax (0 or 1)
%macro FLOAT_IS_ZERO 0
    xorpd xmm1, xmm1
    xor eax, eax
    ucomisd xmm0, xmm1
    sete al
    movzx rax, al
%endmacro

; Check if float in xmm0 is positive (> 0), result in rax
%macro FLOAT_IS_POSITIVE 0
    xorpd xmm1, xmm1
    xor eax, eax
    ucomisd xmm0, xmm1
    seta al
    movzx rax, al
%endmacro

; Check if float in xmm0 is negative (< 0), result in rax
%macro FLOAT_IS_NEGATIVE 0
    xorpd xmm1, xmm1
    xor eax, eax
    ucomisd xmm0, xmm1
    setb al
    movzx rax, al
%endmacro

; Print float in xmm0 to stdout with full precision, trimming trailing zeros
; Format: X.Y (at least one decimal digit, up to 15 significant digits)
%macro PRINT_FLOAT 0
    call _print_float
%endmacro

; Negate float in xmm0 and leave result in xmm0
%macro FLOAT_NEG 0
    call _float_negate
%endmacro

_print_float:
    push rbp
    mov rbp, rsp
    sub rsp, 512               ; extra room below rbp-112 for the exact
                                ; large-magnitude digit buffer (see
                                ; _pf_not_neg below)
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    ; Store the float value
    movsd [rbp-8], xmm0
    
    ; Check for negative
    xorpd xmm1, xmm1
    ucomisd xmm0, xmm1
    jae _pf_not_neg
    
    ; Print minus sign
    mov byte [rbp-48], '-'
    mov rax, 1
    mov rdi, 1
    lea rsi, [rbp-48]
    mov rdx, 1
    syscall
    
    ; Negate the value
    movsd xmm0, [rbp-8]
    mov rax, 0x8000000000000000
    movq xmm1, rax
    xorpd xmm0, xmm1
    movsd [rbp-8], xmm0
    
_pf_not_neg:
    movsd xmm0, [rbp-8]

    ; A magnitude at or beyond 2^63 makes cvttsd2si's float-to-int64
    ; truncation saturate to the "integer indefinite" value instead of
    ; truncating - the origin of the 9223372036854775808.372036854775808
    ; saturation bug (docs/BUGS_FOUND.md #34). 2^63 is already far past
    ; 2^52, the point beyond which a double's 52-bit mantissa has no
    ; room left for a fractional bit, so nothing in this range has a
    ; fraction to print - only an exact integer, produced by
    ; _float_big_int_digits instead of cvttsd2si.
    movsd xmm1, [rel _float_int64_boundary]
    ucomisd xmm0, xmm1
    jb _pf_normal_range

    movq rdi, xmm0
    lea rsi, [rbp-112]         ; end (exclusive) of the 400-byte scratch
                                ; buffer at [rbp-512 .. rbp-112]
    call _float_big_int_digits ; rax = digit ptr, rdx = digit count
    mov rsi, rax
    mov rax, 1
    mov rdi, 1
    syscall

    mov byte [rbp-48], '.'
    mov rax, 1
    mov rdi, 1
    lea rsi, [rbp-48]
    mov rdx, 1
    syscall

    mov byte [rbp-48], '0'
    mov rax, 1
    mov rdi, 1
    lea rsi, [rbp-48]
    mov rdx, 1
    syscall

    jmp _pf_done

_pf_normal_range:
    ; Get integer part
    movsd xmm0, [rbp-8]
    cvttsd2si r12, xmm0       ; r12 = integer part

    ; Print integer part
    mov rax, r12
    lea rdi, [rbp-32]         ; buffer for digits (use middle of buffer)
    mov rcx, 0                ; digit count
    
    test rax, rax
    jnz _pf_int_loop
    
    ; Handle zero
    mov byte [rdi], '0'
    inc rcx
    jmp _pf_print_int
    
_pf_int_loop:
    test rax, rax
    jz _pf_print_int
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc rcx
    jmp _pf_int_loop
    
_pf_print_int:
    mov rax, 1
    mov rdx, rcx
    mov rsi, rdi
    mov rdi, 1
    syscall
    
    ; Print decimal point
    mov byte [rbp-48], '.'
    mov rax, 1
    mov rdi, 1
    lea rsi, [rbp-48]
    mov rdx, 1
    syscall
    
    ; Get fractional part: (value - int_part) * 10^15 for full precision
    movsd xmm0, [rbp-8]
    cvtsi2sd xmm1, r12
    subsd xmm0, xmm1          ; fractional part (0.xxxxx)
    
    ; Multiply by 10^15 (1000000000000000) for 15 decimal places
    mov rax, 1000000000000000
    cvtsi2sd xmm1, rax
    mulsd xmm0, xmm1
    
    ; Round to nearest integer
    roundsd xmm0, xmm0, 0     ; round to nearest
    cvttsd2si r13, xmm0       ; r13 = fractional digits as integer
    
    ; Make positive
    test r13, r13
    jns _pf_frac_pos
    neg r13
_pf_frac_pos:
    
    ; Convert to digits in buffer (15 digits with leading zeros)
    mov rax, r13
    lea rdi, [rbp-64]         ; frac buffer start
    add rdi, 14               ; point to last position (index 14 for 15 digits)
    mov rcx, 15               ; 15 digits
    mov r14, rdi              ; r14 = pointer to last digit
    
_pf_frac_convert:
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov [rdi], dl
    dec rdi
    dec rcx
    jnz _pf_frac_convert
    
    ; Now find last non-zero digit (trim trailing zeros)
    ; r14 points to last digit, scan backwards from there
    ; But keep at least 1 digit after decimal point
    lea rdi, [rbp-64]         ; start of frac buffer
    mov r15, r14              ; r15 = end pointer (will be adjusted)
    
_pf_trim_zeros:
    cmp r15, rdi              ; don't go past first digit
    je _pf_print_frac         ; keep at least one digit
    cmp byte [r15], '0'
    jne _pf_print_frac        ; found non-zero, stop trimming
    dec r15                   ; move end pointer back
    jmp _pf_trim_zeros
    
_pf_print_frac:
    ; Print from rdi to r15 inclusive
    lea rsi, [rbp-64]         ; start of frac digits
    mov rdx, r15
    sub rdx, rsi
    inc rdx                   ; length = end - start + 1
    mov rax, 1
    mov rdi, 1
    syscall

_pf_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

; Negate float in xmm0 and leave result in xmm0
_float_negate:
    push rbp
    mov rbp, rsp
    
    ; Negate by subtracting from zero
    xorpd xmm1, xmm1      ; xmm1 = 0.0
    subsd xmm1, xmm0      ; xmm1 = 0.0 - xmm0 = -xmm0
    movsd xmm0, xmm1      ; xmm0 = -xmm0
    
    leave
    ret

; Parse a double-precision float from a NUL-terminated string.
; Handles an optional leading '-', an integer part, and an optional
; '.' followed by a fractional part. Degrades gracefully to 0.0 on an
; empty or entirely-invalid string, matching the "stop at first invalid
; character" convention used by _parse_i64/_parse_int_radix elsewhere
; in this codebase.
; Args: rdi = string pointer
; Returns: rax = the parsed value's raw 64-bit bit pattern (per this
; codebase's float convention - see RAX_TO_XMM0/XMM0_TO_RAX above)
global _parse_f64
_parse_f64:
    push rbx
    push rcx
    push rdx
    push r8              ; sign flag
    push r9               ; fractional digit count
    push r11              ; parsed-a-digit flag

    xor r8, r8
    xor r9, r9
    xor r11, r11
    mov rbx, rdi

    mov dl, [rbx]
    cmp dl, '-'
    jne .pf64_sign_done
    mov r8, 1
    inc rbx
.pf64_sign_done:
    xor rax, rax

.pf64_int_loop:
    mov dl, [rbx]
    cmp dl, '0'
    jl .pf64_int_done
    cmp dl, '9'
    jg .pf64_int_done
    imul rax, rax, 10
    movzx rdx, dl
    sub rdx, '0'
    add rax, rdx
    inc rbx
    mov r11, 1
    jmp .pf64_int_loop

.pf64_int_done:
    cvtsi2sd xmm0, rax

    mov dl, [rbx]
    cmp dl, '.'
    jne .pf64_check_digits
    inc rbx

    xor rax, rax
.pf64_frac_loop:
    mov dl, [rbx]
    cmp dl, '0'
    jl .pf64_frac_done
    cmp dl, '9'
    jg .pf64_frac_done
    imul rax, rax, 10
    movzx rdx, dl
    sub rdx, '0'
    add rax, rdx
    inc r9
    inc rbx
    mov r11, 1
    jmp .pf64_frac_loop

.pf64_frac_done:
    test r9, r9
    jz .pf64_check_digits
    cvtsi2sd xmm1, rax
    mov rcx, r9
.pf64_pow10_loop:
    test rcx, rcx
    jz .pf64_pow10_done
    mov rax, 10
    cvtsi2sd xmm2, rax
    divsd xmm1, xmm2
    dec rcx
    jmp .pf64_pow10_loop
.pf64_pow10_done:
    addsd xmm0, xmm1

.pf64_check_digits:
    test r11, r11
    jnz .pf64_sign
    mov qword [rel _last_error], 1
    jmp .pf64_done
.pf64_sign:
    mov qword [rel _last_error], 0
    test r8, r8
    jz .pf64_done
    xorpd xmm1, xmm1
    subsd xmm1, xmm0
    movsd xmm0, xmm1

.pf64_done:
    movq rax, xmm0

    pop r11
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; Same as _parse_f64, but bounded by an explicit max length rather than
; scanning for a NUL terminator. Buffer content isn't reliably
; NUL-terminated at its logical end (_buffer_clear only zeroes the
; first byte, not the whole allocation - see the int.asm bounded
; parsers for the full explanation), so buffer-typed float casts must
; use this instead of _parse_f64 directly.
; Args: rdi = string pointer, rsi = max length in bytes
; Returns: rax = the parsed value's raw 64-bit bit pattern
global _parse_f64_bounded
_parse_f64_bounded:
    push rbx
    push rcx
    push rdx
    push r8               ; sign flag
    push r9                ; fractional digit count
    push r10               ; remaining length
    push r11               ; parsed-a-digit flag

    xor r8, r8
    xor r9, r9
    xor r11, r11
    xor rax, rax
    mov rbx, rdi
    mov r10, rsi

    test r10, r10
    jz .pf64b_no_digits

    mov dl, [rbx]
    cmp dl, '-'
    jne .pf64b_int_loop
    mov r8, 1
    inc rbx
    dec r10

.pf64b_int_loop:
    test r10, r10
    jz .pf64b_int_done
    mov dl, [rbx]
    cmp dl, '0'
    jl .pf64b_int_done
    cmp dl, '9'
    jg .pf64b_int_done
    imul rax, rax, 10
    movzx rdx, dl
    sub rdx, '0'
    add rax, rdx
    inc rbx
    dec r10
    mov r11, 1
    jmp .pf64b_int_loop

.pf64b_int_done:
    cvtsi2sd xmm0, rax

    test r10, r10
    jz .pf64b_check_digits
    mov dl, [rbx]
    cmp dl, '.'
    jne .pf64b_check_digits
    inc rbx
    dec r10

    xor rax, rax
.pf64b_frac_loop:
    test r10, r10
    jz .pf64b_frac_done
    mov dl, [rbx]
    cmp dl, '0'
    jl .pf64b_frac_done
    cmp dl, '9'
    jg .pf64b_frac_done
    imul rax, rax, 10
    movzx rdx, dl
    sub rdx, '0'
    add rax, rdx
    inc r9
    inc rbx
    dec r10
    mov r11, 1
    jmp .pf64b_frac_loop

.pf64b_frac_done:
    test r9, r9
    jz .pf64b_check_digits
    cvtsi2sd xmm1, rax
    mov rcx, r9
.pf64b_pow10_loop:
    test rcx, rcx
    jz .pf64b_pow10_done
    mov rax, 10
    cvtsi2sd xmm2, rax
    divsd xmm1, xmm2
    dec rcx
    jmp .pf64b_pow10_loop
.pf64b_pow10_done:
    addsd xmm0, xmm1

.pf64b_check_digits:
    test r11, r11
    jnz .pf64b_sign
.pf64b_no_digits:
    mov qword [rel _last_error], 1
    jmp .pf64b_done
.pf64b_sign:
    mov qword [rel _last_error], 0
    test r8, r8
    jz .pf64b_done
    xorpd xmm1, xmm1
    subsd xmm1, xmm0
    movsd xmm0, xmm1

.pf64b_done:
    movq rax, xmm0

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; Append a double-precision float's decimal representation to a dynamic
; buffer. The output is trimmed of trailing zeros in the fractional part,
; but always includes a decimal point and at least one fractional digit
; (e.g. 3.0 becomes "3.0", 3.14 becomes "3.14"), matching LANGUAGE.md.
; Args: rdi = destination buffer pointer, rax = raw float bits
; Returns: rax = destination buffer pointer (possibly reallocated)
global _buffer_append_float
_buffer_append_float:
    push rbp
    mov rbp, rsp
    sub rsp, 528               ; extra room below rbp-128 for the exact
                                ; large-magnitude digit buffer (see
                                ; .baf_not_neg below)
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; destination buffer
    movq xmm0, rax          ; float value

    ; Handle negative values.
    xorpd xmm1, xmm1
    ucomisd xmm0, xmm1
    jae .baf_not_neg

    mov byte [rbp-1], '-'
    lea rsi, [rbp-1]
    mov rdi, r12
    mov rdx, 1
    call _buffer_append_bytes
    mov r12, rax

    mov rax, 0x8000000000000000
    movq xmm1, rax
    xorpd xmm0, xmm1

.baf_not_neg:
    ; A magnitude at or beyond 2^63 makes cvttsd2si's float-to-int64
    ; truncation saturate instead of truncating - see _print_float's
    ; identical check for the full explanation (docs/BUGS_FOUND.md #34).
    movsd xmm1, [rel _float_int64_boundary]
    ucomisd xmm0, xmm1
    jb .baf_normal_range

    movq rdi, xmm0
    lea rsi, [rbp-128]         ; end (exclusive) of the 400-byte scratch
                                ; buffer at [rbp-528 .. rbp-128]
    call _float_big_int_digits ; rax = digit ptr, rdx = digit count
    mov r14, rax
    mov r15, rdx
    mov rdi, r12
    mov rsi, r14
    mov rdx, r15
    call _buffer_append_bytes
    mov r12, rax

    mov byte [rbp-1], '.'
    lea rsi, [rbp-1]
    mov rdi, r12
    mov rdx, 1
    call _buffer_append_bytes
    mov r12, rax

    mov byte [rbp-1], '0'
    lea rsi, [rbp-1]
    mov rdi, r12
    mov rdx, 1
    call _buffer_append_bytes
    mov r12, rax

    jmp .baf_done

.baf_normal_range:
    ; Append the integer part.
    cvttsd2si r13, xmm0
    mov rax, r13
    lea rdi, [rbp-32]
    xor rcx, rcx
    test rax, rax
    jnz .baf_int_loop
    mov byte [rdi], '0'
    mov rcx, 1
    jmp .baf_int_append

.baf_int_loop:
    test rax, rax
    jz .baf_int_append
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc rcx
    jmp .baf_int_loop

.baf_int_append:
    mov r15, rdi            ; save digit buffer pointer
    mov rdi, r12
    mov rsi, r15
    mov rdx, rcx
    call _buffer_append_bytes
    mov r12, rax

    ; Append the decimal point.
    mov byte [rbp-1], '.'
    lea rsi, [rbp-1]
    mov rdi, r12
    mov rdx, 1
    call _buffer_append_bytes
    mov r12, rax

    ; Compute the fractional part with 15 decimal digits of precision.
    cvtsi2sd xmm1, r13
    subsd xmm0, xmm1
    mov rax, 1000000000000000
    cvtsi2sd xmm1, rax
    mulsd xmm0, xmm1
    roundsd xmm0, xmm0, 0
    cvttsd2si r14, xmm0
    test r14, r14
    jns .baf_frac_pos
    neg r14

.baf_frac_pos:
    ; Generate 15 fractional digits backwards into [rbp-64].
    lea rdi, [rbp-64]
    add rdi, 14
    mov rcx, 15
.baf_frac_loop:
    mov rax, r14
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov [rdi], dl
    mov r14, rax
    dec rdi
    dec rcx
    jnz .baf_frac_loop

    ; Find the last non-zero digit so trailing zeros are trimmed.
    lea rdi, [rbp-64]
    add rdi, 14
    mov rcx, 15
.baf_trim_loop:
    cmp byte [rdi], '0'
    jne .baf_trim_done
    dec rdi
    dec rcx
    jnz .baf_trim_loop
.baf_trim_done:

    test rcx, rcx
    jnz .baf_frac_append
    ; The fractional part was entirely zero; emit a single '0'.
    mov byte [rbp-1], '0'
    lea rsi, [rbp-1]
    mov rdi, r12
    mov rdx, 1
    call _buffer_append_bytes
    mov r12, rax
    jmp .baf_done

.baf_frac_append:
    mov rdi, r12
    lea rsi, [rbp-64]
    mov rdx, rcx
    call _buffer_append_bytes
    mov r12, rax

.baf_done:
    mov rax, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

; Produce the exact decimal digits of a double whose magnitude is at or
; beyond 2^63 (docs/BUGS_FOUND.md #34). Above 2^63 there is no room left
; in a 52-bit mantissa for a fractional bit, so the value is exactly
; mantissa * 2^k for some k >= 11 - an exact integer. cvttsd2si cannot be
; used to get at it (it saturates past 2^63, the original bug), so this
; extracts the raw 53-bit mantissa and exponent instead and produces the
; exact decimal string by schoolbook binary-to-decimal: write the
; mantissa's decimal digits, then double the decimal digit array k
; times. Doubling a decimal string is exact - no floating point is
; involved past reading the raw bits - so this reproduces the double's
; true value digit for digit, with no saturation and no rounding.
;
; Args: rdi = raw f64 bits (sign bit must already be 0; callers print
;             any minus sign themselves, same as the cvttsd2si path).
;       rsi = pointer to one-past-the-end of a caller-owned scratch
;             buffer of at least 400 bytes (comfortably covers the
;             longest possible double magnitude, ~309 decimal digits,
;             since k maxes out at 971 for the largest finite double).
; Returns: rax = pointer to the first digit, rdx = digit count. Digits
;          are written into the caller's buffer, growing downward from
;          rsi. Every register this routine touches is restored before
;          return, so callers keep whatever they had in rbx/rcx/r8-r12
;          across the call.
global _float_big_int_digits
_float_big_int_digits:
    push rbx
    push rcx
    push rsi
    push r8
    push r9
    push r10
    push r11
    push r12

    mov r10, rsi                   ; end (exclusive), fixed for this call

    mov r8, rdi
    shr r8, 52
    and r8, 0x7FF                  ; r8 = biased exponent

    mov r9, rdi
    mov rax, 0xFFFFFFFFFFFFF
    and r9, rax                    ; r9 = 52-bit fraction bits
    mov rax, 1
    shl rax, 52
    or r9, rax                     ; r9 = 53-bit mantissa (implicit bit set)

    mov rcx, r8
    sub rcx, 1023
    sub rcx, 52                    ; rcx = k, doublings needed (>= 11 here,
                                    ; since the caller only calls this for
                                    ; magnitudes at or beyond 2^63)

    ; Write the mantissa's decimal digits right-aligned at the buffer end.
    mov rdi, r10
    mov rax, r9
.init_loop:
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz .init_loop
    mov r11, rdi                   ; r11 = start (leftmost digit so far)

    test rcx, rcx
    jz .done

.double_loop:
    lea rsi, [r10 - 1]              ; least-significant digit position
    xor r12, r12                    ; carry
.double_digit:
    movzx rax, byte [rsi]
    sub rax, '0'
    add rax, rax                    ; * 2
    add rax, r12
    xor r12, r12
    cmp rax, 10
    jl .no_carry
    sub rax, 10
    mov r12, 1                      ; doubling a decimal digit (0-9) plus
                                     ; a carry of 0 or 1 never exceeds 19,
                                     ; so the carry out is always 0 or 1
.no_carry:
    add al, '0'
    mov [rsi], al
    cmp rsi, r11
    je .digit_pass_done
    dec rsi
    jmp .double_digit
.digit_pass_done:
    test r12, r12
    jz .no_new_digit
    dec r11
    mov byte [r11], '1'
.no_new_digit:
    dec rcx
    jnz .double_loop

.done:
    mov rax, r11
    mov rdx, r10
    sub rdx, r11                    ; digit count

    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rcx
    pop rbx
    ret
