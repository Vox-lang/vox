; float.asm - Floating point operations for Vox Compiler
; Uses SSE2 instructions (available on all x86-64 CPUs)

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
    movzx rax, al
%endmacro

%macro FLOAT_NE 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setne al
    movzx rax, al
%endmacro

%macro FLOAT_LT 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setb al
    movzx rax, al
%endmacro

%macro FLOAT_LE 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setbe al
    movzx rax, al
%endmacro

%macro FLOAT_GT 0
    xor eax, eax
    ucomisd xmm0, xmm1
    seta al
    movzx rax, al
%endmacro

%macro FLOAT_GE 0
    xor eax, eax
    ucomisd xmm0, xmm1
    setae al
    movzx rax, al
%endmacro

; Load float from memory into xmm0
%macro FLOAT_LOAD 1
    movsd xmm0, [%1]
%endmacro

; Store xmm0 to memory
%macro FLOAT_STORE 1
    movsd [%1], xmm0
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
    sub rsp, 80
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

    xor r8, r8
    xor r9, r9
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
    jmp .pf64_int_loop

.pf64_int_done:
    cvtsi2sd xmm0, rax

    mov dl, [rbx]
    cmp dl, '.'
    jne .pf64_sign
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
    jmp .pf64_frac_loop

.pf64_frac_done:
    test r9, r9
    jz .pf64_sign
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

.pf64_sign:
    test r8, r8
    jz .pf64_done
    xorpd xmm1, xmm1
    subsd xmm1, xmm0
    movsd xmm0, xmm1

.pf64_done:
    movq rax, xmm0

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

    xor r8, r8
    xor r9, r9
    xor rax, rax
    mov rbx, rdi
    mov r10, rsi

    test r10, r10
    jz .pf64b_int_done       ; zero length -> 0.0 immediately

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
    jmp .pf64b_int_loop

.pf64b_int_done:
    cvtsi2sd xmm0, rax

    test r10, r10
    jz .pf64b_sign
    mov dl, [rbx]
    cmp dl, '.'
    jne .pf64b_sign
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
    jmp .pf64b_frac_loop

.pf64b_frac_done:
    test r9, r9
    jz .pf64b_sign
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

.pf64b_sign:
    test r8, r8
    jz .pf64b_done
    xorpd xmm1, xmm1
    subsd xmm1, xmm0
    movsd xmm0, xmm1

.pf64b_done:
    movq rax, xmm0

    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret
