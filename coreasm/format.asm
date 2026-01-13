; format.asm - Format string macros for English Compiler
; Provides: number formatting (hex, binary, octal), padding, precision

section .data
    _hex_chars_lower: db "0123456789abcdef"
    _hex_chars_upper: db "0123456789ABCDEF"
    _format_buffer: times 66 db 0    ; enough for 64-bit binary + prefix + null

section .text

; ============================================================================
; NUMBER TO STRING CONVERSIONS
; ============================================================================

; Convert integer to hex string (lowercase) - prints directly
; Args: value
%macro PRINT_HEX_LOWER 1
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, %1
    mov rdi, rax
    xor rsi, rsi                ; lowercase flag = 0
    call _print_hex_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Convert integer to hex string (uppercase) - prints directly
; Args: value
%macro PRINT_HEX_UPPER 1
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, %1
    mov rdi, rax
    mov rsi, 1                  ; uppercase flag = 1
    call _print_hex_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Internal: print hex implementation
; rdi = value, rsi = uppercase flag
_print_hex_impl:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    push r12
    push r13
    
    mov r12, rdi                ; value
    mov r13, rsi                ; uppercase flag
    
    ; Build hex string backwards
    lea rdi, [_format_buffer + 20]
    mov byte [rdi], 0           ; null terminator
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    ; Handle zero
    dec rdi
    mov byte [rdi], '0'
    mov byte [rdi - 1], 'x'
    mov byte [rdi - 2], '0'
    sub rdi, 2
    jmp .print_result
    
.convert_loop:
    test rax, rax
    jz .add_prefix
    
    mov rcx, rax
    and rcx, 0xF                ; get low nibble
    
    ; Select correct hex char table
    test r13, r13
    jz .use_lower
    lea rbx, [_hex_chars_upper]
    jmp .get_char
.use_lower:
    lea rbx, [_hex_chars_lower]
.get_char:
    mov cl, [rbx + rcx]
    dec rdi
    mov [rdi], cl
    
    shr rax, 4                  ; next nibble
    jmp .convert_loop
    
.add_prefix:
    dec rdi
    mov byte [rdi], 'x'
    dec rdi
    mov byte [rdi], '0'
    
.print_result:
    ; Count length
    lea rsi, [_format_buffer + 20]
    sub rsi, rdi                ; length
    mov rdx, rsi
    mov rsi, rdi                ; string pointer
    
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; stdout
    syscall
    
    pop r13
    pop r12
    leave
    ret

; Print integer in binary format
; Args: value
%macro PRINT_BINARY 1
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1
    call _print_binary_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

_print_binary_impl:
    push rbp
    mov rbp, rsp
    push r12
    
    mov r12, rdi                ; value
    
    ; Build binary string backwards
    lea rdi, [_format_buffer + 65]
    mov byte [rdi], 0           ; null terminator
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    ; Handle zero
    dec rdi
    mov byte [rdi], '0'
    jmp .print_result
    
.convert_loop:
    test rax, rax
    jz .print_result
    
    mov cl, al
    and cl, 1
    add cl, '0'
    dec rdi
    mov [rdi], cl
    
    shr rax, 1
    jmp .convert_loop
    
.print_result:
    ; Count length
    lea rsi, [_format_buffer + 65]
    sub rsi, rdi
    mov rdx, rsi
    mov rsi, rdi
    
    mov rax, 1
    mov rdi, 1
    syscall
    
    pop r12
    leave
    ret

; Print integer in octal format
; Args: value
%macro PRINT_OCTAL 1
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1
    call _print_octal_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

_print_octal_impl:
    push rbp
    mov rbp, rsp
    push r12
    
    mov r12, rdi
    
    lea rdi, [_format_buffer + 30]
    mov byte [rdi], 0
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    dec rdi
    mov byte [rdi], '0'
    jmp .print_result
    
.convert_loop:
    test rax, rax
    jz .print_result
    
    mov rcx, rax
    and rcx, 7                  ; get low 3 bits
    add cl, '0'
    dec rdi
    mov [rdi], cl
    
    shr rax, 3
    jmp .convert_loop
    
.print_result:
    lea rsi, [_format_buffer + 30]
    sub rsi, rdi
    mov rdx, rsi
    mov rsi, rdi
    
    mov rax, 1
    mov rdi, 1
    syscall
    
    pop r12
    leave
    ret

; ============================================================================
; PADDED NUMBER OUTPUT
; ============================================================================

; Print integer with minimum width (right-aligned, space-padded)
; Args: value, min_width
%macro PRINT_INT_PADDED 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    xor rdx, rdx                ; pad char = space
    call _print_int_padded_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print integer with zero-padding
; Args: value, min_width
%macro PRINT_INT_ZEROPAD 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    mov rdx, 1                  ; pad char = '0'
    call _print_int_padded_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

_print_int_padded_impl:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi                ; value
    mov r13, rsi                ; min width
    mov r14, rdx                ; zero-pad flag
    
    ; Convert number to string first
    lea rdi, [_format_buffer + 30]
    mov byte [rdi], 0
    
    mov rax, r12
    mov r8, 0                   ; negative flag
    
    test rax, rax
    jns .positive
    neg rax
    mov r8, 1
    
.positive:
    xor rcx, rcx                ; digit count
    
    test rax, rax
    jnz .convert_loop
    dec rdi
    mov byte [rdi], '0'
    inc rcx
    jmp .check_padding
    
.convert_loop:
    test rax, rax
    jz .check_negative
    
    xor rdx, rdx
    mov rbx, 10
    div rbx
    
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc rcx
    jmp .convert_loop
    
.check_negative:
    test r8, r8
    jz .check_padding
    dec rdi
    mov byte [rdi], '-'
    inc rcx
    
.check_padding:
    ; rcx = current length, r13 = min width
    ; rdi = pointer to start of number string
    mov r15, rdi                ; save number string pointer
    mov r8, rcx                 ; save number length
    
    cmp rcx, r13
    jge .print_result
    
    ; Need padding
    mov rax, r13
    sub rax, rcx                ; padding needed
    
    ; Print padding chars
    test r14, r14
    jz .pad_space
    mov r9b, '0'
    jmp .pad_loop
.pad_space:
    mov r9b, ' '
    
.pad_loop:
    test rax, rax
    jz .print_result
    
    push rax
    mov byte [_format_buffer + 32], r9b
    mov rax, 1
    mov rdi, 1
    lea rsi, [_format_buffer + 32]
    mov rdx, 1
    syscall
    pop rax
    dec rax
    jmp .pad_loop
    
.print_result:
    ; Print the actual number
    mov rax, 1
    mov rdi, 1
    mov rsi, r15                ; number string pointer
    mov rdx, r8                 ; number length
    syscall
    
    pop r15
    pop r14
    pop r13
    pop r12
    leave
    ret

; ============================================================================
; FLOAT PRECISION PRINTING
; ============================================================================

; Print float with specified decimal precision
; xmm0 = float value, rdi = precision (number of decimal places)
_print_float_precision:
    push rbp
    mov rbp, rsp
    sub rsp, 64
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rdi                ; precision
    
    ; Get the float value
    movq rax, xmm0
    
    ; Check for negative
    test rax, rax
    jns .positive
    
    ; Print minus sign
    mov byte [_format_buffer], '-'
    push rax
    mov rax, 1
    mov rdi, 1
    lea rsi, [_format_buffer]
    mov rdx, 1
    syscall
    pop rax
    
    ; Make positive
    mov rcx, 0x7FFFFFFFFFFFFFFF
    and rax, rcx
    movq xmm0, rax
    
.positive:
    ; Get integer part
    cvttsd2si r13, xmm0         ; r13 = integer part
    
    ; Print integer part
    push r12
    PRINT_INT r13
    pop r12
    
    ; Check if we need decimal places
    test r12, r12
    jz .done
    
    ; Print decimal point
    mov byte [_format_buffer], '.'
    mov rax, 1
    mov rdi, 1
    lea rsi, [_format_buffer]
    mov rdx, 1
    syscall
    
    ; Get fractional part
    cvtsi2sd xmm1, r13          ; xmm1 = integer as float
    subsd xmm0, xmm1            ; xmm0 = fractional part
    
    ; Multiply by 10^precision
    mov r14, r12                ; counter
    movsd xmm1, [_ten_const]
.mul_loop:
    test r14, r14
    jz .print_frac
    mulsd xmm0, xmm1
    dec r14
    jmp .mul_loop
    
.print_frac:
    ; Round and convert to integer
    addsd xmm0, [_half_const]
    cvttsd2si r13, xmm0
    
    ; Print with leading zeros if needed
    mov r14, r12                ; digits needed
    mov r15, r13                ; value
    
    ; Count digits in value
    xor rcx, rcx
    mov rax, r15
    test rax, rax
    jnz .count_digits
    inc rcx                     ; at least one digit
    jmp .pad_zeros
    
.count_digits:
    test rax, rax
    jz .pad_zeros
    inc rcx
    xor rdx, rdx
    mov rbx, 10
    div rbx
    jmp .count_digits
    
.pad_zeros:
    ; Print leading zeros: r14 - rcx zeros needed
    sub r14, rcx
    jle .print_value
    
.zero_loop:
    test r14, r14
    jz .print_value
    mov byte [_format_buffer], '0'
    push rcx
    push r14
    push r15
    mov rax, 1
    mov rdi, 1
    lea rsi, [_format_buffer]
    mov rdx, 1
    syscall
    pop r15
    pop r14
    pop rcx
    dec r14
    jmp .zero_loop
    
.print_value:
    ; Print the fractional digits
    test r15, r15
    jz .done
    PRINT_INT r15
    
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    leave
    ret

section .data
    _ten_const: dq 10.0
    _half_const: dq 0.5

section .text

; ============================================================================
; PRINT WITHOUT NEWLINE (already handled by PRINT_STR, but add explicit macro)
; ============================================================================

; Print string without trailing newline
%macro PRINT_STR_NO_NEWLINE 2
    mov rax, 1
    mov rdi, 1
    lea rsi, [%1]
    mov rdx, %2
    syscall
%endmacro

; Print integer without trailing newline (same as PRINT_INT)
%macro PRINT_INT_NO_NEWLINE 1
    PRINT_INT %1
%endmacro

