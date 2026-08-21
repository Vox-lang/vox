; format.asm - Format string macros for Vox Compiler
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
    lea rdi, [rel _format_buffer + 20]
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
    lea rbx, [rel _hex_chars_upper]
    jmp .get_char
.use_lower:
    lea rbx, [rel _hex_chars_lower]
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
    lea rsi, [rel _format_buffer + 20]
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
    lea rdi, [rel _format_buffer + 65]
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
    lea rsi, [rel _format_buffer + 65]
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
    
    lea rdi, [rel _format_buffer + 30]
    mov byte [rdi], 0
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    dec rdi
    mov byte [rdi], '0'
    jmp .print_result
    
.convert_loop:
    test rax, rax
    jz .add_prefix
    
    mov rcx, rax
    and rcx, 7                  ; get low 3 bits
    add cl, '0'
    dec rdi
    mov [rdi], cl
    
    shr rax, 3
    jmp .convert_loop
    
.add_prefix:
    dec rdi
    mov byte [rdi], 'o'
    dec rdi
    mov byte [rdi], '0'
    
.print_result:
    lea rsi, [rel _format_buffer + 30]
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

section .bss
    ; One page of pad characters, refilled per call. Padding used to go out
    ; one write(2) per character - about 265 KB/s, which is the whole reason
    ; a width in the millions took minutes and a width of 2^31 would have
    ; taken hours (docs/BUGS_FOUND.md #61). A width is a character count
    ; with no ceiling, so the loop still writes exactly as many characters
    ; as asked; it just stops paying a syscall for each one.
    _fmt_pad_chunk: resb 4096

section .text

; Write exactly rdx bytes from rsi to stdout.
; A single write(2) is allowed to write less than it was asked to (a pipe
; with a full buffer does exactly that), so a chunked writer that ignores
; the return value silently truncates its output - a per-byte loop never
; had to care. Resumes after a short write and retries an interrupted one.
; Args: rsi = bytes, rdx = length. Clobbers rax, rcx, r11 (the syscall's
; own scratch); rdi, rsi and rdx come back as they went in.
_fmt_write_all:
    push rdi
    push rsi
    push rdx
.chunk:
    test rdx, rdx
    jz .done
    mov rax, 1
    mov rdi, 1
    syscall
    test rax, rax
    jg .advance
    cmp rax, -4                 ; -EINTR: the same bytes, again
    je .chunk
    jmp .done                   ; any other error: stop, as the per-byte
                                 ; loop this replaces also did
.advance:
    add rsi, rax
    sub rdx, rax
    jmp .chunk
.done:
    pop rdx
    pop rsi
    pop rdi
    ret

; Emit rax copies of the pad character in r9b to stdout.
; Args: rax = count (<= 0 writes nothing), r9b = the character.
; Clobbers rax, rcx, rdx, rsi, rdi, r11; r8 and r9 are preserved.
_fmt_emit_pad:
    push r8
    mov r8, rax                 ; characters still owed
    test r8, r8
    jle .done

    ; Fill the chunk with this call's pad character.
    movzx eax, r9b
    lea rdi, [rel _fmt_pad_chunk]
    mov rcx, 4096
    rep stosb

.chunk:
    mov rdx, 4096
    cmp r8, rdx
    jae .have_length
    mov rdx, r8
.have_length:
    lea rsi, [rel _fmt_pad_chunk]
    call _fmt_write_all
    sub r8, rdx
    jnz .chunk

.done:
    pop r8
    ret


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

; Print hex (lowercase) with zero-padding
; Args: value, min_width
%macro PRINT_HEX_LOWER_ZEROPAD 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    xor rdx, rdx                ; lowercase flag = 0
    xor r8, r8                  ; pad char = '0'
    call _print_hex_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print hex (lowercase) with space-padding
; Args: value, min_width
%macro PRINT_HEX_LOWER_PADDED 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    xor rdx, rdx                ; lowercase flag = 0
    mov r8, 1                   ; pad char = ' '
    call _print_hex_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print hex (uppercase) with zero-padding
; Args: value, min_width
%macro PRINT_HEX_UPPER_ZEROPAD 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    mov rdx, 1                  ; uppercase flag = 1
    xor r8, r8                  ; pad char = '0'
    call _print_hex_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print hex (uppercase) with space-padding
; Args: value, min_width
%macro PRINT_HEX_UPPER_PADDED 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    mov rdx, 1                  ; uppercase flag = 1
    mov r8, 1                   ; pad char = ' '
    call _print_hex_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print binary with zero-padding
; Args: value, min_width
%macro PRINT_BINARY_ZEROPAD 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    xor r8, r8                  ; pad char = '0'
    call _print_binary_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print binary with space-padding
; Args: value, min_width
%macro PRINT_BINARY_PADDED 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    mov r8, 1                   ; pad char = ' '
    call _print_binary_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print octal with zero-padding
; Args: value, min_width
%macro PRINT_OCTAL_ZEROPAD 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    xor r8, r8                  ; pad char = '0'
    call _print_octal_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Print octal with space-padding
; Args: value, min_width
%macro PRINT_OCTAL_PADDED 2
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rdi, %1                 ; value
    mov rsi, %2                 ; min width
    mov r8, 1                   ; pad char = ' '
    call _print_octal_padded_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
%endmacro

; Helper: convert hex to buffer, return ptr in rax, len in rcx
; Args: rdi = value, rsi = uppercase flag
; Returns: rax = ptr to digits, rcx = digit count
_hex_to_buffer:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    
    mov r12, rdi                ; value
    mov r13, rsi                ; uppercase flag
    
    ; Build hex string backwards
    lea rdi, [rel _format_buffer + 20]
    mov byte [rdi], 0           ; null terminator
    xor rcx, rcx                ; digit count
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    ; Handle zero
    dec rdi
    mov byte [rdi], '0'
    mov rcx, 1
    jmp .done
    
.convert_loop:
    test rax, rax
    jz .done
    
    push rcx
    mov rcx, rax
    and rcx, 0xF                ; get low nibble
    
    ; Select correct hex char table
    test r13, r13
    jz .use_lower
    lea rbx, [rel _hex_chars_upper]
    jmp .get_char
.use_lower:
    lea rbx, [rel _hex_chars_lower]
.get_char:
    mov cl, [rbx + rcx]
    dec rdi
    mov [rdi], cl
    pop rcx
    inc rcx
    
    shr rax, 4                  ; next nibble
    jmp .convert_loop
    
.done:
    mov rax, rdi                ; return ptr
    ; rcx already has length
    
    pop r13
    pop r12
    leave
    ret

; Helper: convert binary to buffer, return ptr in rax, len in rcx
; Args: rdi = value
; Returns: rax = ptr to digits, rcx = digit count
_binary_to_buffer:
    push rbp
    mov rbp, rsp
    push r12
    
    mov r12, rdi                ; value
    
    ; Build binary string backwards
    lea rdi, [rel _format_buffer + 65]
    mov byte [rdi], 0           ; null terminator
    xor rcx, rcx                ; digit count
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    ; Handle zero
    dec rdi
    mov byte [rdi], '0'
    mov rcx, 1
    jmp .done
    
.convert_loop:
    test rax, rax
    jz .done
    
    push rcx
    mov cl, al
    and cl, 1
    add cl, '0'
    dec rdi
    mov [rdi], cl
    pop rcx
    inc rcx
    
    shr rax, 1
    jmp .convert_loop
    
.done:
    mov rax, rdi                ; return ptr
    ; rcx already has length
    
    pop r12
    leave
    ret

; Helper: convert octal to buffer, return ptr in rax, len in rcx
; Args: rdi = value
; Returns: rax = ptr to digits, rcx = digit count
_octal_to_buffer:
    push rbp
    mov rbp, rsp
    push r12
    
    mov r12, rdi                ; value
    
    ; Build octal string backwards
    lea rdi, [rel _format_buffer + 32]
    mov byte [rdi], 0           ; null terminator
    xor rcx, rcx                ; digit count
    
    mov rax, r12
    test rax, rax
    jnz .convert_loop
    
    ; Handle zero
    dec rdi
    mov byte [rdi], '0'
    mov rcx, 1
    jmp .done
    
.convert_loop:
    test rax, rax
    jz .done
    
    push rcx
    mov rcx, rax
    and cl, 7                   ; get low 3 bits
    add cl, '0'
    dec rdi
    mov [rdi], cl
    pop rcx
    inc rcx
    
    shr rax, 3                  ; next octal digit
    jmp .convert_loop
    
.done:
    mov rax, rdi                ; return ptr
    ; rcx already has length
    
    pop r12
    leave
    ret

; Print hex with zero-padding
; Args: rdi = value, rsi = min width, rdx = uppercase flag
; Print hex, padded to a minimum width with either '0' or ' '.
; Args: rdi = value, rsi = min width, rdx = uppercase flag, r8 = pad
; char flag (0 = '0', 1 = ' ') - shared by both the ZEROPAD and PADDED
; macros below, mirroring how _print_int_padded_impl already does this
; for decimal.
_print_hex_padded_impl:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15
    
    mov r12, rsi                ; min width
    mov r13, rdx                ; uppercase flag
    
    ; Convert to buffer
    mov rsi, r13
    call _hex_to_buffer
    mov r14, rax                ; digit ptr
    mov r15, rcx                ; digit len
    
    ; Print "0x" prefix
    mov byte [rel _format_buffer + 40], '0'
    mov byte [rel _format_buffer + 41], 'x'
    push r14
    push r15
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel _format_buffer + 40]
    mov rdx, 2
    syscall
    pop r15
    pop r14
    
    ; Print leading pad characters if needed
    mov rax, r12
    sub rax, r15                ; padding needed
    jle .print_digits
    
    ; rax = characters of padding, r8 = 0 for '0' and 1 for ' '.
    ; _fmt_emit_pad writes them a page at a time; this used to be one
    ; write(2) per character (docs/BUGS_FOUND.md #61). r9 is saved because
    ; this routine has never clobbered it, and the macro wrapping it does
    ; not push it.
    push r9
    mov r9b, '0'
    test r8, r8
    jz .emit_pad
    mov r9b, ' '
.emit_pad:
    call _fmt_emit_pad
    pop r9
    
.print_digits:
    ; Print the actual digits
    mov rax, 1
    mov rdi, 1
    mov rsi, r14
    mov rdx, r15
    syscall
    
    pop r15
    pop r14
    pop r13
    pop r12
    leave
    ret

; Print binary with zero-padding
; Args: rdi = value, rsi = min width
; Print binary, padded to a minimum width with either '0' or ' '.
; Args: rdi = value, rsi = min width, r8 = pad char flag (0='0', 1=' ')
_print_binary_padded_impl:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    
    mov r12, rsi                ; min width
    
    ; Convert to buffer
    call _binary_to_buffer
    mov r13, rax                ; digit ptr
    mov r14, rcx                ; digit len
    
    ; Print leading pad characters if needed
    mov rax, r12
    sub rax, r14                ; padding needed
    jle .print_digits
    
    ; rax = characters of padding, r8 = 0 for '0' and 1 for ' '.
    ; _fmt_emit_pad writes them a page at a time; this used to be one
    ; write(2) per character (docs/BUGS_FOUND.md #61). r9 is saved because
    ; this routine has never clobbered it, and the macro wrapping it does
    ; not push it.
    push r9
    mov r9b, '0'
    test r8, r8
    jz .emit_pad
    mov r9b, ' '
.emit_pad:
    call _fmt_emit_pad
    pop r9
    
.print_digits:
    ; Print the actual digits
    mov rax, 1
    mov rdi, 1
    mov rsi, r13
    mov rdx, r14
    syscall
    
    pop r14
    pop r13
    pop r12
    leave
    ret

; Print octal, padded to a minimum width with either '0' or ' '.
; Args: rdi = value, rsi = min width, r8 = pad char flag (0='0', 1=' ')
_print_octal_padded_impl:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    
    mov r12, rsi                ; min width
    
    ; Convert to buffer
    call _octal_to_buffer
    mov r13, rax                ; digit ptr
    mov r14, rcx                ; digit len
    
    ; Print "0o" prefix
    mov byte [rel _format_buffer + 40], '0'
    mov byte [rel _format_buffer + 41], 'o'
    push r13
    push r14
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel _format_buffer + 40]
    mov rdx, 2
    syscall
    pop r14
    pop r13
    
    ; Print leading pad characters if needed
    mov rax, r12
    sub rax, r14                ; padding needed
    jle .print_digits
    
    ; rax = characters of padding, r8 = 0 for '0' and 1 for ' '.
    ; _fmt_emit_pad writes them a page at a time; this used to be one
    ; write(2) per character (docs/BUGS_FOUND.md #61). r9 is saved because
    ; this routine has never clobbered it, and the macro wrapping it does
    ; not push it.
    push r9
    mov r9b, '0'
    test r8, r8
    jz .emit_pad
    mov r9b, ' '
.emit_pad:
    call _fmt_emit_pad
    pop r9
    
.print_digits:
    ; Print the actual digits
    mov rax, 1
    mov rdi, 1
    mov rsi, r13
    mov rdx, r14
    syscall
    
    pop r14
    pop r13
    pop r12
    leave
    ret


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
    lea rdi, [rel _format_buffer + 30]
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
    ; For zero-padding a negative number, print the sign first and
    ; pad only the magnitude so the result is e.g. -0007 rather than 000-7.
    cmp byte [r15], '-'
    jne .pad_loop
    push rax
    mov byte [rel _format_buffer + 32], '-'
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel _format_buffer + 32]
    mov rdx, 1
    syscall
    pop rax
    inc r15                     ; skip the sign in the digit string
    dec r8                      ; magnitude length
    mov rbx, r13
    dec rbx                     ; remaining width for magnitude
    sub rbx, r8                 ; padding needed for magnitude
    cmp rbx, 0
    jle .print_result
    mov rax, rbx
    jmp .pad_loop
.pad_space:
    mov r9b, ' '

.pad_loop:
    ; rax = characters of padding, r9b = the pad character. _fmt_emit_pad
    ; writes them a page at a time and preserves r8 and r15 (the digit
    ; string and its length, printed below); this used to be one write(2)
    ; per character, which is what made a width of a million take minutes
    ; (docs/BUGS_FOUND.md #61).
    call _fmt_emit_pad

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

; float.asm defines __FLOAT_ASM_INCLUDED__ and is included before this
; file. Only the precision printer needs it (it shares the big-integer
; digit routine with the default float printer), and codegen sets
; uses_floats alongside uses_format for every `{f:.N}` it emits, so the
; guard never hides a routine a program can actually reach - it keeps
; format.asm assembling on its own for a program that pads integers and
; has no floats at all. Same idiom as list.asm's float-tag branch.
%ifdef __FLOAT_ASM_INCLUDED__

; Print a float with a given number of decimal places.
;
; `{f:.N}` promises "N decimal places" (LANGUAGE.md:3106) and puts no
; ceiling on N. A double is a binary fraction, so it always HAS an exact,
; finite decimal expansion - at most 1074 places, for the smallest
; subnormal - and "N places of it, correctly rounded" is a well-defined
; string for every N. This routine produces exactly that string, digit by
; digit, matching glibc's printf("%.*f") including its round-half-to-even
; on an exact tie.
;
; Nothing here scales the fraction into a register, which is what the
; previous routine did three ways and got wrong three ways from N=18
; (docs/BUGS_FOUND.md #60): a `mulsd`-by-10 loop that accumulated rounding
; error, a 10^N carry threshold built with `imul` that wrapped negative at
; N=19, and one `cvttsd2si` of the scaled fraction that returned the SSE
; "integer indefinite" 0x8000000000000000 from N=20 - the
; -9223372036854775808 that used to appear spliced into the digits. It also
; splices no longer: the same cvttsd2si took the INTEGER part, so every
; magnitude at or beyond 2^63 printed that sentinel too.
;
; The value is taken apart as m * 2^e with m an exact integer mantissa:
;   e >= 0  - an exact integer with no fraction at all. Its digits come
;             from _float_big_int_digits (float.asm), the same routine the
;             default float printer uses for this range, so `{f}` and
;             `{f:.N}` agree on every value including infinities and NaNs.
;   e < 0   - the integer part is m >> -e, which is below 2^52 and so fits
;             a register, and the fraction is the exact rational
;             (m & (2^-e - 1)) / 2^-e. Its decimal digits come from
;             Horner's rule over the numerator's bits, least significant
;             first: start at 0, and for each bit "add it, then halve".
;             Halving a decimal digit string is exact and appends at most
;             one digit (always a 5), so -e steps yield at most -e digits
;             and every digit is the true one.
;
; Digits past the expansion's end are zeros - not an approximation, the
; value has ended - so an N larger than the expansion just pads, and the
; padding goes out a page at a time like every other pad in this file.
;
; xmm0 = value, rdi = N (>= 0)

section .bss
    ; The '.' sits in the byte before the digits so the point and the
    ; fraction go out in one write.
    _fmt_frac_point: resb 8
    ; One decimal digit per byte (0-9, not ASCII until they are written),
    ; index 0 = the first place after the point. 1074 is the longest exact
    ; expansion a double has; the rest is slack for the guard digit.
    _fmt_frac_digits: resb 1088
    ; ASCII digits of the integer part, written right-aligned at +384: 309
    ; for the largest double, plus room to the left for a rounding carry
    ; that lengthens the string (9.95 -> 10.0) and for a '-'.
    _fmt_int_area: resb 400

section .text

_print_float_precision:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72

%define PFP_PRECISION [rbp-56]
%define PFP_LENGTH    [rbp-64]
%define PFP_STICKY    [rbp-72]
%define PFP_SIGN      [rbp-80]
%define PFP_INT_PTR   [rbp-88]
%define PFP_INT_LEN   [rbp-96]
%define PFP_PLACES    [rbp-104]
%define PFP_KEPT      [rbp-112]

    mov PFP_PRECISION, rdi
    mov qword PFP_LENGTH, 0
    mov qword PFP_STICKY, 0

    movq rax, xmm0
    mov rbx, rax
    shr rbx, 63
    mov PFP_SIGN, rbx           ; the sign bit, so -0.0 prints as -0.00
    btr rax, 63                 ; magnitude only from here on

    mov r8, rax
    shr r8, 52                  ; biased exponent
    mov r9, rax
    mov rcx, 0x000FFFFFFFFFFFFF
    and r9, rcx                 ; the stored 52 fraction bits

    ; value = m * 2^e
    test r8, r8
    jz .subnormal
    mov rcx, 1
    shl rcx, 52
    or r9, rcx                  ; m gains the implicit leading 1
    lea r10, [r8 - 1075]        ; e = exponent - bias(1023) - 52
    jmp .have_mantissa
.subnormal:
    mov r10, -1074              ; no implicit bit, fixed exponent
.have_mantissa:

    test r10, r10
    js .has_fraction

    ; ---- e >= 0: an exact integer, and no fraction at all ----
    movq rdi, xmm0
    btr rdi, 63                 ; the sign is printed separately
    lea rsi, [rel _fmt_int_area + 384]
    call _float_big_int_digits  ; rax = first digit, rdx = digit count
    mov PFP_INT_PTR, rax
    mov PFP_INT_LEN, rdx
    mov qword PFP_PLACES, 0     ; no fraction digits exist to produce
    jmp .digits_ready

.has_fraction:
    ; places = -e: the fraction's denominator is 2^places, and its exact
    ; decimal expansion is at most that many digits long.
    mov rcx, r10
    neg rcx
    mov PFP_PLACES, rcx

    ; The integer part is m >> places. e < 0 puts the value below 2^52, so
    ; it always fits in a register - only the e >= 0 branch above needs
    ; digit-string arithmetic.
    xor rax, rax
    mov r11, r9                 ; places >= 64: the whole mantissa is fraction
    cmp rcx, 64
    jae .integer_ready
    mov rax, r9
    shr rax, cl                 ; integer part
    mov r11, 1
    shl r11, cl
    dec r11
    and r11, r9                 ; fraction numerator over 2^places
.integer_ready:

    push r11
    lea rdi, [rel _fmt_int_area + 384]
    mov rbx, 10
    xor rcx, rcx
.integer_digit:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc rcx
    test rax, rax
    jnz .integer_digit
    mov PFP_INT_PTR, rdi
    mov PFP_INT_LEN, rcx
    pop r11

    ; Keep at most N+1 digits: N to print and one to round on. Digits past
    ; those can never change them - halving carries rightward, never left -
    ; so a dropped digit only has to be remembered as "something non-zero
    ; follows", which is what the sticky flag is.
    mov rax, PFP_PLACES
    mov rcx, PFP_PRECISION
    cmp rcx, rax
    jae .keep_all
    lea rax, [rcx + 1]
.keep_all:
    mov PFP_KEPT, rax

    ; Horner over the numerator's bits, least significant first:
    ; digits = (digits + bit) / 2, in decimal, exactly.
    lea rsi, [rel _fmt_frac_digits]
    xor r14, r14                ; digits produced so far
    mov r15, PFP_KEPT
    mov r13, PFP_PLACES         ; one step per bit of the denominator
    xor r12, r12
.halve_step:
    cmp r12, r13
    jae .halve_done
    xor rbx, rbx
    cmp r12, 64
    jae .bit_is_zero            ; the mantissa ran out; the rest are zeros
    mov rcx, r12
    mov rbx, r11
    shr rbx, cl
    and rbx, 1
.bit_is_zero:
    xor rdi, rdi
.halve_digit:
    cmp rdi, r14
    jae .halve_carry
    movzx rax, byte [rsi + rdi]
    lea rcx, [rbx + rbx*4]
    lea rax, [rax + rcx*2]      ; carry*10 + digit, at most 19
    mov rbx, rax
    and rbx, 1                  ; carry into the next place
    shr rax, 1
    mov [rsi + rdi], al
    inc rdi
    jmp .halve_digit
.halve_carry:
    test rbx, rbx
    jz .halve_next
    ; Halving spilled one place further: that digit is always a 5.
    cmp r14, r15
    jae .halve_drop
    mov byte [rsi + r14], 5
    inc r14
    jmp .halve_next
.halve_drop:
    mov qword PFP_STICKY, 1     ; a non-zero digit fell past the guard
.halve_next:
    inc r12
    jmp .halve_step
.halve_done:
    mov PFP_LENGTH, r14

.digits_ready:
    ; Round to N places. r14 = digits produced, r12 = N.
    lea rsi, [rel _fmt_frac_digits]
    mov r14, PFP_LENGTH
    mov r12, PFP_PRECISION
    xor r13, r13                ; carry to add to the last kept digit
    cmp r14, r12
    jbe .rounding_done          ; the expansion ended inside N: exact

    movzx rax, byte [rsi + r12] ; the first digit not being printed
    cmp rax, 5
    ja .round_up
    jb .round_settled
    cmp qword PFP_STICKY, 0
    jne .round_up               ; more than a half: up
    ; Exactly a half, with nothing after it. glibc's printf rounds such a
    ; tie to even, and so does this.
    test r12, r12
    jz .tie_on_integer
    movzx rax, byte [rsi + r12 - 1]
    jmp .tie_parity
.tie_on_integer:
    mov rax, PFP_INT_PTR
    add rax, PFP_INT_LEN
    movzx rax, byte [rax - 1]
    sub rax, '0'
.tie_parity:
    and rax, 1
    jz .round_settled           ; already even
.round_up:
    mov r13, 1
.round_settled:
    mov r14, r12                ; the guard digit is not printed

.rounding_done:
    test r13, r13
    jz .emit
    mov rdi, r14
.carry_digit:
    test rdi, rdi
    jz .carry_into_integer
    dec rdi
    movzx rax, byte [rsi + rdi]
    inc rax
    cmp rax, 10
    jb .carry_settled
    mov byte [rsi + rdi], 0
    jmp .carry_digit
.carry_settled:
    mov [rsi + rdi], al
    jmp .emit

.carry_into_integer:
    ; Every kept place wrapped (0.999 -> 1.000), or N is 0.
    mov rdi, PFP_INT_PTR
    add rdi, PFP_INT_LEN
.carry_integer_digit:
    dec rdi
    mov al, [rdi]
    inc al
    cmp al, '9'
    jbe .carry_integer_settled
    mov byte [rdi], '0'
    cmp rdi, PFP_INT_PTR
    ja .carry_integer_digit
    ; Carried out of the leading digit: 9.99 -> 10.0.
    dec rdi
    mov byte [rdi], '1'
    mov PFP_INT_PTR, rdi
    inc qword PFP_INT_LEN
    jmp .emit
.carry_integer_settled:
    mov [rdi], al

.emit:
    cmp qword PFP_SIGN, 0
    je .sign_done
    mov rdi, PFP_INT_PTR
    dec rdi
    mov byte [rdi], '-'
    mov PFP_INT_PTR, rdi
    inc qword PFP_INT_LEN
.sign_done:
    mov rsi, PFP_INT_PTR
    mov rdx, PFP_INT_LEN
    call _fmt_write_all

    mov r12, PFP_PRECISION
    test r12, r12
    jz .done                    ; no places asked for, no point printed

    lea rsi, [rel _fmt_frac_digits]
    mov rcx, r14
    xor rdi, rdi
.to_ascii:
    cmp rdi, rcx
    jae .ascii_done
    add byte [rsi + rdi], '0'
    inc rdi
    jmp .to_ascii
.ascii_done:
    mov byte [rsi - 1], '.'
    dec rsi
    lea rdx, [rcx + 1]
    call _fmt_write_all

    ; Whatever is left of the N places is zeros: the expansion has ended.
    mov rax, r12
    sub rax, r14
    jle .done
    mov r9b, '0'
    call _fmt_emit_pad

.done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

%undef PFP_PRECISION
%undef PFP_LENGTH
%undef PFP_STICKY
%undef PFP_SIGN
%undef PFP_INT_PTR
%undef PFP_INT_LEN
%undef PFP_PLACES
%undef PFP_KEPT

%endif  ; __FLOAT_ASM_INCLUDED__

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

