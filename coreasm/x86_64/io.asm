; io.asm - Input/Output macros for Vox Compiler

section .data
    newline_char: db 10
    int_buffer: times 21 db 0

section .text

%macro PRINT_STR 2
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel %1]
    mov rdx, %2
    syscall
%endmacro

%macro PRINT_NEWLINE 0
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel newline_char]
    mov rdx, 1
    syscall
%endmacro

; Print null-terminated string (C-string) - pointer in register
; Print a buffer's content directly to stdout, using its own tracked
; length rather than scanning for a NUL terminator. Buffer content
; isn't reliably NUL-terminated at its logical end (_buffer_clear only
; zeroes the first byte, not the whole allocation), so a NUL-scanning
; print could read straight through stale bytes left over from a
; previous longer value. Mirrors FILE_WRITE_BUF in file.asm, which
; already does this correctly for file descriptors other than stdout.
; Args: buffer struct pointer
%macro PRINT_BUF 1
    push rax
    push rdi
    push rsi
    push rdx

    mov rsi, %1                     ; buffer struct pointer (read %1 BEFORE
                                     ; touching rdi below - the caller may
                                     ; pass rdi itself as %1)
    mov rdx, [rsi + 8]              ; length from struct offset 8
    add rsi, 24                     ; data starts at offset 24
    mov rax, 1                      ; sys_write
    mov rdi, 1                      ; fd = stdout
    syscall

    pop rdx
    pop rsi
    pop rdi
    pop rax
%endmacro

%macro PRINT_CSTR 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, %1
    call _print_cstr_impl
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

_print_cstr_impl:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rsi, rdi          ; string pointer
    xor rcx, rcx          ; length counter
    
.count_loop:
    mov al, [rsi + rcx]
    test al, al
    jz .do_print
    inc rcx
    jmp .count_loop
    
.do_print:
    mov rax, 1            ; sys_write
    mov rdx, rcx          ; length
    mov rdi, 1            ; stdout
    syscall
    
    pop rbx
    leave
    ret

%macro PRINT_INT 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    
    mov rax, %1
    mov rdi, rax
    call _print_int_impl
    
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

_print_int_impl:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov rax, rdi
    mov rcx, 0
    mov r8, 0
    
    test rax, rax
    jns .positive
    neg rax
    mov r8, 1
    
.positive:
    lea rdi, [rel int_buffer + 20]
    mov byte [rdi], 0
    
    test rax, rax
    jnz .convert_loop
    dec rdi
    mov byte [rdi], '0'
    inc rcx
    jmp .print_number
    
.convert_loop:
    test rax, rax
    jz .check_negative
    
    mov rdx, 0
    mov rbx, 10
    div rbx
    
    add dl, '0'
    dec rdi
    mov [rdi], dl
    inc rcx
    jmp .convert_loop
    
.check_negative:
    test r8, r8
    jz .print_number
    dec rdi
    mov byte [rdi], '-'
    inc rcx
    
.print_number:
    mov rax, 1
    mov rsi, rdi
    mov rdx, rcx
    mov rdi, 1
    syscall
    
    leave
    ret
