; io_win64.asm - Input/Output macros for Vox (Windows 11 / x64)
; NASM syntax, COFF64 output (nasm -f win64)

%define crlf 1

bits 64
default rel

section .data
    %if crlf
        newline_char: db 10
    %else
        newline_char: db 13, 10
    %endif
    int_buffer:   times 21 db 0

section .bss align=8
    stdout_handle: resq 1         ; cached handle (0 = not initialized)

section .text

extern GetStdHandle
extern WriteFile

%define STD_OUTPUT_HANDLE -11

; ------------------------------------------------------------
; _get_stdout_handle
; Returns:
;   RAX = stdout HANDLE
; Clobbers:
;   RCX
; ------------------------------------------------------------
_get_stdout_handle:
    mov     rax, [stdout_handle]
    test    rax, rax
    jnz     .done

    mov     rcx, STD_OUTPUT_HANDLE
    sub     rsp, 28h              ; shadow + align
    call    GetStdHandle
    add     rsp, 28h

    mov     [stdout_handle], rax
.done:
    ret

; ------------------------------------------------------------
; _write_stdout
; Args:
;   RCX = buffer pointer
;   EDX = length (DWORD)
; Returns:
;   RAX = bytes written (best effort), or 0 on failure
; Notes:
;   Uses WinAPI WriteFile(h, buf, len, &written, NULL)
; ------------------------------------------------------------
_write_stdout:
    push    rbp
    mov     rbp, rsp

    ; reserve space for:
    ; - shadow space (32 bytes) required by Win64 ABI
    ; - 8 bytes to keep alignment
    ; - 8 bytes local for "written" (DWORD is enough but keep it simple)
    sub     rsp, 40h

    ; Save args we were given
    mov     r8d, edx              ; len -> r8d for WriteFile
    mov     rdx, rcx              ; buf -> rdx for WriteFile

    call    _get_stdout_handle
    mov     rcx, rax              ; handle -> rcx

    lea     r9, [rbp-4]           ; LPDWORD lpNumberOfBytesWritten
    mov     dword [rbp-4], 0

    ; 5th arg (LPOVERLAPPED) goes on stack after shadow space
    mov     qword [rsp+20h], 0

    call    WriteFile             ; BOOL in RAX (non-zero = success)

    test    rax, rax
    jz      .fail

    mov     eax, dword [rbp-4]    ; return bytes written
    jmp     .done

.fail:
    xor     eax, eax

.done:
    mov     rsp, rbp
    pop     rbp
    ret

; ------------------------------------------------------------
; Macros (same API as Linux version)
; ------------------------------------------------------------

%macro PRINT_STR 2
    lea     rcx, [%1]             ; buffer pointer
    mov     edx, %2               ; length (DWORD)
    call    _write_stdout
%endmacro

%macro PRINT_NEWLINE 0
    lea     rcx, [newline_char]
    mov     edx, 1
    call    _write_stdout
%endmacro

; Print null-terminated string (C-string) - pointer in register
%macro PRINT_CSTR 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    mov  rdi, %1
    call _print_cstr_impl

    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
%endmacro

_print_cstr_impl:
    push rbp
    mov  rbp, rsp
    push rbx

    mov  rsi, rdi          ; string pointer
    xor  ecx, ecx          ; length counter (fits in DWORD)

.count_loop:
    mov  al, [rsi + rcx]
    test al, al
    jz   .do_print
    inc  ecx
    jmp  .count_loop

.do_print:
    ; RCX = buf, EDX = len
    mov  rcx, rsi
    mov  edx, ecx
    call _write_stdout

    pop  rbx
    leave
    ret

%macro PRINT_INT 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8

    mov  rax, %1
    mov  rdi, rax
    call _print_int_impl

    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
%endmacro

_print_int_impl:
    push rbp
    mov  rbp, rsp
    sub  rsp, 32

    mov  rax, rdi
    xor  ecx, ecx          ; digit count
    xor  r8d, r8d          ; negative flag

    test rax, rax
    jns  .positive
    neg  rax
    mov  r8d, 1

.positive:
    lea  rdi, [int_buffer + 20]
    mov  byte [rdi], 0

    test rax, rax
    jnz  .convert_loop
    dec  rdi
    mov  byte [rdi], '0'
    inc  ecx
    jmp  .print_number

.convert_loop:
    test rax, rax
    jz   .check_negative

    xor  edx, edx
    mov  ebx, 10
    div  rbx               ; RAX = RAX/10, RDX = remainder

    add  dl, '0'
    dec  rdi
    mov  [rdi], dl
    inc  ecx
    jmp  .convert_loop

.check_negative:
    test r8d, r8d
    jz   .print_number
    dec  rdi
    mov  byte [rdi], '-'
    inc  ecx

.print_number:
    ; RCX = buf, EDX = len
    mov  rcx, rdi
    mov  edx, ecx
    call _write_stdout

    leave
    ret
