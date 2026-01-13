; binary.asm - Bitwise operations and byte access macros for English Compiler
; Provides: bitwise ops, byte read/write, bounds checking

section .data
    _err_bounds_msg: db "Error: Index out of bounds", 10, 0
    _err_bounds_len: equ 27

section .text

; ============================================================================
; BITWISE OPERATIONS - All operate on rax, result in rax
; ============================================================================

; Bitwise AND: rax = rax AND %1
%macro BIT_AND 1
    and rax, %1
%endmacro

; Bitwise OR: rax = rax OR %1
%macro BIT_OR 1
    or rax, %1
%endmacro

; Bitwise XOR: rax = rax XOR %1
%macro BIT_XOR 1
    xor rax, %1
%endmacro

; Bitwise NOT: rax = NOT rax
%macro BIT_NOT 0
    not rax
%endmacro

; Shift left: rax = rax << %1
%macro BIT_SHL 1
    mov cl, %1
    shl rax, cl
%endmacro

; Shift right (logical): rax = rax >> %1
%macro BIT_SHR 1
    mov cl, %1
    shr rax, cl
%endmacro

; Shift right (arithmetic, preserves sign): rax = rax >> %1
%macro BIT_SAR 1
    mov cl, %1
    sar rax, cl
%endmacro

; ============================================================================
; BYTE ACCESS - Read/write individual bytes in buffers
; All indexes are 1-based (natural English: "byte 1" = first byte)
; ============================================================================

; Read byte at 1-based index from buffer
; Args: buffer_ptr, index (1-based)
; Returns: byte value in rax (zero-extended)
%macro BYTE_READ 2
    push rbx
    push rcx
    
    mov rbx, %1                 ; buffer pointer
    mov rcx, %2                 ; 1-based index
    dec rcx                     ; convert to 0-based
    
    xor rax, rax
    mov al, [rbx + rcx]         ; read single byte
    
    pop rcx
    pop rbx
%endmacro

; Write byte at 1-based index to buffer
; Args: buffer_ptr, index (1-based), value
%macro BYTE_WRITE 3
    push rbx
    push rcx
    push rdx
    
    mov rbx, %1                 ; buffer pointer
    mov rcx, %2                 ; 1-based index
    dec rcx                     ; convert to 0-based
    mov rdx, %3                 ; value to write
    
    mov [rbx + rcx], dl         ; write single byte
    
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Read byte with bounds checking
; Args: buffer_ptr, buffer_size, index (1-based)
; Returns: byte value in rax, sets carry flag on error
%macro BYTE_READ_SAFE 3
    push rbx
    push rcx
    push rdx
    
    mov rbx, %1                 ; buffer pointer
    mov rcx, %3                 ; 1-based index
    mov rdx, %2                 ; buffer size
    
    ; Check bounds: index must be >= 1 and <= size
    test rcx, rcx
    jz %%bounds_error           ; index 0 is invalid
    cmp rcx, rdx
    ja %%bounds_error           ; index > size is invalid
    
    dec rcx                     ; convert to 0-based
    xor rax, rax
    mov al, [rbx + rcx]
    clc                         ; clear carry = success
    jmp %%done
    
%%bounds_error:
    xor rax, rax                ; return 0
    stc                         ; set carry = error
    
%%done:
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Write byte with bounds checking
; Args: buffer_ptr, buffer_size, index (1-based), value
; Sets carry flag on error
%macro BYTE_WRITE_SAFE 4
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, %1                 ; buffer pointer
    mov rcx, %3                 ; 1-based index
    mov rdx, %2                 ; buffer size
    mov rsi, %4                 ; value to write
    
    ; Check bounds: index must be >= 1 and <= size
    test rcx, rcx
    jz %%bounds_error           ; index 0 is invalid
    cmp rcx, rdx
    ja %%bounds_error           ; index > size is invalid
    
    dec rcx                     ; convert to 0-based
    mov [rbx + rcx], sil        ; write single byte
    clc                         ; clear carry = success
    jmp %%done
    
%%bounds_error:
    stc                         ; set carry = error
    
%%done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Print bounds error message to stderr and set error flag
%macro BOUNDS_ERROR 0
    push rax
    push rdi
    push rsi
    push rdx
    
    mov rax, 1                  ; sys_write
    mov rdi, 2                  ; stderr
    lea rsi, [_err_bounds_msg]
    mov rdx, _err_bounds_len
    syscall
    
    pop rdx
    pop rsi
    pop rdi
    pop rax
%endmacro

; ============================================================================
; BUFFER UTILITIES
; ============================================================================

; Get buffer data pointer (skip header: capacity + length = 16 bytes)
; Args: buffer_var_ptr
; Returns: data pointer in rax
%macro BUFFER_DATA_PTR 1
    mov rax, %1
    add rax, 16                 ; skip capacity (8) + length (8)
%endmacro

; Get buffer length
; Args: buffer_var_ptr
; Returns: length in rax
%macro BUFFER_LENGTH 1
    mov rax, [%1 + 8]           ; length is at offset 8
%endmacro

; Get buffer capacity
; Args: buffer_var_ptr
; Returns: capacity in rax
%macro BUFFER_CAPACITY 1
    mov rax, [%1]               ; capacity is at offset 0
%endmacro

; ============================================================================
; STRING BYTE ACCESS (for inline string modification)
; ============================================================================

; Get string length (null-terminated)
; Args: string_ptr
; Returns: length in rax (not including null terminator)
%macro STRING_LENGTH 1
    push rcx
    push rdi
    
    mov rdi, %1
    xor rcx, rcx
%%loop:
    cmp byte [rdi + rcx], 0
    je %%done
    inc rcx
    jmp %%loop
%%done:
    mov rax, rcx
    
    pop rdi
    pop rcx
%endmacro

