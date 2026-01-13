; args.asm - Command-line arguments and environment variables for English Compiler
; 
; At program start (before _start prologue), the stack contains:
;   [rsp]       = argc (argument count)
;   [rsp+8]     = argv[0] (program name, null-terminated string pointer)
;   [rsp+16]    = argv[1] (first argument)
;   ...
;   [rsp+8*argc+8] = NULL (end of argv)
;   [rsp+8*argc+16] = envp[0] (first environment variable)
;   ...
;   envp ends with NULL
;
; This module captures argc/argv/envp at startup and provides access functions.

section .bss
    ; Saved startup values (must be populated before stack frame setup)
    _argc: resq 1           ; argument count
    _argv: resq 1           ; pointer to argv array
    _envp: resq 1           ; pointer to envp array

section .text

; ============================================================================
; INITIALIZATION - Use SAVE_ARGS macro FIRST in _start, before setting up stack frame
; ============================================================================

; Note: We use a macro instead of a function call because calling a function
; would modify the stack (push return address), corrupting our argc/argv/envp capture.

; ============================================================================
; ARGUMENT COUNT
; ============================================================================

; Get the number of command-line arguments (including program name)
; Returns: argc in rax
global _get_argc
_get_argc:
    mov rax, [rel _argc]
    ret

; ============================================================================
; ARGUMENT ACCESS
; ============================================================================

; Get argument by index (0 = program name, 1 = first arg, etc.)
; Args: index in rdi
; Returns: pointer to null-terminated string in rax, or 0 if out of bounds
global _get_arg
_get_arg:
    ; Check bounds
    cmp rdi, [rel _argc]
    jge .out_of_bounds
    
    ; Get argv[index]
    mov rax, [rel _argv]
    mov rax, [rax + rdi*8]
    ret
    
.out_of_bounds:
    xor rax, rax
    ret

; Get the program name (argv[0])
; Returns: pointer to null-terminated string in rax
global _get_program_name
_get_program_name:
    mov rax, [rel _argv]
    mov rax, [rax]          ; argv[0]
    ret

; ============================================================================
; ENVIRONMENT VARIABLES
; ============================================================================

; Get environment variable by name
; Args: name pointer in rdi (null-terminated, e.g., "PATH")
; Returns: pointer to value string in rax, or 0 if not found
; Note: Returns pointer to the part after "NAME=", not including the name
global _get_env
_get_env:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    
    mov r12, rdi            ; save name pointer
    
    ; Calculate name length
    xor rcx, rcx
.name_len_loop:
    mov al, [r12 + rcx]
    test al, al
    jz .name_len_done
    inc rcx
    jmp .name_len_loop
.name_len_done:
    mov r13, rcx            ; r13 = name length
    
    ; Iterate through envp
    mov rbx, [rel _envp]
    
.env_loop:
    mov rax, [rbx]          ; current env string pointer
    test rax, rax
    jz .not_found           ; NULL = end of envp
    
    ; Compare name with start of env string
    mov rcx, r13            ; length to compare
    mov rdi, r12            ; name
    mov rsi, rax            ; env string
    
.compare_loop:
    test rcx, rcx
    jz .check_equals        ; matched all chars, check for '='
    
    mov al, [rdi]
    mov dl, [rsi]
    cmp al, dl
    jne .next_env
    
    inc rdi
    inc rsi
    dec rcx
    jmp .compare_loop
    
.check_equals:
    ; After name, should be '='
    mov al, [rsi]
    cmp al, '='
    jne .next_env
    
    ; Found! Return pointer to value (after '=')
    inc rsi
    mov rax, rsi
    jmp .done
    
.next_env:
    add rbx, 8              ; next envp entry
    jmp .env_loop
    
.not_found:
    xor rax, rax
    
.done:
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; Get environment variable by index
; Args: index in rdi
; Returns: pointer to full "NAME=value" string in rax, or 0 if out of bounds
global _get_env_at
_get_env_at:
    mov rax, [rel _envp]
    
.count_loop:
    test rdi, rdi
    jz .found_index
    
    mov rcx, [rax]          ; check if NULL
    test rcx, rcx
    jz .out_of_bounds
    
    add rax, 8
    dec rdi
    jmp .count_loop
    
.found_index:
    mov rax, [rax]          ; get the string pointer
    ret
    
.out_of_bounds:
    xor rax, rax
    ret

; Count environment variables
; Returns: count in rax
global _get_env_count
_get_env_count:
    push rbx
    
    mov rbx, [rel _envp]
    xor rax, rax            ; counter
    
.count_loop:
    mov rcx, [rbx]
    test rcx, rcx
    jz .done
    
    inc rax
    add rbx, 8
    jmp .count_loop
    
.done:
    pop rbx
    ret

; ============================================================================
; CONVENIENCE MACROS
; ============================================================================

; Save arguments at program start (MUST be before stack frame setup)
; This is an inline macro to avoid corrupting the stack with a return address
%macro SAVE_ARGS 0
    ; At entry: rsp points to argc on the stack
    ; Stack layout: [rsp]=argc, [rsp+8]=argv[0], [rsp+16]=argv[1], ...
    
    mov rax, [rsp]              ; argc
    mov [rel _argc], rax
    
    lea rax, [rsp+8]            ; argv = address of argv[0]
    mov [rel _argv], rax
    
    ; Calculate envp: skip past argc value + all argv pointers + NULL terminator
    mov rcx, [rsp]              ; argc
    inc rcx                     ; +1 for NULL terminator after argv
    lea rax, [rsp + 8 + rcx*8]  ; envp starts after argv + NULL
    mov [rel _envp], rax
%endmacro

; Get argument count into specified register
%macro GET_ARGC 1
    push rdi
    call _get_argc
    mov %1, rax
    pop rdi
%endmacro

; Get argument by index into rax
; %1 = index (immediate or register)
%macro GET_ARG 1
    mov rdi, %1
    call _get_arg
%endmacro

; Get program name into rax
%macro GET_PROGRAM_NAME 0
    call _get_program_name
%endmacro

; Get environment variable value into rax
; %1 = name label (null-terminated string)
%macro GET_ENV 1
    lea rdi, [%1]
    call _get_env
%endmacro

; Check if we have at least N arguments (including program name)
; Sets ZF if argc < N
%macro CHECK_ARGC 1
    mov rax, [rel _argc]
    cmp rax, %1
%endmacro
