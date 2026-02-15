; string.asm - String operations for English Compiler

section .text

%macro STR_LEN 1
    push rdi
    push rcx
    
    mov rdi, %1
    xor rcx, rcx
    
%%len_loop:
    cmp byte [rdi + rcx], 0
    je %%len_done
    inc rcx
    jmp %%len_loop
    
%%len_done:
    mov rax, rcx
    
    pop rcx
    pop rdi
%endmacro

%macro STR_COPY 2
    push rax
    push rdi
    push rsi
    
    mov rdi, %1
    mov rsi, %2
    
%%copy_loop:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz %%copy_done
    inc rsi
    inc rdi
    jmp %%copy_loop
    
%%copy_done:
    pop rsi
    pop rdi
    pop rax
%endmacro

%macro STR_CMP 2
    push rdi
    push rsi
    push rbx
    
    mov rdi, %1
    mov rsi, %2
    
%%cmp_loop:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne %%cmp_diff
    test al, al
    jz %%cmp_equal
    inc rdi
    inc rsi
    jmp %%cmp_loop
    
%%cmp_diff:
    movzx rax, al
    movzx rbx, bl
    sub rax, rbx
    jmp %%cmp_done
    
%%cmp_equal:
    xor rax, rax
    
%%cmp_done:
    pop rbx
    pop rsi
    pop rdi
%endmacro

; Duplicate a null-terminated string
; Args: rdi = source string pointer
; Returns: rax = pointer to new copy (or 0 on failure)
global _strdup
_strdup:
    push rbx
    push r12
    push r13
    
    mov r12, rdi            ; save source pointer
    
    ; Get string length
    xor rcx, rcx
.strdup_len:
    cmp byte [rdi + rcx], 0
    je .strdup_len_done
    inc rcx
    jmp .strdup_len
.strdup_len_done:
    inc rcx                 ; +1 for null terminator
    mov r13, rcx            ; save length+1
    
    ; Allocate memory via mmap
    mov rax, 9              ; sys_mmap
    mov rdi, 0              ; addr = NULL
    mov rsi, rcx            ; size = len+1
    add rsi, 4095
    and rsi, ~4095          ; page-align
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 0x22           ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1              ; fd = -1
    mov r9, 0               ; offset = 0
    syscall
    
    cmp rax, -1
    je .strdup_fail
    
    mov rbx, rax            ; save dest pointer
    
    ; Copy string
    xor rcx, rcx
.strdup_copy:
    cmp rcx, r13
    jge .strdup_done
    mov al, [r12 + rcx]
    mov [rbx + rcx], al
    inc rcx
    jmp .strdup_copy
    
.strdup_done:
    mov rax, rbx            ; return new string pointer
    pop r13
    pop r12
    pop rbx
    ret

.strdup_fail:
    xor rax, rax
    pop r13
    pop r12
    pop rbx
    ret

; String equality function (callable)
; Args: rdi = string1, rsi = string2
; Returns: rax = 1 if equal, 0 if not
global _str_eq
_str_eq:
    push rbx
.loop:
    mov al, [rdi]
    mov bl, [rsi]
    cmp al, bl
    jne .not_equal
    test al, al
    jz .equal
    inc rdi
    inc rsi
    jmp .loop
.not_equal:
    xor rax, rax
    pop rbx
    ret
.equal:
    mov rax, 1
    pop rbx
    ret
