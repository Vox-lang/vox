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
