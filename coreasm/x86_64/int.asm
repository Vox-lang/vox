; int.asm - Integer operations for Vox Compiler
; x86-64 implementation

section .text

; Integer arithmetic - operates on rax and rbx, result in rax
%macro INT_ADD 0
    add rax, rbx
%endmacro

%macro INT_SUB 0
    sub rax, rbx
%endmacro

%macro INT_MUL 0
    imul rax, rbx
%endmacro

%macro INT_DIV 0
    test rbx, rbx
    jz %%div_zero
    cqo
    idiv rbx
    jmp %%div_done
%%div_zero:
    xor rax, rax
%%div_done:
%endmacro

%macro INT_MOD 0
    test rbx, rbx
    jz %%mod_zero
    cqo
    idiv rbx
    mov rax, rdx
    jmp %%mod_done
%%mod_zero:
    xor rax, rax
%%mod_done:
%endmacro

; Integer comparisons - compares rax with rbx, result (0 or 1) in rax
%macro INT_EQ 0
    cmp rax, rbx
    sete al
    movzx rax, al
%endmacro

%macro INT_NE 0
    cmp rax, rbx
    setne al
    movzx rax, al
%endmacro

%macro INT_LT 0
    cmp rax, rbx
    setl al
    movzx rax, al
%endmacro

%macro INT_LE 0
    cmp rax, rbx
    setle al
    movzx rax, al
%endmacro

%macro INT_GT 0
    cmp rax, rbx
    setg al
    movzx rax, al
%endmacro

%macro INT_GE 0
    cmp rax, rbx
    setge al
    movzx rax, al
%endmacro

; Boolean operations
%macro INT_AND 0
    and rax, rbx
%endmacro

%macro INT_OR 0
    or rax, rbx
%endmacro

%macro INT_NOT 0
    test rax, rax
    setz al
    movzx rax, al
%endmacro

; Negate integer in rax
%macro INT_NEG 0
    neg rax
%endmacro

; Parse signed integer from string
; Args: rdi = string pointer
; Returns: rax = parsed integer (0 on empty/invalid prefix)
global _parse_i64
_parse_i64:
    push rbx
    push rcx
    push rdx

    xor rax, rax            ; accumulator
    xor rcx, rcx            ; sign flag (0=+,1=-)
    mov rbx, rdi

    mov dl, [rbx]
    cmp dl, '-'
    jne .pi64_loop
    mov rcx, 1
    inc rbx

.pi64_loop:
    mov dl, [rbx]
    test dl, dl
    jz .pi64_done
    cmp dl, '0'
    jl .pi64_done
    cmp dl, '9'
    jg .pi64_done
    imul rax, rax, 10
    sub dl, '0'
    movzx rdx, dl
    add rax, rdx
    inc rbx
    jmp .pi64_loop

.pi64_done:
    test rcx, rcx
    jz .pi64_ret
    neg rax

.pi64_ret:
    pop rdx
    pop rcx
    pop rbx
    ret
