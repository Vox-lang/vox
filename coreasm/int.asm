; int.asm - Integer operations for English Compiler
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
    cqo
    idiv rbx
%endmacro

%macro INT_MOD 0
    cqo
    idiv rbx
    mov rax, rdx
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
