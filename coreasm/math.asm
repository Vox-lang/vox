; math.asm - Math operations for English Compiler

section .text

%macro MATH_ABS 1
    mov rax, %1
    test rax, rax
    jns %%done
    neg rax
%%done:
%endmacro

%macro MATH_MIN 2
    mov rax, %1
    cmp rax, %2
    jle %%done
    mov rax, %2
%%done:
%endmacro

%macro MATH_MAX 2
    mov rax, %1
    cmp rax, %2
    jge %%done
    mov rax, %2
%%done:
%endmacro

%macro IS_EVEN 1
    mov rax, %1
    test rax, 1
    setz al
    movzx rax, al
%endmacro

%macro IS_ODD 1
    mov rax, %1
    test rax, 1
    setnz al
    movzx rax, al
%endmacro
