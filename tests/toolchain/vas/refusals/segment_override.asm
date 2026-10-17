; A segment override, such as the thread pointer in fs.
section .text
    mov rax, [fs:0]
