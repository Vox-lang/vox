; The lock prefix, which the corpus never uses.
section .text
    lock inc qword [rax]
