; .fini_array holds the cleanup a shared library runs when it is unloaded.
section .fini_array progbits alloc write
    dq 0
