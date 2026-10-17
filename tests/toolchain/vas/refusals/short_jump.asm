; short asks for an 8-bit jump; vas always writes 32-bit ones.
section .text
target:
    jmp short target
