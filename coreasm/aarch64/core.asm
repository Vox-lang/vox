; core.asm - Core macros for Vox
; Always included - provides essential functionality

%ifdef SHARED_LIB
    ; Shared library mode: declare BSS as extern
    extern _last_error
%else
    ; Global error flag - set by runtime checks (bounds, syscalls, etc.)
    section .bss
        _last_error: resq 1      ; 0 = no error, non-zero = error code
%endif

section .text

