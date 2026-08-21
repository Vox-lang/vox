; core.asm - Core macros for Vox Compiler
; Always included - provides essential functionality

; Global error flag - set by runtime checks (bounds, syscalls, etc.)
; This is always available so bounds checks can set it
section .bss
    ; _last_error lifecycle: any operation that may set this flag on failure
    ; must clear it to 0 on its success path, so a later On error only sees
    ; errors from the most recent operation. On error itself consumes the flag.
    _last_error: resq 1      ; 0 = no error, non-zero = error code
    _call_depth: resq 1      ; current function call depth (recursion guard)
    ; Shared recursion-depth counter for the recursive printers (_list_print
    ; and _map_print). inc'd on entry, dec'd on every exit path, so it returns
    ; to 0 between top-level prints. Lives here (not in list.asm/map.asm) so a
    ; mixed map/list tree is cycle-safe under ONE 64-deep budget regardless of
    ; which runtime is included. (stage 1e2)
    _print_depth: resq 1
    ; Where the collection renderers (_list_print / _map_print) send their
    ; bytes: 0 = stdout, non-zero = a dynamic buffer pointer to append to.
    ; A format string renders identically in every sink (LANGUAGE.md
    ; "Format Strings Everywhere"), so a list or map interpolated into a
    ; text initializer, a buffer, a `write`, a path, a `treating` clause or
    ; a function argument must produce the same bytes `Print` produces -
    ; from the same renderer. Redirecting that one renderer is how; a
    ; second, buffer-shaped copy of it is how `{list}` shipped as a raw
    ; heap address everywhere except Print (docs/BUGS_FOUND.md #44).
    ; Lives here beside _print_depth because both are state of the shared
    ; renderers, and core.asm is always included.
    _render_sink: resq 1

section .data
    _max_call_depth: dq 10000          ; maximum recursion depth
    ; plan 311: raw wait4 status word from the most recent successful reap.
    ; -1 sentinel before any reap (so "never reaped" is distinct from "exited 0").
    ; Lives in .data, not .bss, because _start (which would zero .bss-bound
    ; globals) is only emitted for executables - a --shared library would
    ; otherwise read 0 and silently report "exited cleanly" with no child reaped.
    _reaped_status: dq -1
    _stack_overflow_msg: db "Error: stack overflow (recursion depth exceeded)", 10, 0
    _stack_overflow_msg_len: equ $ - _stack_overflow_msg - 1

section .text

; _check_call_depth - increment call depth and abort if exceeded
; Called at function entry. Clobbers rax only.
_check_call_depth:
    mov rax, [rel _call_depth]
    inc rax
    mov [rel _call_depth], rax
    cmp rax, [rel _max_call_depth]
    jg .stack_overflow
    ret
.stack_overflow:
    ; Print error message to stderr and exit with code 1
    mov rax, 1              ; SYS_WRITE
    mov rdi, 2              ; stderr
    lea rsi, [rel _stack_overflow_msg]
    mov rdx, _stack_overflow_msg_len
    syscall
    mov rax, 60             ; SYS_EXIT
    mov rdi, 1              ; exit code 1 (not a segfault)
    syscall

; _dec_call_depth - decrement call depth on function return
_dec_call_depth:
    dec qword [rel _call_depth]
    ret

%macro EXIT 1
    mov rax, 60
    mov rdi, %1
    syscall
%endmacro

%macro SYSCALL1 2
    mov rax, %1
    mov rdi, %2
    syscall
%endmacro

%macro SYSCALL2 3
    mov rax, %1
    mov rdi, %2
    mov rsi, %3
    syscall
%endmacro

%macro SYSCALL3 4
    mov rax, %1
    mov rdi, %2
    mov rsi, %3
    mov rdx, %4
    syscall
%endmacro
