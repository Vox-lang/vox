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

; ============================================================================
; ERROR FLAG (_last_error) WRITES
; ============================================================================
; The error flag is a single qword in .bss. Every codegen site that sets or
; clears it goes through these three macros so the flag's storage (symbol,
; size, [rel ...] addressing) is owned by core.asm, not sprinkled through the
; frontend. A future backend that moves the flag elsewhere changes one file.
;
; Reads stay raw (`mov rax, [rel _last_error]`): a read is not a lifecycle
; op, and the On error handler is the only reader.

; SET_LAST_ERROR <code> — record a failure code (1 = generic miss, or an
; errno value). Clobbers nothing.
%macro SET_LAST_ERROR 1
    mov qword [rel _last_error], %1
%endmacro

; CLEAR_LAST_ERROR — clear the flag on a success path. The lifecycle rule
; (core.asm .bss comment above) requires every fallible op to clear on
; success so a later On error only sees the most recent failure.
%macro CLEAR_LAST_ERROR 0
    mov qword [rel _last_error], 0
%endmacro

; SET_LAST_ERROR_RAX — record the errno currently in rax (e.g. a syscall
; that returned -errno). Clobbers nothing; rax is read, not written.
%macro SET_LAST_ERROR_RAX 0
    mov [rel _last_error], rax
%endmacro

; ============================================================================
; DYNAMIC BUFFER HEADER LAYOUT — [capacity][length][flags][data]
; ============================================================================
; The single source of truth for the 24-byte dynamic-buffer header shared
; by codegen (src/codegen/mod.rs: the Rust `BUF_DATA_OFFSET` const mirrors
; these offsets) and the resource.asm runtime (_alloc_buffer / _buffer_*).
; A buffer in memory is:
;   offset 0:  capacity (8 bytes) - bytes allocated for the data area
;   offset 8:  length   (8 bytes) - bytes currently held
;   offset 16: flags    (8 bytes) - reserved (growth/state bits)
;   offset 24: data     - the byte payload; the runtime keeps a trailing
;                         NUL at data[length] so a buffer is a C string too.
; Lives in core.asm (always included) so every backend sees one layout
; without dragging in resource.asm. The %defines cost no bytes, and the
; macros emit nothing unless invoked. (LANGUAGE.md buffer layout.)
%define BUF_CAPACITY_OFFSET   0
%define BUF_LENGTH_OFFSET     8
%define BUF_FLAGS_OFFSET      16
%define BUF_DATA_OFFSET       24

; BUFFER_DATA_ADDR <reg> — point <reg> at the data area of a buffer whose
; base it currently holds. In-place (clobbers <reg>). Replaces the raw
; `add rax/rdi/rbx, 24` sequences formerly scattered through codegen.
%macro BUFFER_DATA_ADDR 1
    add %1, BUF_DATA_OFFSET
%endmacro

; BUFFER_DATA_ADDR_LEA <dst>, <base> — load the data address into <dst>
; without clobbering <base>. Replaces `lea rsi, [rbx + 24]`.
%macro BUFFER_DATA_ADDR_LEA 2
    lea %1, [%2 + BUF_DATA_OFFSET]
%endmacro

; BUFFER_LENGTH <ptr> — load the current length into rax.
%macro BUFFER_LENGTH 1
    mov rax, [%1 + BUF_LENGTH_OFFSET]
%endmacro

; BUFFER_CAPACITY <ptr> — load the capacity into rax.
%macro BUFFER_CAPACITY 1
    mov rax, [%1 + BUF_CAPACITY_OFFSET]
%endmacro

; ============================================================================
; BOOLEAN MATERIALISATION & TAG COMPARISON
; ============================================================================
; The test/setcc/movzx and cmp/setcc/movzx idiots are x86_64 flag-dances.
; Centralising them lets a backend choose its own boolean materialisation
; (e.g. AArch64 `cset`) and tag-compare idiom without a frontend sweep.

; BOOL_FROM_RAX — materialise a boolean (0/1) from any scalar in rax:
; rax = (rax != 0) ? 1 : 0. Used by every scalar-to-boolean retyping/cast.
; Clobbers rax (reads and rewrites it).
%macro BOOL_FROM_RAX 0
    test rax, rax
    setne al
    movzx rax, al
%endmacro

; TAG_EQ_IMM <imm> — rax = (r11 == imm) ? 1 : 0. For runtime `is a <type>`
; and `is nothing` predicates, where r11 holds the value's tag byte. The
; caller zeroes rax first only for readability; movzx makes it redundant.
; Clobbers rax (and reads r11).
%macro TAG_EQ_IMM 1
    cmp r11, %1
    sete al
    movzx rax, al
%endmacro

; TAG_NE_IMM <imm> — rax = (r11 != imm) ? 1 : 0. The not-equal form, for
; negated predicates (`is not nothing`). Clobbers rax (reads r11).
%macro TAG_NE_IMM 1
    cmp r11, %1
    setne al
    movzx rax, al
%endmacro

; ============================================================================
; INTEGER PREDICATES & ARITHMETIC (operate on rax)
; ============================================================================
; The Even/Odd/Zero/Positive/Negative predicates and the Absolute/Sign
; operations are x86_64 flag-dances over rax. Codegen formerly emitted two
; different idioms for the same predicate (test/setcc/movzx and and/xor);
; both now route through one macro so a backend swaps the idiom in one place.
; All are pure-rax except INT_ABS (no extra reg) and INT_SIGN (clobbers
; rbx, rcx). Lives in core.asm (always included) so every predicate site sees
; them without dragging in int.asm.

; INT_IS_EVEN — rax = (rax is even) ? 1 : 0.
%macro INT_IS_EVEN 0
    test rax, 1
    setz al
    movzx rax, al
%endmacro

; INT_IS_ODD — rax = (rax is odd) ? 1 : 0.
%macro INT_IS_ODD 0
    test rax, 1
    setnz al
    movzx rax, al
%endmacro

; INT_IS_ZERO — rax = (rax == 0) ? 1 : 0.
%macro INT_IS_ZERO 0
    test rax, rax
    setz al
    movzx rax, al
%endmacro

; INT_IS_POSITIVE — rax = (rax > 0) ? 1 : 0 (signed).
%macro INT_IS_POSITIVE 0
    test rax, rax
    setg al
    movzx rax, al
%endmacro

; INT_IS_NEGATIVE — rax = (rax < 0) ? 1 : 0 (signed).
%macro INT_IS_NEGATIVE 0
    test rax, rax
    setl al
    movzx rax, al
%endmacro

; INT_ABS — rax = |rax|. Uses a NASM %% local label so every expansion gets
; its own target without a codegen-side label counter.
%macro INT_ABS 0
    test rax, rax
    jns %%done
    neg rax
%%done:
%endmacro

; INT_SIGN — rax = sign(rax): -1, 0, or 1 (signed). Clobbers rbx and rcx.
; The trailing cmovz rax,rax is a deliberate no-op (rax already holds 0 on
; the zero path) kept for readability of the three-way branch.
%macro INT_SIGN 0
    test rax, rax
    mov rbx, 1
    mov rcx, -1
    cmovg rax, rbx  ; positive -> 1
    cmovl rax, rcx  ; negative -> -1
    cmovz rax, rax  ; zero -> 0 (already)
%endmacro

; ============================================================================
; BUFFER STATE PREDICATES (operate on a buffer whose base is in a register)
; ============================================================================
; Mirror the list.asm LIST_IS_EMPTY idiom for dynamic buffers, using the
; BUF_*_OFFSET layout above. BUFFER_IS_EMPTY takes the base in %1 (loads
; length into rax, then test/setz/movzx). BUFFER_IS_FULL takes the base in
; rax and uses rbx as scratch (clobbers rbx) so the capacity can be saved
; before rax is overwritten with the length.

; BUFFER_IS_EMPTY <ptr> — rax = (buffer length == 0) ? 1 : 0.
%macro BUFFER_IS_EMPTY 1
    mov rax, [%1 + BUF_LENGTH_OFFSET]
    test rax, rax
    setz al
    movzx rax, al
%endmacro

; BUFFER_IS_FULL — rax = (buffer length == capacity) ? 1 : 0. Base in rax,
; clobbers rbx.
%macro BUFFER_IS_FULL 0
    mov rbx, [rax + BUF_CAPACITY_OFFSET]   ; capacity
    mov rax, [rax + BUF_LENGTH_OFFSET]     ; size
    cmp rax, rbx
    sete al
    movzx rax, al
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
