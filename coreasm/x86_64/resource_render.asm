; resource_render.asm - Sink-agnostic render writers (the bodies behind
; io.asm's RENDER_* macros). Split from resource.asm (audit rec 1).
; _render_bytes/_render_cstr/_render_int look at _render_sink (core.asm)
; and either write to stdout or append to the named dynamic buffer.
;
; Gated on (resource present) && (uses_lists || uses_maps || uses_format):
; the only expanders of RENDER_* are the list/map collection printers and
; format.asm's _fmt_write_all / _buffer_append_float_precision. A program
; with no collection renderer and no format machinery has no non-stdout
; sink to reach, so this module is dead weight for it. The %ifdef
; __IO_ASM_INCLUDED__ guard (verbatim from resource.asm) keeps the body
; out when io.asm is absent.

section .text
; ============================================================================
; RENDER SINK WRITERS
; ============================================================================
; The bodies behind io.asm's RENDER_* macros. Each one looks at
; `_render_sink` (core.asm) and either performs exactly what the PRINT_*
; macro it replaced performed, or appends the same bytes to the dynamic
; buffer the sink names, storing back the (possibly reallocated) pointer.
; They live here, not in io.asm, because that is where `_buffer_append_*`
; lives: io.asm is included even by programs with no buffer runtime at all.
;
; Every general-purpose register the callers could care about is preserved:
; `_print_int_impl` clobbers rbx and the syscall path clobbers rcx/r11, and
; the collection renderers call these from the middle of a walk.
;
; Gated on __IO_ASM_INCLUDED__ because the stdout branches use it. io.asm is
; included before this file, so the define is visible.
%ifdef __IO_ASM_INCLUDED__

; _render_bytes - write/append rdx bytes at rsi.
; Args: rsi = source pointer, rdx = length.
_render_bytes:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    mov rax, [rel _render_sink]
    test rax, rax
    jnz .render_bytes_to_buffer

    ; stdout: instruction for instruction what PRINT_STR emitted
    mov rax, 1
    mov rdi, 1
    syscall
    jmp .render_bytes_done

.render_bytes_to_buffer:
    mov rdi, rax                    ; destination buffer; rsi/rdx already set
    call _buffer_append_bytes
    mov [rel _render_sink], rax     ; the append may have reallocated it

.render_bytes_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; _render_cstr - write/append a NUL-terminated string.
; Args: rdi = C-string pointer.
_render_cstr:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    mov rax, [rel _render_sink]
    test rax, rax
    jnz .render_cstr_to_buffer

    call _print_cstr_impl           ; rdi = string, as PRINT_CSTR does
    jmp .render_cstr_done

.render_cstr_to_buffer:
    mov rsi, rdi                    ; source string
    mov rdi, rax                    ; destination buffer
    call _buffer_append_cstr
    mov [rel _render_sink], rax

.render_cstr_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; _render_int - write/append a signed 64-bit integer in decimal.
; Args: rdi = value.
_render_int:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    mov rax, [rel _render_sink]
    test rax, rax
    jnz .render_int_to_buffer

    call _print_int_impl            ; rdi = value, as PRINT_INT does
    jmp .render_int_done

.render_int_to_buffer:
    mov rsi, rdi                    ; value
    mov rdi, rax                    ; destination buffer
    xor rdx, rdx                    ; width 0 - the renderers never pad
    xor rcx, rcx                    ; no zero padding
    xor r8, r8                      ; base 10, matching _print_int_impl
    xor r9, r9                      ; uppercase flag (hex only)
    call _buffer_append_formatted_int
    mov [rel _render_sink], rax

.render_int_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

%endif
