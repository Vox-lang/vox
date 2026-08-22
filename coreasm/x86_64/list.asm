; list.asm - List element access macros for Vox Compiler
; Provides: element access by index (1-based), bounds checking

section .data
    _err_list_bounds_msg: db "Error: List index out of bounds", 10, 0
    _err_list_bounds_len: equ 32

section .text

; ============================================================================
; LIST STRUCTURE
; ============================================================================
; Lists are stored as:
;   offset 0:  capacity (8 bytes) - max number of elements
;   offset 8:  length (8 bytes) - current number of elements
;   offset 16: element_size (8 bytes) - size of each element in bytes
;   offset 24: data starts here - elements stored contiguously
;   offset 24 + capacity*element_size: type tags - one byte per slot
;
; Type tags make heterogeneous lists work: each slot records what kind of
; value it holds so reads can be dispatched correctly at runtime. Every
; list allocation must therefore reserve capacity extra bytes after the
; data region. Allocations come from mmap (zero-filled), so untagged
; slots default to TAG_INTEGER - homogeneous lists never touch tags and
; keep their statically-typed fast path.
;
; Tag values:
;   0 = integer (default; also the fallback for unknown)
;   1 = string  (slot holds a NUL-terminated C-string pointer)
;   2 = float   (slot holds an IEEE 754 double's bit pattern)
;   3 = boolean (slot holds 0 or 1)

%define LIST_CAPACITY_OFFSET    0
%define LIST_LENGTH_OFFSET      8
%define LIST_ELEMSIZE_OFFSET    16
%define LIST_DATA_OFFSET        24

%define LIST_TAG_INTEGER        0
%define LIST_TAG_STRING         1
%define LIST_TAG_FLOAT          2
%define LIST_TAG_BOOLEAN        3
%define LIST_TAG_LIST           4
%define LIST_TAG_MAP            5
%define LIST_TAG_NOTHING        6

; Guard tested by map.asm: _map_print's LIST-tag branch calls _list_print,
; so it assembles that branch only when list.asm has been included. list.asm
; is included before map.asm, so this define is visible. (stage 1e2)
%define __LIST_ASM_INCLUDED__

; Compute the address of the tag byte for a 0-based index.
; Args: %1 = destination register, %2 = list base register, %3 = 0-based
;       index register. %1 must differ from %2 and %3; clobbers only %1.
; tag_addr = base + LIST_DATA_OFFSET + capacity * element_size + index
%macro LIST_TAG_ADDR 3
    mov %1, [%2 + LIST_CAPACITY_OFFSET]
    imul %1, [%2 + LIST_ELEMSIZE_OFFSET]
    add %1, %3
    lea %1, [%2 + %1 + LIST_DATA_OFFSET]
%endmacro

; ============================================================================
; LIST PROPERTIES
; ============================================================================

; Get list length (number of elements)
; Args: list_ptr
; Returns: length in rax
%macro LIST_LENGTH 1
    mov rax, [%1 + LIST_LENGTH_OFFSET]
%endmacro

; Get list capacity
; Args: list_ptr
; Returns: capacity in rax
%macro LIST_CAPACITY 1
    mov rax, [%1 + LIST_CAPACITY_OFFSET]
%endmacro

; Get element size
; Args: list_ptr
; Returns: element size in rax
%macro LIST_ELEMSIZE 1
    mov rax, [%1 + LIST_ELEMSIZE_OFFSET]
%endmacro

; Check if list is empty
; Args: list_ptr
; Returns: 1 in rax if empty, 0 otherwise
%macro LIST_IS_EMPTY 1
    mov rax, [%1 + LIST_LENGTH_OFFSET]
    test rax, rax
    setz al
    movzx rax, al
%endmacro

; ============================================================================
; LIST ELEMENT ACCESS (1-based indexing)
; ============================================================================

; Get element at 1-based index (no bounds checking)
; Args: list_ptr, index (1-based)
; Returns: element value in rax (for 8-byte elements)
%macro LIST_GET 2
    push rbx
    push rcx
    push rdx
    
    mov rbx, %1                     ; list pointer
    mov rcx, %2                     ; 1-based index
    dec rcx                         ; convert to 0-based
    
    ; Calculate element offset: data_start + (index * element_size)
    mov rdx, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rcx, rdx                   ; rcx = index * element_size
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx                    ; rax = pointer to element
    mov rax, [rax]                  ; load element value
    
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get element at 1-based index with bounds checking
; Args: list_ptr, index (1-based)
; Returns: element value in rax, sets carry flag on error
%macro LIST_GET_SAFE 2
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, %1                     ; list pointer
    mov rcx, %2                     ; 1-based index
    mov rsi, [rbx + LIST_LENGTH_OFFSET]
    
    ; Check bounds: index must be >= 1 and <= length
    test rcx, rcx
    jz %%bounds_error               ; index 0 is invalid
    cmp rcx, rsi
    ja %%bounds_error               ; index > length is invalid
    
    dec rcx                         ; convert to 0-based
    
    ; Calculate element offset
    mov rdx, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rcx, rdx
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx
    mov rax, [rax]
    clc                             ; clear carry = success
    jmp %%done
    
%%bounds_error:
    xor rax, rax
    stc                             ; set carry = error
    
%%done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Set element at 1-based index (no bounds checking)
; Args: list_ptr, index (1-based), value
%macro LIST_SET 3
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, %1                     ; list pointer
    mov rcx, %2                     ; 1-based index
    mov rsi, %3                     ; value
    dec rcx                         ; convert to 0-based
    
    mov rdx, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rcx, rdx
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx
    mov [rax], rsi                  ; store element value
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Set element at 1-based index with bounds checking
; Args: list_ptr, index (1-based), value
; Sets carry flag on error
%macro LIST_SET_SAFE 3
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rbx, %1                     ; list pointer
    mov rcx, %2                     ; 1-based index
    mov rdi, %3                     ; value
    mov rsi, [rbx + LIST_LENGTH_OFFSET]
    
    ; Check bounds
    test rcx, rcx
    jz %%bounds_error
    cmp rcx, rsi
    ja %%bounds_error
    
    dec rcx                         ; convert to 0-based
    
    mov rdx, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rcx, rdx
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx
    mov [rax], rdi
    clc
    jmp %%done
    
%%bounds_error:
    stc
    
%%done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Get first element
; Args: list_ptr
; Returns: first element in rax
%macro LIST_FIRST 1
    LIST_GET %1, 1
%endmacro

; Get last element
; Args: list_ptr
; Returns: last element in rax
%macro LIST_LAST 1
    push rbx
    push rcx
    push rdx
    
    mov rbx, %1
    mov rcx, [rbx + LIST_LENGTH_OFFSET]     ; get length (which is the 1-based index of last)
    
    ; Calculate element offset
    dec rcx                                  ; convert to 0-based
    mov rdx, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rcx, rdx
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx
    mov rax, [rax]
    
    pop rdx
    pop rcx
    pop rbx
%endmacro

; Print list bounds error message to stderr
%macro LIST_BOUNDS_ERROR 0
    push rax
    push rdi
    push rsi
    push rdx
    
    mov rax, 1                      ; sys_write
    mov rdi, 2                      ; stderr
    lea rsi, [rel _err_list_bounds_msg]
    mov rdx, _err_list_bounds_len
    syscall
    
    pop rdx
    pop rsi
    pop rdi
    pop rax
%endmacro

; ============================================================================
; LIST INITIALIZATION
; ============================================================================

; Initialize a list with given capacity and element size
; Args: list_ptr, capacity, element_size
%macro LIST_INIT 3
    push rax
    
    mov rax, %2
    mov [%1 + LIST_CAPACITY_OFFSET], rax
    
    xor rax, rax
    mov [%1 + LIST_LENGTH_OFFSET], rax      ; length = 0
    
    mov rax, %3
    mov [%1 + LIST_ELEMSIZE_OFFSET], rax
    
    pop rax
%endmacro

; Append element to list (if space available)
; Args: list_ptr, value
; Returns: 1 in rax on success, 0 on failure (list full)
%macro LIST_APPEND 2
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, %1
    mov rsi, %2
    
    mov rcx, [rbx + LIST_LENGTH_OFFSET]
    mov rdx, [rbx + LIST_CAPACITY_OFFSET]
    
    cmp rcx, rdx
    jge %%full
    
    ; Calculate offset for new element
    mov rax, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rcx, rax
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx
    mov [rax], rsi                  ; store value
    
    ; Increment length
    inc qword [rbx + LIST_LENGTH_OFFSET]
    
    mov rax, 1                      ; success
    jmp %%done
    
%%full:
    xor rax, rax                    ; failure
    
%%done:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
%endmacro

; ============================================================================
; LIST APPEND FUNCTION (with reallocation)
; ============================================================================
; _list_append - Append an element to a list, growing if necessary
; Args: rdi = list pointer, rsi = value to append, dl = type tag
;       (LIST_TAG_* - callers appending to homogeneous lists pass 0)
; Returns: rax = new list pointer (may differ if reallocated)
; 
; List structure: [capacity:8][length:8][elem_size:8][data...][tags...]
;
_list_append:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14
    push r15
    
    mov rbx, rdi                    ; rbx = list pointer
    mov r12, rsi                    ; r12 = value to append
    movzx r15, dl                   ; r15 = type tag
    
    mov rcx, [rbx + LIST_LENGTH_OFFSET]     ; current length
    mov rdx, [rbx + LIST_CAPACITY_OFFSET]   ; capacity
    
    ; Check if we have space
    cmp rcx, rdx
    jge .need_realloc
    
    ; We have space - append directly
    ; Store the tag first: tag_addr = base + 24 + capacity*elem_size + length
    mov rax, [rbx + LIST_ELEMSIZE_OFFSET]
    imul rdx, rax                           ; capacity * elem_size
    lea rdx, [rbx + rdx + LIST_DATA_OFFSET]
    mov [rdx + rcx], r15b                   ; tags[length] = tag

    imul rcx, rax                           ; offset = length * elem_size
    
    lea rax, [rbx + LIST_DATA_OFFSET]
    add rax, rcx
    mov [rax], r12                          ; store value
    
    inc qword [rbx + LIST_LENGTH_OFFSET]    ; increment length
    
    mov rax, rbx                            ; return original pointer
    jmp .done
    
.need_realloc:
    ; Need to grow the list
    ; New capacity = old capacity * 2 (or 8 if was 0)
    mov r13, rdx                            ; r13 = old capacity
    test r13, r13
    jz .use_default_cap
    shl r13, 1                              ; double it
    jmp .do_alloc
    
.use_default_cap:
    mov r13, 8                              ; default capacity
    
.do_alloc:
    ; Calculate new size: header (24) + capacity * element_size
    ;                     + capacity tag bytes
    mov rax, [rbx + LIST_ELEMSIZE_OFFSET]
    mov r14, rax                            ; r14 = element size
    imul rax, r13                           ; data size
    add rax, r13                            ; + tag bytes (1 per slot)
    add rax, LIST_DATA_OFFSET               ; + header
    
    ; Allocate new memory using mmap
    push rbx

    mov rdi, 0                              ; addr = NULL
    mov rsi, rax                            ; size
    mov rdx, 3                              ; PROT_READ | PROT_WRITE
    mov r10, 0x22                           ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                              ; fd = -1
    mov r9, 0                               ; offset = 0
    mov rax, 9                              ; sys_mmap
    syscall

    pop rbx                                 ; restore old list ptr

    ; Raw sys_mmap returns -errno in [-4095, -1] on failure (not MAP_FAILED)
    cmp rax, -4096
    jbe .mmap_ok
    mov rdi, 1                              ; allocation failure: exit(1)
    mov rax, 60                             ; sys_exit
    syscall
.mmap_ok:
    mov rdi, rax                            ; rdi = new list

    ; Copy header
    mov qword [rdi + LIST_CAPACITY_OFFSET], r13     ; new capacity
    mov rcx, [rbx + LIST_LENGTH_OFFSET]
    mov qword [rdi + LIST_LENGTH_OFFSET], rcx       ; same length
    mov qword [rdi + LIST_ELEMSIZE_OFFSET], r14     ; same elem size

    ; Copy existing data (rdi = new list base, rbx = old list base)
    ; NOTE: the old block is intentionally NOT munmap'd. A second name may
    ; still hold the old pointer - a list stored into another variable, or
    ; sitting in a thing's field - and freeing it here would turn that stale
    ; read into a use-after-free. The leak is geometric (at most ~1x the final
    ; list size) and reclaimed at process exit.
    ;
    ; This comment used to name a list passed as a function PARAMETER as the
    ; case it protects, and the bound above was false for it: the callee's new
    ; pointer never reached the caller, so the caller re-entered at the old
    ; block's capacity on every call and leaked a whole fresh list each time -
    ; linear in call count, not geometric, and the appends past that capacity
    ; were silently dropped (docs/BUGS_FOUND.md #75). A collection parameter now
    ; travels as the address of the caller's storage and the store-back writes
    ; through it, so the caller's pointer advances with the callee's and the
    ; bound above is true again.
    push rdi                                ; save new list base
    lea rdi, [rdi + LIST_DATA_OFFSET]       ; dest = new list data
    lea rsi, [rbx + LIST_DATA_OFFSET]       ; source = old list data
    mov rcx, [rbx + LIST_LENGTH_OFFSET]
    imul rcx, r14                           ; bytes to copy
    rep movsb                               ; no-op when rcx = 0
    pop rdi                                 ; rdi = new list pointer

    ; Copy type tags: old tags start at old_base + 24 + old_cap*elem_size,
    ; new tags at new_base + 24 + new_cap*elem_size. One byte per element.
    push rdi                                ; save new list base
    mov rax, [rbx + LIST_CAPACITY_OFFSET]
    imul rax, r14
    lea rsi, [rbx + rax + LIST_DATA_OFFSET] ; source = old tags
    mov rax, r13
    imul rax, r14
    lea rdi, [rdi + rax + LIST_DATA_OFFSET] ; dest = new tags
    mov rcx, [rbx + LIST_LENGTH_OFFSET]     ; one tag byte per element
    rep movsb                               ; no-op when rcx = 0
    pop rdi                                 ; rdi = new list pointer

    ; Store the tag for the appended element:
    ; tag_addr = new_base + 24 + new_cap*elem_size + length
    mov rcx, [rdi + LIST_LENGTH_OFFSET]
    mov rax, r13
    imul rax, r14
    lea rax, [rdi + rax + LIST_DATA_OFFSET]
    mov [rax + rcx], r15b                   ; tags[length] = tag

    ; Now append the new element
    mov rax, r14                            ; element size
    imul rcx, rax
    
    lea rax, [rdi + LIST_DATA_OFFSET]
    add rax, rcx
    mov [rax], r12                          ; store value
    
    inc qword [rdi + LIST_LENGTH_OFFSET]    ; increment length
    
    mov rax, rdi                            ; return new pointer
    
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================================================
; LIST -> argv CONVERTER (for execve)
; ============================================================================
; _list_to_argv - Build a NULL-terminated C argv array from a Vox list.
; Args: rdi = list pointer, rsi = path pointer (becomes argv[0])
; Returns: rax = pointer to argv array [ path, elem0, elem1, ..., NULL ]
;
; The list stores one 8-byte pointer per element (string elements are
; already NUL-terminated C-string pointers), so elements are copied
; verbatim. The output array is sized exactly (length + 2) slots from a
; single read of the list's length, and the copy loop is bounded by that
; same length - so the argv array can never be overrun regardless of the
; list's contents or capacity. On allocation failure the process exits(1),
; matching the other list allocation sites.
;
_list_to_argv:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi                            ; rbx = list pointer
    mov r12, rsi                            ; r12 = path (argv[0])
    mov r13, [rbx + LIST_LENGTH_OFFSET]     ; r13 = element count

    ; Bytes needed: (length + 2) slots * 8  (path + elements + NULL)
    lea r14, [r13 + 2]
    shl r14, 3                              ; * 8

    ; Allocate the argv array
    mov rdi, 0                              ; addr = NULL
    mov rsi, r14                            ; size
    mov rdx, 3                              ; PROT_READ | PROT_WRITE
    mov r10, 0x22                           ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                              ; fd = -1
    mov r9, 0                               ; offset = 0
    mov rax, 9                              ; sys_mmap
    syscall

    ; Raw sys_mmap returns -errno in [-4095,-1] on failure
    cmp rax, -4096
    jbe .argv_ok
    mov rdi, 1
    mov rax, 60                             ; sys_exit
    syscall
.argv_ok:
    ; rax = argv array base
    mov [rax], r12                          ; argv[0] = path

    ; Copy element pointers: argv[1 + i] = list.data[i]
    xor rcx, rcx                            ; i = 0
    lea rsi, [rbx + LIST_DATA_OFFSET]       ; source = list data
.copy_loop:
    cmp rcx, r13
    jge .copy_done
    mov rdx, [rsi + rcx*8]                  ; element pointer
    mov [rax + rcx*8 + 8], rdx              ; argv[1 + i]
    inc rcx
    jmp .copy_loop
.copy_done:
    ; NULL terminator at argv[length + 1]
    mov qword [rax + r13*8 + 8], 0

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; WHOLE-LIST PRINTING
; ============================================================================
; _list_print - Render a list as [elem, elem, ...].
; Args:      rdi = list pointer
; Clobbers:  rax, rcx, rdx, rsi, rdi, r8-r11. Preserves rbx, r12-r14.
; Per slot: dispatch on the tag byte; strings are quoted; unhandled tags
; print as integers. Requires io.asm (RENDER_*); float branch requires
; float.asm - hence the %ifdef guards.
;
; The bytes leave through RENDER_* rather than PRINT_*, so this one routine
; serves both `Print flat.` and `a text called note is "{flat}".` - see
; io.asm's RENDER_* block and `_list_render_to_buffer` below
; (docs/BUGS_FOUND.md #44).
%ifdef __IO_ASM_INCLUDED__
section .data
    _lp_lbrk:      db "["
    _lp_lbrk_len:  equ $ - _lp_lbrk
    _lp_rbrk:      db "]"
    _lp_rbrk_len:  equ $ - _lp_rbrk
    _lp_comma:     db ", "
    _lp_comma_len: equ $ - _lp_comma
    _lp_quote:     db '"'
    _lp_quote_len: equ $ - _lp_quote
    ; Truncation marker printed when the nesting depth limit is hit (a
    ; cyclic structure would otherwise recurse forever).
    _lp_trunc:     db "..."
    _lp_trunc_len: equ $ - _lp_trunc
    ; Rendered for a nothing/null element (stage 1e3, tag 6).
    _lp_nothing:   db "nothing"
    _lp_nothing_len: equ $ - _lp_nothing
    ; The recursion-depth counter (_print_depth) lives in core.asm so it is
    ; shared with _map_print (one budget for a mixed map/list tree).

section .text
_list_print:
    push rbx
    push r12
    push r13
    push r14

    ; Lifecycle: any operation that may set _last_error on failure must clear
    ; it on the success path. Do this once at entry so recursive calls clear
    ; for their own frame; the depth-limit error path sets it before returning,
    ; and the unwinding frames do not clear it again.
    mov qword [rel _last_error], 0

    ; Depth guard (stage 1e1): cap recursion at 64 levels so a cyclic list
    ; (e.g. `append x to x`) terminates instead of overflowing the stack.
    ; On overflow, set the error flag, print a truncation marker, and return.
    inc qword [rel _print_depth]
    cmp qword [rel _print_depth], 64
    jg .lp_depth

    mov rbx, rdi                        ; rbx = list pointer

    ; Opening bracket
    RENDER_STR _lp_lbrk, _lp_lbrk_len

    mov r13, [rbx + LIST_LENGTH_OFFSET] ; r13 = length
    test r13, r13
    jz .lp_close                        ; empty list -> just print "]"

    xor r12, r12                        ; r12 = 0-based index

.lp_loop:
    ; Separator before every element except the first
    test r12, r12
    jz .lp_first
    RENDER_STR _lp_comma, _lp_comma_len
.lp_first:
    ; Element address = base + 24 + index * element_size
    mov r14, [rbx + LIST_ELEMSIZE_OFFSET]
    imul r14, r12
    lea r14, [rbx + r14 + LIST_DATA_OFFSET]   ; r14 = &element

    LIST_TAG_ADDR rcx, rbx, r12
    movzx r8, byte [rcx]                ; r8 = element's type tag

    cmp r8, LIST_TAG_STRING
    je .lp_str
%ifdef __FLOAT_ASM_INCLUDED__
    cmp r8, LIST_TAG_FLOAT
    je .lp_flt
%endif
    cmp r8, LIST_TAG_LIST
    je .lp_list
%ifdef __MAP_ASM_INCLUDED__
    cmp r8, LIST_TAG_MAP
    je .lp_map
%endif
    cmp r8, LIST_TAG_NOTHING
    je .lp_nothing
    ; Integer, boolean (as 1/0), and any unhandled tag print as a number.
    mov rdi, [r14]
    RENDER_INT rdi
    jmp .lp_next

.lp_str:
    RENDER_STR _lp_quote, _lp_quote_len
    mov rdi, [r14]                      ; C-string pointer
    RENDER_CSTR rdi
    RENDER_STR _lp_quote, _lp_quote_len
    jmp .lp_next

%ifdef __FLOAT_ASM_INCLUDED__
.lp_flt:
    movq xmm0, [r14]                   ; RENDER_FLOAT takes the value in xmm0
    RENDER_FLOAT
    jmp .lp_next
%endif

.lp_list:
    ; Nested list (stage 1e1): the slot holds a child list pointer. Recurse
    ; with rdi = child pointer. rbx/r12/r13/r14 are callee-saved and restored
    ; by _list_print, so the caller's iteration state survives the call.
    mov rdi, [r14]
    call _list_print
    jmp .lp_next

%ifdef __MAP_ASM_INCLUDED__
.lp_map:
    ; Nested map: the slot holds a map pointer. _map_print shares _print_depth
    ; with this routine, so a mixed map/list cycle stays within one budget.
    mov rdi, [r14]
    call _map_print
    jmp .lp_next
%endif

.lp_nothing:
    ; Tag 6: payload unused, print the literal word.
    RENDER_STR _lp_nothing, _lp_nothing_len
    jmp .lp_next

.lp_next:
    inc r12
    cmp r12, r13
    jl .lp_loop

.lp_close:
    RENDER_STR _lp_rbrk, _lp_rbrk_len

    dec qword [rel _print_depth]
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.lp_depth:
    ; Depth limit exceeded (stage 1e1): signal the error and print a
    ; truncation marker in place of the over-deep subtree, then unwind.
    mov qword [rel _last_error], 1
    RENDER_STR _lp_trunc, _lp_trunc_len
    dec qword [rel _print_depth]
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; _list_render_to_buffer - render a list into a dynamic buffer.
; ----------------------------------------------------------------------------
; Args:      rdi = destination buffer, rax = list pointer
; Returns:   rax = destination buffer (possibly reallocated)
; Clobbers:  same as _list_print.
;
; The return contract deliberately matches `_buffer_append` /
; `_buffer_append_float`, so the codegen arm that emits this call sits
; beside theirs as an equal (src/codegen/buffers.rs).
;
; This is a redirection, not a second renderer: it points `_render_sink` at
; the buffer and calls the very routine `Print` calls, so `{flat}` produces
; the same bytes in a text initializer, a buffer, a `write`, a path, a
; `treating` clause and a function argument as it does in Print position
; (LANGUAGE.md "Format Strings Everywhere"; docs/BUGS_FOUND.md #44).
;
; Gated on __RESOURCE_ASM_INCLUDED__ because it appends to a buffer; a
; program with no buffer runtime has no such sink to render into, and the
; compiler sets `uses_buffers` wherever it emits this call.
%ifdef __RESOURCE_ASM_INCLUDED__
_list_render_to_buffer:
    push rbx
    push r12

    mov rbx, [rel _render_sink]     ; previous sink, restored on the way out
    mov r12, rdi                    ; destination buffer
    mov [rel _render_sink], r12
    mov rdi, rax                    ; list pointer
    call _list_print
    mov rax, [rel _render_sink]     ; the buffer, after any reallocation
    mov [rel _render_sink], rbx

    pop r12
    pop rbx
    ret
%endif

%endif

