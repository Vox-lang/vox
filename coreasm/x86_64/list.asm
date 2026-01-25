; list.asm - List element access macros for English Compiler
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

%define LIST_CAPACITY_OFFSET    0
%define LIST_LENGTH_OFFSET      8
%define LIST_ELEMSIZE_OFFSET    16
%define LIST_DATA_OFFSET        24

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
    lea rsi, [_err_list_bounds_msg]
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
; Args: rdi = list pointer, rsi = value to append
; Returns: rax = new list pointer (may differ if reallocated)
; 
; List structure: [capacity:8][length:8][elem_size:8][data...]
;
_list_append:
    push rbx
    push rcx
    push rdx
    push r12
    push r13
    push r14
    
    mov rbx, rdi                    ; rbx = list pointer
    mov r12, rsi                    ; r12 = value to append
    
    mov rcx, [rbx + LIST_LENGTH_OFFSET]     ; current length
    mov rdx, [rbx + LIST_CAPACITY_OFFSET]   ; capacity
    
    ; Check if we have space
    cmp rcx, rdx
    jge .need_realloc
    
    ; We have space - append directly
    mov rax, [rbx + LIST_ELEMSIZE_OFFSET]   ; element size
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
    mov rax, [rbx + LIST_ELEMSIZE_OFFSET]
    mov r14, rax                            ; r14 = element size
    imul rax, r13                           ; data size
    add rax, LIST_DATA_OFFSET               ; + header
    
    ; Allocate new memory using mmap
    push rbx
    push rax                                ; save size
    
    mov rdi, 0                              ; addr = NULL
    mov rsi, rax                            ; size
    mov rdx, 3                              ; PROT_READ | PROT_WRITE
    mov r10, 0x22                           ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                              ; fd = -1
    mov r9, 0                               ; offset = 0
    mov rax, 9                              ; sys_mmap
    syscall
    
    pop rcx                                 ; restore size (unused)
    pop rbx                                 ; restore old list ptr
    
    ; rax = new list pointer
    mov rdi, rax                            ; rdi = new list
    
    ; Copy header
    mov qword [rdi + LIST_CAPACITY_OFFSET], r13     ; new capacity
    mov rcx, [rbx + LIST_LENGTH_OFFSET]
    mov qword [rdi + LIST_LENGTH_OFFSET], rcx       ; same length
    mov qword [rdi + LIST_ELEMSIZE_OFFSET], r14     ; same elem size
    
    ; Copy existing data
    push rdi
    push rsi
    
    lea rsi, [rbx + LIST_DATA_OFFSET]       ; source
    lea rdi, [rdi + LIST_DATA_OFFSET]       ; dest (note: rdi was saved)
    pop rdi                                  ; restore new list base
    push rdi
    lea rdi, [rdi + LIST_DATA_OFFSET]       ; dest = new list data
    lea rsi, [rbx + LIST_DATA_OFFSET]       ; source = old list data
    
    mov rcx, [rbx + LIST_LENGTH_OFFSET]
    imul rcx, r14                           ; bytes to copy
    
    ; Copy byte by byte
    test rcx, rcx
    jz .copy_done
.copy_loop:
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .copy_loop
    
.copy_done:
    pop rdi                                 ; rdi = new list pointer
    
    ; Now append the new element
    mov rcx, [rdi + LIST_LENGTH_OFFSET]
    mov rax, r14                            ; element size
    imul rcx, rax
    
    lea rax, [rdi + LIST_DATA_OFFSET]
    add rax, rcx
    mov [rax], r12                          ; store value
    
    inc qword [rdi + LIST_LENGTH_OFFSET]    ; increment length
    
    mov rax, rdi                            ; return new pointer
    
.done:
    pop r14
    pop r13
    pop r12
    pop rdx
    pop rcx
    pop rbx
    ret

