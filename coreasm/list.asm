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

