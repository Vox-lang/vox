# Error Handling System Design

## Overview

English provides **memory-safe guarantees** similar to Rust. The error handling system ensures illegal operations are caught at runtime.

## Runtime Error Detection (Always Active)

**Location:** `coreasm/core.asm`

The `_last_error` global variable is **always available** and set by:
- List bounds checking (element access out of range)
- Buffer overflow attempts (fixed-size buffers)
- File operation failures
- System call errors

```asm
; In core.asm - always included
section .bss
    _last_error: resq 1      ; 0 = no error, non-zero = error code
```

**Error Codes:**
- `0` = No error
- `1` = Buffer overflow / Out of bounds
- `2` = File operation error

**Bounds checking example (generated for `element N of list`):**
```asm
; Check index >= 1 and <= length
cmp rcx, 1
jl .error_label
mov rdx, [rbx]      ; get length
cmp rcx, rdx
jle .ok_label

.error_label:
    mov qword [rel _last_error], 1  ; set error
    xor rax, rax                     ; return 0
    jmp .done_label

.ok_label:
    ; safe access
```

## `on error` Statement

Executes user-defined actions when an error occurs:

```english
a number called bad is element 100 of nums.
On error print "Index out of bounds!".
```

**Generated code checks `_last_error` and executes handler if non-zero.**

## Memory Safety Guarantees

| Guarantee | Implementation |
|-----------|----------------|
| No buffer overflow | Bounds checked, returns 0 on error |
| No out-of-bounds list access | Index validated before access |
| No use-after-free | Resources tracked, auto-cleaned |
| No memory leaks | Automatic cleanup on exit |

## Future Work (Deferred)

**Auto Error Catching** - A feature to automatically print descriptive error messages to stderr when errors occur. This would require:
1. Complex assembly macros or a shared library
2. Context-aware error message generation

For now, use `on error` for manual error handling. The auto-catching feature may be revisited as the project matures.
