; map.asm - Map (key/value collection) runtime for Vox Compiler (stage 1e2)
; Activates tag 5 (MAP). Maps hold text keys -> tagged values, JSON-object
; style. Lookup is a hash table (FNV-1a + linear probing over a power-of-two
; bucket array); an insertion-ordered entries array sits alongside it so
; `keys`/`values` iteration and printing are stable (insertion order).
;
; Layout (one mmap block, zero-filled; header 24 bytes, mirrors list.asm):
;   offset 0:  capacity       (u64) - entries-array slots (insertion-ordered)
;   offset 8:  length         (u64) - live entry count
;   offset 16: hash_capacity  (u64) - hash buckets (power of two)
;   offset 24: hash table     hash_capacity * 8 bytes
;              each slot = entry index (1-based; 0 = empty via mmap zero-fill)
;   offset 24 + hash_capacity*8: entries  capacity * 24 bytes
;              each entry: [key_ptr:8][value:8][tag:8]  (tag in low byte; full
;              qword so the 24-byte entry is qword-copyable)
;
; Keys are text. This stage the caller always passes a stable C-string pointer
; (a string literal in .rodata), so the entry stores that pointer directly -
; no strdup, matching how list.asm stores caller-supplied string pointers.
;
; Growth discipline mirrors _list_append: when length == capacity, allocate a
; new block, copy the entries array verbatim, rebuild the hash table by
; rehashing, and LEAK the old block (geometric, bounded; reclaimed at exit).
; The returned pointer may therefore differ from the input; callers must
; store it back into the variable (codegen mirrors the ListAppend store-back).
;
; Tag values (must match LIST_TAG_* in list.asm / TAG_* in codegen):
;   0 = integer, 1 = string, 2 = float, 3 = boolean, 4 = list, 5 = map

%define MAP_CAPACITY_OFFSET    0
%define MAP_LENGTH_OFFSET      8
%define MAP_HASHCAP_OFFSET     16
%define MAP_HEADER_SIZE        24

%define MAP_ENTRY_SIZE         24
%define MAP_ENTRY_KEY          0
%define MAP_ENTRY_VALUE        8
%define MAP_ENTRY_TAG          16

; List-layout constants reused by _map_keys/_map_values (they build a list
; struct with the same layout as list.asm).
%define LIST_HEADER_SIZE       24
%define LIST_ELEMSIZE_OFFSET   16
%define LIST_TAG_STRING        1

%define MAP_TAG_INTEGER        0
%define MAP_TAG_STRING         1
%define MAP_TAG_FLOAT          2
%define MAP_TAG_BOOLEAN        3
%define MAP_TAG_LIST           4
%define MAP_TAG_MAP            5
%define MAP_TAG_NOTHING        6

; FNV-1a 64-bit parameters.
%define MAP_FNV_OFFSET         0xcbf29ce484222325
%define MAP_FNV_PRIME          0x100000001b3

; Hash table is kept at load factor <= 1/2: hash_capacity = next_pow2(cap*2).

section .bss
    ; Bump allocator for map-owned key copies. See _map_key_dup.
    _mk_next: resq 1            ; next free byte (0 before first use)
    _mk_end:  resq 1            ; one past the current chunk

section .text

; Helper: entries-base = map + 24 + hash_capacity*8.
;   %1 = map reg, %2 = dest reg (must differ from %1). Clobbers %2 only.
%macro MAP_ENTRIES_BASE 2
    mov %2, [%1 + MAP_HASHCAP_OFFSET]
    shl %2, 3
    add %2, MAP_HEADER_SIZE
    add %2, %1
%endmacro

; ============================================================================
; _map_next_pow2 - round up to the next power of two (min 1).
; Args: rdi = n. Returns: rax = next power of two >= n (1 if n <= 1).
; Clobbers: rcx.
; ============================================================================
_map_next_pow2:
    mov rax, 1
    cmp rdi, 1
    jbe .done           ; n <= 1 -> 1
    dec rdi             ; handle exact powers of two correctly
    mov rax, rdi
    mov rcx, rax
    shr rcx, 1
    or  rax, rcx
    mov rcx, rax
    shr rcx, 2
    or  rax, rcx
    mov rcx, rax
    shr rcx, 4
    or  rax, rcx
    mov rcx, rax
    shr rcx, 8
    or  rax, rcx
    mov rcx, rax
    shr rcx, 16
    or  rax, rcx
    mov rcx, rax
    shr rcx, 32
    or  rax, rcx
    inc rax             ; next power of two
.done:
    ret

; ============================================================================
; _map_fnv - FNV-1a 64-bit hash of a NUL-terminated C-string.
; Args: rdi = key pointer. Returns: rax = hash. Clobbers: rcx, rdi.
; ============================================================================
_map_fnv:
    mov rax, MAP_FNV_OFFSET
.loop:
    movzx rcx, byte [rdi]
    test rcx, rcx
    jz .done
    xor rax, rcx
    mov rcx, MAP_FNV_PRIME
    imul rax, rcx
    inc rdi
    jmp .loop
.done:
    ret

; ============================================================================
; _map_key_dup - copy a key into the map-owned key arena.
; Args:      rdi = source C-string.
; Returns:   rax = the copy.
; Clobbers:  rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11. Preserves rbx, r12-r15.
;
; The map owns its keys: lookup compares stored key against wanted key, so the
; bytes must outlive the caller's copy. Bump-allocated, never freed (same
; discipline as the grow paths here and in list.asm). Not mmap per key - that
; rounds to a 4096-byte page.
; ============================================================================
%define MAP_KEY_ARENA_SIZE 65536

_map_key_dup:
    push rbx
    push r12
    mov r12, rdi                ; r12 = source

    xor rcx, rcx                ; rcx = length
.kd_len:
    cmp byte [r12 + rcx], 0
    je .kd_len_done
    inc rcx
    jmp .kd_len
.kd_len_done:
    inc rcx                     ; + NUL
    mov rbx, rcx                ; rbx = bytes needed

    mov rax, [rel _mk_next]
    add rax, rbx
    cmp rax, [rel _mk_end]
    jbe .kd_have_room

    ; Exhausted (or first use): map a fresh chunk. A key larger than the
    ; default chunk gets its own exactly-sized one.
    mov rsi, rbx
    cmp rsi, MAP_KEY_ARENA_SIZE
    jae .kd_size_ok
    mov rsi, MAP_KEY_ARENA_SIZE
.kd_size_ok:
    add rsi, 4095
    and rsi, ~4095
    push rsi
    mov rax, 9                  ; sys_mmap
    mov rdi, 0
    mov rdx, 3                  ; PROT_READ | PROT_WRITE
    mov r10, 0x22               ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    mov r9, 0
    syscall
    pop rsi
    cmp rax, -4096              ; raw mmap returns -errno in [-4095,-1]
    jbe .kd_mmap_ok
    mov rdi, 1                  ; allocation failure: exit(1), as every other
    mov rax, 60                 ; allocation site here and in list.asm does.
    syscall                     ; Returning the caller's pointer instead would
.kd_mmap_ok:                    ; silently restore the borrowing bug.
    mov [rel _mk_next], rax
    add rax, rsi
    mov [rel _mk_end], rax

.kd_have_room:
    mov rax, [rel _mk_next]     ; rax = destination (return value)
    mov rdi, rax
    mov rsi, r12
    mov rcx, rbx
    rep movsb
    add [rel _mk_next], rbx
    pop r12
    pop rbx
    ret

; ============================================================================
; _map_new - create an empty map.
; Args: rdi = capacity hint (0 -> default 8). Returns: rax = map pointer.
; ============================================================================
_map_new:
    push rbx
    push r12
    push r13

    mov rbx, rdi                ; hint
    mov r12, 8
    cmp rbx, r12
    cmovge r12, rbx            ; r12 = capacity = max(hint, 8)

    ; hash_cap = next_pow2(cap * 2)
    mov rdi, r12
    shl rdi, 1
    call _map_next_pow2
    mov r13, rax               ; r13 = hash_capacity

    ; total = 24 + hash_cap*8 + cap*24
    mov rax, r13
    shl rax, 3                 ; hash_cap * 8
    add rax, MAP_HEADER_SIZE
    mov rcx, r12
    imul rcx, MAP_ENTRY_SIZE   ; cap * 24
    add rax, rcx

    ; mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    mov rdi, 0
    mov rsi, rax
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    mov rax, 9
    syscall

    cmp rax, -4096
    jbe .ok
    mov rdi, 1
    mov rax, 60
    syscall
.ok:
    mov rdi, rax               ; rdi = new map
    mov [rdi + MAP_CAPACITY_OFFSET], r12
    mov qword [rdi + MAP_LENGTH_OFFSET], 0
    mov [rdi + MAP_HASHCAP_OFFSET], r13
    mov rax, rdi

    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; _map_insert - insert or replace a key/value entry. May reallocate.
; Args: rdi = map, rsi = key_ptr, rdx = value, rcx = tag
; Returns: rax = map pointer (may differ if reallocated).
; ============================================================================
_map_insert:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rbx, rdi                ; rbx = map
    mov r13, rsi                ; r13 = key
    mov r14, rdx                ; r14 = value
    movzx r15, cl               ; r15 = tag

    ; Grow when length == capacity.
    mov rax, [rbx + MAP_LENGTH_OFFSET]
    cmp rax, [rbx + MAP_CAPACITY_OFFSET]
    jb .no_grow

    ; --- inline grow: preserves r13(key)/r14(value)/r15(tag); uses rax,rcx,
    ;     rdx,rsi,rdi,r11,r12 and one stack slot. Returns new map in rbx.
    ;     The old block is leaked (geometric, bounded; reclaimed at exit). ---
    ; new_cap = max(cap*2, 8)
    mov r12, [rbx + MAP_CAPACITY_OFFSET]
    shl r12, 1
    cmp r12, 8
    jge .gg_have_cap
    mov r12, 8
.gg_have_cap:
    ; new_hash_cap = next_pow2(new_cap*2). Stash on stack (r13 must survive).
    mov rdi, r12
    shl rdi, 1
    call _map_next_pow2        ; rax = new_hash_cap (r12/r13/r14/r15/rbx survive)
    push rax                   ; [rsp] = new_hash_cap
    ; total = 24 + new_hash_cap*8 + new_cap*24
    shl rax, 3
    add rax, MAP_HEADER_SIZE
    mov rcx, r12
    imul rcx, MAP_ENTRY_SIZE
    add rax, rcx
    ; mmap new block
    mov rdi, 0
    mov rsi, rax
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    mov rax, 9
    syscall
    cmp rax, -4096
    jbe .gg_mmap_ok
    mov rdi, 1
    mov rax, 60
    syscall
.gg_mmap_ok:
    mov rdx, rax               ; rdx = new map
    pop rax                    ; new_hash_cap
    ; write header
    mov [rdx + MAP_CAPACITY_OFFSET], r12
    mov rcx, [rbx + MAP_LENGTH_OFFSET]
    mov [rdx + MAP_LENGTH_OFFSET], rcx      ; length unchanged
    mov [rdx + MAP_HASHCAP_OFFSET], rax     ; new_hash_cap
    ; copy entries verbatim: src=old entries (rbx), dst=new entries (rdx)
    MAP_ENTRIES_BASE rbx, rsi
    MAP_ENTRIES_BASE rdx, rdi
    mov rcx, [rbx + MAP_LENGTH_OFFSET]
    imul rcx, MAP_ENTRY_SIZE
    rep movsb                  ; no-op when rcx = 0
    ; NOTE: the old block is intentionally NOT munmap'd - a caller may still
    ; hold a pointer to it (e.g. a map passed to a function); freeing it here
    ; would turn that stale read into a use-after-free. The leak is bounded
    ; (geometric, ~1x final size) and reclaimed at process exit.
    mov rbx, rdx               ; rbx = new map (henceforth)
    ; rebuild hash table by rehashing each entry. hash_cap and length are read
    ; back from the new map header, so no extra register survives the loop.
    xor r11, r11              ; r11 = 0-based index
.gg_rehash_loop:
    mov r12, [rbx + MAP_LENGTH_OFFSET]   ; r12 = length (loop bound)
    cmp r11, r12
    jge .gg_rehash_done
    ; entry = new_entries + i*24
    MAP_ENTRIES_BASE rbx, rsi
    mov rax, r11
    imul rax, MAP_ENTRY_SIZE
    add rsi, rax
    mov rdi, [rsi + MAP_ENTRY_KEY]
    call _map_fnv             ; rax = hash (r11/r12 survive)
    mov rcx, [rbx + MAP_HASHCAP_OFFSET]
    dec rcx                   ; mask
    and rax, rcx              ; bucket
.gg_probe:
    lea rdi, [rbx + rax*8 + MAP_HEADER_SIZE]
    cmp qword [rdi], 0
    jne .gg_probe_next
    ; empty bucket: place entry index (1-based)
    mov rcx, r11
    inc rcx
    mov [rdi], rcx
    jmp .gg_rehash_next
.gg_probe_next:
    inc rax
    mov rcx, [rbx + MAP_HASHCAP_OFFSET]
    dec rcx
    and rax, rcx
    jmp .gg_probe
.gg_rehash_next:
    inc r11
    jmp .gg_rehash_loop
.gg_rehash_done:
    ; rbx = new map; fall through to the probe/insert path.

.no_grow:
    ; --- probe the hash table for key (update) or an empty slot (insert) ---
    mov rdi, r13
    call _map_fnv             ; rax = hash
    mov rcx, [rbx + MAP_HASHCAP_OFFSET]
    dec rcx                   ; mask (hash_cap - 1)
    and rax, rcx              ; bucket index

.probe:
    lea rdi, [rbx + rax*8 + MAP_HEADER_SIZE]   ; &hash_table[bucket]
    mov rcx, [rdi]            ; slot (1-based; 0 = empty)
    test rcx, rcx
    jz .empty                 ; empty bucket -> insert new entry here

    ; compare existing entry's key with ours
    push rax                  ; save bucket index
    MAP_ENTRIES_BASE rbx, rsi
    mov rax, rcx
    dec rax                   ; 0-based entry index
    imul rax, MAP_ENTRY_SIZE
    add rsi, rax              ; rsi = entry base
    mov rsi, [rsi + MAP_ENTRY_KEY]
    mov rdi, r13
    call _str_eq             ; rax = 1 if equal
    mov r8, rax              ; r8 = eq result
    pop rax                  ; restore bucket index
    test r8, r8
    jnz .update

    ; collision: linear probe next bucket
    inc rax
    mov rcx, [rbx + MAP_HASHCAP_OFFSET]
    dec rcx
    and rax, rcx
    jmp .probe

.empty:
    ; append a new entry at index `length`.
    mov rcx, [rbx + MAP_LENGTH_OFFSET]   ; rcx = length (0-based new index)
    push rax                  ; save bucket index
    push rcx                  ; save length
    ; Take ownership of the key. Only on this path: replacing an existing
    ; key keeps the copy already stored, so re-setting one key in a loop
    ; does not consume arena space per iteration.
    mov rdi, r13
    call _map_key_dup
    mov r13, rax              ; r13 = map-owned key
    MAP_ENTRIES_BASE rbx, rsi
    mov rcx, [rsp]            ; reload length (the call clobbered rcx)
    imul rcx, MAP_ENTRY_SIZE
    add rsi, rcx              ; rsi = &entries[length]
    mov [rsi + MAP_ENTRY_KEY], r13
    mov [rsi + MAP_ENTRY_VALUE], r14
    mov [rsi + MAP_ENTRY_TAG], r15
    pop rcx                   ; rcx = length
    pop rax                   ; rax = bucket index
    inc rcx                   ; length + 1 (1-based entry index)
    lea rdx, [rbx + rax*8 + MAP_HEADER_SIZE]
    mov [rdx], rcx            ; hash_table[bucket] = length+1
    inc qword [rbx + MAP_LENGTH_OFFSET]
    jmp .done

.update:
    ; slot (1-based) in rcx -> entry = entries + (slot-1)*24
    MAP_ENTRIES_BASE rbx, rsi
    mov rax, rcx
    dec rax
    imul rax, MAP_ENTRY_SIZE
    add rsi, rax              ; rsi = entry base
    mov [rsi + MAP_ENTRY_VALUE], r14
    mov [rsi + MAP_ENTRY_TAG], r15
    ; length unchanged (replace)

.done:
    mov rax, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; _map_lookup - find a key.
; Args: rdi = map, rsi = key_ptr.
; Returns: rax = value, r11 = tag. On miss: _last_error=1, rax=0, r11=0.
; ============================================================================
_map_lookup:
    push rbx
    push r13

    mov rbx, rdi                ; rbx = map
    mov r13, rsi                ; r13 = key
    mov rdi, r13
    call _map_fnv               ; rax = hash
    mov rcx, [rbx + MAP_HASHCAP_OFFSET]
    dec rcx                     ; mask
    and rax, rcx                ; bucket

.probe:
    lea rdi, [rbx + rax*8 + MAP_HEADER_SIZE]   ; &hash_table[bucket]
    mov rcx, [rdi]             ; slot
    test rcx, rcx
    jz .miss                   ; empty bucket -> key absent
    push rax
    MAP_ENTRIES_BASE rbx, rsi
    mov rax, rcx
    dec rax
    imul rax, MAP_ENTRY_SIZE
    add rsi, rax
    mov rsi, [rsi + MAP_ENTRY_KEY]
    mov rdi, r13
    call _str_eq
    mov r8, rax
    pop rax
    test r8, r8
    jnz .hit
    inc rax
    mov rcx, [rbx + MAP_HASHCAP_OFFSET]
    dec rcx
    and rax, rcx
    jmp .probe

.hit:
    MAP_ENTRIES_BASE rbx, rsi
    mov rax, rcx
    dec rax
    imul rax, MAP_ENTRY_SIZE
    add rsi, rax
    mov rax, [rsi + MAP_ENTRY_VALUE]
    movzx r11, byte [rsi + MAP_ENTRY_TAG]
    mov qword [rel _last_error], 0
    pop r13
    pop rbx
    ret

.miss:
    mov qword [rel _last_error], 1
    xor rax, rax
    xor r11, r11
    pop r13
    pop rbx
    ret

; ============================================================================
; _map_keys - build a fresh list of the map's keys (insertion order).
; Args: rdi = map. Returns: rax = list of key string pointers (tag STRING).
; List layout matches list.asm. Forces uses_lists at the codegen call site.
; ============================================================================
_map_keys:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi                ; rbx = map
    mov r12, [rbx + MAP_LENGTH_OFFSET]   ; r12 = length
    mov r13, 8
    cmp r12, r13
    cmovge r13, r12             ; r13 = list_cap = max(length, 8)

    mov rax, r13
    shl rax, 3                 ; list_cap * 8 (data)
    add rax, r13               ; + list_cap (tags)
    add rax, LIST_HEADER_SIZE
    mov rdi, 0
    mov rsi, rax
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    mov rax, 9
    syscall
    cmp rax, -4096
    jbe .mk_ok
    mov rdi, 1
    mov rax, 60
    syscall
.mk_ok:
    mov r14, rax               ; r14 = list
    mov [r14 + MAP_CAPACITY_OFFSET], r13       ; capacity
    mov [r14 + MAP_LENGTH_OFFSET], r12         ; length
    mov qword [r14 + LIST_ELEMSIZE_OFFSET], 8  ; elem_size

    MAP_ENTRIES_BASE rbx, rsi   ; rsi = map entries base
    xor rcx, rcx               ; i
.mk_loop:
    cmp rcx, r12
    jge .mk_done
    mov rdx, rcx
    imul rdx, MAP_ENTRY_SIZE
    mov rax, [rsi + rdx + MAP_ENTRY_KEY]       ; key ptr
    lea rdx, [r14 + rcx*8 + LIST_HEADER_SIZE]  ; &list.data[i]
    mov [rdx], rax
    ; tag addr = list + 24 + list_cap*8 + i
    mov rax, r13
    shl rax, 3
    add rax, LIST_HEADER_SIZE
    add rax, r14
    lea rax, [rax + rcx]
    mov byte [rax], LIST_TAG_STRING
    inc rcx
    jmp .mk_loop
.mk_done:
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; _map_values - build a fresh list of the map's values with their tags
; (insertion order, mixed-typed).
; Args: rdi = map. Returns: rax = list of values (each with its stored tag).
; Forces uses_lists at the codegen call site.
; ============================================================================
_map_values:
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi                ; rbx = map
    mov r12, [rbx + MAP_LENGTH_OFFSET]   ; r12 = length
    mov r13, 8
    cmp r12, r13
    cmovge r13, r12             ; r13 = list_cap = max(length, 8)

    mov rax, r13
    shl rax, 3
    add rax, r13
    add rax, LIST_HEADER_SIZE
    mov rdi, 0
    mov rsi, rax
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    mov r9, 0
    mov rax, 9
    syscall
    cmp rax, -4096
    jbe .mv_ok
    mov rdi, 1
    mov rax, 60
    syscall
.mv_ok:
    mov r14, rax               ; r14 = list
    mov [r14 + MAP_CAPACITY_OFFSET], r13
    mov [r14 + MAP_LENGTH_OFFSET], r12
    mov qword [r14 + LIST_ELEMSIZE_OFFSET], 8

    MAP_ENTRIES_BASE rbx, rsi   ; rsi = map entries base
    xor rcx, rcx               ; i
.mv_loop:
    cmp rcx, r12
    jge .mv_done
    mov rdx, rcx
    imul rdx, MAP_ENTRY_SIZE
    mov rax, [rsi + rdx + MAP_ENTRY_VALUE]     ; value
    movzx rdx, byte [rsi + rdx + MAP_ENTRY_TAG] ; tag (rdx reloaded)
    ; data[i] = value
    push rdx                  ; save tag
    lea rdx, [r14 + rcx*8 + LIST_HEADER_SIZE]
    mov [rdx], rax
    pop rdx                   ; tag
    ; tag addr = list + 24 + list_cap*8 + i
    mov rax, r13
    shl rax, 3
    add rax, LIST_HEADER_SIZE
    add rax, r14
    lea rax, [rax + rcx]
    mov [rax], dl              ; store tag byte
    inc rcx
    jmp .mv_loop
.mv_done:
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; _map_print - print a map as {"key": value, ...} in insertion order.
; Args: rdi = map. Uses the shared _print_depth counter (64-deep budget,
; shared with _list_print) so a mixed map/list tree is cycle-safe.
; Conditional assembly: gated on __IO_ASM_INCLUDED__ (uses RENDER_*, which
; wrap the PRINT_* macros - see io.asm). The
; float branch is further gated on __FLOAT_ASM_INCLUDED__; the list branch
; on __LIST_ASM_INCLUDED__ (a map only holds a list/float value when the
; corresponding literal set that flag, so the needed runtime is present).
; ============================================================================
%ifdef __IO_ASM_INCLUDED__
section .data
    _mp_lbrace:     db '{'
    _mp_lbrace_len: equ $ - _mp_lbrace
    _mp_rbrace:     db '}'
    _mp_rbrace_len: equ $ - _mp_rbrace
    _mp_comma:      db ', '
    _mp_comma_len:  equ $ - _mp_comma
    _mp_quote:      db '"'
    _mp_quote_len:  equ $ - _mp_quote
    _mp_colon:      db '": '
    _mp_colon_len:  equ $ - _mp_colon
    _mp_trunc:      db '...'
    _mp_trunc_len:  equ $ - _mp_trunc
    _mp_nothing:    db 'nothing'
    _mp_nothing_len: equ $ - _mp_nothing

section .text
_map_print:
    push rbx
    push r12
    push r13
    push r14

    ; Lifecycle: clear _last_error once at entry. Recursive calls clear for
    ; their own frame; the depth-limit error path sets it before returning,
    ; and unwinding frames do not clear it again.
    mov qword [rel _last_error], 0

    inc qword [rel _print_depth]
    cmp qword [rel _print_depth], 64
    jg .mp_depth

    mov rbx, rdi                       ; rbx = map
    RENDER_STR _mp_lbrace, _mp_lbrace_len

    mov r13, [rbx + MAP_LENGTH_OFFSET] ; r13 = length
    test r13, r13
    jz .mp_close                       ; empty map -> just print "}"

    MAP_ENTRIES_BASE rbx, r14          ; r14 = entries base
    xor r12, r12                       ; r12 = 0-based index

.mp_loop:
    test r12, r12
    jz .mp_first
    RENDER_STR _mp_comma, _mp_comma_len
.mp_first:
    ; print "key":  quote + key C-string + '": '
    RENDER_STR _mp_quote, _mp_quote_len
    mov rax, r12
    imul rax, MAP_ENTRY_SIZE
    lea rax, [r14 + rax]               ; rax = entry base
    mov rdi, [rax + MAP_ENTRY_KEY]
    RENDER_CSTR rdi
    RENDER_STR _mp_colon, _mp_colon_len

    ; dispatch value on its stored tag
    mov rax, r12
    imul rax, MAP_ENTRY_SIZE
    lea rax, [r14 + rax]               ; rax = entry base
    movzx r8, byte [rax + MAP_ENTRY_TAG]
    mov rdi, [rax + MAP_ENTRY_VALUE]   ; rdi = value (payload / pointer)
    cmp r8, MAP_TAG_STRING
    je .mp_str
%ifdef __FLOAT_ASM_INCLUDED__
    cmp r8, MAP_TAG_FLOAT
    je .mp_flt
%endif
%ifdef __LIST_ASM_INCLUDED__
    cmp r8, MAP_TAG_LIST
    je .mp_list
%endif
    cmp r8, MAP_TAG_MAP
    je .mp_map
    cmp r8, MAP_TAG_NOTHING
    je .mp_nothing
    ; INTEGER / BOOLEAN / fallback: print as a number
    RENDER_INT rdi
    jmp .mp_next

.mp_str:
    ; rdi holds the value pointer; stash it across the opening quote so the
    ; value's lifetime does not rest on a rendering macro's register discipline.
    push rdi
    RENDER_STR _mp_quote, _mp_quote_len
    pop rdi
    RENDER_CSTR rdi
    RENDER_STR _mp_quote, _mp_quote_len
    jmp .mp_next

%ifdef __FLOAT_ASM_INCLUDED__
.mp_flt:
    movq xmm0, rdi
    RENDER_FLOAT
    jmp .mp_next
%endif

%ifdef __LIST_ASM_INCLUDED__
.mp_list:
    call _list_print               ; rdi = child list pointer
    jmp .mp_next
%endif

.mp_map:
    call _map_print                ; rdi = child map pointer
    jmp .mp_next

.mp_nothing:
    RENDER_STR _mp_nothing, _mp_nothing_len
    jmp .mp_next

.mp_next:
    inc r12
    cmp r12, r13
    jl .mp_loop

.mp_close:
    RENDER_STR _mp_rbrace, _mp_rbrace_len
    dec qword [rel _print_depth]
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.mp_depth:
    ; Depth limit exceeded: signal the error, print a truncation marker in
    ; place of the over-deep subtree, then unwind.
    mov qword [rel _last_error], 1
    RENDER_STR _mp_trunc, _mp_trunc_len
    dec qword [rel _print_depth]
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; _map_render_to_buffer - render a map into a dynamic buffer.
; ----------------------------------------------------------------------------
; Args:      rdi = destination buffer, rax = map pointer
; Returns:   rax = destination buffer (possibly reallocated)
; The list twin of this routine carries the full explanation
; (list.asm, `_list_render_to_buffer`; docs/BUGS_FOUND.md #44).
%ifdef __RESOURCE_ASM_INCLUDED__
_map_render_to_buffer:
    push rbx
    push r12

    mov rbx, [rel _render_sink]     ; previous sink, restored on the way out
    mov r12, rdi                    ; destination buffer
    mov [rel _render_sink], r12
    mov rdi, rax                    ; map pointer
    call _map_print
    mov rax, [rel _render_sink]     ; the buffer, after any reallocation
    mov [rel _render_sink], rbx

    pop r12
    pop rbx
    ret
%endif

%endif