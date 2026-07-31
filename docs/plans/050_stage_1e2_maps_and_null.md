# Plan 050 — Stage 1e-2: Maps (tag 5)

> **Scope decided (this stage): maps only.** The original stub bundled maps
> and `nothing`/null. The current roadmap splits them: **1e-2 ships maps
> (tag 5)**; `nothing`/null (tag 6) is **deferred to 1e-3** with the
> JSON/YAML parser. Missing-key lookup sets the `_last_error` flag
> (observable via `on error`) rather than returning a null, so maps do
> not depend on null. See `docs/COLLECTIONS_ROADMAP.md`.

# User Story
> As an author, I want key-value maps so that I can represent JSON objects.

---

## Feature/Problem Description

**Summary:**
Add a map (key-value) collection type using reserved tag 5 — JSON
objects. Key/value collections with text keys, any-typed values,
insertion-ordered iteration, O(1) lookup, and recursive printing.

**Context:**
`docs/COLLECTIONS_ROADMAP.md` identifies nesting, maps, and null as the
three things JSON needs beyond mixed lists. Nesting arrived in 1e-1;
this stage supplies maps. Maps are a genuinely new collection type and
are the largest piece of Track 1 after 1d.

**Current Behavior (if bug):**
No map type exists. There is no way to express a JSON object.

**Expected Behavior:**
```
a map called "person" is {"name": "Ada", "age": 36}.
print person's "name".
(prints: Ada)
print person's length.
(prints: 2)
set person's "age" to 37.
print person's "age".
(prints: 37 — replace, length unchanged)
For each key in person's keys, print key.
(prints: name, then age — insertion order)
```

---

## Scope
- [x] Backend (lexer, parser, analyzer, codegen, coreasm runtime)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- `nothing`/null (tag 6) — deferred to stage 1e-3. Missing-key lookup sets
  the `_last_error` flag instead, so maps do not depend on null.
- The JSON/YAML parser (stage 1e-3).
- Non-text keys. Keys are texts in this stage; JSON requires nothing more.
- Map deletion / tombstones.
- The declarative `person's "age" is 37.` insert form — `Set … to …` only
  (mirrors `Set element N of list to …`).
- Flow-sensitive narrowing after `if x is a map`.
- aarch64/Win64 (no list runtime there either).

---

## Technical Approach

**Proposed Solution:**
A map runtime sibling to the list. Implemented layout (single mmap
block, zero-filled; header 24 bytes, mirrors the list):

```
[capacity:8][length:8][hash_capacity:8]
[hash table: hash_capacity x 8   (entry index, 1-based; 0 = empty via mmap)]
[entries:   capacity x 24         (key_ptr:8, value:8, tag:8)]
```

Open addressing with linear probing over a power-of-two hash capacity,
growing at load ≤ 1/2 (`hash_cap = next_pow2(cap*2)`) by the same
allocate-copy-do-not-free-old-block discipline `_list_append` uses (and
for the same aliasing reason, repeated in the comments). An
insertion-ordered entries array sits alongside the hash table so
`keys`/`values` iteration and printing are insertion-ordered (stable for
tests). Hashing: FNV-1a 64-bit (offset `0xcbf29ce484222325`, prime
`0x100000001b3`) over the key C-string bytes — adequate and trivial in
NASM, and gives O(1) lookup so the 1e-3 JSON parser need not rewrite the
runtime.

Values are tagged exactly like list slots, so a map value may be a
number, text, decimal, boolean, list (tag 4), or map (tag 5) — the JSON
value set minus null (which arrives in 1e-3). `_map_print` recurses on
list/map values and shares one 64-deep `_print_depth` counter with
`_list_print` (moved to `core.asm .bss`) so a mixed map/list tree is
cycle-safe under a single budget.

**Files/Components Affected:**
- `src/lexer/mod.rs` — `nothing`, `{`/`}` and `:` in map literals
- `src/parser/mod.rs`, `src/parser/ast.rs` — map literal, key access,
  `keys`/`values`/`length` properties
- `src/analyzer/mod.rs` — map type, key type validation
- `src/codegen/mod.rs` — map allocation, insertion, lookup, iteration
- `coreasm/x86_64/map.asm` (new) — hashing, probing, growth, printing
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stage 1a; plan 000 and stage 1e-1 for the recursive printer; stage 1c for
`is nothing` / `is a map`; stage 1d if map values are to be passed to
functions generically.

---

## Success Criteria
- [x] Feature works as described in expected behavior
- [x] All tests pass
- [x] Map operations are bounds-safe and never read past an allocation
- [x] Growth preserves all entries (stress test with 10,000 keys)
- [x] Code reviewed and approved
- [x] Documentation updated

---

## Acceptance Criteria
1. **Given** a map literal with text and number values, **when** each key
   is read, **then** each value returns with its correct type. *(met —
   tests 174, 175)*
2. **Given** a map, **when** a key is inserted that already exists,
   **then** the value is replaced and `length` does not change. *(met —
   test 176)*
3. **Given** a lookup of a key that is not present, **when** executed,
   **then** the error flag is set (consistent with list bounds errors)
   rather than returning a garbage value. *(met — test 177)*
4. **Given** 10,000 insertions, **when** all keys are read back, **then**
   every value is intact across all growth events. *(met — test 178)*
5. **Given** a map containing a list and a nested map, **when** printed,
   **then** the whole structure renders recursively. *(met — test 179)*
6. **Given** a map, **when** classified with `is a map`, **then** it
   folds on a static map and compares tag 5 at runtime on a mixed value.
   *(met — test 180)*
7. **Given** the existing suite, **when** it runs, **then** all tests
   pass. *(met — 178 integration + 103 cargo, 0 failures)*

> `nothing`/null acceptance (was criterion 6) moves to plan 060 / stage
> 1e-3.

---

## Tasks
- [x] Design and document the map layout and growth policy
- [x] `coreasm/x86_64/map.asm`: FNV-1a hash, insert, lookup, grow/rehash,
      keys/values, print
- [x] Shared `_print_depth` (rename `_list_print_depth` → `_print_depth`
      in `core.asm .bss`) for cycle-safe mixed map/list printing
- [x] Map literal syntax and codegen (`MapLit`)
- [x] Key access (`person's "name"`) plus `keys`, `values`, `length`,
      `empty` properties
- [x] `Set map's "key" to value` insert/replace with realloc store-back
- [x] Iteration (`For each key in person's keys, ...` / `... values, ...`)
- [x] `is a map` predicate (folds on static, `cmp r11, 5` on a value)
- [x] `value`-ABI carriage (map rides a `value` as payload + tag 5)
- [x] Tests: 174–186 integration, 10 codegen unit tests, compile_fail
      052 (non-string key), `examples/map.vox`
- [x] Update `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`, plan README
- [x] Run `./test.sh` and `cargo test --release` (clean, no warnings)
- [ ] `nothing`/null (tag 6): lexer, parser, printing, `is nothing` —
      **deferred to stage 1e-3 / plan 060**

---

## Notes
- **Insertion order is preserved.** An insertion-ordered entries array
  sits alongside the hash table, so `keys`/`values` and printing are
  stable (JSON does not require it, but authors expect it and tests need
  deterministic output).
- Reused the list's "allocate, copy, do not free the old block" rule on
  growth, with the explanatory comment: freeing would turn a stale
  caller-held pointer into a use-after-free. `_map_insert` returns the
  (possibly new) map pointer and codegen stores it back into the
  variable, mirroring `ListAppend`.
- `{` and `}` are also used by format strings. The OpenBrace
  disambiguation parses the first expression and branches on a following
  `:` (map) vs `}` (grouping); a non-text key like `{1: "x"}` parses as a
  map and is rejected by the analyzer with "Map keys must be text".
- Map keys are text literals: a quoted key is ALWAYS the literal text,
  even when a variable with that name exists (so `{"inner": …}` colliding
  with `a map called "inner"` does not corrupt the key). A quoted key
  with `{...}` interpolation builds a dynamic key.
- Missing-key lookup sets `_last_error` and yields 0 (not a null return),
  so maps work without the `nothing`/null literal.
