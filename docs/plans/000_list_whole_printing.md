# User Story
> As an author, I want `print mylist.` to show the list's contents so that I can inspect data without writing a loop.

---

## Feature/Problem Description

**Summary:**
Printing a list variable directly prints the heap pointer as a decimal
integer instead of the list's contents. This affects all lists,
homogeneous and mixed alike.

**Context:**
Discovered while fixing heterogeneous lists (commit `6d60ea5`). It is a
pre-existing bug, orthogonal to the type-tag work, and was deliberately
left out of that change to keep the diff focused. Now that per-slot type
tags exist, a correct whole-list print is straightforward: the same
dispatch used for single elements can drive a loop.

**Current Behavior (if bug):**
```
a list called "nums" is [1, 2, 3].
print nums.
(prints something like: 140256856788992)
```

**Expected Behavior:**
```
print nums.
(prints: [1, 2, 3])

a list called "m" is [1, "two", 3.5, yes].
print m.
(prints: [1, "two", 3.5, 1])
```
Empty lists print `[]`. Text elements are quoted so `["1"]` is
distinguishable from `[1]`; all other elements print exactly as they do
when printed individually.

---

## Scope
- [x] Backend (codegen + coreasm runtime)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Nested lists (a list element whose tag is 4) — covered by stage 1e-1,
  which will extend this printer recursively.
- Any format-spec handling inside `{mylist}` beyond the default.
- Changing how single elements print.

---

## Technical Approach

**Proposed Solution:**
Add a `_list_print` runtime routine in `coreasm/x86_64/list.asm` that
walks the list, reads each slot's type tag, and prints the element with
the matching primitive (`PRINT_INT` / `PRINT_CSTR` / `PRINT_FLOAT`),
emitting `[`, `, ` separators and `]`. Because homogeneous lists carry a
zero-filled tag region (tag 0 = integer), the same routine works for
them — except for homogeneous string/float lists, whose tags are also
written by the literal/append codegen, so no special case is needed.

In `generate_print`, route `Expr::Identifier` / `Expr::StringLit`
references whose `variable_types` is `VarType::List` to `_list_print`
instead of `PRINT_INT`. Same for the format-interpolation path in
`resolve_format_variable` consumers.

**Files/Components Affected:**
- `coreasm/x86_64/list.asm` — new `_list_print`
- `src/codegen/mod.rs` — `generate_print` (Identifier, StringLit, and
  format-string arms); ensure `uses_lists` / `uses_floats` are set
- `LANGUAGE.md` — document list printing
- `tests/` — new test files

**Dependencies:**
Depends on the tag region introduced in 1a (already merged). No external
dependencies.

---

## Success Criteria
- [x] Feature works as described in expected behavior
- [x] All tests pass (currently 138 passing, 6 skipped)
- [x] Code reviewed and approved
- [x] Documentation updated

---

## Acceptance Criteria
1. **Given** a homogeneous integer list, **when** the author prints the
   list variable, **then** the output is `[1, 2, 3]`.
2. **Given** a homogeneous text list, **when** printed, **then** the
   output is `["Alice", "Bob"]` with quotes.
3. **Given** a mixed list `[1, "two", 3.5, yes]`, **when** printed,
   **then** each element is rendered by its own runtime tag:
   `[1, "two", 3.5, 1]`.
4. **Given** an empty list, **when** printed, **then** the output is `[]`.
5. **Given** a list inside a format string (`print "list: {nums}"`),
   **when** printed, **then** the same rendering appears inline.
6. **Given** any existing test in the suite, **when** the suite runs,
   **then** it still passes.

---

## Tasks
- [x] Write `_list_print` in `coreasm/x86_64/list.asm` (header read, loop,
      tag dispatch, separators, brackets, quoting for tag 1)
- [x] Route list-typed variables in `generate_print` to `_list_print`
- [x] Route list-typed variables in format-string interpolation
- [x] Confirm `uses_lists`/`uses_floats`/`uses_io` include flags are set
      so the routine is linked only when needed
- [x] Add test: homogeneous int / text / float / bool list printing
- [x] Add test: mixed list printing, empty list printing, interpolation
- [x] Update `LANGUAGE.md` list section
- [x] Run `./test.sh` and `cargo test --release`; confirm no regressions

---

## Notes
- Register discipline: `_list_print` must preserve callee-saved registers
  and must not assume `r11` survives — the existing single-element tag
  convention parks tags in `r11` only for immediate consumption.
- Floats print via the existing `PRINT_FLOAT` path, which expects the
  value in `xmm0`; move it from the slot rather than assuming `rdi`.
- Decide (and document) whether booleans render as `1`/`0` or `yes`/`no`.
  Recommendation: `1`/`0`, matching how a boolean element prints today,
  so whole-list output stays consistent with element output.
