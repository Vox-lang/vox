# User Story
> As an author, I want the compiler to fall back to a mixed list whenever it cannot prove my list is homogeneous, so that my data is never silently corrupted by an optimistic guess.

---

## Feature/Problem Description

**Summary:**
Invert the default of the list element-type inference. Today the
pre-scan assumes a list is homogeneous unless it finds positive evidence
of mixing. Stage 1b makes homogeneity something the compiler must
*prove*: any write whose type cannot be determined statically widens the
list to `Mixed`.

**Context:**
Stage 1a (commit `6d60ea5`) introduced per-slot runtime type tags and a
fixed-point pre-scan pass. The pre-scan was deliberately conservative so
that 1a could not change the behavior of any existing program. The
design intent, recorded in `docs/COLLECTIONS_ROADMAP.md`, is that
"static is a proof; mixed is the default" — mixed is always *correct*,
static is merely *faster*, so the fast path must be earned.

**Current Behavior (if bug):**
```
a list called "items" is [].
append 1 to items.
append some_function_result to items.   (type unknowable statically)
```
The list stays statically typed as integer. If the function returns a
text, reading the element back reinterprets a pointer as a number — the
same silent corruption 1a fixed for literals.

**Expected Behavior:**
Any list with at least one write of unprovable type is compiled as
`Mixed`; its slots carry runtime tags and its reads dispatch on them.
Lists whose every write is provably one type are unchanged, keeping
today's untagged fast path bit-for-bit.

---

## Scope
- [x] Backend (compiler analysis + codegen)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- Runtime/layout changes: the tag region and `_list_append` tag argument
  already support everything this stage needs.
- Tags crossing function boundaries (stage 1d).
- Arithmetic/comparison dispatch on mixed elements (stage 1c/1d).

---

## Technical Approach

**Proposed Solution:**
Change `prescan_expr_tag` to return a three-state result rather than
`Option<u8>` conflating "unknown" with "no evidence":

- `Known(tag)` — literal, or a variable whose type is tracked
- `Unknowable` — function call, complex expression, untracked identifier

Then in the join: `Known(t)` behaves as today; `Unknowable` widens the
list straight to `Mixed`. Keep the existing fixed-point loop, which
already guarantees termination because the mixed set only grows.

At emit time, the corresponding gap is `emit_time_expr_tag`, which
currently falls back to `Some(TAG_INTEGER)` for unrecognized
expressions. For lists now known to be `Mixed`, an unprovable value
needs a *runtime* tag rather than a guessed one. Two options, to be
decided during implementation:

1. **Static best-effort (cheaper):** extend `infer_expr_type` coverage
   (function return types are already collected in
   `collect_function_signatures`) so most previously-unknowable values
   become knowable, and only genuinely opaque cases fall back.
2. **Runtime tagging (complete):** have expression evaluation optionally
   yield a tag in `r11`, mirroring the element-read convention.

Recommendation: implement (1) first — it closes most of the gap with
little risk — and defer (2) to stage 1d, where the dynamic `value` type
gives it a principled home.

**Files/Components Affected:**
- `src/codegen/mod.rs` — `prescan_expr_tag`, `prescan_walk`,
  `prescan_note_list_value`, `emit_time_expr_tag`, `infer_expr_type`
- `docs/COLLECTIONS_ROADMAP.md` — mark 1b done, update the limitations list
- `LANGUAGE.md` — remove the "current limitation" note added in 1a
- `tests/` — new test files

**Dependencies:**
Stage 1a (merged). Function signature collection already exists in
`collect_function_signatures`.

---

## Success Criteria
- [x] Feature works as described in expected behavior
- [x] All tests pass
- [x] No performance regression for homogeneous lists (verify emitted
      assembly for an all-integer list is unchanged)
- [ ] Code reviewed and approved
- [x] Documentation updated

---

## Acceptance Criteria
1. **Given** a list built only from integer literals, **when** compiled,
   **then** the emitted assembly is byte-identical to the pre-1b output
   (no tag writes, no dispatch).
2. **Given** a list where a function result of declared text type is
   appended alongside an integer, **when** the elements are printed,
   **then** each prints correctly by type.
3. **Given** a list where a value of genuinely unknowable type is
   appended, **when** compiled, **then** the list is treated as `Mixed`
   and reads dispatch on runtime tags.
4. **Given** an alias of a list widened to `Mixed`, **when** its elements
   are read, **then** they dispatch on tags too (fixed point still
   propagates through aliases).
5. **Given** the existing suite, **when** it runs, **then** all tests
   pass unchanged.

---

## Tasks
- [x] Introduce a three-state tag classification (`Known` / `Unknowable`)
      replacing `Option<u8>` in the pre-scan
- [x] Widen to `Mixed` on `Unknowable` in `prescan_note_list_value` and
      the list-literal path
- [x] Broaden `infer_expr_type` / `emit_time_expr_tag` to cover function
      calls with declared return types, property accesses, and binary ops
      with known operand types
- [x] Audit remaining `unwrap_or(TAG_INTEGER)` fallbacks; document each
      surviving one with why it is safe
- [x] Add test: function-result append into an otherwise integer list
- [x] Add test: homogeneous fast path unchanged (assembly snapshot or a
      `--emit-asm` diff check)
- [x] Update `docs/COLLECTIONS_ROADMAP.md` and `LANGUAGE.md`
- [x] Run `./test.sh` and `cargo test --release`

---

## Notes
- Watch for over-widening: if too many lists become `Mixed`, the fast
  path stops paying for itself. Measure how many lists in `tests/` and
  `examples/` widen before and after; investigate any surprises.
- The empty-list-then-append pattern (`a list called "x" is [].`) is
  extremely common; make sure a single-type append sequence still proves
  homogeneous.
- Termination argument to preserve in comments: the pre-scan loop only
  ever *adds* to `mixed_lists`, and the set is bounded by the number of
  list names, so the fixed point always converges.
