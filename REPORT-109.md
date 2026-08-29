# REPORT-109 — `Free` on a list

Worktree `~/scr/english/worktrees/wt-fix-109`, branch `fix/bug-109-free-list`,
off `main` at `4995394` (v0.4.14). Stopped **staged**, not committed
(signed commits need the owner's hardware key): patch parked at
`/home/josj/scr/english/vox-notes/parked/fix-bug-109.patch`.

## What landed

`Free`/`Release`/`Deallocate` on a **list** now gets the same
released-buffer contract a buffer already has (LANGUAGE.md "Releasing a
Buffer"): the list becomes empty (length 0, `empty` true, prints `[]`),
every later write is refused with the error flag, and a second `Free` is a
no-op that flags rather than a double free. Fixes both defects the brief
registered:

- **Global list `Free` was a silent no-op** (D4.vox) — `Statement::Free`
  only looked a name up in the local stack frame table; a global lives in
  a `gvar_N` BSS mirror and matched no branch.
- **Function-local list `Free` was a dangling-pointer segfault**
  (`local_list_free.vox`) — `HEAP_FREE` genuinely released the block, but
  nothing repointed the slot, so the next read dereferenced unmapped
  memory.

Mid-flight, the owner added scope (steer, 2026-08-29 09:18): **"Freeing a
list should free every item within the list as well."** Built and tested
— see "Deep free" below.

## Files touched

- `coreasm/x86_64/list.asm` — `_released_list_header` (`.data`); the
  identity refusal at the top of `_list_append`, plus `CLEAR_LAST_ERROR`
  on its success path (list.asm had never touched `_last_error` before);
  `_free_list` (replaces the generic `HEAP_FREE` for a list — computes
  block size from its own header and unconditionally munmaps, rather than
  depending on `heap.asm`'s `alloc_table`, which never learns about a
  grown list's later blocks); `_free_visit_or_skip` and the
  `_free_visited`/`_free_visited_count` `.bss` table (deep-free dedup).
- `coreasm/x86_64/map.asm` — `_free_map` (new; reachable only from
  `_free_list`'s walk, no user-facing `Free <map>` surface).
- `src/codegen/statements.rs` — `Statement::Free` gained a `VarType::List`
  arm calling `emit_free_list`, parallel to the existing `VarType::Buffer`
  arm; the `Allocate`d-raw-block fallback is otherwise untouched.
- `src/codegen/collections.rs` — `emit_free_list` (mirrors
  `emit_free_buffer`): resolves the name, resets the dedup table, calls
  `_free_list`, stores `_released_list_header`'s address back through
  `emit_store_back_after_realloc`.
- `LANGUAGE.md` — the "A list also accepts `Free`." sentence (was :3674)
  replaced with the after-state paragraph (empty, refused writes, second
  Free flags, deep free, the parameter rule). The Statement Starters
  `Free` row (~:5028) stays true as written, no change needed.
- `docs/BUGS_FOUND.md` — new entry **#109**, house format, both repros,
  root cause, fix, the "brief was wrong" callouts, the full deep-free
  scope addition (nested-collection probe, dedup design, the
  string/buffer limitation, the new aliasing hazard).
- `CHANGELOG.md` — `## [Unreleased]` created above `## [0.4.14]`, one
  `### Fixed` bullet for #109.
- `tests/584_free_on_a_list_is_unchanged_and_pins_its_after_state.{vox,expected}`
  → renamed and rewritten as
  `584_free_on_a_list_now_empties_it_and_refuses_writes.{vox,expected}`.
  This test predates #109 (from the buffer-Free brief) and pinned the OLD
  undefined stale-pointer-read as "today's behaviour, not changed by this
  brief." It IS changed by this brief, so the old pin is now false;
  rewritten in place at the same number to pin the new, correct behaviour.
- `tests/587`–`596` (10 new `.vox`/`.expected` pairs) — see Tests below.

## Nested collections: copy-in or pointer-in?

Established first, per the steer, before building deep free on top of it.

```vox
a list called inner is [1, 2].
a list called outer is [inner, 3].
Set element 1 of inner to 777.
print outer.
print inner.
```

→ `[[777, 2], 3]` / `[777, 2]`: mutating `inner` through its own name is
visible through `outer`. The emitted assembly for `outer`'s list literal
confirms it directly — it loads `inner`'s pointer (`mov rax, [rel
gvar_0]`) and stores THAT into `outer`'s slot (`LIST_SET_ELEM [rbx+24],
rax`), tagged `LIST_TAG_LIST`. **(b) pointer-in.** Per the ruling, deep
free was built anyway (this report's own recommendation on the aliasing
question below is a `#34`-style ruling for the owner, not something
changed on this branch: **copy-by-default** for nested list/map literal
elements would remove the new dangling-alias hazard below at the cost of
an extra allocation per nested element).

## Deep free

`_free_list` walks its own slots by their per-element type tag before
releasing itself. A `LIST_TAG_LIST` (4) or `LIST_TAG_MAP` (5) slot
recurses (into `_free_list` / the new `_free_map`) because both are
unconditionally heap blocks — nothing else ever allocates that shape, so
no identity or shape check is needed to know it's safe. `_free_map`
mirrors this for a map's own entries, and additionally never touches a
KEY — `map.asm`'s own header comment states a key is always a stable
`.rodata` literal pointer, never heap-owned, by this stage's design.

**Left out on purpose: string/buffer elements.** The steer named "buffers"
and "heap-allocated texts" as things deep free should reach. Investigated:
there is no buffer tag at all in the 0–6 tag scheme; the only way buffer
content enters a list is `append <buffer> to <list>`, which duplicates the
bytes onto the heap via `_strdup_bounded` and tags the result
`TAG_STRING` — indistinguishable, per-slot, from a plain string LITERAL
element (a `.rodata` pointer that must never be freed). Nothing records
which is which. Freeing a `.rodata` pointer risks unmapping part of the
program's own data segment; leaving a heap string element unfreed is
"only" a leak. Left as a leak, not fixed — genuinely out of scope for a
lists-only brief (would need a new per-slot ownership bit, the shape
#108's text-ownership flag already has, threaded through every write to a
list/map element).

**Dedup within one `Free` call tree.** Pointer-in aliasing means the SAME
nested block can be reachable through more than one slot inside one
`Free` — the same nested list twice in one literal, or two parents
sharing one child. `_free_visit_or_skip` records every pointer a `Free`
call tree starts freeing (4096-entry table, `list.asm`), reset fresh by
codegen before each TOP-LEVEL `Free`. A pointer already recorded is
skipped, not freed again. Verified: a list holding the same nested list
through two of its own slots does not crash (test 596); a three-level
diamond (`w = [y, z]`, `y = [shared]`, `z = [shared]`, `Free w`) does not
crash either (probed by hand, not committed as a numbered test — the
shape is the same as 596's, one level deeper).

**A new, confirmed hazard — NOT fixed on this branch, flagged for the
owner.** Because nesting is pointer-in, any OTHER variable that still
names a block a deep free just released is left dangling:

```vox
a list called inner is [1, 2, 3].
a list called outer is [inner, "x"].
Free outer.
print inner's length.   (segfault, rc 139 — reproduced)
```

This is the exact shape the owner's own steer text anticipated
("nothing needs pointing at the released header except the outer
variable itself" — true for the outer variable, not for a second name
naming the same child). Recorded in BUGS_FOUND.md #109 and carried here
as a question below; this is the **#34 ruling** the owner's steer named,
not something this branch decides or changes.

## Tests

`tests/587`–`596`, ten `.vox`/`.expected` pairs, plus 584 rewritten:

| # | proves |
|---|---|
| 584 (rewritten) | list Free's new after-state, superseding the old undefined-read pin |
| 587 | global list: length/empty/print/append-refused (mirrors D4.vox) |
| 588 | function-local list: same, no segfault (mirrors local_list_free.vox) |
| 589 | a second Free flags, no crash |
| 590 | a real list crossing its literal capacity still grows — identity, not shape |
| 591 | Free through a list parameter frees the caller's own variable too |
| 592 | `Release`/`Deallocate` are the same statement for a list |
| 593 | Free reaches a global list from inside a function |
| 594 | deep free reaches a nested list AND a nested map in one outer Free |
| 595 | a second Free after a deep free flags, no double-unmap |
| 596 | deep free dedups a list holding the same nested list through two slots |

`compile_fail` from 281: not used — rule 4 (list parameters) did not
become a compile error; see below.

## What I could NOT do / did not attempt

- **String/buffer element freeing inside deep free** — see "Left out on
  purpose" above. Confirmed unsafe to do blindly; would need a new
  per-slot ownership marker, out of scope for a lists-only brief.
- **The cross-variable dangling-alias hazard** — confirmed real (repro
  above), not fixed. Fixing it would mean either reference-counting
  collections or making nested list/map literal elements copy-in instead
  of pointer-in; both are language-design decisions for the owner, not
  something a lists-only `Free` brief should decide unilaterally.
- **List-of-things** — LANGUAGE.md 1891/2668 state this shape is deferred
  in 0.4.14 (not yet supported), so no test exists for it; nothing to do.
- **`Free <map>` as a top-level statement** — out of scope (narrow: lists
  only, per the brief). `_free_map` exists only as an internal helper
  reachable from list deep-free; a bare `Free somemap.` still falls
  through to the old, pre-existing, out-of-scope `HEAP_FREE` path (its own
  bug, not #109's).

## Where the brief itself was wrong (found and corrected, as invited)

1. **`LIST_SET_ELEM` is not `Set element N of L to ...`'s path.** That
   statement (`Statement::ElementSet`) has always been an inline,
   length-bounded write with its own bounds check, never routed through
   the `LIST_SET_ELEM` macro (which only fills list-literal/argv arrays).
   A released list's length is always 0, so every write to it was
   already refused by the ordinary bounds check — no identity check was
   needed or added there.
2. **List parameters did not need the compile-error fallback.** #75
   already gave `list`/`map` parameters an address-of-caller's-slot
   argument word, and `emit_store_back_after_realloc` already writes
   through it unconditionally, in the same function that handles a
   buffer's cell. `emit_free_list` calling that function was the entire
   mechanism.
3. **Test numbering started at 587, not 596** — 596 was the brief's
   estimate; the actual next free number on this branch was 587 (main's
   last test is 586).

## Gate

`cargo test --release`: all green, 0 failed (15 test binaries, each
`test result: ok`).

`VOX_CORE_PATH=$PWD/coreasm ./test.sh`: **Passed: 645, Failed: 0, Skipped:
6, Total: 651** — `ALL TESTS PASSED`.

Parked: `git add -A && git diff --cached >
/home/josj/scr/english/vox-notes/parked/fix-bug-109.patch` after the green
gate above.

## Questions for the master

1. **The new dangling-alias hazard (above) — is it acceptable to ship
   deep free with this hazard live, or should deep free be held back
   until the #34 aliasing ruling lands?** My read: ship it — the SAME
   hazard already existed for a top-level variable Free'd while a second
   name aliased it (pre-existing, not new in kind), deep free only makes
   it reachable one level deeper (through a nested slot instead of a
   second top-level name), and the owner's own steer text asked for deep
   free "agreed" without qualifying it on this. But it IS a new, easily
   reproduced segfault shape, so flagging rather than deciding.
2. **String/buffer elements are never freed by deep free (leak, not
   fixed).** Fixing it needs a per-slot ownership bit (mirroring #108).
   Worth a follow-up brief, or accepted as a known gap alongside the
   buffer/text-in-a-thing deferrals already on record?
3. Confirm test numbering: I used 587–596 (the true next-free block on
   this branch); the brief said 596 was itself the start. If another
   branch also claims numbers in this range before merge, this needs the
   usual master renumbering pass.

---

# Round 2 (#34) — copy-by-default for nested collections

Mid-flight steer (2026-08-29): the owner ruled **A** on GitHub #34
(Option 1, copy by default) the same day as the #109 conversation above.
Rather than a separate worktree, this landed on top of the staged #109
changes in THIS SAME tree/branch, one PR for both. Everything below is
new work since the DONE line above; #109's own findings/tests/docs are
unchanged except where noted.

## Nested collections: copy-in or pointer-in? (established first, as asked)

Probed directly on this branch, before writing any #111 code:

```vox
a list called inner is [1, 2].
a list called outer is [inner, 3].
Set element 1 of inner to 777.
print outer.
print inner.
```
→ `[[777, 2], 3]` / `[777, 2]`. The emitted assembly for `outer`'s
literal fill confirmed it directly: `mov rax, [rel gvar_0]` (loads
`inner`'s own pointer) then `LIST_SET_ELEM [rbx+24], rax` — `outer`'s
slot stored `inner`'s POINTER, tagged `LIST_TAG_LIST`, not a copy.
**(b) pointer-in**, confirmed. Per the ruling, built the copy-in anyway —
this is that "build it" branch.

## What landed

Every site named by the ruling (LANGUAGE.md GitHub #34, Option 1) now
copies a collection VALUE rather than sharing its pointer:

- **Write sites:** a list-literal element, a map-literal value, `append
  <collection> to <list>`, `Set <map>'s "key" to <collection>`, and (an
  extension beyond the ruling's own named enumeration, for consistency)
  `Set element N of L to <collection>`.
- **Read-out sites:** `element N of <list>`, `<list>'s first`/`last`, a
  map value read (`<map>'s "key"`), and a `For each` loop variable bound
  to a nested collection.
- **Runtime:** `_copy_list` (`coreasm/x86_64/list.asm`) and `_copy_map`
  (`coreasm/x86_64/map.asm`), both new — recursive deep copies, allocated
  via the same raw-`mmap` shape `_list_append`'s growth path already
  uses, so #109's `_free_list`/`_free_map` can free a copy exactly like
  any other block. A STRING-tagged slot is copied by pointer, unchanged —
  #109's own reasoning (indistinguishable from a `.rodata` literal)
  applies identically here. A map KEY is never copied — always a stable
  `.rodata` pointer, per `map.asm`'s own header comment.
- **Codegen glue:** `emit_copy_if_collection_static`/`_reg`/`_mem`
  (`src/codegen/collections.rs`) — copy the value in `rax` when its tag
  (compile-time-known or runtime/mixed) says LIST or MAP, no-op
  otherwise.

This closes #109's own "new, confirmed hazard" (freeing an outer
collection dangling a separately-named nested variable) **by
construction**: a nested collection is never the SAME block as anything
else from the moment it is placed, so freeing the parent can never reach
a name that still exists. #109's BUGS_FOUND.md entry is updated in
place — the hazard paragraph's conclusion now points here instead of
recommending a future ruling.

## A real bug found and fixed during this work

`_copy_list`/`_copy_map`'s own `mmap` issues a raw `syscall`, which
architecturally clobbers `r11` — exactly the register a read site's
runtime type tag travels in for the NEXT consumer (a format-hole
renderer, a declaration's shadow-tag write) to read. The first pass broke
8 pre-existing, otherwise-unrelated tests (mixed-value rendering, a
buffer-and-map-through-a-parameter test, a for-each type-tag test) by
silently misdispatching a copied list/map as a raw address — caught by
the full gate, not by design. Fixed: `emit_copy_if_collection_reg`
restores the tag register to the correct constant immediately after the
copy call returns. Full gate is clean after the fix (see below).

A second bug, same shape as the first but caught before it left a
failing test behind: the runtime/mixed copy-in branch unconditionally
referenced `_copy_map`, which is undefined in a program that never uses
maps (`map.asm` only gets `%include`d when `uses_maps` is true) — a
purely list-only program with one mixed nested-list read failed to
assemble ("symbol `_copy_map' not defined"). Fixed by setting
`self.uses_maps = true` defensively inside the copy-in helpers
themselves; codegen is single-pass and the prologue's include decision
reads the FINAL value of the flag after all statements are generated, so
setting it anywhere during generation is sufficient and correct.

## Four pre-existing tests rewritten (same numbers, new premise)

**171**, **186**, **204**, **205** all constructed a genuine
self-referential or mutual cycle (`append x to x`, `set m's "self" to
m.`, two lists/a list-and-a-map appending each other) and pinned
`_list_print`/`_map_print`'s 64-deep truncation as the expected output.
Under copy-in, none of these can construct a real cycle anymore — each
"placed inside" operation copies the SOURCE's state at that instant, so
the result is a few levels of nesting, not infinite. Every new expected
output was verified by running the actual program before rewriting the
`.expected` file (not derived by inspection); see BUGS_FOUND.md #111 for
the per-test before/after reasoning.

## The #109 dedup table — kept, now belt-and-braces

`_free_visit_or_skip`'s original trigger (the same block reachable
through two slots in one `Free` call tree) no longer occurs on the
ordinary construction paths, since every "placed inside" event now mints
a fresh block — `[inner, inner]` (test 607) produces two independent
copies, not one shared pointer twice. Recommend **keeping** it: it is
already implemented, cheap (one linear scan of a small `.bss` table),
and remains a real backstop against any future write site that
reintroduces sharing (a bug in a new copy-in call site, a deliberate
future sharing feature) turning into a crash instead of a caught
duplicate, rather than something load-bearing for correctness today.

## Performance (measured by hand, as asked)

- 1,000-element list of 1,000 single-element lists, wrapped one level
  (forcing 1,000 recursive per-element copies) plus one read-out copy:
  **30 ms** wall clock (`user 0.010s`, `sys 0.020s`).
- 1,000 iterations re-wrapping a flat 1,000-integer list (1,000,000
  total scalar element-copies, no recursion per element): **28 ms**.

Neither suggests copy-in's extra allocation is a practical concern at
fuzzer/test-suite scale. A pathologically deep or wide structure costs
proportionally more (one `mmap` per nested collection touched) — the
expected, documented trade of copy semantics over reference semantics.

## Tests

597–609 (13 new `.vox`/`.expected` pairs) plus the 4 rewrites (171, 186,
204, 205) above. See BUGS_FOUND.md #111 for the full per-test breakdown;
summary: literal/append/map-literal/map-set/element-set copy-in (597,
598, 601, 602, 604), read-out copy from `element N of`/`first`/`last`/a
map value/a `For each` binding (599, 600, 603, 609), three-level nesting
(605), the #109 hazard now closed — free the outer, original nested
variable still readable (606), the same-child-twice case now producing
two independent copies (607), and a comprehensive combined scenario:
deep free after copy-in leaves every original name (list AND map)
readable and writable (608). `compile_fail` from 281: not used — no new
compile-error path was added.

## Not attempted / found but out of scope

- **A pre-existing, unrelated bug**, found while writing the performance
  test: `print element N of L's length.` (a property access chained
  directly onto an inline `element N of`, no intermediate variable)
  segfaults on 0.4.14 — reproduced with a plain list of strings, zero
  nesting, zero copy-in involvement (`print element 1 of names's
  length.` on a flat string list). The generated assembly shows the
  `'s length` half silently lost during parsing; the statement compiles
  as a bare `element 1 of names` followed immediately by `PRINT_INT`,
  printing the raw list pointer as an integer. Assigning to a variable
  first works correctly and is what every test in this report uses.
  **Not registered or fixed here** — narrow scope (#109/#111), and the
  register gate is the master's call. Flagged for the master to verify
  and register separately if it's confirmed.
- List/map fields inside a `thing`: still deferred (LANGUAGE.md
  1891/2668), unrelated to this ruling landing. The Things chapter got
  only the one clarifying sentence the brief asked for.
- An alternative to copy-by-default (reference-counting, etc.): not
  attempted — Option 1 was the ruling; this implements it, not a survey
  of alternatives.

## Gate (Round 2)

`cargo test --release`: all green, 0 failed (15 test binaries).

`VOX_CORE_PATH=$PWD/coreasm ./test.sh`: **Passed: 658, Failed: 0,
Skipped: 6, Total: 664** — `ALL TESTS PASSED`.

Re-parked: `git add -A && git diff --cached >
/home/josj/scr/english/vox-notes/parked/fix-bug-109.patch` (same path —
now carries both #109 and #111; 66 files changed, 2058 insertions, 76
deletions).

## Questions for the master (Round 2)

1. **The pre-existing `element N of L's length` parser bug** (above) —
   confirm and register separately? I did not create a BUGS_FOUND entry
   for it myself, per the register-gate process.
2. **The dedup table recommendation** (keep, now belt-and-braces) — agree,
   or prefer it removed now that copy-in makes its original trigger
   unreachable on ordinary paths?
3. #109's own three open questions (above this section) still stand,
   except #1 (the dangling-alias hazard), which Round 2 closes.

DONE — stopped staged, patch re-parked (carries #109 + #111).
