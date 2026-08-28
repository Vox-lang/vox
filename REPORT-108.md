# REPORT-108.md — `Set <text> to "<format string>"` frees the string it replaces

Branch `fix/bug-108-free-orphaned-text`, off `origin/main` = Vox 0.4.13
(4c85e03). Worked in this worktree only; nothing touched in
`~/scr/english/vox`.

## Design chosen

Two independent checks, combined at every write of a **top-level (global)**
text variable — declaration and every later `Set`/`the ... is`:

1. **Whole-program, flow-insensitive static gate** — `collect_freeable_texts`
   in `src/parser/ast.rs`, modelled directly on the existing
   `collect_widened_lists` precedent (same file). A text variable name is
   *freeable* only if:
   - it is declared **solely** as `a text` — never a buffer, a `value`, a
     function parameter, a for-each/for-range loop variable. Any one of
     those poisons the name **everywhere**, name-keyed and flat, exactly
     the way `collect_all_typed_decls` already poisons a redeclared type.
   - it is **never read anywhere** in a position that could keep its string
     alive past a `Set` on it: the RHS of another declaration or
     assignment, a function argument, `Return`, an append to a LIST (a
     buffer append only copies bytes and does not count — disambiguated by
     a whole-program buffer-name scan), a map key or value, a list/map
     literal element, or the operand of an expression whose codegen can
     hand back that operand's own pointer unchanged.

   One retaining read anywhere disables freeing for that name everywhere,
   including at a `Set` that runs **before** the retaining read ever does.
   The cost is a missed free; the alternative risks a use-after-free, which
   is worse than the leak this fix exists to close (master's ruling,
   BUGS_FOUND #108).

2. **Runtime ownership flag** — one BSS byte per freeable global, paired
   with its payload mirror (`ensure_global_text_owned_label`, mirroring how
   a `value` global's runtime tag is paired with its payload). Set to 1 only
   when the value just written is a format-string evaluation, or an
   `as text`/bare conversion that copies a buffer's or a scalar's bytes into
   a brand-new buffer (`text_write_is_owned`); 0 for everything else — a
   literal, another variable, a parameter, a list/map read, a function
   result, or a cast that turned out to be a pointer pass-through. BSS
   starts zero-filled, so a fresh declaration's first write reads a 0 and
   the free is skipped automatically — declaration and every later `Set`
   share **one** code path (`emit_owned_text_global_store`), no separate
   "is this the first write" case.

At a `Set` on a freeable global: evaluate the new value first (the
accumulate idiom reads the old string while building the new one), save it,
free the OLD string if its flag says owned (struct pointer = data pointer
− `BUF_DATA_OFFSET`; `_free_buffer` unregisters it from `buf_table` if
present and now **always** munmaps, fixing a latent leak of buffers past
`MAX_BUFFERS` live ones), store the new value, set its own flag from its
own provenance.

This is the brief's recommended design (items 1–3), combined rather than
picked-one: the runtime flag alone cannot see aliasing that happened
*between* two writes to the same variable (`a is "{n}". b is a. Set a to
...` — the flag says "owned" from `a`'s own last write, but `a`'s pointer
had since been copied to `b`); the static gate alone would need per-read
flow tracking to know whether the *current* value is a literal or an
allocation. Together: the gate proves "never shared, whole program"; the
flag proves "this specific value came from an allocation, this specific
write." Neither alone is sound; both together are, and stay simple.

**Why global-only.** A local (stack) freeable text's ownership flag would
need to be reliably initialised before its first read. A declaration that
shares one compile-time stack slot across sibling `If`/`Otherwise` branches
(only one of which runs), or a `VarDecl` re-executing inside a loop body,
cannot prove that without risking a read of uninitialised stack memory as a
pointer — the exact failure mode this fix exists to prevent, not reproduce.
A BSS byte has no such problem (always zero at load), so every freeable
global takes the free-on-`Set` path and only globals do. Every headline
evidence program and aliasing probe in `docs/BUGS_FOUND.md` #108 is a
top-level text; this restriction costs a missed optimisation for
function-local accumulation (confirmed unchanged, see "Local scope
unaffected" below), never a correctness gap.

## A use-after-free found and fixed during review

The first pass of the static gate recursed into a `Cast`'s and a
`TreatingAs`'s operand instead of marking it retaining, so a bare
`Expr::Identifier` operand fell through the recursion's own catch-all and
was never inserted into the retaining set:

```vox
a number called n is 2.
a text called src is "v{n}".
a text called u is src as text.
Set src to "z{n}".
a number called i is 0.
While i is less than 50, Set src to "q{i}", increment i.
Print "u={u} src={src}".
```

`src as text` on an already-text `src` is a bare pointer pass-through in
codegen (`generate_expr`'s `Cast`/`String` branch leaves a text source
untouched — LANGUAGE.md's Basic Conversions table). `u`'s declaration took
`src`'s own pointer, not a copy. The gate never marked `src` retaining, so
`src` stayed "freeable," and `Set src to "z{n}"` (and every later `Set` in
the loop) freed `u`'s string out from under it — a real use-after-free,
segfaulting at the final `Print`. Caught by the master reviewing the first
patch, before it shipped (`steer-1787912538.md`).

Fix: `Expr::Cast{value,..}` and `Expr::TreatingAs{value, replacement, ..}`
now call `mark_retaining` on their pass-through operand(s), not
`find_nested_retains`. `TreatingAs`'s `match_value` stays consuming (it is
only ever compared, never returned — confirmed by reading
`codegen/expr.rs`'s `Expr::TreatingAs` arm: the "no match" path pops and
keeps `value`'s own pointer, the "match" path evaluates and keeps
`replacement`'s own pointer, neither is ever a fresh copy). Marking a
non-text `Cast` operand (a number/float/boolean/buffer) costs nothing —
those are never `freeable_texts` candidates, and a buffer source really
does get copied fresh downstream, so over-marking is only ever
conservative.

**Audit of every other `Expr` variant that could plausibly hand back an
operand's own pointer** (the master's explicit ask), against
`codegen/expr.rs`:
- **`PropertyAccess`** (`x's first`/`last`/`keys`/`values`) — `object` is a
  plain `String` (the list/map's name), not a `Box<Expr>`; it cannot wrap a
  `freeable_texts` candidate identifier at all. Any candidate whose pointer
  reaches a list/map this way was already marked retaining at the
  *insertion* site (`ListAppend`/`MapSet`/a list-literal element), so
  reading it back creates no new gap.
- **`ThingField`** — `base` is a `String`, same reasoning as `PropertyAccess`.
  A candidate stored into a field is already caught at `SetThingField`.
- **`ElementAccess`/`ListAccess`** — `list` **is** a `Box<Expr>`, but is
  type-constrained to a List; a text candidate can never appear there
  under normal type-checking. Upgraded `list` from `find_nested_retains` to
  `mark_retaining` anyway (zero cost) as a defensive margin against that
  assumption.
- **`MapAccess`** — `map` is a `String`; `key` is a lookup key, only ever
  compared, never returned. Same shape as `TreatingAs`'s `match_value`.
- **`ArgumentAt`/`ArgumentHas`/`ArgumentFirst`/etc., `EnvironmentVariable*`**
  — the operand (an index or an env-var name) is only ever a lookup key;
  the *result* is an argv/envp string, never the operand's own pointer.
  No candidate's pointer can flow through as the result.

No other passthrough was found. The rule the gate now states and holds:
**no freeable text's pointer can reach any other slot, container,
argument, return, or thing field by any expression shape** — either
because the shape is provably a fresh allocation (`text_write_is_owned`'s
job) or because the gate marks every shape that is not.

## Step 0 — before/after (the "before" compiler: 0.4.13, 4c85e03, at
`~/scr/english/vox/target/release/vox`, read-only)

| Program | Before (maxrss) | After (maxrss) |
|---|---|---|
| `t_text_acc_20000` (`Set acc to "{acc}x"` × 20000) | 236544 KB (quadratic) | 392 KB |
| `w_set_text_short_format_40k` (`Set t to "n={n}"` × 40000) | 160000 KB (linear) | 440 KB |
| `u_set_text_literal_40k` (`Set t to "hello"` × 40000) | 392 KB | 392 KB |
| `v_set_text_from_text_40k` (`Set t to src` × 40000) | 388 KB | 388 KB |

Fail-before/pass-after on the two new memory-regression tests (564, 565 —
same shapes, gated on `/proc/self/statm`'s resident-page field, threshold
5000 pages vs. a before-fix reading of ~59000/~40000):

```
$ VOX_CORE_PATH=~/scr/english/vox/coreasm ~/scr/english/vox/target/release/vox tests/564_*.vox -o /tmp/t564_before && /tmp/t564_before
59149
$ ./target/release/vox tests/564_*.vox -o /tmp/t564_after && /tmp/t564_after
ok
$ VOX_CORE_PATH=~/scr/english/vox/coreasm ~/scr/english/vox/target/release/vox tests/565_*.vox -o /tmp/t565_before && /tmp/t565_before
40009
$ ./target/release/vox tests/565_*.vox -o /tmp/t565_after && /tmp/t565_after
ok
```

## Aliasing probe matrix (all before AND after this fix — every row is
identical output, both compilers; freeing only ever removes memory a
*different* variable does not still name, so a correct probe cannot
distinguish the two compilers by output, only a wrong one could)

| # | Shape | Output (before = after) |
|---|---|---|
| 1 | `a text called b is orig.` then `Set orig to ...` | `5` (test 566) |
| 2 | `append orig to <list>` then `Set orig to ...` | `5` (test 567) |
| 3 | `'keep' with orig.` (callee stashes it in a global) then `Set orig to ...` | `5` (test 568) |
| 4 | `Return a text, orig.` (callee) + unrelated same-named `orig` reassigned in caller | `5` (test 569) |
| 5 | `a value called v is orig.` then `Set orig to ...` | `5` (test 570) |
| 6 | `Set t to "{t}!"` on a literal-initialised `t`, twice | `hello!?` (test 571) — exercises the runtime flag both ways: first `Set` must NOT free `.rodata`, second `Set` MUST free the first `Set`'s own result |
| 7 | `append tok to cmdargs` then `Set tok to ...` then `Execute ... with arguments cmdargs.` | `5` (test 572) |
| 8 | `a text called u is src as text.` then 50 more `Set src to ...` (the use-after-free found in review) | `u=v2 src=q49` (test 573) |
| 9 | Same as 8, via `Set u to src as text.` instead of a declaration | `u=v2 src=q49` (test 574) |
| 10 | `treating "" as fallback` (replacement is a freeable text) inside `append each ... to <list>`, then `Set fallback to ...` | `anon` / `bob` (test 575) |
| 11 | `Set u to src as text.` where `u` already held an OWNED string (must free `u`'s own prior string while refusing to free `src`'s) | `u=v2 src=z2` (test 576) |

All 11 confirmed against the "before" binary (0.4.13) except 8/9/11, which
depend on the fix existing at all to be meaningful (before this branch,
nothing is ever freed, so they trivially "pass" on the before compiler for
the wrong reason — the interesting comparison there is against the
*use-after-free-introducing intermediate state* of this same branch mid-review,
which is documented above rather than re-frozen as a binary).

## Test counts

- `./test.sh`: baseline 617 (611 passed, 6 skipped) → **630** (**624**
  passed, 6 skipped, 0 failed). +13 new: two memory regressions (564, 565)
  and eleven aliasing probes (566–576).
- `cargo test --release`: baseline 376 passed → **385 passed, 0 failed**.
  +9 new `collect_freeable_texts` unit tests in `src/codegen/tests.rs`
  (the freeable-set computation pinned independent of codegen/asm: the
  headline accumulate shape, the declaration-aliasing shape, the
  list-vs-buffer-append disambiguation, the call-argument shape, the
  parameter-poisoning shape, and — added after the review finding — the
  `Cast`/`TreatingAs` pass-through shapes, both statement kinds, plus a
  control confirming a *number*-to-text cast destination stays freeable).
- `cargo build --release`: clean, no warnings introduced.

## LANGUAGE.md

One sentence added to the Format Strings as Values paragraph (~3396–3419,
shifted +1 line by the addition): "A text variable reassigned from a
format string releases the string it no longer holds." No history, no
version reference, per the standing rule for that file.

## Out of scope / noticed along the way

- **Function-local text accumulation is unaffected** (confirmed:
  `f_format_text_in_fn.vox` measures 80000 KB before and after this
  fix, byte-for-byte) — see "Why global-only" above. This is the
  intersection with #107 (scope-exit freeing), which stays a ruled
  limitation.
- **List-of-text and map-value orphans are not addressed.** If a list or
  map is repeatedly cleared/reset and repopulated with fresh format-string
  texts, those strings are never freed by this fix (they were never
  candidates — appending to a list poisons the appended name, by design,
  and nothing frees a list's own elements when the list itself is
  cleared/reassigned). Genuinely separate from #108's "a single named
  text variable's own `Set`" scope; flagged for a future register entry
  if it turns out to matter in practice.
- **`_free_buffer` now always munmaps**, whether or not the struct is
  currently in `buf_table` (previously the `.not_found` path silently
  skipped the munmap — a latent leak for any buffer allocated past the
  64-entry table, `MAX_BUFFERS`, though `_free_buffer` itself had zero
  callers before this fix, so this is a fix to previously-dead code, now
  exercised for the first time by `emit_owned_text_global_store`).
- Considered and rejected: fixing `_free_buffer`'s callers or the resize
  path's own (separately-implemented, already-correct-per-#107's own
  verification) frees — out of scope, untouched.

## Files changed

- `src/parser/ast.rs` — `collect_freeable_texts` (the static gate).
- `src/codegen/mod.rs` — `freeable_texts`/`global_text_owned_labels`
  fields; `BUF_DATA_OFFSET` now genuinely read (dead_code allow removed).
- `src/codegen/vars.rs` — `ensure_global_text_owned_label`,
  `text_write_is_owned`, `emit_owned_text_global_store`.
- `src/codegen/statements.rs` — wired into `Statement::VarDecl`'s and
  `Statement::Assignment`'s global-text-write sites; `generate()` runs the
  new prescan alongside the existing global-label/type prescans.
- `src/codegen/tests.rs` — 9 new unit tests.
- `coreasm/x86_64/resource_buffer.asm` — `_free_buffer` always munmaps.
- `docs/BUGS_FOUND.md` — #107/#108 brought in (Step -1 patch); #108
  status flipped to fixed with a Fix write-up.
- `CHANGELOG.md` — `## [Unreleased]` created, one `### Fixed` bullet.
- `LANGUAGE.md` — one sentence.
- `tests/564`–`tests/576` — 13 new `.vox`/`.expected` pairs.

## Status

Staged (`git add -A`), not committed. Patch parked at
`~/scr/english/vox-notes/parked/fix-bug-108.patch`. Report copied to
`~/scr/english/vox-notes/`.

FIX 108 DONE
