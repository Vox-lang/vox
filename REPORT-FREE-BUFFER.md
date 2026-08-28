# Report: `Free <buffer>` releases memory now (Q7 option C)

Branch `feat/free-buffer`, off `origin/main` = Vox 0.4.13 (4c85e03). Worked
in `~/scr/english/worktrees/wt-free-buffer` only; `~/scr/english/vox` was
read-only (its live fuzz campaigns and its own in-progress `docs/BUGS_FOUND.md`
edit for #107/#108 were never touched).

## Design as built

1. **`Free <buffer>.` releases now.** `_free_buffer`
   (`coreasm/x86_64/resource_buffer.asm`) was updated to match the #108
   branch's shape exactly: unregister first if tracked, then always munmap
   regardless. Lists and `Allocate`d raw blocks keep the unchanged
   `HEAP_FREE` path — `Statement::Free` codegen (`src/codegen/statements.rs`)
   now branches on `variable_types[name] == VarType::Buffer` first.
2. **After-state.** `Free` points the variable's slot at a shared **static**
   buffer header: capacity 0, length 0, `BUF_FLAG_FIXED` set, one reserved
   NUL-terminator byte (the exact shape `_alloc_buffer_sized(0)` produces —
   bug #78's size guard — just static instead of mmap'd). This header
   lives in coreasm itself now, not in per-program Rust-generated `.data`
   (see "The Resize hazard" below for why): `_released_buffer_header` in
   `resource_buffer.asm`. Every existing bounds-checked buffer operation
   (byte read/write, append, copy) already refuses a capacity-0 fixed
   buffer and sets the error flag with no special-casing needed — that
   was the whole point of matching bug #78's shape.
3. **Globals, locals, parameters — the parameter decision.** I read the
   `buffer` parameter's existing "moves the block, caller follows"
   write-back mechanism (`emit_store_buffer_ptr_to_slot` /
   `emit_buffer_param_cell_writeback` / `buffer_param_cells`, codegen/
   buffers.rs + functions.rs, docs/BUGS_FOUND.md #90) and confirmed it is
   **generic pointer propagation keyed by frame offset** — it does not care
   whether the new pointer is a grown block or my static header's address.
   `emit_free_buffer` rides it via the exact same helper `BufferResize`
   already uses (`emit_load_named_var_addr` / `emit_store_back_after_realloc`),
   so **`Free` on a buffer parameter WORKS** and empties the caller's
   variable too — I did not make it a compile error. Verified with a
   2-frame parameter chain (`outer` passes its own `buffer` parameter to
   `inner free`, which frees it) — the top-level caller ends up empty in
   both the 1-frame and 2-frame cases (see test 585, and `param_free_deep.vox`
   in-session, not committed). I did **not** use test slot 280 as
   compile_fail — see "Test numbering" below.
4. **Spellings.** `parse_free` now skips an optional `the`, exactly like
   `parse_increment`/`parse_decrement` already do. `free`/`release`/
   `deallocate` already folded to one token in the lexer.
5. **Text/map unchanged.** No codegen or analyzer change; `Free` still
   rejects anything but a buffer, list, or `Allocate`d name.
6. **Docs.** New `#### Releasing a Buffer` subsection between Buffer
   Resizing and Buffer Byte Access; one sentence added to Dynamic Buffers
   about per-entry allocation (#107); `Free`/`Allocate` added to the
   Statement Starters table, `release`/`deallocate` added to Reserved
   Aliases (pointing at the alias each folds to, same shape as `ms`/
   `message`/`string`). Every new code block in the section was actually
   run to completion before I wrote it into the doc (see the OOM incident
   below for why I insist on this now).
7. **#107 note.** Added to "Dynamic Buffers" — current-state wording only,
   no "previously"/history language (caught and fixed once already, see
   the second steer below).

## The Resize hazard (master's steer, fixed)

The first cut only taught **codegen** (`emit_free_buffer`) to recognise
the released header before calling `_free_buffer` — nothing taught
`_realloc_buffer`/`_reallocate_buffer` about it. Master found: `Free line.`
then `Resize line to 100.` fell into `_realloc_buffer`'s alloc+copy
fallback, which called `munmap` on the header's own `.data` address
(harmless *only* because 24 bytes there isn't page-aligned — not a real
guarantee) and then returned a **freshly mmap'd, live, writable buffer**,
silently resurrecting the variable. `append` after that really wrote into
memory; a second `Free` then double-freed a real block without ever
setting the error flag. strace confirmed: `munmap(0x403092, 24) = -1 EINVAL`
against the `.data` header.

**Fix (runtime-side, chosen over auditing every codegen call site):**
moved the shared header out of per-program Rust-generated `.data` and into
`resource_buffer.asm` itself as a single well-known symbol,
`_released_buffer_header` (a `section .data` block ahead of the existing
`.bss` block — NASM merges same-named sections across `%include`s the
compiler is already doing). `_free_buffer`, `_realloc_buffer`, and
`_reallocate_buffer` each now compare their incoming pointer's *address*
(not shape) against this label first, and refuse — `SET_LAST_ERROR 1`,
return unchanged, touch nothing — before any table search, mremap, alloc,
or munmap. This is deliberately an **identity** check, not a
`BUF_FLAG_FIXED && BUF_CAPACITY == 0` shape check: a *real* buffer can
legitimately reach that exact shape too (bug #78's own out-of-bounds size
guard), and `Resize` on such a real fixed buffer is documented, intended
behavior (LANGUAGE.md's own Buffer Resizing example resizes an explicitly
fixed buffer) — only the one static instance may never be touched.

Why the runtime fix over the codegen-audit route the steer also offered:
`_realloc_buffer` has exactly one caller (`BufferResize`) and
`_reallocate_buffer`/`_grow_buffer` are reachable only from paths that
already gate on `BUF_FLAG_FIXED` before calling them (`ByteSet`,
`_buffer_append`, `_buffer_copy`, `_buffer_append_bytes`,
`_read_into_buffer`'s presize path) — so the header, always FIXED, could
never reach `_grow_buffer` today regardless. But "always safe by
construction" beats "always safe because every call site currently
remembers to check," so the guard went in both runtime routines rather
than trusting the current caller graph to stay that way. This also let me
**simplify** `emit_free_buffer`: it no longer pre-checks anything itself
(that logic moved into `_free_buffer`), it just calls it unconditionally
and stores the header's address back either way — one behavior, one place
that owns "is this the released header."

**Proof (capped, strace, on the final binary):**
```
$ systemd-run --user --scope -q -p MemoryMax=512M -- timeout 10 ./hazard
resize flagged
len after resize 0
append flagged
text []
second free flagged

$ strace -f -e trace=munmap ./hazard
munmap(0x7f576c5da000, 4120)    = 0     <- the real "hello" buffer, freed once
munmap(0x7f576c5da000, 4121)    = 0     <- unrelated real allocation at exit
+++ exited with 0 +++
```
No munmap anywhere near `.data` (`0x403034`, from `readelf -S`) or `.bss`
(`0x4030fc`). New regression test **586** (see "Test numbering").

## The OOM incident (my mistake, root-caused, resolved)

Master's first steer reported two of *my own scratch test programs*
(`doc_example`, pids 1520453/1527573) OOM-killed at ~48 GB RSS while I was
drafting the LANGUAGE.md worked example. Root cause, confirmed by capped
reproduction: my first draft of that scratch file separated the `While`
loop body's statements with **periods** instead of commas:
```
While n is less than 3,
    a buffer called line is 4096 bytes in size.   <- period closes the While HERE
    Read line from source into line.               <- now unreachable top-level code
    ...
```
Per the termination rule (LANGUAGE.md, "The termination rule" — the same
mechanism the manual's own blank-line-ejection warning describes two
sections earlier), a period closes only the innermost open clause; the
first period here closes the `While` immediately, so its entire body is
just the buffer declaration and `n` never increments. The loop spins
forever, allocating a fresh 4 KB fixed buffer every iteration, until OOM.
This is **not a `Free`/codegen defect** — a version of the same file with
`Free` entirely removed hung identically (verified). The corrected file
(commas between body statements, period only at the end) runs to
completion in both plain and `systemd-run --user --scope -q -p
MemoryMax=2G -- timeout 30` forms, verified on the **final** binary. Every
compiled test program in this session now runs under that cap; no stray
processes remain (`ps aux` checked clean).

## Step 0 — probe matrix, before binary (0.4.13, quoted)

Memory (`/usr/bin/time -v`, `Maximum resident set size`):
- f1 (dynamic buffer loop): **160000 kB**
- f2 (fixed buffer loop): **160000 kB**
- f3 (list loop): **392 kB** (list already worked)
- f4 (buffer declared in a function, loop): **160000 kB**

Behavior:
- f5 use-after-free: `len 5` / `text [hello]` / `after append len 6` — silent, still live
- f6 double free: `survived` — silent
- f7 free-then-error-flag: `end` only — flag never fires
- f8 `Free` on text: compile error, `Free requires a buffer or list: t`
- f9 redeclare-after-free in a loop: `round 0/1/2`, `done`
- f10 free a global from a function: `len 5` — unaffected
- g1 `Release` spelling: `released`
- g2 `Release the data.`: compile error, `Cannot use 'the' as a variable name`
- g3 list use-after-free: `[1, 2, 3]`, `len 4`
- g4 `Free` on a map: compile error, `Free requires a buffer or list: m`
- g5 free then allocate more: `fresh [again] data [hello]` — freed buffer still readable

## After-state matrix, final binary (capped, matches above 1:1)

- f1/f2/f4: **~390 kB** (was 160000 kB)
- f3: 392 kB (list, unchanged)
- f5: `len 0` / `text []` / `after append len 0` — refused, flagged
- f6: `survived` (no crash; second free sets the flag silently — see f7)
- f7: `error flagged` then `end` — flag now fires
- f8: still compile error, message unchanged
- f9: `round 0/1/2`, `done` — unchanged, confirmed safe
- f10 (global freed from a function): `len 0`
- g1: `released`; g2 (`Release the data.`) now **compiles and runs**: `released the`
- g3 (list): `[1, 2, 3]`, `len 4` — **unchanged**, pinned (test 584)
- g4: still compile error, message unchanged
- g5: `fresh [again] data []` — new buffer unaffected, freed one empty
- buffer parameter (585): caller ends up `len 0`/`text []`, and stays refused
  through a 2-frame parameter chain
- Resize-on-freed (586, the hazard fix): flagged, still empty, `append`
  still refused, second `Free` still flagged, strace-clean

## Tests

- **578–586** (numbers 578+ reserved to me, 577 taken by a sibling): all
  new, all pass, fail-before/pass-after confirmed against the 0.4.13
  binary for every one except 583/584 (already-correct/unchanged
  behavior, so no before/after delta — pinned as regression tests) and
  586 (fixed only within this branch's own history; the 0.4.13 binary has
  no flags at all there, shown for contrast, not as a fail-before proof —
  the real fail-before evidence for 586 is the interactive repro +
  strace quoted above, from before the runtime guard existed).
  - 578: the 20 000-iteration loop, `/proc/self/statm` check (#108's
    564/565 idiom), threshold 5000 pages. Before: 20010. After: ok.
  - 579: after-state matrix (length, `as text`, byte read, append, copy).
  - 580: double free → flag once, program continues.
  - 581: `Free`/`Release the`/`Deallocate` all compile and behave identically.
  - 582: function-local free + global-from-function free.
  - 583: redeclare after free in a loop, 3 rounds.
  - 584: list `Free` regression pin (unchanged after-state, documented honestly).
  - 585: buffer-parameter free empties the caller (my addition — see
    "Test numbering" below for why it isn't a compile_fail case).
  - 586: Resize-on-a-freed-buffer regression (the hazard fix).
  - compile_fail 279: `Free t.` on text, message pinned
    (`Free requires a buffer or list: t`).
- `./test.sh`: **620 passed, 0 failed, 6 skipped** (626 total; skips are
  pre-existing `manual_*` fixtures with no `.expected`, unrelated).
- `cargo test --release`: **376 passed, 0 failed** across 14 binaries
  (main unit tests 318, including `compile_fail_corpus_reports_errors`
  which walks 279 among the rest of `tests/compile_fail`).
- Both suites re-run on the **final** binary (after the Resize fix),
  capped, green.

## Test numbering (deviation from the brief, explained)

The brief pre-reserved compile_fail **280** for "`Free` on a buffer
parameter." I decided (see above) that `Free` on a parameter *works*
rather than being a compile error, so there is no compile_fail case for
it — I left slot 280 unused rather than repurposing a compile_fail number
for a passing test, and put the actual regression test at **585** in the
578+ sequence instead. The master's second steer separately asked me to
"add test 585" for the Resize hazard, written before it had seen that I'd
already used 585 for the parameter case; I used the next free slot,
**586**, for the hazard test instead of colliding with my own 585.

## Register and changelog

- `docs/BUGS_FOUND.md`: **not touched.** Bug #107 does not exist yet in
  this branch's copy of the file (it's `main`/4c85e03, before #107 was
  registered) — the registration is currently an *uncommitted* edit in
  the live `~/scr/english/vox` checkout (off-limits to me), not yet
  merged anywhere I could reach. I did not fabricate or copy the entry
  in; that's a registration decision, not mine to make. For when it
  lands, the addendum the brief asked for is exactly:
  > **Resolution.** ... Master's recommendation: A now (docs only), B for 0.5.
  >
  > Remedied by the `Free` statement (v0.4.14): see LANGUAGE.md, Releasing
  > a Buffer.

  (append after the existing `**Resolution.**` paragraph at the entry's
  end; status line stays "Not a compiler defect — a limitation").
- `CHANGELOG.md`: `## [Unreleased]` created above `## [0.4.13]` with the
  `### Added` bullet exactly as specified.

## Noticed, out of scope

- **List after-state.** `Print items` after `Free items` still prints the
  list's old contents (`[1, 2, 3]`) — the block is really unmapped, but
  the variable's slot still holds the stale pointer and nothing has
  overwritten that freed page yet at the size these tests run. Pinned as
  today's behavior (test 584), not changed — the brief was explicit that
  list semantics are not in scope here.
- **`_buffer_copy` on an empty source, into ANY 0-capacity fixed
  buffer (real or released), does not set the error flag.** Traced during
  the Resize investigation: `.copy_fixed_fit` is reached even when the
  source length is 0 (0 ≤ 0 "fits"), so it still writes `BUF_LENGTH = 0`
  (a no-op value) and the reserved terminator byte — safe now that the
  released header reserves that byte, but the *flag* genuinely isn't set,
  unlike every other refused op here. This is a pre-existing gap for any
  real capacity-0 fixed buffer (bug #78's shape), not introduced by this
  brief, and not exercised by copying non-empty content into a freed
  buffer (which does flag correctly, test 579). Flagging for whoever owns
  `_buffer_copy` next.
- **`Clear` on a freed buffer** does not set the error flag either
  (`_buffer_clear` unconditionally zeroes `BUF_LENGTH`/writes the
  terminator byte, no flag logic at all) — same pre-existing gap, same
  reasoning, not a memory-safety issue (writes 0 over 0), out of scope.
- `Allocate` is still otherwise undocumented beyond the one keyword-table
  line this brief added, per instruction ("one line").

## Status

Staged, not committed. `git diff --cached` parked at
`vox-notes/parked/feat-free-buffer.patch`. Report copied to
`vox-notes/`.

FREE BUFFER DONE
