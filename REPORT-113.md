# REPORT — #113: WITHDRAWN — by design (owner ruling); docs + design-pin test only

Worktree: `~/scr/english/worktrees/wt-fix-113`, branch `fix/bug-113-cwd-coreasm-shadow`, off `main` at 4995394 (v0.4.14).

## Owner ruling (2026-08-29, ~14:2x)

> "#113 isn't a bug, it allows unit tests to test the bleeding-edge coreasm.
> This would break CI and integration testing."

The invoking directory's `coreasm/` taking precedence over `VOX_CORE_PATH` at
assembly time is **by design**: a checkout under test must assemble its own
tree's macros, not whatever `VOX_CORE_PATH` happens to point at, or a unit
test suite / CI run would silently exercise the wrong runtime. This
supersedes the master's earlier verification
(`vox-notes/VERIFIED-CWD-CORASM-SHADOW.md`) and the fix built in this
worktree's first pass. The fix has been withdrawn. What remains is the
documentation correction and a regression test that pins the *designed*
precedence, so it cannot regress away by accident later.

## What was withdrawn

`src/main.rs` reverted to HEAD (`git checkout HEAD -- src/main.rs`) — the
nasm invocation is exactly as it was: `nasm` runs with the invoking
process's inherited cwd, no `current_dir` override, `-I<parent>` as a
fallback only. `CHANGELOG.md` reverted to HEAD (no `[Unreleased]` section —
a docs-only clarification doesn't warrant a changelog bullet). The `#113`
entry in `docs/BUGS_FOUND.md` was written and then removed in full — this
report is where the ruling and the history live instead, since #113 was
never a defect.

## What was kept / rewritten

1. **`tests/p113_cwd_coreasm_shadow.rs`** — rewritten from a regression test
   (which asserted the cwd decoy must NOT win) into a design-pin test
   (`cwd_coreasm_takes_precedence_by_design`) that asserts the cwd decoy
   MUST win. It plants a one-byte, macro-free decoy at
   `coreasm/x86_64/list.asm` in a temp working directory, points
   `VOX_CORE_PATH` at this tree's real coreasm, and asserts the compile
   *fails* with nasm's `instruction expected` error — proof that the decoy
   in cwd, not the `VOX_CORE_PATH` tree, was the one actually assembled.
   Went with the one-byte-decoy-must-fail shape (the steer's offered
   fallback) rather than a marker-emitting decoy: it needs no understanding
   of `list.asm`'s macro internals to keep passing as that file evolves, and
   a compile failure specifically bearing the decoy's parse error is already
   unambiguous proof of which file was assembled — a marker would prove the
   same fact at the cost of a more fragile, hand-maintained decoy.
   Doc comment cites the owner's ruling and the CI/bleeding-edge-coreasm
   reason directly.
2. **`docs/INSTALL.md`** — "How `vox` finds `coreasm`" now opens by stating,
   present tense, that nasm resolves each `%include` first against the
   invoking directory, by design, so a checkout under test assembles its own
   coreasm; the six-step resolution order (`VOX_CORE_PATH` → XDG config →
   system paths → executable-relative → cwd fallback → embedded copy) is
   described as what decides only when the invoking directory has no
   matching file. No "before this was fixed" wording — nothing was fixed.

## Regression test — what it proves, now

```
running 1 test
test cwd_coreasm_takes_precedence_by_design ... ok
```

Run against the reverted (HEAD-identical) `src/main.rs`. The nasm stderr it
captures on the way to that pass is the same parse error the earlier verified
repro documented:

```
coreasm/x86_64/list.asm:1: warning: label `x' alone on a line without a colon might be in error [-w+label-orphan]
prog.asm:35: error: instruction expected, found `LIST_SET_ELEM ['
...
NASM assembly failed
```

The test's assertion is now that this failure *happens* (`!status.success()`
and stderr contains `instruction expected`) — the opposite polarity from the
withdrawn fix's test, which asserted the compile succeeded despite the
decoy.

## Files changed (final state, relative to HEAD 4995394)

- `src/main.rs` — **unchanged** (reverted to HEAD; no diff).
- `CHANGELOG.md` — **unchanged** (reverted to HEAD; no diff).
- `docs/BUGS_FOUND.md` — **unchanged** (entry written then removed; no net
  diff against HEAD).
- `tests/p113_cwd_coreasm_shadow.rs` — new file: design-pin test.
- `docs/INSTALL.md` — resolution-order section rewritten to state the
  invoking-directory-first behaviour as designed, present tense.
- `REPORT-113.md` — this file.

## Gate

- `cargo test --release`: **all green**, including the rewritten design-pin
  test (0 failures across the full suite).
- `VOX_CORE_PATH=$PWD/coreasm ./test.sh`: **Passed: 635, Failed: 0, Skipped:
  6, Total: 641 — ALL TESTS PASSED.**

## What I could NOT do / did not attempt

Unchanged from the withdrawn pass — still out of scope, still just flagged,
not touched:

- `docs/INSTALL.md`'s "Working on the compiler with a system install
  present" section describes system paths outranking the executable-relative
  tree, but the code's actual order (`src/main.rs:149–172`) has
  executable-relative ahead of system paths — the opposite. Reads like GH
  #233 ("coreasm resolution: system paths outrank the exe-relative tree",
  already closed) either regressing or never having been fully reflected in
  that paragraph.
- `find_coreasm_path`'s env-var branch (`src/main.rs:187–197`) short-circuits
  on `path.exists()` before ever checking `path.join("coreasm")`, so
  `VOX_CORE_PATH=/path/to/vox` (repo root, which exists) resolves to the
  root itself rather than `/path/to/vox/coreasm` — contradicting INSTALL.md
  Option A's claim that both forms are equivalent. Not live in this repo
  (every documented use sets `VOX_CORE_PATH` to the `coreasm` directory
  directly) but worth a look separately.

Neither is a `%include`-resolution question, and #113 turned out not to be a
defect to fix at all — both remain candidates for separate triage, not for
this branch.

## Questions for the master

None. The ruling was unambiguous and the steer's instructions were complete.

---

DONE — stopped staged, patch parked
