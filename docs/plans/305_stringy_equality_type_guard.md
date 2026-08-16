# Plan 305 — equality dispatch dereferences a non-stringy operand (BUGS_FOUND #20)

A red team pass on the plan-304 (#19) fix surfaced this. It is a **pre-existing**
crash, not introduced by #19 — but the #19 fix makes it reachable from a
common pattern, so it must ship on the same branch
(`fix/stringlit-name-resolution`) before that work merges.

## The defect

Comparing a **stringy** value (a string literal, or a `text`/`buffer`) to a
**non-stringy** value (`number`/`float`/`boolean`, and `list`/`map`) with
`is equal to` / `is not equal to` treats the non-stringy operand's raw value
as a NUL-terminated C-string pointer and dereferences it.

Confirmed against the current branch (`1df7262`), all exit 139 unless noted:

```vox
If "abc" is equal to 3.5 then, print "a". Otherwise, print "b".   (SIGSEGV — no name collision at all)
a float called ratio is 3.5.
If "abc" is equal to ratio then, print "a". Otherwise, print "b". (SIGSEGV)
a float called pi is 3.5.
If "pi" is equal to pi then, print "a". Otherwise, print "b".     (SIGSEGV — the #19 collision case)
```
- `number`, `float`, `boolean` operands all crash; both operand orders; both
  `is equal to` and `is not equal to`.
- `list`/`map` operand does **not** crash (a heap pointer is readable) but
  gives a wrong answer and is a suspected out-of-bounds read — see the red
  team's "unproven suspicions".
- `buffer`-vs-`text` and `text`-vs-`text` are correct and must stay correct:
  both operands are byte sequences, so the stringy path is right for them.

**Why #19 made it matter.** Before #19, `infer_expr_type` on a string literal
whose text matched a `float` variable's name returned `Float` (the buggy name
lookup), so `"pi" is equal to pi` went down the numeric path — a wrong answer,
no crash. #19 correctly made a literal always infer `String`, so those
comparisons now reach this stringy-dispatch guard. The crash itself predates
#19 (`"abc" is equal to 3.5` crashes with the #19 fix reverted too), but a
literal coinciding with a variable name is an ordinary thing to write, where
`"abc" is equal to 3.5` is not — so #19 turns a latent crash into a likely one.

## Root cause

`src/codegen/mod.rs`, the `Equal`/`NotEqual` arm in **both**:
- `generate_condition` (~line 8719), and
- `generate_expr` (~line 7012) — the structurally identical expression-position
  twin. The red team could not find surface syntax to reach it, but it has the
  same defect and must be fixed in the same way.

Both guard with:

```rust
BinaryOperator::Equal | BinaryOperator::NotEqual
    if self.is_stringy_expr(left) || self.is_stringy_expr(right) =>
{ self.emit_stringy_equality(left, right); ... }
```

`is_stringy_expr` = `infer_expr_type(e) ∈ {String, Buffer}`. The `||` means the
stringy path is taken when only **one** side is stringy; `emit_stringy_equality`
→ `generate_cstr_expr` then treats the other operand's `rax` as a C-string
pointer (`generate_cstr_expr` only special-cases `Buffer`; everything else is
passed through as-is) and hands it to `_str_eq`, which dereferences it.

## The fix

Take the stringy comparison path **only when both operands are stringy**. When
one side is stringy and the other is not, the two values are of different,
non-comparable types and can never be byte-equal:

- `is equal to` → constant **false**
- `is not equal to` → constant **true**

computed **without dereferencing or byte-comparing either operand**. This is
the recommended semantics (it matches how `buffer`-vs-`text`, both byte
sequences, already compare, and it never crashes). A **compile error** for a
stringy-vs-non-stringy equality is an acceptable alternative if it turns out
to be less disruptive to existing behaviour — but do not leave it reaching the
old numeric/pointer path, which is *also* wrong (it `cmp`s a pointer against a
scalar). Pick one, apply it to both call sites, and say which and why in the
commit message.

Watch the boundary cases while deciding:
- `value` (dynamic) operands: `infer_expr_type` may report `Value`/`Mixed`, not
  `String`. Do not regress a `value`-holding-text vs literal comparison — check
  what it does today and keep it at least as correct. If it currently works via
  some other path, leave that path alone.
- `nothing` compared to a text literal.
- Two non-stringy operands (`3 is equal to 3.5`) must be untouched — they never
  enter this guard.

## Acceptance

1. Every crashing repro above exits 0 with the correct branch taken:
   `"abc" is equal to 3.5` → prints the `Otherwise` branch (`b`); `"pi" is
   equal to pi` (float `pi`) → `Otherwise`; same for `number`/`boolean`, both
   operand orders, both `Equal` and `NotEqual`.
2. `list`/`map` vs a literal no longer takes the dereferencing path (fixes the
   wrong answer and forecloses the suspected OOB read).
3. `buffer`-vs-`text`, `buffer`-vs-`buffer`, `text`-vs-`text` equality all
   still work (the existing `bugs_found_19_*` and buffer-comparison behaviour
   must not regress).
4. Both call sites fixed (`generate_condition` and `generate_expr`), even
   though only the first is reachable by known syntax.
5. Full gate green: `cargo build --release && ./test.sh` (baseline 323 passed
   / 0 failed / 6 skipped).
6. Regression tests in repo style (`tests/bugs_found_20_*.vox` + `.expected`):
   the no-collision control (`"abc" is equal to 3.5`), the collision cases for
   number/float/boolean, both operand orders, `is not equal to`, a list
   operand, and a buffer-vs-text positive case that must stay working.
7. File `docs/BUGS_FOUND.md` **#20** (pre-existing; note #19 made it commonly
   reachable and cross-reference each way), status fixed, naming the tests.
   CHANGELOG `Unreleased`/`Fixed` entry.

## Verification the master will run (for your awareness)

The red team's PoC lives at
`~/.local/state/agent-worker/vox-redteam-304/arena/findings/01-.../poc.sh`.
After your commit the master re-runs it against the new commit and it must flip
from REPRODUCED to NOT REPRODUCED. A green `./test.sh` is necessary but not
sufficient — the PoC flip is the proof.

## Constraints

- No parser/language-surface change unless you choose the compile-error option,
  which is analyzer-level; argue it if so.
- Named paths only in commits; never `--no-gpg-sign`; throwaway programs from /tmp.
- Semver: bug fix, patch-level; extend `Unreleased`.
