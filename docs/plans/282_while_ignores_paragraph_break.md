# Plan 282 — `while` does not honor a paragraph break as a body terminator

**Status:** root-caused, fix not yet implemented. This replaces an earlier
version of this plan that framed three symptoms as three parser bugs; two of
those are reclassified below as malformed source, not compiler defects, per
the language owner's ruling. See "History" at the end for why, and for what
survives from the earlier version's investigation.

## The rule (already documented, this plan does not invent it)

`LANGUAGE.md` (lines 75-77, 99-115) already states the termination rule this
whole investigation converges on:

> Blank lines (paragraph breaks) can be used freely to organize code into
> logical sections. They are optional and have no effect on program
> execution.
>
> **Key Rules:**
> - **Period** (`.`) ends the entire construct, including all its actions
> - **Comma** (`,`) separates multiple actions within the same construct
> - Only **function definitions** can span multiple sentences (using
>   paragraph breaks)
>
> **Sentence ownership (nested constructs):**
> - A nested construct (especially `if ... then`) owns its **own trailing
>   period**.
> - Outer constructs (`while`, `for each`, `repeat`) do **not** steal that
>   inner period.

Stated as two precise, deterministic rules (the owner's own framing, to be
added to `LANGUAGE.md` alongside the existing text as part of this fix — see
"Documentation" below):

1. **A period closes the most recently opened clause** — the innermost one
   currently open (`if`, `on error`, `for`, `while`, `repeat`), and only that
   one.
2. **A paragraph break (blank line) force-closes every open clause at once**,
   including an enclosing function definition. The English-paragraph analogy:
   you never continue a sentence across a paragraph boundary, so a blank line
   ends everything still open, not just the nearest thing.

Both rules are deterministic and require no lookahead, no backtracking, and
no heuristics to implement — a fact that matters for the fix design below and
is why an earlier attempt at this fix (see "History") that used a
speculative-comma-lookahead heuristic instead of implementing these rules
directly was wrong in multiple, independent ways.

## The one real bug: `while` doesn't implement rule 2

`parse_for`'s three body-parsing loops and `parse_repeat`'s body loop already
implement rule 2 correctly — each has a check like
`if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) { break; }`
that unconditionally ends the body on a blank line. `parse_while`
(`src/parser/mod.rs:1825-1872`) does not: its only `ParagraphBreak` handling
is inside the separator-decision `if`/`else if` chain, where it is treated as
skippable noise (`self.advance(); self.skip_noise();`, no `break`) rather
than a terminator, before the loop continues around to parse another
statement.

**Confirmed repro** (`b143840`, fresh build, `cargo build --release -v`
verified as a genuine recompile, not the environment's known fake-fast-build
trap):

```vox
Print "start".
a number called j is 0.
While j is less than 3,
    if j is equal to 1 then, the j is j add 1.

Print "this should never print if the loop is genuinely stuck".
```

`j` never reaches 1 (the only increment is gated behind a condition that's
never true), so this loop should never terminate, and the trailing `Print`
— correctly separated from the loop by a blank line per rule 2 — should
never run. **Actual:** prints `start`, then loops forever re-printing the
final line; confirmed via `timeout 2 ./bin | wc -c` that output keeps
growing, this is not just slow. This is the single most severe finding in
this whole track: it means the *failure mode* of a non-terminating loop is
broken — any accidental infinite loop with a trailing blank line and more
code after it shows this symptom (runaway execution of whatever comes next)
instead of a clean hang, which will misdirect debugging on unrelated code,
indefinitely, whenever it happens.

Without the blank line, the same repro also loops forever printing the
trailing line — but that shape is now understood to be **malformed source**
under rule 1 (see "Reclassified" below), not evidence of a second defect.
The blank-line-containing repro above is the only one required to
demonstrate the real bug, and the fix target is precisely: this repro must
produce a genuine, bounded hang (prints `start`, nothing else, does not
exit, within a `timeout` window) — not a runaway print, and not termination
(the loop genuinely never becomes false; a hang *is* the correct behavior
here).

### Root cause, precisely

`if`/`on error` unconditionally consume their own trailing period once their
clause is fully parsed — `parse_if`'s "Standalone if-sentences own their
trailing period" step (`src/parser/mod.rs:1809-1815`), and
`parse_sentence_body` (`src/parser/mod.rs:4414-4443`, used by `if`'s
`otherwise` branch and by `on error`) does the same
(`src/parser/mod.rs:4436-4440`). This is correct and necessary — it's what
lets `if x then, y.` work as a genuinely standalone top-level statement, and
it's exactly rule 1 applied to `if`/`on error` themselves (each is a clause,
its own period closes it and only it).

Given that, and given rule 1 (a period closes only the innermost open
clause), the correct behavior when an `if`/`on error` is a loop's last body
statement is straightforward: the `if`'s own period closes the `if`; the
enclosing loop is *still open* (nothing has closed it); the loop's
body-parsing should simply **keep going**, parsing whatever comes next as a
further body statement, exactly as it already does for an ordinary
(non-self-terminating) statement — **until** either the loop's own,
un-stolen period arrives (closing the loop, since at that point the loop is
the innermost open thing), or a `ParagraphBreak` arrives (closing the loop
and everything else open, per rule 2, regardless of what's nested inside).
No lookahead is needed to make this decision — it is fully determined by
whichever of those two tokens is seen next.

`parse_for`'s three loops and `parse_repeat` already have the `ParagraphBreak`
half of this correct (pre-existing, not something this plan needs to add).
`parse_while` is missing exactly that one check. That is the entire bug.

## Reclassified: bugs originally reported as 2 and 3 are malformed source

Both were part of the original bug report for this track and are recorded
here for completeness, since the investigation that reclassified them is
itself worth keeping on record — future reports of "similar" behavior should
be checked against this reasoning before being treated as new bugs.

**Originally "bug 2"** — `for each` swallowing a trailing `Print`:

```vox
For each col from 1 to 3,
    a number called v is col modulo 2,
    If v is equal to 1 then, print "hash". Otherwise, print "dot".
Print "END".
```

This has no blank line separating the loop from `Print "END".`, and under
rule 1 the `if/otherwise`'s own period doesn't close the `for each` (nothing
does, until something explicitly does). **Confirmed on `b143840`:** adding
the blank line that rule 2 requires —

```vox
For each col from 1 to 3,
    a number called v is col modulo 2,
    If v is equal to 1 then, print "hash". Otherwise, print "dot".

Print "END".
```

— already prints `hash, dot, hash, END` correctly, with no parser change.
The original report's source was missing the paragraph break; this was
never a compiler defect.

**Originally "bug 3"** — a `Return` after a `for each` inside a function
silently burying the rest of the program:

```vox
To f.
    For each n from 1 to 2,
        if n is equal to 1 then, print n.
    Return a number, 99.
f.
print "after".
```

**Confirmed on `b143840`:** without a blank line, the `for each`'s body never
gets its own un-stolen period (the `if` inside it keeps consuming periods,
and nothing else closes the `for each`), so `Return` parses as *part of the
loop's own body* — buried, never seen by the function-body parser's own
"a top-level `Return` ends the function" handling
(`src/parser/mod.rs:4270-4287, 4330-4339`, unrelated to this plan, already
correct on its own terms). Net effect: the real top-level call to `f` and
everything after it become unreachable dead code inside `f`'s own body —
clean compile, exit 0, zero bytes of output.

Adding the blank line that would close the `for each` **also closes the
enclosing function definition**, per rule 2 (a paragraph break closes
*everything* open, not selectively) — confirmed on `b143840`: this produces
`Return is only valid inside a function`, since `Return` then parses outside
any function at all.

**Ruling (owner, relayed and independently verified by the sub-master before
being accepted): this is malformed source, not a compiler bug.** There is
currently no way to write "close this loop, but stay inside the enclosing
function" — rule 2's "closes everything, uniformly" is the intended
semantics, and the example must be restructured (e.g., compute into a
variable inside the loop, `Return` the variable in a separate sentence after
the loop closes normally under rule 1, without needing a blank line at all —
since the loop's own un-stolen period, reached once the `if` inside it isn't
the very last thing, already closes it correctly). This is not a language
gap needing new syntax; it's an author error in the original report,
structurally identical to originally-bug-2's.

## Corpus impact — measured by ground truth, not modeled

Static text-scanning for this question (grep for blank lines, reason about
what precedes them) was tried repeatedly during this investigation and
produced a different wrong answer every time — 18 sites, then 0, then 2,
none of which matched reality. The problem is that whether a given blank
line is affected depends on the full parse state at that point (is a clause
still open, and if so, was it opened by a comma or by a self-terminating
nested construct) — exactly the thing a text scanner can't reconstruct
reliably. **Do not scan for this. Measure it.**

**The method that actually works, and produced the result below:** build a
pre-fix binary from a clean `origin/main` checkout in a separate directory,
and a post-fix binary with the fix applied (uncommitted is fine — this
needs no commit). Compile **and run** every `.vox` file under `examples/`
and `tests/` with both binaries, diffing stdout+stderr+exit code for each.
The set of files where the two diverge is the complete, exact answer — no
modeling, no false negatives from missing a nesting case, no false
positives from misreading a comment as a keyword.

**Result, from running this against the full 336-file corpus
(`examples/` + `tests/`, every `.vox` file, not just ones matching a
"contains `While`" filter):**

- **335 files: zero divergence**, compile and runtime, between pre-fix and
  post-fix.
- **Two additional flags that are test-harness artifacts, not fix effects**
  — `examples/greet.vox` (differs only in the printed value of
  `arguments's name`, i.e. `argv[0]`, because the pre-fix and post-fix
  binaries used during the scan necessarily have different file paths —
  confirmed the file contains zero occurrences of `while`, so this fix
  cannot touch it at all) and `examples/time.vox` (differs in printed
  timer/clock values, which vary between any two runs regardless of the
  binary — also confirmed zero occurrences of `while`). Both dismissed;
  neither needs any action.
- **`examples/sh.vox`: the only genuinely affected file in the entire
  corpus.** Confirmed working identically to pre-fix before this fix, and
  broken (compile error) by the fix as originally stated. See "The `sh.vox`
  conformance edit" below for the exact fix and the empirical proof it now
  matches pre-fix behavior end-to-end.

**`examples/pi.vox` is *not* affected, despite having five blank lines
inside its `While` body** (lines 30, 34, 38, 41, 44) — every one of them
follows a line ending in a comma, and `parse_while`'s existing
comma-continuation branch already explicitly treats a `ParagraphBreak`
right after a comma as pure visual spacing (`src/parser/mod.rs`, the
"Skip paragraph breaks after comma" loop, present and unchanged both
before and after this fix). Confirmed by diffing actual output: identical,
`3.141592653589787`, both before and after.

**`tests/lib/cli.vox`** has two `While` loops but no blank line inside
either one's body at all — confirmed by direct inspection, not build — so
there is no `ParagraphBreak` token anywhere for this fix to act on.

### The `sh.vox` conformance edit

Three blank lines inside `sh.vox`'s outer `While true,` loop turned out to
be affected once the fix was applied and actually tested — not two, as
first suspected; a third was found only by re-testing after fixing the
first two, since the file didn't compile far enough to reach it before
that. All three share the same shape: a blank line immediately after a
statement that self-terminated its own period (an `if/then`, or — for one
of the three — a nested `While` loop closing itself), while the outer loop
was still open per rule 1, with more of the outer loop's own body intended
to follow:

- After `increment i.` (closing the nested `While i is less than or equal
  to n,` loop) — a blank line, then `a number called pid is 0,` continuing
  the outer loop.
- After `if have_cmd is 1 then, set pid to fork the process.` — a blank
  line, then the fork/exec handling continuing the outer loop.
- After `exit 127.` (closing the nested `if pid is 0 and have_cmd is 1
  then, ...` block) — a blank line, then the parent's wait/reap handling
  continuing the outer loop.

**Fix: remove all three blank lines** (no other change to the file — same
resolution the owner specified: relocate or remove, not restructure the
logic). **Verified empirically, not assumed:** compiled the conformed file
with the post-fix binary (clean, exit 0) and diffed its actual end-to-end
behavior against the pre-fix binary running the *original* (unconformed)
source, across three separate interactive scenarios (a real command, a
nonexistent command, and multiple sequential commands) piped via stdin —
byte-for-byte identical output in every case.

## Fix — implemented and verified, 2 lines

In `src/parser/mod.rs`, `parse_while`'s separator-decision chain, the
`ParagraphBreak` arm changes from skipping the token as noise to
unconditionally ending the body:

```rust
} else if *self.current() == Token::ParagraphBreak {
    self.advance();       // before
    self.skip_noise();
}
```
becomes
```rust
} else if *self.current() == Token::ParagraphBreak {
    break;                // after
}
```

That is the entire fix. No other change to `parse_while`'s structure —
rule 1 is already correctly implemented by `if`/`on error` owning their own
periods and by `while`'s existing fallthrough (keep parsing the next
statement when the current one didn't leave a separator behind); only
rule 2 was missing, and this is it. No speculative parsing, lookahead, or
backtracking anywhere — the decision is fully determined by the current
token, matching `parse_for`'s three loops and `parse_repeat`, which already
have the equivalent check.

**Uniform across trigger type — verified, not assumed.** The fix does not
distinguish what kind of statement preceded the blank line; it applies
identically whether the last body statement was `if/then`, `if/then/otherwise`,
`on error`, or a nested loop. Confirmed by direct test: `on error` as a
`while`'s last body statement, followed by a blank line and then an
unrelated top-level statement — the blank line correctly closes the `while`,
the trailing statement correctly stays outside it, same as the `if/then`
case.

## Conformance sweep — complete

Per the owner's explicit instruction: audit `examples/` and `tests/` for
source that only works because a construct is being left open when rule 1/2
say it should have closed. Done via the ground-truth corpus method above
(build both binaries, run all 336 files, diff) rather than static auditing,
which is strictly more thorough — it catches this class of issue regardless
of what shape it takes, not just the two shapes anticipated in advance.
**Result: `examples/sh.vox` is the only file needing a conformance edit**,
already made (see above). This was a **conformance pass, not a
rewrite-everything pass** — no other file in the corpus was touched, none
needed to be.

## Documentation

Add the two-rule statement (see "The rule" above, the owner's own framing)
to `LANGUAGE.md`, next to the existing "Paragraph Breaks" and "Sentence
Consumption" sections — the existing text isn't wrong, it's incomplete (it
doesn't state rule 2's "closes everything, including a function" scope
precisely, and doesn't warn about the corpus-impact interaction with
readability blank lines). **`p3`'s track owns a different `LANGUAGE.md`
paragraph (the dynamic-buffer section) and has already committed it** —
merge/rebase cleanly before pushing; do not let this edit collide with
that one.

## Required verification

1. ✅ Bug 1's repro (with the blank line) produces a genuine, bounded hang:
   `start\n` and nothing else, process does not exit and does not print
   the trailing line, within a `timeout` window. Verified.
2. Reclassified bug 2's and bug 3's repros, **rewritten to conform to the
   rule** (blank line added for bug 2; bug 3's example restructured per the
   ruling above), produce correct output. Ship the conforming forms as the
   tests — not the original, malformed inputs asserted as "should fail" or
   similar; they simply aren't part of this fix's test surface. (Bug 2's
   conforming form verified as part of the corpus-impact investigation
   above; bug 3's restructured form still needs a test committed.)
3. ✅ `examples/sh.vox`, after its conformance edit, compiles and produces
   byte-for-byte identical end-to-end behavior to pre-fix across three
   interactive scenarios. Verified — see "The `sh.vox` conformance edit"
   above. (`examples/pi.vox` needs no conformance edit — verified
   unaffected, see "Corpus impact" above.)
4. ✅ **Every `.vox` file under `examples/` and `tests/` compiles and runs
   identically to pre-fix**, except the three explained-and-dismissed cases
   above (`examples/greet.vox`, `examples/time.vox` — harness artifacts,
   not fix effects) and `examples/sh.vox` (conformed, verified separately).
   Full 336-file corpus checked by actual build+run, not by scanning.
   **Still needed:** wire an equivalent check into this project's permanent
   verification loop (`./test.sh` does not compile `examples/` at all,
   which is the gap that let the `sh.vox` regression through undetected
   the first time) — every `.vox` under `examples/` must compile, except
   `examples/mathkit_consumer.vox` (needs a prebuilt `libmathkit.lib`
   first — build that dependency, don't skip the check).
5. ✅ `on error` as a loop's last body statement, followed by a blank line,
   verified to behave identically to the `if/then` case (blank line closes
   the loop, trailing statement stays outside it). Nested-loop-as-trigger
   verified via the `sh.vox` conformance testing above (one of the three
   sites was exactly this shape).
6. `cargo test` fully green — **verified at 218 passed / 0 failed** (with
   the fix + `sh.vox` conformance edit both uncommitted in the worktree;
   re-verify once committed).
7. `./test.sh` on a **force-clean rebuild** (`rm -f target/release/vox`
   before building, or `cargo build --release -v` and confirm an actual
   `Dirty ... recompiling` + `rustc` invocation line — this environment has
   repeatedly shown builds, including after `cargo clean -p vox`, reporting
   instant fake success without recompiling). Baseline on `b143840` was
   211/0/6; `main` has since moved to `a1bcdaa` (p2's PR #119 merged,
   added 7 tests) — **new baseline confirmed: 218 passed / 0 failed / 6
   skipped.** Hold that count, 0 failed.
8. ✅ 0 build warnings — verified (`cargo build --release 2>&1 | grep -i
   warning` empty).

## Hard constraints

- No new crates, no libc.
- Never weaken a test to make it pass.
- No speculative/lookahead parsing anywhere in this fix (see "Fix").
- Conformance-sweep changes are source-only (`.vox` files), never a parser
  accommodation for source that doesn't conform to the rule.
- If implementing the fix surfaces additional gaps beyond `while`/`on
  error`/obvious nested combinations, or the corpus scan turns up more than
  the two files already found, report precisely rather than silently
  expanding or narrowing what gets fixed.

## Release impact — patch, with a release-note mention

With the two originally-reported symptoms reclassified as user error, the
remaining change (`while` fix + the `sh.vox` conformance edit) is a
**bug fix**, not a breaking change — patch, not minor. Confirmed empirically
against the full 336-file corpus (see "Corpus impact" above): exactly one
file needed a conformance edit, and it now behaves identically to pre-fix
after that edit.

**But it should carry an explicit release-note mention, not go silent.**
`examples/sh.vox` is a real, working, non-trivial program (an actual
interactive shell), and the blank lines it needed removed were ordinary,
idiomatic readability formatting — nothing contrived. That one real file in
this corpus needed the edit is itself evidence other users' code plausibly
could too. Recommended note: *a `while` loop whose last body action before
a blank line is itself an `if`/`on error`/nested loop now has that blank
line close the loop, matching `for`/`repeat`'s existing behavior — if your
code relied on the blank line being purely cosmetic there, remove it or
join with a comma.*

## History — what survives from the withdrawn first attempt

An earlier version of this plan and its implementation (commits `7abec9c`,
`1bb9b25`, `6383859`, `2c6d6dc`, `adab8bf`, preserved at
`rescue/p282-wrong-model` for reference, not merged anywhere) treated all
three originally-reported symptoms as compiler bugs and built a
speculative-comma-lookahead heuristic to fix them. That heuristic was wrong:
it approximated the real rule (this document's "The rule" section) instead
of implementing it, and a red team red-teaming the merged fix found six
independent ways it broke — rejecting statements that belonged in a loop
body, accepting ones that didn't, mis-attributing statements across nested
loop boundaries, and an O(N²) parse-time/stack-overflow DoS from the
speculative re-parsing itself. Two things from that investigation remain
valid and are incorporated above: the `if`/`on-error` own-their-own-period
mechanism (unchanged, correctly identified as necessary, not the bug), and
the precise `parse_while`-vs-`parse_for` `ParagraphBreak` asymmetry (the
actual, sole, root cause once the correct rule was identified). Everything
built on top of the wrong "is this independently valid at top level"
heuristic — the speculative lookahead itself, the `tests/040_nested_loops.vox`
rewrite it required, and the conclusion that `examples/sh.vox` needed
fixing — is discarded; both files are correct as originally written and
need no change on that front (though `pi.vox`/`sh.vox` do need the
unrelated blank-line conformance pass described above, found independently
of the withdrawn attempt).
