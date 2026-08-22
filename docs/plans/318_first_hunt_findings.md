# 318 — Findings from the fuzzer's first hunt

**Status:** staged 2026-08-18, after the vox-fuzz Task 9 session and the
language-lawyer adjudication of its findings. Not started.

The fuzzer's two reported "parser bugs" adjudicated into: two documented
rules working correctly, one memory-safety bug, two diagnostic defects,
and two documentation gaps. This plan is everything actionable, in
severity order. Every item below was verified against the 0.4.2 binary
(most also against released 0.4.0) with minimal repros; the memory bug's
repros were independently reproduced by two reviewers.

## 1. Fix bug #25 — uninitialised conditional-path declarations (BLOCKER class)

BUGS_FOUND.md #25. A declaration inside an `On error`, `While`, or
`for each` body registers in the enclosing scope while its initialising
store sits behind the branch — the zero-execution path reads a raw stack
slot: leaked garbage for `number` (a neighbouring frame's values),
segfault for `text`.

**Fix ruling (per LANGUAGE.md:526's no-block-scoping model):** emit the
type's default at frame setup for every name whose declaration sits on a
conditional path, so the name always holds initializer-or-default as
LANGUAGE.md:429-433 promises. Do NOT switch to `if`-style rejection —
it contradicts :526 and breaks declare-in-loop-read-after programs.

Tests: the two repros from #25 as `tests/bugs_found_25_*.vox` (number
prints 0 not garbage; text prints empty not segfault), plus the
`for each k from 1 to 0` and On-error variants, plus a regression
guard that a TAKEN path still stores the initializer.

## 2. Diagnostic: "Return is only valid inside a function" (defect)

The error carries **no source location** (`src/analyzer/statements.rs`
passes `None`) and no hint, while the parser knows the function was
closed by a body-level `Return` (`ended_via_return`). The sibling case
already has the model: `pending_blank_line_truncation` produces "a blank
line ended `f`'s body early at line N". Add the `Return` analogue and a
location. The trap is real: statements after a body-level `Return` are
silently promoted to top-level entry code and run FIRST.

## 3. Diagnostic: "Unknown variable" caret lands on the declaration (defect)

`find_symbol_location(name, occurrence 0)` textually finds the FIRST
occurrence, so a cross-condition use error points at the declaration and
asserts the name it declares is unknown. Same class as accepted finding
#11. Anchor on the use site, and add the rule to the hint: "declared
only in the `if` branch, so not in scope after it — declare it in every
branch, or before the `if`."

## 4. LANGUAGE.md: `Return` closes the function body (doc gap)

The formal grammar already says it (`func_def` and `member_def` both end
at the `Return` sentence, :4886/:4899) but the prose contradicts it:
:88 claims "any other statement is absorbed" (false since the #5 fix)
and "The termination rule" (:131-150) lists only period and blank line.
Add body-level `Return` to the termination rule, correct :88, and warn
that statements after a body-level `Return` become top-level code.

## 5. LANGUAGE.md: the branch-scoped re-use guarantee overpromises (doc gap)

:2918-2924 says a some-branches name "remains scoped to its condition"
and reusable under it. Implemented only for bare-boolean-identifier
conditions (`simple_guard_key` returns None for comparisons), so
`If x is greater than 1` never records a guard and re-use under the same
comparison is rejected (conservative-safe). Either narrow the prose to
boolean-flag conditions, or extend `simple_guard_key` to comparison
shapes — TheJostler's call; narrowing the prose is the cheap honest fix.

## 6. vox-fuzz side (tracked here, executed in that repo)

- Re-classify `findings/parser-reject/{0,1}`: #0 = not-a-bug (doc gap
  item 4 + diagnostic item 2); #1 = two documented rules stacked, which
  led to #25. Keep the directories — they are the provenance trail.
- The worker's flagged classifier gap stands: `'fuzz gen once'` cannot
  distinguish generator bugs from real compile-time findings without a
  human reading stderr. A `parser-reject` category needs design: when
  the generator BELIEVES its output valid, an ordinary compile error IS
  a finding. v2 material.
- repro.sh should pin VOX_CORE_PATH (carried from the Tasks 5-7 review).

## Process notes

One worker session for items 1-3 (compiler), one docs pass for 4-5
(master or worker), item 6 rides the next vox-fuzz session. Gates as
usual; #25's fix is codegen — the red-team treatment applies before it
ships in 0.4.3.
