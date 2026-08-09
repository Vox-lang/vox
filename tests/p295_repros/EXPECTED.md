Expected output for each repro once plan 295 is addressed.

01_but_if_append_discards_rest.vox — fixed, see the plan's finding 1.
    BEFORE
    AFTER
    SECOND AFTER
  (and `line` contains "#", since v is 1)

02_function_tail_escapes.vox and 03_loop_tail_ejected.vox — reclassified,
see "Findings 2 and 3 reclassified" in
docs/plans/295_statement_grouping_defects.md. Both repros are missing a
comma at the exact point required to keep a clause open, per the
already-documented termination rule (LANGUAGE.md, "The termination rule").
The output below is what the *current, unmodified* compiler produces for
each repro exactly as written — not a still-open bug. It is intentionally
different from this file's previous revision, which assumed a rule
(`docs/plans/282_while_ignores_paragraph_break.md`'s discarded
speculative-comma-lookahead heuristic) that was never the language's actual
rule and was never implemented.

02_function_tail_escapes.vox
    ESCAPED
    MAIN
  (`Return.` is not nested inside the `if` — it's the function's own next
  direct statement, per rule 1, and a direct `Return` ends the function
  body early, per the separate function-body convenience at
  src/parser/mod.rs:4319-4337 — so `print "ESCAPED".` is left over as a
  top-level statement. Comma-joining `print "inner",` to `Return.` keeps
  `Return.` nested and reproduces the author's evident intent — `MAIN`
  only — with no parser change; see
  tests/p295_statement_grouping_scope.rs.)

03_loop_tail_ejected.vox
    EXTRA k=1
    EXTRA k=2
    TAIL k=2
  (`print "EXTRA k={k}".`'s period is un-stolen — nothing is nested open at
  that point — so per rule 1 it closes the `while` itself; the second `if`
  and `print "TAIL k={k}".` are left over as top-level statements, run once
  after the loop. A comma after `print "EXTRA k={k}"` keeps the loop's
  sentence open and reproduces the author's evident intent — all four
  actions run every iteration — with no parser change; see
  tests/p295_statement_grouping_scope.rs (the exact print order differs
  from an earlier draft of this file because the conforming rewrite must
  reorder around an unrelated, pre-existing `but if` sugar ambiguity — see
  that test file's comments).
