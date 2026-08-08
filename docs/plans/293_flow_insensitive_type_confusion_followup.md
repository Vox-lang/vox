# Plan 293 — flow-insensitive type tracking enables a segfault (pre-existing; follow-up, not fixed here)

**Status:** discovered 2026-08-08 by the red team spawned on the plan
290/291 track. **Confirmed pre-existing on unmodified `main` (`b143840`) —
not introduced by plans 290/291/292 and not fixed by this track.** Recorded
here so the finding isn't lost; scoping and fixing it is a decision for
whoever picks up this plan next, not something the append/but-if track
should absorb.

## Problem

```vox
a number called n is 5.
a number called g is 0.
If g is equal to 1,
  n is "abc".
Print "{n}".
```

Compiles with no error. At runtime: **segfault (SIGSEGV, exit 139)**.

`n` is declared and used as a `number` throughout, and the branch that
reassigns it to text (`n is "abc".`) is never taken (`g` is `0`). Yet the
program crashes.

## Root cause — confirmed by reading the code and reproducing on unmodified `main`

The analyzer's scalar type tracking (`self.scalar_types`, a
`HashMap<String, Type>`, `src/analyzer/mod.rs:587`) is **flow-insensitive**:
an assignment anywhere in a function permanently updates the tracked type
for that variable's name for the rest of the analysis, regardless of
whether that assignment's branch is ever actually reached at runtime. So
`n is "abc".` inside the untaken `If` branch above permanently relabels
`n`'s tracked type as `Type::String` for everything analyzed afterward —
even though at runtime, since the branch never executes, `n` still holds
the raw integer `5`.

`Print "{n}"` resolves `{n}` via `resolve_format_variable`
(`src/codegen/mod.rs:664-725`), which reports the variable's type from
`self.variable_types` (codegen's own copy of the analyzer's tracked type —
same flow-insensitivity, inherited from the same source). Since `n` is now
tracked as `VarType::String`, the format-string codegen
(`emit_append_runtime_value_to_buffer_ptr` / the `Print`-to-stdout
equivalent) treats the raw integer `5` sitting in `n`'s slot as if it were
a pointer to a C-string, and dereferences it — reading from address `5`,
which is unmapped, hence the segfault.

**This reproduces identically on unmodified `main` (`b143840`), with no
code from plans 290, 291, or 292 involved at all** — confirmed by the
sub-master: extracted `b143840`, built clean, compiled and ran the exact
program above, got the same SIGSEGV. This is a pre-existing bug in the
analyzer's type-tracking architecture, not something plans 290-292 created.

**How this track found it anyway:** the red team spawned on plan 290/291
(brief: probe buffer-bounds behavior around `Append` accepting a `text`
variable source) constructed a variant using the exact same mechanism to
attack `Append`:

```vox
a buffer called b is 64 bytes in size.
a number called n is 5.
a number called g is 0.
If g is equal to 1,
  n is "abc".
Append n to b.
Print "reached".
```

This also segfaults post-plan-290 (confirmed by the sub-master, same
mechanism: `named_value_type(n)` now reports `Type::String` due to the same
flow-insensitivity, so plan 290's widened `ListAppend` check accepts `n` as
a text source; codegen then hands the raw integer `5` to
`_buffer_append_cstr` as if it were a `char*`). **Before plan 290, this
specific program was rejected at compile time** ("Buffer append requires a
buffer source: n") — because the old check rejected every non-buffer
`Identifier` source unconditionally, regardless of tracked type. So plan
290 does make this *specific syntactic path* (`Append <mistyped var> to
<buffer>`) newly reachable — but the underlying vulnerability (trusting
flow-insensitive type tracking for a runtime-safety-relevant codegen
decision) already existed and was already exploitable via `Print`/format-
string interpolation, unrelated to anything in this track.

## Why this is not being fixed as part of plans 290-292

- The blast radius is much larger than buffer append: `scalar_types` /
  `variable_types` flow-insensitivity is a general property of the
  analyzer, used for arithmetic operand checks, map-key checks, and any
  other place that asks "what type does this variable currently hold."
  A real fix means flow-sensitive type narrowing (track type per-branch and
  re-widen/error at merge points, or track "possible types" as a set rather
  than a single value) — a proper type-checker change, not a local patch.
- It already reproduces on `main` with zero involvement from this track's
  changes. Folding it into the append/but-if track would mix an unrelated,
  much bigger problem into a PR that's supposed to be three scoped MEDIUM
  parser gaps.
- Plan 292 (the register-clobber fix, same red-team pass) is narrow,
  clearly caused by this track's own change, and appropriately fixed here.
  This one is neither.

## What plans 290-292 do and don't need to do about it

**In scope for plan 290 (done):** nothing extra — plan 290's own widening
(`is_buffer_variable(source) || named_value_type(source) == Some(Type::String)`)
is not itself wrong; it correctly answers "does the analyzer currently
*believe* this variable is text." The bug is that "currently believes" can
be wrong in a way that matters for memory safety, which is a pre-existing
property of `named_value_type`/`scalar_types`, not something plan 290
introduced into that helper.

**Not in scope for this track:** actually fixing the flow-insensitivity.

**Recommended for whoever picks this up next:**
1. Decide severity/priority — this is a **real, reproducible segfault from
   syntactically valid, non-adversarial-looking Vox source** (no unsafe
   constructs, no attacker-controlled external input required — a plain
   `If` with a dead branch is enough). That argues for higher priority than
   a typical parser-gap MEDIUM.
2. Scope the actual fix: likely either (a) make `scalar_types` track a
   per-branch snapshot and merge conservatively (widen to "unknown"/reject
   rather than silently pick the last-seen assignment) at control-flow join
   points, or (b) something narrower specific to reachability-provable-dead
   branches — (a) is almost certainly the more correct and durable fix.
3. Both repros above are ready to use as regression tests once a fix
   exists — the `Print`-based one (pre-existing, minimal) and the
   `Append`-based one (post plan-290, exercises the same root cause through
   a different sink).

## Repro files

Both confirmed by the sub-master against a genuinely fresh, force-clean
rebuild — not just read from a report:

- `Print`-based (reproduces on unmodified `main`): see "Problem" section
  above.
- `Append`-based (reproduces on `main` + plan 290, rejected pre-plan-290):
  see the red-team variant above.
