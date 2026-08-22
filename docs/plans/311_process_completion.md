# 311 — Completing process management

**Status:** APPROVED by Josj (2026-08-17), both features and their exact
surface syntax. Not yet implemented.

**Dependencies:** none. Builds on `fork`/`reap`/`Execute`/`Send signal`
already on main (merges `3436ad3`, `9a14f1a`).

**Why:** vox-fuzz's harness must answer two questions about a child
process — *has it finished yet?* (so a hung child can be timed out and
killed) and *how did it die?* (exit code vs. signal — the entire content
of a fuzzing result). Today Vox can answer neither: `reap` always blocks
(`REAP_CHILD` passes `options = 0`; WNOHANG appears nowhere in the
compiler), and it discards the wait status (NULL status pointer). The
fuzzer's proven workaround shells out to
`/bin/sh -c "timeout N cmd; echo $? > file"` and parses the file. These
two features delete that workaround, making the fuzzer — and any Vox
program supervising children — dependency-free.

Vox already has everything else such a loop needs: `Wait N
milliseconds.`, timers with `'s elapsed in milliseconds`, `fork`,
`Execute`, and `Send signal`.

---

## 1. Non-blocking reap (approved surface)

A `without waiting` suffix on any existing `reap` form:

```
Set r to reap any child process without waiting.
Set r to reap child pid without waiting.
Set r to reap process pid without waiting.
```

- `wait4(2)` with `options = WNOHANG` (1).
- Returns the reaped child's PID if a child has finished; **0** if
  children exist but none has finished yet; negative on error (sets the
  error flag, as the blocking forms do).
- The distinction between "0 — nothing finished yet" and "negative —
  error (e.g. ECHILD, no such child)" is the whole value of the form and
  must be tested explicitly.
- The blocking forms are unchanged; this is strictly additive.
- `waiting` must remain an ordinary identifier everywhere else (the
  `send`/`begin` lookahead precedent — a user function or variable
  called `waiting` must keep working). **Verified 2026-08-17:
  `a number called waiting is 7.` compiles today and must continue to.**
- **Correction to this spec's original text:** `without` is *already* a
  reserved keyword (`Token::Without`, `src/lexer/scan.rs:464`), used by
  `print "x" without newline.`. It cannot be an identifier today and
  the requirement never applied to it. This is convenient rather than
  awkward: because `without` lexes to a distinct token, the suffix
  cannot be confused with a call argument after the pid expression, so
  no lookahead gymnastics are needed. `print ... without newline` must
  keep working.

## 2. Reaped status (approved surface)

```
Set r to reap child pid.
Set st to the reaped status.
```

- `the reaped status` yields the **raw `wait4` status word** as a plain
  number — exactly what the kernel writes, undecoded, the same thing C
  hands you in `int status`.
- It reflects the most recent successful `reap` in the current process.
- Before any successful reap, it is `-1` (a sentinel no real status can
  take), so "never reaped" is distinguishable from "exited 0". The
  sentinel lives in loader-initialized `.data` (`dq -1`), **not** `.bss`
  zeroing in `_start` — `_start` is only emitted for executables
  (`src/codegen/statements.rs:179`), so a `--shared` build would
  otherwise read 0 and silently report "exited cleanly" with no child
  ever reaped.
- A non-blocking reap that returns 0 (nothing finished) leaves the
  previous value untouched — it did not reap anything.
- `reaped` must remain usable as an ordinary variable name;
  `tests/102_fork_reap.vox` does `Set reaped to reap any child process.`
  The parser consumes `the reaped status` only as that exact phrase.

**Decoding lives in Vox, not the compiler** (Josj's decision, matching
his C argument: the kernel hands you an int, `sys/wait.h` unpacks it).
The compiler adds one expression and no knowledge of the encoding.

## 3. `lib/process.vox` — the first standard library file

Ships in the repo as ordinary Vox, no compiler support:

**Corrected 2026-08-17 and verified compiling against the 0.3.7 binary.**
This spec's first draft put `Return a number,` on *both* the signature
line and in the body, which does not compile — the return clause belongs
at the end of the body only. The verified text:

**Names corrected 2026-08-17** to follow `docs/STYLE.md`: the parameter
is `status`, not `st`, and the local is `'terminating signal'`, not
`sig`. This file is Vox's first standard library, so its names set the
precedent every later library follows — `'exit code of' of status` is a
sentence; `'exit code of' of st` is not.

```
(The low seven bits of a wait status hold the signal that killed the
 process, and are zero when it exited on its own. The exit code lives
 in the next eight bits up. This is the kernel's encoding, not ours -
 see wait(2).)

To 'exit code of' with a number called status.
  Return a number, status divide 256 modulo 256.

To 'signal of' with a number called status.
  Return a number, status bit-and 127.

To crashed with a number called status.
  a number called 'terminating signal' is status bit-and 127.
  Return a boolean, 'terminating signal' is not 0.

To 'exited normally' with a number called status.
  a number called 'terminating signal' is status bit-and 127.
  Return a boolean, 'terminating signal' is 0.
```

The names are chosen for the call site, per the style guide:
`If crashed of status then,` and `Print 'exit code of' of status.` both
read as English sentences.

Semantics being encoded (from `<sys/wait.h>`): the low 7 bits hold the
terminating signal (0 when the process exited normally); bits 8–15 hold
the exit code.

**Arithmetic verified** on the current binary against known status
words: `'exit code of' of 1792` → 7, `'signal of' of 139` → 11,
`crashed of 139` → true, `crashed of 1792` → false, `'exited normally'
of 1792` → true, `'exit code of' of 0` → 0. Tests must still exercise
these against *real* children, since that also proves the compiler
delivers the status word correctly.

Placement: `lib/process.vox`, used as `see "./lib/process.vox".` — or
the bare-name system path if the install lays one down; the
implementation plan settles which after checking how `see` resolves
bare names (LANGUAGE.md documents `/usr/share/vox/lib/<name>` being
tried first).

When user-defined things ship (plan 310), this library upgrades to
return a `process` thing with `pid`/`status` fields **with no compiler
change** — that is the point of putting the decoding here.

## 4. What this unlocks (the motivating example)

A complete supervisor loop in pure Vox, no `/bin/sh`, no coreutils:

```
see "./lib/process.vox".

Set 'the child' to fork the process.
If 'the child' is 0 then,
    Execute "./candidate",
    Exit 101.

a timer called clock.
Start the clock.
a boolean called 'the child is still running' is true.
a boolean called 'we killed it' is false.

While 'the child is still running',
    Set finished to reap process 'the child' without waiting,
    If finished is 'the child' then,
        Set 'the child is still running' to false.
    If 'the child is still running' then,
        a number called 'milliseconds waited' is the clock's elapsed in milliseconds,
        If 'milliseconds waited' is greater than 5000 then,
            Send signal 9 to process 'the child',
            Set reaped to reap process 'the child',
            Set 'we killed it' to true,
            Set 'the child is still running' to false..
    If 'the child is still running' then,
        Wait 10 milliseconds.

If 'we killed it' then,
    Print "hang".
If 'we killed it' is false then,
    Set status to the reaped status.
    If crashed of status then,
        Print "died by signal {'signal of' of status}".
    If 'exited normally' of status then,
        Print "exit {'exit code of' of status}".
```

**Punctuation, verified by running the equivalent shape** (2026-08-17,
with blocking `reap` standing in for the non-blocking form): each `If`
inside the loop body closes with **one** period, which per rule 1 closes
only that `If` and leaves the `While` open; the *nested* `If` closes
with **two** (`false..`) to close itself and its parent; and the
**blank line** after the body closes the `While`. Get this wrong and the
trailing statements silently execute inside the loop — the failure mode
LANGUAGE.md warns about, and one this document's first draft contained.

**Naming, verified compiling:** `'the child'` is a quoted name, so it
does not collide with the `child` keyword in `reap child <pid>`; the
`reap process <pid>` form is used throughout for that reason. A bare
boolean is a valid `While` condition, so `While 'the child is still
running',` needs no `is true`.

**Names corrected 2026-08-17** per `docs/STYLE.md`. The original used
`pid`/`r`/`r2`/`done`/`st` and encoded loop state as the numbers 0, 1
and 2 — `If done is 2 then, Print "hang".` requires the reader to
remember what 2 meant. Named booleans say it instead: `While 'the child
is still running',` and `If 'we killed it' then,` read as sentences and
need no comment. Note `While 'the child is still running',` also drops
the redundant `is true` comparison, per the guide's boolean rule.

(The implementation plan must verify this exact program compiles and
behaves correctly — it is the acceptance test for the whole plan, and
mirrors what vox-fuzz's harness will do.)

**Correction 2026-08-17:** the loop's local was originally named `ms`,
which does not compile — `ms` is a reserved alternate spelling of the
keyword `milliseconds`. Renamed to `waited` above.

**Timer granularity — a real constraint on this loop, and a dogfood
finding.** `the clock's elapsed in milliseconds` currently reports whole
seconds × 1000: `TIMER_DURATION_SECONDS` (`coreasm/x86_64/time.asm:503`)
computes `current_sec − start_sec` and never reads the
`TIMER_START_MONO_NSEC` field that `TIMER_START` captures via
`clock_gettime`. Measured: a 1500 ms wait reports 1000; a 30 ms wait
reports 0. The nanosecond precision is captured and discarded.

Consequences for this plan, which does **not** fix that (out of scope,
reported separately):
- The supervisor loop works, because its timeout is multi-second, but
  its timing resolution is one second — a 5000 ms deadline fires
  somewhere in the 5–6 s range.
- **Tests must not assert sub-second timing.** Use deadlines of several
  seconds and assert ordering/outcome, never precise elapsed values, or
  the suite will be flaky.
- The `Wait N milliseconds.` *statement* is unaffected — only reading
  elapsed time is coarse.

## 4b. Style (binding on everything this plan adds)

All Vox written for this plan follows `docs/STYLE.md` (branch
`docs/style-guide`, `6e513b8`), with `examples/cat.vox`, `pi.vox` and
`controller.vox` as the models — where the guide and those files
disagree, the files win. The test is: **read the line aloud; does it
sound like something a person would say?**

This binds hardest on `lib/process.vox`, which is Vox's first standard
library file and therefore sets the naming precedent for every library
that follows. No abbreviations or placeholders as names (`st`, `buf`,
`sig`, `i`, `tmp`) at any length; quoted multi-word names used freely;
booleans named so the condition reads as a claim (`If crashed of status
then,`); function names chosen for how the *call* reads with its
preposition; comments giving the why, not restating the line.

**Approved surface syntax is exempt and unchanged.** `the reaped status`
and `reap ... without waiting` are the project owner's approved wording.
Style applies to names chosen inside the library, tests, and examples —
never to the language surface.

Name review is part of this plan's acceptance gate, alongside the diff
read and the green suite.

## 5. Documentation and tests

- LANGUAGE.md: extend "Process Control: fork and reap" with the
  `without waiting` forms (including the 0-vs-negative distinction) and
  `the reaped status`; state plainly that decoding is done by
  `lib/process.vox`, not the compiler, and show the supervisor loop.
- CHANGELOG: unreleased entries for both features and the new library.
- vox-vscode: `without waiting` and `the reaped status` highlighting;
  keep the drift check green.
- Tests: non-blocking reap returning 0 while a child sleeps, then its
  PID after it exits; non-blocking reap with no children (error flag);
  status after a normal exit with a known code; status after a signal
  death; the `-1` sentinel before any reap; `reaped`, `waiting`, and
  `without` all still usable as ordinary identifiers; each
  `lib/process.vox` function against real children; the section-4
  supervisor loop end to end for both the clean-exit and hang paths.
