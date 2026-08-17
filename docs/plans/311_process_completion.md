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
- `without` / `waiting` must remain ordinary identifiers everywhere else
  (the `send`/`begin` lookahead precedent — a user function called
  `waiting` must keep working).

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

```
(Decode a raw wait status, as sys/wait.h does with macros.)

To 'exit code of' with a number called st. Return a number,
    Return a number, st divide 256 modulo 256.

To 'signal of' with a number called st. Return a number,
    Return a number, st bit-and 127.

To crashed with a number called st. Return a boolean,
    a number called sig is st bit-and 127.
    Return a boolean, sig is not 0.

To 'exited normally' with a number called st. Return a boolean,
    a number called sig is st bit-and 127.
    Return a boolean, sig is 0.
```

Semantics being encoded (from `<sys/wait.h>`): the low 7 bits hold the
terminating signal (0 when the process exited normally); bits 8–15 hold
the exit code. Verify each function against real children in tests
rather than trusting these expressions.

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

Set pid to fork the process.
If pid is 0 then,
    Execute "./candidate",
    Exit 101.

a timer called clock.
Start the clock.
Set done to 0.
While done is 0,
    Set r to reap child pid without waiting,
    If r is pid then,
        Set done to 1.
    If done is 0 then,
        a number called ms is the clock's elapsed in milliseconds,
        If ms is greater than 5000 then,
            Send signal 9 to process pid,
            Set r2 to reap child pid,
            Set done to 2.
    If done is 0 then,
        Wait 10 milliseconds.

If done is 2 then,
    Print "hang".
If done is 1 then,
    Set st to the reaped status.
    If crashed of st then,
        Print "died by signal {'signal of' of st}".
    If 'exited normally' of st then,
        Print "exit {'exit code of' of st}".
```

(The implementation plan must verify this exact program compiles and
behaves correctly — it is the acceptance test for the whole plan, and
mirrors what vox-fuzz's harness will do.)

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
