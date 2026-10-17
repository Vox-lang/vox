# Not compiler defects

Reports that turned out not to be compiler defects (a misreading, a documentation gap, a limitation by design, or a report that did not reproduce), moved here unchanged from [the register](../BUGS_FOUND.md), which indexes every entry.

---

## Compiler bugs found while building a JSON library for Vox

Found while designing, writing, and testing `json.vox` against the v0.3.5 binary
(commit-matched to the `Vox-lang/vox` source tree). Every repro below is minimal,
standalone, and was re-run in isolation to confirm it's not an artifact of the
surrounding code. Each is real Vox behavior, not a misreading of the docs on my
part — where I *thought* I'd found a bug and it turned out to be my own mistake
(mostly comma/period sentence-grouping errors), those are noted at the bottom
instead, since they're worth knowing about even though they aren't compiler bugs.

## Not bugs — my own mistakes, worth knowing about anyway

- **Comma vs. period inside a loop/if is unforgiving.** A period closes only
  the *innermost currently-open* clause. If that's a nested `if`, the outer
  loop stays open and silently absorbs whatever comes next as a repeating
  per-iteration action — including statements clearly meant to run once, after
  the loop. I re-derived this the hard way at least four separate times before
  it stuck.
- **`"1.5e10" as a float` silently truncates to `1.5`.** Not a bug against the
  docs — Vox's own float literal grammar has no exponent form either, so the
  cast is consistent with the language, just short of JSON's number grammar.
  The library applies exponents manually (repeated multiply/divide by 10)
  rather than relying on the cast.
- **Duplicate function definitions in one file compile silently when standalone**,
  and only surface as a NASM `label inconsistently redefined` linker error once
  another file `see`s it. This was my own leftover code from an earlier edit,
  not a language bug — but a friendlier duplicate-definition diagnostic at the
  Vox level would have caught it immediately instead of several edits later.

---

### 5. Omitting the blank line after a function definition is silently required, not "not a requirement"

**Status:** docs corrected + diagnostic added in v0.3.6. The LANGUAGE.md claim that a
trailing blank line after a function is "not a requirement" was false — a blank line
is the only thing that closes a function body (the "termination rule", rule 2). The
docs now say so. The compiler now warns, pointing at the function definition, when a
function is still open at end of file (its body reached EOF with no closing blank
line), instead of silently compiling a do-nothing program with exit 0. The
behaviour is unchanged: the program still absorbs the following statements and
produces no output — this is a diagnostic, not a behaviour fix. (A following `To`/
`Library` does close the previous body; only a non-`To` statement with no blank line
is absorbed.) The warning is suppressed for a `Library <name> version "..."` file and
in `--shared` builds — a library legitimately consists only of function definitions
with no top-level entry, so its last function ending at EOF is correct by
construction. Because the parser cannot tell a function that is simply last in the
file (its body is the whole trailing text) from one that swallowed top-level entry
code, the message states only the structural fact and offers the blank-line fix as
conditional advice — it never asserts statements were absorbed when none were.
Regression test: `tests/bugs_found_05_open_function_warns.rs`.

LANGUAGE.md's exact words: *"Function definitions are typically followed by a
blank line to visually separate them from other code, **but this is a style
convention, not a requirement**."*

```vox
To ping.
  Print "pong".
Print "after".
```

Produces **zero output** — not even "pong". Both statements get silently
absorbed into `ping`'s body, and since `ping` is never called, neither runs.
Exit code 0, no error, no warning. Restore the blank line and `after` prints
correctly (still without `pong`, since `ping` still isn't called — which
confirms the absorption, not some unrelated issue).

---

### 6. A variable named `length` reading `.size`/`.length` fails, blaming `"size"`

**Status:** docs corrected + diagnostic improved in v0.3.6. The error now names the
identifier the user actually typed (`length`, not the internal canonical `size`) and
explains the alias relationship. `length`/`size` were added to the Reserved Aliases
table, and `flag`/`empty` (also rejected as variable names) are now documented as
reserved. The original report's claim that `length` "isn't actually reserved" was
false — `length` IS reserved (an alias for the `size` property keyword) and remains
unusable as a bare variable name; quoting (`'length'`) still works. Regression test:
`tests/compile_fail/bugs_found_06_length_alias_message.vox`.

```vox
a buffer called data is "hello".
a number called length is data's length.
```
```
error: Cannot use 'size' as a variable name - it's a reserved keyword
```

`length` isn't actually reserved — it's used as an ordinary variable name
throughout LANGUAGE.md's own examples. Renaming *only the target variable*
(keeping the same `.length` read) compiles fine. The `length`/`size` alias
canonicalization is leaking into the declared name's own reserved-word check.

---

### 10. A bare `{` or `}` in a string literal throws a confusing, empty-named error

**Status:** docs corrected + diagnostic improved in v0.3.6. A bare/unmatched `{` in a
string literal now reports "Unmatched `{` in a string literal" with the `{{`/`}}`
escape hint, instead of the empty-named "Unknown variable: ". The caret still points
at the offending brace. (A bare `}` is accepted as a literal `}`, so only `{` triggers
this.) The `{{`/`}}` escapes do work — `Print "{{}}".` prints `{}` — contrary to a now-
corrected stale note in `docs/COMPILER-ISSUES.md`. Regression test:
`tests/compile_fail/bugs_found_10_bare_brace.vox`.

```vox
append "{" to destination.
```
```
error: Unknown variable: 
```

The variable name in the error is empty. LANGUAGE.md documents `{{`/`}}` as
the escape for a literal brace, but the error gives no hint that's what's
needed — it reads like an internal parser failure, not a usage mistake.

---

### 12. A nested if/but-if chain with no trailing `Otherwise`, as the last action in an outer branch, silently breaks everything after it

**Status: NOT A COMPILER DEFECT — documentation gap, documented in v0.3.7.**
The reported behaviour is real and reproduces exactly as described, but the
compiler is behaving correctly and consistently throughout. What was missing
was any written account of how to close more than one level of nesting.

**Periods stack: one period closes one open clause, so N periods close N
levels.** Nothing else was ever needed. Three nested `if`s take three periods
to leave all three:

```
a number called n is 0.
If n is equal to 1 then,
    If n is equal to 1 then,
        If n is equal to 1 then, print "innermost"...
print "back at the top".
```

This is also how an author chooses which `if` an `Otherwise` belongs to. An
`Otherwise` continues the innermost `if` still open, so closing that `if`
first hands the `Otherwise` to the enclosing one — a **one character**
difference:

| inner branch ends with | the following `Otherwise` continues |
|---|---|
| `print "inner then".` | the **inner** `if` |
| `print "inner then"..` | the **outer** `if` |

An empty `Otherwise,.` closes an inner chain the same way and reads better
than counting periods.

So the reporter's original program was simply under-punctuated: adding one
period, or giving the inner chain its own `Otherwise`, makes it behave as
intended. No binding rule was wrong and no parse was incorrect.

The genuine problem is that **miscounting fails silently** — too few periods
and following statements are absorbed into a clause you thought you had left;
if one of them is a loop's increment, the loop hangs with no output and no
error. That failure mode is inherent to rule 1 and is the same one already
documented for blank lines under rule 2; it is not specific to `Otherwise`.

Fixed by documentation: see LANGUAGE.md, *Closing more than one level*, and
the regression test `tests/nested_clause_close_levels.vox`.

**Two earlier assessments in this session were wrong** and are recorded here
so the reasoning is not repeated. The first called #12 unreproducible, having
tested only Shape B. The second called it a parser defect — "one OPEN but two
CLOSEs when nested" — and a fix was drafted to make a chain keyword bind to
the innermost *still-open* clause. That rule is incorrect: it makes ordinary
two-level `if`/`Otherwise` nesting a compile error, failing 420 of 896
generated branching programs against 90 for the shipped compiler. Both errors
came from generalising off a handful of hand-built cases instead of the
grammar. `docs/FINDINGS-bug12-confirmed.md` reflects the superseded second
assessment and is retained only as a record of it.

---

This is the deepest and most consequential bug I found — I hit it in two
different shapes, and it's worth stating as a general pattern rather than two
unrelated reports.

**Shape A — silent infinite loop.** A `While` loop's body ends in `if b is
equal to 92 then, [...9-way But-if chain with no Otherwise...]. Otherwise,
[plain-character branch].` The outer `if/Otherwise` is a complete, self-closed
construct — but because the *inner* chain has no `Otherwise` of its own, the
loop's own increment/exit logic that should follow gets silently misattached.
The visible symptom was a hang with no error; giving the inner chain an
explicit `Otherwise` (even a no-op one) fixed it outright:

```vox
While true,
  ...
  if b is equal to 92 then,
    ...
    If escaped is equal to 34 then, ...
    But if escaped is equal to 117 then, ...
    Otherwise,                          (<- adding this fixed the hang)
      'json parse advance' with cursor.
  Otherwise,
    ...
  increment guard.                      (<- never ran without the fix above)
```

**Shape B — a construct whose last action is itself unclosed.** Separately, in
the number parser:

```vox
If exp_count is greater than 0 then,
  ...
  While ii is less than exponent_value,
    ...
    increment ii.
If exp_count is greater than 0 then, Return a value, base_value.   (swallowed
                                                                      into the
                                                                      first If)
```

The first `If`'s last action is a `While` loop; the `While` closes correctly
via its own last plain statement, but that does *not* close the outer `If` —
so the second, unrelated `If` (and everything after it) gets absorbed into the
first one's body, corrupting a completely different variable
(`Unknown variable: final_int`, reported several lines past where the real
problem was).

**The pattern:** if a branch's last action is itself a construct (an if-chain
or a loop) that doesn't end in a plain, non-clause-opening statement, whatever
follows at the outer level risks silent misattachment — sometimes causing a
hang, sometimes a garbled unrelated error. The fix in both cases was the same:
restructure so nothing meaningful follows a "bare" nested construct — either
give the inner chain its own `Otherwise`, or move the trailing logic into a
plain statement, or split into a second function.

---

### 101. An over-precise float compares unequal to itself across the two parse routes — the literal route's rule was undocumented, and the headline oversold the text route

**Status: NOT A COMPILER DEFECT — documentation gap, documented in
0.4.12's successor (LANGUAGE.md commit a0370d2, PR #226).** Found by
vox-fuzz campaign 90000 (seeds 90573 and 90611, `ASSERT VAL-09`), the
first campaign with the dynamic-value leaf band live. Severity:
specification clarity; the compiler is bit-exact on both routes.

A decimal reaches a float by two documented routes: a source literal,
or a text read at runtime. The manual's Type Casting paragraph led with
"A float read from text is the same double as the literal" and only
qualified afterwards that a decimal beyond eighteen significant digits
is read as the nearest float those eighteen digits describe. What no
sentence stated is the literal route's own rule: a source literal of
any length parses to the nearest float of ALL its digits. Beyond
eighteen digits the two routes can therefore land one unit in the last
place apart, so a program that reads `"469046.3893743563967901442"`
from text and compares it against the same digits written as a literal
finds them unequal — correctly, per IEEE 754 and per each route's rule.

Proven during verification: Python/IEEE check shows the compiler's
literal route lands 0.0 ulps from the nearest double of all 25 digits
and its text route 0.0 ulps from the nearest double of the 18-digit
prefix, exactly one ulp apart. The fuzzer's own leaf asserted the two
routes equal and convicted itself (vox-fuzz Defect 14); the manual now
states the literal rule and the one-ulp divergence explicitly and says
to compare an over-precise value within one route.

---

### 107. A buffer, list, or format-string text declared inside a function or loop body is allocated on every entry and released only at program exit

**Status:** Not a compiler defect — a limitation, ruled by TheJostler 2026-08-28
("agreed with your verdict on #107; what we need is a new feature that
allows a program to free a buffer manually"). The compiler keeps every
promise LANGUAGE.md makes (see "What the manual already said"); the missing
piece is a release verb, which is a language feature, not a fix. Recorded
here because the growth is real: 4 KB per call or iteration, linear, never
returned before exit. Verified on vox 0.4.13 (4c85e03) and on the installed
0.4.13. The manual-free feature is tracked as design work (Q7, option C).

```vox
To 'make a piece' with a text called s.
    a buffer called piece is "{s}".

a number called n is 0.
While n is less than 40000, 'make a piece' with "x", increment n.
Print "done {n}".
```

→ prints `done 40000`, exit 0, **maxrss 160 MB** (`/usr/bin/time -f %M`);
20 000 calls → 80 MB. One 4 KB page (the 1024-byte default buffer's mmap)
per call, never returned. The same shape leaks identically for
`a buffer called piece is 64 bytes in size.`, for `a list called items is
[1, 2, 3].`, for `a text called t is "{s}{s}".`, and with the declaration
placed in a top-level `While` body instead of a function. Flat controls
(0.4 MB throughout): a `number` local, a text-literal local, a text
parameter copied to a local — and one program-level buffer reused with
`clear` + `append`, which is the composition the manual already offers.

**What the manual already said.** Dynamic and fixed buffers are
"Automatically freed on program exit" (LANGUAGE.md:3499, 3513); the
safety table says "Forgot to free memory | Memory leak | Auto-freed on
exit" (4089); README's Memory Safety Model says resources are "Explicitly
released when possible" and "Automatically freed or closed on program
exit, even if cleanup is omitted" (README.md:97–98). Every one of those
promises is kept. `clear <buffer>` "reset[s] a buffer to empty while
preserving capacity" (3017). Nothing in the manual says a variable
declared in a function is freed when the function returns — and nothing
says it is not; there is no release verb for memory at all.

**Root cause.** The emitted assembly for the function above is
`FUNC_PROLOGUE 16` → `mov rdi, 1024` / `call _alloc_buffer` (mmap, then
registration in the 64-slot `buf_table` for the exit sweep) →
`_buffer_append_cstr` → `FUNC_EPILOGUE`, with no release anywhere; the
whole program contains zero `_free_buffer` / `HEAP_FREE` sites.
`_free_buffer` exists (`coreasm/x86_64/resource_buffer.asm:222–250`,
munmap + unregister) but codegen reaches it only through the resize path
("New buffer is allocated and old buffer is freed", 3608 — verified flat),
and `HEAP_FREE` is emitted at exactly one statement site
(`src/codegen/statements.rs:1144`). No scope-exit or function-return
release exists in codegen. Side note for the same mechanism:
`MAX_BUFFERS` is 64 (`resource_buffer.asm:13`) and `_register_buffer`
silently skips a 65th live buffer (`.table_full`), so past 64 the exit
sweep cannot free them either.

**How it was found.** The vox-fuzz day-0.4.13 stripes (2026-08-25): the
fuzzer's own `'gen emit'` declared a buffer per emitted fragment, four
campaigns reached 20/15/10 GB and the OOM killer took them at 13:57
(kernel journal); every one of the 269 "compile exceeded 60 s" findings
they saved recompiles in ≤ 2.4 s on an idle machine — artifacts of a
starved box, not compiler bugs. The fuzzer side is vox-fuzz Defect 17.
Evidence programs and the emitted `.asm` were recorded at the time.

**Resolution.** Ruled a limitation; the way forward is (C), a manual release
verb — design work, not a fix. For the record, the shapes considered were:
(A) Document the idiom —
declare heap-backed variables once at program level and reuse them with
`clear`; a declaration inside a function or loop body allocates on every
entry and is released at exit — under Buffers, Lists and Functions. (B)
Free function-local heap variables at return, exempting the returned
value: a text made from a buffer is already an independent copy
(LANGUAGE.md:2040), so a returned text never aliases a freed buffer; a
returned buffer or list escapes and is kept; things holding buffers need
the same escape rule. (C) An explicit release verb. Recommendation: A now (docs only), B for 0.5.

Remedied by the `Free` statement (v0.4.14): see LANGUAGE.md, Releasing a
Buffer.

---

### 121. A removed directory still answers `available`

**Status:** fixed, not a compiler defect: does not reproduce. Regression tests: tests/710_a_removed_directory_correctly_reports_unavailable.vox, tests/711_a_directory_recreated_after_removal_correctly_reports_available.vox, tests/712_a_deleted_file_correctly_reports_unavailable.vox.

After a successful `Remove the directory`, the path answers `available` = true, though the filesystem confirms it is gone. Deterministic, self-contained repro (harness seed 13). Composition-sensitive to reduce, so seed-13's generated program is the canonical repro.

A removed directory, and a deleted file, both correctly report `unavailable`, and a directory recreated after removal correctly reports `available` again, in every case checked directly against the current compiler. The original finding traced to an inverted guard condition in the vox-fuzz generator that produced the seed-13 repro, not to any defect in the compiler's availability check; the finding did not reproduce.
