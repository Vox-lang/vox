# Compiler bugs found while building a JSON library for Vox

Found while designing, writing, and testing `json.vox` against the v0.3.5 binary
(commit-matched to the `Vox-lang/vox` source tree). Every repro below is minimal,
standalone, and was re-run in isolation to confirm it's not an artifact of the
surrounding code. Each is real Vox behavior, not a misreading of the docs on my
part — where I *thought* I'd found a bug and it turned out to be my own mistake
(mostly comma/period sentence-grouping errors), those are noted at the bottom
instead, since they're worth knowing about even though they aren't compiler bugs.

---

### 1. A float routed through `{}` interpolation into `text`/`buffer` prints the raw bit pattern

**Status:** fixed in v0.3.6. Regression test: `tests/bugs_found_01_float_interp_text.vox`.

```vox
a float called y is 3.5.
Print "{y}".              (correct: 3.5)

a text called t is "{y}".
Print t.                   (wrong: 4615063718147915776)

a buffer called b is "{y}".
Print b.                   (also wrong: same bit pattern)
```

Direct `Print y.` and the cast `y as text` both give the correct `3.5`. Only
interpolation into a `text`/`buffer` destination is affected. Doesn't affect
`number` or `boolean` interpolated the same way. This is distinct from the bug
the 0.3.5 changelog says it fixed (`Print` on an inlined float-returning call) —
that one's genuinely fixed; this is a different code path with the same symptom.

**Workaround:** use `as text` on a statically-typed `float` instead of `{}`.

---

### 2. `value` → `float`: reassignment is broken, declare-with-initializer isn't

**Status:** fixed in v0.3.6. Regression test: `tests/bugs_found_02_value_float_reassign.vox`.

```vox
To identity with a value called v. Return a value, v.
a value called vf is identity of 3.5.

a float called y is 0.0.
the y is vf.
Print y.                          (wrong: 4615063718147915776)

a float called y2 is vf.
Print y2.                         (correct: 3.5)
```

LANGUAGE.md states `x is <v>.`, `the x is <v>.`, and `Set x to <v>.` are "checked
the same way." They aren't, at least for extracting a float out of a `value` —
only the declare-with-initializer form works.

**Workaround:** always extract via a fresh declaration, never reassign an
existing float from a `value`. I used this as a two-line helper throughout the
library (declare a fresh `float` from the `value`, then `as text` cast that).

---

### 3. `but if` is restricted to `print` actions — silently, undocumented

**Status:** fixed in v0.3.6. `but if` is now a generic conditional branch:
both the base action and the branch action may be any valid statement, in the
plain form and in loop expansion. Regression tests:
`tests/butif_generic_append_loop.vox`, `tests/butif_generic_terse_append.vox`,
`tests/butif_generic_chain_otherwise.vox`,
`tests/butif_generic_nonprint_branch.vox`,
`tests/butif_generic_nonprint_base.vox`,
`tests/compile_fail/086_butif_append_retarget.vox`.

```vox
a list called source is [1, 2, 3].
a list called dest is [].
append each n from source to dest,
    but if n modulo 2 is equal to 0 append 0 to dest.
```
```
error: 'but if' conditional branching only works with print statements
```

LANGUAGE.md frames loop expansion as working "with any action" and never states
this restriction in either of the two `but if` sections. The error message
itself is clear once you hit it — it's just not documented anywhere you'd see
it in advance.

---

### 4. A top-level `number` global doesn't retain mutations made inside a function

**Status:** fixed in v0.3.6 for every top-level type, `value` included.
Regression tests: `tests/bugs_found_04_number_global_in_function.vox`,
`tests/bugs_found_04_aliased_globals.vox`, `tests/bugs_found_04_local_shadow.vox`,
`tests/bugs_found_04_non_number_globals.vox`,
`tests/bugs_found_04_value_global_numeric.vox`,
`tests/bugs_found_04_value_global_text_tag.vox`,
`tests/bugs_found_04_value_global_float_tag.vox`,
`tests/bugs_found_04_value_global_predicate.vox`,
`tests/bugs_found_04_value_global_shadow.vox`.

The effect was worse than reported here: the write did not merely fail to
persist, it landed in an uninitialised per-call stack slot that could **alias
another function's local**. Three `bump` calls interleaved with an unrelated
function that set a local to `999` produced `1, 2, 999, 1000` — the counter
read the other function's local and incremented it. Top-level variables now
share one storage location with every function, so this cannot happen.

```vox
a number called g is 0.
To bump. Set g to g add 1.

bump.
bump.
bump.
print g.                          (was: 0; now: 3)
```

A top-level **`value`** variable initially stayed carved out of this fix: its
payload and runtime type tag are a pair, and the original fix only gave the
payload shared storage. A `value` global's tag now gets the same treatment —
a second BSS mirror alongside the payload's, updated together on every read
and write, in top level code and inside every function — so a `value` global
persists mutations AND keeps carrying its own runtime type correctly:

```vox
a value called vg is 0.
To bumpv. Set vg to "hello".

bumpv.
print vg.                          (was: a raw pointer; now: hello)
```

A `value` declared *inside* a function still shadows a same-named global
rather than mutating it, exactly like the other types.

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

### 7. `map's "{loopvar}"` fails when the loop variable comes from `.keys`

**Status:** fixed in v0.3.6. Regression test: `tests/bugs_found_07_keys_dynamic_lookup.vox`.

```vox
a map called m is {"a": 1, "b": "two"}.
a list called ks is m's keys.
For each k in ks,
  a value called v is m's "{k}",
  print "key={k} value={v}".
```

Prints `key=a value=0` / `key=b value=0` — always the not-found sentinel (`0`),
even though `k` prints correctly as text and the key genuinely exists. The
*identical* code with `ks` as a hand-written list literal (`["a", "b"]`) instead
of `m's keys` works correctly. `.keys` itself enumerates correctly (confirmed
separately) — it's specifically using one of its elements as an interpolated
key that fails.

**Workaround:** never dynamic-key-lookup using a `.keys`-derived loop variable.
Get `.keys` and `.values` as two parallel lists and walk them by index instead
— that's what the library's map serializer does, and it sidesteps this entirely.

---

### 8. Extracting a `list` from a `value` corrupts it; `float` and `map` extraction (the same way) don't

**Status:** fixed in v0.3.6. Regression test: `tests/bugs_found_08_value_list_extract.vox`.

```vox
To inspect with a value called item.
  print "direct: {item}".               (correct: [10, 20, 30])
  a list called xs is item.
  print "extracted: {xs}".               (wrong: a raw pointer-looking number)
  print "extracted length: {xs's length}".  (wrong: -1)

inspect with [10, 20, 30].
```

Declare-with-initializer extraction (bug #2's workaround pattern) works for
`float` and, separately confirmed, for `map` — but not for `list`, where even
a bare `print` of the extracted variable is wrong.

**Workaround:** never extract a `list` from a `value`. `For each x in item,`
iterates directly over a value known (via `is a list`) to hold a list, with
no extraction step, and this works correctly. The library's generic serializer
uses this for its list-value path.

---

### 9. `buffer as text` cast silently returns an empty string

**Status:** fixed in v0.3.6. Regression test: `tests/bugs_found_09_buffer_as_text_cast.vox`.

```vox
a buffer called b is "hello".
a text called t1 is b as text.
print "[{t1}]".              (wrong: [])

a text called t2 is "{b}".
print "[{t2}]".              (correct: [hello])
```

**Workaround:** use `"{buffer_var}"` interpolation, never `as text`, to read a
buffer's contents into a text value.

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

### 11. That error's reported line can be badly misattributed

**Status:** fixed in v0.3.6 — the `but if`/period shape, together with #14,
its underlying cause. `tests/butif_chain_period_shape_b_plain.vox` covers the
exact misattribution repro below and now compiles and runs cleanly (`did
proc` / `did sysfs` / `done`, no spurious `Unknown variable: f` error). The
original report below could not be reproduced from its own description, but
the same *class* of failure (a real mistake surfacing as an error anchored to
an unrelated, valid line) reproduced reliably from a mis-terminated `but if`
chain before the fix.

Building the library, a genuine unmatched-brace bug in my map serializer (see
#10) was reported by the compiler as `Unknown variable: ` at a **completely
different, unrelated line** — one that contained a valid, complete `{b:02x}`
format expression. I confirmed this isn't a coincidence: fixing the real bug
(the actual bare brace, many lines away) made the phantom error at the
unrelated line disappear entirely. I'd guess this is the same class of issue
as the project's own `073_type_lock_caret_points_at_write_site`-style tests,
just a different trigger.

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

### 13. Chaining `element N of X's property` in one expression corrupts the result — splitting it into two statements doesn't

**Status:** fixed in v0.3.6. Regression test: `tests/bugs_found_13_chained_element_property.vox`.

```vox
a map called m is {"status": "ok", "count": 3}.

a value called chained is element 1 of m's values.
print "chained: {chained}".              (wrong: 4214989)

a list called vs is m's values.
a value called separate is element 1 of vs.
print "separate: {separate}".            (correct: ok)
```

Same map, same program, same read — the only difference is whether the
`.values` read has its own statement or is inlined into the `element N of`
expression. I initially chased this as a "map extracted from a value" bug (an
early version of the JSON library's demo genuinely produced a garbage pointer
this way) before isolating that the extraction was irrelevant — the chaining
itself is the trigger, on a perfectly ordinary, directly-declared map.

**Workaround:** never chain `element N of X's property` — always read the
property into its own variable first. I checked the library's own source for
this pattern afterward; it doesn't appear anywhere, which is presumably why
the round-trip tests all passed cleanly.

---

### 14. A `but if` chain is closed by a period that belongs to a nested clause

**Status:** fixed in v0.3.6. Regression tests:
`tests/butif_chain_period_shape_a_on_error.vox` (per-branch `On error`,
three branches), `tests/butif_chain_period_shape_b_plain.vox`
(period-separated plain branches, no `On error`), and
`tests/butif_chain_period_still_terminates.vox` (proves a period that
genuinely ends the chain still ends it — the statement after runs once,
after the loop, not once per branch/iteration).

Found in v0.3.6 while checking whether `but if` branches can carry real
side-effecting actions. A period that should close only the *innermost* open
clause instead closes the whole `but if` chain, so every following `but if`
is lost.

Per LANGUAGE.md's termination rule 1, *"a period closes the most recently
opened clause — the innermost one currently open, and only that one."* The
nesting should be:

```
<but if> <on error> <action> </on error> </but if>   (correct)
<but if> <on error> <action> </but if>               (what happens)
```

The period closing the `on error` sentence is consumed by the enclosing
`but if` instead, terminating the chain.

**Shape A — silent, with `On error`.** Both opens fail, so both handlers
should fire:

```vox
a list called fs is ["proc", "sysfs", "other"].
For each f in fs,
  Continue,
    but if f is equal to "proc" Open a file for reading called fa at "/nonexistent_dir/p", On error print "FAILED proc".
    but if f is equal to "sysfs" Open a file for reading called fb at "/nonexistent_dir/s", On error print "FAILED sysfs".

Print "done".
```
Prints `FAILED proc` / `done`. The second branch never runs — no error, no
warning, exit 0.

**Shape B — misattributed error, without `On error`.** The same structure
with plain prints:

```vox
a list called fs is ["proc", "sysfs", "other"].
For each f in fs,
  Continue,
    but if f is equal to "proc" print "did proc".
    but if f is equal to "sysfs" print "did sysfs".
```
```
error: Unknown variable: f
 --> line 1:15   (a valid list declaration, nothing to do with the mistake)
```
This is a minimal reproduction of the misattribution described in #11.

**Mechanism.** `parse_conditional_suffix` in `src/parser/mod.rs` continues the
chain only on `But`/`Comma`/`And`:

```rust
if !matches!(self.current(), Token::But | Token::Comma | Token::And) {
    break;
}
```
A `Period` falls through to `break`, ending the chain rather than closing the
one clause it belongs to.

**Why it matters:** this is the natural way to write a dispatch loop that
performs real work per branch — mount a filesystem, open a device, call a
setup function — with each branch's own failure handling. Both failure modes
are silent or misdirected, which is the worst combination for init-style code
where a failed mount must not sail past its `exit 1`.

**Workaround:** wrap each action and its `On error` in a function and call
that from the branch, which keeps the handler inside its own sentence scope:

```vox
To 'mount proc'.
  Mount "proc" at "/proc" with type "proc".
  On error print "FAILED proc".

For each f in fs,
  Continue,
    but if f is equal to "proc" 'mount proc',
    but if f is equal to "sysfs" 'mount sysfs'.
```
Confirmed working. Note the branches are comma-separated — a `but if` chain
currently only holds together with commas.

---

### 15. Reassigning a `value` that holds a `float` to an integer leaves the tag as `float`

**Status:** fixed in v0.3.6. Regression tests:
`tests/bugs_found_15_value_float_to_int.vox`,
`tests/bugs_found_15_value_int_to_float.vox`,
`tests/bugs_found_15_value_text_to_int.vox`,
`tests/bugs_found_15_value_spellings.vox` (all three assignment spellings),
`tests/bugs_found_15_value_global_float_to_int.vox`, and
`tests/bugs_found_15_value_func_global_float_to_int.vox` (a function
reassigning a top-level `value` global).

The title above describes the symptom as first observed; the actual cause was
the other way round. The **runtime tag was written correctly** — what went
stale was the *static* type. Declaring `a value called v is 3.5.` let the
initializer's type inference demote the variable from `Mixed`
(runtime-tagged) to a concrete `Float`, so later reads dispatched on that
stale static type instead of the tag: `Print v` emitted `PRINT_FLOAT` over an
integer payload, and `If v is a number` folded statically to false. A declared
`value` now keeps `Mixed` through its initializer.

Found in v0.3.6 while verifying the in-place retype construct. Confirmed
**pre-existing** — reproduced identically on a v0.3.6 binary built before that
work, so it is not a regression from it.

```vox
a value called v is 3.5.
Set v to 1.
Print v.                                            (prints 0.0, want 1)
If v is a number then, print "num". Otherwise, print "NOT num".   (says NOT num)
If v is a float then, print "float". Otherwise, print "NOT float". (says float)
```

The payload is updated to the integer `1` but the runtime type tag is left
saying `float`, so `Print` dispatches on the stale tag and reinterprets the
integer's bits as a double — `1` as an IEEE-754 bit pattern is a denormal,
which formats as `0.0`. The predicates confirm the tag never moved.

This is a **tag/payload desync**, the failure class the `value` type exists to
prevent, and it is reachable from ordinary code with no casts involved.

**Only this direction is affected.** Verified working:

```vox
a value called v is 1.      Set v to 3.5.   Print v.   (3.5 — correct)
a value called v is "text". Set v to 7.     Print v.   (7   — correct)
```

So `float` → integer is the one transition that fails to write the new tag.
Note the existing `tests/bugs_found_02_value_float_reassign.*` regression
passes — it covers extracting a float *out of* a `value`, not overwriting a
float-holding `value` with an integer, so this case was never under test.

**Workaround:** declare a fresh `value` rather than overwriting one that
currently holds a float, or retype it explicitly first (`v is a number.`)
before assigning.

**Status:** fixed in v0.3.6. The tag write was correct all along; the real
defect was that declaring `a value called v is 3.5.` let the initializer
type-inference clobber the `value`'s `Mixed` static type down to `Float`, so
every later read dispatched on the stale static type instead of the runtime
tag (Print emitted `PRINT_FLOAT`, reinterpreting the integer `1` as the
denormal `0.0`; the `is a number` predicate folded statically to false). The
`VarDecl` arm now keeps a declared `value` at `Mixed` through its initializer,
mirroring the guard the bare-assignment arm already had. Regression tests:
`tests/bugs_found_15_value_float_to_int.vox`,
`tests/bugs_found_15_value_int_to_float.vox`,
`tests/bugs_found_15_value_text_to_int.vox`,
`tests/bugs_found_15_value_global_float_to_int.vox`,
`tests/bugs_found_15_value_func_global_float_to_int.vox`,
`tests/bugs_found_15_value_spellings.vox`.

---

### 16. A declared-but-uninitialised `text` variable segfaults on first read

**Status:** fixed in v0.3.6. Regression tests:
`tests/bugs_found_16_text_default_declare.vox`,
`tests/bugs_found_16_text_default_create.vox` (both declaration spellings),
`tests/bugs_found_16_text_default_interpolation.vox`, and
`tests/bugs_found_16_text_default_reassign.vox`.

```vox
a text called ex.
Print ex.
Print "survived".
```
```
Segmentation fault (exit 139)
```

Nothing is printed, not even `survived` — the process dies on the first read.
`Create a text called ex.` does the same.

The no-initializer default-value codegen has dedicated arms for `buffer`,
`list`, `map`, `float`, and `value`; every other declared type fell through to
a generic `xor rax, rax` arm that stores a plain zero. For `text`, that zero
is read back as a pointer, so printing, interpolating, or comparing the
variable dereferences null. Confirmed **pre-existing** — reproduced
identically on a clean build of the v0.3.6 release commit, so it is not a
regression from other work landing alongside it.

`text` now gets its own arm: a real pointer to a shared, immutable empty
string in `.rodata`, created once and reused by every uninitialised `text` in
the program. An uninitialised `text` now reads as `""`: it prints an empty
line, interpolates as empty, compares equal to `""`, and can be reassigned a
real value afterward exactly like any other `text` variable.

**Neighbouring types checked, not just read.** The same fallback arm is also
reachable for `number` and `boolean` — both were tested directly and are
genuinely fine with a zero default (`0` and `false` respectively are valid
values, not sentinels for "absent"). `file` and `time` require an initializer
and are already rejected at analysis time before reaching codegen
(`tests/compile_fail/declare_create_file_no_initializer.vox`,
`tests/compile_fail/declare_create_time_no_initializer.vox`). `timer` never
reaches this arm at all — `a timer called t.` parses to a dedicated
`TimerDecl` statement that always emits `TIMER_INIT` over a real stack slot,
regardless of whether the declaration has this fallback in its match. No
other type was found holding a null pointer through this path.

---

### 17. Appending a format string to a list stores a corrupt element — printing or reading it back segfaults or leaks a raw pointer

**Status: fixed in v0.4.0.** Found 2026-08-16 while building a
text-utilities shared library (`textkit`) against `main` post-v0.3.6. Not
library-specific — the minimal repro is a four-line standalone executable.

Root cause: `Expr::FormatString` had no arm in either `prescan_expr_tag` (the
whole-program pre-scan that proves list homogeneity and scalar provability)
or `infer_expr_type` (the emit-time fallback that `emit_time_expr_tag`
consults). Both fell through to their generic default, which reports a
format string's type as plain integer. The *payload* `generate_expr` builds
for a format string was always a sound, durable string pointer — only the
*tag* written alongside it was wrong, so a reader dispatching on that tag
reinterpreted a valid pointer as an integer. Fixed by adding an explicit
`Expr::FormatString { .. } => TAG_STRING`/`VarType::String` arm to both
functions — a format string can only ever produce text, so this is always a
safe proof, unlike a declared-but-unproven scalar type. Regression tests:
`tests/bugs_found_17_format_append_text.vox`,
`tests/bugs_found_17_format_append_number.vox`,
`tests/bugs_found_17_format_append_buffer.vox`,
`tests/bugs_found_17_format_append_named.vox`,
`tests/bugs_found_17_element_access.vox`, `tests/bugs_found_17_for_each.vox`,
plus `format_string_append_tags_string`,
`format_string_append_does_not_spuriously_widen_list`, and
`format_string_local_appended_by_name_tags_string` in `src/codegen/mod.rs`.

**A note on the original repro below: it reproduces a *different*, still-open
bug, not this one — see #19.** Its variable is named `x` and initialized to
the literal `"x"`, the same text as its own name; the reproduction matrix
below has been re-verified with non-colliding names to isolate bug #17
specifically.

As originally found (this exact source still segfaults — see the note above
on why, and why that's not this bug):

```vox
a list called out is [].
a text called x is "x".
append "fmt {x}" to out.
Print the out.
```
```
Segmentation fault (exit 139)
```

Element access (`a text called t is element 1 of out. Print t.`) and
`For each w from out, print "<{w}>".` were reported broken identically, so
the stored element itself was bad, not merely the whole-list print path. The
failure mode as originally observed depended on what the format string
interpolated:

| appended expression | result of `Print the out.` as originally observed |
|---|---|
| `"literal"` (no interpolation) | correct: `["literal"]` |
| `"fmt {x}"` — `x` a text | **SIGSEGV** (the `x`/`"x"` name collision above) |
| `"n {k}"` — `k` a number | `[139846434144280]` — a raw pointer |
| `"{w}"` — `w` a buffer | `[140144756633624]` — a raw pointer |

A text variable *initialized* from a format string and then appended by name
(`a text called tok is "fmt {x}". append tok to out.`) crashed the same way —
again the `x`/`"x"` collision, confirmed by rerunning with a non-colliding
interpolant name.

**Re-verified post-fix with non-colliding names** — every row now prints
correctly with exit 0, via whole-list print, `element N of`, and `for each`:

| appended expression | result of `Print the out.` |
|---|---|
| `"literal"` (no interpolation) | `["literal"]` |
| `"fmt {greeting}"` — `greeting` a text | `["fmt hello"]` |
| `"n {k}"` — `k` a number | `["n 7"]` |
| `"{w}"` — `w` a buffer | `["buf"]` |
| text local from a format string, appended by name | `["fmt hi"]` |

Both spec promises this broke are explicit: list `append` "works with any
value", and format strings are first-class values (v0.1.17) usable
"everywhere" (v0.1.21). The pointer-printing variants were also a
memory-safety wart in their own right — the program printed an address
instead of the bytes.

The workaround previously documented here — routing the value through a
function with a declared `text` return — is no longer necessary; direct
format-string append now works.

---

### 18. The `.lib` list-element-type inference credits fewer shapes than the runtime element tagger — provably-`text` elements ship as plain `list`

**Status: fixed in v0.4.0.** Same session as #17; mild, no
crash. LANGUAGE.md ("The `.lib` file") says a `--shared` build scans the
exported function's body and writes `list of <type>` "when every
appended/returned element provably agrees on one type". Before this fix the
scan credited only two shapes. One library, six exported functions, each
appending exactly one element to a fresh list and returning it with a
declared `Return a list, out.`:

| element appended | `.lib` recorded before this fix | records now |
|---|---|---|
| `append "literal" to out` | `list of text` | `list of text` |
| `append "fmt {x}" to out` | `list` | `list of text` (bug #17 fixed the element itself first) |
| text local from literal, appended by name | `list` | `list of text` |
| text local from format string, appended by name | `list` | `list of text` |
| text parameter appended by name | `list of text` | `list of text` |
| call to a function with declared `text` return | `list` | `list of text` |

Rows 3, 4, and 6 were the gap this entry was about: the element was provably
`text` (row 3 by its declaration and literal initializer, row 4 by #17 plus
row 3's reasoning, row 6 by the callee's declared return type), the runtime
tagger already agreed — the consumer printed real strings — but the table of
contents still said plain `list`, so the consumer lost the static element
type the docs promise.

Root cause: `scan_list_element_type`/`scalar_expr_type` (the narrow,
single-pass, non-flow-sensitive scan `.lib` emission uses — deliberately
separate from the whole-program pre-scan #17 fixed) only ever credited a
direct literal or a *parameter's* declared type. A local's declared type and
a called function's declared return type were both real, sound evidence the
scan simply never looked at. Fixed by: (1) collecting every `VarDecl`-declared
scalar local's type from the function body (dropping a name declared with
two disagreeing types across branches, rather than guessing which one a
later read sees); (2) a `Expr::FunctionCall` arm crediting the callee's
declared return type, looked up in a `(library, version)`-scoped map built
ahead of time so a call to a function defined *later* in source order is
still resolved, and so two libraries in one file defining a same-named
function with different return types can't leak into each other's `.lib`;
and (3) an `Expr::FormatString` arm (always text — sound now that #17 is
fixed). The runtime tag-forging guard (`declared_type_does_not_forge_a_string_tag`)
is a separate, deliberately more conservative mechanism and was not touched.
Regression tests: `plan_303_local_declared_type_credits_element_parameter`,
`plan_303_call_declared_return_type_credits_element_parameter`,
`plan_303_format_string_credits_element_parameter`,
`plan_303_newly_credited_shapes_in_return_position`,
`plan_303_function_call_return_type_scoped_per_library`,
`plan_303_local_declared_type_conflict_stays_unknown` in `src/codegen/mod.rs`
(the existing `plan_296_list_element_type_stays_unknown_on_disagreement_or_no_evidence`
guard still passes unchanged).

---

### 19. A string literal's content resolved against known variable names at codegen time — crash on self-name collision, silent wrong data on any other collision

**Status: fixed in v0.4.0.** Found 2026-08-16 while isolating
bug #17: the plan's own Phase 1 repro used a variable named `x` initialized
to the string `"x"`, and segfaulted for a *second*, unrelated reason once
#17's actual defect (wrong element type tag on an appended format string)
was fixed. Not list- or format-string-specific — plan 304 found two
manifestations, one far worse than the other.

**Crash, self-name collision** (the original finding):
```vox
a text called x is "x".
Print x.
```
```
Segmentation fault (exit 139)
```

**Silent wrong data, any-other-name collision** (escalation found while
scoping the fix — no crash, no diagnostic, just the wrong value):
```vox
a text called greeting is "hello".
a text called b is "greeting".
Print b.
```
prints `hello`, not `greeting`. Every program is affected the moment a
string literal's content coincides with *any* in-scope variable name — an
ordinary thing for real programs to do (`"count"`, `"line"`, `"name"`, …).
The same substitution happened for a literal used directly in a `Print`
statement (`Print "greeting".` also printed `hello`), and could silently
flip a `is a float`/`is a buffer` type predicate's answer when a literal's
text happened to match a same-typed variable's name.

**Root cause.** `Expr::StringLit`'s codegen did not treat its payload as
string data unconditionally — several sites checked whether the literal's
own *text content* matched a currently-known variable name (or, in one
case, a folded top-level constant's name) and substituted that instead of
materializing the literal bytes:

- `generate_expr`'s `Expr::StringLit` arm called `emit_load_named_var_into_rax(s)`
  before falling back to the literal — the direct cause of both repros above
  (for the self-name case, `x` is already a registered variable with an
  unwritten slot by the time its own initializer is generated, per
  `Statement::VarDecl` registering the declared type/BSS label *before*
  generating the initializer expression; the load reads that
  not-yet-written slot instead of the literal).
- `generate_print`'s `Expr::StringLit` arm did the same, *plus* a second,
  independent fallback to `emit_global_constant_format_fallback(s, None)` —
  a lookup of `s` against `self.global_constants` (top-level literal-valued
  declarations) — reached whenever the first check failed. Removing only the
  first check would have left this second one to reproduce the exact same
  bug through a different table; both had to go.
- `is_float_expr`, `is_buffer_expr`, and `has_float_operands` each consulted
  `quoted_name_var_type(s)` (a thin wrapper over the same variable tables)
  to decide these predicates for a `StringLit`, so a literal spelled like a
  float/buffer variable could flip a type check or pick the wrong equality
  comparison strategy.
- `infer_expr_type`'s `Expr::StringLit` arm called the same
  `quoted_name_var_type` as a first-choice override before its `Some(VarType::String)`
  fallback.

**The tension (why this was a violation, not a feature).** LANGUAGE.md's
*Naming Rules* section states this unconditionally: "A name is an
**identifier**, never a string literal," and rule 1 under it: "`\"...\"` is
never an identifier, in any position. Where an identifier is expected and a
string literal is found, that is a compile error." The *Names and strings*
section recounts why: before v0.3.0 a double-quoted token was read as
string-literal-or-identifier depending on position, that overload caused
silent wrong answers (a variable receiving a function pointer instead of a
call result, printed as a number, no error), and v0.3.0 explicitly split the
two so a double-quoted token is "a string literal everywhere." That split
was real at the grammar/parser level, but every codegen site above
re-introduced the identical pre-0.3.0 disambiguation *after* parsing, on the
literal's own bytes — not on anything the parser had marked as a name
reference. A `StringLit` reaching any of these sites had already been
through the parser and, per the Naming Rules, was data, not a name up for
re-negotiation.

**Fix.** All five sites now treat `Expr::StringLit` as text, unconditionally
— no variable-table or constant-table lookup on its content. `quoted_name_var_type`
and `emit_global_constant_format_fallback` are deleted (the fix removed
every call site of each). `emit_load_named_var_into_rax` and
`self.global_constants` themselves are untouched and still used correctly
elsewhere for genuine identifier/`{name}`-interpolation resolution (map
key/value access by the map variable's own name, a `Print` of a plain
`Expr::Identifier`, and `{name}` format-string interpolation, which is a
name by construction of the `{...}` syntax, never an ambiguous literal).
No existing test relied on the removed behaviour — the full suite passed
unchanged after the removal. Regression tests:
`tests/bugs_found_19_self_name_initializer.vox`,
`tests/bugs_found_19_other_name_initializer.vox`,
`tests/bugs_found_19_other_name_print_direct.vox`,
`tests/bugs_found_19_predicate.vox`.

**See also #20:** a red team pass on this fix found that it makes a
*separate*, pre-existing crash commonly reachable — comparing a string
literal against a same-named `float`/`number`/`boolean` variable for
equality (e.g. `"pi" is equal to pi`) now correctly infers the literal as
text (this fix) and so reaches equality-dispatch code that dereferences the
non-stringy operand as a string pointer (#20's own defect, not this one).

---

### 20. Equality dispatch treats a non-stringy operand as a string pointer and dereferences it

**Status: fixed in v0.4.0.** Found 2026-08-16 by a red team
pass on the #19 fix. **Pre-existing** — reproduces with #19 reverted too —
but #19 made it commonly reachable: before #19, a string literal whose text
matched a `float` variable's name was (wrongly) inferred as `Float`, so
`"pi" is equal to pi` took the numeric comparison path, giving a wrong
answer but not crashing. #19 correctly makes a literal always infer
`String`, so that same, ordinary-to-write comparison now reaches this
defect instead.

```vox
If "abc" is equal to 3.5 then, print "a". Otherwise, print "b".
```
```
Segmentation fault (exit 139)
```
No name collision needed at all. `number`, `float`, and `boolean` operands
all crash, in both operand orders, for both `is equal to` and `is not equal
to`. A `list`/`map` operand doesn't crash (a heap pointer happens to be
readable) but gives a wrong answer via a suspected out-of-bounds read.
`buffer`-vs-`text` and `text`-vs-`text` were already correct and had to stay
correct — both sides are genuinely byte sequences there.

**Root cause.** Comparing a **stringy** value (`text`, `buffer`, or a string
literal) to anything else for equality took the same content-comparison path
whenever *at least one* side was stringy (`is_stringy_expr(left) ||
is_stringy_expr(right)`, in both `generate_condition` and its structurally
identical expression-position twin in `generate_expr`). That path
(`emit_stringy_equality` → `generate_cstr_expr`) special-cases only `Buffer`;
every other type's raw value — a float's bit pattern, an integer, a
boolean's 0/1, a list/map struct pointer — is passed through unchanged and
handed to `_str_eq`/`_mem_eq`, which dereferences it as a NUL-terminated
C-string pointer.

**Fix.** The content-comparison path is now taken only when *both* operands
are stringy, or when one side is stringy and the other is `value`/`Mixed`
(a dynamic operand whose runtime tag might be text — not provably
incompatible, so the existing behaviour there is preserved exactly:
correct when the `value` does hold text, unchanged — still a latent,
separate crash, out of this fix's scope — when it holds something else).
When one side is stringy and the other is a *provably* non-stringy type
(`number`, `float`, `boolean`, `list`, `map`), the two representations can
never be byte-equal: `is equal to` folds to a compile-time-constant `false`
and `is not equal to` to `true`, without evaluating or dereferencing either
operand. Both call sites (`generate_condition` and `generate_expr`) got the
identical fix; a genuine surface-syntax repro was found for both
(`Return a boolean, "abc" is equal to 3.` reaches the `generate_expr` site
and crashed pre-fix, confirmed by testing against the pre-fix binary —
broader reach than the red team's own search had found). Regression tests:
`tests/bugs_found_20_no_collision.vox`, `tests/bugs_found_20_float_collision.vox`
(includes the `"pi" is equal to pi` collision case), `tests/bugs_found_20_number_boolean_list.vox`,
`tests/bugs_found_20_not_equal.vox`, `tests/bugs_found_20_buffer_text_positive.vox`,
`tests/bugs_found_20_return_position.vox`, plus three codegen unit tests
(`stringy_vs_non_stringy_condition_never_dereferences`,
`stringy_vs_non_stringy_expression_never_dereferences`,
`both_stringy_equality_still_dereferences_correctly`) pinning that no
`_str_eq`/`_mem_eq` call is emitted for a mismatch, while a genuine
stringy-vs-stringy comparison still is.

### 21. A string literal in an `If`/`While` condition inside a function body resolves as a variable name

**Status:** **fixed in v0.4.4.** A **regression**, not a latent defect:
the analyzer's `validate_function_condition_variable_refs` matched
`Expr::StringLit` and checked it against known variable names —
reintroducing the pre-0.3.0 quoted-token-as-identifier ambiguity that
#19 removed from five codegen sites but missed in the analyzer. It stayed
unreachable until `7d5895d` ("Cleaned up the code", April 2026) widened a
`BinaryOp` recursion guard from `And`/`Or` to all operators. The helper is
deleted entirely (per #19's precedent) and was proven redundant —
`analyze_expr`'s `Identifier` arm already validates bare identifiers at
every scope. Regression tests: `tests/bugs_found_21_literal_condition.vox`
(all four spellings × `If`/`While`) and
`tests/compile_fail/094_function_condition_unknown_bare_identifier.vox`
(pinning that real undeclared-identifier detection still fires). Found by
the vox-fuzz plan red team (2026-08-18); independently reproduced before
filing.

```vox
To g with a text called w.
  If w is not "banana" then,
      Return a number, 1.
  Return a number, 0.

Print g of "hang".
```

```
error: Unknown variable: banana
  --> repro.vox:2:15
```

LANGUAGE.md's identifier rules say a `"..."` is a string literal
**everywhere** and never an identifier. The same comparison works at top
level, works as `Return a boolean, w is "banana".` inside a function, and
works when the literal is first bound to a local. Only `If`/`While`
**conditions inside a function body**, string literals only, all four
comparison spellings (`is`, `is equal to`, `is not`, `is not equal to`);
number literals in the same position are fine.

`grep -rn '^\s\+\(If\|While\) .*is\( not\)\?\( equal to\)\? "' examples/ tests/`
returns zero hits — no test or example in the repo exercises the shape,
which is how it survived. Workaround until fixed: bind the literal to a
named local and compare against that.

### 22. An integer literal too large for 64 bits compiles silently and evaluates to 0

**Status:** **fixed in v0.4.4.** Now a compile-time error naming both the
literal and the valid range, in the shape of the existing out-of-range
file-descriptor check; `i64::MAX` still compiles and the negative boundary
is pinned. Found by the vox-fuzz plan red team (2026-08-18); independently
reproduced before filing.

```vox
Print 99999999999999999999999999.
```

Compiles clean, prints `0`. No error, no warning. LANGUAGE.md documents
`number` as "Whole numbers" with no stated range, so there is no
documented licence for the wrap-to-zero — it is a silent wrong answer,
and the worst kind: arithmetic built on such a literal is quietly wrong
everywhere downstream. A literal that cannot be represented should be a
compile-time error, the way an out-of-range file-descriptor literal
already is (LANGUAGE.md documents that check explicitly).

Also worth noting for the fuzzer: this is exactly the class of defect a
differential oracle would catch and the crash-only invariant cannot —
recorded in vox-fuzz's DECISIONS.md as evidence for the deferred oracle.

---

### 23. Printing a list of `arguments's all` elements leaks raw pointers; element access is fine

**Status:** **fixed in v0.4.4** with the same explicit tag arm #17's fix
established; a homogeneous number list is pinned to guard against
blanket-tagging. Sibling of #17 and #18 (element-tag mis-attribution),
distinct site. Found by the vox-fuzz plan red team (2026-08-18);
independently reproduced before filing.

```vox
a list called everything is arguments's all.
Print everything.                (wrong: [140728673871980, 140728673871986])
Print element 1 of everything.   (correct: alpha)
```

Run with `./program alpha beta`. The elements' payloads are sound string
pointers — `element 1 of` reads one back as text correctly — but
whole-list printing dispatches on the elements' type tags and treats
them as integers, printing the pointers. Same shape as #17's root cause
(payload right, tag wrong), but #17's fix covered `Expr::FormatString`;
whatever expression produces `arguments's all`'s elements needs the same
tag arm.

### 24. Reading an unset environment variable by name segfaults — `On error` cannot catch it

**Status:** **fixed in v0.4.3.** A missing variable now sets the error flag
and yields empty text, so `On error` catches it like every other fallible
read. Regression tests: `tests/bugs_found_24_missing_env_var.vox`,
`tests/bugs_found_24_present_env_var_unaffected.vox`,
`tests/bugs_found_24_exists_guard_unaffected.vox`. (Still open, flagged
during the fix: `_get_env_at`, behind `At`/`First`/`Last`, has the same
null-return-on-out-of-bounds shape.) Found 2026-08-18 during review of
vox-fuzz's foundation work; minimal repro is one line.

```vox
Print environment's "DEFINITELY_NOT_SET_ANYWHERE".
```

Dies with SIGSEGV (exit 139). An `On error` handler on the reading
statement does not fire — the crash happens before any error flag is set.
The same read with the variable present works, and the documented
guard-then-read pattern works in both directions:

```vox
a text called 'the compiler' is "../vox/target/release/vox".
If the environment variable "VOX" exists then,
    Set 'the compiler' to environment's "VOX".
```

LANGUAGE.md's own examples only ever read after an exists-check (or read
variables like USER that always exist), so the unguarded read is arguably
misuse — but Vox's core promise is that failure surfaces through
compile-time rejection or runtime error flags, never memory corruption. A
missing variable should set the error flag and yield empty text, the same
contract as every other fallible read. Same family as #16 (uninitialised
text read segfaults): a text-typed slot consumed before anything backs it.

Noted with some satisfaction: this is the first compiler bug surfaced by
the vox-fuzz project's own build-out — a one-line program that dies by
signal is precisely the invariant the fuzzer exists to enforce.

---

### 25. A declaration on a non-`If` conditional path stays in scope over storage nothing ever initialises — stack garbage for numbers, segfault for text

**Status:** **fixed in v0.4.3.** Per plan 318 §1 and LANGUAGE.md:526's
no-block-scoping model, the compiler now emits the type's default at frame
setup for any name whose declaration sits on a conditional path, so a
declared name always holds initializer-or-default. `emit_type_default`
factors out the code a no-initializer declaration always emitted;
`collect_all_typed_decls` (the explicit complement of
`collect_definite_decls`) tells codegen which names need it. 12 regression
tests, `tests/bugs_found_25_*.vox`, covering `On error`/`While`/`for
each`/`Repeat` × number and text, collections, and a taken-path guard.
Found by the vox-fuzz Task 9 hunt (2026-08-18): the fuzzer's finding
dissolved under adjudication into two documented parsing rules — and this
underneath.

`If` bodies are properly scoped: `collect_definite_decls` refuses to call
a some-branches declaration definite, and use-after is rejected
(LANGUAGE.md "Declarations in Branches"). But `On error`, `While`, and
`for each` bodies are not scoped at all — the analyzer walks their
declarations in the enclosing environment — so a name declared there is
accepted everywhere after, while its initialising store sits behind the
branch that never ran. The slot is never written on the zero-execution
path: no default emission, no `.bss` mirror.

```vox
To dirty.
  a number called scratch is 12345.
  Print scratch.

To probe.
  On error print "handler ran",
  a number called total is 7.
  Print total.

dirty.
probe.
```

Prints `12345` — `dirty`'s leftover frame slot, read out of `probe` as if
it were `total`. Exit 0, no warning: the "wrong answer that looks
completely plausible" LANGUAGE.md:2560 says the language exists to
prevent. The text form is worse:

```vox
a number called n is 0.
While n is greater than 5,
  a text called label is "hi",
  the n is n add 1.
Print label.
```

Segfault (exit 139) — an uninitialised slot read as a string pointer.
This is #16's exact failure mode reached by a route its fix does not
cover: that fix added defaults for declarations *without* initializers;
here the initializer exists but its statement never runs.

**Rule violated:** LANGUAGE.md:429-433 and the defaults table — a
declared name holds its initializer or its type's default; there is no
documented state in which an accepted, in-scope name holds neither.

**The fix most consistent with the book** (LANGUAGE.md:526: no
block-level scoping; these names are meant to be visible): emit the
type's default at frame setup for any name whose declaration sits on a
conditional path. Rejecting the use `if`-style would contradict :526 and
break programs that declare in a loop body and read after.

---

### 26. Out-of-range `arguments`/`environment` positional properties segfault

**Status:** **fixed in v0.4.4.** Every out-of-range positional read now
sets the error flag and yields empty text, catchable by `On error`,
matching the already-correct neighbours. Five shapes were fixed — the
four below plus a negative-index form found during the audit.
Regression tests: `tests/bugs_found_26_*` (the faulting shapes, an
`On error` proof, the out-of-range `environment ... at N` stand-in, the
negative index, and an in-range/safe-neighbour guard). Note for the
harness: `test.sh` cannot run a test with an empty environment, so the
two `env -i` cases were verified by hand and the automated coverage uses
a far-out-of-range index instead. Flagged (not filed) during #24's fix
as "`_get_env_at` has the identical null-return-on-out-of-bounds shape";
this entry is that sibling, and testing showed it is **wider than
flagged** — the `arguments` family has it too.

Reading a positional property that does not exist returns a null
pointer, which the reader dereferences:

```vox
Print arguments's first.    (no user arguments -> SIGSEGV, exit 139)
Print arguments's second.   (fewer than 2 -> SIGSEGV)
Print environment's first.  (empty environment -> SIGSEGV)
Print environment's last.   (empty environment -> SIGSEGV)
```

Reproduce the environment cases with `env -i ./program`, the argument
cases by running with no arguments.

**Safe, and worth noting as the shape a fix should match:**
`arguments's last`, `arguments's name`, `arguments's all`,
`arguments's raw`, and every `count` return sensible empty/zero values
rather than faulting — so the correct behaviour is already implemented
next door. `arguments's last` being safe while `arguments's first`
faults is the clearest possible evidence this is an oversight rather
than a design position.

Same family as #16, #24, and #25: a text-typed slot handed to a reader
with nothing behind it. Per LANGUAGE.md's contract, a fallible read
should set the error flag and yield empty text, catchable by
`On error` — never fault.

---

### 27. A period never closes a `Repeat` body — following statements are silently absorbed into the loop

**Status:** **fixed in v0.4.6.** Found 2026-08-19 against
released v0.4.5. Surfaced by a vox-fuzz worker hand-verifying loop syntax
for plan 323; its own characterisation ("a `While` containing another loop
cannot be closed") did not reproduce, and the real defect was localised by
the master.

`Repeat` is the only loop construct whose body a period fails to close.
The statement after it is silently pulled inside the loop and re-runs on
every iteration. There is no error — just wrong output.

```vox
Repeat 2 times, Print "r".
Print "after".
```

**Expected** (LANGUAGE.md rule 1, line 135): the period closes the
innermost open clause. The clause list is given explicitly as
``(`if`, `on error`, `for`, `while`, `repeat`)`` — `repeat` is named.
So this should print `r`, `r`, `after`.

**Actual:** `r after r after`. The period does not close the `Repeat`;
`Print "after"` becomes the loop's second action.

A blank line **does** close it (`r r after`), which is rule 2 working
correctly and is the only reason the construct is usable at all today.

**The controls both behave correctly**, which is what isolates this to
`Repeat` rather than to the termination rule:

| Source | Output | |
|---|---|---|
| `Repeat 2 times, Print "r".` + `Print "after".` | `r after r after` | ✗ |
| same with a blank line instead | `r r after` | ✓ |
| `While n is less than 2, Set n to n add 1.` + `Print "after".` | `after` | ✓ |
| `For each n from 1 to 2, Print n.` + `Print "after".` | `1 2 after` | ✓ |

**Secondary symptom, same root cause.** Because the `Repeat` never
consumes a period, a stacked period intended to close it errors instead:

```vox
For each n from 1 to 2,
    Repeat 2 times, Print "r"..
Print "after".
```
→ `error: Expected a statement, got Period`

The second period has nothing left to close, so it is rejected — while
the identical shape with `For each` or `If` nested inside compiles and
closes both levels, as [Closing more than one
level](../LANGUAGE.md#closing-more-than-one-level) documents
("periods stack: write one period per level you want to close").

**Second symptom, same root cause — a comma does not continue the body.**
`parse_repeat`'s body loop had no `Token::Comma` branch at all, unlike
`parse_while`/`parse_for`, so a multi-action `Repeat` was impossible:

```vox
Repeat 2 times, Print "a", Print "b".
```
→ `error: Expected a statement, got Comma`

The comma that should separate two actions in the same `Repeat` sentence
was instead rejected as the start of a statement. Both symptoms are the
one missing structure: `parse_repeat`'s body loop did not match
`parse_while`'s separator handling.

**Why it matters more than it looks.** This is the family of bug #5 —
silently required punctuation whose absence changes behaviour rather
than raising an error. Any program that uses `Repeat` with a period and
continues afterwards re-runs the continuation once per iteration and
reports nothing wrong. `Repeat` is also the construct a reader is least
likely to suspect, because `While` and `For each` beside it behave
exactly as documented.

**Fix.** `parse_repeat`'s body loop now matches `parse_while`'s separator
handling: comma continues, period breaks unconditionally, paragraph break
breaks, EOF breaks. The two bodies are identical, so they were factored
into one shared `parse_loop_body` that both `parse_while` and
`parse_repeat` call — better than two copies drifting apart again.
(`parse_for`'s three body loops were left alone: their top-of-loop
terminator check is a paragraph break, not `Return`, a deliberate
difference not in this bug's scope.) `Repeat` was also added to
`parse_block`'s self-terminating-construct list alongside `If`/`While`/
`For`, so a `Repeat` that is not the last action in a branch no longer
orphaning the action that follows it — the same rule-1 promise, applied
uniformly. Regression tests: `tests/bugs_found_27_period_closes.vox`,
`tests/bugs_found_27_comma_continues.vox`,
`tests/bugs_found_27_blank_line_closes.vox` (the one path that already
worked — the regression guard),
`tests/bugs_found_27_stacked_for_each.vox`,
`tests/bugs_found_27_stacked_while.vox`,
`tests/bugs_found_27_stacked_if.vox`,
`tests/bugs_found_27_in_function.vox`,
`tests/bugs_found_27_nested_if_last_action.vox`, and
`tests/bugs_found_27_repeat_branch_no_comma.vox` (the self-termination
case). Before the fix the suite ran 389 passed / 8 failed; after, 397
passed / 0 failed — the eight fixed tests, no regressions.

---

### 28. A `buffer` declared on an untaken `If` branch, then redeclared at top level, segfaults on first read

**Status:** **fixed in v0.4.6.** Found 2026-08-19 against `main`
(post-#27). Surfaced
by a vox-fuzz generator worker whose generated program hit it through a
name collision; hand-reduced by that worker to a form with nothing
fuzzer-specific left, then independently reproduced and characterised by
the master.

```vox
a number called n is 0.
If n is greater than 5 then,
  a buffer called b is "x".      (branch never taken)
a buffer called b is "y".
Print b.                          (segfault)
```

**It is specific to `buffer`, and to the redeclaration.** The controls
isolate it exactly:

| Case | Result |
|---|---|
| `buffer`, untaken branch declares `b`, top level redeclares `b` | **segfault (139)** |
| identical but the branch **is** taken (`n is 9`) | exit 0 |
| `buffer`, but the two declarations use **different names** | exit 0 |
| `number` in place of `buffer`, same shape | exit 0 |
| `text` in place of `buffer`, same shape | exit 0 |

So neither conditional declaration alone nor redeclaration alone is
enough: it takes both, on a buffer.

**Family.** This is bug #25 — declarations on a conditional path in
scope over storage nothing initialises — with the buffer redeclaration
case missed when #25 was fixed. #25's cure was `emit_type_default`,
giving a conditionally-declared name the same default a plain
declaration gets. The likely gap here is that the *second* declaration
is treated as a redeclaration of an existing name and so emits no
initialisation at all, leaving the buffer's header or data pointer as
whatever was on the stack — which `Print` then dereferences.

**Severity: high.** A runtime segfault from legal-looking code, with no
diagnostic. The shape is not exotic: a buffer declared inside a guard
and again outside it is an ordinary thing to write, and the program is
silently fine whenever the guard happens to be true, which is the worst
possible failure pattern for anyone trying to reproduce it.


**CORRECTION (master, 2026-08-19, after reviewing the regression tests).**
My original matrix understated the reach of this bug in two places, and
the fix worker found shapes I had not tried:

- **`Repeat 0 times` is not immune.** Closing its body with a *period*
  survives; closing it with a **blank line** segfaults. My "the odd one
  out, a free control sample" note applied only to the period form and
  should not be read as `Repeat` being safe.
- **A sized declaration does not protect the later one.** Sized→sized
  survives, but **sized-in-branch followed by a string-initialised
  redeclaration segfaults**. The protection came from the *second*
  declaration being sized, not the first.

Both shapes are covered by regression tests and both segfault on the
unfixed compiler. The lesson for the entry: the trigger is a
string-initialised declaration reusing a name whose only prior
allocation sat on a path that did not run — the enclosing construct and
the *earlier* declaration's form are both incidental.

**ROOT CAUSE — diagnosed from the emitted assembly, 2026-08-19 (master).**
Not a guess: `vox --emit-asm` on the crashing program shows it exactly.

```asm
    jle .else_1
    mov rdi, 1024
    call _alloc_buffer          ; allocation happens INSIDE the If branch
    mov [rel gvar_0], rax
    ...
.if_end_0:
    mov rdi, [rel gvar_0]       ; still 0 (.bss) when the branch did not run
    call _buffer_clear          ; clear on a NULL pointer -> SIGSEGV
```

The **second** declaration emits no `_alloc_buffer` at all — only
`_buffer_clear` + `_buffer_append_bytes` — because the name is already
known. But the allocation it relies on was emitted only on the
conditional path, so when that path is not taken the pointer is null and
the very first thing the second declaration does is dereference it.

This also explains every control:

- **`never read` still crashes** — the fault is in the *declaration*
  (`_buffer_clear`), not in any read. This is why the original
  "stack garbage dereferenced by `Print`" guess was wrong.
- **Sized buffers survive** — `a buffer called b is 8 bytes` emits
  `_alloc_buffer_sized` on **every** declaration (2 calls in the same
  shape, versus 1 for the string form). Allocating unconditionally is
  precisely what keeps it safe.
- **`text`/`number`/`list` survive** — their declarations do not depend
  on a prior heap allocation the same way.
- **Branch taken survives** — the allocation ran.

**Fix, therefore:** make the string-initialised buffer declaration
allocate unconditionally, exactly as the sized path already does, rather
than skipping allocation whenever the name is already bound. The sized
path is the working reference implementation sitting in the same
compiler.

**Fix direction:** find where a redeclaration suppresses initialisation
and make the top-level declaration initialise unconditionally, as its
non-conditional counterpart does. Regression tests must cover all five
rows above, not just the failing one — the passing rows are what pin the
diagnosis.

---

### 29. A string literal inside a list literal is resolved as a variable name — silent wrong data, or a segfault

**Status:** **fixed in v0.4.6.** Found 2026-08-19 against `main`
(post-#27/#28).
Found by the vox-fuzz generator red team; reproduced and characterised
by the master. **This is [#19](#19-a-string-literals-content-resolved-against-known-variable-names-at-codegen-time--crash-on-self-name-collision-silent-wrong-data-on-any-other-collision)'s
family, and #19 is marked fixed in v0.4.4 — the list-literal path was
missed.**

```vox
a list called hello is [1, 2].
a list called L is ["hello", "hello"].
Print L.
```

prints roughly 96KB of `8589934592` (`0x200000000` — a corrupted tag)
and then **segfaults**.

**The controls, which show the crash is the lesser problem:**

| Program | Result |
|---|---|
| `a number called hello is 7.` + `["hello"]` | prints **`[4198536]`** — *silent wrong data* |
| `a list called hello is [1,2].` + `["hello"]` | prints `[[]]` — wrong |
| `a list called hello is [1,2].` + `["hello","hello"]` | **segfault (139)** |
| no variable named `hello` exists | correct: `["hello", "hello"]` |
| the colliding variable is a `text` | correct: `["hello"]` |
| collision present, list never printed | survives |

**The rule being broken is stated in the grammar**, so there is no
reading in which the compiler is right:

```
string      ::= '"' ... '"'            ; a string literal is data, never a name
```

**Severity: the highest of anything currently open.**

- The **number-collision case corrupts data silently.** `["hello"]`
  becomes `[4198536]` — a pointer printed where a string was written —
  with no crash, no diagnostic, nothing to notice. That is worse than
  the segfault, which at least announces itself.
- The **list-collision case is memory-unsafe.**
- The trigger is *ordinary code*. A list of strings, one of which
  happens to match a variable name in scope, is not an exotic program.

**Why the fuzzer never caught it.** It cannot generate the shape: its
string literals never spell an identifier, and its lists are never
nested nor printed whole. Three coverage gaps intersect exactly here.
The fuzzer did not look and find nothing — it could not look.

**ROOT CAUSE — diagnosed from the emitted assembly, 2026-08-19 (master).**

Compiling the colliding and non-colliding programs and diffing the
assembly isolates it to a single instruction — the list slot's **type
tag**:

```asm
    mov byte [rbx+88], 1   ; slot 1 type tag  <- no collision  (correct: text)
    mov byte [rbx+88], 4   ; slot 1 type tag  <- collides with a list (wrong)
```

The tag is taken from **the colliding variable's type**, not from the
literal:

| The literal collides with | Slot tag emitted | |
|---|---|---|
| *nothing* | **1** (text) | correct |
| a `text` | 1 | correct **only by coincidence** |
| a `float` | 2 | wrong |
| a `list` | 4 | wrong — later dereferenced as a list, hence the segfault |
| a `number` | (immediate form) | wrong — the pointer prints as an integer |

So the element's *value* is written correctly; its **tag** is not. The
consumer then reads a string pointer as whatever the tag claims — an
integer (silent wrong data) or a list (dereference, crash).

**Critical for anyone fixing this: the `text` case passing is not
evidence that the text path is correct.** It passes because the wrong
answer and the right answer happen to be the same number. Any fix
validated only against a `text` collision will look correct and change
nothing.

**The fix is therefore narrow and clear:** a string literal in a list
element must always be tagged as text, with no lookup of its content
against variable names at all.

**Fix direction:** #19's cure deleted the resolve-literal-as-identifier
behaviour from five codegen sites. Find the list-literal element path
that still does it. The `text`-collision case behaving correctly is a
useful control: whatever that path does differently is probably the
right shape. Regression tests must cover **every row of the table
above**, because the passing rows are what pin the diagnosis, and the
silent-wrong-data row is the one most likely to regress unnoticed.

**Generator follow-up (vox-fuzz):** teach the generator to sometimes
emit a string literal that spells an existing variable name. It is a
demonstrated bug-finding shape and costs almost nothing to add.

---

### 30. A buffer initialised from a string literal copies a same-named buffer instead — silently

**Status:** **fixed in v0.4.6.** Found 2026-08-19 against `main`.
Found by the
master while locating #29's code site; same family as #19/#29.

```vox
a buffer called hello is "SURPRISE".
a buffer called b is "hello".
Print b.
```

**prints `SURPRISE`.** It should print `hello`. The string literal
`"hello"` is resolved as a variable name, the buffer of that name is
found, and its *contents* are copied in place of the literal.

`Set b to "hello"` behaves identically.

**Controls:**

| Program | Output | |
|---|---|---|
| no variable named `hello` | `hello` | correct |
| a **buffer** named `hello` exists | **`SURPRISE`** | wrong |
| a **text** named `hello` exists | `hello` | correct |

Only a `buffer`-typed collision triggers it, because the site tests
exactly that.

**Site:** `src/codegen/buffers.rs`, the `Expr::StringLit(s)` arm of the
buffer-value path:

```rust
Expr::StringLit(s) => {
    if self.variable_types.get(s) == Some(&VarType::Buffer) {
        ... emit _buffer_copy / _buffer_append from that variable ...
```

The literal's own text is used as a lookup key. This is the same defect
as #29 at a different site, and note it does **not** match the
`Expr::StringLit(name) | Expr::Identifier(name)` shape — so a search for
that pattern alone will miss it. The real search is *any* place a
`StringLit`'s content is used as a name.

**Severity: high, and arguably worse than #29.** #29 crashes, which
announces itself. This one silently substitutes different data and the
program carries on. A `buffer` initialised from a literal that happens
to match a buffer name in scope gets the wrong contents, with no
diagnostic at any stage.

**Fix:** a string literal is data. Delete the lookup; initialise the
buffer from the literal bytes unconditionally. If copying a named buffer
into another is a wanted feature it needs its own syntax
(`a buffer called b is the hello` or similar) — it must not be spelled
identically to a string literal.

---

### 31. A `text` flag with no default segfaults when the flag is not supplied

**Status:** **fixed in v0.4.6.** Found 2026-08-19 against `main`. Surfaced while
rewriting vox-fuzz's CLI onto the flag schema — the hand-rolled parser it
replaced had never exercised this path.

```vox
a flag called outdir is "-o" or "--out", it is a text.
Parse flags.
Print "got:{outdir}".
```

| Invocation | Result |
|---|---|
| no arguments | **segfault (139)** |
| `--out hello` | `got:hello`, exit 0 |
| declared `with default ""` instead | prints empty, exit 0 |
| declared `with default "xyz"` | prints `xyz`, exit 0 |
| a **number** flag with no default | fine |

An undefaulted `text` flag that the user does not supply is left holding
a null pointer; the first read dereferences it.

**LANGUAGE.md makes the default optional.** The Command-Line Arguments
section documents `with default ...` as one of two *optional* schema
modifiers ("Flags may be marked as required and/or given defaults"), so
a `text` flag without one is legal code — and it crashes.

**Family.** This is bug **#16** — *a declared-but-uninitialised `text`
variable segfaults on first read* — reappearing on a path that #16's fix
did not cover. #16's cure was to point an uninitialised `text` at a
shared empty string rather than leave it null; the flag-schema path
never got that treatment. Compare `emit_type_default` in
`src/codegen/vars.rs`, whose `Type::String` arm does exactly the right
thing for ordinary declarations.

**Severity: high.** It is a crash from a documented, legal declaration,
on the very first read, in the code path most likely to run before a
program does anything else. Any Vox CLI that declares an optional text
flag and does not pass it dies immediately.

**Fix direction:** give the flag schema's `text` slots the same default
`emit_type_default` gives an ordinary `a text called x.` — the shared
empty string — so an unsupplied flag reads as `""`. Check `buffer` and
any other pointer-backed flag type for the same gap while there.
Regression tests should cover every row of the table above, including
the passing rows: the `number` and `with default` rows are what isolate
the defect to undefaulted pointer types.

---

### 32. A flag read inside a function body is typed `boolean`, whatever it was declared as

**Status:** **fixed in v0.4.6.** Found 2026-08-19 against
`main`, immediately after #31, while rewriting vox-fuzz's CLI onto the
flag schema.

```vox
a flag called voxpath is "-V" or "--vox", it is a text with default "".
Parse flags.
a text called target is "unset".

To apply.
    Set target to voxpath.

apply.
```
→ `error: cannot assign boolean to 'target', which is a text`

**It affects every non-boolean flag**, not just text — a `number` flag
fails the same way. Only reads **inside a function body** are affected;
at top level the declaration's own type is still in scope, so the bad
path is never consulted. That is why the defect survived: the obvious
one-line test passes.

**Cause.** `src/analyzer/mod.rs` kept flags as a bare
`HashSet<String>` — names only, no types. Both type-query sites in
`src/analyzer/types.rs` (lines ~21 and ~235) therefore hardcoded:

```rust
} else if self.flag_variables.contains(name) {
    Some(Type::Boolean)
}
```

Every flag answered *boolean* to a type question, regardless of
`it is a text` or `it is a number`.

**Fix.** `flag_variables` becomes `HashMap<String, Type>`, populated
from `value_type` at declaration, and both sites answer with the
declared type. The other consumers only tested membership, so they moved
to `contains_key` unchanged.

**Why this and #31 were found together.** vox-fuzz's CLI hand-rolled its
own argument parsing in a `While` loop instead of using the language's
flag schema. Rewriting it onto the documented feature exercised the
schema properly for the first time and surfaced two defects immediately
— a null-pointer crash (#31) and this mis-typing. A documented facility
with no real user can carry bugs indefinitely.

**Regression test:** `tests/bugs_found_32_flag_type_in_function.vox` —
all three flag types round-tripped through a function body. It fails on
the unfixed compiler with the exact error above.

---

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

### 33. `is empty` on a `text` is always false — it tests the pointer, not the contents

**Status:** **fixed in v0.4.6.** Found 2026-08-20 while verifying the
documentation line #31's fix earned ("an unsupplied `text` flag … can be
tested with `is empty`") — the claim was written, then proven false
before it shipped.

```vox
a text called blank is "".
If blank is empty then, Print "IS empty". Otherwise, Print "NOT empty".
```
→ prints `NOT empty`

**It is specific to `text`.** The controls isolate it exactly:

| Case | Result |
|---|---|
| `[]` list `is empty` | correct (IS) |
| `[1]` list `is empty` | correct (NOT) |
| empty buffer `is empty` | correct (IS) |
| `"x"` buffer `is empty` | correct (NOT) |
| `""` text `is empty` | **wrong (NOT)** |
| unsupplied `text` flag `is empty` | **wrong (NOT)** |
| `""` text `is ""` equality | correct — the value really is `""` |

The spec promises the predicate on a text: LANGUAGE.md's own worked
example (`if 'output file' is empty then,` — a text filename) and the
flags section both use it.

**Root cause**, localised to two twin sites. `Property::Empty` in
`src/codegen/expr.rs` (~746, expression form) and
`src/codegen/statements.rs` (~2765, branch form) special-case buffers
and lists — read the size field at `[rax+8]` — and for every other type
fall through to `test rax, rax`. A text's value is a pointer to its
NUL-terminated bytes; the pointer is never null, so the predicate
compiles to "is this pointer null" and always answers false. `""` is a
real allocation whose first byte is NUL — the pointer test cannot see
that.

**Fix:** at both sites, a text operand now tests its first byte — with
a null pointer defensively redirected at the shared empty string rather
than dereferenced (`cmovz` on `get_empty_string_label`, no branch
needed). Buffers, lists, numbers and booleans are untouched. Both sites
also carried the `Expr::StringLit(s) | Expr::Identifier(s)` pattern —
the #19/#29 family, on plan 322's audit list — and lose it here: a
string literal is data, always takes the text path, and no longer
consults `variable_types` at all.

**Regression test:** `tests/bugs_found_33_text_is_empty.vox` — the full
matrix above plus a `While ... is empty` loop-condition case. Proven to
fail on the unfixed compiler on exactly the three text rows, every
control passing on both sides.

**Family:** #31/#32 — the flag schema's first real user (vox-fuzz's CLI
rewrite) keeps finding defects on the documented path nothing had
exercised.

---

### 34. A float outside ±2^63 prints as `9223372036854775808.372036854775808`, and one below ~1e-8 prints as `0.0`

**Status:** **fixed in v0.4.7** — the large-magnitude half
only: a float at or beyond 2^63 now prints its own exact decimal digits
instead of the saturated `9223372036854775808...` constant. This was
the wrong-DATA half of the bug. The small-magnitude half (a nonzero
value below the formatter's fixed 15-digit fractional precision still
prints `0.0`) is **not fixed** — it is a lost-precision problem in a
different part of the same routine, not a saturation, and needs a
variable-precision fractional path rather than the fixed-point exact
technique that fixed the large end; see the note after "Fix direction"
below. **Regression test:**
`tests/bugs_found_34_float_magnitude.vox` — proven to fail on the
unfixed compiler on exactly the large-magnitude rows (`over`, `negover`,
`atboundary`, and the same values through `"{x}"` interpolation and
`x as text`), with `belowboundary`, `one18`, `half`, and the IEEE-
rounding control (`roundctrl`) kept passing on both sides of the fix.
Found 2026-08-20 against released v0.4.6. Found
while probing which literal magnitudes are legal before teaching
vox-fuzz to emit aggressive ones (Josj: *"I wanna see
1243626351836374761.1224435542121323 ... I wanna make the compiler AND
the runtime cry"*). The first extreme value tried reproduced it.

```vox
a float called over is 10000000000000000000.0.
Print over.                      (9223372036854775808.372036854775808)
a float called half is over divide 2.0.
Print half.                      (5000000000000000000.0 - CORRECT)
```

**The stored value is correct; only the output path is wrong.** That is
what `half` proves: dividing the "broken" value by two yields exactly
5e18, so `over` really does hold 1e19. The defect is in float
formatting, not in the lexer, the parser, or arithmetic.

**It is not the literal.** `1000000000000000000.0 multiply 10.0`,
computed at runtime with no large literal anywhere in the source,
prints the same string.

**All three output paths share it** — `Print x`, `"{x}"` interpolation,
and `x as text` — which is expected if they funnel into one formatter.

| Value | Printed | Correct |
|---|---|---|
| `1000000000000000000.0` (1e18) | `1000000000000000000.0` | ✓ |
| `10000000000000000000.0` (1e19) | `9223372036854775808.372036854775808` | ✗ |
| `1e19 divide 2.0` (5e18) | `5000000000000000000.0` | ✓ |
| `0.0 subtract 1e19` | `-9223372036854775808.372036854775808` | ✗ |
| `0.1`, `0.0000001` | correct | ✓ |
| `0.000000000000000000001` (1e-21) | `0.0` | ✗ (see below) |

**The magic number is the tell.** 9223372036854775808 is exactly 2^63 —
`i64::MAX + 1`. The formatter converts the double's integer part
through a signed 64-bit integer, which saturates for any magnitude at
or beyond 2^63; the trailing `.372036854775808` is the fractional
remainder computed from the already-saturated value, which is why the
same digits appear after the point for every input.

**Second face, same formatter: small magnitudes vanish.** `1e-21`
prints `0.0` — but the value is not zero, as `is positive` confirms
(true for every exponent tested down to 1e-23). The formatter appears
to emit a fixed number of decimal places rather than choosing a
representation, so anything below its precision floor renders as `0.0`.
Lossy and silent, the same shape of defect as the high end.

LANGUAGE.md documents `float` as a 64-bit IEEE 754 double, whose range
is roughly ±1.8e308 with subnormals to ~5e-324. Both 1e19 and 1e-21 are
comfortably inside that and 1e19 is *exactly* representable, so this is
the implementation failing the documented type, not a limit of it.

**Fix direction:** find the float→text routine (shared by `Print`,
interpolation, and `as text`) and stop routing the integer part through
an i64. Print the double's own decimal representation — shortest
round-trip formatting if practical, otherwise at minimum a path that
does not saturate and does not silently flush small values to zero.
Regression tests must cover both ends and keep the correct rows above
as controls.

**What actually shipped, and what did not.** Only the large end was
fixed. At or beyond 2^63 the double is already far past 2^52, the point
beyond which a 52-bit mantissa has no room left for a fractional bit —
so every such value is an exact integer, computable from the raw
mantissa and exponent bits by schoolbook binary-to-decimal (write the
mantissa's decimal digits, then double the decimal digit array once per
bit of exponent past 52). That is exact — no floating point is involved
past reading the bits — and it only had to replace the one saturating
`cvttsd2si` used for magnitudes cvttsd2si can no longer represent; values
below 2^63 are untouched and still go through the original, already-
correct path. The small end is a different shape of problem: it is not
that a conversion saturates, it's that the fractional part is generated
at a fixed 15 decimal digits (`* 10^15`, `roundsd`), so any value whose
first significant digit falls past that point rounds to zero. Fixing it
needs the formatter to pick its fractional precision from the value's
own binary exponent (mirroring the large-end technique's mantissa/2^k
extraction, but multiplying by 5 instead of 2 and placing the decimal
point on the left) rather than swap one conversion instruction, and was
judged out of scope for this pass. It is filed as an open follow-up, not
closed by this entry.

**Note on scope:** correct IEEE rounding is NOT this bug.
`1243626351836374761.1224435542121323` printing as
`1243626351836374784.0` is a double holding what a double can hold, and
must stay passing.

---

### 35. `as a number` wraps silently on overflow — a positive numeral parses to a negative number

**Status:** **fixed in v0.4.7.** Found 2026-08-20 against
released v0.4.6, while probing the base-conversion surface before
teaching vox-fuzz to emit it — a surface no test and no example had
ever exercised. **Regression test:**
`tests/bugs_found_35_number_parse_overflow.vox` — proven to fail
unfixed (the three overflow-raise lines are silently missing from the
output), with i64::MAX, i64::MIN, a valid hex value, and the pre-existing
`"abc" as a base5 number` raise kept as controls that pass unchanged on
both sides of the fix.

```vox
a number called n is "9223372036854775808" as a number.
On error print "raised".      (never prints)
Print n.                       (-9223372036854775808)
```

**The boundary is exact, and the wrap is silent:**

| Input | Result | |
|---|---|---|
| `"9223372036854775807"` (i64::MAX) | `9223372036854775807` | ✓ correct |
| `"9223372036854775808"` (MAX+1) | `-9223372036854775808` | ✗ wraps to i64::MIN |
| `"99999999999999999999"` | `7766279631452241919` | ✗ arbitrary |
| `"ffffffffffffffffff"` as a hex number | `-1` | ✗ |

Every digit in these inputs is valid for its base, so the documented
"stops at the first character invalid for that base" rule does not
apply — parsing consumes the whole string and the accumulator wraps.

**Why this is worse than a wrong number.** The error flag is never
set, so `On error` cannot catch it, and the result is
indistinguishable from a real value: a program asking `is negative`
about a user-supplied numeral gets `true` for an input that was
positive. Compare the neighbouring cases, which the language *does*
signal: `"abc" as a base5 number` returns 0 **and raises**. So the
implementation already has a way to say "that did not parse" — it
simply is not used for the one malformed input that produces a
plausible-looking answer.

LANGUAGE.md §"Text to number" documents the invalid-character rule and
the supported bases but says nothing about magnitude, so there is no
documented licence for wraparound. `number` is a 64-bit signed integer,
and the conversion is the boundary where untrusted text becomes one —
exactly where a silent wrap is least acceptable.

**Fix direction:** detect accumulator overflow during conversion and
set the error flag (returning 0, or the saturated value, but the flag
is the point), so `On error` can catch it as it already can for a
wholly-invalid string. Regression tests must pin i64::MAX as a passing
control on both sides of the fix, plus MAX+1, a long decimal, and a
long hex string.

**Related, filed as an observation rather than a defect:**
`"12g5" as a hex number` gives 18 and raises nothing (matching the
spec exactly), while `"abc" as a base5 number` gives 0 and DOES raise.
Both are "invalid characters encountered", and LANGUAGE.md describes
them in one breath as not raising. The asymmetry is defensible — 0 is
ambiguous where a partial parse is not, so flagging it carries real
information — but the documentation should say so, since as written it
promises neither raises.

---

### 36. A width specifier in a format string reinterprets a float's bits, and leaks a text's address

**Status:** **fixed in v0.4.7** — the harm half: a width no
longer changes what a value IS. The width is not yet *applied* to
floats/texts (no padding primitive exists in coreasm for them), matching
the `value` path's behaviour; that residue is a cosmetic gap, tracked in
the entry below. Regression test:
`tests/bugs_found_36_format_width_type.vox` — proven to fail unfixed on
exactly the float/text/buffer rows, with the two-texts control printing
two different addresses (4210950/4210953). Found 2026-08-20 against
released v0.4.6. The
float half was found by a red-team agent attacking documented-but-
unexercised surfaces; the master reproduced it independently and the
controls below widened it to `text`, which is the worse half.

```vox
a float called f is 3.5.
Print "{f:06}".              (4615063718147915776 — the f64 bit pattern)

a text called t is "hi".
Print "{t:06}".              (4210942 — a POINTER)
```

**It is the WIDTH specifier, not padding in general, and not precision:**

| Expression | Printed | |
|---|---|---|
| `"{n:06}"`, n = 42 | `000042` | ✓ correct |
| `"{ready:06}"`, boolean true | `000001` | ✓ correct (booleans print 1/0, LANGUAGE.md:2229) |
| `"{f:.2}"`, f = 3.5 | `3.50` | ✓ precision alone is correct |
| `"{f:06}"` | `4615063718147915776` | ✗ the IEEE-754 bits of 3.5 |
| `"{f:8.2}"` | `4615063718147915776` | ✗ adding a width breaks the working precision case |
| `"{t:06}"`, t = "hi" | `4210942` | ✗ a pointer |
| `"{t:3}"` | `4210942` | ✗ same pointer, any width |
| `"{f}"` / `Print f` | `3.5` | ✓ unformatted is correct |
| `"{b:06}"`, buffer "hi" | `139755576881176` | ✗ a heap pointer |
| `"{v:06}"`, **`value`** holding 3.5 | `3.5` | ✓ right value (width ignored, not padded) |
| `"{w:06}"`, **`value`** holding "words" | `words` | ✓ right value (width ignored, not padded) |
| `"{l:06}"`, list `[1,2]` | `[1, 2]` | ✓ correct |

**Proof that the text case prints an address, not a value.** Two
distinct `text` variables holding the *same* content print *different*
numbers:

```vox
a text called t is "hi".
a text called u is "hi".
Print "{t:06}".              (4210942)
Print "{u:06}".              (4210945)
```

Same bytes, different addresses, different output. No value-based
explanation survives that.

**Why this is the worst class.** It is silent wrong data — no crash, no
diagnostic, no error flag — and for a `text` it prints a raw memory
address into program output, which is an information leak as well as a
wrong answer. A program formatting a table with `"{name:20}"`, the
obvious reason to use a width at all, emits pointers where it meant
words.

**Family:** #34. That bug is a float formatter routing the integer part
through an i64; this is the width path treating a non-integer slot as
an integer outright. Both live in the float/format layer, both are
silent, and both were found within a day of anyone actually exercising
formatting. They should be fixed together and their regression tests
kept adjacent.

**The working implementation is already in the compiler.** The
runtime-tagged `value` type formats correctly under a width — a `value`
holding 3.5 prints `3.5`, one holding `"words"` prints `words` — and so
do lists. To be exact, the dynamic path *ignores* the width rather than
applying it, so it has a cosmetic gap of its own; but it yields the
right value, which is the difference between a cosmetic gap and silent
wrong data. Only the *statically typed* slots (`float`, `text`, `buffer`)
are wrong. So the width path has a correct, type-aware rendering route
and simply does not take it when the type is known at compile time,
which is the one case where it has the most information. That is a
strong hint about where the fix goes and a ready-made oracle for it.

**Fix direction:** the width path appears to dispatch on the slot's raw
64 bits with no consultation of the value's type, while the precision
path clearly does consult it (`"{f:.2}"` is correct) and the tagged
`value` path clearly does too. Make width honour the same type dispatch
those already use: pad the value's rendered text, never its raw
representation. Regression tests must cover width
on number/float/text/boolean, precision alone, width+precision
together, and the two-texts-same-content control above, which is the
one that makes the diagnosis unambiguous.

---

### 37. A file's `readable` property is always true, whatever mode the file was opened in

**Status:** **fixed in v0.4.7.** Regression test:
`tests/bugs_found_37_file_readable_mode.vox` — opens the same file for
writing, appending, and reading in turn and prints `readable`,
`writable`, and `permissions` for each. Proven to fail unfixed on
exactly the writing/appending `readable` rows (both wrongly printed 1);
the `writable` rows on both sides of the fix, and the constant
`permissions` value across all three rows, are the controls. Found
2026-08-20 against released v0.4.6 by the same red-team agent that found
#36, after being steered off format strings onto the file-property
surface. Reproduced independently by the master, whose controls
narrowed the claim: it is `readable` alone, not the property pair.

```vox
open a file for writing called w at "/tmp/out.txt".
Print w's readable.        (1 — but the handle is write-only)
```

**`writable` is correct in every mode. Only `readable` is stuck:**

| Opened for | `readable` | `writable` | |
|---|---|---|---|
| reading | 1 | 0 | ✓ both correct |
| writing | **1** | 1 | ✗ `readable` wrong |
| appending | **1** | 1 | ✗ `readable` wrong |

`writable` distinguishes the modes correctly, which is the control that
matters: the mechanism for reporting a handle's mode exists and works,
so `readable` is not an unimplemented feature but a broken one.

**Why nothing caught it, stated exactly.** The pair has precisely one
test in the whole suite — `tests/044_file_io.vox:25-27` — and it reads
both properties on a file opened **for reading**, which is the single
mode in which this bug is invisible. The test is not wrong; it is just
the one row of the matrix that cannot fail. That is this register's
recurring lesson in its sharpest form yet: coverage of a *name* is not
coverage of its *behaviour*.

**The "it means the file's permission bits" reading is dead twice
over.** First, LANGUAGE.md:3332 defines it as *"Whether file is open
for reading"* — the handle's mode, in as many words. Second, the same
table carries a **separate** `permissions` property for the bits
(LANGUAGE.md:3336), and it works: the same handle reports `420`, which
is 0644 in decimal. A property that already exists elsewhere is not the
meaning of this one.

**Consequence.** The obvious defensive idiom — `If f's readable then,`
before reading — is exactly what this defeats: it passes on a
write-only handle and the read that follows fails at the OS level. A
guard that always says yes is worse than no guard, because code is
written to trust it.

**Fix direction:** report `readable` from the handle's recorded open
mode, the way `writable` already does — the two should share one source
of truth rather than one being derived and the other constant.
Regression tests must cover all three modes for BOTH properties, since
the `writable` rows are what pin the diagnosis, plus a `permissions`
row so the two concepts stay distinguished.

**Note for whoever fixes it:** check whether a file opened for reading
and writing (if the language offers such a mode) is expressible — the
matrix above only covers the three modes LANGUAGE.md documents.

---

### 38. The documented file property `exists` is a parse error

**Status:** **fixed**, found 2026-08-20 against released v0.4.6 by the
red-team agent on the file-property surface, alongside #37. Reproduced
by the master, who tested the whole table rather than the one property.
Closed 2026-08-21 by master ruling (with the language designer's
delegated judgment): **option 3** below — the row is removed and
LANGUAGE.md now documents the existing `On error` idiom in its place,
with a worked example covering both an existing and a missing path.
Option 2 (a path-level `exists` predicate) is noted in the manual as a
planned future addition rather than implemented now: it is a genuine new
feature, and features wait until the fuzzer runs autonomously. The parse
error itself — `Expected property name, got Exists` — is now a specific
diagnostic naming the idiom, raised unconditionally whenever `exists`
appears in property position (the parser tracks no per-variable type at
that site to gate on "is this actually a file handle", but `exists` has
no valid meaning for any other object type either, so the unconditional
reading is correct). Regression tests:
`tests/compile_fail/141_file_handle_exists_property.vox` (the
diagnostic) and `tests/390_file_exists_idiom.vox` (the documented
idiom).

```vox
open a file for reading called h at "/tmp/f.txt".
Print h's exists.
```
→ `error: Expected property name, got Exists`

**Seven of the eight documented file properties work. `exists` alone is
rejected:**

| Property | LANGUAGE.md | Result |
|---|---|---|
| `size` | 3330 | ✓ `3` |
| `descriptor` | 3331 | ✓ `3` |
| `readable` | 3332 | ✓ parses (but always true — see #37) |
| `writable` | 3333 | ✓ `0` |
| `modified` | 3334 | ✓ `1787209736` |
| `accessed` | 3335 | ✓ `1787209711` |
| `permissions` | 3336 | ✓ `420` (0644) |
| **`exists`** | **3337** | ✗ **parse error** |

LANGUAGE.md:3337 lists it in the File Properties table as *"Whether the
file exists | Boolean"*, with no note marking it unimplemented, unlike
other Not-Yet features which the document does flag.

**This is the mildest class of defect and should be recorded as such.**
It fails loudly at compile time, so no program can silently do the
wrong thing — the opposite of #36 and #37, which is why it is filed
below them. The cost is a documented feature nobody can use and a spec
that promises something the compiler does not provide.

**A design question the fix must answer first.** `exists` is odd among
these: the other seven describe an *open handle*, but a file that does
not exist cannot be opened, so `h's exists` on a successfully opened
handle is trivially true. The useful form is a question about a
**path**, asked before opening. So the fix is not simply "add the
missing property" — it needs a decision about what the construct means.
Three options, for whoever picks this up:

1. Implement it on the handle, where it is nearly always `true` and
   therefore nearly useless, but matches the table as written.
2. Provide it on a path instead (some `"/tmp/f.txt"'s exists` form),
   which is what a program actually wants, and correct the table.
3. Remove the row and document the existing idiom — opening inside an
   `On error` handler already answers the question.

Option 2 or 3, with the documentation corrected to match, is more
honest than making the table true by adding a property that answers a
question nobody asks.

---

### 39. A format string as the FIRST element of an inline collection makes every element print as a raw pointer

**Status:** **fixed in v0.4.7.** Found 2026-08-20 by an Opus
worker hand-verifying every format-string shape before writing an emitter
for it. Reproduced independently by the master, including the ASLR proof
below.

```vox
a text called base is "core".
print each item from ["{base}", "plain"].
```
→ prints two integers, e.g. `139924308365336` and `4210945`

**Two independent facts, both from the control table:**

| Collection | Format string at | Clause | Output |
|---|---|---|---|
| literal `["{base}", "plain"]` | 1st | `print each` | ✗ two integers |
| literal `["plain", "{base}"]` | 2nd | `print each` | ✓ `plain` / `core` |
| literal `["{base}", "plain"]` | 1st | `For each ... in` | ✗ two integers |
| literal `["{{lit}}", "plain"]` | escaped braces, no slot | `print each` | ✓ `{lit}` / `plain` |
| named `src`, same literal | 1st | `print each` | ✓ `core` / `plain` |
| named `src`, same literal | 1st | `print each ... treating` | ✗ two integers |
| named `src`, format 2nd | 2nd | `print each ... treating` | ✓ `plain` / `core` |
| named `src`, same literal | 1st | `element 1 of src` | ✓ `core` |
| literal `["alpha", "beta"]` | no format string | `treating` | ✓ `alpha` / `beta` |

1. The **first** element decides the rendering for the **whole**
   collection — put the format string second and both print correctly.
2. It is the **statically inferred** element type that is wrong. A named
   list under a plain `print each` is correct, so the runtime tag is
   right; attaching a `treating` clause to that *same* list breaks it,
   as does writing the list inline.

**Proof the integers are addresses.** The first number changes on every
run of the *same binary* — `139924308365336`, then `140253455810584` —
while the second is stable (`4210945`, static rodata). That is ASLR
moving a heap allocation. No value-based explanation survives it. So
this is silent wrong data **and** an information leak, the same class as
#36's `text` half.

**What it contradicts.** LANGUAGE.md §"Format Strings as Values"
(~3051): a format string "materializes into a fresh NUL-terminated
string … and survives being carried through lists". §"Format Strings
Everywhere" (~3076): "Every statement that takes a string value accepts
a format string … `treating` clauses. All sinks share one name
resolver." The two sinks named there are exactly the two broken rows.

**Family:** #17 and #18 — a format string's *type tag*, not its payload,
being got wrong. #17 was fixed by giving `Expr::FormatString` an
explicit `TAG_STRING` / `VarType::String` arm in `prescan_expr_tag` and
`infer_expr_type`. The list-literal and `treating` element-type
inference paths evidently consult a third inference that still lacks
that arm and falls through to integer — which is also what #18
describes. Likely the same missing arm in a third place.

**Fix direction:** find the element-type inference used by list literals
and by `treating`, and give it the same `FormatString → String` arm.
Regression test should cover all nine rows; the first-vs-second-position
pair and the named-list-with-and-without-`treating` pair are the two
that make the diagnosis unambiguous.

**Root cause, confirmed.** Three separate "classify by first element"
matches — none of them the two functions bug #17 fixed — all lacked a
`FormatString` arm: the `For each`/`print each` inline-literal element-type
inference (`src/codegen/statements.rs`, in `Statement::ForEach`'s
`Expr::ListLit` branch), the named-list-declaration inference that records
`list_element_types` for a `treating` clause to later consult
(`src/codegen/statements.rs`, in `Statement::VarDecl`'s `Expr::ListLit`
branch), and `element N of <literal>` (`src/codegen/print.rs`, in
`Expr::ElementAccess`'s `Expr::ListLit` branch). Each fell through to a
generic `_ => VarType::Unknown`/`None` default.

The named-list case was a coincidence, not a working path: `Unknown` for a
*named* list widens the loop variable to `Mixed`, which dispatches on the
still-correct runtime tag — so a plain `print each` over a named list with
a format-string element happened to print right. Attaching a `treating`
clause wraps that same loop variable in `Expr::TreatingAs`, and the
runtime-tag lookup (`mixed_element_tag_slot`/`expr_leaves_tag_in_r11`) only
matches a bare `Identifier`/`StringLit`, not `TreatingAs` — so the accidental
safety net doesn't reach through the wrapper, and it falls back to
`infer_expr_type`, which reports `Mixed` (untyped) and prints as an integer.
Once the named-list inference itself credits `FormatString → String`, the
loop variable is typed `String` (not `Mixed`) and both the plain and
`treating` spellings render correctly the same way — no `TreatingAs` unwrap
was needed.

For an inline literal, there is no named-list detour and no runtime-tag
fallback to coincidentally save it: `Unknown` there was just wrong, and
always rendered as `PRINT_INT`, regardless of position.

Fixed by adding `Expr::FormatString => VarType::String` (or
`Some(VarType::String)`) to all three matches — a format string always
materializes text, as established by bug #17. Position is irrelevant to
the fix: it types whichever element is first, format string or not, so a
format string second (already correct) and a format string first (now
fixed) go through the exact same arm.

**Regression test:** nine `.vox`/`.expected` pairs under
`tests/bugs_found_39_*` reproducing every row of the control table above.
Proven to fail on the unfixed compiler (`git stash` the fix, rebuild, run)
on exactly `bugs_found_39_literal_fmt_first`,
`bugs_found_39_for_each_fmt_first`, and `bugs_found_39_named_treating` —
each printed two raw addresses instead of `core`/`plain` (or `core`/
`PLAIN`) — with the other six rows (`literal_fmt_second`,
`escaped_braces_only`, `named_plain`, `named_treating_fmt_second`,
`element_access`, `no_format_treating`) passing on both the unfixed and
fixed compiler as controls.

---

### 40. `Write` of any scalar to a file segfaults — number, float, and boolean alike

**Status:** **fixed (diagnostic)** (0.4.8), found 2026-08-20 while
building vox-fuzz's stdin input generation — the generator needed to
write bytes to a file and tried the obvious thing. The analyzer now
refuses a scalar or `value` `Write` operand at compile time, naming the
operand, its type, and the working spelling; the segfault is gone.
Compile-fail cases `tests/compile_fail/write_number_to_file.vox`,
`write_float_to_file.vox`, `write_boolean_to_file.vox`, and
`write_value_to_file.vox` (all four compiled and crashed at 139 before
the fix); passing companion
`tests/bugs_found_40_write_text_and_format.vox` pins that text, buffer,
format-string, and copied-into-a-typed-variable operands still write.

```vox
open a file for writing called out at "/tmp/f.txt".
a number called n is 72.
Write n to out.
```
→ **segfault (139)**

Five lines, no dependencies, crashes every time.

**Every operand type, tested — it is not specific to `number`:**

| Written | Result |
|---|---|
| a `text` | ✓ writes the text |
| a `buffer` | ✓ writes its bytes |
| a format string `"{n}"` | ✓ writes the rendered number |
| a **`number`** | ✗ **segfault (139)** |
| a **`float`** | ✗ **segfault (139)** |
| a **`boolean`** | ✗ **segfault (139)** |

So the two pointer-backed types work and **all three scalars crash**,
which points at `Write` dereferencing its operand as a pointer
unconditionally: a text or buffer holds one, a scalar holds a value, and
the value gets used as an address.

**What the spec says.** LANGUAGE.md's file section documents `Write` for
text and buffer sources; it does not say a number is permitted. So the
defensible reading is that a number is simply not a valid `Write`
operand.

**That reading does not rescue this.** An unsupported operand should be
a compile-time error naming the problem — which is exactly what the
compiler does elsewhere, and generously: `append` rejects a number
source with "Buffer append requires a buffer source or format/literal
text", a clear diagnostic pointing at the fix. `Write` takes the same
category of mistake and crashes the generated program at runtime
instead.

So this is a diagnostics defect at minimum and a codegen defect at
worst: either reject it like `append` does, or define it and implement
it. A segfault is the one outcome that cannot be correct.

**Fix direction:** find `append`'s operand check in the analyzer — it
already knows how to phrase this — and give `Write` the equivalent. If
writing a number is meant to be supported, it needs to render like
`"{n}"` does rather than dereferencing the value as a pointer, which
the crash suggests is what happens now.

**What was done.** The first of those two: `check_file_write_operand` in
`src/analyzer/types.rs` refuses a named operand whose tracked type is
number, float, or boolean, with `Cannot write number n to a file; Write
takes text, a buffer, or a format string. Render it as text: Write
"{n}" to out.` — the exact statement that works, built from the
operand's and the file's own names. Rendering a scalar directly remains
an **open design option**: it is a language decision (what `Write true`
should put on disk, and whether a float follows the `"{x}"` formatter),
deliberately not taken here, and LANGUAGE.md now states the rule the
compiler enforces.

**A `value` operand is refused too** (master review). It is the same
defect wearing a runtime tag: `a value called gap is nothing. Write gap
to out.` segfaulted, a value holding a number segfaulted, and a value
holding text happened to write correctly. The compiler cannot tell those
apart — the type is only known at runtime — so the category goes whole,
exactly as `check_arithmetic_operand` refuses a value. Its message names
a *different* fix, and deliberately so: **`Write "{v}" to out` does not
work for a value.** On the file-write path that interpolation renders the
value's raw payload, so a text-holding value writes its pointer as a
decimal (`sensor` → `4210906`) and `nothing` writes `0`, while the print
path renders both correctly (`Print "{v}"` → `sensor`, `nothing`) — a
separate formatter defect in `Write`, not filed here, and worth its own
entry. The message therefore names the spelling that was verified on
both sides: copy the value into a typed variable (`a text called plain is
gap.`) and write that; `tests/bugs_found_40_write_text_and_format.vox`
covers it so the promise stays proven.

**Left open, deliberately:** a `list` or `map` operand still writes the
bytes at the collection pointer. That is garbage, not a crash, and a
different question from this one (what *should* writing a list to a file
mean?), so it stays a follow-up rather than riding along here.

**Note on how it was found:** by a human writing ordinary Vox, not by
the fuzzer. The generator cannot currently reach this shape because it
never writes to files — which is exactly the coverage plan 327 Part B is
adding, and `Write` of a non-text operand is now worth adding to it.

---

### 41. `buffer as text` aliases the buffer — resizing it leaves the text dangling, and reading it segfaults

**Status:** **fixed** (0.4.8), found 2026-08-20. `as text` on a
buffer now copies the buffer's bytes into a fresh dynamic buffer — the
same `_alloc_buffer` allocation format strings and the other
text-producing casts use, so exit cleanup tracks it identically — and
returns that copy's data area, so neither rewriting nor resizing the
source buffer can reach the text. Regression test
`tests/buffer_as_text_copies.vox`. Originally filed as: **use-after-free
in a language whose headline promise is memory safety**, the most
serious entry in this register.

```vox
a buffer called b is 512 bytes in size.
append "the quick brown fox jumps over the lazy dog" to b.
a text called t is b as text.
resize b to 4 bytes.
Print t.                     (segfault)
```

Eight lines. Nothing unusual about them — converting a buffer to text
and later resizing that buffer is ordinary code.

**The cause: `as text` returns a POINTER INTO THE BUFFER, not a copy.**
Demonstrated without any crash at all:

```vox
a buffer called b is 64 bytes in size.
append "first" to b.
a text called t1 is b as text.
Print t1.                    (first)
clear b.
append "SECOND" to b.
Print t1.                    (SECOND)
```

`t1` was never touched. A `text` silently changed because an unrelated
buffer was reused. That alone is a correctness bug of the worst kind —
silent wrong data with no diagnostic — before any memory is freed.

**The crash follows from LANGUAGE.md's own documented behaviour.**
§"Buffer Resizing" (3232) states: *"New buffer is allocated and old
buffer is freed."* So the text points at freed memory, and reading it is
a use-after-free.

**Control table:**

| Case | Result |
|---|---|
| text from buffer, then **shrink** the buffer | **segfault** |
| text from buffer, then **grow** the buffer | **segfault** |
| two texts from one buffer, then resize | **segfault** |
| text from buffer, then `clear` the buffer | survives, prints empty |
| plain text literal, unrelated buffer resized | survives, correct |

Both resize directions crash, which is consistent with the documented
free-and-reallocate. `clear` survives because it presumably zeroes in
place rather than reallocating — the allocation is still there, so the
pointer is still valid. The literal control proves the fault is in the
buffer-derived text specifically, not in resize generally.

**Why this outranks everything else here.** Vox's core claim is that no
program can be made to violate memory safety. This is a one-line road to
a use-after-free from ordinary code, with no unsafe construct, no
foreign function, and no hostile input required. A program that
processes lines from a file into a list of texts — a completely natural
shape — hits it the moment the buffer is reused or resized, which is
exactly what such a loop does.

**Fix direction:** `as text` on a buffer must COPY. The cheap
alternative — making the text keep the buffer alive — does not fix the
aliasing half, where `t1` changes because the buffer was rewritten, and
that is a correctness bug in its own right. A copy fixes both.

**How it was found:** a worker writing the invariant-detector tool in
Vox needed to read lines from a file into a list, hit behaviour it could
not explain, and started probing whether `as text` aliased. The master
reproduced it and found the dangling case. Worth noting that this came
from *writing an ordinary program in Vox*, not from fuzzing — the third
such find today, after #40 and the format-string bugs.

---

### 42. A buffer declared with a byte count reports `Text (dynamic)` from its `type` property

**Status:** **fixed** (0.4.8), found 2026-08-20 by the vox-fuzz
buffer claim ledger — the mapper hand-ran every property in the manual's
table and this one disagreed; adjudicated by the language lawyer as a
compiler bug before anything was filed.

```vox
a number called n is 3.
a buffer called buf1 is 16 bytes in size.
a buffer called buf2 is "seed".
Create a buffer called buf3 with size 16.
a buffer called buf4 is 16 bytes.
a buffer called buf5.
print n's type.      (Number (static))
print buf1's type.   (Text (dynamic)   — wrong)
print buf2's type.   (Buffer (static)  — right)
print buf3's type.   (Text (dynamic)   — wrong)
print buf4's type.   (Text (dynamic)   — wrong)
print buf5's type.   (Text (dynamic)   — wrong)
```

Repo build and installed 0.4.7 agree. Only the string-initialised form is
right; every sized spelling and the bare dynamic form are wrong, and they
are wrong in the *same* way, which is the tell.

**What the spec says.** LANGUAGE.md's `type` table: "Declared type name
plus `(static)` or `(dynamic)`", and the paragraph under it lists
`buffer` by name among the statically-typed kinds that "report their type
with `(static)` because the compiler knows the type from the
declaration". The manual then recommends the `is a <type>` predicate over
comparing the display string — but `If buf1 is a buffer then` is rejected
by the parser ("Expected a type noun (number, text, decimal, boolean,
list, or map) after 'is a'"), so for buffers the display string was the
only type test there was, and it lied.

**The strongest reading in the compiler's favour** — buffers are
heap-backed string-like objects, so `Text (dynamic)` is "honest about the
runtime tag" — fails on three counts: the table says *declared* type;
the paragraph names `buffer` explicitly; and the compiler gives two
different answers for two spellings of one declaration.

**Mechanism.** `emit_type_property` (`src/codegen/expr.rs`) keys off
`declared_types`. Every sized and dynamic spelling routes through
`Statement::BufferDecl` (`src/codegen/statements.rs`), which registered
the variable's runtime kind in `variable_types` but never inserted into
`declared_types`; the lookup missed, control fell through to the
runtime-tag dispatch, and a buffer pointer reads as a string tag. `is
"seed"` takes the `VarDecl` path, which already inserts — hence right.

**Fix.** `BufferDecl` now registers `Type::Buffer` in `declared_types`,
so all five spellings print `Buffer (static)`. The same omission on
`Get the current time into` is closed alongside it — a `time` now
reports `Time (static)`, as the :3202 table lists it. Regression test
`tests/buffer_type_property.vox` covers the five spellings, the
string-initialised control, and a `value` holding text (which must stay
`Text (dynamic)`).

**Still open from the same probe, for a human to decide:** there is no
correct buffer type *test* at all — `is a buffer` does not parse — so the
manual's own advice at :3208 cannot be followed for buffers. Either the
predicate grows a `buffer` noun or the manual stops recommending it here.

### 43. A conditional `value` return leaves a stale tag, and the caller dereferences an integer as text — segfault

**Status:** **fixed in 0.4.8.** Severity: **memory safety** — a
valid program, written in a shape the manual itself describes, crashes.
Regression test: `tests/value_conditional_return.vox`, proven to
segfault (139, no output at all) on unfixed `origin/main` and to pass
after. Found 2026-08-20 by the vox-fuzz VALUES claim ledger mapping,
discrepancy D1 — a mapper probing the manual's own limitation in the
direction the manual did not show; adjudicated a compiler bug by the
language lawyer.

```vox
To label with a value called v.
  If v is a number, return a value, v.
  Otherwise, return a value, 99.

a value called r is label of "hello".
print r.
```
→ **segfault (139)**, deterministic. Under gdb: SIGSEGV in
`_print_cstr_impl.count_loop` with `rdi=0x63` — the integer **99**
being dereferenced as a `char*`.

**The manual promised a wrong print and got a crash.** LANGUAGE.md's
`value` section carried a paragraph headed *"One limitation to know"*:
a conditional `value` return "does not track the return type, so the
value would print as a number." A wrong print is a defensible
limitation. It is not what happens. The opposite direction — a text
returned from a frame whose parameter held a number — does print a
stable garbage number (`4210906`, tagged `Number (dynamic)`), which is
the documented outcome; it is only the number-over-text direction that
crashes. README's "Memory Safety Model" and ROADMAP M0 ("no valid Vox
program may segfault") both forbid the result either way.

**The single-expression form is fine, which is the control.** `To label
with a value called v. Return a value, 99.` compiles and prints
correctly. Only the branch-nested return is affected, and that is
exactly the difference the mechanism turns on.

**Mechanism, in three steps.**

1. **The parser never puts the type on the signature.**
   `src/parser/functions.rs` "Gate B" feeds a `Return`'s
   `declared_type` into the function's `return_type` only for
   **top-level** body statements. A `Return` nested in an `If` lives in
   the conditional's own body vector, so Gate B never sees it and
   `return_type` stays `Type::Void`.
2. **So codegen never emits the tag.** `src/codegen/statements.rs`
   loads a `value` return's runtime tag into r11 only when
   `current_function_return_type == Some(Type::Value)`. With the
   signature reading `Void`, that load is skipped and r11 is never set
   for the return.
3. **And the caller writes r11 anyway.** The `value` declaration path
   in `src/codegen/statements.rs` stores `r11b` into the variable's tag
   slot via `emit_load_value_tag`, whose "already in r11" arm assumed
   r11 held a tag without ever consulting `expr_leaves_tag_in_r11`. The
   last instruction to touch r11 inside the callee was the predicate's
   load of the **parameter's** tag — `1`, meaning text. So the caller
   labels the integer payload `99` as text, and `print` dereferences
   it.

The generated assembly shows all three at once: the callee's
`movzx r11, byte [rbp-16]  ; load mixed element tag` for the `is a
number` predicate is the last write to r11, and the caller's very next
use is `mov [rel gvar_0_tag], r11b  ; value global tag`.

**The same root cause, memory-safe but silently wrong, in the plain-type
family:**

```vox
To choose with a number called n.
  If n is greater than 0, Return a text, "big".
  Otherwise, Return a text, "small".

print choose of 5.
```
→ prints `4198488` — the address of `"big"`, printed as a number, with
no diagnostic. Same missing signature; no crash only because a
plain-typed return carries no tag to corrupt.

**Fix.** Three parts, in the order that matters:

1. **`src/codegen/tags.rs` — make the crash impossible.**
   `emit_load_value_tag`'s no-tag arm now emits `mov r11, TAG_INTEGER`
   unless `expr_leaves_tag_in_r11` says the expression really did leave
   one. This alone turns the segfault into the wrong print the manual
   had promised, and it holds for any future expression that reaches
   that arm.
2. **`src/parser/functions.rs` — fix the cause.** `typed_returns`
   already collects *every* typed `Return` line in a body, nested ones
   included — the member rule reports against it — and it is cleared
   before each body is parsed. When Gate B left `return_type` at `Void`
   and every collected declaration agrees, that type is now adopted as
   the signature. Both the `value` case and the `Return a text` family
   are fixed by this one change.
3. **`src/codegen/statements.rs` — close the door the fix opens.**
   Before this, a function's body always ended at its first top-level
   `Return`, so a typed function could never fall off its end. A
   branch-only return can. The implicit epilogue now hands back the
   declared type's empty value — empty text, zero, or a `value` tagged
   as the number `0` — instead of whatever rax and r11 happened to
   hold, which for a `text` return would have been a fresh wild
   dereference.

**Left for a human: conflicting branch types.** A function declaring
`Return a text` in one branch and `Return a number` in the other has no
single type to put on its signature. The compiler accepts it today
with no diagnostic, and this fix deliberately does **not** change that:
picking either branch's type would mislabel the other one's payload,
and picking one is a policy choice, not a bug fix. Such a function
keeps the old `Void` reading — memory-safe, silently wrong. Making it a
compile error with a clear diagnostic is the obvious answer, but it is
a language decision and it belongs to whoever owns the spec.

---

### 51. A text initialised from a buffer WITHOUT the cast (`a text called t is b.`) points at the buffer's header and prints its capacity byte

**Status:** **fixed** (this branch), found 2026-08-20 by the vox-41 fix
worker probing sibling forms of bug #41. Silent wrong data: one character
where a whole line of text was expected, with no warning and no error.
Adjudicated by the language designer (TheJostler, 2026-08-21), who ruled
**option 1, copy**: helpful by default — the bare spelling means what `as
text` means and what `"{b}"` has meant since v0.1.17.

```vox
a buffer called b is 64 bytes in size.
append "first" to b.
a text called t is b.
Print t.                     (prints @ — not "first")
Print "expected: first".
```

**The cause: the bare `is <buffer>` initializer never adds
`BUF_DATA_OFFSET`.** A buffer is a struct whose 24-byte header is
`[capacity][length][flags]`, with the character data at
`struct + BUF_DATA_OFFSET`. The `as text` cast (`Expr::Cast` →
`Type::String`, `src/codegen/expr.rs`) knows this and, since #41, copies
the data area. The cast-free spelling takes the `VarDecl` path instead
and never reaches that code at all: it stores the **struct pointer**
into the text variable verbatim. Printing the text therefore reads the
first byte of the capacity field as a one-character C string.

**Proof it is the capacity field and not memory noise.** Change only the
declared size; the printed character tracks it exactly:

| Declaration | Prints | Byte |
|---|---|---|
| `a buffer called b is 64 bytes in size.` | `@` | 0x40 = 64 |
| `a buffer called b is 65 bytes in size.` | `A` | 0x41 = 65 |

Deterministic, reproducible, and a direct read of the header — not
uninitialised stack, not a dangling pointer.

**Why this is harder to catch than #41 was.** It is *stable across
mutation*. Clearing and refilling the buffer does not change what the
text prints, because the text is reading the header and never touches the
data. The "my value changed under me" tell that led to #41 being found
never fires here, so the only symptom is a wrong character that has
looked the same since the moment it was written.

The spelling is not exotic. A user who has met `a text called t is
"hello".` and `a buffer called b is "seed".` will reach for `a text
called t is b.` well before `a text called t is b as text.` — the
manual's Basic Conversions table (which, until #41, did not list
`buffer → text` at all) gives them no reason to expect the cast is
load-bearing.

**Control:** `a text called t is b as text.` is correct as of the #41
fix, and `"{b}"` has been correct since v0.1.17. Only the cast-free
initializer is affected.

**Fix options — a human decided between them:**

1. **Copy, like `as text` now does.** Route the bare `is <buffer>`
   initializer through the same copy the cast emits, so both spellings
   mean the same thing. Most forgiving, and consistent with `"{b}"`
   already doing exactly this.
2. **Reject it, naming the cast.** A compile error on `a text called t is
   <buffer>.` that suggests `as text`. Keeps one obvious way to spell a
   conversion, and makes the type change explicit at the point it
   happens — which is the argument the manual makes elsewhere for
   preferring explicit casts.

Either is defensible; what is not defensible is the current third
option, which is to silently print the capacity.

**The ruling: option 1, copy.** The designer's reason is "helpful by
default" — the sentence already reads as a conversion to anyone who wrote
it, and refusing it would demand a cast that does not change what the
sentence means. It sits comfortably with what the manual already says.
The Basic Conversions table (LANGUAGE.md:1918) gives `buffer → text`
exactly one meaning, "a copy of the buffer's bytes", added by the #41 fix
and not qualified by which spelling asks for it. Type immutability
(:531-532: "**A variable's type is fixed at its declaration and never
changes**", and every write to an already-declared name is checked
against that type) is untouched, because this is a *conversion into* a
text and not a *retype of* one: `t` is text before the write and text
after. And :3347-3351 ("Creating buffer from string") already reads a
cross-type initializer the same way in the other direction — `a buffer
called buf is "Hello".` copies the text's bytes into the buffer rather
than retyping `buf`.

**The sibling write sites, all of which had the same defect.** The
register found the declaration; the fix worker found four more ways to
land a cast-free buffer in a text slot, and every one of them stored the
struct pointer:

| spelling | before | after |
|---|---|---|
| `a text called t is b.` | `@` | `first` |
| `Set t to b.` | *compile error naming the cast* | `first` |
| `the t is b.` | *compile error naming the cast* | `first` |
| `'show it' with b.` (a `text` parameter) | `@` | `first` |
| `Return a text, b.` | `@` | `first` |

An empty buffer showed it too: `a buffer called untouched is 32 bytes in
size.` converted to a text that printed as a single space, 0x20 being a
32-byte capacity's low byte. There was never a case that did not read the
header — only cases whose header byte happened to be printable.

The two assignment spellings were refused rather than wrong, by the type
lock in `src/analyzer/types.rs` (`check_type_lock`) — which is option 2
already implemented, at two of the five sites, while the other three were
silently wrong. Under the ruling they convert like the rest, so the lock
now returns "allow" for a buffer flowing into a text and leaves the
conversion to codegen. Nothing else about the lock moves: every other
mismatched write is still an error, and `nothing` into a text is still
bug #57's error.

**Fix.** The copy sequence the cast emitted inline is now
`emit_buffer_to_text_copy` (`src/codegen/buffers.rs`) — one function,
called by the cast and by every cast-free site through the thin wrapper
`generate_expr_as_text` (generate the expression; if it is a buffer,
copy). The five sites reach it from `Statement::VarDecl` and
`Statement::Assignment` (`src/codegen/statements.rs`, both the local-slot
and global-mirror branches), `Statement::Return` (guarded by the
function's declared return type), and `emit_function_call`
(`src/codegen/functions.rs`, guarded by the parameter's declared type).
Writing the copy a second time per site is the mistake #58 was: two
spellings of one idea drift apart exactly where nobody looks.

The `VarDecl` arm needed one more guard, composed with #58's rather than
fighting it. That arm infers a name's type from its initializer's shape,
and #58 taught it to skip a name already typed buffer; a buffer
initializer flowing into a *text* is the mirror image, and without the
same skip `Set t to b.` would have relabelled `t` a buffer — turning a
conversion back into the retype the ruling says it is not.
`tests/387_...` prints `t's type` for exactly this reason.

**Tests.** `tests/385_text_from_buffer_copies.vox` (the register's repro
at 64 and 65 bytes, so the old answer's dependence on the capacity field
is what fails; the `as text` and `"{b}"` controls; and an empty buffer,
which must give empty text rather than a header read),
`386_text_from_buffer_at_every_write_site.vox` (the four siblings), and
`387_text_from_buffer_is_an_independent_copy.vox` (#41's class through
#51's spelling: clear-and-refill and then resize the buffer, and the text
must not move — the resize being the half that would otherwise be a
use-after-free — plus the type check above and a frame-local copy inside
a function, which is a different store in codegen). All three fail on
`origin/main`.

**Also true on this branch, and NOT fixed here:** `a text called n is 5.`
compiles and segfaults. The declaration path has no type check at all —
the type lock above only guards *writes to an already-declared name* — so
a number initializer lands in a text slot and the first read dereferences
`5`. It is a different bug from this one (this entry is about a
conversion the language defines; that is about a mismatch it does not),
it was outside this branch's brief, and it wanted its own register entry:
it got one, and its fix — see **### 65.** below.

---

### 47. `Seek ... to line N` lands on line 2 for every N of 2 or more, and a line past EOF never sets the error flag

**Status:** **fixed** (0.4.8), found 2026-08-20 by the vox-fuzz files
claim ledger — the mapper hand-ran the manual's Seeking rules against a file
whose lines were all different lengths, so the landing line could not be
mistaken; adjudicated by the language lawyer as a compiler bug before
anything was filed.

```vox
(the file is AA / BBBB / CCCCCC / DD / EEEEEEEE — five lines, five lengths)
Seek reader to line 1.   Read line -> AA          (right)
Seek reader to line 2.   Read line -> BBBB        (right)
Seek reader to line 3.   Read line -> BBBB        (should be CCCCCC)
Seek reader to line 5.   Read line -> BBBB        (should be EEEEEEEE)
Seek reader to line 99.  Read line -> BBBB        (past EOF; no error flag)
```

Every target above 2 lands at the start of line 2. It is absolute, not
relative — seeking twice gives the same place — and `Seek ... to byte N` is
correct throughout, so this is specific to the line form.

**What the spec says.** LANGUAGE.md's Seeking rules: "`Seek ... to line N`
moves to the first byte of line `N`", and "Invalid targets (e.g. line past
EOF, position < 1, invalid fd) set the error flag".

**The strongest reading in the compiler's favour** rescues only the second
half. `lseek(2)` past EOF is legal, so a line form that clamps rather than
fails would be consistent with the byte form, making the past-EOF rule an
intent the implementation never had. Nothing rescues the wrong offset: a
relative reading ("advance one line") would make two consecutive `Seek ... to
line 2` calls advance twice, and they do not, and would stop `line 1` from
rewinding to offset 0, and it does.

**Mechanism.** `_seek_fd_line` (`coreasm/x86_64/resource.asm:547`) kept its
line counter in **rcx** across the read syscall in `.seek_line_scan` — and
`syscall` clobbers rcx (and r11) with the return address. By the time control
reached `inc rcx / cmp rcx, r13 / jl`, the counter was a code address, which
compares far above any plausible line number, so the loop fell out at the
first newline. That is line 2 for every target, and it is also why the scan
never ran on to EOF: the past-EOF branch was simply unreachable. EOF detection
itself was never broken — a single-line file with no trailing newline does set
the flag, because that read returns 0 before the first newline is ever seen.

**Fix.** The counter now lives in `rbx`, which is callee-saved, already pushed
at entry and otherwise free, and the newline test reads the byte straight out
of `line_read_tmp` rather than borrowing a register for it. `_seek_fd_line`
exists only in the x86_64 runtime; no other architecture has the routine at
all. Regression test `tests/355_seek_line_positions.vox` runs the shape the
ledger found this with — a fresh handle for each of lines 1, 2, 3, 5 and 99 —
and then walks a single handle out of order, forward to line 5, back to line
3, and past the end, which is what shows the seek is absolute rather than a
scan that happens to accumulate. Both shapes fail on `origin/main`.

**How it was found:** vox-fuzz files claim ledger discrepancy D3, adjudicated
by the language lawyer.

---

### 48. A failing `Write` never sets the error flag, and `Read from` a dead handle sets nothing while `Read line from` sets it

**Status:** **fixed** (0.4.8), found 2026-08-20 by the vox-fuzz files
claim ledger; adjudicated by the language lawyer as a compiler bug (D4) with
the read-side inconsistency (D5) folded into it.

```vox
(a valid, writable handle on a device that fails every write with ENOSPC)
open a file for writing called sink at "/dev/full".
Write "x" to sink.
On error print "caught".      (never printed)
```

Four more failure modes, none of them caught: a write to a descriptor that was
never valid, to a handle opened for reading, to a handle whose `open` failed,
and to a handle that was closed. `open`, `Read line`, `Seek` and `Delete` all
set the flag on failure; `Write` never did, in any mode. **From inside Vox, a
write that did not happen was indistinguishable from one that did.**

The read side disagreed with itself in the same area. A failed `open` leaves
the handle with descriptor `-2`; against that handle `Read line from` fired
the handler and `Read from` reported a silent zero-byte read. Against a
descriptor that is merely invalid rather than negative (`2147483647`) both
fired — so `Read from` treated a negative descriptor as EOF and a
positive-but-invalid one as an error.

**What the spec says.** LANGUAGE.md lists "File operation failures" among the
catchable errors.

**The strongest reading in the compiler's favour** is that "file operation
failures" is scoped by its section, whose every example is a *read*, so `Write`
was never claimed to be checkable and the manual is merely silent. Silence is
not much of a defence in a language whose headline promise is resource safety,
and it does not touch the read-side half at all: nothing explains why two read
forms should disagree about the same handle.

**Mechanism.** Two independent omissions.

`FILE_WRITE_STR`, `FILE_WRITE_BUF` and `FILE_WRITE_NEWLINE`
(`coreasm/x86_64/file.asm:243/285/305`) issued their `write(2)` and then popped
their saved registers straight past rax without ever inspecting it — the
syscall's result was discarded. And `Statement::FileWrite`
(`src/codegen/statements.rs:~2196`) never touched `_last_error` either: it
`js`-skipped a negative descriptor in silence.

`Statement::FileRead` (`~2093`) took the same `js`-skip on a negative
descriptor and set nothing, where `Statement::FileReadLine` (`~2109`) emits
`mov qword [rel _last_error], 1` on the identical jump. One missing line.

**Fix.** A new `RECORD_WRITE_RESULT` macro records the outcome of every write
syscall in `_last_error` — the errno for a negative return, `EIO` for a short
write (Vox does not retry, so the missing bytes are lost, and the kernel gives
no errno for one), zero on success so a later handler cannot fire on stale
state. It runs before the pops, when rax still holds the return and rdx still
holds the requested count, and leaves rax untouched the way `FORK` does.
`FileWrite`, `FileWriteNewline` and `FileRead` each grew the negative-descriptor
error `FileReadLine` already had. Regression test
`tests/356_write_and_read_error_handling.vox` covers the `/dev/full` write in
all three forms, the read-only handle, the closed handle, both read forms and a
`Write` on a failed-open handle, and — the control that matters — asserts a
successful write does **not** fire the handler.

**How it was found:** vox-fuzz files claim ledger discrepancies D4 and D5,
adjudicated by the language lawyer.

---

### 44. `{list}` / `{map}` in a format string renders correctly only in `Print` position — everywhere else it prints a raw heap address

**Status:** **fixed** (unreleased, on top of 0.4.8). The reading taken is
**render everywhere**, on LANGUAGE.md:3133-3136 and :3157-3163 (see "What
the spec promises" below) — a list or map now renders through the SAME
routine `Print` uses in every sink. Regression tests
`tests/368_collection_in_a_text_initializer.vox`,
`tests/369_collection_in_the_buffer_sinks.vox`,
`tests/370_collection_written_to_a_file.vox`,
`tests/371_collection_as_a_function_argument.vox`,
`tests/372_collection_in_a_treating_clause.vox` and
`tests/373_quoted_list_name_in_a_format_string.vox`, all six proven to
print heap addresses on unfixed `main` and to pass after, each stable over
three consecutive runs. Found 2026-08-20 by the vox-fuzz collections-a
claim ledger (discrepancy D7) and adjudicated by the language lawyer.

**One more sink than the entry knew about.** `{'the running total'}` — a
`{name}` whose name is QUOTED — and a bare list literal `{[1, 2]}` do not
parse as `FormatPart::Variable` at all: `parse_format_string`
(`src/parser/expressions.rs:564`) hands anything `try_parse_expression`
accepts to `FormatPart::Expression`. Print's expression arm carried a
`Map` case from stage 1e2 and never a `List` one, so those two spellings
printed a heap address **in Print position too** — the one position this
entry reported as working. Fixing only the sinks below would have inverted
the bug, leaving `Print` the sole sink still wrong for a quoted list name.
`src/codegen/print.rs` gained the list twin of that map arm; test 373 is
that case.

```vox
a list called flat is [1, 2, 3].
print "print position: {flat}".      (print position: [1, 2, 3])
a text called captured is "{flat}".
print captured.                      (140237428518912   — wrong)
a buffer called sink is 64 bytes in size.
copy "{flat}" to sink.
print sink.                          (140237428518912   — wrong)
```

Maps behave identically: `print "{person}"` gives `{"name": "Ada"}`, and
`a text called captured is "{person}".` gives `140696375164928`.

The address **changes between runs** — two consecutive runs of the same
binary gave `140237428518912` and `140604117905408`. That puts this bug in
a class of its own for vox-fuzz: any generated program that interpolates a
collection into a non-print sink has wandering output, and the runner
classifies the program as nondeterministic. The generator would be
manufacturing a false finding, not reporting a real one.

**What the spec promises.** LANGUAGE.md:3054-3056 — a format string used as
a value "materializes into a fresh NUL-terminated string, so it works as a
text initializer or assignment". LANGUAGE.md:3081 — "Every statement that
takes a string value accepts a format string: `write`, buffer
`set`/`copy`/`append`, filesystem paths ..., `treating` clauses, and
function arguments." Both are stated without a type restriction, and both
are broken by a collection. (The neighbouring "all sinks share one name
resolver ... render identically" sentence at :3082-3085 does *not* carry
this: "special names" is fairly read as only the named specials that
sentence goes on to list. The two citations above are the ones that carry
it.)

**The language already has a considered answer for this shape.**
LANGUAGE.md:1224-1227 shows the same construct for a `thing` and makes it a
compile error with a fix-it:

```vox
a point called origin.
a text called note is "the point is {origin}".
(compile error: 'origin' holds a whole point, which only `Print` can interpolate
   Interpolate a field instead - point's fields are: x, y)
```

An aggregate interpolated into a non-print sink is refused, and the
diagnostic names the way out. Lists and maps get silence and a pointer.

**Mechanism.** `src/codegen/print.rs:88-101` special-cases
`VarType::List` and `VarType::Map` *inside the Print emitter*, calling
`_list_print` / `_map_print` on the pointer in `rdi`. Every other sink goes
through the shared resolver `resolve_format_variable`
(`src/codegen/format.rs:13`), whose result is handed to
`emit_append_runtime_value_to_buffer_ptr`
(`src/codegen/buffers.rs:75-106`). That function has arms for `Buffer`,
`String`, and `Float` — and no `List`/`Map` arm — so both fall through to
`_ => self.emit_append_formatted_int_to_buffer(fmt)`: the heap pointer,
formatted as a decimal integer.

That is exactly the per-sink duplication the resolver's own doc comment
forbids (`src/codegen/format.rs:4-12`): *"Special names, variable/global
lookup, and the constant fallback must never be re-implemented per sink:
that duplication is exactly how the buffer sinks shipped without
`{current time's hour}` support while Print had it."* Name resolution was
unified; **value rendering** was not, and the missing-arm bug has already
been paid for once — the `Float` arm at `buffers.rs:87-101` was added to
fix bug #1 in this register, and its comment says so in as many words
("The Print path never hit this because it formats through
`emit_formatted_value`, which already had a Float arm").

**Severity.** A silent wrong answer with no diagnostic — the failure mode
LANGUAGE.md:649-660 says the 0.3.0 identifier/literal split was designed to
eliminate. It costs a false nondeterminism finding on top of the wrong
answer.

**The fix — render everywhere, through one renderer.** The two readings on
offer were *render* (:3133-3136 and :3157-3163, which promise a format
string materialises into a string and that every string-taking statement
accepts one, neither with a type restriction) and *refuse like a thing*
(:1224-1227, where a whole `point` in a text initializer is a compile
error). Render wins, and the `thing` precedent is not evidence against it:
a `thing` has no runtime renderer at all — `emit_thing_print` writes its
fields out at COMPILE time from a layout the compiler knows and the
program does not carry, so there is nothing for a runtime sink to call. A
list and a map each have `_list_print` / `_map_print` sitting in the
runtime already. The manual refuses the thing because it cannot be done,
not because an aggregate ought to be refused.

So the renderer was redirected rather than copied. `_list_print` and
`_map_print` now emit through `RENDER_*` macros (`coreasm/x86_64/io.asm`)
instead of `PRINT_*`: with the new `_render_sink` (`core.asm`) at zero the
bytes go to stdout, instruction for instruction, as before; with it
holding a buffer pointer the same bytes are appended to that buffer, the
possibly-reallocated pointer stored back each time.
`_list_render_to_buffer` / `_map_render_to_buffer` are eight-line
redirections that set the sink, call the very routine `Print` calls, and
return the buffer — the `_buffer_append` / `_buffer_append_float`
contract, so the two new arms in
`emit_append_runtime_value_to_buffer_ptr` sit beside the Float arm as
equals. Every sink named at :3157-3163 goes through that one function, so
the text initializer, `set`/`copy`/`append`, `write`, filesystem paths,
`treating` clauses and function arguments were all fixed by those two
arms; nothing renders per sink.

Because the redirection is the renderer itself, the awkward cases come
free and identical in both sinks: nested lists, an empty list or map, a
mixed list's quoted strings and floats, a map holding a list, and a cyclic
list — which truncates at the shared 64-deep `_print_depth` budget and
writes the same `...` marker into a buffer that it writes to stdout. A
fixed-size buffer too small for the rendering truncates through
`_buffer_append_bytes`'s existing fixed-buffer path and sets the error
flag, rather than growing or faulting.

Refusing like a thing was the fallback if the render path could not be
unified. It could, so it was not taken, and a `thing` in a text
initializer is still the compile error :1224-1227 documents
(`tests/compile_fail/thing_interpolated_into_text.vox`, unchanged).

**Line numbers.** The two format-string citations above have shifted since
this entry was written: :3054-3056 is now :3133-3136 and :3081 is now
:3157-3163. The `thing` precedent is still at :1224-1227.

**Not affected today:** no vox-fuzz leaf emits a collection slot in a
non-print sink — `gen leaf format types` builds its `{hl{n}}` and `{hm{n}}`
slots into `Print` statements only. The corpus was clean, and with this
fix a leaf worker adding one gets stable output instead of a false
nondeterminism finding; a quoted collection name in a `Print` slot is now
safe to emit too.

---

### 45. A function with no declared return type is read back as an integer wherever its result lands untyped

**Status:** **fixed** (this branch), found 2026-08-20 by the vox-fuzz
collections-a claim ledger (discrepancy D5) and adjudicated by the language
lawyer, who found the defect is broader than the mixed-list case the ledger
reported.

```vox
To 'opaque label'. Return "hi".
print 'opaque label'.               (4198488   — wrong)
a text called saved is 'opaque label'.
print saved.                        (hi        — right)
```

Four lines, no list in sight. `'opaque label'` returns a text; printed
directly it prints `4198488`, the rodata address of `"hi"`. Routed through
a **declared** `text` first, it prints `hi`. The returned value is intact —
the read is what is wrong, and it is wrong precisely where nothing supplies
a type.

The mixed-list case the ledger found is the same confusion reaching a list
slot, and declaring the return type fixes that too:

```vox
To 'opaque label'. Return "hi".
To 'declared label'. Return a text, "hi".
a list called items is [].
append 'opaque label' to items.
append 'declared label' to items.
print element 1 of items.           (4210906   — wrong)
print element 2 of items.           (hi        — right)
```

`is a number` fires on element 1 and `is a text` does not: the slot was
written with a conservative `TAG_INTEGER` guess. The address is **stable
across runs** (4210906, 5/5), because it is a static rodata address — so
the wrong answer looks like data, not like a crash.

**This is type confusion, not a memory-safety fault.** The pointer is never
dereferenced as an integer nor an integer as a pointer; it is a valid
pointer handed to the wrong formatter. Nothing segfaults, and it does not
belong in #41's class.

**What the spec says.** LANGUAGE.md:649-660 describes this exact shape as
the thing the 0.3.0 identifier/literal split was written to kill: *"a
function pointer, printed as a number, silently. No error, no warning; the
program runs and gives a wrong answer that looks like data."* And
LANGUAGE.md:2233-2235 promised, until this branch, that an unprovable value
appended to a list "is always read back as what it is rather than silently
reinterpreted" — flatly contradicted twenty lines later at :2250-2254,
which concedes the `TAG_INTEGER` guess and narrows the promise to "when it
really is a number". The manual half is fixed on this branch (:2233-2235
now carries the same hedge and points the reader at declaring the return
type); this entry is the compiler half.

**Fix direction.** The honest fix is a rejection at the widening/untyped
site, not a wider guess. Precedent: `src/analyzer/things.rs:817`
(`push_whole_thing_not_interpolable`) refuses a construct codegen cannot
render and names the way out in the diagnostic. The same shape here — *"'opaque
label' has no declared return type, so its result is read as a number here.
Declare it (`Return a text, "hi".`), or assign it to a declared variable
first."* Guessing `number` and staying silent is the one option the
language's own stated philosophy rules out. Full runtime tag propagation
(stage 1d, `docs/COLLECTIONS_ROADMAP.md`) fixes it properly; the rejection
is what can ship before then.

**Which positions are actually untyped.** Hand-run before the fix, the
"read as a number" fault is not everywhere a call appears — it is exactly
the positions that store or render a value with no declared type of their
own. Two positions that look untyped are not, and both keep working
unchanged:

| position | before the fix |
|---|---|
| `print 'opaque label'.` | `4198488` — wrong |
| `print "got {'opaque label'}".` | `got 4198488` — wrong |
| `append 'opaque label' to items.` | element reads `4210906` — wrong |
| `a list called items is ['opaque label', …].` | `4210906` — wrong |
| `set element 1 of items to 'opaque label'.` | `4210906` — wrong |
| `set labels's "first" to 'opaque label'.` | `4210906` — wrong |
| `a value called label is 'opaque label'.` | `4210906` — wrong |
| `a text called saved is 'opaque label'.` | `hi` — **right** |
| `the saved is 'opaque label'.` (reassignment) | `hi` — **right** |
| `'announce label' with 'opaque label'.` (a `text` parameter) | `hi` — **right** |
| `if 'opaque label' is "hi",` | `same` / `diff` — **right** |

The argument position was the surprise. An argument is *not* untyped: the
callee's parameter declares its own type, and that is what the result is
read as, so the rejection deliberately stops short of it. A comparison
against a typed operand likewise settles the read. The rule the fix
implements is therefore narrower than "reject every untyped call": it is
*reject where the position supplies no type*.

**Fix.** One set, `untyped_result_functions`, filled in the analyzer's
signature pre-pass beside `function_signatures` (`src/analyzer/statements.rs`)
so a call above the definition is judged the same as one below it. A
function joins it when its declared return type is `Void` **and** its body
hands a value back — a `Return <expr>` at any depth, since bug #43
established the only `Return` can sit inside an `If`. A function with no
value-returning `Return` at all is deliberately excluded: it returns
nothing, which is a different question and a different diagnostic.

Everything else lives in `src/analyzer/untyped_returns.rs`:
`untyped_call_result` names the callee behind an `Expr::FunctionCall` or a
zero-argument name in expression position (plan 270 G4), and
`reject_untyped_call_result` pushes the diagnostic. The seven rejection
sites are one call to it each — `Statement::Print`, `FormatPart::Expression`,
`Statement::ListAppend`'s list path, `Statement::ElementSet`,
`Statement::MapSet`, `Expr::ListLit`, `Expr::MapLit`, and a `value`
declaration or `Set` — so the rule reads in one place.

The caret is put on the call, not the definition: `find_symbol_location`
takes the first textual hit for a name, which for a function is always its
own `To` line, so `find_call_site_location` excludes that line first.

**The manual.** LANGUAGE.md's mixed-list section documented the old guess
as a residual limitation and gave a worked example of it (`To five with a
number called x. Return x add 1.` appended to a list, printing `5`). That
example is now a compile error, so the section is rewritten: a `value` is
the everyday opaque element (its tag genuinely travels with its payload),
an undeclared-return call is refused with both ways out, and stage 1d is
named as what would let such a call carry its own tag. A new "Reading a
result" subsection under Functions states the rule where the author is
looking when they decide whether to write `Return a <type>,`.

**Tests.** Compile-fail fixtures
`tests/compile_fail/130_print_undeclared_return.vox`,
`131_append_undeclared_return_to_list.vox`,
`132_map_value_undeclared_return.vox`,
`133_format_hole_undeclared_return.vox`,
`134_list_literal_undeclared_return.vox`,
`135_value_declaration_undeclared_return.vox` and
`136_set_element_undeclared_return.vox`, each pinning the position clause
as well as the message. `133`'s also pins `7:14`, its caret's
file:line:column: a call may legitimately sit inside a text literal
(`"got {'opaque label'}"` is an interpolated call), which is the one place
#46's "a match inside a literal is a coincidence" rule has to be stepped
around rather than obeyed - see the composition note in that entry. Passing controls
`tests/374_undeclared_return_into_declared_variable.vox` (declaration,
interpolation of the declared variable, reassignment, and appending it),
`tests/375_undeclared_return_as_an_argument.vox` (the position that was
never broken), and `tests/376_declared_return_reads_everywhere.vox` (a
declared return read back correctly in all six refused positions).

`tests/155_unknowable_append_widens.vox` and
`156_alias_of_mixed_dispatches.vox` were written on the rejected
construct — they proved that an element the compiler cannot type widens
the list to mixed, using an undeclared-return function as the opaque
value. The property is unchanged and still worth testing; both now use a
`value`, which is opaque in exactly the same way and carries the tag the
function never did.

**Not closed by this fix:** a function with **no** `Return` at all
(`To ping. Print "pong".`) still reads back as whatever its last
instruction left in the accumulator — `print ping.` prints `pong` then
`1`. It is the neighbouring shape, not this one (nothing was returned, so
there is no returned type to declare), and it wants its own diagnostic. An
undeclared-return function exported through a `.lib` is also out of reach:
the `.lib` records no `returning` clause for it, which is exactly what a
procedure records, so the two cannot be told apart without the body.

---

### 46. The diagnostic caret can land inside a comment

**Status:** **fixed** (this branch), found 2026-08-20 by the language
lawyer during adjudication of the vox-fuzz collections-a claim ledger — every probe file
in that ledger opens with a header comment quoting the token it is testing,
and the carets were pointing at the header instead of the code.

```vox
(mentions hello here)
a list called items is [].
append hello to items.
```
```
error: Unknown variable: hello
  --> repro.vox:1:11
    |
  1 | (mentions hello here)
    |           ^--- here
```

Three lines. The error itself is right — `hello` on line 3 is an unquoted
bare word, which LANGUAGE.md:645-668 defines as an identifier, and there is
no variable `hello`. Only the location is wrong: `1:11` is the word `hello`
**inside the comment on line 1**. The offending token is on line 3, column
8.

**Mechanism.** `find_symbol_location` (`src/analyzer/scope.rs:194-220`)
locates a diagnostic from the symbol's *name*, not from a span: it walks
`source.content.lines()` and takes the first `line.find(&pattern)` hit for
`{name`, then `"name"`, then bare `name`. It is a plain text search over
raw source with no awareness of comments or string literals, so the first
textual occurrence wins wherever it sits. `push_unknown_variable`
(`:263-290`) routes through `find_use_site_location` (`:143-152`), which
tries to anchor on the failing read rather than the declaration (plan 318
§3) — but its pattern list is the same one and it falls back to
`find_symbol_location`, so a comment mentioning the name still outranks the
real use site.

**Why it matters more than it looks.** It is a trap laid specifically for
the people who document their repros. Every probe under
`docs/ledger/probes/` opens by naming the construct under test, so every
one of them with a symbol-located diagnostic mis-points — including the D2
probe in this very ledger, whose caret lands at `D2.vox:4:56`, in the
middle of its own header comment. A reader who trusts the caret looks at a
comment, finds nothing wrong there, and starts doubting the diagnostic
instead of the code. The misleading-diagnostic class is cheap to fix and
expensive to leave.

**Fix direction.** Give the diagnostic the token's real span — the lexer
already has it, and `push_error_with_hint_at` (`:247-261`) is the existing
door for a caller holding a genuine `SourceLocation`. Failing that, make
the source scan skip comment and string spans; `find_pattern_location`
already carries exclusion machinery (a declaration line to avoid, a
`guard_against_called` flag), so the shape is not new. Regression test is
the three lines above.

**The real span was not available.** The preferred fix — hand
`push_error_with_hint_at` a genuine `SourceLocation` — has nowhere to get
one for this family. `Expr::Identifier` is a bare `String`
(`src/parser/ast.rs:89`), and no statement carrying an identifier carries
a location either: the only spans in the AST are `ThingDefinition`'s
`line` and `FunctionDef`'s two body-ended-early markers, none of which
reach an unknown-variable or unknown-function error. The lexer's
`TokenInfo` has the line and column, and the parser drops them at every
expression site. Threading a span through `Expr` is a compiler-wide
refactor — parser, analyzer, codegen and every test that builds an AST by
hand — so nothing was converted, and the fix is the fallback done
properly.

**Fix.** Two defects, one scan.

`classify_lines` (`src/lexer/regions.rs`) reads the source the way
`Lexer::tokenize` does and answers, for every byte, whether it is code,
inside a `( … )` comment, or inside a text literal. It mirrors rather
than approximates: comments nest and span lines, a quote inside a comment
opens nothing, a parenthesis inside a text literal or a character literal
opens nothing either, and an unclosed comment runs to end of file — the
`'` cases ask the lexer's own `is_char_literal` / `is_single_quoted_
identifier` lookahead rather than guessing. A quoted identifier's content
counts as code, because it is a name. `SourceFile` computes the map once
and answers `region_of(line, start, end)` (`src/errors.rs`).

`find_pattern_location` (`src/analyzer/scope.rs`) — the scan every
symbol-located diagnostic ends up in — now refuses a match whose symbol
sits in a comment, and runs its pattern list **twice**: once for code
only, then once allowing a text literal, so a hit in real code always
outranks an earlier hit inside a literal. Only a pattern that asks for a
literal (`{name` for interpolation, `"name"` for the literal itself) can
land in the second pass, and interpolation is undisturbed: a name that
appears only as `{name}` inside a text still anchors there.

`find_symbol_location` — the terminal fallback for the whole family, and
the one function in the file with **no word boundaries at all** — now goes
through `find_pattern_location` instead of running its own bare
`line.find`. That closes the substring anchoring the #55 worker hit
(symbol `n` anchoring on the `n` inside `print`) everywhere at once, and
makes the occurrence counter see every match on a line rather than only
the first. The pre-fix scan survives as `find_mention_location`, reached
only when the name occurs nowhere in code at all: a caret on a comment is
poor, an error with no `-->` line is worse, and "point at something rather
than nothing" is this file's existing policy.

**Tests.** Compile-fail fixtures
`tests/compile_fail/137_caret_skips_a_comment_mention.vox` (the three
lines above, caret pinned at 3:8), `138_caret_skips_a_text_literal_
mention.vox` (`Print "hello".` above the use), `139_caret_matches_a_whole_
word_only.vox` (`n` against `print`) and `140_caret_skips_a_multi_line_
comment_mention.vox` — each `.err` pins the file:line:column, so a caret
that drifts back fails the corpus. Twelve unit tests in
`src/lexer/regions.rs` cover nesting, multi-line comments, escapes,
character literals holding a `(`, quoted identifiers, multi-byte
characters and row alignment with `str::lines`; the last of them pins the
classifier against the lexer itself — no token the lexer emits may start
inside what the classifier calls a comment.

**Not closed by this fix:** the caret still points at *an* occurrence of
the name, not at the token that failed. Where a name is used twice in
code, the occurrence counter picks between them by error order, which is
right for the common case and a guess in the rest. Only real spans fix
that, and they need `Expr` to carry one.

---

### 49. `For each` over a scalar segfaults; over a map or a buffer it silently iterates garbage

**Status:** **fixed** (this branch), found 2026-08-20 by the vox-fuzz
collections-b claim ledger discrepancies D3 + D4 — the mapper hand-ran
every collection kind against LANGUAGE.md's supported-collections list and
two of them were neither refused nor handled; adjudicated by the language
lawyer as one compiler bug, **memory safety, certain**, before anything was
filed.

The whole program is two tokens long:

```vox
print each part from 4.          (segmentation fault, exit 139)
```

Deterministic across runs, and it is not the literal that matters:

```vox
a number called gauge is 4.
print each part from gauge.      (segfault)

For each part in gauge,          (segfault)
    print part.

a list called out is [].
append each part from 4 to out.  (segfault)

a text called word is "hello".
print each part from word.       (segfault)
```

The quiet half is worse. Nothing crashes, nothing is flagged, and the
answers are garbage:

```vox
a map called scores is {"a": 1, "b": 2, "c": 3}.
print each entry from scores.    (prints 0, 0, 3)

a buffer called sink is "abc".
print each part from sink.       (prints 6513249, 0, 0)
```

`6513249` is `0x636261` — the bytes `abc` read as a qword.

**What the spec says.** LANGUAGE.md's "Supported collections" list (2803–
2806) names exactly three: a list, a range, and `arguments's all`. A
number, a text, a buffer and a map are none of them, and the manual
documents map iteration only through `'s keys` and `'s values`. There is no
reading under which the segfault is correct — Vox's standing promise is
that no program, however silly, violates memory safety.

**Mechanism.** A `Statement::ForEach` got no collection-kind check at all.
The analyzer arm (`src/analyzer/statements.rs`) only called
`analyze_expr(collection)`, which checks that the name is *defined* and
nothing about its shape. Codegen (`src/codegen/statements.rs`) then treats
the collection's value as a list pointer and unconditionally emits `mov
rax, [rax + 8]` to read the element count out of the list header. For a
number that dereferences the number itself — address `4` — hence the
crash. For a map or a buffer the pointer is real, so the load succeeds and
reads whatever that object keeps at offset 8 as an element count: the
3-entry map iterated 3 times, and the buffer's payload came back as an
integer. The analyzer already rejects the neighbouring mistake — `element 1
of <a number>` is a clean compile error from
`analyzer/expressions.rs` — so the machinery existed and was simply never
applied to the `each` clause.

**Fix.** A new `non_collection_kind` predicate (`src/analyzer/scope.rs`)
names the kind of a collection the analyzer can PROVE is not walkable, and
the `ForEach` arm rejects it with `Loop collection must be a list: <name>`
plus a hint — for a map, the hint names `'s keys` and `'s values`.

It is deliberately a **known-scalar rejection, not a list whitelist**. Vox
is dynamically typed and this pass cannot see the shape of an untyped
parameter, a `value`, a function result or a property read, all of which
iterate correctly today and all of which a whitelist would have broken. It
refuses only a literal number/float/flag/text/map, or a name it has
positively categorised as a number, float, flag, text, buffer or map.
Superseded in v0.4.15 by #104: a buffer is now a legal `each ... from`
collection walked byte by byte; `compile_fail/097` became run test 595.

**Tests.** Compile-fail fixtures
`tests/compile_fail/095_foreach_over_number.vox`,
`096_foreach_over_text.vox`, `097_foreach_over_buffer.vox` and
`098_foreach_over_map.vox` (the last pinning the `'s keys` hint), and the
passing control `tests/355_foreach_supported_collections.vox`, which
iterates a list two ways, an inline range, `arguments's all`, and an
`append each ... to` sink.

**Not closed by this fix:** a file and a timer are heap/handle kinds the
same clause will still walk without complaint. They are outside the
ledger's finding and outside this branch; the predicate has an obvious
place to grow when someone maps them.

---

### 50. A bare `otherwise` is rejected after any base action except `append`

**Status:** **fixed** (this branch), found 2026-08-20 by the vox-fuzz
collections-b claim ledger discrepancy D2 — the mapper found the generator
already carried a comment recording that bare `otherwise` "does not work
after print" and had shaped its coverage around it; adjudicated by the
language lawyer as a compiler bug, **high**, rather than a manual
tightening.

```vox
a number called gauge is 8.
print gauge, but if gauge is greater than 50 print "high", otherwise print "low".
```
```
error: Expected a statement, got Otherwise
```

The three neighbouring spellings all compile and run:

| sentence | result |
|---|---|
| `print gauge, but if … print "high", but otherwise print "low".` | `low` |
| `append 1 to kept, but if … append 7, otherwise append 9.` | `[9]` |
| `append 1 to kept, but if … append 7, but otherwise append 9.` | `[9]` |

It was never print-specific — `increment n, otherwise increment n` failed
identically. `append` was the outlier that worked.

**What the spec says.** LANGUAGE.md:2960 ("An optional `otherwise` clause
provides a final alternative") and :2966 ("`otherwise` provides a catch-all
alternative") name the clause without qualification, in a section that
states at :2937 that `but if` works "over any base action". :393 and :399
document the bare clause again. The manual never spells it `but otherwise`.

**Mechanism.** `parse_conditional_suffix`'s chain-continuation guard
(`src/parser/control_flow.rs`) accepted only `Token::But | Token::Comma |
Token::And` and broke out of the loop on anything else — including the
`Otherwise` it was about to need. The branch parser reaches that guard by
two different routes. Every non-`append` branch goes through `parse_block`,
whose trailing-comma arm deliberately consumes the comma and stops **on**
`Otherwise`, leaving the guard to see a token it did not accept. The terse
`append` branch (`parse_terse_append_branch`) leaves the comma in place, so
the guard saw a `Comma`, consumed it, and reached the `Else | Otherwise`
arm that had been sitting there working all along. Hence one base action
that worked and every other one that did not.

**Fix.** `Token::Else | Token::Otherwise` join the guard. Because
`parse_block` already ate the separator in that case, the loop body must
not advance over the keyword as though it were one — a bare alternative is
the clause keyword itself, not a separator standing in front of one — so
the separator consume is now skipped when the loop is already sitting on
`Else`/`Otherwise`. Widening the guard alone would have skipped the keyword
and left the branch's own action current, trading the parse error for a
wrong parse.

**Tests.** `tests/356_bare_otherwise_after_print.vox` (both spellings, plus
a chain whose condition holds, so the test says *which* branch ran),
`tests/357_bare_otherwise_after_increment.vox` (each branch counting into
its own tally), and the control
`tests/358_bare_otherwise_after_append.vox`, which pins that the route that
already worked still produces `[9, 9, 7]`.

---

### 52. Any text-valued special name built into a buffer segfaults — `copy "{arguments's first}" to built`

**Status:** **fixed** (unreleased, on top of 0.4.8). Severity: **memory
safety** — a legal program, in the exact shape LANGUAGE.md:3158-3161
promises, crashes. Regression test:
`tests/bug52_argv_property_into_buffer.vox`, proven to segfault (139, no
output at all) on unfixed `origin/main` and to pass after; plus a codegen
unit test (`src/codegen/tests.rs`) that locks the instruction ordering
without assembling. Found 2026-08-21 by the vox-fuzz Input/Output claim
ledger (discrepancy D1), master-reproduced on 0.4.8.

```vox
a buffer called built is 64 bytes in size.
copy "{arguments's first}" to built.
Print built.
```
→ **segfault (139)**, deterministic, with arguments and without.

**The matrix, each case its own program, run as `./case alpha beta` on
`origin/main` and on the fix:**

| built into a buffer | 0.4.8 | fixed |
|---|---|---|
| `copy "{arguments's first}"` | 139 | `alpha` |
| `copy "{arguments's second}"` | 139 | `beta` |
| `copy "{arguments's last}"` | 139 | `beta` |
| `copy "{arguments's name}"` | 139 | `./copy_name` |
| `copy "{arguments's all}"` | 139 | an address (see below) |
| `copy "{arguments's raw}"` | 139 | an address (see below) |
| `copy "{environment's first}"` | 139 | `SHELL=/bin/bash` |
| `set built to "{arguments's first}"` | 139 | `alpha` |
| `append "{arguments's first}" to built` | 139 | `alpha` |
| `copy "{arguments's count}"` | 3 | 3 |
| `copy "{environment's count}"` | 109 | 109 |
| `copy "{current time's hour}"` | 23 | 23 |

Every text-valued special name crashed; every numeric one did not. All
three buffer verbs crashed, because all three route through one sink.

**The controls say it is the sink, not the property.** `Print
"{arguments's first}"` and `write "{arguments's first}" to <file>` are
both fine, so the property itself resolves correctly. The type split in
the table looks like the story and is not: it is a split by which
register the resolution happens to touch.

**What the spec promises.** LANGUAGE.md:3158-3161: "All sinks share one
name resolver, so special names like `{arguments's first}` and `{current
time's hour}` ... render identically whether the result is printed,
written to a file, or built into a buffer." The buffer sink is named by
that paragraph's own list at :3155-3157. README's "Memory Safety Model"
and ROADMAP M0 ("no valid Vox program may segfault") forbid the outcome
independently of what the paragraph promises.

**Mechanism — a clobbered destination register, not a bad string.**
Every `_buffer_append_*` helper takes the destination buffer in `rdi`
(`coreasm/x86_64/resource.asm:1628-1631`).
`emit_format_parts_into_buffer` (`src/codegen/format.rs:110-169`,
pre-fix) loaded the destination into `rdi` at the *top* of each part
(`:125`), then resolved the part's value, then appended. But resolving an
argv property means calling `_get_arg`, which takes its **index in
`rdi`** (`coreasm/x86_64/args.asm:55-68`) — so
`generate_expr(Expr::ArgumentFirst)` (`src/codegen/expr.rs:1416-1425`)
emits `mov rdi, 1` straight over the destination pointer. The emitted
assembly for the three lines above:

```asm
    mov rdi, [rbp-8]
    push rdi  ; save destination buffer pointer
    mov rdi, 1  ; index 1 - first user arg      <-- destination gone
    call _get_arg
    ...
    mov rsi, rax
    call _buffer_append_cstr                    <-- rdi = 1
```

`_buffer_append_cstr` then reads a buffer header at address `1`. The
`push rdi` on the line before is not a red herring: the destination *was*
saved — and never restored. It was popped into `rsi` after the append and
discarded (`:167`).

Two things follow from the mechanism that the symptoms hid. First, the
numeric specials were never safe, only lucky: `{arguments's count}`
resolves through `call _get_argc`, which happens not to write `rdi`, so
the stale destination survived by accident. Second, the exposure is not
confined to the named specials the resolver knows about:
`{environment's first}` is not in `resolve_format_variable` at all and
arrives as a `FormatPart::Expression`, whose lowering (`xor rdi, rdi` /
`call _get_env_at`) clobbers `rdi` exactly the same way — hence its 139
in the table. Any expression that needs a first argument would have done
the same.

`emit_format_parts_into_buffer_slot` (`:76-108`) — the sibling sink used
when the destination is a plain stack slot — resolves the value *first*
and loads `rdi` after, and never crashed. The two sinks disagreed about
one ordering.

**Fix.** `src/codegen/format.rs`: the destination is now loaded from its
home slot immediately before each append, once the value is settled in
`rax` — the ordering the slot sink already used. The save-and-discard
`push rdi`/`pop rsi` pair is gone with it, since reading the home slot is
both the restore and a pickup of any destination that resolution itself
reallocated. All four arms (literal, resolved-literal, unknown
placeholder, and runtime value) reload, so the expression arm is covered
too. The runtime needed no change: `_buffer_append_cstr` already measures
its source with a `strlen` loop and assumes no arena header, so the argv
`char*` — which points into the process's original argv block, not the
string arena — was always a valid source.

**One text-valued form cannot reach this path at all:** `environment's
"HOME"` does not survive inside a format string, because the nested
quotes end the string (`Expected 'to' after source in copy statement`).
It is unaffected, and reading a named environment variable into a buffer
has to go through a `text` variable today.

**Not fixed here, and deliberately:** `{arguments's all}` and
`{arguments's raw}` build a raw heap address into the buffer. `Print`
renders them exactly the same way, so the shared-resolver promise holds
and the rendering question is bug #44's family (a collection in a format
string renders correctly only in `Print` position), not this one. The
regression test covers the `all` form as "must not crash" and prints a
fixed marker instead of the unstable address.

**Latent, same shape, left alone:** the `Statement::BufferCopy` fallback
(`src/codegen/statements.rs:1975-1993`) also loads `rdi` before
`generate_expr(source)`, and pushes twice while popping once. The
analyzer rejects every source expression that would reach it ("Copy
source must be a buffer"), so it is unreachable today; worth closing
before something new makes it reachable.

---

### 53. `Return a buffer, "<text literal>"` answers with an empty buffer — or segfaults, once the program holds a second string

**Status:** **fixed** (unreleased, on top of 0.4.8). Severity: **memory
safety** — a legal program, compiled clean, reads megabytes past the end
of its own mapping. Regression tests:
`tests/compile_fail/099_return_buffer_text_literal.vox` and
`tests/compile_fail/100_return_buffer_text_variable.vox` (both proven to
compile clean and segfault with 139 on unfixed `origin/main`, and to be
rejected at compile time after), plus the passing control
`tests/bug53_return_buffer_variable.vox`, which pins that the buffer
spellings that always worked still do. Found 2026-08-21 by the vox-fuzz
Functions claim ledger (discrepancies D7 empty / D8 segfault),
master-reproduced on 0.4.8 and on current `main`.

```vox
To 'give literal'. Return a buffer, "ABC".

a buffer called direct is "ABC".
a buffer called second is "DEF".
a buffer called 'from literal' is 'give literal'.
Print 'from literal''s size.
```
→ **segfault (139)**, deterministic.

Drop the two other buffers and the same call silently answers an **empty
buffer** — `size` prints `0`, no crash, no error flag. The wrong answer
and the crash are the same defect reading different bytes; which one a
program gets depends on what the assembler happened to lay down after
the literal.

**The control says it is the source, not the return.** Returning a
buffer *variable* is fine:

```vox
To 'give made'. a buffer called made is "ABC". Return a buffer, made.
```
→ `3`, correct, before the fix and after. So does a buffer parameter
handed straight back, and so does a call to another buffer-returning
function. Only a source that is not a buffer is affected.

**A text VARIABLE fails identically.** `a text called greeting is "ABC".
Return a buffer, greeting.` segfaults in the same program shape (139),
because it hands back the same kind of address. Both spellings are
refused.

**What the spec promises.** LANGUAGE.md:722-727 makes `buffer` a legal
`Return a <type>,` return type, and nothing more. The manual gives text a
buffer meaning in exactly one place — "Creating buffer from string",
LANGUAGE.md:3347-3352, the declaration initializer `a buffer called buf
is "Hello".`, which allocates a buffer and appends the bytes. No
paragraph promises that conversion in a return.
README's "Memory Safety Model" and ROADMAP M0 ("no valid Vox program may
segfault") forbid the outcome either way.

**Mechanism — a text's address returned where a buffer struct's address
is expected.** A buffer is a header plus its bytes: capacity at +0,
length at +8, flags at +16, data from +24
(`coreasm/x86_64/resource.asm:11-14`). The general `Statement::Return`
arm (`src/codegen/statements.rs:1025-1042`) just leaves
`generate_expr(value)`'s result in `rax`, and for a text literal that is
`lea rax, [rel str_0]` (`src/codegen/expr.rs:389-392`) — the address of
the characters, with no header in front of them. On the caller's side, a
buffer declared from a call takes the initializer path at
`src/codegen/statements.rs:580-596`: `emit_copy_expr_into_buffer_slot`
declines the expression, the call is emitted, `infer_expr_type` reports
`Buffer` from the declared return type, and
`emit_append_runtime_value_to_buffer_ptr`
(`src/codegen/buffers.rs:75-81`) emits `mov rsi, rax` / `call
_buffer_append`. `_buffer_append`
(`coreasm/x86_64/resource.asm:1428-1441`) then reads `[rsi + BUF_LENGTH]`
— eight bytes past the first character of `"ABC"` — as the source length,
and copies that many bytes from `rsi + 24`.

The emitted assembly for the repro, with the two loads that disagree
about what `rax` holds:

```asm
    call give_literal
    mov rdi, [rel gvar_1]  ; destination buffer
    mov rsi, rax           ; "source buffer" - actually str_0's characters
    call _buffer_append

give_literal:
    lea rax, [rel str_0]   ; str_0: db 'ABC', 0
```

In the repro's binary the three literals land adjacent — `str_0` at
`0x40308c` holding `ABC\0ABC\0DEF\0` — so the qword at `str_0 + 8` is
`"DEF\0"` plus the zeroed head of `.bss`: **4,605,764**. The destination
grows to fit, and the copy then walks 4.6 MB forward from `str_0 + 24`,
which is inside a `.bss` of 68 KB. It runs off the end and the program
dies. With only one literal in the program, `str_0 + 8` is entirely
zeroed `.bss`, the length reads 0, `_buffer_append` takes its
`jz .append_done` branch, and the caller gets an empty buffer instead of
a crash. Nothing in between is checked, because nothing on this path
knows the address is not a buffer.

**Fix — refuse the return.** `check_buffer_return_source`
(`src/analyzer/types.rs:285-343`, with `render_buffer_return_source` at
`:349-360`), called from the `Statement::Return`
arm when the declared return type is `buffer`
(`src/analyzer/statements.rs:948-951`), rejects a source it can prove is
not a buffer and names the spelling that works:

```
error: Cannot return text "ABC" as a buffer; the caller reads what Return
hands back as a buffer, and text is not one. Build the buffer first:
'a buffer called made is "ABC". Return a buffer, made.'
```

The remedy is one spelling for every rejected type, because a buffer
declaration already accepts text, a format string, a number, a float or
a boolean as its initializer and writes the value's bytes (the same
latitude `check_type_lock` grants a buffer destination). Only a provable
non-buffer is refused: a call, a property read, a `value` name, an
unresolved name all pass, the "can't prove it, allow it" policy
`check_arithmetic_operand` and `check_file_write_operand` (bug #40)
already follow. This is the same treatment bug #40 gives `Write <scalar>`
— refuse the form that compiles to a bad address, rather than invent a
conversion.

**The language question this does not answer.** Whether `Return a
buffer, "ABC"` *should* convert the way the declaration does is a
decision that has not been taken. Converting would add language surface
(a second place text means "buffer") and belongs to the language owner,
not to a memory-safety fix; refusing it keeps the door open in either
direction.

**Never exercised until now.** `Return a buffer` appears nowhere in the
repository — not in `tests/`, not in `examples/`, not in LANGUAGE.md.
The only coverage was `tests/p296_full_type_vocabulary.rs`, whose matrix
proves the *parser* accepts all eleven type nouns and stands every one of
them on the same filler operand, `1`. Its buffer case now stands on a
real buffer, so it still tests the parser vocabulary it was written for.

**Sibling, out of scope, not fixed here:** `Return a list, "ABC".` and
`Return a number, "ABC".` are unchecked in exactly the same way — the
list form answers `0` for its size on the repro shape, and the number
form prints the literal's address. Neither was in this fix's scope; only
`buffer` is judged today.

### 54. A list element read into a variable of another type segfaults — `a text called label is element 1 of counts.`

**Status:** **fixed** (unreleased, on top of 0.4.8+#49/#50/#52). Severity:
**memory safety** — a legal-looking program with no diagnostic at all
crashes, and the near-miss version silently prints an address as a number.
Regression tests: compile-fail cases
`tests/compile_fail/099_element_number_list_into_text.vox` through
`105_foreach_element_into_mistyped_variable.vox`, and the passing controls
`tests/bug54_element_read_typecheck.vox` and
`tests/bug54_helper_widens_a_list.vox`. Found 2026-08-21 by the vox-fuzz
Variables claim ledger (discrepancy D1), master-reproduced on
0.4.8+#49/#50/#52.

```vox
a list called counts is [1, 2].
a text called label is "x".
label is element 1 of counts.
Print label.
```
→ **segfault (139)**, deterministic, no output at all.

**The matrix, each case its own program, on `origin/main` (34f9831) and on
the fix:**

| read | destination | 0.4.8+ | fixed |
|---|---|---|---|
| `element 1 of counts` (`[1, 2]`) | `text`, by assignment | 139 | rejected |
| `element 1 of counts` | `text`, by declaration | 139 | rejected |
| `element 1 of names` (`["a", "b"]`) | `number`, by assignment | prints `4198536` | rejected |
| `counts's first` | `text`, by declaration | 139 | rejected |
| `byte 1 of raw` (a buffer) | `text`, by declaration | 139 | rejected |
| `ages's "bo"` (`{"bo": 42}`) | `text`, by declaration | 139 | rejected |
| `ages's "bo"` | `text`, by assignment | already rejected | rejected |
| `For each part in counts, label is part.` | `text` | 139 | rejected |
| `element 1 of counts` | `number` | `1` | `1` |
| `element 1 of oddments` (`[7, "seven"]`) | `value` | `7` | `7` |
| `Print element 1 of counts.` (no copy) | — | `1` | `1` |

Two rows carry the whole story. **Printing the read directly is correct**
— `Print element 1 of counts.` prints `1`, and `Print element 1 of names.`
prints `a` — so the read itself, its bounds check and its tag dispatch all
work. It is the *copy into a differently-typed slot* that breaks. And the
map row shows the asymmetry that hid this: the assignment spelling of a
mismatched map read was already refused (plan 294 findings 4/14 gave a
homogeneous map literal a provable value type), while the declaration
spelling of the same read was not, and crashed.

**What the spec promises.** LANGUAGE.md:530-541: "A variable's type is
fixed at its declaration and never changes", `value` excepted, and every
form that writes to a declared name is checked "the same way". An element
read is such a write. LANGUAGE.md:2783-2807 documents element access and
promises only an error flag on the one failure it has (out of bounds).
ROADMAP M0 (ROADMAP.md:62-64) and README's "Memory Safety Model" forbid the outcome
independently: no valid Vox program may segfault at runtime.

**Mechanism — an untyped 8-byte copy into a typed slot.** The analyzer
knew nothing about what an element read yields:
`arithmetic_operand_type` (`src/analyzer/types.rs:38`) answered `None`
for `Expr::ElementAccess`, `ByteAccess` and `PropertyAccess{First,Last}`
— and `None` means "can't prove it, allow it", so `check_type_lock`
(`src/analyzer/types.rs:662`) passed every such assignment through.
The declaration spelling was worse off still: the `VarDecl` arm
(`src/analyzer/statements.rs:576-600`) type-checked nothing at all, it
merely *recorded* a category, and for a `text` declaration whose
initializer was not provably text it silently dropped the name from
`scalar_types` — so the mismatch not only passed, it erased the tracking
that would have caught the next line.

Codegen then emitted a plain quadword move. The whole of the repro's
element read and print, from `--emit-asm`:

```asm
.elem_ok_1:
    mov rax, [rax]        ; get element  -> rax = 1
.elem_done_3:
    mov [rel gvar_1], rax ; label's slot now holds the NUMBER 1
    mov rax, [rel gvar_1]
    mov rdi, rax
    PRINT_CSTR rdi        ; ... printed as a char* at address 1
```

`Print` picks its printer from the destination *variable's* declared type
(`src/codegen/print.rs:205-226`): `label` is a `text`, so `PRINT_CSTR`
walks a string at address `1`. The reverse direction is the same copy with
the roles swapped — a text element's pointer lands in a `number` slot and
`PRINT_INT` renders the pointer, which is where `4198536` comes from. No
bounds check, tag, or conversion is involved in either; the element's raw
payload is simply moved.

**Fix — refuse the provable mismatch, stay silent on the unprovable
one.** Three parts, all in the analyzer:

1. `list_element_type` (`src/analyzer/mod.rs:121`) records a list's element
   type from a homogeneous literal initializer, exactly as
   `map_value_type` already did for maps;
   `list_literal_element_type` (`src/analyzer/types.rs:414`) reads it off the
   same `list_element_kind` classifier `list_literal_is_mixed` uses, so
   the two can never disagree about which lists are homogeneous.
2. `arithmetic_operand_type` now answers for the read forms:
   `element N of <list>` and `<list>'s first`/`'s last` yield the proven
   element type, and `byte N of <buffer>` yields a number, which is true
   of every byte whatever buffer it came from. That alone makes the
   assignment spelling reach the existing type lock.
3. `check_declared_read_type` (`src/analyzer/types.rs:543`) applies the same
   judgement at the declaration site, which had no type check to reach.
   A `For each` loop variable over a proven list now carries the element
   type too (`src/analyzer/statements.rs:913`, the `ForEach` arm), which is
   what catches the loop spelling.

**The proof is only offered where it holds.** `collect_widened_lists`
(`src/parser/ast.rs:955`) walks the whole program — function bodies included —
and collects every list name that an `Append`, a `Set element N of`, a
whole-list assignment, a call argument, or a copy into or out of another
variable could widen or alias. A name in that set gets no element type at
all, so

```vox
a list called grown is [1, 2].
Append "three" to grown.
a text called third is element 3 of grown.   (still accepted, still prints "three")
```

keeps working. The scan is whole-program and order-independent by design:
a read early in the file gets the same answer as one after the append, and
a widening move anywhere disables the proof everywhere. The cost is a
missed diagnostic; the alternative is a false one.

One widening move cannot be pinned on a name at all — a function that
appends to a list it was *handed*, since the append names the parameter
and the call that passed the list may sit in an expression position the
scan does not walk. `any_function_widens_a_parameter`
(`src/parser/ast.rs`) answers that bluntly: while any function in the
program appends to or element-sets one of its own parameters, no list
anywhere gets a proof. (A function that appends to a list by its own
global name is a different case, and IS attributed — that append names
the list directly, and the scan descends into function bodies to see it.)

Mixed lists are untouched — `list_literal_element_type` answers `None`
for them, which is the existing "can't prove it, allow it" path, so the
`value` machinery keeps handling them and LANGUAGE.md:2460-2467's guarded
read out of `[1, "two", 3.5]` still prints `2, guarded away, guarded
away`.

**A separate, wider defect this deliberately does NOT fix.** The
declaration site performs no general type check, and only the *reads*
above were given one here. All of these still compile, and all of them
still crash or lie, on the fix:

```vox
a text called label is 42.        (segfault, 139)
a number called n is "hello".     (prints 4198488 — an address)
a number called n is 5.
a text called label is n.         (segfault, 139)
```

That is one bug — a missing declaration-site type check — with a far wider
blast radius than this one, since it reaches every literal and every
variable copy rather than the six read forms. It wants its own number, its
own reproduction matrix and its own regression sweep; folding it in here
would have made this fix unreviewable. Recorded here so it is not lost.

**Also noticed, unrelated:** the `compile_fail` corpus counter in
`test.sh` counts `.vox` recursively but is compared against a `.err` count
that two `see`-include helpers under `tests/compile_fail/include/` can
never satisfy, so the runner prints a `WARN` about a `.vox`/`.err` count
mismatch on a perfectly healthy corpus. Cosmetic, pre-existing, left alone.

---

### 55. A `treating` clause whose types do not match the collection segfaults — `print each item from ["a"] treating 98 as 31.`

**Status:** **fixed** (unreleased, on top of 0.4.8+#49/#50/#52/#53/#54).
Severity: **memory safety** — a one-line program, compiled clean, faults
on an address taken from a number literal. Regression tests: compile-fail
cases `tests/compile_fail/113_treating_number_match_over_text_list.vox`,
`114_treating_number_match_over_text_list_variable.vox` and
`115_treating_text_match_over_range.vox`, plus the passing controls
`tests/359_treating_matching_types_substitutes.vox` (every spelling where
the types agree still substitutes) and
`tests/360_treating_over_an_unprovable_list.vox` (the collection whose
element type cannot be proven no longer faults). Found 2026-08-21 by the
vox-fuzz basics-expansion claim ledger (discrepancies D3 and D4),
master-reproduced on 0.4.8+#49/#50/#52/#53/#54.

```vox
print each item from ["a"] treating 98 as 31.
```
→ **segfault (139)**, deterministic, no output at all.

**The matrix, each case its own program, on `origin/main` (131cf73) and on
the fix:**

| program | before | after |
|---|---|---|
| `print each item from ["a"] treating 98 as 31.` | 139 | rejected |
| `a list called words is ["a", "b"].` + `print each item from words treating 98 as 31.` | 139 | rejected |
| `print each step from 1 to 3 treating "a" as "b".` | prints `1 2 3`, clause dead | rejected |
| `a list called words is ["a"].` + `append "b" to words.` + `print each item from words treating 98 as 31.` | 139 | prints `a b`, clause never fires |
| `print each item from ["-", "keep"] treating "-" as "/dev/stdin".` | correct | correct |
| `print each count from [1, 2] treating 1 as 9.` | correct | correct |
| `print each name from arguments's all treating "-" as "dash".` | correct | correct |
| `print each item from [1, "a"] treating 98 as 31.` | prints `1` then `4198536` | unchanged — see below |

**The check was not missing — it was blind on one side.** The analyzer
already refuses `treating 98 as "z"`, with `Treating match and
replacement must be the same type`, and it already had a second check
comparing the clause's *subject* to its match. That second check could
never fire over a loop, because `infer_simple_expr_type`
(`src/analyzer/types.rs:399`) answers `None` for a plain
`Expr::Identifier` unless the name is a buffer, list, map or flag — and a
loop variable is none of those. Its scalar category lives in
`scalar_types`, which only `named_value_type` (`src/analyzer/types.rs:10`)
consults. So the check saw literals and nothing else.

**What the spec promises.** LANGUAGE.md:404-424 introduces `treating X as
Y` as "inline value substitution" and says only "If the loop variable
equals `<match>`, it's replaced with `<replacement>` for that iteration".
Nothing licenses a match of a type the loop variable can never hold —
equality between a text and a number is not a comparison Vox offers
anywhere else, and LANGUAGE.md:530-541 fixes a name's type at its
declaration. ROADMAP M0 (ROADMAP.md:62-64) and README's "Memory Safety
Model" forbid the outcome independently: no valid Vox program may
segfault at runtime.

**Mechanism — codegen was more confident than the analyzer.**
`Expr::TreatingAs` (`src/codegen/expr.rs:1670-1713`) picks its comparison
from the *subject's* type alone:

```rust
let treating_type = self.infer_expr_type(value);
if is_buffer || matches!(treating_type, Some(VarType::String)) {
    ...
    self.emit_indent("mov rdi, rax  ; comparison ptr in rdi");
    self.generate_expr(match_value);
    self.emit_indent("mov rsi, rax  ; match value in rsi");
    self.emit_indent("call _str_eq");
```

Over `["a"]` the subject is text, so this branch is taken and
`generate_expr(match_value)` leaves the *integer* 98 in `rsi`. `_str_eq`
(`coreasm/x86_64/string.asm:92-109`) then walks both operands a byte at a
time:

```asm
.loop:
    mov al, [rdi]
    mov bl, [rsi]      ; rsi = 98 — reads address 0x62
```

which is the fault. The other direction is the same confusion with no
signal: over a range the subject is a number, the register branch is
taken instead, a pointer is compared against an integer, they are never
equal and the clause is silently dead — the ledger's D4 shape.

**Fix — reject the provable mismatch, and never dereference an
unprovable one.** Two parts, one per layer:

1. *Analyzer, `src/analyzer/types.rs`.* A new `treating_subject_type`
   resolves a plain name through `named_value_type` instead of
   `infer_simple_expr_type`, so the subject-vs-match check finally sees
   the loop variable's element type. A `value`-typed name answers `None`
   and is left alone. The error names both types and points at the
   subject:

   ```
   error: Treating value and match must be the same type (got text vs number).
     --> 113_treating_number_match_over_text_list.vox:5:12
       |
     5 | print each item from ["a"] treating 98 as 31.
       |            ^--- here

     hint: 'item' holds text here, so it can never equal a number - the
           substitution would never fire, and comparing the two reads one
           as the other
   ```

   The `ForEach` arm (`src/analyzer/statements.rs`, the bug #54 block)
   now also reads an element type off a list *literal* in the loop
   header via `list_literal_element_type`; before, only a named list had
   one, because only a name could be looked up.

2. *Codegen, `src/codegen/expr.rs`.* The text branch is taken only when
   the match value could itself be text. A match that is provably a
   number, float or boolean can never equal a text subject, so the
   register comparison is used: the two are unequal, the substitution
   correctly never fires, and nothing is read through the match value.
   This is what closes the case the analyzer cannot prove — a list
   widened by a later `Append` has no element type, so nothing is
   rejected, and before this the generated program still faulted.

**The proof is only offered where it holds.** `arguments's all` has no
provable element type and keeps compiling exactly as it did (both
existing analyzer tests over it are untouched and still pass). So does a
widened list, an untyped parameter and a function result — the analyzer
stays silent on all of them and codegen's guard carries the safety.

**Not fixed: `treating` over a MIXED list still prints a raw pointer.**
This is the ledger's D4, and it survives:

```vox
print each item from [1, "a"] treating 98 as 31.
```
→ prints `1` then `4198536`, exit 0.

A mixed list's loop variable is runtime-tagged (`value`), so there is no
static element type to check against and this fix deliberately does not
invent one. But the leak is **not** caused by the type mismatch, which is
what the ledger assumed. The type-*matching* version leaks identically:

```vox
print each item from [1, "a"] treating "a" as "b".
```
→ prints `1` then `4198536`, where `1` then `b` is correct — while the
same list with no `treating` clause at all prints `1` and `a`, correctly.
So
wrapping a mixed-list loop variable in `Expr::TreatingAs` loses its tag:
`infer_expr_type` for `TreatingAs` reports the subject's type
(`src/codegen/expr.rs:2408`) and `Print` picks its printer from that,
rather than dispatching on the per-slot tag the way a bare read does.
That is a wrong-value bug in the `Mixed`/`value` printing path, the same
family as #44/#45, and it wants its own number and its own reproduction
matrix. Recorded here so it is not lost.

---

### 56. `all the numbers from/between X and Y` — a range that segfaults in a loop header, segfaults as a value, and drops its end bound

**Status:** **fixed** (unreleased, on top of 0.4.8). Severity: **memory
safety** — two legal-looking programs, two and two lines long, crash; a
third answers wrongly. Regression tests
`tests/361_foreach_over_all_the_numbers.vox` and
`tests/362_all_the_numbers_is_inclusive.vox` plus three compile-fail
fixtures (`tests/compile_fail/116_range_as_list_initialiser.vox`,
`117_print_a_range.vox`, `118_range_in_arithmetic.vox`), all proven to
misbehave on unfixed `main` and to pass after. Found 2026-08-21 by the
vox-fuzz keywords claim ledger (discrepancies D5, D6 and D7),
master-reproduced on 0.4.8.

**Three symptoms, one phrase.**

```vox
For each step in all the numbers between 1 and 3,
    Print step.
```
→ **segfault (139)**, no output. (D6)

```vox
a list called steps is all the numbers from 1 to 3.
Print steps.
```
→ prints `[` and **segfaults (139)**. (D7)

```vox
Print each step from all the numbers from 1 to 3.
```
→ prints `1 2`. The same sentence with `between 1 and 3` prints `1 2 3`.
(D5)

**The matrix, each case its own program, on `main` and on the fix:**

| the phrase's position | 0.4.8 | fixed |
|---|---|---|
| `For each step in all the numbers between 1 and 3,` | 139 | `1 2 3` |
| `For each step in all the numbers from 1 to 3,` | 139 | `1 2 3` |
| `For each step from all the numbers between 1 and 3,` | 139 | `1 2 3` |
| `For each step from all the numbers from 1 to 3,` | 139 | `1 2 3` |
| `Print each step from all the numbers between 1 and 3.` | `1 2 3` | `1 2 3` |
| `Print each step from all the numbers from 1 to 3.` | `1 2` | `1 2 3` |
| `a list called steps is …` then `Print steps.` | 139 | compile error |
| `… Print steps's length.` | 139 | compile error |
| `Print all the numbers between 1 and 3.` | `0` | compile error |
| `a number called total is all the numbers between 1 and 3 add 4.` | `8` | compile error |
| `Print each step from 1 to 3.` (plain range, control) | `1 2 3` | `1 2 3` |

Loop expansion was the one position that already ran — and it was the one
that showed D5, because it was the only place the end bound was ever
observable.

**What the spec promises.** LANGUAGE.md:4715-4716 names `all` a
contextual keyword claimed by "the `all the numbers from/between …`
range" — so the phrase denotes a **range**, in both spellings, named in
one breath. LANGUAGE.md:262 says what a range is: "Ranges … are **not**
allocated as lists - they compile directly to efficient loop constructs
with a counter, bounds check, and increment." A range is therefore not a
value and has nothing to put in a variable. LANGUAGE.md:277 says how far
one goes: "Ranges are **inclusive** - `1 to 5` includes 1, 2, 3, 4, and
5." The `For each` forms at :2095-2116 are `For each <n> from <start> to
<end>` for a range and `For each <var> in <list>` for a list; loop
expansion at :284 is explicitly "a loop that executes for each item in a
collection **or range**". README's "Memory Safety Model" and ROADMAP M0
("no valid Vox program may segfault") forbid the crash independently.

**Mechanism, part one — one node with no value, reachable from every
expression position.** `all the numbers …` is parsed in `parse_primary`
(`src/parser/expressions.rs:1030-1055`) and yields `Expr::Range`. That is
the only place in the language that builds a `Range` in *expression*
position; everywhere else a range is constructed directly into a
`Statement::ForRange`. But `parse_primary` is `parse_primary` — the node
then flows wherever an expression may go, and codegen's arm for it
(`src/codegen/expr.rs:840`) is:

```rust
Expr::Range { .. } => {}
```

Nothing is emitted, so `rax` keeps whatever the previous instruction left
in it. Two ends of the same defect follow:

- **The loop header (D6).** `For each <var> in <collection>` and `For
  each <var> from <collection>` (`src/parser/control_flow.rs`, pre-fix
  :561 and :608) built a `Statement::ForEach` whatever the collection
  was, and `ForEach` codegen reads `[ptr + 8]` as a list header's element
  count — the same dereference bug #49 closed for scalars, reached this
  time by a node no analyzer check could name. `rax` is dereferenced as a
  list pointer: SIGSEGV.
- **The value position (D7).** `a list called steps is <Range>` stores
  that same stale `rax` in the list slot. The declaration alone survives
  — replacing the read with `Print "declared".` runs clean — because
  nothing has walked the header yet. `Print steps.` walks it: it manages
  the opening `[` and dies. The quieter siblings never crash and are
  worse for it: `Print all the numbers between 1 and 3.` printed `0`, and
  the same phrase as an arithmetic operand printed `8` — the constant `4`
  it was added to, plus a `4` that was never a range.

**Mechanism, part two — inclusiveness read off the preposition (D5).**
The same parse site decided how far the range goes from which word the
programmer happened to write:

```rust
let inclusive = *self.current() == Token::Between;
```

`Expr::Range`'s `inclusive` flag is a single `inc rax` on the end bound
before the `jge` (`src/codegen/statements.rs:880-889`), so `from` lost
the last iteration and `between` did not. Every other range-building site
in the parser hardcodes `inclusive: true` — `control_flow.rs:459`, `:895`
and `:909` — which is why the documented `For each number from 1 to 10`
was always right and only this phrase was not. Nothing in :4716
distinguishes the two spellings; it names them as one range.

**The fix, one root, three symptoms.** A range now reaches codegen only
as a loop's counter bounds, and it always includes its end.

1. Every `For each` header handed a range routes to `Statement::ForRange`
   through the existing `for_each_loop` helper — the same helper the
   loop-expansion clause has always used, which is precisely why loop
   expansion was the one spelling that worked. `in` and `from` now agree
   with `each … from`.
2. `Expr::Range` in the analyzer's expression walk is a compile error,
   `A range is not a value: all the numbers from/between ...`, with the
   hint "a range counts, it does not hold - iterate it with `For each
   n from 1 to 3,`, or write the items out as a list, `[1, 2, 3]`". The
   caret is placed by searching the source for the phrase itself.
   `Statement::ForRange` walks its own `start` and `end` instead of the
   `Range` node, so the one legitimate position is unaffected.
3. `inclusive` at the phrase's parse site is `true`, like every other
   range site, so both spellings reach their end bound.

Rejecting rather than allocating a list is what the manual supports:
:262 is explicit that a range is not a list, so building one here would
invent a value the language says does not exist.

**Manual gap, recorded not closed.** LANGUAGE.md never states in one
place that a range is not a first-class value — :262 says ranges are not
*allocated* as lists, which a reader can take as an implementation note
about efficiency rather than a rule about where the phrase may appear.
Nor does the Ranges section mention the `all the numbers …` spelling at
all; it is introduced 4,400 lines later in a list of contextual keywords.
A reader who meets the phrase there has no way to learn from the Ranges
section that `a list called steps is all the numbers from 1 to 3.` is not
a thing. The diagnostic now says so; the manual still should.

---

### 57. A `text`, `list` or `map` initialised to `nothing` segfaults on the first read — `a text called t is nothing.`

**Status:** **fixed** (unreleased, on top of 0.4.8+#49/#50/#52/#53/#54/#55/#56).
Severity: **memory safety** — a two-line program, compiled clean, faults on
a null pointer it was handed by a literal. Regression tests: compile-fail
cases `tests/compile_fail/119_nothing_into_text_declaration.vox`,
`120_nothing_into_list_declaration.vox`,
`121_nothing_into_map_declaration.vox`,
`122_nothing_into_number_declaration.vox`,
`123_nothing_assigned_to_text.vox`,
`124_nothing_as_a_text_argument.vox` and
`125_nothing_returned_as_text.vox`, plus the passing control
`tests/363_nothing_in_its_documented_places.vox`, which walks every
position LANGUAGE.md gives the literal and is byte-identical before and
after. Found 2026-08-21 by the vox-fuzz random-literals worker's probes
(REPORT-LITERALS.md §4 D1), master-reproduced on 0.4.8+#49–#56.

```vox
a text called greeting is nothing.
Print greeting.
```
→ **segfault (139)**, deterministic, no output at all.

**The matrix, each case its own program, on `origin/main` (5dbbc75) and on
the fix:**

| program | before | after |
|---|---|---|
| `a text called t is nothing.` + `Print t.` | 139 | rejected |
| `a list called t is nothing.` + `Print t.` | prints `[`, then 139 | rejected |
| `a map called t is nothing.` + `Print t.` | prints `{`, then 139 | rejected |
| the same three with `null` / `nil` | 139 | rejected |
| `a text called t is nothing.` + `Print "declared".` | prints `declared` | rejected |
| `a text called t is nothing.` + `If t is nothing, …` | prints nothing at all | rejected |
| `a list called t is nothing.` + `Append 1 to t.` | 139 | rejected |
| `a map called t is nothing.` + `Print t's "k".` | 139 | rejected |
| `a text called t is "hi".` + `set t to nothing.` + `Print t.` | 139 | rejected |
| `the t is nothing.` on a declared text | 139 | rejected |
| `Set a text called t to nothing.` / `Create … to nothing.` | 139 | rejected |
| `To greet with a text called who. Print who.` + `greet with nothing.` | 139 | rejected |
| `To label. Return text, nothing.` + `print label.` | 139 | rejected |
| `a number called n is nothing.` + `Print n.` | prints `0` | rejected |
| `a float called f is nothing.` + `Print f.` | prints `0.0` | rejected |
| `a boolean called b is nothing.` + `Print b.` | prints `0` | rejected |
| `a buffer called b is nothing.` + `Print b.` | prints `0` | rejected |
| a sized buffer, then `set b to nothing.` + `Print b.` | prints `0` | rejected |
| `a file called f is nothing.` | compiles | rejected |
| `To bump with a number called n. Print n.` + `bump with nothing.` | prints `0` | rejected |
| `a value called v is nothing.` + `Print v.` (control) | `nothing` | `nothing` |
| `print nothing.` / `null` / `nil` (control) | `nothing` | `nothing` |
| `a list called L is [1, nothing, "x"].` + `print L.` (control) | correct | correct |
| `a map called m is {"absent": nothing}.` + `print m.` (control) | correct | correct |
| `Set element 1 of L to nothing.` / `Set m's "k" to nothing.` (control) | correct | correct |
| a `value` parameter and a `value` return carrying it (control) | correct | correct |
| `a text called t is v.` where `v` is a `value` holding it | 139 | **unchanged — see below** |
| `a text called t is m's "absent".` | 139 | **unchanged — see below** |
| `Set t to nothing.` on a brand-new, untyped name | prints `0` | **unchanged — see below** |

The declaration alone is not what crashes — `a text called t is nothing.`
followed by `Print "declared".` runs clean. The READ is the fault, which is
why the crash arrives a line away from its cause.

**Which reading the manual supports.** The rejecting one, on three
independent statements:

1. LANGUAGE.md:2659-2661 enumerates where the literal may sit, and the
   enumeration is the definition: "`nothing` is the value that means 'no
   value here' … It **can sit in a list slot, a map value, or a `value`
   parameter or return**, and it prints as the word `nothing`." A
   `text`/`list`/`map`/`number` variable is none of those three.
2. The bare-`Create` defaults table (LANGUAGE.md:489-501) says what each
   type's absent-looking value actually is, and only one row is `nothing`:
   `text` defaults to the empty string, `list` to `[]`, `map` to `{}`,
   `number` to `0` — and `value` to `nothing`. The language already has a
   type whose inhabitant set includes the absent value, and it is not any
   of these.
3. LANGUAGE.md:2685 forbids the quiet half outright: "**`nothing` is not
   zero.** This is the distinction that matters most." A `number`
   initialised to `nothing` printed `0`, which is precisely the collision
   that sentence denies, and :2706-2713 already makes `a number called n is
   nothing add 1.` a compile error *for this very reason* — "the stored
   payload of `nothing` really is 0. Left unchecked, `total add
   missing_field` would quietly evaluate to `total` — a wrong answer that
   looks completely plausible." A language that refuses `nothing add 1`
   because the payload is 0, but accepts `a number called n is nothing.`
   and hands back that same 0, is refusing the symptom and licensing the
   cause.

The alternative reading — make a `text` holding `nothing` print `nothing`,
the way a `value` does — was rejected because it adds a second inhabitant
to every concrete type that the manual never describes. It would make `is
nothing` a meaningful question about a `text` (LANGUAGE.md:2677 introduces
the predicate for map values and mixed elements), it would need an answer
for `t's length` and for `Append` on a `nothing` list, and it would leave
`a number called n is nothing.` still colliding with `0` at :2685. The
memory-safety promise (README "Memory Safety Model"; ROADMAP M0, "no valid
Vox program may segfault") forbids the crash under either reading; only
this one also stops the wrong answer.

**Mechanism — the payload is stored, the tag has nowhere to go.** Codegen's
literal arm (`src/codegen/expr.rs`) is honest about what it emits:

```rust
Expr::NothingLit => {
    self.emit_indent("xor rax, rax  ; nothing literal, payload 0 (tag 6 set by caller)");
}
```

The tag is the caller's job, and only a `value` slot, a list slot and a map
slot have a place to keep one. A concretely-typed variable has one
quadword, so the declaration compiles to a bare store of 0 and the read
dispatches on the *declared* type, which is all codegen has left:

```asm
    xor rax, rax  ; nothing literal, payload 0 (tag 6 set by caller)
    mov [rel gvar_0], rax  ; global store greeting
    mov rax, [rel gvar_0]
    mov rdi, rax
    PRINT_CSTR rdi          ; rdi = 0
```

`_print_cstr_impl` (`coreasm/x86_64/io.asm:77-90`) then counts the string's
length with `mov al, [rsi + rcx]` from address 0 — the fault. The list and
map spellings differ only in which routine walks the null: `_list_print`
(`coreasm/x86_64/list.asm:605-630`) prints `[` and *then* reads `[rbx +
LIST_LENGTH_OFFSET]`, which is exactly the partial output the crash shows,
and `_map_print` dies the same way after `{`. Where the type is a scalar
there is no dereference and nothing to fault — the 0 simply prints as 0,
which is the same defect wearing a plausible answer.

`If t is nothing` on such a text printed nothing at all, and that is the
tell: the predicate compares runtime type tags (LANGUAGE.md:2691-2693), and
a text slot has no tag to compare, so a text "holding nothing" cannot even
be recognised as holding it. There was never a value there to read.

**The fix — refuse the literal at every write site that can see it.**
One rule, `Analyzer::nothing_is_refused_for` (`src/analyzer/types.rs`):
`nothing` may not be written into a slot of any concrete type
(`number`, `float`, `text`, `boolean`, `list`, `map`, `buffer`, `file`,
`time`, `timer`). `value` is its documented home and is untouched;
`Thing` is left to `check_thing_copy`, which already owns every write into
a thing's storage.

Four sites see the literal, and all four faulted or lied:

1. *The declaration* — `check_nothing_initialiser`, called from the
   `VarDecl` arm beside bug #54's `check_declared_read_type` and for the
   same reason: the type lock only guards writes to an ALREADY-declared
   name, and this is the declaration itself. This covers `Set a text
   called t to nothing.` and `Create … to nothing.`, which parse into the
   same statement.
2. *The assignment* — a new branch at the top of `check_type_lock`.
   `nothing` is not a `Type` (tag 6 exists only at runtime), so
   `arithmetic_operand_type` answered `None` for it and the lock's
   "can't prove it, allow it" policy waved it straight through. A buffer
   is deliberately **not** excused here, though it is excused from the
   lock proper: a buffer content write formats the value's text into the
   buffer, and `nothing` has no text — it formatted its payload and wrote
   `0`, which would have contradicted the same statement's rejection two
   lines earlier at the buffer's own declaration.
3. *A call argument* — `check_nothing_argument`, from
   `analyze_call_arguments`. The callee stores the argument in its
   parameter's concretely-typed slot and reads it as that type, so
   `greet with nothing.` faulted *inside* `greet`, one frame from the
   sentence that caused it.
4. *A return* — `check_nothing_return`, from the `Return` arm. The caller
   reads the result as the declared type, so a `text` return handed back a
   null pointer and a `number` return quietly answered `0`.

Each diagnostic names the type, points at the site, and offers the two
ways out — the type that can be absent, or this type's own empty value:

```
error: cannot initialise 'greeting', which is text, with nothing
  --> 119_nothing_into_text_declaration.vox:7:15
    |
  7 | a text called greeting is nothing.
    |               ^^^^^^^^ this text is given nothing
    |
  note: nothing is the absent value: it sits in a list slot, a map value, or a value parameter or return - never in text
  help: declare 'greeting' as a value, the type that can be absent - or give it text's own empty value, ""
```

**Nothing documented was taken away.**
`tests/363_nothing_in_its_documented_places.vox` runs the literal through
every position the manual gives it — all three spellings printed, a list
slot, a map value, a `value` declaration, `Create a value called v.`, a
`value` reassigned to and from the literal, a `value` parameter and a
`value` return, `Set element 1 of L to nothing.` and `Set m's "k" to
nothing.` — and its output is byte-identical on `origin/main` and on the
fix.

**Not fixed: the same crash reached at run time, where no literal is
visible.** Three shapes survive, all of them 139 before and after:

```vox
a value called v is nothing.
a text called t is v.
Print t.
```
```vox
a map called m is {"absent": nothing}.
a text called t is m's "absent".
Print t.
```
```vox
a list called L is [nothing].
a text called t is element 1 of L.
Print t.
```

These are the residue of bug #54's deliberate permissiveness: a `value`
source, and a collection whose element/value type cannot be proven, both
answer "can't prove it" and are allowed through, so the null arrives in a
text slot with nothing static to catch it. This fix does not invent a proof
it does not have. The manual already says what the answer should be —
:2715-2717, for exactly this situation: "When a value only turns out to be
`nothing` at run time — read out of a map or a mixed list — the compiler
cannot catch it, so the operation **sets the error flag** instead", with
`on error` as the author's handle. That is a codegen change at every
concretely-typed store fed by a dynamically-tagged source, it needs its own
number and its own reproduction matrix, and it is recorded here so it is
not lost.

**Manual gaps, recorded not closed.**

- LANGUAGE.md is silent on what an *untyped* declaration makes of the
  literal. `Set t to nothing.` and `the t is nothing.` on a brand-new name
  declare `t` with no type keyword to check against, and both print `0` —
  the ":2685 is not zero" collision again, through the one door this fix
  does not close, because there is no declared type for the literal to
  conflict with. The coherent answer is that such a name infers `value`,
  the type whose default the table already gives as `nothing`; that is a
  language decision, not a bug fix, so the behaviour is unchanged.
- The `nothing` section states its three legal positions in a sentence of
  prose (:2660-2661) and never says what happens outside them. A reader
  who writes `a text called t is nothing.` has nothing in that section to
  read it against — the defaults table 2,170 lines earlier is what settles
  it, and the table is about `Create` with no initialiser. The diagnostics
  now say the rule; the manual still should.

---

### 58. A buffer declared from a text-valued property (`environment's "HOME"`, `environment's first`, `arguments's first`) is silently re-typed as text — size `-1`, prints nothing, and on `Set` loses its bounds

**Status:** **fixed** (unreleased, on top of 0.4.8). Severity: **memory
safety** — the declaration form answers wrongly, and the `Set` form drops
a fixed buffer's bounds check and lets `Set byte N of ...` write into the
process's own argument block, segfaulting at a large `N`. Regression
tests `tests/364_buffer_from_named_environment_variable.vox`,
`tests/365_buffer_from_positional_environment_property.vox`,
`tests/366_buffer_from_argument_property.vox` and
`tests/367_set_buffer_to_argument_keeps_its_bounds.vox`, all proven to
misbehave on unfixed `main` and to pass after. Found 2026-08-21 by the
vox-fuzz environment claim ledger (discrepancy D1,
`docs/ledger/environment.md`, probes `D1.vox`/`D1b.vox`), re-found by the
fuzzer's new environment leaves (ASSERT ENV-03/ENV-06 in 2 of 40 seeds),
master-reproduced on 0.4.8. Sibling of #52 — the same family of text-valued
special names built into a buffer — but a different mechanism.

```vox
a buffer called home is environment's "HOME".
Print home.               (wrong: an empty line)
Print home's size.        (wrong: -1)

a text called address is environment's "HOME".
a buffer called duplicate is address.
Print duplicate's size.   (correct: 10)
```

The two-step spelling — read the property into a `text`, then declare the
buffer from that text — is the control, and it was always right. The
one-step declaration named in the same breath was not.

**The matrix, each case its own program, run as `./case alpha beta` on
`main` and on the fix:**

| the program | 0.4.8 | fixed |
|---|---|---|
| `a buffer called b is environment's "HOME".` then `Print b.` | *(empty line)* | `/home/josj` |
| `… Print b's size.` | `-1` | `10` |
| `… Print b's capacity.` | `4096` | `4096` |
| `… Print b's empty.` | `0` | `0` |
| `a buffer called b is environment's "VOX_NOPE_58".` then `… size` | `-1` | `0` |
| `a buffer called b is environment's first.` then `… size` | `-1` | `15` |
| `a buffer called b is environment's last.` then `… size` | `-1` | `19` |
| `a buffer called b is arguments's first.` then `Print b.` | *(empty line)* | `alpha` |
| `… Print b's size.` | `-1` | `5` |
| `a buffer called b is arguments's last.` then `… size` | `-1` | `4` |
| `a buffer called b is arguments's name.` then `… size` | `-1` | `17` |
| `a buffer called b is 64 bytes in size.` `Set b to arguments's first.` `… size` | `-1` | `5` |
| `… Print b's capacity.` | `7305401963912391777` | `64` |
| `… Set byte 100000000 of b to 'X'.` | **139** | error flag, program survives |
| `a text called t is arguments's first.` `a buffer called b is t.` `… size` (control) | `5` | `5` |
| `a buffer called b is "alpha".` `… size` (control) | `5` | `5` |
| `a buffer called b is "{arguments's first}".` `… size` (control) | `5` | `5` |
| `a text called t is environment's "HOME".` `Print t.` (control) | `/home/josj` | `/home/josj` |
| `a buffer called b is arguments's count.` `… size` (numeric, control) | `1` | `1` |

Three properties of a buffer that was, by the compiler's own `type`
property, still a `Buffer (static)`, disagreed with each other: it printed
as empty, reported `size -1`, and reported `empty` false. The
disagreement is the tell. `capacity` and `empty` read the buffer header
directly and were right; only `size` and `Print` dispatch on the
variable's *type*, and only those two were wrong.

**What the spec promises.** LANGUAGE.md:531-532 is the rule this breaks:
"**A variable's type is fixed at its declaration and never changes** —
`value` is the one deliberate exception". LANGUAGE.md:3285 says the same
thing from the other side, explaining why a buffer reports `(static)`:
"the compiler knows the type from the declaration". `a buffer called b`
is a declaration; nothing that follows `is` may change what `b` is.
LANGUAGE.md:3347-3351 establishes that a buffer's initializer is a *text
value to copy in* — "Creating buffer from string: `a buffer called buf is
"Hello".`" — and the environment and argument properties are text
(LANGUAGE.md:3158-3161's shared name resolver, and #52's own finding that
"every text-valued special name" belongs to one family). README's "Memory
Safety Model" and ROADMAP M0 ("no valid Vox program may segfault") forbid
the `Set` form's outcome independently.

**Mechanism — a silent retype in codegen, not a missing copy.** The copy
always ran. The emitted assembly for the headline program allocates,
clears, resolves the environment variable and appends its bytes, exactly
as the working two-step control does:

```asm
    mov rdi, 1024  ; default buffer size
    call _alloc_buffer
    mov [rel gvar_0], rax  ; global store buffer home
    mov rdi, [rel gvar_0]
    call _buffer_clear
    mov [rel gvar_0], rax
    lea rax, [rel str_0]
    mov rdi, rax
    call _get_env
    ...
    mov rdi, [rel gvar_0]
    mov rsi, rax
    call _buffer_append_cstr      ; the bytes are in the buffer
    mov [rel gvar_0], rax
```

The two programs' assembly diverges at one instruction, and it is in the
property read, not the initialization:

```asm
    mov rax, [rax + 8]  ; buffer length/size    <- the control
    call _file_size                             <- the one-step declaration
```

`Expr::PropertyAccess`'s `Size` arm (`src/codegen/expr.rs:1076-1089`)
branches on `self.variable_types.get(object)`; anything that is not a
Buffer, List or Map falls through to the file fallback `_file_size`,
which is handed a buffer pointer as a file descriptor and returns `-1`.
`Print` dispatches on the same table and rendered the buffer *header* as
a C string — an empty line, because the capacity's low byte is `0`.

The type was correct when the declaration was read and wrong a few lines
later. `Statement::VarDecl` (`src/codegen/statements.rs:313-338`) writes
the declared type into `variable_types` — `Type::Buffer` → `VarType::Buffer`.
The block that follows (`:402-551`) then re-reads the type off the
*initializer's shape*, for names that have no declared type of their own,
and one of its arms is a list of every argument and environment spelling:

```rust
// Argument/environment expressions return string pointers
else if matches!(val,
    Expr::ArgumentAt { .. } | Expr::ArgumentName | Expr::ArgumentFirst |
    Expr::ArgumentSecond | Expr::ArgumentLast |
    Expr::EnvironmentVariable { .. } | Expr::EnvironmentVariableAt { .. } |
    Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
) {
    self.variable_types.insert(name.clone(), VarType::String);
}
```

It is right about the expression — these do return string pointers — and
that is exactly the trap. The initializer's type is not the variable's
type when the variable was declared; here it overwrote `Buffer` with
`String` unconditionally.

**Why the neighbours were safe, which is what names the missing guard.**
The arm below it, which inherits a type from a source *variable*, is
guarded — `var_type.is_none() || matches!(var_type, Some(Type::List(_)))`
— so the two-step control never entered it and never lost its type. The
bare-assignment arm at `:738-740` carries the guard in its other spelling,
`self.variable_types.get(name) != Some(&VarType::Buffer)`. Only the
declare-with-initializer arm had none. A string literal and a format
string are not in any of these arms at all, which is why `a buffer called
b is "alpha".` and `a buffer called b is "{arguments's first}".` — #52's
territory — were always correct.

**Why `Set` was worse than a wrong answer.** `Set b to <property>` on a
name with no declared type of its own routes through this same `VarDecl`
arm. Twenty lines further down, the decision to treat the destination as a
buffer at all is read back out of the table this arm just corrupted:

```rust
let is_buffer_target = matches!(var_type, Some(Type::Buffer))
    || self.variable_types.get(name) == Some(&VarType::Buffer);
```

With `var_type` `None` (an assignment declares nothing) and the table now
saying `String`, `is_buffer_target` is false, so the assignment stopped
copying bytes into the buffer struct and stored the raw `argv`/`environ`
pointer straight over the buffer pointer. The declared 64-byte buffer was
still allocated, and nothing pointed at it any more. From there every
buffer operation was aimed at the process's own argument block:
`capacity` read the argument's first eight bytes as an integer
(`7305401963912391777` — the eight bytes `alpha\0be`, read little-endian), the bounds
check in `Set byte N of b` compared against that number and passed
everything, and the write landed at `argv[1] + 24`. With three arguments
`aaaa bbbb…bbbb cccc`, `Set byte 1 of b to 'X'` on `main` left the
*second* argument reading `bbbbbbbbbbbbbbbbbbbX`. A large position
segfaulted (139).

**Fix.** `src/codegen/statements.rs`: the initializer-shape inference
block is now skipped when the name is already a buffer —
`self.variable_types.get(name) != Some(&VarType::Buffer)`, the guard the
bare-assignment arm beside it already used. Reading the *current* type
rather than the declaration's `var_type` is what covers the `Set b to ...`
and `the b is ...` spellings, which route through `VarDecl` carrying no
declared type of their own; an explicit declaration has already written
its own type into the table above this point, so a later `a text called b
is ...` still re-types freely and Type Immutability's real enforcement,
in the analyzer, is untouched. No runtime change was needed: the copy was
always emitted correctly.

**Checked and found sound, recorded not fixed:** `append <property> to
<buffer>` has no such hole because it has no such form. `append
arguments's first to joined.` is a parse error (`Expected value to
append`), and the two-step `append <text variable> to <buffer>` is
rejected by the analyzer (`Buffer append requires a buffer source`).
Both spellings LANGUAGE.md:3383-3389 does document — `append "literal"
to b` and `append "{arguments's first}" to b` — go through the format-part
sink #52 fixed, and both are correct. The rejection is uniform for a
property and for a plain text variable, so nothing here is
property-specific.

**Not this bug's family, left alone:** `b's capacity` on an *unsized*
buffer reports `4096` where the declaration's allocation request was
`1024`. That is `_alloc_buffer` rounding to a page and is the same before
and after this fix, for every unsized buffer however it is initialized.

---

### 59. A `treating` clause on a mixed-list loop variable prints a pointer, matched or mismatched (wrong value; family of #44/#45)

**Status:** **fixed** (unreleased, on top of 0.4.8+#49/#50/#52/#53/#54/#55/#56/#57/#58).
Regression tests: `tests/400_treating_a_mixed_list_keeps_each_tag.vox`
(the three reproductions below plus a number match that does fire),
`401_treating_a_mixed_list_spares_floats_and_booleans.vox`,
`402_treating_a_mixed_list_holding_a_value_keeps_its_tag.vox`,
`403_treating_inside_a_function_keeps_each_tag.vox`,
`404_treating_a_map_s_values_keeps_each_tag.vox`,
`405_treating_carries_the_tag_into_a_value_parameter.vox` and
`406_treating_survives_an_is_a_guard_downstream.vox`, plus the unchanged
controls `359_treating_matching_types_substitutes.vox` and
`360_treating_over_an_unprovable_list.vox` from #55. Found 2026-08-21 by
the #55 fix worker (REPORT-55, §6) while closing #55; master-reproduced on
this branch.

```vox
print each item from [1, "a"] treating "a" as "b".
```
→ `1` then `4198536` (expected `1` then `b`)

```vox
print each item from [1, "a"] treating 98 as 31.
```
→ `1` then `4198536` (left standing after #55 — #55 added a compile-time
type-mismatch guard for statically-typed collections only, see Mechanism)

```vox
print each item from [1, "a"].
```
→ `1` then `a` (correct — no `treating` clause)

All three re-run three times each on this branch's binary; every line is
byte-for-byte identical across runs, including the pointer value
(`4198536` = `0x401088`). That address does **not** wander the way #44's
heap pointer does — this is a fixed `.rodata`/text-segment address in a
non-PIE binary, not an ASLR'd allocation — but it is still a raw address
printed as if it were the string's value.

**What the manual promises.** The `treating X as Y` clause (LANGUAGE.md
:404-424, duplicated at :3050-3070) is "inline value substitution": "If
the loop variable equals `<match>`, it's replaced with `<replacement>`
for that iteration" (:424 / :3070) — nothing here narrows the promise to
single-typed collections. Mixed-list printing is documented separately
(:2227 "elements carry a small per-slot type tag at runtime"; :2348 "the
value carries its runtime tag, so a text prints as text and a number as
a number") — and the third repro above, with no `treating` clause,
honors that exactly. `treating` is the only thing that breaks it.

**Step 0.** The vox-fuzz keywords ledger (`expansion.md`, Discrepancy 4)
already carries the *mismatched* case as unfiled, reasoning that "with a
mixed list the element type genuinely is not statically uniform, so the
'can't always know' defence is at its strongest here" — while still
noting "it still leaks a memory address into program output." That
defence does not reach the first repro above at all: `treating "a" as
"b"` substitutes text for text, so there is no type ambiguity for the
compiler to plead ignorance of, and the *matched* case fails identically
to the mismatched one. A defence that only covers half of two
reproductions that behave identically cannot license either, so this is
filed rather than left as a recorded discrepancy.

**Mechanism.** `Expr::TreatingAs { value, .. } =>
self.infer_expr_type(value)` (`src/codegen/expr.rs:2421`) reports the
*subject's* static type for a `treating`-wrapped loop variable — for a
mixed list, that's an untyped/unknowable static type — instead of
deferring to the per-slot runtime tag the way a bare `Expr::Identifier`
read does. `Print`'s printer selection reads that inferred type, so
wrapping the loop variable in `TreatingAs` at all — independent of
whether `<match>` fires, and independent of whether its type matches the
collection's — discards tag dispatch and falls through to the same
print-the-pointer-as-an-integer path #44 documents for an unrelated
reason. #55 (this repo, commit 5aab1c3) closed the *statically-typed*
half of this family — a `treating` clause whose `<match>`/`<replacement>`
type disagrees with a **known** collection element type is now a compile
error — but it deliberately does not invent a static element type for a
mixed list (there isn't one to invent), so `TreatingAs`'s type inference
at :2421 is untouched by that fix and this survives it.

**The fix.** #55 rejected the *provable* mismatch and deliberately left
the dynamic subject "to the runtime" — `treating_subject_type`
(`src/analyzer/types.rs:1180-1187`) returns `None` for exactly
`Type::Value | Type::Unknown`, so there is no compile-time answer to give
here and none is invented. This is the runtime half. When the subject
carries a runtime tag, `treating` now dispatches on it
(`generate_treating_on_tagged_subject`, `src/codegen/expr.rs`), reaching
one of three answers in the order the hardware finds them:

1. **The subject's tag differs from the match's** — a text element under
   `treating 98 as 31`, say. Different types can never be equal, so the
   substitution does not fire, nothing is read through the match (no
   crash, no pointer), and the element comes through wearing its own tag.
   This is the same guarantee #55's `match_cannot_be_text` gave the static
   path, now stated by the tags outright rather than inferred from static
   types.
2. **The tags agree, the values differ** — text compares by bytes
   (`_str_eq`), everything else in registers. Element untouched, own tag.
   This is the half the old pointer `cmp` got wrong: on a mixed list
   `treating "a" as "b"` compared the element's address against the match
   literal's address and so never fired, even on `"a"`.
3. **The tags agree and the values are equal** — the substitution fires
   and the result is the replacement, carrying the replacement's own tag.

The result leaves its value in rax and its tag in r11, the contract a
mixed-element read already has (`expr_leaves_tag_in_r11`,
`src/codegen/tags.rs`), so Print, the append path, and `value` parameter
passing all dispatch on it exactly as they do for a bare read of the loop
variable. `infer_expr_type`'s `TreatingAs` arm at :2421 is left alone:
with the tag now flowing, the clause reports the same static type a bare
read of the subject does, which is the parity the entry asked for.

A subject that *does* have a static type — a homogeneous text list, a
buffer, a range — keeps the existing static path unchanged, which is why
`359_treating_matching_types_substitutes.vox` and
`360_treating_over_an_unprovable_list.vox` are byte-identical before and
after.

**The two open questions, answered.** A `treating` clause inside a
`For each ... in` grid clause does not exist to be wrong: `treating`
belongs to the `each <var> from <collection>` loop expansion only
(LANGUAGE.md:5223), and `For each item in [1, "a"] treating "a" as "b",
print item.` is a parse error ("Expected a statement, got Treating"). The
downstream question was real and is now fixed: the tag reaching a `value`
parameter was the integer default, so `if what is a text` was false for a
text element — `406_treating_survives_an_is_a_guard_downstream.vox` is the
regression test.

**What this fix does not reach.** The subject's tag is compared against
the match's, so the match (and the replacement) must have a tag to
compare. A literal or a statically-typed variable does; a `value` does
not, at emit time, so a clause whose *match* or *replacement* is a
`value` keeps the old static path and still prints the element's address:

```vox
a value called probe is "-".
print each item from [1, "-"] treating probe as "X".
```
→ `1` then `4198538` (expected `1` then `X`), and the same for
`treating "-" as swap` with `a value called swap is "X".` Both are
byte-identical before and after this fix — no regression, just not
covered. This is a different mechanism from the one above (there the
subject had no static type; here the *match* has no emit-time tag), and
closing it means loading the match's and replacement's tags at runtime
too and choosing the comparison — bytes or registers — on a runtime
branch. Unfiled; worth its own entry. No memory-safety hazard either way:
with no provable text on either side the comparison stays in registers,
so nothing is dereferenced.

**Found alongside, not fixed here (out of scope).** `append each <var>
from <collection> treating <match> as <replacement> to <list>.` — a form
the grammar gives at LANGUAGE.md:5190 — drops the clause entirely. It is
not this bug and not a tag problem: it drops on a *homogeneous* text list
too (`append each item from ["a", "c"] treating "a" as "b" to out.`
yields `["a", "c"]`), and no `treating` block is emitted for it at all.
Unfiled; worth its own entry.

---

### 60. `{f:.N}` for N ≥ 18 corrupts the decimals — culminating in a spliced `i64::MIN` sentinel from N=20

**Status:** **fixed** (unreleased, on top of 0.4.8+#49–#58). Severity:
**wrong answer** — a documented specifier with no stated bound printing
digits that are not the value's, and from N=20 a decimal integer spliced
into the middle of a fraction. Regression test
`tests/410_float_precision_any_places.vox` (the three bands; the boundaries
N = 0, 1, 15–20, 30, 50; negatives; zero; a value past 2^53 and one past
2^63; the rounding cases and the exact ties), proven to print the corrupt
bands on `origin/main`'s runtime and to pass after, plus the untouched
control `tests/135_float_rounding_carry.vox`. Found 2026-08-20 by the
vox-fuzz literals worker's format-specifier probes (REPORT-LITERALS §4,
D2); master-reproduced on this branch.

```vox
a float called f is 3.14159.
Print "{f:.17}".   → 3.14158999999999988      (correct)
Print "{f:.18}".   → 3.141589999999999872     (wrong — see below)
Print "{f:.19}".   → 4.-8584100000000001280   (wrong — bad integer part, embedded '-')
Print "{f:.20}".   → 3.0-9223372036854775808  (wrong — i64::MIN literally spliced in)
Print "{f:.25}".   → 3.000000-9223372036854775808
Print "{f:.30}".   → 3.00000000000-9223372036854775808
```

Re-run three times each; all six lines reproduce byte-for-byte every
time. The double's true value, expanded to arbitrary precision
(`python3 -c "from decimal import Decimal; print(format(Decimal(3.14159),'f'))"`),
is `3.14158999999999988261834005243144929409027099609375…`; glibc's
correctly-rounded `printf("%.*f", n, f)` agrees with Vox through N=17 and
diverges starting at N=18, where the correct rounding is `…999883`
against Vox's `…999872`.

**What the manual promises.** LANGUAGE.md:3106: `{var:.N}` is "N decimal
places" (`{pi:.2}` → `3.14`). No bound on N is stated anywhere in the
Format Specifiers section (:3101-3119).

**Mechanism.** `_print_float_precision` (`coreasm/x86_64/format.asm
:1035`) takes the fractional part once, then scales it by `10^N` two
different ways, both unbounded in N:
- `.mul_loop` (:1081-1088) multiplies the fractional `xmm0` by 10, N
  times, in a plain `mulsd` loop rather than computing `10^N` once —
  the accumulated floating-point error from N sequential multiplications
  is already enough to explain N=18's `…872` vs the correctly-rounded
  `…883`.
- `.threshold_loop` (:1096-1101) separately computes `10^N` as a
  **64-bit signed integer**, via `imul r15, 10` repeated N times, also
  with no bound. `10^19` (10 000 000 000 000 000 000) exceeds
  `i64::MAX` (9 223 372 036 854 775 807), so at N=19 the multiplication
  wraps and `r15` reads as negative under the signed `cmp r14, r15 / jl
  .no_carry` carry check at :1104-1105 — which is why N=19 shows a
  corrupted integer part and a `-` spliced into the middle of the
  digits, not yet the clean `i64::MIN` literal.
- By N=20 the scaled fractional value itself (`~1.4×10^19`) exceeds what
  `cvttsd2si` (:1093) can convert. Per the SSE2 spec, `cvttsd2si` on a
  source that overflows the destination range returns the "integer
  indefinite" value `0x8000000000000000` = **`-9223372036854775808`** —
  exactly the literal spliced, unmodified, into every N≥20 output above.

**Also this bug, not separately filed.** The same `cvttsd2si` took the
INTEGER part (:1085), so every magnitude at or beyond 2^63 printed the
sentinel there too — `{big:.2}` on 1e22 gave
`-9223372036854775808.-9223372036854775808`, and `{big:.0}` gave
`-9223372036854775808`. The default printer `{big}` has been right in that
range since #34; only the precision path was left behind.

**What this entry could not name before.** The first-bad-N is a function of
the float's fractional magnitude, not a constant — the 18/19/20 boundary
above is specific to `3.14159`. The two overflows underneath it are
unconditional and surface for any float at a large enough N, which is why
the fix is not a bound but a different algorithm.

**The fix — nothing is scaled; the digits are produced.**
`_print_float_precision` (`coreasm/x86_64/format.asm`) now takes the value
apart as `m * 2^e` with `m` the exact integer mantissa:

- `e >= 0` — an exact integer with no fraction at all (past 2^52 a double
  has no room left for a fractional bit). Its digits come from
  `_float_big_int_digits` (`coreasm/x86_64/float.asm`), the routine the
  default float printer already uses in this range, so `{f}` and `{f:.N}`
  now agree on every value — including the infinities and NaNs both render
  as the max-double digit string.
- `e < 0` — the integer part is `m >> -e`, below 2^52 and so a plain
  register value, and the fraction is the exact rational
  `(m & (2^-e - 1)) / 2^-e`. Its decimal digits come from Horner's rule
  over the numerator's bits, least significant first: start at zero and,
  for each bit, "add it, then halve". Halving a decimal digit string is
  exact and appends at most one digit (always a 5), so `-e` steps produce
  at most `-e` digits — 1074 at the very most, for the smallest subnormal
  — and every digit is the true one.

Rounding happens once, on those digits: the first digit not printed
decides, with a sticky flag for anything past it, and an exact tie goes to
the even digit, which is what glibc's `printf` does. Digits past the
expansion's end are zeros because the value has ended, so an N larger than
the expansion pads with them — a page at a time, through the same writer
#61's padding uses — rather than computing anything. Only N+1 digits are
ever kept: halving carries rightward and never left, so a digit past the
guard can never change a printed one, and dropping it costs only the
sticky bit.

**Exactness.** Checked digit-for-digit against glibc `printf("%.*f")` on
979 (value, N) pairs: 30 values × 23 precisions and 17 extreme values × 17
precisions. Every pair matches — including the smallest subnormal
(5e-324, whose expansion is 1074 places), the largest double
(1.7976931348623157e308), 2^52, 2^53 and 2^63 with their neighbours, the
exact ties, and N up to 1500. `{f:.1000000}` renders a million places in
0.2 s, byte-identical to `printf`.

**Before and after** (`origin/main`'s runtime against the fix, same
compiler; the last column is glibc `printf("%.*f")` on the same double):

| program | before | after | printf |
|---|---|---|---|
| `{pi:.17}` | `3.14158999999999988` | same | same |
| `{pi:.18}` | `3.141589999999999872` | `3.141589999999999883` | `3.141589999999999883` |
| `{pi:.19}` | `4.-8584100000000001280` | `3.1415899999999998826` | `3.1415899999999998826` |
| `{pi:.20}` | `3.0-9223372036854775808` | `3.14158999999999988262` | `3.14158999999999988262` |
| `{pi:.30}` | `3.00000000000-9223372036854775808` | `3.141589999999999882618340052431` | same |
| `{pi:.50}` | `3.0000000000000000000000000000000-9223372036854775808` | `3.14158999999999988261834005243144929409027099609375` | same |
| `{big:.2}`, big = 1e22 | `-9223372036854775808.-9223372036854775808` | `10000000000000000000000.00` | same |
| `{big:.0}`, big = 1e22 | `-9223372036854775808` | `10000000000000000000000` | same |
| `{nearly:.0}`, nearly = 9.9999 | `9` | `10` | `10` |
| `{nearly:.3}` | `10.000` | `10.000` | `10.000` |
| `{half:.0}`, half = 0.5 | `0` | `0` | `0` |

The `9.9999` row is the one behaviour change outside the corrupt bands:
N=0 used to print the truncated integer while every N≥1 rounded, so the
specifier disagreed with itself. It rounds now, as `printf` does. (The
cast rule at LANGUAGE.md:2023, "Float to number **truncates**", is about
`as a number`, not about printing decimal places.)

---

### 61. A format pad width beyond `i32::MAX` is silently dropped — no padding, no diagnostic; a pad width below that renders correctly but at roughly one syscall per byte

**Status:** **fixed** (unreleased, on top of 0.4.8+#49–#58). Severity:
**silent wrong output** for the dropped width; the per-character render
below it is a performance defect, not a hang. Regression tests
`tests/411_pad_width_any_size.vox` (every padded form, and a width past
the 4096-character page the padding is now written in),
`tests/compile_fail/169_pad_width_past_what_vox_can_count.vox` and
`170_decimal_precision_past_what_vox_can_count.vox`, plus four codegen
tests in `src/codegen/tests.rs` that pin the emitted width and precision
either side of `i32::MAX` without writing two billion spaces. Found
2026-08-20 by the vox-fuzz literals worker's format-specifier probes
(REPORT-LITERALS §4, D3); master-reproduced on this branch, root-caused
against source on this branch (below).

```vox
a number called n is 255.
Print "{n:1000000000}" without newline.
```

| width | measured on this branch |
|---|---|
| 1 000 | 1 000 bytes, instant |
| 100 000 | 100 000 bytes, 0.39 s |
| 1 000 000 | 1 000 000 bytes, 3.88 s |
| 10 000 000 | 10 000 000 bytes, 36.6 s |
| 100 000 000 | not finished after 25 s in the foreground (only 6.47 MB written by then); run to completion in the background: **100 000 000 bytes, 413.25 s** |
| 2 147 483 647 (2^31 − 1, `i32::MAX`) | not finished after 30 s (only 8.37 MB written); not run to completion |
| **2 147 483 648 (2^31)** | **returns instantly, 3 bytes (`255`), no padding at all** |

The 100 000 → 100 000 000 points give a stable throughput of roughly
240-273 KB/s across three orders of magnitude — consistent with a
genuinely linear render, just a very slow one. 2 147 483 647 at 30 s had
written 8.37 MB, ≈279 KB/s, the same rate — **this is the documented,
correctly-padding case, not a hang; it is slow because of how each byte
is written (see Mechanism), and it is on a linear track to finish, not
stuck.** At the measured 1e8 rate, `1 000 000 000` extrapolates to
≈4 130 s (≈69 minutes) and `2 147 483 647` to ≈8 870 s (≈2.5 hours) —
both large, neither divergent. Per the language designer's standing
ruling (2026-08-21), the timing above is recorded as measured, not
asserted as a "hang" — whether the render being this slow is itself
worth filing is a separate, pending call.

**The one datapoint that is unambiguously a bug: 2 147 483 648 renders no
padding at all, silently.** LANGUAGE.md documents `{var:N}` / `{var:0N}`
("Pad to N characters" / "Zero-pad to N chars", :3107-3108) with no
upper bound on N stated anywhere in :3101-3119 — the construct is legal
for any `N`, and the compiler gives no diagnostic. What actually happens
at N = 2^31 is not "attempt a 2-billion-byte pad and something goes
wrong at that scale" — it is that the width clause is discarded before
codegen ever sees it.

**Mechanism, the silent drop.** `src/codegen/format.rs:230`:
```rust
if let Ok(width) = width_digits.parse::<i32>() {
    spec.width = Some(width);
    ...
    has_width = true;
    ...
}
```
`width_digits` is parsed as `i32`. `"2147483648"` is one past
`i32::MAX`, so `.parse::<i32>()` returns `Err`, the `if let` body never
runs, `has_width` stays `false`, and the format spec is built exactly as
if no width had been written at all — the same code path as a bare
`{n}`. No error surfaces because nothing checks the `Err` arm; the parse
failure is silently swallowed. `2147483647` (`i32::MAX` itself) parses
successfully, so it takes the normal padded-print path — which is why
the boundary sits at exactly `2^31`, not at some render-size limit.

**Mechanism, the slow-but-linear render for widths that do parse.**
`_print_int_padded_impl`'s `.pad_loop` (`coreasm/x86_64/format.asm
:999-1012`) writes padding **one character per `write(2)` syscall** —
`push`/set one byte in `_format_buffer`/`syscall`/`pop`, in a loop that
runs `width - digit_count` times. That is O(N) as documented, but with a
syscall's worth of overhead per byte instead of one buffered/vectored
write, which is the entire reason a width in the low billions takes
minutes: at ~265 KB/s, `2^31` bytes (if it parsed) would be a ~2.2 hour
render, and `1 000 000 000` a ~1 hour render — neither is an infinite
loop, both are just this loop's per-byte cost multiplied out.

**What this entry could not answer before.** The `.parse::<i32>()` is in
the one function every sink reads a spec through, so it truncated the
zero-pad and the hex, binary and octal width forms identically — and the
precision, `{f:.N}`, which is the same `if let` two branches up: a
precision past `i32::MAX` silently printed the float at its default
precision instead. The per-character pad loop was likewise in all four
padded printers (`_print_int_padded_impl` and the hex, binary and octal
ones), not only the integer one. All of them are fixed together below.
`2 147 483 647` has now been run to completion (1.39 s) rather than
extrapolated.

**The fix, the silent drop — one reader, and a count it cannot honour is
said out loud.** `src/codegen/format.rs` reads the spec through
`read_format_spec`, which returns the spec *and*, separately, any count it
could not honour. A too-large count comes back **saturated** to
`i64::MAX`, never absent: an absent width is indistinguishable from one
that was never written, which is the entire shape of this bug. The
analyzer (`Analyzer::check_format_spec`, `src/analyzer/expressions.rs`)
turns that fault into an error naming the limit, on both format-string
sinks (`Print` and a format string used as a value). `FormatSpec`'s
`width` and `precision` are now `i64`. A width that fits — `2147483648`
included — reaches the printer and pads.

One more thing the same reader got wrong: `remaining` was cut at a fixed
offset of one zero, so a width written with more than one leading zero
lost its base specifier — `{n:004x}` printed as zero-padded *decimal*
while the documented `{n:04x}` (LANGUAGE.md:3110) printed hex. It is cut
at the digits actually consumed now, and both spellings print `0x00ff`.

**The fix, the syscall per byte — a page at a time.** `_fmt_emit_pad`
(`coreasm/x86_64/format.asm`) fills one 4096-byte page with the pad
character and writes it in blocks through `_fmt_write_all`, which resumes
after a short write and retries an interrupted one — a per-byte loop on a
blocking fd never had to care about either. All four padded printers call
it, and so does the precision printer for the zeros past a value's
expansion (#60).

**Before and after** (this machine, output to `/dev/null`, best of 3–5
runs; "before" is `origin/main`'s runtime assembled against the same
compiler, which is why the 2^31 row is measurable at all):

| width | before | after |
|---|---|---|
| 1 000 | 0.0038 s | 0.0011 s |
| 1 000 000 | 2.579 s | 0.0015 s |
| 100 000 000 | 283.5 s | 0.065 s |
| 2 147 483 647 (`i32::MAX`) | not run: ~1.6 h at the measured rate | 1.39 s, 2 147 483 647 bytes |
| **2 147 483 648 (2^31)** | **3 bytes, no padding, instantly** | 1.34 s, 2 147 483 648 bytes |
| 99 999 999 999 999 999 999 | 3 bytes, no padding, instantly | compile error naming 9223372036854775807 |

The 1 000 row is process startup, not padding. Both 2^31 rows were also
piped to `wc -c`, which returned the width exactly — the byte count is
the width, not merely "a lot of spaces". The two sides of `i32::MAX` now
behave the same as each other, which was the point: the old cliff sat
between two adjacent literals with nothing said about it.

---

### 62. A `.lib` entry with no `, returning` clause is not type-checked at the call site — its non-existent result is silently accepted into a typed variable

**Status:** **fixed** (unreleased, on top of 0.4.8). Regression test:
`see/void-result` in `test.sh` (A4.5) — the consumer that reads `greet`'s
result is refused with the diagnostic below, and the same program calling
`greet.` as a statement still compiles and runs. Found 2026-08-20 by the
vox-fuzz libraries claim ledger (Discrepancy 4) as "recorded, not filed,
not adjudicated"; adjudicated and ordered filed by the language designer
(Josj, 2026-08-21) and master-reproduced on this branch.

```vox
see mathkit version "1.0" from "fixtures/libmathkit.lib".

a number called n is greet.
Print n.
```

`greet`'s `.lib` entry is bare — `To greet.`, no `, returning` clause —
meaning it genuinely returns nothing. Re-run against
`fixtures/libmathkit.lib`/`.so` from the vox-fuzz libraries probe set:

```
hello from mathkit
1
```

Exit 0, no diagnostic. `greet` ran (it printed its message), and `n`
receives `1` — plausibly leftover register state from the call/return
convention, not a computed answer — accepted into `a number called n`
with no complaint anywhere in the pipeline.

**What the manual promises.** LANGUAGE.md:4964-4966: "No `returning`
clause means the function returns nothing." The six-step `see`-of-`.lib`
consumption process, step 5 (LANGUAGE.md:4990): "Registers the
signatures, so calls type-check like any other function." A void
function's result used as a value is exactly the shape a type-check
exists to reject.

**The check exists and works on the other side of the same call.**
`'add two numbers' of 3.` (arity mismatch, one argument short) against
the same `.lib` is rejected at compile time: `error: Function 'add two
numbers' expects 2 arguments but was called with 1.` — re-run and
confirmed on this branch. Step 5's promise holds for **parameters** and
fails for **return values** on the identical library, the identical
`see`, the identical call-site type-checking pass.

**Step 0.** LANGUAGE.md states plainly that no clause means "the
function returns nothing" — there is no reading under which a genuinely
void function's result may be read into `a number`. The ledger's own
weakest defence ("the omitted clause is ambiguous between true `void`
and 'return type not recorded'") does not survive here either: `greet`
is unambiguously `To greet.` with no `Return` statement anywhere in its
body — the true-void case, not the recorded-vs-unrecorded edge case —
so even the ledger's most charitable reading does not reach this repro.
Filed rather than left as a discrepancy, per the designer's ruling.

**Severity.** Not memory-unsafe — nothing crashes, nothing is
dereferenced wrongly, and the value read is a plausible-looking small
integer rather than a raw pointer (contrast #44/#45/#59). It is a
soundness gap in the one step of the `.lib` pipeline whose stated job is
type-checking a boundary: a library consumer gets no compiler help
distinguishing "this call's result is real" from "this call's result is
whatever was left in a register," for both a genuinely void function and
(per the ledger's LIB-39/broader note) any function whose author wrote a
bare `Return <expr>.` with no declared return type.

**Expected fix (Josj, 2026-08-21).** Using a void `.lib` entry's result
as a value is a compile-time error, not a wider guess at what the
leftover register might mean — symmetric with #45's fix direction.
Reject at the use site, naming the function, stating that it returns
nothing, with the caret on the use and a hint pointing at both ways out:

```
error: 'greet' has no declared return type in its .lib entry, so its
result cannot be used as a value here.
  --> D4.vox:3:20
    |
  3 | a number called n is greet.
    |                      ^--- here

  hint: add ', returning a <type>' to greet's .lib entry, or call
        'greet' as a statement instead of assigning its result
```

The same rejection applies to any `.lib` entry with no `, returning`
clause, not just a true `void` function — per the vox-fuzz `libraries.md`
ledger's LIB-39, a bare `Return <expr>.` with no declared type records no
return type in the `.lib` at all, so it is indistinguishable from
`greet` at the consuming end and must be rejected identically.

**Mechanism.** `ImportedFunction::return_type` is already `Type::Void` for
an entry with no `, returning` clause (`src/lib_file.rs`) — the fact was
recorded correctly and then never consulted. `check_function_call` reached
the import and checked its **arguments** (`validate_import_call_args`:
arity, then each argument's provable category), and nothing anywhere asked
what the call answered with. The result slot took whatever `rax` held on
return from a function that never set it.

**The fix.** `src/analyzer/void_results.rs`, one rule for both halves of
"returns nothing": the `Expr::FunctionCall` and bare-name arms of
`analyze_expr` are the two places a call's result is READ (a call run for
its effect is `Statement::FunctionCall` and never comes through there), so
each asks `void_result_of` first. That resolves the name the way a call
resolves — a local definition shadows a same-named import, and an
ambiguous name is left to its own diagnostic — and answers with the
imported-entry case here, or bug #63's procedure case for a local `To`
with no `Return`. Rendered:

```
error: 'greet' has no declared return type in its .lib entry, so its result cannot be used as a value here
  A `.lib` entry with no `, returning` clause is a function that returns nothing (LANGUAGE.md:4963-4965), and consuming a library type-checks its calls like any other function's (LANGUAGE.md:4990) - so what lands here is whatever the call left in the return register, not an answer.
  --> d4clean.vox:3:22
    |
  3 | a number called n is greet.
    |                      ^--- here

  hint: add `, returning a <type>` to greet's .lib entry, or call 'greet' as a statement instead of using its result
```

Parameter-side checking is untouched (ledger LIB-43f/g still pass), and
`greet.` as a statement — the whole point of exporting a void function —
is untouched too.

---

### 63. A procedure — a `To` with no `Return` at all — is silently accepted as a value: `print ping.` prints `pong`, then `1`

**Status:** **fixed** (unreleased, on top of 0.4.8). Regression tests:
compile-fail cases `tests/compile_fail/158_procedure_result_in_a_declaration.vox`
through `168_bare_return_result_used.vox` — one per value position — plus
the passing controls `tests/407_procedure_called_as_a_statement.vox` (both
call spellings, and a `Return.` that bails out early) and
`tests/408_declared_return_used_as_a_value.vox` (a function that DOES
declare its return type, read in all nine positions). Found 2026-08-21 by
the #45 fix worker, master-reproduced on this branch.

```vox
To ping. Print "pong".

print ping.
```
→ `pong`, then `1` — exit 0, no diagnostic

```vox
To ping. Print "pong".

a number called n is ping.
Print n.
```
→ `pong`, then `1`

`ping` returns nothing: there is no `Return` anywhere in its body. The `1`
is not an answer, it is whatever the call left in the return register —
`Print`'s own syscall result, as it happens — read as a number because the
slot it landed in was a number.

**What the manual promises.** LANGUAGE.md:684-686 gives `To ping. Print
"pong".` as a definition in its own right, LANGUAGE.md:772-777 says a
zero-argument call may be written as the bare name, and "Calling as
Statement" (LANGUAGE.md:779-785) is the position a call with no result
belongs in. Nowhere does the Functions section hand a value back from a
function that never returns one, and LANGUAGE.md:2641-2645 — the only
sentence in the manual about a function reaching its end without
returning — is explicitly about the empty value of a **declared** type
("empty text, zero, or a `value` tagged as the number `0`"), which a
procedure has not got. Not even that most charitable reading reaches this
program: it does not answer `0`, it answers a leftover.

The governing rule is LANGUAGE.md:656-660, the paragraph that decided the
0.3.0 identifier/literal split: "A function pointer, printed as a number,
silently. No error, no warning; the program runs and gives a wrong answer
that looks like data." That is this bug's output exactly, from a sibling
cause — a name in value position whose result does not exist — and the
manual says the payoff of 0.3.0 is that "this class of silent wrong answer
is gone."

**Severity.** Not memory safety: the leftover is a small integer and
nothing dereferences it. It is a soundness gap of the same family as #45
(a result with no type) and #62 (the same absence across a `.lib`
boundary) — a wrong answer that looks like data, with the compiler silent.

**The fix.** `src/analyzer/void_results.rs`. The signature pre-pass records
every `To` whose declared return type is `Void` **and** whose body contains
no value-returning `Return` at any depth; a call in value position to one
of those is refused. The two halves of `Void` partition cleanly: a function
that hands a value back but declared no type for it is #45's case and is
untouched here, including the one where the branches return different
declared types (LANGUAGE.md:2647-2652), which stays `Void` in the signature
and still returns something. A bare `Return.` counts as no return: it ends
the call without answering it, and its result is refused with the same
message. Rendered:

```
error: 'ping' returns nothing, so its result cannot be used as a value here
  A `To` with no `Return` hands nothing back (LANGUAGE.md "Functions"), and this position reads a value - so what lands here is whatever the call left in the return register, not an answer.
  --> 159_procedure_result_printed.vox:8:7
    |
  8 | print ping.
    |       ^--- here

  hint: give 'ping' a `Return a <type>, <expression>.`, or call 'ping' as a statement instead of using its result
```

**Positions covered**, all refused: a declaration initializer, `print`, a
list slot, a map value, a format hole, a `value` declaration, a comparison
operand, an argument to another call, `Set x to`, `Append x to`, and a
`Return` of the result. Every one is `analyze_expr` reading an expression,
which is what makes it one check rather than eleven.

**One position that was already an error, for a different reason.** A bare
name in a format hole — `print "got {ping}"` — is `Unknown identifier
'ping'` before and after: a hole names a variable, and the zero-argument
bare-name call form (plan 270 G4) does not reach into one. `{shout of 3}`,
the `of` spelling, is a real expression and is refused with the message
above. Unchanged by this fix, recorded because a reader of the corpus will
notice the two holes read differently.

---

### 64. The `the <name>'s <property>` spelling implements almost no properties — `the h's size` reads, `the h's descriptor` is a parse error

**Status:** **fixed** (this branch), found 2026-08-21 by the #38 fix
worker while probing the file-property surface, master-confirmed. Fails
loudly at compile time, so no program can silently do the wrong thing —
the same mildest class as #38. The cost is that a documented, encouraged
spelling reaches only a fraction of the language.

```vox
open a file for reading called h at "./data.txt".
Print the h's size.          (11 — reads)
Print the h's descriptor.    (error: Expected property name, got Descriptor)
```

Both lines are the same reading. LANGUAGE.md:1857 says *"`the` is
optional before variable names in expressions"* (and :1872 repeats it for
comparisons); :523 introduces `the` as the way to *"reference an existing
variable"*; :887 states the article rule outright — *"`the` pairs with
**known identifiers**"*. Nothing in the Variables section, the possessive
rule at :632, or the File Properties table at :3470 marks a property as
reachable through one spelling and not the other. The manual writes both
spellings itself: `src's size` in the File Properties example, `the 'job
timer''s start time` in the Timer example.

**The parser had two possessive property sites and they knew different
languages.** `src/parser/expressions.rs` resolved `name's property` in
the `Token::Identifier` arm of `parse_primary` and `the name's property`
in the `Token::The` arm, each with its own hand-written list of property
arms. The second list held the time properties, the timer properties,
and `size`/`length`/`capacity`/`empty`/`full` — and nothing else. Every
property outside it fell to that arm's `_ =>` and became *"Expected
property name"*.

**The whole surface, probed both ways against origin/main.** Every row
is one property read twice, once per spelling, on the same value:

| Property group | Read | Bare `x's p` | `the x's p` |
|---|---|---|---|
| **File** | `size` | ✓ `11` | ✓ `11` |
| | `descriptor` | ✓ `3` | ✗ *Expected property name, got Descriptor* |
| | `readable` | ✓ `1` | ✗ *…got Readable* |
| | `writable` | ✓ `0` | ✗ *…got Writable* |
| | `modified` | ✓ `1787319556` | ✗ *…got Modified* |
| | `accessed` | ✓ `1787319556` | ✗ *…got Accessed* |
| | `permissions` | ✓ `420` | ✗ *…got Permissions* |
| | `exists` | ✓ #38's diagnostic | ✗ *…got Exists* (generic) |
| **List** | `length`, `size`, `empty` | ✓ | ✓ |
| | `first` | ✓ `Alice` | ✗ *…got Identifier("first")* |
| | `last` | ✓ `Charlie` | ✗ *…got Identifier("last")* |
| **Map** | `size`, `empty` | ✓ | ✓ |
| | `keys` | ✓ `["name", "age"]` | ✗ *…got Keys* |
| | `values` | ✓ `["Alice", 30]` | ✗ *…got Values* |
| | `"name"` (key read) | ✓ `Alice` | ✗ *…got StringLiteral("name")* |
| **Number** | `absolute`, `sign`, `even`, `odd`, `positive`, `negative`, `zero` | ✓ | ✗ all seven |
| **Buffer** | `size`, `length`, `capacity`, `empty`, `full` | ✓ | ✓ |
| | `type` | ✓ `Buffer (static)` | ✗ *…got Identifier("type")* |
| **Time** | `hour`, `minute`, `second`, `day`, `month`, `year`, `unix` | ✓ | ✓ |
| **Timer** | `duration`, `elapsed`, `running`, `start time`, `end time` | ✓ | ✓ |
| | `'start time'`, `'end time'` (quoted) | ✗ *…got Identifier("start time")* | ✓ |
| **Specials** | `'arguments''s count`, `'environment''s count` | ✓ | ✗ *Expected property name* |
| | misspelled `arguemnts's count` | ✓ *did you mean 'arguments'?* | ✗ generic |
| **Thing field** | `origin's x` | ✓ `3` | ✓ `3` |

**Inside a format hole the message is different, the outcome is not.**
`Print "{the h's descriptor}".` reported `Unknown variable: the h's
descriptor` — the hole's parse falls back to reading its whole contents
as a name, and the analyzer rejects that name later. Still a compile
error, never a silent wrong answer; the errors in the table above are
what statement, condition and initializer position report.

The quoted-timer and misspelled-specials rows are the same defect
pointing the other way: the `the` list had picked up two arms the bare
list never got, and the bare list had the typo diagnostic the `the` list
never got. Two hand-maintained copies drift in both directions.

**Not a bug: `the` before a name that is not a variable.** `the
arguments's count`, `the environment's count` and `the current time's
hour` are all rejected, and correctly so. `arguments`, `args`,
`environment`, `env` and `current time` are reserved words, not variable
names, so LANGUAGE.md:1857 does not reach them; the manual writes every
one of them bare (`arguments's count` at :4385, `environment's "HOME"`
at :4559, `{current time's hour}` at :3215) and offers `the argument at
N` / `the environment variable "NAME"` as the separate `the`-led phrases
those names do have. Left alone. The *quoted* forms `'arguments''s` and
`'environment''s` are ordinary identifiers, and those the fix does make
agree.

**Consequence.** `the` is not a niche spelling: LANGUAGE.md teaches it
in the Variables section, uses it in the Timer example, and the whole
surface syntax is built to read as English, where the article is the
natural thing to write. A program that says `the handle's size` and then
`the handle's descriptor` gets one line of English and one parse error,
with a message that names a token kind rather than the real problem.

**Fix.** One property-resolution path, not two:
`Parser::parse_possessive_tail` in `src/parser/expressions.rs` holds the
whole tail after `'s` — the specials, the typo diagnostic, the map-key
read, the property arms, #38's `exists` explanation, the `start time` /
`end time` two-word follower and the duration unit — and both spellings
call it. Adding or diagnosing a property now happens in exactly one
place. This is #51's and #58's lesson applied to the parser: a second
copy of a list is a second answer waiting to disagree.

Regression tests: `tests/420_the_possessive_reads_file_properties.vox`
(every File Properties row through `the`),
`tests/421_possessive_spellings_agree.vox` (the same property read twice,
once per spelling, across file, list, map, number and buffer),
`tests/422_the_possessive_in_every_position.vox` (initializer, `Set`,
condition, format hole, collection literal, arithmetic, call argument),
`tests/423_the_possessive_on_collections.vox`,
`tests/424_the_possessive_on_numbers_and_timers.vox` (including the
quoted-timer row, which failed the other way round), and
`tests/compile_fail/171_the_possessive_file_handle_exists.vox` — #38's
diagnostic, which the article used to hide. Every one of the six is
proven to fail against origin/main.
`tests/compile_fail/172_the_possessive_unknown_property.vox` is a guard,
not a fail-before case: it passes on both sides, pinning that the
unified path still rejects a word that is not a property.
---

### 65. A declaration whose initializer is the WRONG type is accepted — `a text called n is 5.` segfaults on the first read, `a number called n is "get five".` prints the literal's address

**Status:** **fixed** (unreleased, on top of 0.4.8+#49–#58).
Severity: **memory safety** — a two-line program, compiled clean, faults
on a pointer it was handed by an integer literal; the non-faulting half is
a wrong value that looks completely plausible. Regression tests:
compile-fail cases `tests/compile_fail/145_number_into_text_declaration.vox`
through `157_number_returned_as_text.vox` (thirteen cases, covering the
declaration, both `Set`/`Create` spellings, a variable source, a call
result, an argument and a return), plus two passing controls —
`tests/395_declaration_initialiser_types_that_agree.vox`, which walks every
declaration shape the manual documents and is byte-identical before and
after, and `tests/396_mistyped_initialisers_written_correctly.vox`, which
writes each refused program the two documented ways and checks the answers.
Found 2026-08-20 by the #51 fix worker while probing sibling forms, and
independently by the vox-fuzz `names-and-strings` claim ledger
(Discrepancy 1, probes `D1.vox` / `D1b.vox`); master-reproduced on
0.4.8+#49–#58.

```vox
a text called n is 5.
Print n.
```
→ **segfault (139)**, deterministic, no output at all.

```vox
a number called n is "get five".
Print n.
```
→ prints `4198488` — the string literal's address, as a decimal number.

**The matrix, each case its own program, measured on this branch's parent
(9734e5d) and on the fix:**

| program | before | after |
|---|---|---|
| `a text called n is 5.` + `Print n.` | 139 | rejected |
| `a number called x is "get five".` + `Print x.` | prints `4198488` | rejected |
| `a boolean called ready is "x".` + `Print ready.` | prints `4198488` | rejected |
| `a float called ratio is "abc".` + `Print ratio.` | prints `0.0` | rejected |
| `a list called items is 5.` + `Print items.` | prints `[`, then 139 | rejected |
| `a map called ages is "bo".` + `Print ages.` | prints `{}` | rejected |
| `a text called label is true.` + `Print label.` | 139 | rejected |
| `a number called count is 3.5.` + `Print count.` | prints `3.5` | prints `3.5` (designer's ruling — see below) |
| `a float called ratio is 3.` + `Print ratio.` | prints `0.0` | prints **`3.0`** (converted at the declaration) |
| `a float called ratio is 3.` + `Print ratio multiply 2.0.` | prints `0.0` | prints **`6.0`** |
| `a float called ratio is 3.` + `Set ratio to 4.0.` | rejected, "which is a number" | accepted, prints `4.0` |
| `a text called written is "5".` + `a number called count is written.` | prints `4198488` | rejected |
| `Set a text called n to 5.` + `Print n.` | 139 | rejected |
| `Create a number called n is "five".` + `Print n.` | prints `4198488` | rejected |
| `To 'five'. Return a number, 5.` + `a text called got is five.` | 139 | rejected |
| `To greet with a text called who. Print who.` + `greet with 5.` | 139 | rejected |
| `To 'label'. Return a text, 5.` + `print label.` | 139 | rejected |
| `a value called v is 5.` / `set v to "x".` (control) | correct | correct |
| `a buffer called b is "seed".` / `a buffer called b is 42.` (control) | correct | correct |
| `a file called source is "input.txt".` (control) | correct | correct |
| `a time called now is current time.` (control) | correct | correct |
| every cast in the Basic Conversions table (control) | correct | correct |
| `a text called line is b.` on a buffer (control, bug #51) | #51's answer | **unchanged** |

Seven of the thirteen fault. The declaration alone never does — `a text
called n is 5.` followed by `Print "declared".` runs clean — so the crash
arrives a line away from its cause, exactly as bug #57's did.

**Which reading the manual supports.** The rejecting one, on four
independent statements, and the permissive reading is not merely weaker
but self-contradicting:

1. **LANGUAGE.md:531-532** is the rule in one sentence: "**A variable's
   type is fixed at its declaration and never changes**". The declaration
   is named as the point at which the type is *fixed*. A reading in which
   the initializer decides the type instead would make that sentence
   false — the type would be fixed by the value, not by the declaration.
2. **LANGUAGE.md:566-576 already refuses a mistyped declaration**, in the
   manual's own worked example: `a number called n is 5.` followed by a
   nested `a text called n is "abc".` is "compile error: cannot bind 'n'
   to text in this declaration". The error names `text` — the declared
   noun — which settles that the noun *is* the type and not a hint the
   initializer may overrule. The compiler agrees: that program is refused
   today, and was before this fix. The only thing missing was the check on
   the initializer.
3. **LANGUAGE.md:647-667 is this bug's worked example**, and the manual
   claims it is already fixed: `a number called "x" is "get five".` /
   `print x.` "(prints: 4198480)", followed by "The program above is now a
   compile error." It is a compile error only because of the quoted
   *name*. Written with a legal identifier — `a number called x is "get
   five".` — it compiles and prints `4198488`, the same address, eight
   bytes from the number the manual prints as the symptom. "A function
   pointer, printed as a number, silently. No error, no warning; the
   program runs and gives a wrong answer that looks like data" — the
   manual's own words, describing a program the manual says no longer
   exists.
4. **LANGUAGE.md:597-608 states the purpose** the gap defeats: the type
   rules exist to close "a variable's compiler-tracked type disagreeing
   with what it actually holds at runtime, which previously produced a
   wrong number on screen at best and a segfault at worst". Both halves
   are in the matrix above.

**The strongest reading in which the compiler is correct, and why it
fails.** LANGUAGE.md:534-537 scopes the type-lock check narrowly: "Every
form that writes **to an already-declared name** — `x is <value>.`, `the x
is <value>.`, and `Set x to <value>.` — is checked the same way". A
declaration is not a write to an already-declared name, so on a literal
reading the check was never promised here; and :597-608 ("What this
doesn't catch") concedes that unprovable values pass unchecked. One could
therefore argue the declaration is simply outside the checked set, and
`a text called n is 5.` means "n holds 5, and the noun was decorative".

That reading dies on the evidence:

- It contradicts :531-532 and :566-576 above — the manual both states that
  the declaration fixes the type and shows a declaration being refused for
  declaring the wrong one.
- It is not what the compiler does either. If the initializer won, `a
  float called ratio is 3.` would hold `3.0` and `a map called ages is
  "bo".` would hold the text. They hold `0.0` and `{}`. There is no
  semantics here to defend — only an unconverted bit pattern read as the
  declared type.
- No reading makes a segfault correct. README's "Memory Safety Model" and
  ROADMAP M0 ("no valid Vox program may segfault") forbid the crash under
  either reading, and `a text called n is 5.` is a program the compiler
  accepted.
- The two spellings disagree with each other. `Set n to 3.5.` on a number
  is refused today — "cannot assign float to 'n', which is a number" —
  while `a number called n is 3.5.` was accepted and printed `3.5`. One
  intent, two spellings, opposite answers, and the accepted one is the
  wrong one.

**Mechanism.** The analyzer's `Statement::VarDecl` arm registered the
declared type and analyzed the initializer as an ordinary expression, and
that was all. `check_type_lock` (`src/analyzer/types.rs`) — which owns
this rule — is reached only from `Statement::Assignment` and from the
`Set`-on-an-existing-name path, both of which require the name to be
already declared. Bug #54 had added `check_declared_read_type` for one
narrow initializer shape (a collection or buffer *read*) and said so
explicitly in its own doc comment: "This is deliberately NOT a general
declaration-site type check: a declaration initialised from a plain
literal or another variable (`a text called t is 42.`) is unchecked too,
and crashes the same way, but that is a separate defect of much wider
blast radius". Bug #57 then added `check_nothing_initialiser` for the
literal `nothing`. #65 is that "separate defect": the general case those
two carved single shapes out of.

Codegen never converts. The initializer's value is stored into the
variable's slot as it is, with no tag, and the first read takes it for the
declared type — a number in a `text` is dereferenced as a pointer
(SIGSEGV), a text in a `number` is printed as a decimal address, an
integer in a `float` is read as a double (`0.0`), and a text in a `map`
becomes a map header that prints as `{}`.

**The fix — refuse the provable mismatch where the type is chosen.**
`check_initialiser_type` in `src/analyzer/types.rs` sits beside #54's and
#57's checks in the `VarDecl` arm and applies the type lock's own
compatibility predicate (`treating_types_compatible`) to the declaration,
minus the `number`/`float` pair, which the language designer's ruling makes
one family (below).
`check_argument_type` and `check_return_type` close the same hole at a
call's argument and at a return, which faulted identically — the shape
#57 already has for `nothing` at all three sites. Provability follows the
same "can't prove it, allow it" policy as every other check in this file,
with two additions that matter only in a storage position: a
double-quoted token is text (LANGUAGE.md:612-620 — since 0.3.0 it is a
string literal "always, everywhere"), and a call answers with the return
type its function declares.

**What is deliberately still allowed**, each for a reason the manual
gives:

- **`value` destinations** — the sanctioned dynamic type
  (LANGUAGE.md:585-595), and a `value` *source* likewise: its runtime type
  is not knowable statically.
- **`buffer` destinations** — writing to a buffer is a content write, not
  a type change (LANGUAGE.md:581-584), so `a buffer called b is "seed".`
  and `b is 42.` stay correct.
- **`file`, `time` and `timer` destinations** — these are handles with no
  literal spelling and no row in the Basic Conversions table, and their
  documented initializers are of another type outright:
  LANGUAGE.md:503-519 makes `a file called source is "input.txt".` (text
  into a file) and `a time called now is current time.` the canonical
  forms. Refusing them would have rejected the manual's own examples; this
  was caught by probing the documented forms before trusting the rule.
- **`thing` destinations** — a whole-thing copy, owned by
  `check_thing_copy`.
- **a buffer read into a text without the cast** — that is bug #51, still
  open, and its two candidate fixes (copy the bytes, or reject and name
  `as text`) are a human's call. Refusing it here would have decided that
  open question as a side effect of this one.
- **`number` ↔ `float`, in both directions** — by the language designer's
  ruling; see below.

**The `number` ↔ `float` family: the language designer's ruling.** The
first cut of this fix refused both directions, on the argument that
LANGUAGE.md:1803's "Floats and integers can be mixed in arithmetic
expressions" sits under **Literals** and scopes itself to expressions, that
the Basic Conversions table gives both directions an explicit cast (:1906,
:1907), and that the type lock already refuses both one line later. The
language designer overruled it (Josj, 2026-08-21):

> "in human language we call 1 a number and pi a number; it should be the
> same in Vox — dynamic casting as and when needed; static int64 is MY
> language gap, leave it with me"

So neither direction is a mismatch:

- `a number called count is 3.5.` keeps the 3.5 and behaves exactly as it
  did before this fix — untouched.
- `a float called ratio is 3.` is **accepted and converted**. It used to
  print `0.0` (3 as an IEEE-754 bit pattern is 1.5e-323), and every later
  read was wrong with it: `ratio add 1.0` answered `1.0`, `ratio multiply
  2.0` answered `0.0`. The declaration now emits the same two instructions
  `3 as a float` emits (`cvtsi2sd` / `XMM0_TO_RAX`) before the store, so
  the slot holds a real 3.0 and the arithmetic above answers `4.0` and
  `6.0`. The conversion fires only for an initializer codegen can see is an
  integer; a proven float, a text, a buffer, a collection and a `value` all
  answer something other than `Integer` and are untouched.
- The analyzer now keeps a declared float labelled `float`. It used to
  relabel the name from the initializer's shape, which is why `a float
  called f is 3.` then `Set f to 4.0.` answered "cannot assign float to
  'f', which is a number" — naming a type nobody wrote — while `Set f to
  4.` was let through into a slot that printed `0.0`. Those two now answer
  the right way round.

**The inconsistency this leaves, deliberately.** The type lock still
refuses `Set f to 3.` on a float and `Set n to 3.5.` on a number, one line
after accepting the same values at the declaration. That is the static-int64
gap the designer has kept for themselves; it is not closed from this side,
and no test here pins the refusal as desirable.

**Three more places the same family is still wrong**, all outside the
declaration and all left for that gap:

| program | answers |
|---|---|
| `To scale with a float called x. Print x.` + `scale with 3.` | `0.0` — the same integer bits, at the argument site |
| `To 'give it'. Return a float, 3.` + `print 'give it'.` | `0.0` — the same integer bits, at the return site (it answered `3` until #67 made `Print` read a declared float return as a float; the `3` was the integer formatter's accident, and `a float called kept is 'give it'.` already answered `0.0`) |
| `a float called f is element 1 of counts.` (a list of numbers) | refused by bug #54's read check, which still uses the strict predicate |

**Not in scope, noticed on the way.**

- An *imported* call's arguments are checked by `param_accepts`
  (`src/analyzer/expressions.rs`), which lets a boolean ride as a number
  and treats `file` as number-like. Its `number`/`float` leniency now
  agrees with the ruling; its boolean leniency does not agree with the
  local check. That is the looser end of the same rope as #62 and is left
  where it is.
- `examples/casting.vox:20` prints `3.7 rounded: 3.7`, not `4`. `a number
  called rounded is the val add 0.5 as a number.` casts only the `0.5` —
  the cast binds to the expression immediately to its left
  (LANGUAGE.md:1833) — so the example needs the braces LANGUAGE.md:2024
  documents: `{the val add 0.5} as a number`. A one-line documentation
  defect, unrelated to this fix's mechanism, recorded here for the queue
  and deliberately not changed.

---

### 66. A global declared below a function is read inside it as a raw machine word — every type but `number`

**Status:** **fixed** (unreleased, for 0.4.10). Severity: **wrong value,
silent** — no diagnostic, no crash, and an address printed straight into
program output: a static rodata address for a `text`, a live heap address
that changes between runs for a `list`, `map` or `buffer`. Found 2026-08-21
by the vox-fuzz `functions` claim ledger (Discrepancy 1, probes `D1.vox` and
`D1b.vox`, against rows FUN-11, FUN-17 and FUN-19), adjudicated as candidate
**A** of the 0.4.10 audit and master-reproduced on `4b77934` (= v0.4.9).

```vox
To 'show all'.
    Print label.

a text called label is "hello".

'show all'.
Print label.
```
→ compiles clean and prints `4198488`, then `hello`. Move the declaration
above the function and both reads print `hello`.

**The whole defect in eight lines of assembly** (`vox A1.vox --emit-asm`) —
one BSS slot, two different printers, chosen by which side of the
declaration the read sits on:

```nasm
_start:
    lea rax, [rel str_0]
    mov [rel gvar_0], rax   ; global store label
    call show_all
    mov rax, [rel gvar_0]
    mov rdi, rax
    PRINT_CSTR rdi          ; top-level read: correct printer
...
show_all:
    mov rax, [rel gvar_0]
    mov rdi, rax
    PRINT_INT rdi           ; in-function read: same slot, integer printer
```

**Every read measured, one program per row, on `4b77934` and on the fix.**
The middle column is the read inside a function defined *above* the
declaration; the right-hand column is the same read at top level, which was
right all along and is unchanged.

| read | before | at top level | after |
|---|---|---|---|
| `Print counter.` (`a number called counter is 42.`) | `42` | `42` | `42` |
| `Print label.` (`a text`) | `4210888` | `hello` | `hello` |
| `Print ratio.` (`a float called ratio is 2.5.`) | `4612811918334230528` | `2.5` | `2.5` |
| `Print items.` (`a list called items is [1, 2, 3].`) | `140602256846848` | `[1, 2, 3]` | `[1, 2, 3]` |
| `Print payload.` (`a buffer called payload is "ABC".`) | `140602256838656` | `ABC` | `ABC` |
| `Print scores.` (`a map called scores is {"a": 1}.`) | `140493452648448` | `{"a": 1}` | `{"a": 1}` |
| `Print flagged.` (`a boolean`) | `1` | `1` | `1` |
| `Print anything.` (`a value called anything is "vv".`) | `4210906` | `vv` | `vv` |
| `Print "interp {label}".` | `interp 4211053` | `interp hello` | `interp hello` |
| `Print label's type.` | `Number (dynamic)` | `Text (static)` | `Text (static)` |
| `Print names's first.` (a list of texts) | `4210900` | `alpha` | `alpha` |
| `a float called doubled is ratio multiply 2.0.` | `9225623836668461056.0` | `5.0` | `5.0` |
| `Append "DEF" to payload.` then `Print payload.` | mojibake — the buffer's own header, read as text | `ABCDEF` | `ABCDEF` |
| `Print output.` (a `text` flag declared below the reader) | `4198488` | `out.txt` | `out.txt` |
| `Print element 1 of names.` (control — runtime tags) | `alpha` | `alpha` | `alpha` |
| `Print scores's "a".` (control — a map lookup) | `1` | `1` | `1` |
| `Append 4 to items.` (control) | `[1, 2, 3, 4]` | — | `[1, 2, 3, 4]` |
| `Set label to "bye".` (control — the store, not the read) | `bye` | — | `bye` |

**It is the read, not the store.** Copying the same global into a declared
local inside the same forward-referencing function and printing the local
printed `hello` even before the fix, and `Set label to "bye"` from inside
such a function always updated the global correctly. The bytes were there;
the type was not.

**Cause.** Name resolution in this compiler is deliberately whole-program
and order-independent: `collect_definite_decls`
(`src/parser/ast.rs`) gathers every top-level declaration before the walk,
`src/analyzer/statements.rs` seeds `global_variables` from it, and
`self.variables = self.global_variables.clone()` makes every top-level name
available from the very first statement — which is why a name that is
genuinely never declared *is* rejected (`error: Unknown variable`), and why
this program compiles at all. Codegen had only half of that. Its
`variable_types` (`src/codegen/mod.rs`) is filled as statements are walked
(`src/codegen/statements.rs`, the `VarDecl` arm), with no equivalent
pre-pass, so a function body generated above the declaration found no entry
for the name and every downstream dispatch — `Print`, format holes, `'s`
properties, arithmetic, buffer appends, the `type` property — fell through
to its integer default.

Either horn was a defect. If the name is known, LANGUAGE.md:705 says the
read must work; if it is unknown, :712 says the program must be rejected.
"Compiles silently and prints a pointer" is the one outcome no reading of
the manual reaches — and LANGUAGE.md:658-659 names that outcome as the
disease the 0.3.0 identifier/literal split was written to end: *"A function
pointer, printed as a number, silently. No error, no warning; the program
runs and gives a wrong answer that looks like data."*

**Fix.** Codegen gets the pre-pass it was missing.
`collect_global_var_types` (`src/codegen/vars.rs`) reads the declared type
of every top-level name straight after `collect_global_var_labels` reads
its storage — the same two walkers the analyzer uses
(`collect_definite_decls` ∩ `collect_all_typed_decls`), so the type map and
the storage map can never disagree about which names behave as globals — and
`seed_global_var_types` gives them to each function body before its
parameters and locals are registered. A name already carrying a type keeps
it, so a global declared *above* a function is untouched; a parameter or a
local of the same name still shadows, exactly as LANGUAGE.md:711 says.
Three things ride along because they are the same question asked of a
different table: a `value` global's tag byte is allocated in the pre-pass
(the payload's type is useless without it), a list's element type is read
off its initializer (it is inferred, never declared, so it is not in the
type map — without it `names's first` still printed the element's address),
and a flag's schema type is collected too.

**The flags needed it as much as the variables, despite #32.** That entry
made the *analyzer's* flag types whole-program (`flag_variables:
HashMap<String, Type>`, filled in a pre-pass); the order-dependence that
survived was codegen's, so a `text` flag read inside a function defined
above its schema printed the address of the flag's own default string. This
is that fix's other half, and the shape is deliberately the same one.

**The window the fix opens, and how it is closed.** A read that is now
typed is also a read that dereferences: a function *called* above the
declaration would have found the BSS mirror still holding the zero it
starts life with, and a `text`/`list`/`map`/`buffer` read as its own type
would have faulted on it where before it merely printed `0`.
`emit_forward_global_defaults` writes each such global's empty value at
frame setup — `""`, `[]`, `{}`, an empty buffer — which is exactly #25's
rule (a slot whose declaring path may not have run) and #16/#31's (an
uninitialised `text` must point at a real empty string, never at null).
Only the pointer types get it; `0`, `0.0` and `false` are already the right
defaults for the rest.

**Family.** #32 (the same order/type split, for flags, fixed once already
on the analyzer's side), #45 and #63 (a read where nothing supplies a type),
#25 (a slot no executed path wrote), #16/#31 (a null text default).

**Not in scope, met on the way.** A `thing` global declared below a
function that reads one of its fields is a *parse* error — `Print origin's
x.` answers `Expected property name, got Identifier("x")` — because the
parser's `thing_vars` is filled in source order (`src/parser/things.rs`).
It is a diagnostic, not a silent wrong value, so it is a different entry
in the #45/#62/#63 diagnostic family and is left alone. A top-level read
placed *before* the declaration (not inside a function) still prints `0`
and is likewise unchanged.

**Regression tests.** `tests/425_global_declared_below_a_function.vox`
(the five-type probe plus `map`, `boolean`, both columns of the table
above), `tests/427_forward_global_read_in_every_sink.vox` (format hole,
`'s first`, arithmetic, buffer append, list append, copy into a local,
`value`, `'s type`), `tests/428_forward_flag_read_in_a_function.vox` (all
three flag types), `tests/429_forward_global_read_before_its_declaration.vox`
(the window above: a call before the declaration, then the same call after
it), and two controls that pass on both sides —
`tests/426_global_declared_above_a_function.vox` (the working neighbour,
byte-identical before and after) and
`tests/430_a_local_shadows_a_forward_global.vox` (a parameter and a local
of a different type, both against a global declared below them). Every one
of the four fail-before cases was run against a clean extract of
`4b77934` and fails there with the addresses quoted above.

LANGUAGE.md:705 gained the sentence it was missing: where a top-level
declaration sits in the file makes no difference to a function that reads
it, and a function that runs before the declaration reads the type's empty
value.


---

### 67. A declared `float`, `map` or `buffer` return is printed by the integer formatter — the fix #45's diagnostic tells the author to apply

**Status:** **fixed in 0.4.10** (this branch), found 2026-08-21 by the
vox-fuzz claim ledger / candidate audit against 0.4.9 (`4b77934`) and
adjudicated by the language lawyer — section **B** of
`vox-notes/REPORT-CANDIDATES-0.4.10.md`. Worker's own re-run of the
headline repro and its neighbour is quoted in `REPORT-67.md`.

```vox
To 'give float'. Return a float, 2.5.
Print 'give float'.                 (4612811918334230528   — wrong)

a float called routed is 'give float'.
Print routed.                       (2.5                   — right)
```

`4612811918334230528` is `0x4004000000000000`, the IEEE-754 bit pattern of
2.5. A declared `map` return printed a heap address (`139755989557248`,
different every run), and so did a declared `buffer` return. Routing the
same call through a declared variable of the same type printed all three
correctly, so the value came back intact and a renderer existed for it —
the **read** was wrong, exactly as in #45, and this is the other half of
that rule: #45 closed the **un**declared case by refusing it and pointing
the author at declaring the return type; declaring it did not work for
three of the eleven types.

**Exactly which of the eleven types were wrong.** Seven declared returns,
printed directly, one program (`tests/431`):

| declared return | `Print <call>.` before | after |
|---|---|---|
| `Return a text, "hi".` | `hi` | `hi` |
| `Return a boolean, yes.` | `1` | `1` |
| `Return a list, [1, 2].` | `[1, 2]` | `[1, 2]` |
| `Return a number, 7.` | `7` | `7` |
| `Return a float, 2.5.` | `4612811918334230528` | `2.5` |
| `Return a map, {"ann": 30}.` | `140715186864128` | `{"ann": 30}` |
| `Return a buffer, made.` | `140715186794496` | `bytes` |

The three failures failed in **different** positions, which is the tell
that they are three separate one-line gaps and not one (`tests/433`):

| position | `float` | `map` | `buffer` |
|---|---|---|---|
| `Print <call>.` (bare name) | ✗ bits | ✗ address | ✗ address |
| `Print <call> of 1.` (connector) | ✓ | ✗ address | ✗ address |
| `Print "{<call>}"` | ✓ | ✗ address | ✓ |
| `a value called c is <call>.` | ✓ | ✗ address | — |
| `a <type> called r is <call>.` | ✓ | ✓ | ✓ |
| an imported `.lib` call, printed | ✓ | ✗ address | ✓ |

**What the spec promises.** LANGUAGE.md:721-726 — "the same 11 types are
also legal as a declared `Return a <type>,` return type (plan 296) —
parameters and returns share one vocabulary, not two", the eleven being
`number`, `float`, `text`, `boolean`, `list`, `map`, `buffer`, `file`,
`time`, `timer`, `value`. And LANGUAGE.md's "Reading a result" (:787-793,
written by #45's own fix) — "A declared return type travels to every call
site, so the result can be printed, interpolated, stored in a list or map
slot, or put in a `value` — each of those reads it back as what it is."
Neither sentence carries a type restriction, and both are broken by three
of the eleven.

**No reading makes the compiler right.** Three were tried. *"`Print` of a
call has no variable to carry a type"* — it has the declared return type,
and it uses it correctly for `text` and `list` in that same position.
*"A map cannot be rendered from a call"* — a map variable renders in all
three positions and `a map called routed is 'give map'.` renders, so the
renderer exists and the value is intact. *"This is #45, and #45 is
fixed"* — #45 is the **un**declared case; its own control test
`tests/376_declared_return_reads_everywhere.vox` is titled "a declared
return read back correctly in all six refused positions" and every line
of it returns a `text`. `float`, `map` and `buffer` were never exercised.

**Root cause — three missing arms in three dispatchers, the #44 shape.**

- **map, local `To`**: `collect_function_signatures`
  (`src/codegen/functions.rs`) translates a declared return type into the
  `VarType` codegen tracks. It is the same table as the declaration path's
  (`src/codegen/statements.rs`, `a map called ages is {}.`) arm for arm —
  minus `Type::Map(_)`. A map return therefore became `VarType::Unknown`
  and every consumer that asks what a call answers with fell through to
  `PRINT_INT`. `VarType::Map` has existed since stage 1e2 and Print's
  catch-all has had an arm for it just as long; nothing routed a call into
  it. This is the mirror of #44's own discovery — *"Print's expression arm
  carried a `Map` case from stage 1e2 and never a `List` one"* — one layer
  up.
- **map, imported `.lib`**: the imports copy of that same table, further
  down the same function, had the identical gap. `returning a map` is a
  spelling a `.lib` can state (`src/lib_file.rs`'s `Token::Map` arm), so
  fixing only the local table would have left the bug alive on the other
  side of the boundary — the half-fix #44 records catching itself making.
- **float**: `is_float_expr` (`src/codegen/expr.rs`) answers for
  `Expr::FunctionCall`, but its `Expr::Identifier` arm consulted only
  `variable_types` and never fell back to `zero_arg_func_return_type` —
  the fallback `infer_expr_type`'s own `Expr::Identifier` arm already has.
  A **bare** zero-argument call parses as `Expr::Identifier` (plan 270
  G4), so it was not seen as a float; the spelling with a connector took
  the `FunctionCall` arm and was right all along.
- **buffer**: `generate_print`'s catch-all (`src/codegen/print.rs`) has
  arms for `String`, `List` and `Map` and none for `Buffer`. A buffer
  variable is printed by the *variable* arm above, which has had
  `PRINT_BUF` all along; a buffer-returning call reaches Print only
  through the catch-all, so the struct pointer went to `PRINT_INT`.

**Fix.** Four lines, one per gap: `Type::Map(_) => VarType::Map` in both
return-type tables in `src/codegen/functions.rs`; the
`.or_else(|| self.zero_arg_func_return_type(name))` fallback in
`is_float_expr`'s Identifier arm in `src/codegen/expr.rs`, mirroring
`infer_expr_type`'s; and a `VarType::Buffer => PRINT_BUF rdi` arm in
`generate_print`'s catch-all in `src/codegen/print.rs`. No analyzer
change, no new diagnostic — the manual promises these reads work, and they
now do.

**Severity.** Wrong value, silent — the failure mode LANGUAGE.md:649-660
says the 0.3.0 identifier/literal split was written to kill. Not memory
safety: the pointer is handed to the wrong formatter, never dereferenced
as an integer. The map and buffer addresses **change between runs**, which
puts this in #44's class for vox-fuzz — a generated program printing a
declared map return had wandering output and would be classified
nondeterministic, a manufactured finding on top of the wrong answer.

**Did 0.4.9 touch it?** No. Both tables above reproduce identically on
0.4.8 and on `4b77934`; only the heap addresses differ per run. #45
shipped in that batch and is the entry that should have caught it.

**One neighbouring answer changes with this fix, and should.** #65's
"three more places the same family is still wrong" table records `To 'give
it'. Return a float, 3.` + `print 'give it'.` answering `3` — "rendered as
an integer, not `3.0`". It now answers `0.0`, because `Print` finally
reads it as the float it is declared to be, and the slot really does hold
a raw integer 3 — which as an IEEE-754 bit pattern is 1.5e-323, the same
`0.0` #65 documents for `a float called ratio is 3.` before 0.4.9
converted it. The `3` was the integer formatter's accident, not a right
answer: every typed reader of that same function already said `0.0`. The
return site's missing int-to-float conversion is #65's open gap, not this
one's, and is left there; that row is updated in place so the register is
not stale.

**Tests.** `tests/431_declared_float_map_buffer_return_printed.vox` (all
seven rows of the type table), `tests/432_declared_return_routed_through_-
a_variable.vox` (the nearest working neighbour, which had to keep
working), and `tests/433_declared_float_map_buffer_return_in_every_-
position.vox` (the position table: bare name, connector, format hole,
`value` declaration, list slot, whole list, map slot, text initializer and
buffer sink) — 427 is the float/map/buffer twin of #45's text-only
`tests/376`. The `.lib` row cannot be expressed as a single `.vox`, so it
is a `test.sh` stage in the repo's own shared-library convention: **A4.3**
`run_see_collection_return_test`, over the new fixture
`tests/shared/collections_lib.vox`. All four proven to fail on a clean
extract of `4b77934` and to pass after.

**Incidental, recorded and left** (see `REPORT-67.md` for repros): a `map`
**parameter** printed inside a function body prints its address (`To 'show
map' with a map called seen. Print seen.` over a plain map variable — no
call involved); its cause is the third copy of the same type table,
`src/codegen/statements.rs`'s parameter table, missing the same `Map` arm,
but a parameter is not a call result and it is a different entry.


---

### 68. A mixed list's element in the *expression* form of a format hole prints as an integer — the same read printed as a statement is correct

**Status:** **fixed** in 0.4.10 (unreleased, on top of 0.4.9 `4b77934`).
Regression tests: `tests/434_element_of_a_mixed_list_in_a_format_hole.vox`
(the headline repro), `426_a_mixed_element_renders_by_its_own_type.vox`
(every row of the candidate report's table, mixed and uniform),
`427_the_working_neighbours_of_an_element_hole.vox` (the spellings that
already worked, unchanged — the control),
`428_a_format_hole_dispatches_on_every_runtime_tag.vox` (all seven slot
tags, hole against statement),
`429_a_tagged_hole_renders_the_same_in_every_sink.vox` (Print, a text
initializer, a fixed buffer, a function argument, and a real file read back
from disk) and `430_a_value_in_a_hole_outside_print.vox` (the `value`
half: a local's shadow slot, a global's BSS mirror, `'s last`, and a call
declared to give back a `value`). Five of the six print addresses on
unfixed `main` and pass after; 427 is the control and passes on both. Each
stable over three consecutive runs.

Found 2026-08-21 by the vox-fuzz claim ledger —
`vox-fuzz/docs/ledger/collections-b.md` row **LST2-13** (blocked on D7) and
its **Discrepancy 7**, which reproduces collections-a's D7 against this
range and whose lawyer resolution reads: *"COMPILER BUG, duplicate of vox
#44 … New sub-case: the EXPRESSION form `print "{element 2 of nested}"`
leaks an address in print position too. Fold into #44 as an extra repro."*
It is filed separately because #44 shipped in 0.4.9 without reaching it.
Re-adjudicated in the candidate audit 2026-08-21
(`REPORT-CANDIDATES-0.4.10.md` §E) and master-reproduced on this branch.

```vox
a list called nested is [1, [2, 3], "four"].
Print "{element 2 of nested}".
Print element 2 of nested.
```
→ `140477763297280` then `[2, 3]`. Same element, same run: the statement
form dispatches on the tag and the format hole does not. Two consecutive
runs gave `140477763297280` and `140268219564032` — a **live heap address**,
so the program's own output wanders.

**It is every element of a mixed list, not only a nested one.** Each row
re-run on `4b77934` and on this branch:

| program | format hole, 0.4.9 | format hole, fixed | statement form |
|---|---|---|---|
| `[1, [2, 3], "four"]`, element 1 (`1`) | `1` | `1` | `1` |
| `[1, [2, 3], "four"]`, element 2 (a list) | `140155337404416` | `[2, 3]` | `[2, 3]` |
| `[1, [2, 3], "four"]`, element 3 (`"four"`) | `4210888` | `four` | `four` |
| `[1, "two", 2.5]`, element 3 (`2.5`) | `4612811918334230528` | `2.5` | `2.5` |
| `["a", "b"]` (uniform), element 1 | `a` | `a` | `a` |
| `[10, 20]` (uniform), element 1 | `10` | `10` | `10` |

A uniform list was fine because the static guess happened to be right,
which is exactly why the defect hid. `4612811918334230528` is `2.5`'s
IEEE-754 bits read as a decimal integer — #1's symptom, at a new site.
`4210888` is a `.rodata` address, stable across runs, the same class the
register quotes for #55 (`:3981`), #54 (`:3812`) and #29 (`:1438`).

**And it is every sink, not only `Print`.** The same hole, on `4b77934`:

```vox
a list called nested is [1, [2, 3], "four"].
a text called captured is "{element 2 of nested}".   (140213536817152)
a buffer called sink is 64 bytes in size.
copy "{element 3 of nested}" to sink.                (4206780)
```

The `value` half of the same defect is worse still, because there the
*variable* form fails too — the one form #44 fixed everywhere:

```vox
a list called nested is [1, [2, 3], "four"].
a value called v is element 3 of nested.
Print v.                                (four   — right)
a text called t is "{v}".
Print t.                                (4210906   — wrong)
```

`Print "{v}"` is right and `a text called t is "{v}".` is wrong, on the
same variable in the same run.

**Step 0 — the reading in which the compiler is right, and where it stops.**
LANGUAGE.md documented this, twice, as a known limitation. As of 0.4.9,
at :2382-2385 ("the *expression* form of format interpolation … has no
runtime-tag dispatch, so a nested list does not render there; use the
*variable* form") and at :2811-2813 ("the *expression* form (`print
"{element 2 of xs}"`) does not dispatch on a nested element's runtime
tag"). On the letter, for a **nested-list** element, the compiler did what
the manual said.

That reading does not reach the rest, for three reasons.

1. **It is scoped to nested elements.** Both sentences say "a *nested*
   element's runtime tag", and both sit inside the Nested Lists discussion.
   A `text` element and a `float` element of a mixed list are not nested,
   and both were wrong — undocumented, unmentioned, silent.
2. **It says the dispatch is absent, never what is rendered instead.** A
   live heap address that changes between runs is not a rendering. It is
   the `4198480` disease LANGUAGE.md:649-660 says the identifier/literal
   split exists to kill: *"a function pointer, printed as a number,
   silently. No error, no warning; the program runs and gives a wrong
   answer that looks like data."*
3. **The tag is present and is being discarded.** The two emissions are
   byte-identical up to the dispatch — the element load emits
   `movzx r11, byte [rbx + r11 + 24]  ; slot type tag` in *both* cases.
   The statement form then compares r11; the format hole emits
   `PRINT_INT rdi` over it. Nothing was unknowable; the answer was in a
   register and was thrown away.

So the manual half of the nested case is a promise that stopped one clause
too early, and the text/float/`value` cases were never covered at all.
Both are fixed, and the two limitation sentences are gone (below).

**Mechanism.** A `{...}` hole becomes one of two AST parts.
`parse_format_string` (`src/parser/expressions.rs`) makes
`FormatPart::Variable` only for a bare name; everything else
`try_parse_expression` accepts — an `element N of` read, a *quoted* name, a
list literal, `'s last`, a call — becomes `FormatPart::Expression`. That is
the same split #44's entry records for `{'the running total'}`.

Print's Variable arm learned to read a runtime tag in stage 1e
(`src/codegen/print.rs`, the `VarType::Mixed` case), and the statement arms
`Expr::ElementAccess`, `Expr::MapAccess` and the catch-all each dispatch on
one too. **The Expression arm never did.** It asked `infer_expr_type` —
which correctly answers `Mixed`/`None` for a value whose type is only known
at runtime — and then fell past the Buffer/List/Map cases into
`emit_formatted_value`, whose default is `PRINT_INT rdi`.

The non-Print sinks fail one layer down, for the matching reason:
`emit_append_runtime_value_to_buffer_ptr` (`src/codegen/buffers.rs:75`) has
arms for `Buffer`, `String`, `Float`, `List` and `Map` — the last three
added by bug #1 and by #44 — **and none for a runtime-tagged value**, so it
too fell to `_ => emit_append_formatted_int_to_buffer`. This is the third
time that same missing arm has been paid for: the `Float` arm closed #1,
the `List`/`Map` arms closed #44, and this entry closes the `Mixed` one.

**The fix — dispatch on the tag, render through the routine Print calls.**
Two readings were on offer, exactly as in #44: *render* (LANGUAGE.md
:3196-3198, a format string "materializes into a fresh NUL-terminated
string"; :3221-3227, "every statement that takes a string value accepts a
format string", both stated without a type restriction) and *refuse* (the
`thing` precedent at :1251-1254). Render wins for the same reason it won in
#44 — a tagged value has a runtime renderer already, so there is something
for a sink to call — and it wins more easily here, because the correct
answer was already sitting in r11.

- `src/codegen/print.rs`, the `FormatPart::Expression` arm: ask
  `runtime_tag_source(expr)` *before* generating the value (it reports
  where the tag **will** be), then dispatch through the existing
  `emit_mixed_print_dispatch`. Taken ahead of the static Buffer/List/Map
  arms, because a runtime tag outranks a static guess — the same order the
  catch-all statement arm below it already used.
- `src/codegen/buffers.rs`: a new `emit_append_mixed_value_to_buffer_ptr`
  (and its buffer-slot twin), branch for branch the twin of
  `emit_mixed_print_dispatch`, with the same `rdi` = buffer, `rax` = value,
  `rax` = possibly-reallocated buffer contract every other arm uses. Each
  branch calls the SAME routine the Print dispatch calls, pointed at the
  destination: `_buffer_append_cstr` for `PRINT_CSTR`,
  `_buffer_append_float` for `PRINT_FLOAT`, and `_list_render_to_buffer` /
  `_map_render_to_buffer` — #44's own redirections — for `_list_print` /
  `_map_print`. **No renderer was duplicated**, which is the rule
  `resolve_format_variable`'s doc comment states and #44's entry restates.
- `src/codegen/format.rs`: both sinks (`_slot` and `_ptr`) route a tagged
  part to the new dispatch. The Expression arm reads
  `runtime_tag_source`; the Variable arm reads the new
  `mixed_value_tag_location` (`src/codegen/tags.rs`), which returns a
  `value`'s shadow-slot or BSS-mirror operand and `None` when there is no
  tag to read — so a name with no shadow slot falls back to the integer
  rendering rather than dispatching on whatever r11 happens to hold, which
  is the same fallback Print takes.

No coreasm changed: every routine the fix calls was already there, written
for #1 and #44.

**Why r11 survives.** The tag is only valid until the next call or syscall.
Between `generate_expr` and the dispatch the emitted code is `mov`
instructions only — the destination load (`mov rdi, [rbp-N]` /
`mov rdi, [rel label]`) and `mov rdi, rax` — and the tag comparisons all run
before any branch makes its one call. A growing dynamic buffer was checked
across three tagged appends (30 + 31 + 30 = 91 bytes, correct).

**Severity.** A silent wrong answer **plus an address leak**: a `.rodata`
address for a text element, a live heap address for a nested list or a map.
The heap case also costs vox-fuzz a false nondeterminism finding — the
program's output wanders between runs — which is why the ledger had to
forbid the construct outright rather than assert on it.

**Family.** #44 (`:2940`) — this is the sub-case its own ledger row asked to
be folded in, and the sink arm it did not add; #1 — the first missing arm in
the same function, and the same float-bits symptom; #59 (`:4732`) — the
identical confusion in a `treating` clause, fixed the identical way, by
dispatching on the runtime tag instead of a static type; #45 (`:3097`) for
the shape (a value read back as an integer wherever nothing supplies a
type); #29 (`:1438`), #54 (`:3812`) and #55 (`:3981`) for the `.rodata`
address this class prints.

**Manual.** Both limitation sentences are removed, because the limitation
is gone: LANGUAGE.md:2378-2383 now says "One limitation remains for this
stage" (the child-reference dangling case) and drops the interpolation
clause; :2808-2812 now says the rendering "appears inside `{...}` format
interpolation, in both its forms and in every sink … so an element renders
in a hole exactly as it does printed as a statement".
`docs/COLLECTIONS_ROADMAP.md`'s 1e1 limitations bullet records the same
closure. No feature was added: every spelling that compiled before still
compiles, and only the rendering of a value the compiler could not type
statically has changed.

**Not affected today.** No vox-fuzz leaf emits this construct — LST2-13 is
`todo`, blocked on D7, and D7's standing instruction is that no leaf may put
a collection slot in a non-print sink. With this fix that row is unblocked
and the construct becomes assertable: a leaf can now emit
`"{element N of xs}"` and compare it against the statement form, with
stable output either way.

**Incidental, not fixed (out of this entry's scope).**

- A map value read cannot be written in a format hole at all: the key is a
  double-quoted literal (LANGUAGE.md:2397-2400) and a nested `"` closes the
  format string, so `Print "{person's "name"}"` is a parse error
  ("expected a name, found a string literal"). The single-quoted spelling
  `person's 'name'` is a different error ("Expected property name"). The
  tag dispatch this entry adds would render such a hole correctly if it
  could be spelled; the gap is in the quoting, not the rendering.
- The caret for `Copy source must be a buffer: v` and `Buffer append
  requires a buffer source: v` lands on the **declaration** of `v` rather
  than on the offending `copy`/`append` line — #46's family, a second
  instance, left where it is.


---

### 69. A `treating` clause whose match or replacement is a `value` keeps the static path — a pointer printed as a number, or a number read as a `char*`

**Status:** **fixed** (unreleased, on top of 0.4.9 — ships in 0.4.10).
Severity: **wrong value, silent** — a rodata address printed as data — and,
where the `value` holds a number over a text collection, **memory safety**: a
number handed to `_str_eq` as a `char*`. Regression tests:
`tests/461_treating_a_value_as_the_match_on_a_mixed_list.vox`,
`426_treating_a_value_as_the_replacement_on_a_mixed_list.vox`,
`427_treating_a_value_over_a_typed_list.vox` (the two crashes),
`428_treating_a_value_over_a_map_s_values.vox`,
`429_treating_a_value_carries_the_tag_into_a_value_parameter.vox`, plus the
control `430_treating_a_value_when_opening_a_file.vox` (a neighbouring form
that was already right and stays byte-identical). The #59 controls
`359_treating_matching_types_substitutes.vox`,
`360_treating_over_an_unprovable_list.vox` and `400`-`406` are unchanged.
Recorded 2026-08-21 by the #59 fix worker, in #59's own "What this fix does
not reach" ("Unfiled; worth its own entry"); re-verified against 0.4.9 by
the candidate audit of the same day (REPORT-CANDIDATES-0.4.10 §H1) and
master-reproduced on this branch.

```vox
a value called probe is "-".
print each item from [1, "-"] treating probe as "X".
```
→ `1` then `4198538` (expected `1` then `X`)

```vox
a value called swap is "X".
print each item from [1, "-"] treating "-" as swap.
```
→ `1` then `4198538` (expected `1` then `X`)

```vox
a value called probe is 7.
a list called names is ["ann", "-"].
print each name from names treating probe as "X".
```
→ **segfault**, no output (expected `ann` then `-`: a number can never equal
a text, so the clause simply does not fire)

```vox
a value called seven is 7.
a list called names is ["ann", "-"].
print each name from names treating "-" as seven.
```
→ `ann`, then **segfault** (expected `ann` then `7`)

The address is a fixed `.rodata` one in a non-PIE binary, byte-identical
across runs, exactly as #59 records for its own case. The two crashes are
new to this entry: the candidate report has the two silent-wrong-value
reproductions, and the pair above turned up while mapping the clause's
behaviour across subject types.

**What the manual promises.** `treating X as Y` is "inline value
substitution": "If the loop variable equals `<match>`, it's replaced with
`<replacement>` for that iteration" (LANGUAGE.md:424, duplicated at :3131),
and neither sentence restricts what `<match>` or `<replacement>` may be.
`value` is one of the eleven expressible types (LANGUAGE.md:729-731) and its
whole definition is that it "carries its runtime tag *alongside* its payload"
(LANGUAGE.md:2554-2556) so that "printing dispatches on it" (:2575). A mixed
list's elements carry the same per-slot tag (:2272 "elements carry a small
per-slot type tag at runtime", :2409 "the value carries its runtime tag, so a
text prints as text and a number as a number"). Every ingredient of a correct
answer is therefore present at runtime; only the compiler's emit-time view
was missing one. And even the most charitable reading — that a
`value`-typed match is of a different type from the element and so should
never fire — does not reach any of these outputs: not firing means printing
the element, which is `-`, not its address, and certainly not a fault.
(Every line number here was landed on by searching this branch's manual,
after the edit below. #59's `:2227`/`:2348` for the last two sentences were
pinned to an older manual and no longer land.)

**Mechanism.** #59 made the clause dispatch on the *subject's* runtime tag,
but `treating_dispatches_on_runtime_tag` (`src/codegen/tags.rs`) demanded
`emit_time_expr_tag(...).is_some()` for the match **and** the replacement:
the tag path had to know, at emit time, what to compare the subject's tag
against and what tag to hand out when the substitution fires. A `value`
answers `None` there — its tag is a runtime fact, in its shadow slot — so
the whole clause fell back to the static path, which chooses its comparison
from the *subject's* static type alone:

- a mixed subject has no static type, so the comparison is a raw pointer
  `cmp` and the result carries no tag: `Print` renders a text element's
  address as an integer (the first two reproductions — #44's rendering
  failure reached through #59's gap);
- a text subject means `_str_eq`, and a `value` holding a number goes into
  it as a `char*` (the third and fourth reproductions — #55's dereference
  hazard, reached the one way #55's compile-time guard cannot see, because
  a `value`'s type is not there to check).

`treating_subject_type` (`src/analyzer/types.rs`) deliberately answers `None`
for `Type::Value`, so the analyzer is right not to reject these programs:
`probe` may hold text, and only the runtime knows. The missing half was
always codegen's.

**The fix.** `src/codegen/{mod,tags,expr}.rs` — 180 lines added (69 of them
comment), 49 removed — no analyzer change.
A new `ClauseTag` says where each of the three operands keeps its tag —
`Static(u8)` at emit time, or `Runtime(RuntimeTagSource)` for a `value` — and
`treating_clause_tag`/`treating_subject_tag` classify them.
`treating_dispatches_on_runtime_tag` now asks only that every operand have a
tag *somewhere*, and that at least one of them be a runtime one (when all
three are static the old path is already right and is emitted unchanged).
Checked, not assumed: `--emit-asm` output for `359`, `400`, `402` and a
three-clause static probe is byte-identical between this branch and
`4b77934`.

`generate_treating_on_tagged_subject` gained the runtime-match arm. Where the
match's tag is static, the emitted code is exactly what #59 emitted. Where it
is a `value`, the two questions the static tag used to answer at emit time
become runtime branches, in the order the hardware finds them:

1. **the tags disagree** — different types can never be equal, so the clause
   does not fire, nothing is read through the match, and the element comes
   through wearing its own tag;
2. **the tags agree and say text** — compare the bytes (`_str_eq`), which is
   safe *because* the tags agree;
3. **the tags agree otherwise** — compare in registers.

When the substitution fires the result carries the replacement's own tag,
which for a `value` replacement is read from its shadow slot. And
`emit_time_expr_tag` now answers `None` for a clause that dispatches at
runtime: it used to answer with the subject's static type, which is right for
the element and wrong for a replacement that turned out to hold something
else, so a `value` parameter, a list append and a map insert all take the
real tag out of r11 instead. That half has its own crash to its name:

```vox
To announce with a value called what.
  print what.

a value called nine is 9.
a list called names is ["ann", "-"].
announce of each name from names treating "-" as nine.
```
→ `ann`, then **segfault** — the parameter was handed `mov r11, 1` (text)
over the payload `9`. It now reads `push r11` straight from the clause and
prints `9`. Last block of `429`.

A subject that keeps a static type — a homogeneous list, a range — still
takes the static path whenever the whole clause is static; it reaches the tag
path only when a `value` is in the clause, which is the case that was broken.
A **buffer** subject is excluded outright: its payload is a struct pointer
rather than the bytes, so it compares by `_mem_eq` over the tracked length,
which the tag path does not do (see below).

**What this fix does not reach.** `write <buffer> treating <value> as <text>
to <file>` — a spelling the parser accepts (`src/parser/io.rs`) and the manual
never documents — has its own copy of the clause inside
`Statement::FileWrite` (`src/codegen/statements.rs`), which
never consults a tag at all: it calls `_str_len` on the match to size a
`_mem_eq`. With a `value` match holding a number that is a segfault, before
and after this fix:

```vox
a value called seven is 7.
a buffer called content is 8 bytes in size.
copy "-" to content.
open a file for writing called out at "/dev/stdout".
write content treating seven as "REPLACED" to out.
close out.
```
→ segfault, byte-identical on 0.4.9 and on this branch (no regression, not
covered). The same program with a text-valued `value` writes `REPLACED`
correctly. Closing it means teaching that second emitter the same runtime tag
branch, over a buffer's length-bearing comparison rather than `_str_eq`.
Unfiled; worth its own entry.

**Found alongside, not this bug.** `append each <var> from <collection>
treating <match> as <replacement> to <list>.` still drops the clause
entirely — `append each item from [1, "-"] treating "-" as "X" to out.`
yields `[1, "-"]`. #59 recorded it and it is section H2 of the 0.4.10
candidate report, on its way to its own entry; nothing here touches it.


---

### 70. `append each … treating …` parses the clause and discards it — silently in the spelling that compiles, as a parse error in the grammar's own

**Status:** **fixed** (unreleased, on top of 0.4.9). Regression tests:
`tests/467_append_each_treating_substitutes.vox` (the repro, a list
literal, the no-clause control, and a `but if` branch),
`tests/468_append_each_treating_over_a_range.vox` (a range source, plus
the two controls the range disambiguation depends on),
`tests/469_append_each_treating_into_a_buffer.vox` (a buffer
destination, with and without the clause) and
`tests/470_append_each_treating_matches_print.vox` (the working
neighbour `print each … treating …` unchanged, and both actions agreeing
over a mixed list), plus the compile-fail cases
`tests/compile_fail/201_append_treating_after_the_destination.vox` and
`tests/compile_fail/202_append_treating_after_a_range_destination.vox`.
Found 2026-08-21 by the vox-fuzz **grammar-summary** claim ledger,
Discrepancy 3 (row GRM-16, probe `docs/ledger/probes/grammar-summary/
D3.vox`) — "wrong position in the manual's own grammar, and a silent
no-op once moved to a position that parses", left unfiled there — and
adjudicated in the candidate audit of 2026-08-21 (REPORT-CANDIDATES-0.4.10
§H2). Recorded before that inside #59 as "Found alongside, not fixed here
(out of scope)". Master-reproduced on this branch.

```vox
a list called names is ["ann", "-"].
a list called out is [].
append each name from names treating "-" as "anon" to out.
Print out.
```
→ `["ann", "-"]` (expected `["ann", "anon"]`) — exit 0, no diagnostic

```vox
append each name from names to out treating "-" as "anon".
```
```
error: Expected a statement, got Treating
  --> H2.vox:3:36
```

```vox
a list called out is [].
append each n from 1 to 3 treating 2 as 99 to out.
```
```
error: Expected list name after 'to'
  --> t_range.vox:2:25
    |
  2 | append each n from 1 to 3 treating 2 as 99 to out.
    |                         ^--- here
```

The nearest working neighbour — the byte-identical clause on the same
list under `print`, the form the manual demonstrates:

```vox
print each name from names treating "-" as "anon".
```
→ `ann` then `anon` (correct)

It is not a tag problem in the #44/#59 sense: the clause drops on a
homogeneous text list too (`append each item from ["a", "c"] treating "a"
as "b" to out.` → `["a", "c"]`), and on a buffer destination
(`ann-`), so no runtime dispatch is involved. The clause simply never
reaches the AST.

**What the manual promises.** `treating` is a clause of the loop
expansion, not of any one action: `loop_expansion ::= "each" name "from"
expr ("treating" expr "as" expr)?` (LANGUAGE.md:5310), and the prose
syntax rule — stated twice, at :422 and again at :3122 — is `... each
<var> from <collection> treating <match> as <replacement>, ...`, in a
section that lists `print`, `open` and a function call as the actions it
rides on. The loop expansion itself is documented as universal:
"**Works with any action**", with `append each X from Y to Z` named in
that list (:2944). So the clause is promised over `append`, and its
place is straight after the collection.

**The manual's own grammar summary said otherwise, and was wrong.**
`append_stmt`'s second production (LANGUAGE.md:5277) put the optional
group after the destination:

```
append_stmt ::= "append" expr "to" name "."
              | "append" "each" name "from" expr "to" name ("treating" expr "as" expr)? "."
```

That contradicts `loop_expansion` five lines further down, and it
contradicts `print_stmt` on the same page, both of which attach the
clause to the collection. Two sentences promise one placement; one
transcription of the append production promises another. The
transcription is the outlier and is now corrected to
`("treating" expr "as" expr)? "to" name`, so the summary agrees with the
production it is a specialisation of. The two `treating` sections gained
an `append` example alongside the existing `print`/`open`/call ones, so
the placement is demonstrated where a reader looks for it rather than
inferred.

**Mechanism.** Three failures, one root: the append path was written from
the plain `append <expr> to <name>` form outward and never wired the
clause in.

1. `parse_append` (`src/parser/collections.rs`) destructured the clause
   into `_treating` and threw it away — `if let Some((variable,
   collection, _treating)) = self.try_parse_each_from(true)?` — then built
   `Statement::ListAppend { value: Expr::Identifier(variable) }`. That is
   the silent half: `try_parse_each_from` *does* parse the clause, which
   is why the sentence compiles, and nothing downstream ever sees it.
2. `try_parse_each_from`'s range disambiguation
   (`src/parser/control_flow.rs`) was blinded by the clause. In append
   position a range source shows two `to`s (`from 1 to 5 to rl`) and a
   list source one (`from source to dest`), so the parser speculatively
   reads the would-be range end and keeps the range only if a second `to`
   follows. A `treating` clause sits between the two, so the test saw
   `Treating` where it wanted `To`, rewound, and handed `1` back as the
   whole collection — after which `append` demanded a list name and found
   the literal `3`.
3. Written where the grammar summary put it, the clause fell out of the
   statement entirely and reached the top level as `Expected a statement,
   got Treating` — a diagnostic that names neither the clause nor the way
   out.

**The fix.** Three local changes, each following the shape an existing
action already uses.

- The appended value is now `Self::each_arg_expr(&variable, &treating)`,
  the same helper `print each … treating …` uses
  (`src/parser/statements.rs`) and the same wrapping `open … at each …`
  does by hand (`src/parser/io.rs`): the loop variable is wrapped in
  `Expr::TreatingAs` when a clause is present and left bare when it is
  not. Nothing new is invented for `append` — it joins the two actions
  that already worked. As with those, the clause applies to the base
  action; a `, but if …` branch's own action is a separate sentence and
  is untouched, which `425` pins.
- The range test reads the clause speculatively, alongside the end bound,
  and keeps it only when the second `to` proves the range. On a list
  source the rewind gives the clause back to the caller, which is what
  lets the misplaced spelling reach its diagnostic instead of being
  silently reinterpreted.
- A `treating` sitting after the destination is now refused by name, in
  the #45/#62/#63 family, with the caret on the offending token (#46):

```
error: A `treating` clause belongs to the `each` clause, not after the append destination
  --> 173_append_treating_after_the_destination.vox:8:36
    |
  8 | append each name from names to out treating "-" as "anon".
    |                                    ^^^^^^^^ this substitutes for the loop variable, so it goes where the variable is bound
    |
  help: write `append each name from <collection> treating <match> as <replacement> to out.`
```

One analyzer change came with it. `Statement::ListAppend` into a **buffer**
destination is checked against a small set of legal sources
(`src/analyzer/statements.rs`) — a buffer, a text-valued name, a string
literal or a format string — and a `TreatingAs` wrapping any of them was
none of those, so wiring the clause in would have turned a program that
compiled (wrongly) into one that did not compile at all. The check now
looks through the clause and judges the append by its subject, which is
exactly the parity #59 established for a `treating`-wrapped read: it
reports what a bare read of the same subject reports.

**Family.** #50 — a bare `otherwise` rejected after every base action but
`append` — is the same shape from the other side: a clause the grammar
offers generally that one statement's parser never wired in, with
`append` the odd one out. #59 fixed the runtime half of `treating` over a
tagged element and recorded this drop as out of scope; with the clause now
reaching the AST, #59's tag work is what makes `append each item from [1,
"a"] treating "a" as "b" to mixed.` answer `[1, "b"]` rather than a
pointer (`428`).

**What this does not reach.** #59's unfiled residual is untouched: a
clause whose *match* or *replacement* is a `value` has no emit-time tag,
so it keeps the old static path under `append` exactly as it does under
`print` — that is candidate H1, its own entry, not this one. And a
`treating` after a plain `append <expr> to <name>` (no `each`) is still
the generic `Expected a statement, got Treating`: with no loop variable
bound there is nothing for the clause to substitute for, so the sentence
is not valid under any reading and was deliberately left alone.


---

### 71. A format specifier other than a width still ignores the value's type — a precision on a number renders `0.00`, and `:x` / `:b` / `:o` on a text or buffer print its address

**Status:** **fixed in 0.4.10** (unreleased). Severity: **address leak**,
which by #36's own ranking is the worst class in the format layer — a
`text` or `buffer` formatted with `:x` emitted a live pointer into program
output — plus **wrong value, silent** for the precision half. Regression
tests: `tests/471_precision_on_a_whole_number.vox`,
`tests/472_specifiers_the_type_can_answer.vox`, compile-fail cases
`tests/compile_fail/203_hexadecimal_of_a_text.vox` through
`182_hexadecimal_of_a_float_expression.vox` (ten cases, covering each radix,
each refused type, a width in front of the radix, a non-`Print` sink, and the
expression form of a hole), and five codegen routing tests in `src/codegen/tests.rs` that drive
`emit_formatted_value` directly, because the analyzer now refuses every
program that could reach the leaking arms. Found 2026-08-21 by the
candidate audit for 0.4.10 (`vox-notes/REPORT-CANDIDATES-0.4.10.md` §H4
and §H4b): H4 from a note against the format layer, H4b — the address
leak, the bigger half — found by the auditor while checking it.
Master-reproduced on `4b77934` (= v0.4.9) before this fix.

```vox
a number called n is 255.
Print "{n:.2}".              (0.00 — 255's bits read as an IEEE-754 double)

a text called first is "hi".
a text called second is "hi".
Print "{first:x}".           (0x4030ee — an ADDRESS)
Print "{second:x}".          (0x4030f1 — same bytes, different address)

a buffer called payload is "hi".
Print "{payload:x}".         (0x7f3db387e018 — a LIVE heap address, per run)
```

**This is the half of #36 that v0.4.7's fix did not take.** That entry's
status line scopes itself precisely — "the harm half: a **width** no longer
changes what a value IS" — and its fix put the type check behind a
`matches!(fmt.base, IntegerBase::Decimal)` gate. A radix is by definition
not `Decimal`, so it walked straight past; and a precision was handled
above the gate, before any type was consulted at all. Both then reached the
integer routines holding a float's bits or a pointer.

**The matrix, each row measured on this branch's parent (`4b77934` = 0.4.9)
and on the fix:**

| hole | value | before | after |
|---|---|---|---|
| `{n:.2}` | number 255 | `0.00` | **`255.00`** |
| `{n:.0}` | number 255 | `0` | `255` |
| `{n:.5}` | number 255 | `0.00000` | **`255.00000`** |
| `{owed:.2}` | number -5 | a **310-digit** number (see below) | **`-5.00`** |
| `{big:.2}` | number 9007199254740993 | `0.00` | **`9007199254740993.00`** |
| `{largest:.1}` | number 9223372036854775807 | a **309-digit** number | **`9223372036854775807.0`** |
| `{ready:.2}` | boolean true | `0.00` | **`1.00`** |
| `{ratio:.2}` | float 2.5 | `2.50` | `2.50` ✓ the working neighbour |
| `{label:.2}` | text "hi" | `0.00` (the rodata pointer as a double) | **rejected** |
| `{payload:.2}` | buffer "hi" | `0.00` | **rejected** |
| `{first:x}` / `{second:x}` | two texts, both "hi" | `0x4030ee` / `0x4030f1` | **rejected** |
| `{first:X}` | text "hi" | `0x4040FA` | **rejected** |
| `{first:b}` | text "hi" | `10000000100000011111010` (= 0x4040FA) | **rejected** |
| `{first:o}` | text "hi" | `0o20040372` (= 0x4040FA) | **rejected** |
| `{label:04x}` | text "hi" | `0x4010ba` — an address, and no padding, since six digits already exceed the width | **rejected** |
| `{payload:x}` | buffer "hi" | `0x7f3db387e018`, moves between runs | **rejected** |
| `{ratio:x}` | float 2.5 | `0x4004000000000000` (the IEEE bits) | **rejected** |
| `{ratio:b}` | float 2.5 | the same bits in binary | **rejected** |
| `{n:x}` / `{n:X}` / `{n:b}` / `{eight:o}` | numbers | `0xff` / `0xFF` / `11111111` / `0o10` | unchanged ✓ |
| `{n:04x}` / `{n:8x}` / `{n:06}` / `{n:6}` | number 255 | correct | unchanged ✓ |
| `{ready:x}` / `{ready:06}` | boolean true | `0x1` / `000001` | unchanged ✓ |
| `{f:06}` / `{t:06}` / `{b:06}` | float / text / buffer | #36's answers | unchanged ✓ |
| `{held:06}` / `{worded:x}` | `value` 2.5 / `value` "words" | `2.5` / `words` | unchanged ✓ |
| `{items:x}` / `{ages:.2}` | list / map | `[1, 2]` / `{"bo": 3}` | unchanged ✓ |
| `a text called built is "{n:.2}".` | number 255 | `255` | **`255.00`** |
| `copy "{label:x}" to out.` | text "hi" | `hi`, the `:x` silently dropped | **rejected** |

**The negative row is the worst arithmetic answer in the table.** `-5` is
`0xFFFFFFFFFFFFFFFB`, and that bit pattern read as a double is about
-3.6e308 — one place below the largest finite double. So a two-line program
asking for a small negative number to two places printed 310 digits:

```vox
a number called owed is 0 subtract 5.
Print "{owed:.2}".
```
→ `-359538626972462981961830084685823781086324092104604707801734118769711…
   …0708994615585441174176564756845767803804301355268373821189624847455485952.00`

`{largest:.1}`, on `i64::MAX`, printed the positive twin of it. Both are
`0.00` in disguise: every small positive number's bits are a denormal, which
rounds to zero at any precision, which is why the wrong answer usually
looked like a plausible `0.00` rather than like a bit pattern.

**Proof that the text case printed an address, not a value** — #36's own
control, one specifier over. Two distinct `text` variables holding the same
content printed different numbers, and a `buffer` printed a number that
changed between runs of the same binary. No value-based explanation
survives either. (The particular rodata addresses above belong to the
program they were measured in; another program with a different string
layout prints different ones, which is the point.)

**Root cause.** `emit_formatted_value` (`src/codegen/format.rs`) dispatched
on the *specifier* and consulted the type only in one branch of it:

- the precision arm ran first, unconditionally — `movq xmm0, rdi` / `call
  _print_float_precision` — so any slot's 64 bits were read as a double;
- the type-aware block #36 added was gated on `IntegerBase::Decimal`, so
  every radix skipped it;
- the radix arms then ran `PRINT_HEX_LOWER rdi` and friends on whatever
  those bits were.

The correct architecture was already in the compiler, one file away:
`emit_append_runtime_value_to_buffer_ptr` (`src/codegen/buffers.rs`), the
buffer/text sink, dispatches on `value_type` FIRST and only falls to the
integer formatter for the integer family — which is why *no* sink ever
leaked an address, and why `copy "{label:x}" to out.` printed `hi` while
`Print "{label:x}"` printed a pointer.

**Fix.** `emit_formatted_value` now dispatches on the type first, in the
sink's shape: a `float` renders as a float (with the precision, if one was
written), a `text` as a C string, a `buffer` as its bytes, and only then
does the integer family reach the width/base routines. A raw slot can no
longer be reinterpreted whatever specifier is written, including for a type
the analyzer could not prove.

On top of that the analyzer refuses, at compile time, the combinations that
have no meaning — `check_format_spec_against_type`
(`src/analyzer/expressions.rs`), reached from `analyze_format_parts`, so it
covers every sink:

- a radix on a `text`, a `buffer` or a `float`;
- a precision on a `text` or a `buffer`.

The diagnostic names the construct and the way out, with the caret on the
offending hole rather than the declaration (#46), and quotes the specifier
back exactly as written so the suggested rewrite pastes:

```
error: cannot render 'first', which is text, in hexadecimal
  --> leak.vox:2:9
    |
  2 | Print "{first:x}".
    |         ^--- here
    |
  note: `:x`, `:X`, `:b` and `:o` write a whole number in another base, and text is not one
  help: convert it first - `{first as a number:x}`, or drop the specifier to render `{first}`
```

**Two rulings this fix makes, and the ground for each.**

1. **A precision on a whole number renders it.** LANGUAGE.md:3175 writes
   the rule of `{var:.N}` with no type attached, and the designer's
   number/float ruling recorded on #65 — "in human language we call 1 a
   number and pi a number; it should be the same in Vox" — makes a whole
   number a member of the family a decimal place belongs to. So `{n:.2}`
   is `255.00`, not a category error. It is rendered as the integer, a
   point and N zeros rather than by converting to a double first, because
   2^53+1 and `i64::MAX` have no exact double: a conversion would print
   `9007199254740992.00` and `9223372036854775808.0` while the manual
   promises "exactly `N` decimal places, correctly rounded". Digits then
   zeros is exact for every i64.
2. **A radix on a float is refused, not truncated.** The same family ruling
   *keeps the value* — `a number called count is 3.5.` still holds 3.5 —
   and no base can write 2.5 without dropping the fraction. A silent
   truncation is the class of defect this register exists to catalogue, so
   the loss is the author's to ask for: `{ratio as a number:b}` prints
   `10`.

**Why a diagnostic and not a silent drop.** With the codegen fix alone,
`{label:x}` would print `hi` — the right value, with the `:x` quietly
doing nothing. That is the mildest wrong rather than none, and it is what
the buffer sink had been doing all along. Vox knows the type at the format
site, which is the one place it has the most information, so a specifier
the type cannot answer is refused the way #45, #62, #63 and #65 refuse a
category error the compiler can see. A `value` is exempt — its type is not
known until it runs — and so are a `list` and a `map`, which render through
their own routines and ignore a specifier entirely.

**Family:** **#36** (`docs/BUGS_FOUND.md:1952`) directly — this is the half
its v0.4.7 fix did not reach, and its regression test
(`tests/bugs_found_36_format_width_type.vox`) is unchanged and still green,
which is what proves the width path was not disturbed. **#34** (the float
formatter's i64 routing), which #36 already pairs with itself, and which is
the reason the whole-number precision path avoids a double. **#45**, **#62**,
**#63**, **#65** for the shape of the diagnostic. **#61** for the count
limits, which are unchanged: `check_format_spec` still reports a count too
large to hold, and now runs alongside the type check rather than instead of
it.

**Incidental, found on the way and deliberately not fixed here.**

- **A precision on a FLOAT is still dropped by every sink but `Print`.**
  `a text called built is "{ratio:.2}".` renders `2.5`, where `Print
  "{ratio:.2}"` renders `2.50` — LANGUAGE.md:3226 promises a specifier
  renders identically "whether the result is printed, written to a file,
  or built into a buffer". The whole-number half of this was closed here
  (`emit_append_int_with_decimal_places`) because `{n:.2}` is this entry's
  own headline case; the float half needs a
  `_buffer_append_float_precision` in coreasm, which is a defect of its
  own and not this one's scope.

  ```vox
  a float called ratio is 2.5.
  a text called built is "{ratio:.2}".
  Print "{built}".            (2.5, where Print "{ratio:.2}" gives 2.50)
  ```

- **`{f:8.2}` drops the precision.** A spec is read as *either* a precision
  *or* a width-and-base, never both, so a width in front of a precision
  silently discards it — `{ratio:8.2}` renders `2.5`. This is #36's
  recorded residue seen from the other side (that entry's table lists the
  row) and is a dropped specifier, not a wrong value.

- **`{'label'}` — a quoted single-word name in a format hole — is "Unknown
  variable: 'label'"**, rejecting legal Vox. This is §I1 of the candidate
  report, reproduced here independently while building the test cases; it
  is its own entry, not part of this one.


---

### 72. An absent map key, or an out-of-range list index, is typed from the collection's VALUES — the manual's own `a number called x is m's "never_set".` is refused, and the `help:` line it offers segfaults

**Status:** **fixed** (unreleased, on top of 0.4.9). Severity: **rejects a
correct program that 0.4.8 compiled — a 0.4.9 REGRESSION — and the
alternative its own `help:` line recommends is a segfault.** Regression
tests: `tests/440_absent_map_key_reads_zero.vox` and
`tests/441_out_of_range_list_read_reads_zero.vox`, and compile-fail cases
`tests/compile_fail/173_absent_map_key_into_a_text.vox` through
`181_absent_key_proof_withheld_for_an_aliased_map.vox`. Found 2026-08-21 by
the vox-fuzz collections claim ledger — hand-reduced from campaign seed
1009 while sweeping the leaves `gen leaf map oob` (kind 10) and `gen leaf
list oob` (kind 5), written up as finding C of
`vox-notes/REPORT-SWEEP-COLLECTIONS.md`. Adjudicated 2026-08-22 as
candidate **C-i** of `vox-notes/REPORT-CANDIDATES-ROUND-2.md`,
master-reproduced on 4b77934.

```vox
a map called guess is {"a": "t"}.
a number called n is guess's "absent".
Print n.
```
→ on 0.4.9:
```
error: cannot initialise 'n', which is a number, with a text read out of map 'guess'
  --> c1.vox:2:17
    |
  2 | a number called n is guess's "absent".
    |                 ^ this reads text
    |
  note: the read yields a text, and 'n' is declared as a number
  help: declare it as a text - `a text called n is guess's "absent".` - or convert it explicitly:  a number called n is guess's "absent" as a number.
```
On **0.4.8** the same three lines compiled and printed `0`.

And the `help:` line, followed verbatim, is the one destination that
crashes:

```vox
a map called guess is {"a": "t"}.
a text called n is guess's "absent".
Print n.
```
→ **segfault (139)**, deterministic, no output at all.

**The matrix, each cell its own program, on 4b77934 (= 0.4.9) and on the
fix. In every row the runtime yields the number `0`.**

| collection | destination | 0.4.9 | fixed |
|---|---|---|---|
| `{"a": "t"}`, key `"absent"` | `number` | rejected | prints `0` |
| `{"a": "t"}`, key `"absent"` | `text` | **139** | rejected |
| `{"a": 1}`, key `"absent"` | `number` | prints `0` | prints `0` |
| `{"a": 1}`, key `"absent"` | `text` | rejected | rejected |
| `{"a": 1, "b": "x"}`, key `"absent"` | `number` | prints `0` | prints `0` |
| `{"a": 1, "b": "x"}`, key `"absent"` | `text` | **139** | rejected |
| `{}`, key `"absent"` | `number` | prints `0` | prints `0` |
| `{}`, key `"absent"` | `text` | **139** | rejected |
| `["a","b"]`, `element 5 of` | `number` | rejected | prints `0` |
| `["a","b"]`, `element 5 of` | `text` | **139** | rejected |
| `[1,2]`, `element 5 of` | `number` | prints `0` | prints `0` |
| `[1,2]`, `element 5 of` | `text` | rejected | rejected |
| `[1,"b"]`, `element 5 of` | `number` | prints `0` | prints `0` |
| `[1,"b"]`, `element 5 of` | `text` | **139** | rejected |
| `[]`, `'s first` | `number` | prints `0` | prints `0` |
| `[]`, `'s first` | `text` | **139** | rejected |
| `["a","b"]`, `element 0 of` | `text` | **139** | rejected |
| `[true,false,true]`, `element 100 of` | `boolean` | prints `0` | prints `0` |
| `[1.5,2.5]`, `element 100 of` | `float` | prints `0.0` | prints `0.0` |

Six of those rows are a **segfault the check was written to prevent and
walked straight past**, and two more are the regression itself. The
assignment spelling (`n is guess's "absent".`) and the arithmetic spelling
(`guess's "absent" add 1`) were refused for the same reason and are fixed by
the same change.

**What the spec promises.** LANGUAGE.md:2429 — "A missing key does not
crash: the lookup **yields 0** and sets the error flag, so an `on error`
handler can react", with `print person's "nope".    (prints: 0)` beside it.
LANGUAGE.md:2857 — "Out-of-bounds access sets an error flag and **returns
0**". The manual then writes the rejected sentence itself, twice, and both
times the destination is a `number`:

```
a map called m is {"k": nothing}.                 (LANGUAGE.md:2756-2759)
If m's "k" is nothing, print "k is present and holds nothing".
a number called x is m's "never_set".
on error print "never_set is absent".
```
```
a list called items is [1, 2, 3].                 (LANGUAGE.md:2861-2864)
a number called bad is element 100 of items.
On error print "Cannot access element 100 - out of bounds!".
```

Both survive on 0.4.9 only because their collections happen not to hold
text. Swap `{"k": nothing}` for `{"k": "v"}` and the manual's own paragraph
stops compiling.

**Mechanism — the read is typed from the values, and a miss has no value.**
`arithmetic_operand_type` (`src/analyzer/types.rs:114` on 4b77934) answered a
map read with `map_value_type.get(map)` and a list read with
`list_element_type_of(name)`, unconditionally — the key and the index were
never consulted. Those two tables are #54's and plan 294's, filled from a
homogeneous literal initializer, and for a key the literal **does** contain
they are exactly right. For a key it does not, the type they name is one no
value of that read will ever have: `_map_lookup` sets `_last_error`, `rax =
0`, `r11 = 0`, and the read is the number 0 with the number tag. A `value`
destination proves it at runtime —

```vox
a map called guess is {"a": "t"}.
a value called v is guess's "absent".
Print "{v's type}".    (prints: Number (dynamic))
Print v.               (prints: 0)
```

`check_declared_read_type` (`src/analyzer/types.rs:661` on 4b77934) then
compared that false type against the declaration and refused the number,
while the `text` it recommended sailed through — declared and inferred agreed
— into this, from `--emit-asm`:

```asm
    call _map_lookup
    mov [rel gvar_1], rax  ; global store n   <- rax is 0 on a miss
    mov rax, [rel gvar_1]
    mov rdi, rax
    PRINT_CSTR rdi         ; walks a string at address 0
```

#54 and #65 both judge a *type mismatch*; here the declared and inferred
types **agree** and the runtime value is 0, so neither of them looks.

**Fix — prove the miss, then type it as what a miss yields.** All in the
analyzer; codegen and the runtime are untouched.

1. `absent_read_reason` (`src/analyzer/types.rs`) answers whether a read
   provably asks for something the collection's own literal does not
   contain — a map key the literal never wrote, an index below 1 or past
   the literal's last element, a `'s first`/`'s last` on an empty literal —
   and returns the reason, phrased for the diagnostic's `note:` line.
2. `arithmetic_operand_type`'s `MapAccess`, `ElementAccess`/`ListAccess` and
   `PropertyAccess{First,Last}` arms ask it first, and answer `number` when
   it fires. That single answer fixes the declaration spelling, the
   assignment spelling (through `check_type_lock`) and the arithmetic
   spelling at once, because all three read the type from this one
   function.
3. Two new tables carry the proof, both filled by
   `collect_literal_collection_shapes` (`src/parser/ast.rs`) in one
   whole-program pass **before** the analyzer's walk, beside
   `collect_widened_lists`: `map_literal_keys` (the literal's key set, when
   every key is a string literal — a `"{k}"` key is dynamic, so the set
   would be incomplete and the whole map gets no proof) and
   `list_literal_len` (the literal's length, recorded for a **mixed**
   literal too, since a length is provable whether or not the elements
   share a type — which is why the two mixed rows above are caught where
   #54's element-type proof never reached them). A name the program
   declares more than once is in neither table; see below for why that
   matters more here than it does for #54.
4. `absent_zero_fits` decides what the miss is refused into: a `number`
   holds 0, a `float` holds it as +0.0, and a `boolean` holds it as false —
   Vox represents a boolean as 0/1 and prints it that way. A `text`, `list`
   or `map` slot holds a **pointer**, and 0 as an address is the crash. Only
   those three are refused. This is #65's "a number and a float are one
   family" ruling (Josj, 2026-08-21) applied to the one read that yields a
   bare 0, and it is what keeps `examples/lists.vox:27` —
   `a boolean called bad is element 100 of bools.` — compiling.

**The proof is only offered where it holds.** A map's key set stops being
the literal's the moment anything can add to it, so `map_literal_keys_of`
withholds it when the program contains any `Set <map>'s "k" to <value>.`
(`collect_map_key_writers`, `src/parser/ast.rs`), when any function inserts
into a map it was handed (`any_function_writes_a_map_parameter`, the map
twin of #54's `any_function_widens_a_parameter`), or when the name is in
`widened_lists` — #54's whole-program alias scan, which is name-keyed and
type-blind and so already collects every map copied into or out of a
variable, returned, or passed to a call. `list_literal_len_of` reuses
`list_element_type_of`'s guard unchanged, because an `Append` is exactly
what makes an index no longer past the end. In every withheld case the
behaviour is byte-identical to 0.4.9 — compile-fail cases 180 and 181 pin
that.

**Why the shapes are collected before the walk, and why a name declared
twice gets nothing.** #54's tables are filled at each declaration as the
walk reaches it, and that is safe for them because a wrong answer there
costs a *diagnostic*. An absence proof is different: a wrong answer there
costs a wrong **acceptance**. Recorded at the declaration, this program was
accepted and printed an address, where `main` rejects it:

```vox
a map called guess is {"b": "t"}.

To peek.
    a number called n is guess's "a".    (analyzed while the table says {"b"})
    Print n.

a map called guess is {"a": "t"}.        (but THIS is the map peek reads)
peek.                                     (prints 4198562)
```

`collect_literal_collection_shapes` (`src/parser/ast.rs`) therefore walks
the whole program **before** the analyzer's walk and offers a shape only for
a name the program declares exactly once — so a read gets the same answer
wherever in the file it sits, which is the property #54's own doc comment
says these scans must have.

**The diagnostic that replaces the segfault.** In #45/#62/#63's family: it
names what is actually read, says why, and points at the destination the
manual itself uses.

```
error: cannot initialise 'n', which is a text, with a number read out of map 'guess'
  --> c2.vox:2:15
    |
  2 | a text called n is guess's "absent".
    |               ^ this reads the number 0
    |
  note: map 'guess' has no key "absent", and a missing key yields the number 0 and sets the error flag
  help: declare it as a number - `a number called n is guess's "absent".` - and catch the miss with `on error`
```

**What this deliberately does NOT fix.** An absent-key or out-of-range read
into a `text`, `list` or `map` still compiles and still segfaults wherever
the miss is **not** provable — a dynamic key, a variable index, a collection
grown by `Append`, a non-literal initializer, a map some `Set` reaches. That
residual is not new (0.4.8 segfaults identically) and it is the corner #54
and #65 did not cover: they judge a *type mismatch*, and there the declared
and inferred types agree while the runtime value is 0. It is candidate
**C-ii** of `REPORT-CANDIDATES-ROUND-2.md` and wants its own number — the
general answer is a runtime one (a miss must not hand back a raw 0 into a
pointer slot), not another static proof.

**Downstream — `gen leaf map oob` now encodes the bug as a rule.** The
collections sweep, unable to decide whether finding C was a compiler bug or
a manual gap, taught the leaf to live with it:
`REPORT-SWEEP-COLLECTIONS.md` §"Per leaf" 4 records, under "Kept, with
citations", that "the captured holder's type follows the map's values —
Finding C, a compiler rule with a probe table". That is now the wrong rule:
for an all-text map the leaf will declare a `text` holder for a
missing-key read, and this fix rejects exactly that. The leaf must be
changed to declare the holder a `number`, which is what the manual writes
(LANGUAGE.md:2758) and what the read yields. `gen leaf list oob` (kind 5)
needs the same look — its citation is the runtime claim (":2857 … returns
0"), which stays true, but any captured-read form it draws has the same
holder-type question.

**Family.** #54 (the read-type check this over-reached), #65 (the
declaration-site type check beside it, and the number/float ruling reused
here), #45/#62/#63 (the diagnostic's shape), #46 (the caret).


---

### 73. A `To` definition swallowed into an open clause is accepted, and every call to it passes a `value` parameter's tag from an uninitialised register — an integer is then dereferenced as a text pointer

**Status:** **fixed in 0.4.10** (unreleased, on top of 0.4.9 = `4b77934`).
Severity: **memory safety** — an eleven-line program, compiled clean,
faults on a pointer it was handed by an integer literal; the non-faulting
half reports a text's type as `Number` and then as `Unknown`. Deterministic,
no fuzzing needed: five runs, five × exit 139. Regression tests
`tests/442_swallowed_definition_keeps_the_value_abi.vox` through
`tests/449_a_swallowed_definition_returns_a_value.vox` (eight cases — the
mis-tag, the segfault, the nearest working neighbour, a `number` and a
`text` parameter, an `If` clause instead of a loop, a call at the true top
level, and a `value` return).
Found by the vox-fuzz claim ledger — the `gen_misc` "cast and break" leaf
swallowed a `To` into an open clause and hit exit 95 twice in the
2026-08-21 core sweep — then reduced and adjudicated as candidate **D** of
`vox-notes/REPORT-CANDIDATES-ROUND-2.md` (2026-08-21/22 audit round 2);
master-reproduced on 0.4.9 before the fix.

```vox
To probe with a value called sample.
    a number called ignored is 1.

For each attempt from 1 to 3,
    probe of "t",
    If attempt is 99 then, Break.
To examine with a value called given.
    Print given.

examine of 42.
Exit 0.
```
→ **segfault (139)**, deterministic, no output at all.

```vox
For each attempt from 1 to 3,
    If attempt is 99 then, Break.
To examine with a value called given.
    Print "{given's type}".

examine of "".
Exit 0.
```
→ `Number (dynamic)`, then `Unknown (dynamic)` twice. The argument is a
text.

**Root cause.** A `To` written while a clause is still open is parsed into
that clause's body — the termination rule (LANGUAGE.md, "The termination
rule") names a period and a blank line as the closers, and a definition is
a statement like any other. That parse is a separate question (see "The
parse half", below) and is **unchanged** by this fix.

What was wrong is what happened next. Both pre-passes that answer "what is
this function's signature?" walked only the flat top-level list:

- `collect_function_signatures` (`src/codegen/functions.rs`) —
  `function_param_types`, `function_return_types`,
  `function_return_full_types`
- the analyzer's pre-pass (`src/analyzer/statements.rs`) — `functions`,
  `function_param_counts`, `function_signatures`, and the #45 / #63
  questions about the body

A swallowed `FunctionDef` is not in that list, so it had no entry. At the
call site `emit_function_call` (`src/codegen/functions.rs`) looks its
callee up and falls back on `.unwrap_or_default()` — an empty signature,
which spells "every parameter takes one argument word". A `value`
parameter takes **two** (payload, then tag), so the tag word was never
pushed:

```asm
; before — definition swallowed          ; before — definition at top level
    lea rax, [rel str_8]                     lea rax, [rel str_8]
                                             mov r11, 1  ; value tag (static)
                                             push r11    ; value param tag word
    push rax                                 push rax
    pop rdi                                  pop rdi
                 ; <- rsi never written      pop rsi
    call examine                             call examine
```

The callee is byte-identical in both — the *definition* was always
compiled correctly — so it reads its tag from `rsi & 0xFF`, a
general-purpose register the caller never wrote. That is an uninitialised
**register** read, not an out-of-bounds or freed-memory read; nothing out
of bounds is touched. But the tag steers pointer-versus-integer dispatch,
so the integer `42` arriving tagged `Text` makes `Print` dereference 42 as
a text pointer. The mis-tag is stable and steerable, not noise: in the
segfault repro the correct call `probe of "t"` leaves `rsi = 1` (Text) and
the broken call inherits it.

This is **register #43's exact shape** ("a conditional `value` return
leaves a stale tag, and the caller dereferences an integer as text —
segfault") reached by a different route, and it sits in the family of #45
and #63, which fixed the *other* two questions the same analyzer pre-pass
answers about a definition.

**The fix.** One answer to "which statements define a function", used by
both pre-passes.

- `nested_function_defs` (`src/parser/ast.rs`) returns every definition
  hidden inside a statement's block bodies, at any depth, in source order.
  It descends through `If` (all three block kinds), `While`, `ForRange`,
  `ForEach`, `Repeat`, `on error` and a `FunctionDef`'s own body, so a
  definition nested two clauses deep is found as readily as one nested in a
  loop.
- Each pre-pass keeps its flat scan of the top level and, for each
  top-level statement, sweeps that statement's nested definitions with the
  library identity in force where it stands. The registration itself was
  lifted into one method per pre-pass
  (`CodeGenerator::record_function_signature`,
  `Analyzer::register_function_definition`) so the flat scan and the sweep
  cannot drift apart.

`.lib` exports are deliberately **not** extended: a library interface
lists what the library offers, and a definition swallowed into a block is
not something the author wrote at a library's top level. A shared build's
`.lib` output is byte-identical.

**The matrix, each case its own program, measured on `4b77934` and on the
fix:**

| program | before | after |
|---|---|---|
| swallowed `To … with a value called v.` + `Print "{v's type}"`, called with `""` | `Number`, `Unknown`, `Unknown` | `Text` ×3 |
| the eleven-line segfault repro above | **139** | prints `42` ×3 |
| the same, with a blank line before the `To` (control) | `Text (dynamic)` | unchanged |
| swallowed definition, `number` parameter (control) | `7`, `7` | unchanged |
| swallowed definition, `text` parameter (control) | `hi`, `hi` | unchanged |
| swallowed by an `If` instead of a loop | `Unknown (dynamic)` | `Number (dynamic)` |
| call at the true top level, definition swallowed | `Unknown (dynamic)` | `Text (dynamic)` |
| swallowed `To echo … Return a value, given.` round trip | `Number (dynamic)`, `4210906` | `Text (dynamic)`, `round trip` |
| wrong arity against a swallowed definition (control) | `Function 'examine' expects 2 arguments but was called with 1.` | unchanged |
| a genuinely undefined name (control) | `error: Unknown function: examine` | unchanged |

**The parse half — a question for the designer, not fixed here.** Whether a
`To` inside an open clause should force-close that clause or be refused
outright is a language decision, and the manual states both answers:

- LANGUAGE.md:88 — "A following `To` or `Library` **does** begin a new
  top-level construct and so ends the body" (said of a function body,
  which rule 2 calls the strongest clause there is).
- LANGUAGE.md's termination rule — "1. A period closes the most recently
  opened clause … 2. A blank line (paragraph break) force-closes every open
  clause at once". A `To` is neither closer, so the definition belongs to
  the open body.
- LANGUAGE.md:1607, for the sibling case — a `thing` "definition inside an
  `If`, a loop, or a function body is a compile error, and the message says
  to move it above the block". `src/parser/things.rs` enforces exactly
  that, with the comment "A definition is a top-level statement, **like a
  function definition**". `Token::To => self.parse_function_def()`
  (`src/parser/statements.rs`) has no such guard, though `at_top_level()`
  is right there.

The two options are one `if !self.at_top_level()` (refuse it, matching
`thing` and :1607) or extending :88's closer rule to every clause. This
entry fixes neither, because **the ABI must be right either way**: if the
parse is refused the fix is dead code that costs nothing, and if the
definition stays legal the fix is what makes it correct. Note for whoever
answers it: a swallowed `To` also **eats the blank line** that would have
closed the enclosing clause (the blank line closes the innermost thing,
the new function body), which is why the statements after it keep being
drawn into the loop.

**A related blind spot, recorded not fixed.** The Stage A4 shadow warning
(`src/analyzer/statements.rs`) — "'x' is defined in this program and also
exported by library … the local definition wins" — is keyed off the same
flat top-level scan, so a *swallowed* definition shadowing an imported one
wins **silently**. The warning exists precisely so that adding a `see` can
never redirect an existing call without a diagnostic. Repro and measurement
are in `REPORT-73.md` ("Incidental"). It is a missing diagnostic, not a
wrong-code bug, and belongs to #45/#62/#63's family rather than this one.

**Also noted, outside this entry.** `#66`'s fix adds a third flat
top-level pre-pass (`collect_global_declared_types`), so a global declared
inside a nested block will be invisible to it in exactly the way a nested
`FunctionDef` was invisible here. Not a fault in `#66` — a note that the
"flat scan of the top level" assumption now has several dependents;
`nested_function_defs` is the shape a fix would reuse.


---

### 74. A `'s length` / `'s size` / `'s capacity` / `'s empty` read is typeless to the type lock — `a text called t is xs's length.` compiles and segfaults

**Status:** **fixed** (unreleased, on top of 0.4.9).
Severity: **memory safety** — silent, no diagnostic, segfault on the first
read, at the declaration site *and* the call site. It needs nothing unusual
at all: `a text called t is xs's length.` is a plausible typo, not a corner.
Regression tests: compile-fail cases
`tests/compile_fail/182_list_length_into_a_text_declaration.vox` through
`190_list_length_assigned_to_a_text.vox` (eighteen cases, covering the
declaration, the argument, the return and the `Set`, on a list, a map, a
buffer, a file, a number, a time and a timer), plus two passing controls —
`tests/450_property_reads_into_the_types_the_manual_gives.vox`, which reads
every property in the manual's tables into the type those tables give it and
is byte-identical before and after, and
`tests/451_mistyped_property_reads_written_correctly.vox`, which writes each
refused program the two documented ways and checks the answers.
Found 2026-08-21 during the round-2 candidate audit (candidate **E**), by a
throwaway probe reducing candidate F that segfaulted for an unrelated
reason; adjudicated as a bug and master-reproduced on 4b77934 (0.4.9).

```vox
a list called xs is ["a","b"].
a text called t is xs's length.
Print t.
```
→ **segfault (139)**, deterministic, no output at all.

```vox
To 'shout' with a text called word. Return a text, word.

a list called xs is ["a","b"].
Print 'shout' of xs's length.
```
→ **segfault (139)** as well — one frame from the sentence that caused it.

**Root cause.** `arithmetic_operand_type` (`src/analyzer/types.rs`) is the
one type oracle the whole family shares: bug #65's `check_initialiser_type`,
`check_argument_type` and `check_return_type` reach it through
`provable_value_type`, and the type lock (`check_type_lock`) calls it
directly. Its property arm answered for exactly two properties —

```rust
Expr::PropertyAccess { object, property: ObjectProperty::First }
| Expr::PropertyAccess { object, property: ObjectProperty::Last } => {
    self.list_element_type_of(object)
}
Expr::ByteAccess { .. } => Some(Type::Integer),
_ => None,                    // <- length, size, capacity, empty, full, ...
```

— so `length`, `size`, `capacity`, `empty`, `full`, `keys`, `values`, `type`,
every file property, every number question, every time component and the
timer's timestamps all fell to `_ => None`, which the whole function reads as
"can't prove it, allow it". That policy is right where nothing *can* be
proven; it is wrong here, because these are the properties the analyzer knows
best. `xs's length` is as provable as `element 1 of xs`, which the same
function resolves (#54's `list_element_type_of`), and the manual types every
one of them outright: LANGUAGE.md's List, Buffer, File, Number, Time and
Timer property tables give each property a Number or Boolean column, and
codegen leaves exactly that in `rax`. A byte was already `Some(Type::Integer)`
"by construction" on the line below; a length is a number by the same
construction.

**Fix.** One new arm and one new function in the same file. Every property
whose runtime type is the same *whatever it is read from* now answers with
that type — the measurements (`size`/`length`, `capacity`, a file's
`descriptor`/`modified`/`accessed`/`permissions`, a number's `sign`, every
time component, a timer's `start time`/`end time`) are `Integer`; the
questions (`empty`, `full`, `readable`, `writable`, `even`, `odd`,
`positive`, `negative`, `zero`, `running`) are `Boolean`; `keys`/`values`
build a list; the universal `type` reports text. The properties whose type
follows their **base** deliberately keep answering `None` and stay allowed:
`first`/`last` (the list's element type, already resolved above), `absolute`
(a float's absolute is a float), and a timer's `duration`/`elapsed`, which
are a Duration and only readable through a unit cast. `render_value_hint`
was widened the same way so the `help:` line is pasteable source rather than
`<value>`; a multi-word base gets its quotes back
(`'job timer''s start time`) and `current time's hour` is spelled the way it
was written rather than as its synthetic object name.

Nothing was added to codegen: every one of these reads already produced the
right value at runtime. What was missing was only the compiler noticing where
it was being stored.

**The matrix, each case its own program, measured on this branch's parent
(4b77934 = 0.4.9) and on the fix:**

| program | before | after |
|---|---|---|
| `a text called t is xs's length.` | 139 | rejected |
| `a list called L is xs's length.` | prints `[`, then 139 | rejected |
| `a text called t is b's capacity.` (buffer) | 139 | rejected |
| `a text called t is m's keys.` (map) | prints an empty line | rejected |
| `a number called n is xs's empty.` | prints `0` | rejected |
| `a boolean called done is xs's length.` | prints `2` out of a boolean | rejected |
| `a number called what is n's type.` | prints `4198488` — the literal's address | rejected |
| `a text called t is n's even.` | 139 | rejected |
| `a text called t is now's year.` | 139 | rejected |
| `a text called t is src's descriptor.` (file) | 139 | rejected |
| `a text called t is clock's running.` (timer) | 139 | rejected |
| `'shout' of xs's length` (text param) | 139 | rejected |
| `'shout' of m's length` (text param) | 139 | rejected |
| `'shout' of b's size` (text param) | 139 | rejected |
| `'shout' of xs's empty` (text param) | 139 | rejected |
| `'ident' of xs's length` (list param) | prints `[`, then 139 | rejected |
| `Return a text, items's length.` | 139 | rejected |
| `Set label to xs's length.` on a text | 139 | rejected |
| **controls — unchanged, before and after** | | |
| `a number called count is xs's length.` | prints `2` | prints `2` |
| `a text called t is xs's length as text.` | prints `2` | prints `2` |
| `a boolean called drained is xs's empty.` | prints `0` | prints `0` |
| `a list called ks is m's keys.` | prints `["a"]` | prints `["a"]` |
| `a text called what is n's type.` | prints `Number (static)` | prints `Number (static)` |
| `print xs's length add 1.` | prints `3` | prints `3` |
| `If xs's empty then, ...` | takes the right branch | takes the right branch |
| `a number called m is n's absolute.` | prints `4` | prints `4` |
| `'doubled' of xs's first` (number param, text elem) | rejected (#54) | rejected (#54) |
| `a number called d is clock's duration in seconds.` | prints `0` | prints `0` |
| `tests/450` (every documented property read) | 31 lines | **byte-identical** |

Eighteen of the twenty-nine are wrong; fourteen of those eighteen segfault
and four just lie, and the four that lie are the worst of them, because
nothing on screen says anything went wrong.

**Two programs that worked and are now refused, deliberately.** `a number
called n is xs's empty.` printed `0` and `a boolean called done is xs's
length.` printed `2`. Both are the boolean/number confusion #65 already
refuses when it is spelled with a literal — `a number called n is true.` has
been a compile error since 0.4.9 — and `2` is not a value a boolean can hold.
Both now report, and both help lines name the documented cast
(`xs's empty as a number`, `xs's length as a boolean`), which is the same
escape #65 offers for the literal form.

**Family: #65 and #54.** This is the hole in the type oracle those two share.
#54 built `list_element_type_of` and the `First`/`Last` arms; #65 added the
declaration, argument and return checks that consult them. #74 is the next
arm in the same `match`, and the caret-and-help shape is #45/#62/#63's and
#46's.

**One manual line changed.** LANGUAGE.md's "What this doesn't catch"
paragraph under **Type Immutability** enumerated the shapes the check can
prove — "a literal, a cast, a read from a list/map whose element type is
provably uniform, ..." — and a property read was not among them, which was
true before this fix and is not true after it. The sentence now names the
property read and the five properties (`first`, `last`, `absolute`,
`duration`, `elapsed`) that stay unproven because their type follows the
thing they are read from. No behaviour is promised that the compiler does
not now enforce.

**Not in scope, noticed on the way.**

- `arguments's` and `environment's` reads are not `PropertyAccess` at all —
  the parser gives them their own `Expr` variants — so they have the same
  hole under a different node. `arguments's count` and `environment's count`
  were already typed `Integer`; the rest are not, and `a text called t is
  arguments's empty.` still segfaults. That is #58's family, not this one's,
  and closing it means typing seven more `Expr` variants.
- `Print src's empty.` on a **file** segfaults, before and after. LANGUAGE.md's
  File Properties table has no `empty` or `full`, but
  `src/analyzer/expressions.rs` accepts both on a file handle and codegen then
  reads `[fd + 8]` — the descriptor used as an address. Either the analyzer
  should refuse it or codegen should answer from `_file_size`; that is a
  language call, and this fix only types the read, it does not decide whether
  it is legal.
- `a float called g is f's absolute.` prints `4606619468846596096.0`. Codegen's
  `Absolute` arm is `test rax, rax / neg rax` — integer negation applied to a
  double's bit pattern. This is exactly why `absolute` is left unproven here;
  typing it `Integer` would have asserted something false about a float.
- `xs's empty as text` prints `0`, while `true as text` prints `true`. A
  boolean rendered as text is only spelled out when it is a literal; out of a
  property (or any non-literal) it renders as its digit. Cosmetic, unrelated
  to the type oracle, and recorded here for the queue.


---

### 75. A list or map grown through a function parameter silently stops at the literal's capacity — the realloc is never stored back, and every call past that leaks a whole collection

**Status:** **fixed** (unreleased, on top of 0.4.9). Regression tests:
`tests/473_a_list_grown_through_a_parameter.vox` (the repro, plus every row
of the capacity table below, plus two lists through one call and a literal
argument), `tests/474_a_map_grown_through_a_parameter.vox` (the map half,
including replace-not-insert through the parameter),
`tests/476_a_collection_passed_on_and_grown.vox` (a collection passed on to
a second function, three calls deep, and recursion), and the controls
`tests/475_the_neighbours_of_a_grown_parameter.vox` (every shape that was
already right — reading a parameter, an in-place write, return-and-assign,
growth into a global, growth at the top level, a map at the top level,
iteration over a parameter, and a collection past the sixth argument word).
Found 2026-08-21 by the buffers-sweep worker (`vox-notes/REPORT-SWEEP-BUFFERS.md`
§5 discrepancy **D-A**, recorded but not filed — "either a compiler bug or a
manual gap; I have not decided which"), adjudicated as a bug by the
candidate audit of 2026-08-22 (`vox-notes/REPORT-CANDIDATES-ROUND-2.md`
section **F**), master-reproduced on this branch.

```vox
To 'add one to' with a list called items.
    append "x" to items.

a list called xs is ["a"].
a number called n is 0.
While n is less than 20,
    'add one to' of xs,
    Set n to n add 1.
Print xs's length.
```
→ `8`. Expected 21. No error, no warning, exit 0.

The reported number was eight; eight is not the rule. The cut-off is the
capacity the list's own literal allocated — `max(8, element count)`, the
capacity `_list_append` gives a fresh list (`coreasm/x86_64/list.asm`, double
or 8 from zero) — so the allocator's internal sizing was visible in the
language:

| the list's own literal | caller's length after 40 calls | after the fix |
|---|---|---|
| `[]` | **8** | 40 |
| `[1]` | **8** | 41 |
| `[1,2,3]` | **8** | 43 |
| `[1,…,8]` | **8** | 48 |
| `[1,…,9]` | **9** | 49 |
| `[1,…,12]` | **12** | 52 |

**Maps have it too**, and for maps the manual had made the promise outright.
LANGUAGE.md's Maps section says of `Set map's "key" to value`: "The map may
reallocate on growth, so **the returned pointer is stored back into the
variable automatically**" — and a parameter is a variable.

```vox
To 'store into' with a map called holder and a text called label.
    Set holder's "{label}" to 1.

a map called m is {"seed": 0}.
… 20 calls …
Print m's length.
```
→ `8`. Expected 21.

**Why this is a bug and not copy semantics.** The strongest reading in which
the compiler is right is that a collection parameter is a copy, like a
`thing` parameter (LANGUAGE.md "A function receives a copy of a thing and
hands one back by returning it; nudging the parameter cannot reach the
caller's point"). The compiler refutes that reading twice. First, an in-place
write through the same parameter **is** visible — `Set element 1 of items to
"CHANGED"` reaches the caller, which a copy could not do; LANGUAGE.md says so
directly of collections in a thing's fields, which are deferred because they
"**carry references**". Second, and decisively, the caller saw the first N
appends and then stopped: copy semantics would show none and reference
semantics would show all, and no reading of the manual reaches "the first
eight". It was not a semantic rule at all — it was an allocator's capacity
leaking out.

**Severity: wrong value (silent), plus unbounded memory growth.** Not a
memory-safety fault — nothing was freed, so nothing dangled, and the runtime
comment quoted below shows that was deliberate. But this is the class
`docs/COLLECTIONS_ROADMAP.md`'s own preamble names as the reason Track 1
exists: "silent data corruption in a language whose pitch is memory safety
and predictability."

**The runtime knew, and was wrong about the bound.** `coreasm/x86_64/list.asm`,
in the realloc path, carried this note (`map.asm` had its twin):

```asm
; NOTE: the old block is intentionally NOT munmap'd. Lists passed as
; function parameters keep the caller's pointer to the old block when a
; realloc happens inside the callee; freeing it here would turn that
; stale read into a use-after-free. The leak is bounded (geometric, at
; most ~1x the final list size) and reclaimed at process exit.
```

That comment is this defect written down, and it is why the failure was a
wrong answer rather than a use-after-free. Its bound was false for the very
case it named: the geometric argument holds only when the store-back happens
and the caller's pointer advances. In the parameter case it never advanced,
so the caller re-entered at the old block's capacity on every call and leaked
a whole fresh list each time — linear in call count. Measured at 200 000
calls: **781 MiB resident for a list reporting eight elements**; after the
fix, 3.9 MiB and the right answer, 200 001. Both comments have been corrected
to name the case they actually protect (a second variable, or a thing's
field) and to record that the parameter case no longer belongs to it.

**The fix — carry the way back with the argument.** Family: **the store-back**.
`Set m's "k" to …` and a top-level `append` both store the reallocated pointer
back into the variable (`emit_store_back_after_realloc`, `src/codegen/vars.rs`);
the parameter path was the one place that could not, because the caller's
variable is not reachable from the callee. It is now, by the same shape a
`thing` argument has used since plan 310 §5: the argument word is an
**address**, not the value.

- `src/codegen/functions.rs` — `emit_collection_argument_address` puts the
  address of the caller's own storage in the argument word for a `list`/`map`
  parameter. A named variable hands over its slot (local or global label); an
  argument with no variable behind it — a literal, a call's result, an element
  read — is parked in a slot the call site owns and the address of that is
  passed, so the callee's store-back is a harmless write to a temporary and
  the argument still arrives intact.
- `src/codegen/statements.rs` — the `FunctionDef` prologue parks that address
  in a `{name}_backptr` shadow slot (the shape `{name}_mixtag` already had for
  a `value` parameter's tag) and reads the pointer out of it into the
  parameter's own slot. **Every read inside the body is therefore unchanged**
  — `'s length`, `element N of`, `for each`, `print`, passing it on — which is
  what keeps the change small.
- `src/codegen/vars.rs` — `emit_store_back_after_realloc` writes the new
  pointer through that address as well as into the local slot, so every site
  that already stored back (`_list_append`, `_map_insert`, and the buffer
  sites, which have no backing slot and are untouched) reaches the caller.
- `src/codegen/functions.rs` — `emit_resync_collection_after_call` carries a
  collection onward after a call: a name that is itself a collection parameter
  has our own caller's storage behind it, and a top-level name also has the
  global BSS mirror a function body reads it by. Without this, growth stopped
  one call short of home whenever a function passed its own collection
  parameter along, and recursion — which is that shape — stayed at 8. It runs
  after the `call` and works in `rbx`/`rcx`, both restored, so it touches
  neither `rax` (the return value) nor `r11` (a `value` return's tag).

**LANGUAGE.md.** The manual stated no rule for a collection parameter's
aliasing in either direction — it was careful to say "copy" only of things.
The Functions section now has "A collection parameter is the caller's
collection", which states the rule, contrasts it with the `thing` copy one
section down, names the one case that has nowhere to write back to (a
collection built at the call itself), and carries the rebuild note below. The
Maps store-back sentence now says a `map` parameter counts, and the Lists
"Dynamic growth" bullet says where a list may be named from.

**The ABI change, and what it costs.** An exported function's parameters
changed shape, so a `.so` with a `list` or `map` parameter and the programs
that `see` it must be built by the same version of Vox. Both directions of a
mixed pair were checked and both are broken, as expected: a 0.4.9-built
consumer calling a 0.4.10 `.so` segfaults; a 0.4.10-built consumer calling a
0.4.9 `.so` answers silently wrong. Within one version the boundary is
correct — a library with `To 'add one to' with a list called items.` grown
twenty times through a `.lib` answers 21. Nothing in the `.lib` format
records a compiler ABI, so nothing catches the mix; a stamp there is the
obvious follow-up and is a feature, deliberately not added here.

**Not fixed, in scope terms.** An untyped parameter (`with items`) is
`Type::Unknown` on both sides of the call, so neither knows a collection is
in flight and the old behaviour stands; a collection reached through a thing's
field or any other non-variable argument has no storage to write back to, as
above. Buffers are a **separate defect with a worse symptom** — see the
Incidental note in `REPORT-75.md`: `_reallocate_buffer` does free the old
block, so a buffer grown through a `buffer` parameter past one page
segfaults rather than answering short. Extending this fix's two match arms
to `Type::Buffer` was tried and does **not** close it — `Append <x> to
<buffer>` writes the reallocated pointer straight into `dst_local`/
`dst_global` and never reaches `emit_store_back_after_realloc`, so the hook
is bypassed. It needs its own register entry and its own adjudication.


---

### 76. A `map` parameter is typed as nothing at all — `holder's length` emits `_file_size` and the program fails to ASSEMBLE, `Print holder` leaks a heap address, and `holder's length` reads `-1` where it links

**Status:** **fixed** in 0.4.10 (unreleased). Severity: **the build failure
is the headline** — a valid six-line Vox program is refused by NASM, not by
Vox, naming a symbol that appears nowhere in the source; there is no Vox
diagnostic at all, so nothing points at the cause. Behind it an **address
leak** into program output (bug #44's exact disease, in a position #44 did
not cover) and a **wrong value** (`-1`, bug #58's shape). Regression tests:
`tests/477_map_parameter_length_assembles.vox` (the program assembles at
all), `tests/478_map_parameter_properties_and_printing.vox`,
`tests/480_map_returned_from_a_function.vox`,
`tests/482_map_parameter_length_beside_a_keyed_read.vox` (the `-1`), plus
two controls that were already right and must stay right —
`tests/479_map_parameter_keyed_read_and_iteration.vox` and
`tests/481_typed_parameter_properties_agree.vox`. Found by the vox-fuzz
claim ledger / candidate audit 2026-08-21 (`REPORT-66.md` incidental 3,
which asked whether the `VarType::Unknown` had any user-visible symptom;
adjudicated in `REPORT-CANDIDATES-ROUND-2.md` §J, which found three) and
master-reproduced on `4b77934` = v0.4.9.

**Symptom 1 — the compiler emits assembly that will not assemble.**

```vox
To 'show' with a map called holder.
    Print holder's length.

a map called scores is {"a": 1, "b": 2}.
'show' of scores.
Exit 0.
```
→
```
j1.asm:76: error: symbol `_file_size' not defined
NASM assembly failed
[compile exit 1]
```

`_file_size` is only linked when the program uses files, and this program
does not. Controls: the same with a **list** parameter prints `2`;
`scores's length` at the **top level** prints `2`.

**Symptom 2 — a raw heap address.**

```vox
To 'show' with a map called holder.
    Print holder.

a map called scores is {"a": 1, "b": 2}.
'show' of scores.
Print scores.
Exit 0.
```
→
```
140376191160320
{"a": 1, "b": 2}
```

The same map, printed from inside the function and from outside it.
`Print "the map is {holder}"` leaks the address identically.

**Symptom 3 — `-1` where the program does happen to link.** A keyed read in
the same sentence pulls the file runtime in, so this one assembles:

```vox
To 'show' with a map called holder.
    Print holder's length,
    Print holder's "a",
    Print holder's empty.

a map called scores is {"a": 1, "b": 2}.
'show' of scores.
Exit 0.
```
→ `-1`, then `1`, then `0`. `-1` is a file size on a thing that is not a
file. `holder's "a"` → `1` ✓ and `for each key in holder's keys` → `a`,
`b` ✓, so the keyed read and the iteration were always fine; it was the
**properties** and the **printing** that were lost.

**A fourth symptom, the same omission one table over: a declared `map`
return.**

```vox
To 'make' with a number called seed. Return a map, {"a": 1, "b": 2}.
Print 'make' of 1.
```
→ `140612866650112`. `A map called got is 'make' of 1.` was already right,
because there the *declaration* supplied the type the call could not.

**Which reading the manual supports.** The rejecting one, and there is no
reading in which the compiler is right — this was looked for.

1. **LANGUAGE.md:722-725** is as explicit as the manual gets: "Parameters
   may use any of the 11 expressible types — `number`, `float`, `text`,
   `boolean`, `list`, `map`, `buffer`, `file`, `time`, `timer`, `value` —
   and **a typed parameter supports the same properties and operations as
   a top-level variable of that type**." `map` is named in the 11, and the
   promise is "the same", not "some".
2. **LANGUAGE.md:2422-2424** says a map's `length` (live entry count) and
   `empty` "work as for lists", and a top-level map delivers both.
3. **LANGUAGE.md:725-727** — "The same 11 types are also legal as a
   declared `Return a <type>,` return type (plan 296) — parameters and
   returns share one vocabulary, not two" — which is why the return
   position is the same defect and not a second one.
4. No reading makes an **assembler** error correct. README's "Memory
   Safety Model" and ROADMAP M0 are about runtime, but the weaker rule
   above them holds too: a program Vox accepts must build.

**The strongest reading in which the compiler is correct, and why it
fails.** "The manual over-promises, and `map` was simply never wired
through the parameter path." That dies on the evidence: `holder's "a"`
works, `holder's keys` works, and `for each key in holder's keys` works, so
the parameter *is* wired. It is one arm of one `match`, not a missing
feature.

**Mechanism.** The declared-type → codegen-`VarType` table had been copied
out **four** times — the declaration (`src/codegen/statements.rs`), the
parameter (same file, 940 lines away), a local function's declared return
type and an imported one's (`src/codegen/functions.rs`) — and `Type::Map`
had reached only the declaration's copy. The other three fell through to
`_ => VarType::Unknown`, and every property and print dispatch that
switches on `VarType` takes its default branch, which is the **file**
branch: `ObjectProperty::Size` on an `Unknown` emits `mov rdi, rax` / `call
_file_size` (`src/codegen/expr.rs`), and printing an `Unknown` pointer
renders it as an integer. Hence all four symptoms from one missing row:
unlinked symbol, `-1` (the file fallback's answer), and the address.

**The fix.** One table, `vartype_of_declared_type` in `src/codegen/mod.rs`,
beside the `VarType` enum it produces — carrying `Type::Map(_) =>
VarType::Map` — and all four sites now call it. Fixing only the parameter
arm would have left three copies to drift again, which is the shape this
bug already is; the hoist is the point of the repair, not a tidy-up beside
it. `file`, `time`, `timer` and `thing` stay `Unknown` deliberately (their
property reads go through their own paths), so the change is exactly one
new row and no behaviour moves for any other type — pinned by
`tests/481_typed_parameter_properties_agree.vox`, which is byte-identical
before and after.

**Family:** **#44** (`{list}`/`{map}` renders as a raw heap address outside
`Print` position — the same disease, in a position #44 did not cover),
**#45** (a forgotten type read back as an integer), **#58** (a lost type
falling through to `_file_size` and answering `-1` — the same wrong value
from the same fallback, reached by a different route). All four are "the
type was forgotten, so the integer formatter or the file path took it".

**LANGUAGE.md.** The Key-points bullet at :743 listed what buffer, list and
file parameters support and named no map at all, while :722-725 promised
them everything a top-level map has. The bullet now says so: map parameters
support `'s length`/`'s empty`/`'s keys`/`'s values` and keyed access, and
print as a whole map. Nothing new is promised — the general sentence
already promised it; the specific one had a hole where this bug lived.

**Not in scope, noticed on the way.**

- `Print "{key} is {holder's key}"` — a map read by a *dynamic* key inside
  a format hole — is rejected with `Unknown variable: holder's key`. That
  is `REPORT-CANDIDATES-ROUND-2.md` §K's territory (its "bug underneath"),
  not this entry's, and is unchanged here.
- A two-word variable name must be quoted: `A map called blank scores is
  {}.` parses, but `Print blank scores's length.` then fails with `Expected
  a statement, got Apostrophe`. Pre-existing on `4b77934`, unrelated to
  this mechanism, recorded for the queue and deliberately not changed.


---

### 77. The `append` value slot refuses a negative literal, `nothing`, every collection read and `times` — `append -5 to xs.` is "Expected value to append"

**Status:** **fixed in 0.4.10**.
Severity: **diagnostic — rejects legal Vox**, twice over, and both messages
name a cause that is not the cause: "Expected value to append" when a value
is exactly what was written, and "Expected 'to' after value in append
statement" with the `to` written right there. No wrong value and no memory
unsafety; a correct program is simply refused.
Regression tests: `tests/483_append_value_slot_takes_a_sign.vox`,
`tests/484_append_value_slot_takes_every_read.vox`,
`tests/485_append_value_slot_takes_times.vox`, plus two compile-fail
guards, `tests/compile_fail/213_append_value_slot_names_its_own_slot.vox`
and `tests/compile_fail/214_append_negative_to_buffer_is_still_a_type_rule.vox`.
Found 2026-08-22 by the collections sweep (`vox-notes/REPORT-SWEEP-COLLECTIONS.md`,
worktree `wt-sweep-collections`, Finding B) and by the core sweep
(`vox-notes/REPORT-SWEEP-CORE.md`, worktree `wt-sweep-core`, D-D — operators
ledger row **OPR-41**); adjudicated in `vox-notes/REPORT-CANDIDATES-ROUND-2.md`
§B and `vox-notes/REPORT-CANDIDATES-ROUND-3.md` §O, which ruled the two one
entry because they are one cause. Master-reproduced on 4b77934 (= 0.4.9).

```vox
a list called xs is [1].
append -5 to xs.
```
→
```
error: Expected value to append
  --> b1.vox:2:8
    |
  2 | append -5 to xs.
    |        ^--- here
```

```vox
a list called l1 is [].
a number called v1 is 3.
a number called v2 is 4.
append v1 times v2 to l1.
```
→
```
error: Expected 'to' after value in append statement
  --> o1.vox:4:11
    |
  4 | append v1 times v2 to l1.
    |           ^--- here
```

**The matrix, each row its own program, measured on 4b77934 and on the fix.
Every rejected form compiled the moment it was wrapped in braces — which is
what proves the refusal belonged to the slot and not to the language.**

| written in the append slot | before | braced, before | after |
|---|---|---|---|
| `append -5 to xs.` | Expected value to append | `-5` | `-5` |
| `append -0.5 to xs.` | Expected value to append | `-0.5` | `-0.5` |
| `append -n to xs.` (`n` a number) | Expected value to append | `-5` | `-5` |
| `append -9223372036854775808 to xs.` | Expected value to append | `i64::MIN` | `i64::MIN` |
| `append nothing to xs.` | Expected value to append | `nothing` | `nothing` |
| `append element 1 of ys to xs.` | Expected value to append | `9` | `9` |
| `append byte 1 of b to xs.` | Expected value to append | `65` | `65` |
| `append ys's first to xs.` | Expected 'to' after value | `9` | `9` |
| `append ys's last to xs.` | Expected 'to' after value | `8` | `8` |
| `append ys's length to xs.` | Expected 'to' after value | `2` | `2` |
| `append m's "k" to xs.` | Expected 'to' after value | `7` | `7` |
| `append v1 times v2 to l1.` | Expected 'to' after value | `48` | `48` |
| `append v1 multiply v2 to l1.` (control) | `48` | — | `48` |
| `append 0 minus 5 to xs.` (control) | `-5` | — | `-5` |
| `append 'A' to xs.` (control) | `65` | — | `65` |
| `append 0xFF to xs.` (control) | `255` | — | `255` |
| `append "s" to items.` (control) | `s` | — | `s` |
| `append "v={n}" to xs.` (control) | `v=5` | — | `v=5` |
| `append the n to xs.` (control) | `5` | — | `5` |
| `append 'twice' of n to out.` (control) | `10` | — | `10` |
| `append each item from src to out.` (control) | `3`, `4` | — | `3`, `4` |
| `append , to xs.` (control) | Expected value to append | — | Expected value to append |

The buffer overload takes the same primary, so `append -5 to b.` was
rejected identically. It is still rejected — by the rule that owns the
refusal ("Buffer append requires a buffer source or format/literal text"),
not by the parser refusing to read the value. That is what
`compile_fail/214` pins.

**Which reading the manual supports.** The rejecting one has no sentence
behind it, and the accepting one has four:

1. **LANGUAGE.md:1822** puts `-5` in the literal table — `| Integer |
   `42`, `0`, `-5` |` — alongside `42` and `0`, with no note attaching it
   to a position.
2. **LANGUAGE.md's append section** says the slot takes a `<value>`
   (`- `append <value> to <list>` appends one list element.`) and then
   "**Works with any value**: integers, strings, booleans, variables,
   expressions". No sentence anywhere narrows it.
3. **LANGUAGE.md's grammar summary settles `times` outright**:
   `append_stmt ::= "append" expr "to" name "."`, and
   `multiplicative ::= primary ((multiply | times | divide | modulo)
   primary)*` inside `expr`. The manual's own EBNF derives
   `append v1 times v2 to l1.`
4. **LANGUAGE.md's operator table** lists `multiply` and `times` as two
   spellings of one operator. The compiler accepted the first and refused
   the second, in the same slot with the same operands.

**The strongest reading in which the compiler is correct, and why it
fails.** The slot really does need its own parser: `to` is the append
separator, so a bare name must not read it as a call connector
(`append id of item to out`), and that is why `parse_append_value_primary`
and `parse_append_value_ops` exist at all. On that reading, refusing a
leading `-` is the price of keeping `append "s" to items` unambiguous, and
refusing `times` is the price of a slot terminated by a keyword.

It fails on the lexer. `-` is `Token::Minus`, and `Token::Minus` has
exactly one parser arm in the whole compiler: unary negation. It is **not**
a binary operator anywhere in Vox — subtraction is the *words* `subtract`
and `minus`, and `Print 7 - 2.` is "Expected a statement, got Minus". There
is no ambiguity for the slot to protect: a `-` at the start of a value can
only be a sign. And it fails on `times` twice over, because the other
fourteen operator spellings all compile in that position, `multiply` among
them — there is no separator that `multiply` protects and `times` does not.
The second reading, "the restriction is deliberate, use braces", is refuted
by the compiler's own behaviour: every rejected form above is accepted
verbatim inside `{…}`, which routes the identical tokens to `parse_primary`.
Braces changed nothing but which parser read them.

**Root cause.** Two hand-rolled copies of the general parser, in
`src/parser/collections.rs`, that had fallen behind the thing they copy:

- `parse_append_value_primary` (`:48-126` at 4b77934) wrote out an arm per
  value form. It knew literals, a string, a bare name and `the <name>`, and
  had never learned `Token::Minus`, `Token::Nothing`, `Token::Element`,
  `Token::Byte`, or any possessive `'s` — five value forms `parse_primary`
  has had all along. The separator protection it exists for is not in those
  arms at all: it lives in `suppress_to_connector`, one flag, consulted by
  `parse_call_tail`.
- `parse_append_value_ops` (`:136-165`) enumerated the operator tokens the
  slot accepts and listed `Token::Multiply` without `Token::Times`.
  `parse_multiplicative` has both. `times` and `multiply` are separate
  tokens because `Repeat N times` claims one of them.

This is the same shape as **#64** (a property table written out twice, so
the same reading answered under one spelling and was a parse error under
the other) and **#51**/**#58**: a second copy of a decision, kept by hand,
drifting from the first. The lesson is the same — one path.

**The fix.** The arms that do not need restricting now read one primary:
`parse_append_value_primary` keeps its explicit token list and its string
literal arm, and every other listed token goes to
`parse_primary_reserving(true, false)` — the general primary with `to`
reserved for the whole subtree. Nothing is copied any more, so a value form
is added or diagnosed in exactly one place, and an index's own list operand
(`element 1 of ys to xs`) is protected by the same flag rather than by a
second hand-written rule. `Token::Times` joins `parse_append_value_ops`,
making that list identical to `parse_multiplicative`'s.

Two things deliberately kept:

- **The string literal arm stays restricted.** `parse_primary` rejects
  `"s"` followed by `to` as a string used as a name (plan 270 §S1.5); in
  the append slot that `to` is the separator, so `append "s" to items.`
  must stay an append of the literal. Delegating it would have broken the
  most ordinary append in the language.
- **The token list stays explicit**, so a token that cannot start a value
  still answers with the slot's own diagnostic, caret on the offending
  token (**#46**), rather than falling through to the general parser's
  "Expected a statement, got Comma". `compile_fail/213` pins that.

**Fail-before/pass-after**, against a clean `git archive 4b77934` extract
built in a scratchpad: `425` stops at `append -5 to xs.` with "Expected
value to append", `426` at `append nothing to xs.` with the same, `427` at
`append v1 times v2 to xs.` with "Expected 'to' after value in append
statement"; all three pass on the fix. `compile_fail/214` fails before —
the baseline answers "Expected value to append", not the buffer rule — and
passes after. `compile_fail/213` is a guard, not a fail-before case: it
passes on both sides, pinning that the shared path still diagnoses a
non-value as the append slot's problem.

**LANGUAGE.md.** The manual was right and the compiler was behind it, so
nothing was walked back. The loose half was "**Works with any value**:
integers, strings, booleans, variables, expressions", a list of categories
with no rule under it: it named neither the forms above nor the one real
constraint on the slot. It now names them, and states that `to` is the
separator rather than an operator, with the braces escape for a value that
would otherwise read `to` as a word of its own (`append {'twice' to i} to
nums.`). Every snippet added was compiled and run before it was written in.

**Still refused, and left there deliberately — the residual of the same
drift, outside this entry's adjudicated scope.** Each of these is one token
in the same arm list, and each already compiles when braced, so none is a
new capability; they were not part of what round 2 §B and round 3 §O ruled
on, and they are recorded here rather than swept in:

| still refused | message | braced |
|---|---|---|
| `append not true to xs.` | Expected value to append | `{not true}` → `0` |
| `append current time to xs.` | Expected value to append | works |
| `append arguments's count to xs.` | Expected value to append | works |
| `append environment's "HOME" to xs.` | Expected value to append | works |
| `append [1, 2] to xs.` | Expected value to append | works |
| `append n as a text to xs.` | Expected 'to' after value | works |
| `append n is less than 9 to xs.` | Expected 'a'/'an' and a type noun after 'is' in append value | **braces do not help** |

The last row is a different defect and the only one with no workaround: the
statement's own `is a <type>` predicate branch claims the `is` that follows
a *closed* brace, so `append {n is less than 9} to xs.` is refused too. A
comparison cannot be written in an append value at all.


---

### 78. A buffer sized from a variable escapes the size bound — `-1 bytes` is accepted and reports `capacity -1`, and a size past what can be mapped segfaults

**Status:** **fixed** (unreleased, on top of 0.4.9).
Severity: **memory safety**. The reported half is a wrong number — a
`capacity -1` handed back to the author, the shape of #58 — but the arm
that let it through validates nothing at all, so the same three words
accept a size no mapping can serve: `_alloc_buffer_sized` answers 0, the 0
is stored as the buffer, and the next read of it dereferences it. Three
spellings reach that in three lines, one of them from a plain `2.5`.
Regression tests: compile-fail cases
`tests/compile_fail/219_buffer_size_named_is_negative.vox` through
`178_buffer_size_named_is_a_float.vox` — six cases covering the floor,
zero, the ceiling, the `Create ... with capacity N` spelling that was never
bounded at all, and the two wrong-type sizes — plus three passing controls:
`tests/505_buffer_sized_from_a_named_number.vox` (a named size within the
bound, in every declaration spelling the manual gives, byte-identical
before and after), `tests/506_buffer_size_only_run_time_can_decide.vox`
(the size arrives on the command line — this program segfaulted) and
`tests/507_buffer_size_from_arguments_good_and_bad.vox` (either side of the
bound in one program). Found by the vox-fuzz `gen_buffers` derandomisation
sweep (`REPORT-SWEEP-BUFFERS.md` §5, discrepancy D-B — the one bound
`'gen buffer size'` keeps, because a draw outside it is a non-compiling
program), adjudicated as candidate **G** of the round-2 candidate audit
(`REPORT-CANDIDATES-ROUND-2.md`, written 2026-08-22 against 4b77934, which
separated the manual gap **G-i** from the bug **G-ii**); master-reproduced
on 0.4.9.

```vox
a number called wanted is 0 minus 1.
a buffer called room is wanted bytes in size.
Print room's capacity.
```
→ prints **`-1`**. Written as a literal, `a buffer called room is -1 bytes
in size.` is refused.

```vox
a float called wanted is 2.5.
a buffer called room is wanted bytes in size.
Print room's capacity.
```
→ **segfault (139)**. The float's bit pattern is read as a byte count:
`2.5` asks for 4612811918334230528 bytes.

**The matrix, each case its own program, measured on this branch's parent
(4e29c3c) and on the fix:**

| program | before | after |
|---|---|---|
| `a buffer called room is 0 bytes in size.` | rejected | rejected (unchanged) |
| `a buffer called room is 1073741825 bytes in size.` | rejected | rejected (unchanged) |
| `a buffer called room is -100 bytes.` | rejected | rejected (unchanged) |
| `wanted is 0.` → `room is wanted bytes in size.` | prints `0` | rejected |
| `wanted is 0 minus 1.` → same | prints `-1` | rejected |
| `wanted is 1073741825.` → same | prints `1073741825` | rejected |
| `wanted is 4611686018427387904.` → same | **139** | rejected |
| `a float called wanted is 2.5.` → same | **139** | rejected |
| `a text called wanted is "ten".` → same | prints `4206732` (the characters' address) | rejected |
| `a boolean called wanted is true.` → same | prints `1` | rejected |
| `Create a buffer called room with capacity 1073741825.` | prints `1073741825` | rejected |
| `Create a buffer called room of size 4611686018427387904.` | **139** | rejected |
| the size read from `arguments's first`, given `4611686018427387904` | **139** | prints `0`, error flag raised, exit 0 |
| the size read from `arguments's first`, given `-1` | prints `-1` | prints `0`, error flag raised, exit 0 |
| `wanted is 100.` `Set wanted to 0 minus 1.` → same | prints `-1` | prints `0` at run time (the proof declines a written name; the guard holds it) |
| `To 'make one' with a number called wanted.` … `'make one' of 0 minus 5.` | prints `-5` | prints `0` at run time |
| `wanted is 256.` → same (control) | prints `256` | prints `256` |
| `base is 64.` `wanted is base multiply 4.` → same (control) | prints `256` | prints `256` |
| `a buffer called room is 256 bytes in size.` (control) | prints `256` | prints `256` |
| `a buffer called room.` (control, dynamic) | prints `4096` | prints `4096` |
| `Create a buffer called room with size 0.` (control, dynamic) | prints `4096` | prints `4096` |

**Which reading the manual supports.** The bound itself was undocumented —
that is the audit's **G-i**, and this fix writes it down (LANGUAGE.md:3315,
under "Fixed-Size Buffers"). But nothing in the manual made the bound a
property of the *spelling*, and three sentences make the behaviour above
wrong under any reading:

1. **LANGUAGE.md:3309** — "Allocates exactly the specified capacity" — is
   the only sentence about the number. `capacity -1` is not a capacity
   that was allocated; it is a field written from an argument nobody
   checked. `_alloc_buffer_sized` mapped 24 bytes (`-1 + BUF_DATA + 1`)
   and stored `-1` in the header.
2. **LANGUAGE.md:3310** — a fixed buffer "does NOT grow — a read or write
   past capacity is truncated at capacity and sets the error flag" — is
   the rule a negative capacity silently defeats: every write is "past
   capacity", so the buffer holds nothing and reports `size 0`, which is
   #58's symptom under a different cause.
3. **README's Memory Safety Model** and **ROADMAP M0** ("no valid Vox
   program may segfault") forbid the crash outright, and the crashing
   programs are ones the compiler accepted.

**The strongest reading in which the compiler is correct, and why it
fails.** The source states one: `src/parser/declarations.rs:701-702` —
"Validate that the size expression is a positive integer literal or
constant variable. **This is critical for memory safety.**" On that
reading a 1 GiB ceiling is a sane guard, a zero-byte fixed buffer is
useless, and the only thing missing is a sentence in the manual.

That reading dies on the next arm of the same `match`, which the same
comment covers:

```rust
Expr::Identifier(_var_name) => {
    // Allow variable references for size - validated at compile time
}
```

It was validated nowhere — not in the analyzer, not in codegen, not in the
runtime. The comment describes a check that did not exist, and the parser
is the one place it could never have been written: the parser knows no
values and no types. So the three refusals the compiler did make were
rules about how the size was *written*, not about the size.

**Mechanism.** Every buffer declaration spelling — `is N bytes`, `is N
bytes in size`, `Create ... with size N`, `with capacity N`, `of size N`,
and the sizeless dynamic form — parses to one `Statement::BufferDecl`, and
codegen's arm evaluates the size expression into `rax` and calls
`_alloc_buffer_sized` (`src/codegen/statements.rs:1698`). Nothing between
the parser's literal arm and that call looked at the number:

- a negative size mapped a header and nothing else, and reported the
  negative capacity back (`_alloc_buffer_sized`,
  `coreasm/x86_64/resource.asm:804` — `mov [rax + BUF_CAPACITY], r12`);
- a size past what mmap can serve took the `.sized_failed` path, which
  returns 0 — a null the declaration stored as the buffer pointer, so the
  fault landed on the next read rather than at the declaration, exactly as
  #57's and #65's crashes did;
- a text or float name was never a byte count at all: its address, or its
  mantissa's bits, went to `mmap` as a length.

The `Create ... with size N` spelling (`src/parser/declarations.rs:405-427`)
never reached the literal check either — it parses the size with
`parse_primary` and returns, so `with capacity 1073741825` was accepted
while `is 1073741825 bytes` was refused, one rule, two answers.

**The fix — hold the bound wherever a size is decided.** The two numbers
move to one place, `MIN_BUFFER_SIZE`/`MAX_BUFFER_SIZE` in
`src/parser/ast.rs:1128`, and three sites read them:

- **The parser** keeps the literal check it already had, unchanged, and
  its identifier arm now says what is true — that a named size is decided
  elsewhere.
- **The analyzer** gains `check_buffer_size` (`src/analyzer/types.rs:1641`),
  called from the one `Statement::BufferDecl` arm every spelling routes
  through, so the bound is a rule about sizes rather than spellings. It
  refuses what it can prove: a literal past the bound in the `Create`
  spelling the parser does not check; a named size whose value is fixed
  for the whole program and outside the bound; and a named size whose type
  is not a whole number of bytes. The diagnostics are in #45/#62/#63's
  family — they name the size, what it comes to, the bound, and the way
  out — with the caret on the size token (#46).
- **Codegen** guards the rest (`emit_buffer_size_guard`,
  `src/codegen/buffers.rs:333`), emitted only for a size that is not a
  literal. Out of bound at run time, the request becomes a fixed buffer of
  no capacity and raises the error flag; in bound, it clears the flag, per
  `_last_error`'s lifecycle rule. That is the buffer LANGUAGE.md:3332-3337
  already describes — writes truncated, the flag set, "program continues
  normally", `On error` able to catch it — and it is what closes the
  segfault for a size no static check can see, like one read from
  `arguments`.

The value proof is `collect_constant_numbers` (`src/parser/ast.rs:1178`), a
whole-program pre-pass in the shape of #54's `collect_widened_lists`: a
name is only proved constant if it is declared once with an initializer
`constant_integer` can evaluate and **nothing anywhere writes to it** —
not an assignment, an increment, a second declaration, a loop variable or
a parameter of that name. A value tracked as the walk proceeds would be
whatever the last branch happened to store, and a size proved from a branch
nobody takes would refuse a program that is legal on the other path. Losing
the proof costs a diagnostic; a wrong proof would cost a correct program.
`Set wanted to 0 minus 1.` after a good declaration is exactly that case:
the proof declines, and the run-time guard holds the size instead.

**What is deliberately still allowed:**

- **`Expr::IntegerLit(0)`.** That is not an author writing `0` — the
  parser gives every sizeless buffer (`a buffer called room.`, `Create a
  buffer called room.`) exactly that tree, so at the declaration the two
  are indistinguishable, and a literal `0 bytes` is already refused in the
  parser where they can be told apart. `Create a buffer called room with
  size 0.` therefore still makes a dynamic buffer.
- **A dynamic buffer's `capacity` of 4096**, where LANGUAGE.md:3297 says
  zero. That is round-1 candidate G, an open design question about what a
  declared capacity *means*, and it is untouched here.
- **A `value`, a parameter, a flag, or any size the compiler cannot
  prove** — the same "can't prove it, so allow it" policy as every other
  check in `types.rs`. The run-time guard is what stands behind it.
- **`resize`.** See below.

**Incidental, not fixed here.** `resize` takes a new capacity through a
different statement (`Statement::BufferResize`) and has never had a bound
at all — not even on a literal:

```vox
a buffer called room is 64 bytes in size.
resize room to 0 minus 1 bytes.
Print room's capacity.
```
→ **SIGBUS (135)**, and the same program with the size in a variable faults
identically. It is the same family as this entry — a size that reaches the
runtime unchecked — but a separate statement and a separate code path, so
it is recorded rather than folded in; it wants its own entry and its own
fail-before test.



### 79. A top-level read before the variable's own declaration is accepted and prints the raw slot — no "used before its declaration" diagnostic exists

**Status:** **fixed** (unreleased, on top of 0.4.9). Severity: **memory
safety**. The audit filed this as a missing diagnostic with a wrong value
behind it, which is what the scalar `Print` it was found through does — but
the audit only measured that one shape. Every collection, map and buffer
spelling of the same too-early read **segfaults**: eleven of them, measured
below, none of them reported by the compiler. Regression tests: compile-fail
cases
`tests/compile_fail/230_top_level_read_before_declaration.vox` through
`178_top_level_element_read_before_declaration.vox` (six cases — the bare
read, the number twin, a format hole, a property read, an `append` and an
element read), plus five passing controls,
`tests/516_top_level_read_after_declaration.vox` (the nearest working
neighbour),
`tests/517_global_read_inside_a_function_defined_first.vox` (the shape
that must NOT be rejected),
`tests/518_top_level_write_before_the_declaration.vox`,
`tests/519_declaration_in_every_branch_read_after.vox` and
`tests/520_declaration_in_a_loop_body_read_after.vox` — all five
byte-identical before and after. Found 2026-08-21 by the #66 fix worker
(`REPORT-66.md`, incidental 1) and adjudicated by the language lawyer in
the round-2 candidate audit, section H; master-reproduced on 4e29c3c.

```vox
Print label.
a text called label is "hello".
```
→ prints `0`, exit 0, no diagnostic.

```vox
Print count.
a number called count is 42.
```
→ prints `0` — right by accident, which is how the text case above went
unnoticed.

**Nearest working neighbour:** move the declaration above the read. That is
the order every example in LANGUAGE.md's "Variables" section is written in.

**The reading in which the compiler is right, and why it fails.** Top-level
statements run in order, so at line 1 the declaration on line 2 has not
executed. The storage exists — it is `.bss`, zeroed at load — and the read
sees its zero. Nothing is undefined and nothing faults; on that reading Vox
behaves like C with a zero-initialised global and the author's program is
simply wrong.

**That reading gets the wrong answer even on its own terms.** If the read
sees "the variable before its initializer ran", LANGUAGE.md's bare-`Create`
default table says what that is: a `text` defaults to the **empty string**.
`Print label.` should print an empty line. It prints `0` — the raw slot,
formatted as an integer, because `variable_types` has no entry for the name
yet and codegen falls back to the integer formatter. **The type has been
forgotten, not defaulted.**

And the compiler already proves it knows the difference between "not yet"
and "never":

```vox
Print label.
```
→ `error: Unknown variable: label`, caret on `label`.

So the name **is** resolved; only its type is not. Typing the read would be
worse than the diagnostic, not better: it would turn a printed `0` into a
null-pointer dereference. The answer is a diagnostic.

**Root cause.** `src/analyzer/statements.rs` seeded the top-level walk with
the whole-program set — `self.variables = self.global_variables.clone()`
immediately before the second pass — so every top-level name was available
from the very first statement. `global_variables` comes from
`collect_definite_decls` (`src/parser/ast.rs`), which is whole-program and
order-independent by design, because a **function** body genuinely needs it:
a function runs when it is called, after the whole file has been read, so a
body written above a global's declaration may name it (LANGUAGE.md "Function
Scope"). Top-level code has no such licence, and got it anyway. Meanwhile
the *type* sets (`scalar_types`, and the label codegen reads) are filled by
the walk, in order — so between the two, the name existed and its type did
not. That split is the disease; the same split one scope in is #66's.

**The fix.**

- `src/analyzer/statements.rs` — the top-level walk now starts with nothing
  available and fills `variables` in declaration order. The `FunctionDef`
  arm already seeds itself from `global_variables`, so the case that needs
  the whole-program set keeps it and nothing else does.
- `src/analyzer/scope.rs` — `is_used_before_its_declaration` (a name the
  pre-pass proved exists, that this walk has not reached, outside a function
  body, and not a flag — a flag read before `parse flags.` has its own, more
  specific diagnostic) and `push_used_before_declaration`, which names the
  construct, says which line the declaration is on, and gives the way out.
  The caret goes on the failing read via `find_use_site_location`, not on
  the declaration that happens to contain the same name (#46).
- `src/analyzer/scope.rs` — `push_unknown_variable` and `push_error_with_hint`
  route to it. The second is the choke point that catches the twenty
  `Unknown …: X` sites in `statements.rs` and `expressions.rs` —
  `Unknown buffer:`, `Unknown list:`, `Unknown timer:` and so on. Each sits
  behind `if !self.is_variable_available(X)`, so an error about a symbol that is
  unavailable *here* but declared further down is always this defect,
  whatever wording the arm chose. An error about a symbol that IS available
  cannot reach it, so no type-lock or wrong-kind diagnostic is touched.
- `src/analyzer/scope.rs` — `is_variable_declared_anywhere`, the old
  order-blind predicate, kept for the two callers that must stay order-blind:
  `was_already_declared` in the `VarDecl` and `Assignment` arms, which asks
  "is this statement a declaration or a reassignment?" and decides whether
  the type lock applies. Those two answers are byte-identical to before.
- `src/analyzer/scope.rs` — `declare_variable_in_current_scope` now registers
  the name **before** complaining that it starts with `_`. It used to push
  that error while the name still looked unavailable, so the new choke point
  read it as a use-before-declaration and reported
  `'_foo' is used before it is declared`, pointing at the line *after* its
  own declaration. Caught by `tests/compile_fail/071_reserved_underscore_variable.vox`.
- `src/analyzer/statements.rs` — the `ListAppend` arm asked what **kind** the
  name was before it asked whether the name was available, and both kind sets
  are whole-program. `append 1 to items.` above `a list called items is [].`
  therefore walked past the availability check into codegen and **segfaulted**
  on a list header that did not exist yet. Order first, kind second.

**The diagnostic:**

```
error: 'label' is used before it is declared
  --> h1.vox:1:7
    |
  1 | Print label.
    |       ^--- here
    |
  note: top-level statements run in the order they are written, and 'label' is declared at line 2
  help: move the declaration of 'label' above this line; a function body may read a global declared further down, top-level code may not
```

**The matrix, each case its own program, measured on a clean extract of this
branch's parent (4e29c3c) and on the fix:**

In every row the read is written first and the declaration immediately
below it. The declarations used are `a text called label is "hello".`,
`a number called count is 42.`, `a number called total is 5.`,
`a list called items is [1, 2].`, `a map called ages is {"bo": 3}.` and
`a buffer called built is "seed".`

| program | before | after |
|---|---|---|
| `Print label.` | prints `0` | rejected |
| `Print count.` | prints `0` | rejected |
| `Print "the label is {label}".` | prints `the label is 0` | rejected |
| `a number called doubled is total multiply 2.` then `Print doubled.` | prints `0` | rejected |
| `If total is 5 then, Print "yes".` | runs, branch not taken, prints nothing | rejected |
| `Print label's size.` | rejected — *"Property 'size' requires a buffer, list, map, or file variable: label"* | rejected, and now names the real cause |
| `append 1 to items.` | **139** | rejected |
| `append "x" to built.` | **139** | rejected |
| `Print element 1 of items.` | **139** | rejected |
| `Print ages's "bo".` | **139** | rejected |
| `Set element 1 of items to 9.` | **139** | rejected |
| `Set ages's "bo" to 9.` | **139** | rejected |
| `Set byte 1 of built to 65.` | **139** | rejected |
| `Clear built.` | **139** | rejected |
| `Resize built to 8 bytes.` | **139** | rejected |
| `copy "hi" to built.` | **139** | rejected |
| `For each part in items, Print part.` | **139** | rejected |
| `a text called label is "hello".` + `Print label.` (control) | `hello` | `hello` |
| a function reading a global declared **below the function** (control) | works | works |
| `Set total to 9.` + `a number called total is 5.` + `Print total.` (control) | `5` | `5` |
| a name declared in every branch of an `if`/`otherwise`, read after (control) | `first` | `first` |
| a name declared in a loop body, read after (control) | `5`, `0` | `5`, `0` |
| `Print nothingatall.` — never declared at all (control) | `Unknown variable: nothingatall` | **unchanged** |
| a flag read before `parse flags.` (control) | `Flag variable 'verbose' is used before flags are parsed` | **unchanged** |

Eleven of the seventeen shapes fault. The scalar `Print` the audit was
found through is the *mildest* row in the table: it is the one where the
zeroed slot happens to be a legal integer rather than a null pointer about
to be dereferenced.

**A write is deliberately untouched.** `Set total to 9.` above
`a number called total is 5.` still compiles: the order it describes is well
defined — store 9, then the declaration stores 5 — and nothing reads a slot
nobody has written. #79 is about reads. Pinned by
`tests/518_top_level_write_before_the_declaration.vox`.

**LANGUAGE.md.** The manual stated no rule for the top level in either
direction — it simply never wrote the program. LANGUAGE.md:707's
"Referencing an unknown variable inside a function is a compile-time error"
is scoped to function bodies. A new **Declaration Order** subsection under
"Variables" states the order rule and the function-body exception, and the
"Function Scope" bullet about globals now says explicitly that a function
written *above* the declaration may still name it. No feature added; the
sentence the manual was missing.

**Incidental, not in scope, left alone.** A function body that reads a
**text** global declared below the function prints the string's rodata
address as a decimal number:

```vox
To announce.
  Print label.

a text called label is "hello".
announce.
```
→ `4198488` (stable across 5 runs). Moving the declaration above the
function prints `hello`. The manual explicitly permits the reference
(LANGUAGE.md "Function Scope"), so the answer there is a **type**, not a
diagnostic — the opposite of #79's answer, which is why it is not fixed
here. It is the same forgotten-type split one scope in, and the round-2
audit names it as #66's, not this entry's. Byte-identical before and after
this fix. The number twin of the same program answers correctly, by the same
accident as the `Print count.` row above.

**Family:** #45 / #62 / #63 — the "silently accepted, silently wrong word"
entries, whose answer is a helpful compile error. The diagnostic follows
#46's caret rule (on the offending token, never on a comment or an unrelated
earlier mention of the name). #66 is the same forgotten-type split inside a
function body.

---

### 80. A `thing` instance declared below a function cannot be read inside it — `Expected property name, got Identifier("x")`, with the caret on the property name

**Status:** **fixed** (this branch), for 0.4.10. Found 2026-08-21 by the
#66 fix worker while probing the forward-global surface (`REPORT-66.md`,
Incidental 1), adjudicated 2026-08-21 in the round-2 candidate audit
(`REPORT-CANDIDATES-ROUND-2.md` §I) and master-confirmed against
`4b77934`. Rejects legal Vox at compile time, so no program could
silently do the wrong thing — the same diagnostic class as #64, and the
loud half of the pair whose silent half is #66.

```vox
A thing called point has
  a number called x is 7,
  a number called y is 9.

To 'show all'.
  Print origin's x.

a point called origin.

'show all'.
Exit 0.
```
```
error: Expected property name, got Identifier("x")
  --> repro.vox:6:18
    |
  6 |   Print origin's x.
    |                  ^--- here
```

Move `a point called origin.` above the `To` and the same program prints
`7`. The declaration is an ordinary top-level variable, and
LANGUAGE.md:705 says *"Variables declared at top level are global and
can be used inside functions"* — with no ordering condition attached.
The ordering rule the manual does state (:1607, :1630) is about a thing
**definition**: *"A thing is defined where a function is defined — at
the top level"*, and *"the same defined-earlier rule that orders one
file orders the pair — every use below stands after the definition it
names"*. In the repro the definition is already above the function.
Only the instance is below.

**The message describes the wrong problem.** The caret lands on `x`
under *"Expected property name"* — and `x` is the one token in that line
that demonstrably is a property name. Nothing points at the
declaration's position, which is the actual complaint.

**One layer out of four still resolved by walk order.** The parser
decides whether `origin's x` is a field chain or an object property from
`thing_vars` (`src/parser/mod.rs:122`), and that table was filled as
declarations were *parsed*, in source order
(`src/parser/things.rs:742`). A function body parsed above the
declaration therefore asked the table before the answer was in it, fell
through to the generic property table in
`Parser::parse_possessive_tail`, and reported the first token that
matched none of its arms. The analyzer and codegen have had a
whole-program answer to the same question all along —
`collect_thing_vars` (`src/analyzer/things.rs:283`) walks the statement
list, and both layers call it (`src/analyzer/things.rs:377`,
`src/codegen/things.rs:25`). The parser was the one layer resolving by
where the cursor had reached.

**The whole surface, probed against `4b77934`.** Every row is one
program: a thing definition, a function that reads the global, the
global declared **below** that function. The last two rows are the
controls.

| read, inside a function defined above the declaration | before | after |
|---|---|---|
| `Print origin's x.` | ✗ *Expected property name, got Identifier("x")* | `7` |
| `Print the origin's x.` | ✗ *…got Identifier("x")* | `7` |
| `Set origin's x to 11.` | ✗ *Expected a statement, got Apostrophe* | `11` |
| `Print "x is {origin's x}".` | ✗ *Unknown variable: origin's x* | `x is 7` |
| `Print origin's doubled.` (instance possessive → call) | ✗ *…got Identifier("doubled")* | `14` |
| `Print trip's outbound's start.` (chain through a nested thing) | ✗ *…got Identifier("outbound")* | `3` |
| `Create a point called moved.` then `Print moved's x.` | ✗ *…got Identifier("x")* | `7` |
| `see`n definition, instance declared below the function | ✗ *…got Identifier("x")* | `11` |
| **control** — the declaration written above the function | `7` | `7` |
| **control** — a `number` global declared below the function | `7` | `7` |

The last control is the point of comparison: a *scalar* global read the
same way already worked, which is why this pair's silent half (#66) and
its loud half (this entry) had to be fixed separately. #66 is codegen;
this is the parser.

**Fix.** The parser gets the pre-pass the other three layers already
have. `Parser::register_declared_thing_vars`
(`src/parser/things.rs`) walks the token stream once before the first
statement is parsed and registers every `a <thing> called <name>`
declaration into `thing_vars`; `parse_statement_list` calls it, and
`parse_include` calls it again after a `see` splices new definitions in,
so a declaration naming a seen file's thing is registered too.

Three things it deliberately does **not** do:

- **It skips function bodies.** The set it walks is exactly the set
  `collect_thing_vars` walks — the top level and the blocks written at
  it, never a body's parameters or locals, which are registered when
  that body is parsed and belong to it. Three tables describing
  different sets are three answers waiting to disagree, which is #51's
  and #58's lesson and #64's.
- **It skips thing definitions.** The `a leg called outbound` inside
  `A thing called route has` declares a field of `route`, not a variable.
- **It does not lift the definition-ordering rule.** A type noun is only
  read from a definition the scan has already passed, the same rule
  `try_parse_thing_type_noun` applies during the walk, and the manual
  states that rule outright.

First declaration wins; the walk that follows overwrites each entry as
it reaches it, so a name declared twice still reads as whichever
declaration stands above the use — which is what the walk alone gave
before this existed.

**The residual rejection now says what is wrong.** A thing used above
its *definition* is still refused — LANGUAGE.md:1630 says every use
stands after the definition it names — but that case used to reach the
same *"Expected property name"* message, and the arm in
`parse_thing_possessive` that catches it was marked unreachable. It is
reachable now (the declaration is known before the definition is read),
and it names the construct and the way out, in #46's family:

```
error: Thing 'point' is defined below this line
  A thing is defined at the top level, like a function, and every use of
  its name stands after the definition.
  Move the definition of 'point' above this line.
```

**LANGUAGE.md.** Two sentences tightened, no feature added: :705 now
says a top-level variable is readable inside a function *"whether the
declaration stands above the function or below it"*, and *Definitions
are top-level only* now says in as many words that the ordering rule is
about the definition and not about an instance of it.

Regression tests: `tests/511_thing_global_below_function.vox` (the
repro, now right), `tests/512_thing_global_above_function.vox` (the
working neighbour, still right — a control that passes on both sides),
`tests/513_thing_global_below_function_spellings.vox` (the article, the
write target, the format hole and the nested chain),
`tests/514_thing_global_below_function_instance_call.vox` (the instance
possessive resolving to a declared member and to an ordinary function
taking the thing first), and
`tests/515_thing_global_below_function_seen_type.vox` (the definition
arriving through a `see`). Four of the five are proven to fail against a
clean extract of `4b77934`; 426 is the control.
`tests/compile_fail/229_thing_defined_below_use.vox` pins the residual
diagnostic.


### 81. A dynamic map key inside a format hole — `"{m's \"{k}\"}"` — renders the value then two stray characters from the hole's own syntax

**Status:** **fixed** (this branch, 0.4.10), found 2026-08-22 by the #68 fix
worker as an incidental (`REPORT-68.md`, `wt-vox-68`) and adjudicated in the
candidates round-2 audit (`REPORT-CANDIDATES-ROUND-2.md` §K, verdict
**K-underneath: bug**, severity *wrong value (silent)*). Silent: the value is
right, the two extra characters are not, and the program exits 0. Family of
**#44** / **#59** / **#60** / **#61** (format-hole rendering) — and like #60
and #61 it is the hole parser mis-splitting its own syntax rather than codegen
emitting the wrong bytes.

Note the register also closes **K-as-reported** — *"a map value by key cannot
be spelled in a format hole"* — as a **misread**: `"` inside a `"`-delimited
string ends the string, `\"` is the documented escape and works, and a bare
identifier after `'s` is a property, not a key (LANGUAGE.md:2400). Both
reported halves are the compiler applying documented rules. The bug is the
composition *underneath* them.

```vox
a map called scores is {"a": 1}.
a text called key is "a".
Print "[{scores's \"{key}\"}]".    ([1"}]  — should be [1])
Print "[{scores's \"a\"}]".        ([1]    — the static key was always right)
```

**Nearest working neighbour**, which is what makes it a bug and not a
limitation — the same read, one line earlier, is exact:

```vox
a number called got is scores's "{key}".
Print "[{got}]".                   ([1])
```

Both features are documented and the manual sanctions the composition.
LANGUAGE.md:2400 — *"Read a value by key with `map's "key"` (the key is a
text literal; a quoted key with `{...}` interpolation builds a dynamic
key)"*. LANGUAGE.md:3147 — *"Embed variables and expressions directly in
strings using curly braces `{}`"*, and :3169 says the hole holds *"a variable
or expression"*, which a possessive map read is; the manual writes possessives
in holes itself (`{arguments's count}` at :3191). Nothing marks a hole as
unable to hold a quoted string, and no reading makes silent output corruption
correct — even if the composition were refused, the answer would be a
diagnostic.

**The hole parser could not see a quoted string inside the hole.**
`parse_format_string` in `src/parser/expressions.rs` did two things to a
hole's contents, and both were blind to quoting:

1. It scanned for the terminator with `if c == '}' { break }` — the *first*
   `}`, wherever it sat. For `{scores's "{key}"}` that is the key's own
   closing brace, so the hole content came out as `scores's "{key` and the
   leftover `"}` fell through to the next iteration of the outer loop, which
   pushed both into the literal run. Hence a correct value followed by `"}`:
   the sub-parser recovered the key from the truncated `"{key` (an
   unterminated string yields `{key`, which re-enters the format parser and
   resolves `key`), which is exactly why the *value* looked right and hid the
   defect.
2. It split the format spec with `placeholder_content.find(':')` — again the
   first one, so a key containing a colon was cut in half.

Both now track whether the scan is inside a quoted string and ignore a `}`
or a `:` that sits in one. Every `"` reaching this function was written `\"`
in source — the lexer (`read_string`, `src/lexer/scan.rs`) unescapes it
before the parser sees it — so each quote really does open or close a string
and the toggle is exact.

**The whole surface, probed on `main` (4b77934) and on this branch.** One
map, `{"ada": 10, "grace": 20, "}": 1, "a}b": 3, "a:b": 5}`, and `key` is
`"ada"`:

| hole | `main` 4b77934 | this branch |
|---|---|---|
| `{scores's \"{key}\"}` | `10"}` | `10` |
| `{scores's \"grace\"}` | `20` | `20` (unchanged) |
| `{scores's \"{key}\"} and {scores's \"grace\"}` | `10"} and 20"}` | `10 and 20` |
| `{scores's \"}\"}` | `0"}` — **wrong value** | `1` |
| `{scores's \"a}b\"}` | `0b"}` — **wrong value** | `3` |
| `{scores's \"a:b\"}` | `0` — **wrong value, no stray characters** | `5` |
| `{scores's \"{key}\":6}` | `10":6}` — spec dropped | `    10` |
| `{scores's \"{key}\":x}` | `10":x}` — spec dropped | `0xa` |
| `{scores's \"ada\":6}` | `    10` | `    10` (unchanged) |

The last three rows are why the colon split was fixed with the terminator
scan rather than left for a second entry: it is the same blindness, in the
same function, two lines apart, and it is the more dangerous of the two —
a wrong value with *no* visible corruption to notice.

**It is the shared parser, so the fix reaches every site.** `string_value_expr`
routes every value-position string literal through `parse_format_string`, so
the same hole was broken in a `Print`, a text initializer, a buffer `Append`
and a list element, and all four are fixed by the one change:

```vox
a text called line is "as a text value: {scores's \"{key}\"}".   (was 10"}, now 10)
Append "into a buffer: {scores's \"{key}\"}" to note.            (was 10"}, now 10)
a list called lines is ["in a list: {scores's \"{key}\"}"].       (was 10"}, now 10)
```

**Untouched, and pinned:** quotes outside a hole (`"he said \"hi\" to
{name}"`), the `{{`/`}}` escapes, every format specifier row, a static key,
and the *"Unmatched `{` in a string literal"* diagnostic that
`Append "{" to out.` still raises.

**Tests.** `tests/508_dynamic_map_key_in_a_format_hole.vox` (the repro, the
static key next to it, text either side of the hole, two dynamic keys in one
string, keys holding the hole's own punctuation, and the working neighbour)
and `tests/509_a_quoted_key_reads_at_every_format_hole.vox` (the colon key,
the specs it composes with, and the same hole at each of the four sites).
Both fail on a clean 4b77934 extract and pass here.

**Not in scope, noticed on the way.** A key holding a *single* `{` — `{"{": 2}`
— cannot be written at all: a lone `{` in any string literal is *"Unmatched
`{` in a string literal"*, which is the documented `{{` escape rule doing its
job, not this bug. But its caret lands on the **first string literal in the
file** rather than on the offending one (in a 25-line test it pointed at line
8's map literal and at an unrelated `Print` on line 12). That is a span
misattribution in the #46 family, unrelated to this mechanism, left alone.


---

### 82. The runtime text→float parser rounded once per fractional digit, so `"0.88" as a float` was not `0.88` — 53 of the 1000 two-decimal values disagreed with their own literal

**Status:** **fixed** (unreleased, for 0.4.10).
Severity: **wrong value, silent** — no error flag, no diagnostic, and
`_print_float` trims the answer back to the spelling you asked for, so the
only way the difference ever surfaced was a comparison that mysteriously
failed or a total that drifted. Regression tests:
`tests/495_text_to_float_matches_the_literal.vox` (the headline repro
through both the static cast and the `value` retype, plus the neighbours
that were always right),
`tests/496_text_to_float_over_the_reported_table.vox` (every row of the
adjudication report's table, plus four values with an integer part),
`tests/497_buffer_to_float_matches_the_literal.vox` (the length-bounded
parser behind a buffer cast, including a buffer filled byte by byte and
one cleared and refilled), and
`tests/498_text_to_float_past_the_mantissas_room.vox` (decimals longer
than the mantissa can hold). Found by the vox-fuzz claim ledger row
**VAL-09** (`'gen leaf value retype'`, `src/gen_collections.vox`),
surfaced as discrepancy **D-F** of the core sweep
(`REPORT-SWEEP-CORE.md`) and adjudicated in
`REPORT-CANDIDATES-ROUND-3.md` §L-i (2026-08-22). Master-reproduced on
`4b77934` = v0.4.9; byte-identical on v0.4.8, so not a 0.4.9 regression.

```vox
a value called p is "00.88".
p is a float.
If p is not 00.88 then, Print "ASSERT: expected 00.88 got {p}", Exit 95.
Print p.
```
→ `ASSERT: expected 00.88 got 0.88`, exit **95**. The assertion fired
while printing a number that looked identical to the one it expected.

It was never the `value` retype. The manual's own documented static cast
had it too:

```vox
a text called s is "0.88".
a float called viacast is s as a float.
If viacast is not 0.88 then, Print "cast: differs". Otherwise, Print "cast: equal".
a float called plain is 0.88.
If plain is not 0.88 then, Print "literal: differs". Otherwise, Print "literal: equal".
Print "{viacast:.17}".
Print "{plain:.17}".
```
→ `cast: differs` / `literal: equal` / `0.88000000000000012` /
`0.88000000000000000`. The printer was fine — `{:.17}` told the truth on
both lines. The two parsers were one ulp apart.

**Root cause.** `coreasm/x86_64/float.asm:399-497` (`_parse_f64`)
accumulated the fractional digits as an integer and then divided by ten
once per fractional digit:

```asm
.pf64_pow10_loop:
    mov rax, 10
    cvtsi2sd xmm2, rax
    divsd xmm1, xmm2        ; one rounding per digit
    dec rcx
```

Every `divsd` rounds. The compile-time parser is Rust's `f64` parse,
which is correctly rounded in one step. For `0.88` the runtime walked
88 → 8.8 → 0.8800000000000001 (bits `4606101554889448490`) where the
literal gives 0.88 (`4606101554889448489`) — and the bit pattern the
ledger's assertion printed is *exactly* the repeated-division answer, not
the correctly-rounded one. `_parse_f64_bounded` (`:507-621`) carried the
identical loop, so the buffer-typed cast had it too. Between them these
two routines are reached by `<text> as a float`
(`src/codegen/expr.rs:2068`), `<buffer> as a float` (`:2061`) and the
`value` retype (`src/codegen/tags.rs:624`) — every way a Vox program can
turn text into a float, including text read from a file, an argument or
an environment variable.

**Two corrections to the adjudication report.** Both of its headline
figures were modelled rather than measured, and both are wrong in the
compiler's favour:

- It predicted **288 of 1000** two-decimal values in [0, 10). The
  measured answer is **53** — 30 of the 100 below one, 11 in [1, 2), 6
  in [2, 3), 6 in [3, 4), and none at all from 4 upward. The model
  compared the fractional parse in isolation and multiplied by ten; in
  the real routine a large integer part is added back afterwards, and
  that addition re-rounds the sum onto the same double. The report's
  twelve spot-checks were all below one, where the model happens to be
  right, so all twelve confirmed.
- It said the bug included "the manual's own example". It did not:
  `"3.14" as a float` and the literal `3.14` were already the same
  double before this fix, and `tests/495` pins that they still are.

**What is true and was under-reported:** the same routines also wrapped
their 64-bit accumulator with no room check, so a long decimal did not
land an ulp away — it landed somewhere else entirely.
`"3.141592653589793238462643"` read as **2.999995446079999**;
`"123456789012345678901.5"` read as a **negative** number; twenty nines
read as `7.7662796314522419e+18`. And `_parse_f64_bounded` jumped to its
no-digits exit without ever writing its result register, so an empty
buffer cast to a float handed back **whatever float had been computed
last** (`tests/497` prints `-0.88` for that line on the old runtime).
Neither could be left standing by a rewrite of the accumulator they live
in; both are fixed here and pinned by `tests/497` and `tests/498`.

**The fix.** Both parsers now read the whole decimal — every digit of
both parts — into one integer mantissa, carrying a decimal exponent that
says where the point sits, and hand both to a new `_f64_scale10`
(`coreasm/x86_64/float.asm:440`) that places the point in a **single**
rounding. The scaling is done on the x87 stack rather than in SSE,
because x87 can be told how wide to round: `fild` loads any mantissa
below 2^63 exactly, the powers of ten up to 10^22 are exact doubles that
`fld` widens without loss, and with the precision-control field set to a
53-bit significand the one `fmul`/`fdiv` rounds straight to what a double
can hold — so the qword store afterwards is exact and the whole
conversion has rounded once. That is the correctly-rounded result, bit
for bit what Rust's parser gives the same digits at compile time.
Nothing else in the compiler or the runtime uses the FPU, and the
caller's control word is restored before returning.

The window it covers — up to 18 significant digits with the point within
22 places — is wider than a `float` can tell apart (17 digits round-trip
a double). Digits past the eighteenth are dropped, and a dropped digit
left of the point still counts towards the exponent, so the magnitude
survives what the old accumulator used to corrupt. Past the window the
point is walked in strides of 10^22 with the precision control left at
the full 64-bit significand, which keeps eleven spare bits under the
answer and leaves the final store to do the rounding that matters.

**Measured, on the twelve rows the report listed plus the headline:**

| text | before, `{:.17}` | the literal | after |
|---|---|---|---|
| `"0.07"` | 0.06999999999999999 | 0.07000000000000001 | agrees |
| `"0.11"` | 0.11000000000000001 | 0.11000000000000000 | agrees |
| `"0.14"` | 0.13999999999999999 | 0.14000000000000001 | agrees |
| `"0.17"` | 0.16999999999999998 | 0.17000000000000001 | agrees |
| `"0.21"` | 0.21000000000000002 | 0.20999999999999999 | agrees |
| `"0.22"` | 0.22000000000000003 | 0.22000000000000000 | agrees |
| `"0.23"` | 0.22999999999999998 | 0.23000000000000001 | agrees |
| `"0.28"` | 0.27999999999999997 | 0.28000000000000003 | agrees |
| `"0.33"` | 0.32999999999999996 | 0.33000000000000002 | agrees |
| `"0.34"` | 0.33999999999999997 | 0.34000000000000002 | agrees |
| `"0.42"` | 0.42000000000000004 | 0.41999999999999998 | agrees |
| `"0.44"` | 0.44000000000000006 | 0.44000000000000000 | agrees |
| `"0.88"` | 0.88000000000000012 | 0.88000000000000000 | agrees |

**And in bulk**, both routines driven directly from a C harness against
glibc's `strtod`, which is correctly rounded:

| corpus | before | after |
|---|---|---|
| 817,466 decimals of ≤ 18 significant digits (every two-decimal value below 100, every three-decimal value below 10, and 800,000 random ones, half of them negative) | **183,534 wrong**, up to 6 ulp | **0 wrong** |
| 200,000 decimals of 19–30 significant digits and points up to 60 places away | **143,344 wrong**, to the point of sign inversion | **799 wrong**, never more than 1 ulp |

The 799 are the truncation residue: every one has 21 or more significant
digits, well past what a double distinguishes, and each is one ulp from
the correctly-rounded answer rather than a corrupted one.

**Family.** #34 — a float *formatter* routed through an i64 — is the
nearest neighbour; this is the float *parser*, and the shape it shares
with #34 is a runtime numeric routine reaching for the cheap integer
arithmetic that is right for a number and wrong for a double. #60's
`{f:.N}` corruption is the same file from the other end. The
uninitialised-result half is the shape of #58's silent re-type: a path
out of a routine that skips the write everyone downstream assumes
happened.

**Not changed, deliberately.** `-0` still parses to `+0.0` (the sign is
applied as `0.0 - x`, and `0.0 - 0.0` is `+0.0`); that is exactly what
the old routine did, it is unrelated to the rounding, and glibc's
disagreement with it is the only difference left in the ≤ 18-digit
corpus. Exponent notation (`"1e5"`) is still not accepted by either
parser — it never was, and adding it is a feature, not this fix.


---

### 83. `not` binds to a primary, so `If not v1 is v2 then,` compiles as `(not v1) is v2` and the guard never fires — no spelling of `not <comparison>` exists

**Status:** **fixed in 0.4.10**.
Severity: **wrong condition, silent** — the guard compiles, runs, and is
false whatever the operands, so a program that means "if these differ"
takes the other branch forever with no diagnostic anywhere.
Regression tests: `tests/492_not_takes_the_whole_comparison.vox` (the
repro rows), `tests/493_not_before_a_comparison_in_every_slot.vox` (every
condition position — both operands of `and`, the left of `or`, `but if`,
a guarded `print`, a plural-subject `are`, a returned condition and a
`While` header), and `tests/494_is_not_and_not_a_boolean_unchanged.vox`,
a control that pins the three spellings which were already right.
Found by the vox-fuzz claim ledger: row **OPR-21** (`not <condition>`)
was left deliberately unexercised by the `gen_core` derandomisation sweep
because "emitting `If not <comparison>` would put a construct in every
program whose meaning nobody has blessed"
(`vox-notes/REPORT-SWEEP-CORE.md`, discrepancy **D-B**, 2026-08-21);
adjudicated as candidate **M** of
`vox-notes/REPORT-CANDIDATES-ROUND-3.md` (candidate audit, 2026-08-22)
and master-reproduced on 0.4.9.

```vox
a number called v1 is 3.
a number called v2 is 6.
If not v1 is v2 then, Print "fires". Otherwise, Print "silent".
```
→ prints **`silent`**. So does the same program with `v2 is 3`, and with
every other pair: `not v1` is `0` for any non-zero `v1`, and `0 is v2` is
false for any non-zero `v2`.

**The matrix, each row its own program, measured on this branch's parent
(4b77934 = v0.4.9) and on the fix:**

| condition | before | after |
|---|---|---|
| `not heat is limit` (3, 6) | silent | **fires** |
| `not heat is depth` (3, 3) | silent | silent |
| `not heat is greater than 5` (3) | silent | **fires** |
| `not readings is empty` (empty list) | fires | **silent** |
| `not heat is even` (3) | fires | fires |
| `heat is 3 and not limit is 5` | silent | **fires** |
| `not heat is 4 and limit is 6` | silent | **fires** |
| `not heat is 4 or limit is 99` | silent | **fires** |
| `not not heat is limit` | silent | silent |
| `But if not heat is limit then,` | silent | **fires** |
| `Print "d", but if not heat is limit print "g".` | `d` | **`g`** |
| `not door_open, alarm_armed, and door_open are true` | silent | **fires** |
| `Return a boolean, not temperature is greater than 10.` | silent | **fires** |
| `While not tick is greater than 5,` (tick 3) | 0 iterations | **3 iterations** |
| `heat is not limit` (control) | fires | fires |
| `heat is not greater than 5` (control) | fires | fires |
| `readings is not empty` (control) | silent | silent |
| `If not door_open then,` on a boolean (control) | fires | fires |
| `Print not door_open.` (control) | `1` | `1` |
| `a boolean called door_shut is not door_open.` (control) | `1` | `1` |

Row 4 is the decisive one: it is the only row where the two readings give
*opposite* answers rather than one of them being accidentally right.
`not heat is even` agrees under either binding, which is why a property
check never exposed this.

**Which reading the manual supports.** The clause reading, on three
independent statements:

1. **LANGUAGE.md's Logical Operators fence** writes the three operators
   in parallel, and every operand slot is spelled `<condition>`:
   `<condition> and <condition>`, `<condition> or <condition>`,
   `not <condition>`. `and` and `or` demonstrably take whole comparisons
   — `If v1 is 3 and v2 is 6 then,` fires — so `<condition>` in the third
   line means what it means in the first two.
2. **The Comparisons table** makes `v1 is v2` a comparison, which is
   exactly what that `<condition>` slot then holds.
3. **The stated goal of the language.** English `not` takes scope over
   the clause it precedes: "if not v1 is v2" is heard as "if it is not
   the case that v1 is v2", never as "if the negation of v1 equals v2".
   A reader cannot arrive at the primary binding unaided, and the manual
   never gave them anything to arrive at it from.

**The strongest reading in which the compiler was correct, and why it
fails.** The grammar summary gives `expr ::= or_expr`, `or_expr`,
`and_expr`, `comparison`, down to `primary`, and **`not` appears nowhere
in it**. Insert it at the primary level — which is where the
implementation had it — and the summary is internally consistent; a unary
operator over a primary is the ordinary C-family precedence, and the
manual never stated another. Two things kill it:

- The summary uses the nonterminal `condition` in `if_stmt` and
  `while_stmt` and **never defines it**. A grammar that does not define
  the nonterminal in question cannot settle a question about it.
- The mis-parse was only *reachable* because `not` silently accepts a
  number: `Print not v1.` prints `0` for `v1 = 20`. If `not` took
  conditions, as the fence says, `not v1` on a number would be a type
  error and `not v1 is v2` would have failed to compile rather than
  silently evaluating `(not v1) is v2`. The compiler was not choosing a
  precedence; it was falling through a hole. (That permissiveness is its
  own entry and is deliberately untouched here — see "Not in scope".)

And the deciding practical fact: **`not <comparison>` had no working
spelling at all.** `If not {v1 is v2} then,` does not parse
(`error: Expected a statement, got CloseBrace`), because a brace group
takes an expression and a comparison lives above it. There was no way to
write the thing the manual documents.

**Mechanism.** `not` existed only as a `Token::Not` arm inside
`parse_primary` (`src/parser/expressions.rs`), which recursed into
`parse_primary` — so it consumed one primary and stopped. `parse_comparison`
then took that `Not(v1)` as its left operand and read `is v2` on top of
it. The precedence chain had no level for `not` between `and` and
`comparison`, which is the level the manual's fence describes. Same family
as **#50** (a chain-continuation keyword the parser's guard simply never
listed) — a construct the manual documents that the grammar has no
production for — and the mirror image of **#64**, where two spellings of
one thing disagreed because only one had a parse path.

**The fix — one new level in the precedence chain.**
`parse_not_expr` (`src/parser/expressions.rs`) sits between `parse_and_expr`
and `parse_comparison`: it claims a leading `Token::Not`, recurses on
itself so `not not X` cancels, and otherwise falls straight through to
`parse_comparison`. `parse_and_expr` now calls it for **both** operands of
`and`, so a `not` on the right of an `and` reads the same as one on the
left — putting the claim inside `parse_and_expr` itself would have fixed
only the leading position. `or` inherits it through `and_expr`, and every
condition site (`If`, `When`, `While`, `but if`, a guarded `print`, a
typed or untyped `Return`, and the format-string sub-parser, which enters
at `parse_and_expr`) inherits it through `parse_condition`.

The `parse_primary` arm **stays**. It is what `not` in value position
reads through — `Print not door_open.`, `a boolean called door_shut is
not door_open.` — and it was already right; the two do not overlap,
because `parse_not_expr` has consumed any leading `not` before
`parse_primary` is reached.

**The manual line.** LANGUAGE.md now states the precedence next to the
fence that documents `not` ("`not` takes the whole condition after it …
binds looser than every comparison and property check, and tighter than
`and` and `or`"), and the grammar summary gains the two productions it was
missing — `and_expr ::= not_expr ("and" not_expr)*`,
`not_expr ::= "not" not_expr | comparison` — plus `condition ::= expr`,
the nonterminal `if_stmt` and `while_stmt` had been using undefined. No
behaviour is promised that the fix does not deliver.

**Not in scope, noticed on the way.**

- **`not` accepts any type, not just a condition.** `Print not v1.` on a
  number answers `0`/`1` (unchanged by this fix, which does not touch the
  value path), and on a text, list or map it segfaults — the round-3
  audit's incidental **T-1**, filed separately. Typing `not` is what
  would have made this bug a compile error instead of a wrong answer, but
  it is a behaviour change of its own with its own blast radius.
- **A brace group still cannot hold a comparison.** `If not {v1 is v2}
  then,` is the same parse error before and after. It no longer matters
  for `not`, which now has a working spelling without braces, but
  `{a is b}` as a groupable condition remains unimplemented and
  undocumented.


---

### 84. `isn't` and `aren't` — documented spellings of `not` at LANGUAGE.md:4662 — can never be lexed: `read_word` stops at the apostrophe, so six keyword-table entries are dead code

**Status:** **fixed** in 0.4.10 (this branch). Severity: **diagnostic —
rejects documented Vox**. Nothing silent and nothing unsafe: the program is
refused, loudly and with the caret in the right column, for a reason the
manual says is not a reason. Found by the vox-fuzz **operators** claim
ledger — rows `OPR-22` and `OPR-23`, both recorded *not assertable, blocked
on* its **Discrepancy 1** (probe `docs/ledger/probes/operators/D1.vox`) —
re-confirmed byte-identical on 0.4.9 by the core sweep
(`REPORT-SWEEP-CORE.md`, D-C) and adjudicated in the candidate audit of
2026-08-22 (`REPORT-CANDIDATES-ROUND-3.md` §N). Regression tests:
`tests/502_contraction_isnt.vox`, `tests/503_contraction_arent.vox`,
`tests/504_apostrophe_meanings_unchanged.vox`, four compile-fail cases
`tests/compile_fail/contraction_*.vox`, and six lexer unit tests in
`src/lexer/tests.rs`.

```vox
a number called v1 is 20.
a number called v2 is 6.
If v1 isn't v2 then, Print "differ". Otherwise, Print "same".
```
→ `error: Expected a statement, got Apostrophe`, caret on the apostrophe.
The same sentence spelled out — `If v1 is not v2 then,` — prints `differ`.

**The intent was in the compiler and the word never reached it.** The
keyword table at `src/lexer/scan.rs` claimed six contractions:

```rust
"is" | "it's"   => Token::Is,
"are" | "they're" => Token::Are,
"not" | "isn't" | "aren't" | "doesn't" | "don't" => Token::Not,
```

`read_word` accumulates only `is_alphanumeric() || '_' || '-'`, so it stops
dead at `'` and can never produce a word containing one. No input could
reach any of those six arms. The scanner's `'` arm then took the apostrophe
as one of its three real meanings — character literal, quoted name, or the
`'s` possessive marker — and the parser met a bare `Apostrophe` where a
statement belonged.

**The six, before and after:**

| spelling | table entry | in the manual? | before | after |
|---|---|---|---|---|
| `isn't` | → `Token::Not` | **yes, :4662** | *Expected a statement, got Apostrophe* | **compiles**, as `is not` |
| `aren't` | → `Token::Not` | **yes, :4662** | *…got Apostrophe* | **compiles**, as `are not` |
| `doesn't` | → `Token::Not` | no | *…got Apostrophe* | entry removed; still refused |
| `don't` | → `Token::Not` | no | *…got Apostrophe* | entry removed; still refused |
| `it's` | → `Token::Is` | no | *…got Apostrophe* | entry removed; still refused |
| `they're` | → `Token::Are` | no | *…got Apostrophe* | entry removed; still refused |

**The fix is one look-ahead in `read_word`, and it had to produce two
tokens.** `isn't` means `is not`, and `parse_comparison`
(`src/parser/expressions.rs`) reads `Is`/`Are` and *then* an optional
`Not`. Reaching the old table would have produced a lone `Token::Not`,
which does not parse and never did — `If v1 not v2 then,` is
`error: Expected a statement, got Not` before this fix and after it. So
`read_word` now consumes the `'t` of a complete contraction and returns
`Is`/`Are`, leaving the `Not` for `tokenize` to push behind it; both halves
carry the contraction's own line and column, so a caret under either lands
on the word the author wrote. A contraction is the one apostrophe that
falls *inside* a word already in progress — the character literal, the
quoted name and the `'s` possessive all begin where no word is being read —
so the rule cannot take a byte from any of them.

**Why only the two the manual documents.** Waking the table wholesale would
have brought four undocumented spellings to life at once, and two of them
take working code away: `it` and `they` are ordinary identifiers, so
`print it's length.` is the possessive on a variable called `it` and prints
a length today. The rule therefore admits `isn't` and `aren't` and nothing
else, and the four unreachable entries were deleted rather than woken —
a table that lies is what caused this entry. `tests/504_*` pins the
possessives, and the four `tests/compile_fail/contraction_*` cases pin the
refusals, so neither half can drift back.

**Family: a table the lexer cannot reach.** Same shape as **#64**, where
the parser had two possessive property sites that knew different languages
and one of them silently implemented almost nothing — an internal list that
does not match the manual it was written from. The diagnostic class is
#45/#62/#63's: a refusal whose message names the token it tripped over and
not the construct the author was writing. Here the right answer was to
accept the construct, so no new diagnostic was added; the message for the
four undocumented spellings is unchanged.

**Not in scope, noticed on the way.** A stray apostrophe inside a word can
silently swallow a *later* quoted name on the same line, and the caret then
lands 30 columns from the mistake:

```vox
a number called v1 is 20.
a text called 'a long name' is "hi".
If v1 don't v2 then, print 'a long name'. Otherwise, print "no".
```
→ `error: Expected a statement, got Apostrophe` at **3:40**, the closing
quote of `'a long name'` — because `is_single_quoted_identifier` scans to
the next `'` on the line and reads `t v2 then, print ` as a name. The real
mistake is at 3:10. Identical before and after this fix, which does not
touch that path. It is the diagnostic half of this family and wants its own
entry: a word interrupted by an apostrophe that completes no contraction
and is not the possessive is always an error, and the lexer knows it at the
apostrophe.



---

### 85. A width and a precision written together silently drop both — `{f:8.2}` prints `2.5` while `{f:.2}` prints `2.50`; and the manual never said whether `N.M` composes

**Status:** **fixed in 0.4.10**. Severity: **wrong value, silent** — a
specifier that works on its own is destroyed by writing a second one beside
it, with no diagnostic anywhere. Regression test:
`tests/521_a_width_or_a_precision_never_both.vox`, plus three codegen unit
tests over `read_format_spec`. Found by the vox-fuzz seed sweep, whose
`gen_text.vox` emits `{name:W.P}` specs.

```vox
a float called f is 2.5.
Print "[{f:8.2}]".        (was: [2.5]   - neither half)
Print "[{f:.2}]".         (        [2.50]  - the precision alone works)
a number called n is 255.
Print "[{n:8.2}]".        (was: [     255] - the width honoured, places gone)
```

**Root cause.** `read_format_spec` (`src/codegen/format.rs`) consumed the
width, leaving `.2` in `remaining`. That matched none of the base specifiers
(`x`, `X`, `b`, `o`), so it fell to their catch-all, which sets the base to
decimal and returns — and `precision` was never assigned. Writing a width
destroyed a precision, and on a float the width was not applied either
(#36's residue), so `{f:8.2}` came out as neither.

**The fix — both halves are read, and both are kept.** They compose under
the rule #71 already states for the width: *"the width is the one exception
— it applies to any value and is ignored where no padding exists for that
type yet"*. So the precision decides the digits and the width decides the
padding, and each is honoured wherever a primitive for it exists:

| spec | value | renders | why |
|---|---|---|---|
| `{n:8.2}` | `a number called n is 255.` | `  255.00` | both: digits padded so the whole rendering is 8 wide |
| `{n:08.2}` | the same | `00255.00` | a zero-pad is a width and composes the same way |
| `{f:8.2}` | `a float called f is 2.5.` | `2.50` | the places print; there is no float padder, so the width is dropped — as a bare `{f:8}` already dropped it |
| `{t:8.2}` | a `text` | refused | #71's check: a text has no decimal expansion. Untouched by this entry |

The padding arithmetic is the same in every sink: a rendering of
`<digits>.<zeros>` is the digit count plus one plus the precision, so
padding the DIGITS out to `width - 1 - precision` brings the whole to
exactly `width`. `emit_formatted_value` (Print) and
`emit_append_int_with_decimal_places` (the buffer sinks) each do that, so a
hole renders the same in a `Print`, a text initializer and a buffer.

**Why honoured and not refused.** The first cut of this fix refused the pair
with a diagnostic naming both halves. That was wrong twice over: it
contradicts #71's own sentence, now in LANGUAGE.md, that a width "applies to
any value and is ignored where no padding exists for that type yet" — a
width beside a precision is that same case, not a new one — and it turned
roughly a quarter of the vox-fuzz generator's legal-looking programs into
compile errors (73 of 300 seeds), for a spelling every reader would expect
to work. A count past `FORMAT_MAX_COUNT` on either half is still a fault
(#61's rule, unchanged), and a specifier asked of a type that cannot answer
it at all is still refused (#71's check, unchanged).

**LANGUAGE.md.** The "Format Specifiers" section never said whether `N.M`
composes. It now states the rule and both worked examples.

### 86. A float's precision is dropped by every sink but `Print` — `copy "{ratio:.2}" to b` and `write "{ratio:.2}"` give `2.5` where `Print` gives `2.50`

**Status:** **fixed in 0.4.10** (unreleased, on top of 0.4.9). Regression
tests `tests/486_float_precision_in_every_sink.vox`,
`tests/487_float_precision_matches_print_in_a_buffer.vox` and
`tests/488_float_without_a_precision_in_every_sink.vox`, plus three codegen
cases in `src/codegen/tests.rs`
(`a_float_precision_in_a_text_initializer_carries_its_places`,
`a_float_precision_in_every_buffer_sink_carries_its_places`,
`a_float_precision_in_a_buffer_asks_for_the_render_writers`,
`a_float_without_a_precision_still_appends_directly`). 425 and 426 and the
first two unit tests were proven to fail on clean `main` (4b77934) and to
pass after; 427 and `a_float_without_a_precision_still_appends_directly` —
the working neighbour — pass on both. Found
2026-08-21 by the vox-fuzz claim ledger / candidate audit (recorded as #71's
incidental, where it was named for the buffer sinks only), adjudicated by
the language lawyer as candidate **Q** and master-reproduced on this branch.

```vox
a float called ratio is 2.5.
Print "print   : {ratio:.2}".
a text called t is "text    : {ratio:.2}".
Print t.
Create a buffer called b.
copy "buffer  : {ratio:.2}" to b.
Print b.
Open a file for writing called out at "qout.txt".
write "file    : {ratio:.2}\n" to out.
Close out.
```

```
print   : 2.50
text    : 2.5     (wrong)
buffer  : 2.5     (wrong)
file    : 2.5     (wrong)
```

**Every sink, not just the buffer ones.** The incidental that recorded this
named `copy`/`set`/`append`; it is every sink the manual lists, including
the one it names explicitly — a file.

| sink | `{ratio:.2}` before |
|---|---|
| `Print "…"` | `2.50` ✓ |
| `a text called t is "…"` | `2.5` ✗ |
| `copy "…" to b` | `2.5` ✗ |
| `set b to "…"` | `2.5` ✗ |
| `append "…" to b` | `2.5` ✗ |
| `write "…" to <file>` | `2.5` ✗ |
| a function argument | `2.5` ✗ |

**And exactly one arm wide.** Every other specifier already kept parity —
measured, not assumed:

```
print : [0xff] [000255] [0o377] [11111111]
text  : [0xff] [000255] [0o377] [11111111]
buffer: [0xff] [000255] [0o377] [11111111]
```

Radix (`x`, `o`, `b`) and integer width (`06`) are identical in all three,
and so is a float with no specifier at all (`2.5`, `-1.25`, `3.0`). Only the
float-precision arm broke, which is why the fix adds a branch rather than
rerouting the default rendering.

**What the manual promises.** LANGUAGE.md "Format Strings Everywhere" —
"All sinks share one name resolver, so special names like `{arguments's
first}` and `{current time's hour}`, **format specifiers**, and the
`0x`/`0o` hex/octal prefixes **render identically whether the result is
printed, written to a file, or built into a** text or a **buffer**." The
strongest reading in which the compiler is right is that the sentence's
subject is the *name resolver*, so it promises only that names *resolve* the
same everywhere. That reading does not survive the sentence's own list:
"format specifiers" is a separate item, coordinate with "special names" and
with the `0x`/`0o` prefixes, and the verb governing all three is "render
identically". Nor does it survive the compiler's own behaviour, which kept
the promise for every specifier but this one — a shared resolver that
renders radix and width identically in every sink and precision only in
`Print` is not implementing a narrower promise, it is missing an arm. The
specifier table (`{var:.N}` | N decimal places) and the sentence below it
("`{var:.N}` prints exactly `N` decimal places") carry no sink restriction
either.

**Severity: a wrong value, silently.** A program writing `{price:.2}` to a
receipt file gets `2.5` where the same line shown on the terminal reads
`2.50`. Nothing is diagnosed, and the two disagree in the one place a
program is least likely to look.

**Root cause.** `src/codegen/buffers.rs`, the `Some(VarType::Float)` arm of
`emit_append_runtime_value_to_buffer_ptr` — the one point every non-`Print`
sink funnels through — emitted `call _buffer_append_float`, and
`_buffer_append_float` (`coreasm/x86_64/float.asm`) takes the destination
and the raw bits and nothing else: there was no precision argument to pass
and no routine to pass it to. `Print` goes through `emit_formatted_value`
(`src/codegen/format.rs`), which has had a precision arm calling
`_print_float_precision` all along. The spec was parsed correctly in both
paths; it was dropped on the floor in one of them.

**The fix**, in #44's shape — one renderer, redirected, never a second copy.
#44 gave `{list}`/`{map}` sink parity by pointing `_render_sink` at the
destination buffer and calling the very routine `Print` calls; the same move
works here:

- `coreasm/x86_64/format.asm` — `_fmt_write_all`, the single writer every
  byte of `_print_float_precision` goes out through (digits, point and pad
  alike), now consults `_render_sink`: zero means stdout, instruction for
  instruction as before; a buffer pointer means the same bytes are appended
  there, via `_render_bytes`. Gated on `__RESOURCE_ASM_INCLUDED__` and
  `__IO_ASM_INCLUDED__` — where `_render_bytes` lives, and behind which
  guard — the idiom io.asm's `RENDER_*` macros already use.
- `coreasm/x86_64/format.asm` — new `_buffer_append_float_precision`: saves
  the sink, points it at the destination, calls `_print_float_precision`,
  restores, and answers with the (possibly reallocated) buffer. Its argument
  and return contract is deliberately `_buffer_append_float`'s and
  `_list_render_to_buffer`'s, so the codegen arm sits beside theirs as an
  equal.
- `src/codegen/buffers.rs` — the float arm emits `mov rsi, N` +
  `call _buffer_append_float_precision` when a precision was written, and is
  otherwise untouched. It sets `uses_format` (format.asm holds the printer)
  and `uses_io` (io.asm guards the render-sink writers), the way `uses_maps`
  already forces io.asm on. A program that builds `{ratio:.2}` into a buffer
  and never prints has no other reason to include io.asm, and without that
  flag it did not assemble at all — `symbol _render_bytes not defined`. That
  case is pinned by the unit test
  `a_float_precision_in_a_buffer_asks_for_the_render_writers`.

Because it is a redirection and not a reimplementation, everything the
precision printer knows arrives with it in every sink: the exact decimal
expansion, round-half-to-even on a tie, the carry that lengthens the integer
part, and the magnitudes at or beyond 2^63 that #60 was about. Test 426
pins that by rendering the same value twice, through `Print` and through a
buffer, and requiring the two lines to match — including at 400 places,
which reallocates the destination part-way through the render.

**Family.** Sink parity: #44 (`{list}`/`{map}` renders correctly only in
`Print` position), #52 (a text-valued special name built into a buffer
segfaults), #59 (a `treating` clause on a mixed-list loop variable prints a
pointer). Same shape, one arm over. #60 is the neighbour whose work this
now carries into every sink; #61 is the pad-width twin in the same file.

**LANGUAGE.md.** The promise sentence named only "printed, written to a
file, or built into a buffer", though a text initializer is a sink too (it
is documented as one a paragraph earlier, under "Format Strings as
Values"). Tightened to "or built into a text or a buffer", with the
precision spelled out as the example. No behaviour is promised that the
compiler does not now do.


---

### 87. A buffer in a `value` carries its struct pointer, not its bytes — `a value called carried is made.` prints an empty line, or the capacity byte (`@` at 64 bytes)

**Status:** **fixed** (this branch, for 0.4.10). Severity: **wrong value,
silent** — no error flag, no diagnostic, and the `type` property actively
misreports the payload it is sitting on. Found 2026-08-22 by the round-3
candidate audit (`REPORT-CANDIDATES-ROUND-3.md`, section **S**), which took
the claim from the #67 fixer's incidental — #67's own position table left
the `a value called c is <call>.` row for a buffer unfilled, and that hole
was the bug. It is **not** attributable to a vox-fuzz ledger row: the audit
names no ledger for **S**, and this entry does not invent one. The headline
repro was re-run by the master on `4b77934` (= 0.4.9) before this branch
opened. Byte-identical on 0.4.8, so it is not a 0.4.9 regression.

Family: **#51 / #44** — a buffer's struct pointer used where its data
pointer belongs. This is #51's *identical* defect in the one family of
spellings #51's fix did not reach.

```vox
a buffer called made is "ABC".
a value called carried is made.
Print carried.
```

```
$ VOX_CORE_PATH=$PWD/coreasm target/release/vox S1.vox -o S1 && ./S1 | cat -A
$
```

An empty line. Also empty: `"{carried}"`, and `a text called back is
carried.`

**Proof it is the buffer's header and not memory noise — #51's own tell.**
Change only the declared size; the printed character tracks the capacity
field exactly, while the `text` beside it (which #51's fix repaired) is
correct at every size:

| declaration | `a value called carried is b.` → `Print carried` | `a text called t is b.` → `Print t` |
|---|---|---|
| `a buffer called b is 64 bytes in size.` | `@` (0x40 = 64) | `first` ✓ |
| `a buffer called b is 65 bytes in size.` | `A` (0x41 = 65) | `first` ✓ |
| `a buffer called b is 66 bytes in size.` | `B` (0x42 = 66) | `first` ✓ |

A *dynamic* buffer's capacity has a zero low byte, which is why the
headline repro prints an empty line rather than a character: the same
defect with a quieter symptom. A 32-byte buffer printed a single space
(0x20). There was never a case that did not read the header — only cases
whose header byte happened to be printable.

**Working neighbours, all correct before and after:** `a text called direct
is made.` → `ABC`; `a text called viacast is made as text.` → `ABC`;
`"{made}"` → `ABC`.

**The cause.** `vartype_to_tag` (`src/codegen/tags.rs:8-18`) maps
`VarType::String | VarType::Buffer => Some(TAG_STRING)`, so a buffer
written into a `value` is *tagged text* — and the program agrees out loud:

```
Print carried's type.                        (Text (dynamic))
If carried is a text then, ... Otherwise, ...   (takes the text branch)
```

Having declared the payload text, the compiler then stored the buffer's
**struct pointer** as that payload. A buffer is a struct whose 24-byte
header is `[capacity][length][flags]`, with the characters at
`struct + BUF_DATA_OFFSET`, so every later read — `Print`, a format hole,
a text initialised from the `value` — dereferenced the capacity field as a
C string. The tag was right; the payload never caught up with it.

**Why the "undefined territory" reading does not save it.** LANGUAGE.md's
`value` section enumerates the tags a `value` carries (`Text (dynamic)`,
`Number`, `Float`, `Boolean`, `List`, `Map`, `Nothing`) and the retype
targets (`number`, `float`/`decimal`, `text`, `boolean`); a buffer is in
neither list, so one could argue a buffer is simply not a `value` payload
and an empty line is as good as anything. That reading dies on the `type`
property and the predicate above. A compiler in undefined territory does
not answer `Text (dynamic)` and `is a text` → true. It had committed to an
answer; it just did not deliver it. Undefined behaviour that confidently
self-describes is not undefined behaviour, it is a wrong value.

And the manual reaches this case directly. LANGUAGE.md's Basic Conversions
table gives `buffer → text` one meaning — "a copy of the buffer's bytes" —
and the sentence under it says **the cast is optional for this one
conversion**: "Every spelling that puts a buffer into a slot that holds
text means the same thing and makes the same copy." By the compiler's own
tag and its own predicate, a `value` holding a buffer **is** a slot that
holds text, which puts it squarely inside "every spelling".

**The ruling was already made.** #51 was adjudicated by the language
designer (TheJostler, 2026-08-21): *"option 1, copy: helpful by default —
the bare spelling means what `as text` means and what `"{b}"` has meant
since v0.1.17."* That ruling answers this case; it was simply not carried
to the `value` path. No new decision was needed here, and none was taken.

**The sibling write sites, all of which had the same defect.** As with #51,
the register found the declaration and the fix worker found the rest. Every
one of the five stored the struct pointer; all five print `@` before and
`first` after, with a 64-byte buffer holding `"first"`:

| spelling | before | after |
|---|---|---|
| `a value called v is b.` | `@` | `first` |
| `a value called v is 'a buffer-returning call'.` | `@` | `first` |
| `Set v to b.` | `@` | `first` |
| `the v is b.` | `@` | `first` |
| `'show it' with b.` (a `value` parameter) | `@` | `first` |
| `Return a value, b.` | `@` | `first` |

(Six rows, five sites: the two declaration spellings are one site.)

**Fix.** No new copy sequence: every site now routes through
`generate_expr_as_text` (`src/codegen/buffers.rs:318`), the thin wrapper
#51 added over `emit_buffer_to_text_copy` (`:256`) — generate the
expression, and if it is a buffer, copy the bytes into a fresh dynamic
buffer the exit cleanup already tracks. The wrapper converts *only* a
buffer, so every other `value` payload reaches its slot untouched. The
change is one widened condition per site:

- `Statement::VarDecl` — `src/codegen/statements.rs:665`, now
  `is_text_target || is_value_var` (the declaration, and `Set v to b.`,
  which parses to `VarDecl` with no declared type of its own).
- `Statement::Assignment` — `:846` (local slot) and `:890` (global
  mirror), now matching `VarType::String | VarType::Mixed` (`the v is b.`).
- `Statement::Return` — `:1149`, now `Some(Type::String) ||
  Some(Type::Value)`. A copy is the only safe thing to return anyway: a
  buffer local to the callee's frame does not outlive it.
- `emit_function_call` — `src/codegen/functions.rs:83`, now
  `is_text_param(i) || is_value_param(i)`, so the payload word matches the
  `TAG_STRING` word pushed beside it.

The tag half is untouched at every site — it was already right — and
`emit_load_value_tag`'s register discipline is preserved: the copy runs
*before* the tag is loaded into r11 at every site, so nothing clobbers it.

**Independence, the #41 half.** The copy makes the `value` its own text,
not a window onto the buffer: clearing and refilling the source leaves the
`value` as it was, and *resizing* the source — which frees the old
allocation — no longer leaves the `value` pointing at freed memory. This is
why #51 fixed `as text` by copying rather than by adding an offset, and the
same reasoning carries here. A buffer flowing into a `value` is a
**conversion, not a retype**: the name is still a `value` afterwards, and
`snapshot's type` still answers `Text (dynamic)`.

**LANGUAGE.md.** Two sentences tightened, no feature added. The "cast is
optional for this one conversion" paragraph now names the `value` slot
among the spellings that make the copy, and the `type`-property paragraph
now says its seven tags are the whole list and that a buffer put into a
`value` arrives as text. Both describe what the compiler now does; neither
grants a `value` a `Buffer (dynamic)` tag, which does not exist.

**Tests.** `tests/489_value_from_buffer_copies.vox` (the register's repro
at 64 and 65 bytes, so the old answer's dependence on the capacity field is
what fails; the dynamic-buffer headline repro; the `as text` and `"{b}"`
controls; an empty buffer, which must give empty text rather than a header
read; and the `type`/predicate agreement),
`488_value_from_buffer_at_every_write_site.vox` (the six rows above), and
`489_value_from_buffer_is_an_independent_copy.vox` (#41's class through
this spelling: clear-and-refill, then resize, plus the type check and a
frame-local copy inside a function). All three fail on `4b77934`; 487's
failure diff shows `@` then `A` where `first` belongs, which is the
capacity tell in the test output itself. (Test numbers: the next free
number at `4b77934` is 425, but eleven parallel fix branches have all
claimed 425 upward from the same commit, so this entry takes the free 487
block to keep the merge from being an add/add conflict on identical
filenames.)

**Not fixed here, and not this entry.** `append <buffer call> to <list>`
stores a raw heap address (`140216441348096`) — a different predicate
(`Statement::ListAppend`'s `is_buffer_value`, which matches only an
identifier), which is why `append <buffer variable> to <list>` is correct.
That is #67's incidental 2 and has its own entry; nothing here touches it.


---

### 88. `Print not <text | list | map>` segfaults — `infer_expr_type` and `is_float_expr` return a unary `not`'s OPERAND type, while `is_boolean_expr` twelve lines away and the declaration path both correctly call it a boolean

**Status:** **Fixed in 0.4.10.** Severity: **memory safety** — a
deterministic segfault from two lines of legal-looking Vox, with no
diagnostic and no error flag. Found 2026-08-21 by the vox-fuzz claim
ledger / candidate audit (round 3, candidate **T-1**), met while probing
the `not`-precedence candidate's "does `not` accept a non-boolean"
control; adjudicated and master-reproduced on 0.4.9 (4b77934).

```vox
a text called t is "hi".
Print not t.
```
→ **segfault (139)**, deterministic, no output at all.

**The matrix, each case its own program, measured on a clean extract of
0.4.9 (4b77934) and on the fix:**

| program | before | after |
|---|---|---|
| `a text called t is "hi".` + `Print not t.` | **139** | `0` |
| `a text called t is "".` + `Print not t.` | **139** | `0` |
| `a list called xs is [1, 2, 3].` + `Print not xs.` | prints `[`, then **139** | `0` |
| `a list called xs is [].` + `Print not xs.` | prints `[`, then **139** | `0` |
| `a map called m is {"a": 1}.` + `Print not m.` | prints `{`, then **139** | `0` |
| `a float called f is 2.5.` + `Print not f.` | prints `0.0` — a *float*, where a boolean belongs | `0` |
| `a text called t is "hi".` + `Print "{not t}".` | **139** | `0` |
| `a value called payload is "hi".` + `Print not payload.` (control) | `0` | `0` |
| `a list called mixed is [1, "two", 3.5].` + `Print not element 2 of mixed.` (control) | `0` | `0` |
| `a buffer called bf is 16 bytes in size.` + `Print not bf.` (control) | `0` — safe by accident | `0` |
| `a number called v is 20.` + `Print not v.` (control) | `0` | `0` |
| `a number called n is 0.` + `Print not n.` (control) | `1` | `1` |
| `a boolean called b is true.` + `Print not b.` (control) | `0` | `0` |
| `if not t, print "fired", otherwise print "silent".` (control) | `silent` | `silent` |
| `if t is not empty, ...` (control) | `not empty` | `not empty` |
| `a number called r is not t.` (control) | rejected, "with a boolean" | rejected, "with a boolean" |
| `a float called f is 2.5.` + `Print -f.` (control) | `-2.5` | `-2.5` |
| `To 'flip' with a float called ratio. Return a float, -ratio.` (control) | `-2.5` | `-2.5` |

Only `Print` position — and format-string interpolation, which is the same
sink — was unsafe, and only where the operand's type is known statically. A
`value` and a mixed-list element were already safe: `infer_expr_type` answers
`None` for both, so `Print` falls back to the runtime tag `generate_expr`
leaves in `r11` — and `emit_time_expr_tag` (`src/codegen/tags.rs:335`) has
tagged a `not` `TAG_BOOLEAN` all along. The bug was reachable exactly where
the wrong static answer was available to believe.

**Root cause**, two predicates in `src/codegen/expr.rs`:

```rust
// :51   — is_float_expr
Expr::UnaryOp { operand, .. } => self.is_float_expr(operand),
// :2477 — infer_expr_type
Expr::UnaryOp { operand, .. } => self.infer_expr_type(operand),
```

Both returned the **operand's** type for *both* `Negate` and `Not`. For
`Negate` that is right — `-x` really does have `x`'s type. For `Not` it is
wrong: the result is always a boolean. `Print` consults `infer_expr_type`,
was told "text", and emitted a text print of a value that is a boolean 0 —
dereferencing address 0. A list or a map got as far as printing its opening
bracket first, because the collection printers write the delimiter before
they walk what they think is a header.

**The rule was already written down, three times, and simply not applied
here.** `is_boolean_expr`, twelve lines below the first site in the same
file, has `Expr::UnaryOp { op: UnaryOperator::Not, .. } => true`.
`prescan_expr_tag` in `src/codegen/tags.rs:126` spells it out in words —
*"Logical negation is always a boolean, regardless of the operand's type
(`not 5` is a boolean) … Other unary ops (e.g. arithmetic negation) keep
the operand's tag"* — and `emit_time_expr_tag` at :335 agrees. The analyzer
agrees twice more (`src/analyzer/types.rs:84` and `:448`, both
`UnaryOperator::Not => Some(Type::Boolean)`), which is why the declaration
path refuses `a number called r is not t.` with *"cannot initialise 'r',
which is a number, with a boolean"* — the compiler naming the correct type
of the very expression it elsewhere dereferenced as text. `is_float_expr`'s
own `BinaryOp` arm, twelve lines above the first site, states the same
distinction for `and` and `or`: *"Comparison and boolean operators return
integers, not floats"*.

**Fix:** one match arm added ahead of each of the two, leaving the existing
arm to keep serving `Negate`:

```rust
Expr::UnaryOp { op: UnaryOperator::Not, .. } => false,               // is_float_expr
Expr::UnaryOp { op: UnaryOperator::Not, .. } => Some(VarType::Integer), // infer_expr_type
```

`VarType::Integer` is the convention `infer_expr_type` already uses for
every boolean-valued expression in the same function — `BoolLit`,
`TypeCheck`, and each comparison operator. No analyzer, parser or runtime
change; nothing outside these two arms is touched.

**Why not a diagnostic.** The alternative reading — that `not` takes a
`<condition>` (LANGUAGE.md:1890) and a bare text is not one, so
`not <text>` should be refused the way `-t` and `t add 1` already are
(LANGUAGE.md:1832) — was considered and rejected. It would contradict five
sites that deliberately record `not` as boolean *whatever its operand*,
including `tags.rs`'s explicit `not 5`; and it would break `if not t`,
which compiles and behaves today. The defect reported here is a type
error, and the type fix closes every row above.

**What this fix does NOT decide.** On a text, list, map or buffer, `not`
tests the value's *pointer*, which a declared variable always has — so
`not ""` and `not []` both answer `0`, exactly the shape #33 fixed for
`is empty`. That was true before this fix (reachable via `if not t` and
`a boolean called r is not t.`) and is unchanged by it; the fix makes it
printable instead of fatal. LANGUAGE.md gains a sentence saying so and
sending the reader to `is empty`; whether `not <collection>` should
instead mean "is empty", or be refused outright, is a language ruling that
has not been taken.

**Regression tests:**
`tests/452_not_is_a_boolean_whatever_its_operand.vox` — every operand type
through `Print`, plus the `value`, mixed-list-element and format-string
sinks; and `tests/453_negate_still_carries_its_operand_type.vox` — the
guard on the other side, that `-x` still carries `x`'s type (a negated
float still prints `-2.5`, not `-2`) and that the `if not`, `is not empty`
and `is not a <type>` paths are unmoved. Compile-fail case
`tests/compile_fail/200_not_on_a_text_is_a_boolean.vox` pins the declaration
path's "with a boolean" refusal — the reading the segfault contradicted.
Proven to fail on a clean extract of 4b77934 — `425` faults on its first
line there, with no output at all — while `426` and the compile-fail case
pass identically on both sides, which is what makes them controls.

**Family:** the predicate that asks only about its operand — #67's
`is_float_expr` blind spot and #74's type lock, same file. The sink is
#44's and #45's: an expression whose type is guessed wrong reaches a
printer that dereferences it. The always-false-on-a-pointer half is #33's
and #20's.

**Incidental, recorded and not fixed** (found on the way, each its own
defect):

| program | answers | note |
|---|---|---|
| `a text called t is "hi".` + `a boolean called ready is true.` + `if t and b, ...` | `fired` | `and` and `or` accept a pointer operand as truthy, silently — the same always-true-on-a-pointer shape as `not`, one operator over. `not` is now type-correct; `and`/`or` were never mistyped, so they are outside #88 |
| `a float called ratio is 2.5.` + `Print "{-ratio}".` | `error: Unknown variable: -ratio` | a negated variable inside a **format string** is not parsed as an expression — the `-` is taken into the name. `Print -ratio.`, `a float called flipped is -ratio.` and `Return a float, -ratio.` all work, so it is interpolation position only |
| the same two lines preceded by `a float called flipped is -ratio.` and `Print flipped.` | the caret lands on **line 2**, `a float called flipped is -ratio.` | the line that compiles fine on its own — the caret is found by searching the source for the offending phrase, so it stops at the first textual occurrence. Round 3's candidate **T-2** exactly. Both rows pre-existing on 4b77934 and unchanged by this fix |


---

### 89. The "Unknown variable" caret for a bare literal in a format hole lands on the first textual occurrence of that literal anywhere in the file - a legal `a float called f is 3.14.` is marked as the error

**Status:** **fixed in 0.4.10**, found 2026-08-22 by the language lawyer
while reducing candidate M of the round-3 candidate audit
(`REPORT-CANDIDATES-ROUND-3.md` §T-2, an incidental of that audit rather
than a ledger row). Severity: **diagnostic only** - no wrong value, no
unsafety; a correct error pointed at an innocent line. Family: **#46**, the
same caret machinery.

```vox
a float called f is 3.14.
Print "ok".
Print "ok".
Print "{3.14:.17}".
```
```
error: Unknown variable: 3.14
  --> T3.vox:1:21
    |
  1 | a float called f is 3.14.
    |                     ^--- here
```

**The error is right and documented.** LANGUAGE.md:3169-3170: "The value
inside `{}` must be a variable or expression, not a bare literal -
`{255:x}` is rejected (`255` is read as a variable name)." Only the
location is wrong. The caret sits three lines above the mistake, on a
perfectly legal declaration, and tells the reader that a correct line
contains an unknown variable.

**Control.** Change only the declaration's value and the caret is right:

```vox
a float called f is 2.5.     (only this line changed)
...
Print "{3.14:.17}".
```
```
  --> T4.vox:4:9
  4 | Print "{3.14:.17}".
    |         ^--- here
```

The caret moved because of a line the error has nothing to do with. That
is what makes it a bug rather than a poor choice: the location is decided
by unrelated text elsewhere in the file.

**Mechanism.** `find_use_site_location` (`src/analyzer/scope.rs`) tries
three patterns in order - `{symbol`, `"symbol"`, then the bare `symbol` -
through `find_pattern_location`, which since #46 runs **two passes**: pass
1 refuses a match sitting inside a text literal, pass 2 allows one, and
only a text-seeking pattern (`{name`, `"name"`) may land there. The rule
is #46's: *a hit in real code always beats one inside a text literal,
however much earlier the literal sits.*

That rule is right for a **name**. Here the symbol is `3.14`: the format
parser hands the hole's contents back as the "variable" it could not find
(`parse_format_string`, `src/parser/expressions.rs`), so the symbol is a
literal, not an identifier. Both text-seeking patterns are skipped in pass
1, leaving the bare pattern - which matches the float literal on line 1,
genuine "real code". Pass 1 succeeds and pass 2 never runs. The rule
assumes a bare-pattern hit in code is a *use of the name*; for this error
the symbol is a number, and any numeric literal anywhere in the file
satisfies it.

**Fix.** One predicate, applied where the scan decides whether a match's
region counts. `can_begin_a_name` asks whether the symbol could have been
lexed as a name at all - the lexer starts a word on an alphabetic
character or `_` (`src/lexer/scan.rs`), so `3.14`, `255` and `-3.14` never
were one. For such a symbol `scan_patterns` inverts #46's rule: a match in
**code** is now the coincidence and is refused, and a match inside a
**text literal** is the real thing, so the bare pattern may reach into the
literal in pass 2. The caret lands on the literal as written inside the
hole. Nothing changes for a symbol that is a name: `can_begin_a_name` is
true for every identifier, and #46's ordering, #55's word boundaries and
the comment refusal are untouched. The empty symbol - the unmatched-`{`
sentinel of #10 - answers true and keeps its caret, its match being
zero-width and reported as code.

The text-literal half of the fix is what makes the spaced spelling work: a
hole's content is trimmed, so `{ 3.14 :.2}` reports the same unknown
variable while no `{3.14` exists in the source to find it by. Without it
that case has no location at all and falls back to `find_mention_location`
- the pre-#46 first-occurrence scan - which puts the caret back on line 1.

**Tests.** Compile-fail fixtures, each `.err` pinning file:line:column so a
caret that drifts back fails the corpus:
`tests/compile_fail/225_caret_for_a_literal_in_a_format_hole.vox` (the
repro above, caret pinned at 10:9),
`174_caret_for_a_literal_in_a_hole_without_a_decoy.vox` (the control,
still 8:9), `175_caret_for_the_manuals_rejected_hex_literal.vox`
(LANGUAGE.md:3169's own `{255:x}` with the declaration the manual suggests
sitting above it, 6:9) and
`176_caret_for_a_spaced_literal_in_a_format_hole.vox` (`{ 3.14 :.2}`,
7:10). Each case's header comment names the literal, so the comment
refusal of #46 is exercised at the same time. Run test
`tests/510_a_literal_and_its_named_variable_in_a_hole.vox` pins the legal
neighbour - the same number as a literal and as a named variable, `{f:.2}`
and `{f:.17}` - still compiling and printing. #46's own fixtures
`137`-`140` are unchanged and green.

**LANGUAGE.md.** Nothing to tighten: :3169-3170 already predicts the error
exactly, and the manual says nothing about where a caret goes.

**Not closed by this fix.** The message is still `Unknown variable: 3.14`.
With the caret in the right place it is now readable - the reader sees the
literal it names sitting in the hole - but a hint in #45/#62/#63's family
("a format hole names a variable or an expression, not a literal; declare
it and interpolate the name") would say the rule outright. That is a
diagnostic improvement rather than this entry's defect, and it is left for
the queue. #46's own open end also still stands: the caret points at *an*
occurrence, not at the token that failed, because `Expr` carries no span.


---

### 90. A `buffer` grown past its capacity through a parameter is a use-after-free — the caller's next read of its own buffer segfaults

**Status:** **fixed** in 0.4.10 (unreleased, on top of 0.4.9 `4b77934`).
Severity: **memory safety** — a six-line program, compiled clean, reads a
block the runtime has already handed back to the kernel. Found 2026-08-21
by the #75 fix worker while probing the sibling shapes of a list or map
grown through a parameter, recorded as that report's Incidental (1)
(`vox-notes/REPORT-75-incidentals.md`), and traced from there to the
vox-fuzz buffers sweep (`vox-notes/REPORT-SWEEP-BUFFERS.md` §5, ledger row
**D-A**) which found the list half. Master-reproduced on `4b77934`.
Regression tests: `tests/454_a_buffer_grown_through_a_parameter.vox`
through `tests/460_a_buffer_argument_with_no_name.vox` (seven fixtures,
one behaviour each).

```vox
To 'pad out' with a buffer called sink.
    append "0123456789" to sink.

a buffer called journal is "start".
a number called appended is 0.
While appended is less than 2000,
    'pad out' of journal,
    Set appended to appended add 1.
Print journal's size.
```
→ **segfault (139)**, deterministic, no output at all.

Smaller still — one call, no loop, either spelling:

```vox
To 'widen' with a buffer called sink.
    Resize sink to 9000.

a buffer called journal is "start".
'widen' of journal.
Print journal's size.        (segfault 139)
```

```vox
To 'poke far out' with a buffer called sink.
    Set byte 9000 of sink to 65.

a buffer called journal is "start".
'poke far out' of journal.
Print journal's size.        (segfault 139)
```

**Where the cut-off is, and what it is made of.** Ten bytes appended
through the parameter, once per call count, on `4b77934`:

| appends through the parameter | caller's `size` afterwards | expected |
|---|---|---|
| 1 | `15` | 15 |
| 50 | `505` | 505 |
| 200 | `2005` | 2005 |
| 405 | `4055` | 4055 |
| **409** | **`4095`** | 4095 |
| **410** | **segfault** | 4105 |
| 2000 | segfault | 20005 |

`INITIAL_BUF_CAP` is 4096 (`coreasm/x86_64/resource.asm:25`). Every append
that still fitted in the buffer's FIRST allocation was correct, because
the block never moved; the first append that did not fit moved it, and the
caller was left holding the address of the old one. The boundary is an
allocator's page arithmetic, not a language rule. It is also the proof
that a `buffer` parameter is a reference: `Set byte 1 of sink to 65`
through the same parameter shows `Atart` in the caller, and 409 appends
are all visible.

**Freed, not merely stale — which is what separates this from #75.** The
callee's own view is correct right up to the crash:

```
callee sees 4085
callee sees 4095
callee sees 4105          <- the callee is right
Segmentation fault        <- the caller's next read, one instruction later
```

`_reallocate_buffer` (`coreasm/x86_64/resource.asm:979`) grows with
`mremap`/`MREMAP_MAYMOVE` — *"the old mapping was consumed by mremap"*,
says the code — and falls back to mmap + copy + `munmap`. **Both paths
release the old block.** A list grown through a parameter (#75) left the
caller reading a real, still-mapped, merely out-of-date block: a silent
wrong answer. A buffer leaves the caller reading unmapped memory.

**Which reading the manual supports.** Only the fixing one, and every
statement that touches this says so:

1. **LANGUAGE.md:3877** — the Safety vs C table — gives *"Use after
   free"* the Vox column *"Not possible by design"*, and :3819's Memory
   Safety Guarantees repeats *"No use-after-free"*. README's Memory Safety
   Model and ROADMAP M0 (*"no valid Vox program may segfault"*) forbid the
   crash outright.
2. **LANGUAGE.md:722-726** — *"a typed parameter supports the same
   properties and operations as a top-level variable of that type"*. The
   same growth at the top level answers `20005`; through the parameter it
   faults.
3. **LANGUAGE.md:3306** — *"No buffer overflows possible - memory expands
   dynamically"* — and :3469, *"Dynamic destination buffers grow
   automatically as needed"*. The buffer did grow; the caller was not told
   where to.

**The strongest reading in which the compiler is right, and why it
fails.** Copy semantics: LANGUAGE.md:1090-1092 says *"A function receives
a copy of a thing … nudging the parameter cannot reach the caller's
point"*. It fails three times. That sentence says **thing**, and
:886-890 says the opposite of the collections — `text`, `list`, `map` and
`buffer` are deferred as thing fields precisely because *"they carry
references"*. The observed behaviour is neither semantics: a copy would
show none of the callee's writes, and `Set byte 1 of sink` reaches the
caller. And no reading of any manual makes a segfault the correct answer
to a legal program.

**Confirmed bug**, same family as **#75** (a list or map grown through a
parameter), **#41** (`buffer as text` aliasing a block that resizing then
frees) and **#28** (a buffer read through a pointer its declaration never
wrote). Sibling of the store-back family pinned by `tests/300`–`305` and
`tests/p302_storeback_refactor.rs`.

**Root cause.** `src/codegen/vars.rs:126`, `emit_store_back_after_realloc`,
is the one place a reallocated pointer is filed. It resolves a name to
this frame's slot and mirrors that slot into the BSS label functions read
through — which is why a top-level `append` and a global grown inside a
function were always right. A parameter has neither home: its slot is the
callee's private copy of a pointer, and nothing in the ABI told the callee
where the caller kept its own.

- `emit_function_call` (`src/codegen/functions.rs:90` on `4b77934`) pushed
  the pointer **value** as the parameter's argument word.
- the parameter-store loop in the `FunctionDef` arm
  (`src/codegen/statements.rs:1424` on `4b77934`) stored that word straight
  into the parameter's slot.

So the callee's realloc reached the callee's slot and stopped. For a list
that was the end of it. For a buffer, `_reallocate_buffer` had already
released the block the caller's copy pointed at.

**The fix — give the parameter the cell the store-back was missing.** A
`buffer` parameter's argument word is now the **address of the cell
holding the pointer** instead of the pointer itself:

| file | change |
|---|---|
| `src/codegen/functions.rs` | `is_buffer_param`; `emit_buffer_arg_cell_address` at the call site (the name's BSS mirror at top level, this frame's slot inside a function, the mirror for a global, or a temporary for an argument with no name); `emit_buffer_arg_fixups` after the call |
| `src/codegen/statements.rs` | a hidden `{name}_cell` slot per buffer parameter (the shape a `value`'s shadow tag slot already has), a prologue that parks the caller's address there before taking its own copy of the pointer out of it, and the two declaration sites that disown the cell when a body redeclares the parameter's name |
| `src/codegen/buffers.rs` | `emit_store_buffer_ptr_to_slot` / `emit_buffer_param_cell_writeback`, and the four buffer-slot stores routed through them |
| `src/codegen/format.rs`, `src/codegen/vars.rs` | the remaining two buffer-slot stores routed the same way |
| `src/codegen/mod.rs` | the `buffer_param_cells` table, saved and restored per function like every other per-frame table |

No runtime change: `coreasm/` is untouched.

**The argument word count is unchanged** — one word, like every other
non-`value` parameter — so the `value` two-word layout, `thing` address
passing, the stack argument words the seventh parameter and beyond ride
on, and the recursion guard are all untouched (`tests/459`). Only the
meaning of the word moved.

**The write-back happens at the reallocation, not when the call returns.**
Between the two, the callee can call a function that reaches the same
buffer through its global mirror, and that read must not land in the freed
block either. That is why a top-level name hands over its **mirror** as
the cell — the holder every function reads — and the frame slot, which
only the top level reads and only after the call returns, is refreshed
from it afterwards. `tests/456` is that window: on `4b77934` it faults
*inside* the call, after the watcher has printed the literal half of its
own line.

**A buffer grown two or thirty calls deep still reaches the variable that
owns it** (`tests/457`): each frame knows only where the frame above it
keeps its copy, so the call site carries the new pointer on out through
its own parameter's cell.

**Deliberately unchanged:**

- **Rebinding stays local.** `a buffer called sink is "…"` inside a
  function whose parameter is `sink` names a buffer of that function's own
  from there on, and the caller keeps its own — 0.4.9's behaviour, kept,
  by disowning the cell at the declaration. `Set sink to "…"` is *not* a
  rebinding: on a buffer it copies bytes into the buffer the name already
  denotes, so the caller sees the new bytes, before and after
  (`tests/458`).
- **An argument with no variable of its own** — a literal, an element
  read, a call's result — gets a temporary cell: the callee is correct for
  the length of the call and the growth dies with the temporary, because
  there is no caller variable for it to reach (`tests/460`).
- **A fixed-size buffer still refuses to grow** and sets the error flag
  through a parameter exactly as it does at the top level (`tests/458`).
- **Nothing new is freed.** `_reallocate_buffer` already released the old
  block; with the caller's pointer advancing again, that release is now
  correct rather than fatal. 200 000 appends through a parameter measure
  **under 2 MiB resident for 2 000 005 bytes**, exit 0 (was: signal 11).

**What this does NOT fix, and the repro for it.** A buffer reallocated
inside a **shared library** still leaves the *consumer's* cleanup table on
the freed block, because each module gets its own `buf_table` (it is a
local BSS symbol — `nm consumer` shows `b buf_table`, and the `.so`
exports only its function). The program now prints the right answer and
then faults in `_cleanup_buffers` at exit instead of faulting on the
caller's read:

```vox
(lib.vox, built --shared)   Library bufkit version "1.0".
                            To 'pad out' with a buffer called sink.
                                … 600 appends of ten bytes …
(consumer.vox)              see bufkit version "1.0" from "libbufkit.lib".
                            a buffer called journal is "start".
                            'pad out' of journal.
                            Print "consumer sees: {journal's size}".
```
| | `4b77934` | this fix |
|---|---|---|
| output | *(nothing)* | `consumer sees: 6005` |
| exit | 139, in the caller's read | 139, in `_cleanup_buffers.free_loop` |

Two modules, two buffer tables, one block: the module that grows the
buffer updates its own table and cannot reach the other's. It wants its
own entry, its own fail-before tests and its own review — either a
`_retable_buffer(old, new)` at the boundary, or one table shared across
modules — and not a ride in this diff.

The same is true of a **top-level buffer declared without an initializer**
and grown inside a function BY NAME — no parameter anywhere:

```vox
a buffer called journal.
To 'grow the global by name'.  … 600 appends of ten bytes …
'grow the global by name'.
Print "after the global grew: {journal's size}".    (139, before and after)
```

`a buffer called journal.` (and the sized spelling) goes through
`BufferDecl`, which gives the name a frame slot AND a BSS mirror; a
function can only reach the mirror, and nothing carries its growth back
into the slot the top level reads. Written `a buffer called journal is
"start".` the same program answers `6005` on both sides, because a
top-level initialised buffer resolves straight to the BSS label and has
only one holder. Identical on `4b77934` and here: this fix cannot close it
from where it stands, because the top level's frame slot is not
addressable from inside the callee. Its own entry too — the answer is
either to stop giving a mirrored top-level buffer a frame slot, or to
refresh that slot from the mirror after every call.

**One ABI note for shared libraries.** A `.so` exporting a function with a
`buffer` parameter must be rebuilt with 0.4.10 alongside its consumer:
both sides derive the meaning of that argument word from the same
signature table, and a 0.4.9 `.so` called from 0.4.10 code (or the
reverse) would disagree about it. The same note applies to #75's `list`
and `map` parameters. Every shape the repo builds builds both sides from
source in the same run.

**LANGUAGE.md.** The manual stated the rule for neither direction: :886-890
says a buffer carries a reference, :1090-1092 says a *thing* is a copy,
and nothing said what an `append` through a `buffer` parameter does. One
bullet added to *Parameter and Local Types → Key points* (LANGUAGE.md:746)
saying that a `buffer` parameter is the caller's buffer including across a
growth, that redeclaring the name is local, and that `Set` on it copies
bytes rather than rebinding. No feature is added; this is the behaviour
the fix makes true, written where a reader looks for it.


---

### 91. A non-provable absent-key or out-of-range read into a `text`, `list` or `map` slot hands the raw 0 to a pointer and segfaults

**Status:** **fixed** in 0.4.10. Severity: **memory safety** — a four-line
program, compiled clean, faults on the first read of a value the manual
promises is safe to take. Regression tests:
`tests/499_missed_list_read_into_a_text_slot.vox`,
`tests/500_missed_map_read_into_a_pointer_slot.vox`,
`tests/501_missed_read_into_a_pointer_slot_across_frames.vox`.
Found by the vox-fuzz claim ledger — the `gen leaf list oob` (kind 5) and
`gen leaf map oob` (kind 10) leaves of `src/gen_collections.vox`, whose
"Kept, with citations" lists pin exactly the two manual sentences this
entry is about — and separated out by the candidate audit of 2026-08-21
(`vox-notes/REPORT-CANDIDATES-ROUND-2.md` §C, sub-case **C-ii**;
`vox-notes/REPORT-SWEEP-COLLECTIONS.md` Finding C). Master-reproduced on
`4b77934` (= 0.4.9); byte-identical on 0.4.8, so this is not a 0.4.9
regression — it is the corner #54 and #65 never covered.

```vox
a list called grown is ["a", "b"].
Append "c" to grown.
a text called third is element 5 of grown.
Print third.
```
→ **segfault (139)**, no output at all.

The working neighbour, `element 2 of grown`, prints `b`.

**Where it comes from.** LANGUAGE.md says what a miss yields, twice:

> "A missing key does not crash: the lookup **yields 0** and sets the error
> flag, so an `on error` handler can react." (Maps)
>
> "Out-of-bounds access sets an error flag and **returns 0**" (Lists, twice)

Both sentences are about the *number* 0, and for a `number` destination
they are exactly right — `a number called missed is element 5 of counts.`
prints `0` before this fix and after it. But the 0 is untyped, and codegen
hands it to whatever the read's **static** type says: for a list of texts
that type is `text`, and a `text` is a pointer. The first read dereferences
address 0.

`src/codegen/expr.rs` — the miss paths of `ElementAccess`, `ListAccess`,
`First` and `Last` — all emitted `xor rax, rax  ; return 0 on error`, and
`_map_lookup` (`coreasm/x86_64/map.asm:455`) returns `rax=0, r11=0` on a
miss. A map read carries a runtime tag, so `Print found's "zebra".` was
always safe (the tag says "number", and it prints `0`); a list read of a
homogeneous list carries no tag at all, so `Print element 5 of grown.`
faulted too.

**Why the static checks do not reach it.** #54's `check_declared_read_type`
and #65's initializer check both judge a **type mismatch**, and here the
declared type and the inferred type *agree* — `element 5 of grown` is a
text read into a `text`. It is the runtime *value* that is wrong. #72
closes every case where the miss is provable from a literal, with a
diagnostic; what is left is every case where it is not — a variable index,
a dynamic key, an `Append`-grown list, a `Set`-grown map, a collection
reached through a parameter — and **no static proof reaches a dynamic key**.
The answer therefore had to be a runtime one.

**The fix: a miss yields the destination's default value, never a raw 0.**
The manual already has the table — the one under
[Two Canonical Forms](../LANGUAGE.md) that says what `Create a text called
n.` leaves in the slot: `0` for a `number`, the empty text for a `text`,
`[]` for a `list`, `{}` for a `map`. Since #25 the compiler has written
exactly those values into a slot no initializer reached
(`emit_type_default`, `src/codegen/vars.rs`), for exactly this reason — its
own comments read "a null pointer here makes the first read dereference 0".
A missed read is the same situation arriving by a different road, so it now
gets the same answer, in the same two places a static pointer type is
asserted about the value:

1. **At the read** (`src/codegen/expr.rs`). When the list's element type is
   statically known and is a pointer type, the miss path emits that type's
   empty value instead of `xor rax, rax`. This is what makes the *tagless*
   consumers safe — `Print element 5 of grown.`, a format hole, an
   `Append` of the result — because every one of them reads the value as
   that same static type. A **mixed** list is untouched: its miss still
   yields `rax=0, r11=0`, and the tag says "number", which is honest and
   is what the manual prints.
2. **At the destination** (`src/codegen/statements.rs`,
   `src/codegen/functions.rs`). A declaration, a bare assignment, a
   `Return` and an argument all name a slot whose declared type may be a
   pointer. When the initializer is one of the reads that can miss, the
   value is null-checked and a `text`/`list`/`map` slot takes its own empty
   value. This is what catches the map (no static value type exists to key
   on at the read) and the read that happens inside another frame.

Shared machinery, so the two halves cannot drift apart:
`emit_empty_value_for` (the value half of #25's `emit_type_default`, which
now calls it), `emit_empty_value_if_missed`, `is_fallible_collection_read`
and `static_list_element_type` — the last extracted from
`src/codegen/print.rs`, which had the only copy of the "what type is this
element read?" answer that the miss paths also needed.

**The error flag is not touched.** The read sets it exactly as before, so
`On error` still fires on every row below; the miss is still an error, and
that is the whole point of yielding a value rather than crashing.

**The matrix, each row its own program, measured on a clean `git archive
4b77934` extract (md5 `7936b6d5f1780a640c5672f4695bdb34`, byte-identical
to the build the candidates report quotes) and on the fix:**

| program | before | after |
|---|---|---|
| Append-grown list, `element 5` → `text` | **139** | prints an empty line |
| Append-grown list, variable index `9` → `text` | **139** | prints an empty line |
| Append-grown list, `element 5` printed directly | **139** | prints an empty line |
| Append-grown list, `Set seeded to element 5` | **139** | prints an empty line |
| the missed text then appended to a list | **139** | prints `[""]` |
| `first` of an empty list → `text` | **139** | prints an empty line |
| `last` of an empty list → `text` | **139** | prints an empty line |
| `Set`-grown map, absent key → `text` | **139** | prints an empty line |
| map of lists, absent key → `list` | **139** | prints `[]` |
| map of maps, absent key → `map` | **139** | prints `{}` |
| `Return a text, element 5 of shelf.` → caller's `text` | **139** | prints an empty line |
| a missed read passed to a `text` parameter | **139** | prints `announced: []` |
| Append-grown list, `element 5` → `number` (control) | prints `0` | prints `0` |
| `Set`-grown map, absent key → `number` (control) | prints `0` | prints `0` |
| `Print found's "zebra".`, tag-driven (control) | prints `0` | prints `0` |
| `Set kept's "k" to found's "zebra".` (control) | prints `{"k": 0}` | prints `{"k": 0}` |
| `element 2 of grown`, in range (control) | prints `b` | prints `b` |
| `On error` after a missed read (control) | fires | fires |

Twelve of eighteen faulted; the six controls are byte-identical.

**LANGUAGE.md tightened, three sentences.** "the lookup yields 0" (Maps)
and the two "Out-of-bounds access sets an error flag and returns 0" bullets
(Lists, and List Properties) each now name the destination's default value
and point at the table that already defines it. Nothing new is promised —
the sentences were loose about a case the manual's own default table had
already answered, and a reader who took "returns 0" literally for a `text`
would have written the program at the top of this entry.

**Family.** #25 (a slot no initializer reached gets its type's default, for
this same reason), #24 and #26 (`emit_text_or_empty_on_null` — a fallible
positional read that misses substitutes the shared empty text, so `On
error` catches it and nothing dereferences 0; this entry is that discipline
carried to collection reads), #54 and #65 (the static read/initializer
type checks, which judge a mismatch and so cannot see this), and #72 (the
provable half of the same miss, closed with a diagnostic — its report's
"What #72 does not fix" section is this entry).

**For the fuzzer.** The `gen leaf list oob` and `gen leaf map oob` leaves
draw only holders whose type matches the collection's values, and their
notes say a missing-key read "yields 0". That is still true for a `number`
holder and the leaves keep passing unchanged. What is now *also* legal, and
was not before, is a `text`/`list`/`map` holder for a missed read — it no
longer crashes, and it yields that type's empty value. Both leaves can
widen to draw it.


---

### 92. `Set <global> to <value>.` at top level takes a `list`, `map` or `buffer` global out of scope, so every function reading it fails with `Unknown variable` — and the caret lands on the declaration

**Status:** **fixed** in 0.4.11. Severity: **wrong rejection** — a correct
six-line program is refused, and the byte-equivalent `the <global> is
<value>.` compiles and runs. Regression tests:
`tests/523_a_global_list_written_with_set_at_top_level.vox`,
`tests/524_a_global_map_written_with_set_at_top_level.vox`,
`tests/525_a_global_buffer_written_with_set_at_top_level.vox`,
`tests/526_a_global_write_above_the_function_that_reads_it.vox`,
`tests/527_a_global_list_written_with_set_in_every_branch.vox`,
`tests/528_the_three_spellings_of_a_write_to_a_global.vox`,
`tests/529_global_scalars_written_with_set_at_top_level.vox`,
`tests/530_set_brings_a_fresh_global_into_being.vox`,
`tests/531_a_global_list_a_function_appends_to_and_a_set_replaces.vox`,
`tests/compile_fail/236_unknown_global_caret_lands_on_the_possessive.vox`,
`tests/compile_fail/237_a_global_declared_as_both_a_list_and_a_buffer.vox`.

**How it was found.** By the repin-tool worker on 2026-08-22, building the
vox-fuzz ledger's repin citations (`feat/repin-citations`): a global `list`
that a function read could not be reassigned by a top-level `Set`, and the
tool shipped a one-line function wrapping the `Set` as a workaround. Probe
preserved at `vox-fuzz docs/ledger/probes/repin/vox-global-list-set.vox`.
Carried into the round-4 candidate list, adjudicated in
`vox-notes/REPORT-CANDIDATES-ROUND-4.md` §1 (mechanism traced and confirmed
by two predictions), then **verified by the master himself** on 2026-08-23
(`vox-notes/VERIFIED-ROUND-4.md` §92 — he re-ran the repro, the working
neighbour and the whole behaviour table on `527cb89` = 0.4.10) and approved
for fixing by Josj the same day.

```vox
a list called roster is [].

To 'how many'.
    Return a number, roster's length.

Set roster to ["ada", "grace"].
Print 'how many'.
```
→ `error: Unknown variable: roster`, with the caret on **line 1, the
declaration**. The same program with `the roster is ["ada", "grace"].`, or
with `roster is ["ada", "grace"].`, prints `2`.

**What the manual promises.** LANGUAGE.md, *Type Immutability*, names the
three write forms in one breath:

> Every form that writes to an already-declared name — `x is <value>.`,
> `the x is <value>.`, and `Set x to <value>.` — is checked the same way

and *Function Scope* lists `[]`, `{}` and an empty buffer among the values a
global reads as inside a function, so a global collection read from a
function is contemplated throughout. No sentence anywhere gives `Set` its own
rules for a global. **The manual needed no change for this fix.**

**The pro-compiler reading, and why it fails.** A global `list`/`map`/`buffer`
is a handle to heap storage, so rebinding it could leave an
already-compiled reader holding a pointer to the old allocation — an
aliasing hazard the compiler would be right to refuse. That reading does not
survive its neighbours: `the roster is [...]` performs the same rebind at the
same point on the same storage and is accepted, and the identical `Set`
*inside* a function is accepted too, where the manual says it "mutates the
global itself". The message is also `Unknown variable`, not a refusal that
gives a reason.

**Where it comes from.** A kind-mismatch poison in `collect_definite_decls`
(`src/parser/ast.rs`), reached in four steps:

1. `Set roster to [...]` carries no type noun, so it parses into
   `Statement::VarDecl { var_type: None, .. }`
   (`src/parser/declarations.rs`) — the same node shape a fresh declaration
   produces. `the roster is [...]` instead parses into
   `Statement::Assignment`. That one difference is the whole bug.
2. `collect_definite_decls` mapped each `VarDecl` to a `DefiniteDeclKind`,
   and `var_type: None` fell into the same `_ => Plain` arm as a `number`,
   `float` or `text` declaration — conflating "names no type" with "names a
   scalar type".
3. Its `record` helper saw `roster` already recorded as `List`, saw the new
   kind `Plain`, and since the two disagreed it **removed the name and
   poisoned it** so it could never be re-added. That poison is right for a
   genuine kind conflict — `a text called notes is "hello".` followed by
   `open a file for reading called notes at ...` — and exists so the pre-pass
   never pre-judges a type the analyzer's own ordered walk should judge
   (plan 294 finding 3). A write is not a kind conflict.
4. `src/analyzer/statements.rs` builds `global_variables` (and
   `list_variables`/`map_variables`/`buffer_variables`) from that map, and
   analyzes every function body against a clone of it. `roster` was absent,
   so `is_variable_available` was false and
   `src/analyzer/expressions.rs`'s `Expr::PropertyAccess` arm reported
   `Unknown variable`.

The scalars escaped for the same reason they now stay safe: `Some(Type::Integer)`,
`Float`, `String`, `Boolean` all map to `Plain` too, which is the kind the
untyped write yielded — no disagreement, no poison. `Append` is a different
statement and was never recorded. A `Set` inside a function was never seen at
all, because this walk does not enter function bodies. Position was
irrelevant, because the map is built over every top-level statement before
any of them is analyzed.

**The fix: a write that names no type claims no kind.**
`collect_definite_decls` now splits `VarDecl { var_type: None }` out of the
scalar arm and routes it to `record_untyped_write`, which registers the name
only if nothing else has, and never collides with, overrides or poisons a
kind a real declaration recorded. A real declaration arriving *after* such a
write takes the name over rather than poisoning it. The walk carries the
distinction through the if/otherwise branch merge as well (a `DefiniteDecls`
value now carries its poisoned and untyped sets alongside the kinds), so the
same `Set` written into every branch behaves as it does at the top level.
This mirrors `collect_all_typed_decls` two functions below, which has always
ignored a `VarDecl` with no type noun.

Registering the name is the half the untyped write must keep doing: `Set
tally to 5.` on a name nothing else declares brings `tally` into being, and a
function may read it (`tests/530_...`).

**The caret, the same entry's second fault.** The `Expr::PropertyAccess` arm
in `src/analyzer/expressions.rs` reported the failure through `push_error`,
which anchors on the first textual occurrence of the name — the declaration.
Its five sibling call sites all go through `push_unknown_variable`, which
anchors on the failing read instead (and answers a too-early read in #79's
words); this one now does too. Measured on
`tests/compile_fail/236_unknown_global_caret_lands_on_the_possessive.vox`:
the caret moves from `7:19` (`a list called scratch is [].`) to `10:22`
(`Return a number, scratch's length.`).

**The behaviour table, each row its own program, run on a clean `git archive
527cb89` extract and on the fix:**

| program | before | after |
|---|---|---|
| `list` global, fn reader, top-level `Set` | **Unknown variable** | prints `2` |
| `map` global, fn reader, top-level `Set` | **Unknown variable** | prints `2` |
| `buffer` global, fn reader, top-level `Set` | **Unknown variable** | prints `5` |
| the `Set` written above the function definition | **Unknown variable** | prints `1` |
| the `Set` written into every branch of an if/otherwise | **Unknown variable** | prints `1` |
| all three write spellings on one global | **Unknown variable** | prints `1`, `2`, `3` |
| `list` global a function appends to and a `Set` replaces | **Unknown variable** | prints `1`, `2`, `3` |
| identical program written `the roster is [...]` (control) | prints `2` | prints `2` |
| `number`, `float`, `text` globals, top-level `Set` (control) | prints `5`, `2.5`, `new` | unchanged |
| `Set` on a name nothing declares, read in a function (control) | prints `5` | unchanged |
| `list` declared, then declared again as a `buffer` (control) | refused | still refused |
| `a text called notes` then `open ... called notes` (control) | refused, names the conflict | unchanged |
| `Set xs to [...]` with no declaration at all (control) | `Property 'size' requires a buffer, list, map, or file variable` | unchanged |

The last row is the still-open question of what an untyped `Set` on a name
nothing declares should mean, which is not this entry's to answer: the name
is registered but no kind is, so a collection property on it is refused. That
is unchanged by this fix and is Josj's ruling to make.

**Family.** #46 and #89 (the caret anchored on a textually earlier mention
rather than the failing read — this is the possessive-read spelling of the
same fault), #79 (a name read before its declaration is answered in words
that say so, which the corrected call site now inherits), #66 (the same
"a function must see a top-level declaration whole" contract, on the codegen
side), and #25 (`collect_definite_decls`' other consumer — the definite set
decides which names get a bss mirror and which get a frame-setup default, so
un-poisoning a name gives it both).

---

### 93. A user-facing diagnostic cites LANGUAGE.md by a stale line number, and the manual and a compiler warning both say a fresh dynamic buffer has zero capacity when the runtime gives it 4096 bytes

**Status:** **fixed in 0.4.11**. Severity: **diagnostic/documentation
only** — no runtime change; two unrelated inaccuracies bundled into one
entry because both are the compiler or the manual telling the user
something false about a value the user can check for themselves. Found
2026-08-23 by the round-4 candidate audit
(`vox-notes/REPORT-CANDIDATES-ROUND-4.md` §6, "now VERIFIED BY EXECUTION")
and by Josj's own recollection of the buffer default, put to him as design
question Q2 (`vox-notes/DESIGN-RULINGS.md`); verified by the master by
execution the same day (`vox-notes/VERIFIED-ROUND-4.md` #93); approved by
Josj the same day (WhatsApp: "all are real bugs … please get those fixed
for vox 0.4.11").

#### Part A — `void_results.rs:139,141` cite LANGUAGE.md by line number, and both numbers are now stale

```vox
Library greetlib version "1.0".

To greet.
    Print "hi".
```
```vox
see greetlib version "1.0" from "./libgreetlib.lib".

a number called n is greet.
Print n.
```
→
```
error: 'greet' has no declared return type in its .lib entry, so its result cannot be used as a value here
  A `.lib` entry with no `, returning` clause is a function that returns nothing (LANGUAGE.md:4963-4965), and consuming a library type-checks its calls like any other function's (LANGUAGE.md:4990) - so what lands here is whatever the call left in the return register, not an answer.
```

`LANGUAGE.md:4963-4965` is the **Contextual Keywords** bullet list; `:4990`
is "Three words the things feature claims only inside their construct" —
neither has anything to do with `.lib` entries or `returning`. The rule the
diagnostic means lives at **`LANGUAGE.md:5230-5232`**, section **"The
`.lib` file"**, and **`LANGUAGE.md:5279-5282`**, section **"Consuming a
library"**. A line number is the most precise citation available when it
stays right, but LANGUAGE.md moves every release and nothing in the build
kept these two in sync with it — a confidently wrong pointer is worse than
a vaguer one that stays true. `src/analyzer/untyped_returns.rs:135-136`
already cites its own LANGUAGE.md rule by section name
(`(LANGUAGE.md "Functions")`); `void_results.rs`'s `LibraryEntry` arm was
the only user-facing string in the diagnostic vocabulary that had not
followed suit. `grep -rn 'LANGUAGE.md:[0-9]' src/ --include=*.rs` finds 46
line-number citations; these two, inside a string literal a user actually
sees, are the only ones this entry touches — the other 44 are stale too,
but sit in comments and doc-comments that never reach a user, so they are
left for a documentation pass (see "Not closed by this fix" below).

**Fix.** `void_results.rs:139,141` now cite `` (LANGUAGE.md "The `.lib`
file") `` and `` (LANGUAGE.md "Consuming a library") ``, matching
`untyped_returns.rs`'s house style.

#### Part B — the manual and a compiler warning say a fresh dynamic buffer has zero capacity; the runtime gives it 4096 bytes

```vox
a buffer called b.
Print "capacity: {b's capacity}".
Print "size: {b's size}".
```
→
```
Warning: Buffer "b" declared without size or initializer.
  This creates a zero-capacity buffer which may not be useful.
  Consider: a buffer called 'b' is 1024 bytes.
capacity: 4096
size: 0
```

The warning says "zero-capacity"; `capacity` reads **4096**, immediately
and every time — `coreasm/x86_64/resource.asm:741` writes
`INITIAL_BUF_CAP` (`:25`, `4096`) into `BUF_CAPACITY` at declaration, and
the one `mmap` the declaration makes is sized `4121` bytes (`4096 +
BUF_DATA + 1`). LANGUAGE.md agreed with the warning, wrongly, in three
places: the `Create a buffer called buf.` comment at :498 ("buf is empty,
0 bytes, dynamic capacity"), the Dynamic Buffers "Features" bullet at
:3438 ("Start with zero capacity and grow automatically as needed"), and
the Resource Management section at :3995 ("Buffers start at zero capacity
and grow automatically"). Josj's own recollection (design ruling Q2,
2026-08-23): "My understanding was that 4K of buffer is automatically
given on a fresh dynamic buffer... The docs are wrong" — confirmed by the
master's own run above and by reading the runtime source; **Option B:
4096 is the rule.**

**Fix (no runtime change).** LANGUAGE.md's three sentences now say,
present tense, that a dynamic buffer starts with 4096 bytes of capacity
(size 0) and grows as needed — each edit kept on its existing line, so the
file's line count is unchanged (5545 lines before and after). The
`capacity` property row (:3518, "Maximum bytes the buffer can hold") was
also mis-stated for a dynamic buffer, whose capacity is not a fixed
ceiling but a current allocation that grows — it now reads "Bytes
currently allocated (fixed for a sized buffer, grows automatically for a
dynamic one)". The compiler warning at `src/parser/declarations.rs:69-77`
keeps suggesting a sized declaration (still useful advice when the size is
known ahead of time) but no longer claims zero capacity — it now says the
buffer starts at the default 4096 bytes and grows automatically.

**Tests.**
- `tests/bugs_found_93_lib_void_result_diagnostic.rs` (part A) — builds a
  real `.so`/`.lib` pair and compiles a separate consumer against it: the
  `LibraryEntry` diagnostic can only be triggered through the full `.lib`
  import path wired up in `main.rs` (`lib_file::resolve_program_imports`),
  and the analyzer-only `compile_fail` corpus (`src/compile_fail_tests.rs`)
  never calls `.with_imports`, so it cannot exercise this diagnostic at
  all. Asserts the error names both sections and no longer contains
  `LANGUAGE.md:4963` or `LANGUAGE.md:4990`.
- `tests/bugs_found_93_buffer_capacity_warning.rs` (part B) — asserts the
  uninitialized-buffer warning states "4096 bytes of capacity", no longer
  contains "zero capacity"/"zero-capacity", and still offers the sized-
  declaration suggestion. No test previously asserted this warning's text
  at all.
- `tests/532_dynamic_buffer_default_capacity.vox` (part B) — a fresh
  dynamic buffer's `capacity` is `4096` and `size` is `0`; after a small
  `Append`, `capacity` is still `4096` and `size` is `2`.

**LANGUAGE.md.** Four lines changed, all on their existing lines, no lines
added or removed (5545 before and after): :498, :3438, :3518, :3995. No
heading renamed, merged or removed.

**Family.** #93 is a diagnostic/documentation entry, closest in kind to
#89 (a diagnostic that pointed at the wrong place) and #85/#86 (LANGUAGE.md
stating a rule the runtime did not actually follow).

**Not closed by this fix.** The other 44 stale `LANGUAGE.md:<N>` citations
the same grep finds sit in `src/` comments and doc-comments, never reach a
user, and are left for a documentation pass rather than a diagnostic fix —
see `vox-notes/REPORT-CANDIDATES-ROUND-4.md` §6.2. The `full` buffer
property ("Whether size equals capacity (for fixed buffers)", :3520) and
the "size is equal to capacity" example (:3488) were checked against the
new capacity value and still read truthfully; neither needed a change.


---

### 94. `Set <reserved-type-noun> to <value>.` blames the following `to`, not the reserved word the author actually typed

**Status:** **fixed** in 0.4.11. Severity: **diagnostic quality** — a
one-line program is refused for the right reason with the wrong caret, and
the compiler already had the correct message one branch over. Found by the
language-lawyer adjudicator during the Round-4 audit's candidate review
(`audit/round-4`, `vox-notes/REPORT-CANDIDATES-ROUND-4.md` §2); verified
independently by the master against `vox v0.4.10` on 2026-08-23
(`vox-notes/VERIFIED-ROUND-4.md` §#94); approved by Josj the same day
(WhatsApp: "all are real bugs … please get those fixed for vox 0.4.11").
Regression tests: `tests/compile_fail/238`–`251`,
`tests/533`–`540`.

```vox
Set message to "x".
```
```
error: Cannot use 'to' as a variable name - it's a reserved keyword.
  Tip: Try a more descriptive name like 'to_value' or 'my_to'
  --> repro.vox:1:13
    |
  1 | Set message to "x".
    |             ^--- here
```

The working neighbour, the declaration path, shows the diagnostic the
compiler is capable of:

```vox
a number called message is 1.
```
```
error: Cannot use 'message' as a variable name - it's a reserved keyword.
  'message' is an alternate spelling of the reserved keyword 'text'.
  Tip: Try a more descriptive name like 'message_value' or 'my_message'
  --> repro.vox:1:17
```

`Set text to "x".` (the canonical spelling, not the `message` alias) gives
the same wrong shape, caret on `to` — this is not about the alias.

**Where it comes from.** `LANGUAGE.md`'s declaration section documents
`Set a <type> called <name> to <value>.`; the author wrote a type noun and
omitted `called`. That much the parser gets right. The bug is that the
message it then gives blames whatever token happens to sit where a name
would go, not the token that caused the trouble.

**Mechanism.** `parse_var_decl` (`src/parser/declarations.rs`) reads `Set`,
then `try_parse_type_noun` matches `message` (the lexer folds it onto
`Token::Text` before the parser ever sees it) and consumes it, believing it
is reading `Set a text called <name> …`. The next line was
`self.expect(&Token::Called);` with **the return value discarded** — `to`
is not `called`, so nothing is consumed and nothing is reported. The
following `self.check_not_keyword(self.current())?` then finds `to` sitting
at the cursor and correctly, but pointlessly, reports that `to` is
reserved. Two more call sites carry the identical discarded-`expect`
pattern one function over: `parse_typed_var_decl` (the `a <type> called
<name>` statement form, for `a message is "x".` with `called` omitted
entirely) and `parse_the_statement` (the `The <name> is <value>.` form),
which instead of a discarded `expect` fell back to a hardcoded `"_iter"`
placeholder name — meant for `The number is 5.` reassigning a `for each`
loop's implicit iterator, a form `LANGUAGE.md`'s Variable Reference section
documents only as a read (`the number` — an expression), never as an
assignment target; `claim_name` unconditionally refuses any name starting
with `_`, so that fallback could never actually succeed and was already
dead code for every type noun, including `number`. All three sites now
report through the same message.

**Fix.** `check_not_keyword` (`declarations.rs:87`) already builds the
right diagnostic from the source lexeme at the parser's current position —
the family #45/#62/#63 house standard: name what the author actually did.
A new helper, `err_type_noun_as_name`, saves the type noun's own token
position before it is consumed, and — only once the fallback token also
turns out to be unusable as a name — rewinds to that saved position and
raises the diagnostic against the type noun itself, matching the caret
convention #46 fixed. The "only once" matters: `Set float pi to 3.0.` and
`a float pi is 3.0.` (`examples/pi.vox` uses the latter) never write
`called` and are legal — `pi` is a perfectly good name sitting right where
the parser looks next, so the existing fallback-to-whatever-follows
behaviour is preserved whenever that fallback IS a usable name. The
blame only redirects to the type noun when it is not, which is exactly
the case a reserved word was mistaken for a name.

**Every reserved type noun and alternate**, both through `Set … to` and
`The … is`, and the `a … is` shorthand: `number`, `int`/`integer`, `text`/
`message`/`string`, `boolean`/`bool`, `float`, `list`/`array`, `map`,
`file` all now name themselves correctly. `buffer`/`time`/`timer` were
never affected — `require_called_after_type` already reports their own
specific "Missing 'called' after 'buffer'" message before the generic path
is ever reached, and that message is untouched (`tests/compile_fail/250`
pins it). `value` and a defined thing's name are unaffected for a
different reason: both already require `called` to be confirmed by
lookahead before `try_parse_type_noun`/`try_parse_thing_type_noun` will
consume them at all, so the discarded-`expect` path can never be reached
for them.

**#95's boundary.** An untyped `Set <fresh name> to <value>.` (no type
noun consumed at all — `Set greeting to 5.`) is untouched: it is legal, it
creates the name, and it stays that way (`tests/536`). Its separate defect
— a `Set`-created name carrying a stale dynamic type tag that prints an
address on retype — is entry #95's, not this one's.

**Family.** #6 (recovering the source lexeme for an aliased keyword,
which `check_not_keyword` already did — this entry is that same recovery
reaching a call site it hadn't before), #45 (name what the author actually
did), #46 (the caret belongs on the real offending token), #62/#63 (the
house standard for a diagnostic naming the actual mistake and the way
out).


### 95. A name brought into being by an untyped `Set` escapes the type lock and carries no type at all, so a rewrite of another type prints an ADDRESS — and LANGUAGE.md never said `Set` declares

**Status:** **fixed** in 0.4.11. Severity: **wrong answer, silently** — a
three-line program, compiled clean, prints a pointer where the manual
promises a compile error; and a two-line one prints a pointer where the
manual promises the text that was put there. Regression tests:
`tests/542_untyped_declaration_takes_the_values_type.vox`,
`tests/543_the_and_bare_forms_declare_the_same_way.vox`,
`tests/544_an_untyped_declaration_reports_a_static_type.vox`,
`tests/545_an_untyped_declaration_takes_a_same_type_rewrite.vox`,
`tests/546_a_read_between_an_untyped_declaration_and_a_later_set.vox`,
`tests/547_an_untyped_declaration_of_a_text_interpolates.vox`, and
compile-fail cases
`tests/compile_fail/255_untyped_declaration_rewritten_with_another_type.vox`,
`256_set_declared_name_rewritten_by_the_form.vox`,
`257_untyped_declaration_rewritten_by_set.vox` and
`258_declared_name_rewritten_by_set.vox` (the working neighbour, which was
always right and is byte-identical before and after).

**How it was found.** The candidate audit of 2026-08-23 went looking for
what `Set count to 5.` means on a name with no declaration — a form the
parser has always accepted and the manual has never described — and chasing
what type such a name gets turned up a defect that was not on the candidate
list (`vox-notes/REPORT-CANDIDATES-ROUND-4.md` §2b, verdicts 2b-i and
2b-ii). Verified by the master on 2026-08-23 against
`vox v0.4.10` with the manual read at `527cb89`
(`vox-notes/VERIFIED-ROUND-4.md` §#95); approved by Josj the same day, with
the design sub-question — what an untyped `Set` on a fresh name should mean
— ruled shape **(b)**: it declares the name with the value's type and locks
it like any declaration.

```vox
Set zoo to 5.
Set zoo to "text now".
Print zoo.
```
→ `[compile exit 0]`, prints **`4198488`**.

The same file with a declaration is correctly refused:

```vox
a number called zoo is 5.
Set zoo to "text now".
```
→ `error: cannot assign text to 'zoo', which is a number`, caret on line 2,
note on line 1.

**And it does not take a rewrite to reach it.** The name got no type at
all, so the very first read of one was wrong wherever the type mattered:

```vox
Set label to "hello".
Print label.
```
→ prints **`4198488`**. `Set ages to {"ann": 30}. Print ages.` prints the
map's heap address. `Print label's type.` answers `Number (dynamic)` — a
type the name never held, and `(dynamic)`, which LANGUAGE.md reserves for a
`value`.

**Root cause — one question asked of the wrong half of the compiler.**
`Set NAME to VALUE.` parses into `Statement::VarDecl` with `var_type: None`
(`src/parser/declarations.rs:462-465`, whose own comment reads "`Set point
to 42.` brings a variable into being where none stood"). Whether such a
statement is a *declaration* or a *write* decides whether the type lock at
LANGUAGE.md's "Type Immutability" applies, and the analyzer asked
`is_variable_declared_anywhere` — the whole-program question
(`src/analyzer/statements.rs:541`). But `collect_definite_decls`
(`src/parser/ast.rs:800-808`) counts an untyped `Set` as a definite
declaration, so the name is in `global_variables` from the first statement
and the answer is already "already declared" **on the very statement that
creates it**. The declaration branch was therefore never taken:
`scalar_types` never learned the type, `check_type_lock`
(`src/analyzer/types.rs:1664-1670`) resolves no declared type and returns
"allow", and `src/codegen/statements.rs`'s inference arms — which label a
slot from a list literal, a float, an argv/environ read or another
variable — have no arm for a plain text or map literal, so `variable_types`
stayed empty and every read fell through to the integer formatter.

The same one question poisons the other two spellings, which is why the
bug is not confined to `Set`. `the NAME is VALUE.` and `NAME is VALUE.`
parse into `Statement::Assignment`, whose arm asked the same whole-program
question — so a single untyped `Set` **anywhere in the file**, including
below, made the earlier `the`/bare write look like a reassignment of a name
nothing had declared. `the zoo is 5.` followed by `the zoo is "text now".`
is correctly rejected; adding a `Set zoo to 7.` further down made the
rejection vanish. It also cost a correct program its compile: with the
name never entered into the walk's own scope, a read between the write that
really declared it and that later `Set` was reported as `'tally' is used
before it is declared`.

**The fix: an untyped write on a name that does not exist yet is a
declaration, and a declaration fixes the name's type.**

1. **The question** (`src/analyzer/statements.rs`). Both arms now ask
   `is_variable_available` — read before the statement declares the name,
   so it means "did this name exist HERE, before this line?" — which is the
   question the walk can answer and the whole-program set cannot. Inside a
   function body the two answers are identical (the scope is seeded with
   `global_variables` there), so #79's function case is untouched.
2. **The type** (`src/analyzer/types.rs`, `bind_untyped_declaration_type`).
   One helper, shared by both arms, records the value's type in
   `scalar_types` and the declaration's own site in `declared_locations`.
   That is what gives `check_type_lock` something to check every later
   write against; it reuses the existing diagnostic verbatim.
3. **The slot** (`src/codegen/vars.rs`, `declare_untyped_from_value`, called
   from the `VarDecl` and `Assignment` arms of `src/codegen/statements.rs`).
   The same declaration labels the storage — `variable_types` so the value
   renders as its own type, and `declared_types` so `NAME's type` answers
   `(static)` from the declaration like every other statically-typed name
   rather than off a runtime tag byte only a `value` ever writes. It only
   ever fills a gap: a name that already carries a type keeps it, so no
   write can retag a slot out from under an earlier read even if the lock
   were reopened.
4. **The caret** (`src/analyzer/scope.rs`, `find_declaration_location`).
   The declaration-site search had no `Set NAME to` pattern at all, and
   took the first pattern that matched anywhere rather than the earliest
   match in the file — so a `Set`-declared name's declaration was reported
   as whichever later line rewrote it, which put the new error's caret on
   the declaration and its "was declared at" note on the offending write,
   backwards. It now searches every spelling that can bring a name into
   being and takes the earliest, keeping the code-before-text-literal
   guarantee of #46 by running the whole search as two passes.

**The matrix, each row its own program, measured on a clean `git archive
527cb89` extract and on the fix:**

| program | before | after |
|---|---|---|
| `Set zoo to 5.` then `Set zoo to "text now".` | prints **`4198488`** | compile error, caret on the write |
| `Set zoo to 5.` then `the zoo is "text now".` | prints **`4198488`** | compile error, caret on the write |
| `the zoo is 5.` then `Set zoo to "text now".` | prints **`4198488`** | compile error, caret on the write |
| `Set label to "hello". Print label.` | prints **`4198488`** | prints `hello` |
| `the greeting is "hello". Print greeting.` | prints **`4198536`** | prints `hello` |
| `motto is "carry on". Print motto.` | prints **`4198542`** | prints `carry on` |
| `Set ages to {"ann": 30}. Print ages.` | prints a **heap address** | prints `{"ann": 30}` |
| `roster is ["ann", "bo"]. Print roster.` | prints a **heap address** | prints `["ann", "bo"]` |
| `Set label to "hello".` in a format hole | prints **`the label is 4198488`** | prints `the label is hello` |
| `Set label to "hello". Print label's type.` | `Number (dynamic)` | `Text (static)` |
| `Set tally to 5. Print tally's type.` | `Number (dynamic)` | `Number (static)` |
| `Set ratio to 2.5. Print ratio's type.` | `Float (dynamic)` | `Float (static)` |
| `Set ready to true. Print ready's type.` | `Number (dynamic)` | `Boolean (static)` |
| `tally is 5. Print tally.` with a `Set tally to 7.` below | **rejected**, "used before it is declared" | prints `5` then `7` |
| `Set tally to 9.` then `a text called tally is "x".` | prints `x` | compile error, the two declarations conflict |
| `Set zoo to 5.` then `Set zoo to 7.` (control) | prints `7` | prints `7` |
| `Set tally to 9.` then `a number called tally is 5.` (control, test 518) | prints `5` | prints `5` |
| `a number called zoo is 5.` then `Set zoo to "x".` (control) | compile error | compile error, byte-identical |
| `a value called v is 5.` then `Set v to "text now".` (control) | prints `text now` | prints `text now` |
| `Set tally to 3.` inside a function (control) | prints `3` | prints `3` |

**LANGUAGE.md, one sentence.** "Two Canonical Forms" listed only the
spellings that name a type, and nothing in the manual said an untyped
`Set`/`the`/bare write may create a name — the parser has always intended
it, and a reader had no way to know what type the name took or whether it
was locked. The first canonical form's bullet now says it: on a name that
does not exist yet the type noun is optional, the three spellings each
bring the name into being with the value's type, and it is fixed from then
on like any other declaration's.

**What this does not change.** An untyped declaration of a `list` or `map`
still is not registered as a collection *name*, so `items's length` after
`Set items to ["a", "b"].` is refused with "Property 'size' requires a
buffer, list, map, or file variable". That refusal is identical for all
three untyped spellings, was identical before this fix, and is not part of
this entry — the collection reads and writes it, prints as one, and reports
`List`; only the property path does not know it. Left for its own
adjudication.

**Family.** #79 (the same split between "the name exists" and "its type is
known", one scope out — the read side; its `is_variable_declared_anywhere`
is the function this entry re-aimed), #66 (the same split one scope in),
#57, #65 and #72 (the type lock's other holes — an initialiser of the wrong
type, `nothing`, a provable missed read), #51 and #87 (what a bare
assignment means when the source is a buffer, which this fix leaves
untouched), #46 (the code-before-text-literal rule the declaration-site
search keeps), and #42 (`Text (dynamic)` from a tag that disagreed with the
slot).

**For the fuzzer.** Any generator that emits `Set NAME to VALUE.` on a
fresh name now has a locked type to respect from that statement on: a
second write of another type is a compile error, in every spelling, and is
no longer a way to produce a program that runs and prints something wrong.
The three untyped spellings are interchangeable as declarations, which is
one more shape a declaration leaf may draw.

**Resolved by #96.** Josj ruled Option B on "The parse half" above: a `To`
reached while a clause is still open is now a compile error, not a
force-closed clause, which also closes "A related blind spot" just above
(the swallow it depended on can no longer happen). The eight regression
tests this entry added (`442`-`449`) exercised the ABI fix on a program
shape that no longer compiles, so #96 removes them and replaces their
coverage with compile_fail tests proving the shape is now refused.

---

### 96. A `To` (function definition) inside a still-open `If`/loop/function body was parsed into that body instead of refused, silently moving every following statement's control flow

**Status:** **fixed** in 0.4.11. Severity: **insufficient compile-time
coverage** (Josj's framing, 2026-08-23) — a program shape that should be
rejected was instead silently mis-parsed; no runtime or codegen change (the
assembly is already correct either way, `vox-notes/ASM-ANALYSIS-96.md`).
Regression tests: compile_fail `265`-`269` (a loop body, an `If` body, a
clause nested inside another function's body, a `Library` declaration, and
the #73 §4 shadow-warning repro); run `560`/`561` (the blank-line-closed
and double-period forms still compile and run once). Superseded run tests
`442`-`449` (see "Family" below): they exercised #73's ABI fix for a
program shape this entry now refuses at parse time, so they no longer
compile and are removed.

Found by the round-4 candidate audit, `vox-notes/REPORT-CANDIDATES-ROUND-4.md`
§4 ("#73 incidental (1)", the Stage A4 shadow-warning blind spot) and
design question 1 (`vox-notes/DESIGN-QUESTIONS-FOR-JOSJ.md`); Josj ruled
Option B in `vox-notes/DESIGN-RULINGS.md` (2026-08-23): "function
declarations are not supposed to be nestable... through a compiler error."

```vox
For each n from 1 to 3,
    If n is 99 then, Break.
To examine with a value called v.
    Print "{v's type}".

examine of "".
Exit 0.
```
→ compiled clean and printed `Text (dynamic)` three times: the `To` was
parsed as a nested statement of the still-open `For each` body, so the call
after it was drawn into the loop and ran once per iteration.

The manual said both things at once. Its termination rule named only a
period and a blank line as closers, so by that rule a `To` belonged to the
open body; the note just above it said "a following `To` or `Library`...
ends the body," but only of a *function's own* body; and the sibling
`thing` rule (LANGUAGE.md, "Definitions are top-level only") already made
the identical shape a compile error for `thing`, with no matching guard on
`To`.

**Root cause.** `Token::To => self.parse_function_def()`
(`src/parser/statements.rs`) had no top-level guard, unlike
`parse_thing_definition` (`src/parser/things.rs`), which already calls
`self.at_top_level()` before accepting a `thing`. `parse_library_decl`
(`src/parser/functions.rs`) had the identical gap: `Library mathkit version
"1.0".` reached while a clause is open was silently swallowed too, on a
plain non-shared compile (there is no shared-library check to catch it
there, since that check only runs in `--shared` mode).

**The fix.** One `if !self.at_top_level() { return Err(...) }` at the head
of `parse_function_def` and of `parse_library_decl`, reusing
`at_top_level()` (already used by `things.rs`) and mirroring its message
shape: name the construct, state the canonical form, say to move the
definition above the block. The guard fires on `statement_depth`, not on
any textual heuristic, so it is exactly as forgiving as the manual's own
termination rule: a blank line or a stacked period (`Break..`) that closes
the enclosing clause first leaves the following `To`/`Library` genuinely
at the top level, and both forms still compile and run (tests 560, 561).
The pre-existing, unrelated leniency that lets a function's own unclosed
body end on a following `To`/`Library` with no blank line
(`src/parser/functions.rs`'s body-parsing loop, guarding against
BUGS_FOUND #5) is untouched: that mechanism decides the next `To` is never
dispatched as a nested statement in the first place, so the new guard
never sees it as nested.

No codegen changed: `vox-notes/ASM-ANALYSIS-96.md` shows the swallowed and
blank-line forms emit byte-identical code for the function itself, and the
only difference is where the trap places a caller's statement (inside the
loop instead of after it); a parse-time rejection removes the trap
program, not any correct one.

**Closes the #73 §4 shadow-warning blind spot.** A definition swallowed
into an open clause used to shadow an imported library function with no
warning, because the Stage A4 shadow loop (`src/analyzer/statements.rs`)
scans only the flat top level while its neighbour twenty lines above
already descends through `nested_function_defs`. Since the swallow is now
refused at the `To`, the shadow check never has a swallowed definition to
miss. Compile_fail `269` reproduces the report's own repro
(`consumer_swallowed.vox`: a definition inside a `For each` shadowing a
`see`n `greet`) and confirms it now errors before the shadow check ever
runs, instead of compiling silently.

**`Library`, checked.** The `.lib`/`--shared` section already documents
`Library` as top-level only ("Only function definitions, `Library`, and
`see` may appear at the top level of a `--shared` compile"), and
`src/parser/functions.rs` already treats `Token::To` and `Token::Library`
identically for the "ends an open function body" leniency. A nested
`Library` was reachable and silently swallowed outside `--shared` mode (a
`--shared` compile's own top-level-statement check flags the enclosing
`If` first, not the `Library`, so this exact shape was unreachable there;
a plain non-shared compile had no such check at all). Guarded the same way
(compile_fail `268`). `see` is unaffected: it is not a definition, and
`things.rs`'s own guard does not extend to it either, so this entry does
not touch it.

**Family.** #73 (the codegen ABI fix for the same swallow; its regression
tests 442-449 exercised a program shape this entry now refuses, so they
are removed, see the note added to #73's entry), #46 (the caret lands on
the offending token, `To` or `Library`, because the guard runs before
either is consumed).

---

### 97. A text appended into a caller's list through a `list` parameter reads back as its address — the heterogeneous verdict stopped at the callee's own parameter

**Status:** **fixed** in 0.4.11. Severity: **wrong answer**, and **memory
safety** across a `.lib` boundary (see "The shared-library corner" below).
Regression tests:
`tests/550_a_text_appended_through_a_parameter.vox`,
`tests/551_a_widened_list_reads_back_every_way.vox`,
`tests/552_a_proven_list_keeps_its_fast_path.vox`,
`tests/553_a_buffer_and_a_map_through_a_parameter.vox`,
`tests/554_a_list_widened_along_a_chain_of_helpers.vox`,
`tests/555_a_widened_list_through_recursion_and_an_alias.vox`,
`tests/556_a_global_widened_through_a_shadowing_parameter.vox`,
the `see/list-parameter` case in `test.sh` over
`tests/shared/noting_lib.vox`, and four codegen unit tests in
`src/codegen/tests.rs`.
Found by the #75 fix report as incidental (2), 21–22 Aug 2026; separated
out and adjudicated by the candidate audit of 2026-08-23
(`vox-notes/REPORT-CANDIDATES-ROUND-4.md` §5), verified by the master the
same day (`vox-notes/VERIFIED-ROUND-4.md` §97) and approved by Josj that
day, with the fix shape ruled to be **(A), the caller widens**.

```vox
To 'note whatever' with a list called noted and a text called label.
  append label to noted.

a list called noted is [].
'note whatever' of noted and "tail".
Print "last: {noted's last}".
```
→ **`last: 4198536`** — the text's address, printed as a number.

The working neighbour is the same append written at the caller:

```vox
a list called noted is [].
append "tail" to noted.
Print "last: {noted's last}".
```
→ `last: tail`.

**Where it comes from.** `prescan_mixed_lists`
(`src/codegen/collections.rs`) walks each function body on a *snapshot* of
the global pre-scan state and partitions the verdict per function, so a
function's own locals never leak into another's analysis. A `list`
parameter is one of those locals. The callee's `append label to noted` is
therefore attributed to the callee's parameter and dropped when the
snapshot is restored; the caller's `noted` is left with the verdict it had
before the call — for `[]`, no proven element type at all. The caller then
reads `noted's last` off the untagged fast path and hands the raw stored
word to the integer formatter.

The slot itself was never wrong. `_list_append` takes the element's tag in
`dl` and stores it in the list's tag array on **every** append
(`coreasm/x86_64/list.asm:361`), and the callee emits the right one —
`mov edx, 1  ; element type tag` for a `text` parameter. The bug is
entirely on the read: the caller had proven something the callee's write
made false, and never learned.

**What the manual says.** Mixed-Type Lists, LANGUAGE.md:

> The compiler earns the homogeneous fast path by **proof**, not
> assumption. A value whose type it cannot statically prove widens the list
> to mixed, so reads dispatch on each slot's runtime tag rather than on one
> assumed type.

and, in the same section:

> Appending, `set element`, `element N of`, `first`/`last`, iteration, and
> `{...}` format interpolation all respect each element's actual type.

Both are wrong here in the same direction: the compiler took the fast path
on a list it had *not* proven homogeneous, and `first`/`last` did not
respect the element's actual type. **No LANGUAGE.md change was needed** —
the first sentence is exactly the rule the fix implements.

**The reading in which the compiler is right, and why it does not reach
this output.** Vox lists dispatch statically, and the choice must be made
where the read is written — in the caller. To know the list is mixed the
caller would have to see inside every callee it hands the list to, which is
whole-program analysis and is impossible past a `.lib` entry that has no
body. That argument is sound as far as it goes, and it is why codegen
partitions per function in the first place. But what it supports is
*refusing* the callee's append, or *widening the caller's list at the call
site* — a one-level, intra-program question, and codegen already runs
several whole-program pre-passes of exactly that character
(`collect_definite_decls`, `collect_literal_collection_shapes`,
`collect_constant_numbers`, `collect_global_declared_types`). Nothing in it
makes printing a pointer as a number the right answer. Josj ruled for the
widening: refusing the callee would forbid a reasonable, readable program —
a helper that collects into whatever list it is given.

**The fix — the caller widens.** A new pre-pass,
`collect_list_param_writes` (`src/codegen/collections.rs`), records for
every function what a call writes into the caller's list through each
`list` parameter, as one of three verdicts: no write, one proven tag, or
`Unknowable`. `prescan_walk` then joins that verdict into the caller's list
at each call site: the list is widened to mixed **unless** the callee
provably writes the one tag the caller has already proven the list holds.
Reads of a widened list dispatch on each slot's runtime tag, which was
always there.

Three properties fall out of doing it this way:

- **The fast path survives where it is earned.** A list the function only
  reads is untouched; a list proven to hold numbers, handed to a function
  that appends a `number` parameter, keeps its untagged path. `tests/552`
  emits no tag dispatch at all.
- **It is transitive.** A helper that hands its own `list` parameter on to
  a second helper inherits what that one writes, and the verdict loop runs
  to a fixed point, so a chain of helpers, direct recursion and mutual
  recursion all settle. A local the callee declared as an alias of its
  parameter is the same block, so a write through it counts too.
- **It is conservative where it cannot prove.** A callee that appends a
  body-local, or a call result, reads `Unknowable` and widens. The output
  is right either way — the tagged path is always correct — and only the
  fast path is lost.
- **It survives name shadowing.** The pre-scan walks each function body on
  a snapshot precisely so two same-named things keep opposite verdicts, and
  the widening is applied inside that walk, so it lands on the caller's
  list — a global two calls away included — and not on a callee parameter
  that happens to carry the same name.

`set element N of` through a parameter goes through the same join, so
`tests/551`'s number list given a text in slot 1 reads slot 1 back as
`one` and slot 2 as `2`.

**The shared-library corner — and the segfault it was hiding.** A `.lib`
carries types, not bodies. The chosen policy is the conservative one: every
`list` parameter of an imported function widens the caller's list
unconditionally. The alternative — trusting what the `.lib` already says —
was measured and rejected, because the `.lib`'s `list of <type>` is an
element-type inference, not a record of what the function writes:

```vox
To 'stash a local' with a list called noted.
  a list called borrowed is ["borrowed"].
  append element 1 of borrowed to noted.
```
renders in the `.lib` as bare `` `a list called noted` `` — no element type
— while it does append a text into the caller's list. A consumer trusting
the `.lib` would leave that list on the fast path, which is this same bug
one boundary over. Recording "this function widens its list parameter"
would mean changing the `.lib` format, and no evidence yet asks for it.

The corner was worse than the local case. `list of text` is promised to
**every** caller, including one whose list holds numbers:

```vox
see noting version "1.0" from "./libnoting.lib".

a list called stashed is [].
'stash a local' of stashed.
Print "stashed: {stashed's last}".

a list called tally is [1, 2, 3].
'note whatever' of tally and "four".
Print "tally first: {tally's first}".
```
On 0.4.10 this prints `stashed: 139735983992975` and then **segfaults
(139)** — the caller believed the `.lib`'s `list of text`, read the integer
`1` as a `char*`, and dereferenced it. With the widening it prints
`stashed: borrowed`, `tally first: 1`, `tally last: four`. That row is in
the `see/list-parameter` test.

**The neighbours, measured.** Each row its own program, on a clean
`git archive 527cb89` extract (= 0.4.10) and on the fix:

| program | before | after |
|---|---|---|
| text appended through a parameter, `'s last` | **`4198536`** | `tail` |
| the same, `'s first` | **`4211090`** | `first entry` |
| the same, `element 2 of` | `second entry` | `second entry` |
| the same, iteration | `first entry` / `second entry` | unchanged |
| the same, whole-list `Print` | `["first entry", "second entry"]` | unchanged |
| `set element 1 of` a number list to a text, then `'s first` | **`4211165`** | `one` |
| a buffer appended through a parameter | **`140202178994176`** | `buffered` |
| a list appended through a parameter | **`140202178985984`** | `[1, 2]` |
| a two-argument helper, the widened list | **`4198536`** | `hello` |
| the same, the list given a number (control) | `99` | `99` |
| a chain of two helpers | **`4198557`** | `chained` |
| the call written as an initialiser | **`4198575`** | `held` |
| the call written inside a `{...}` hole | **`4198575`** | `held` |
| mutual recursion, `'s last` | **`4202637`** | `pong` |
| a write through an alias of the parameter | **`4202692`** | `aliased` |
| a global widened by a call inside another function | **`4198536`** | `reached the global` |
| the same, a global given its own proven type (control) | `3` | `3` |
| a `.lib` function that widens, `.lib` says bare `list` | **`139735983992975`** | `borrowed` |
| a `.lib` `list of text` onto a caller's number list | **segfault (139)** | `1` / `four` |
| direct recursion, whole-list print (control) | `[3, 2, 1]` | `[3, 2, 1]` |
| a map given a text through a parameter (control) | `written` | `written` |
| a number list read only by the callee (control) | `3` | `3` |
| a number list given a number by the callee (control) | `30` | `30` |
| a text list given a text by the callee (control) | `bea` | `bea` |

Fourteen of twenty-four faulted or printed an address; the seven controls
and the three rows that already read the tag are byte-identical.

**Why `element N of`, iteration and the whole-list print already worked.**
They read through paths that consult the slot tag (or `_list_print`, which
always does), while `'s first` and `'s last` took the element type from the
caller's static verdict. That is why the defect looked narrower than it
was: the same list answered the same question two ways depending on which
spelling asked it, which is exactly what LANGUAGE.md's "all respect each
element's actual type" forbids.

**A map does not share the path.** A map slot always carries its value's
tag, so `Set <map>'s "<key>" to` through a `map` parameter already read
back as what it is, before this fix and after. `tests/553` pins that it
still does.

**Family.** #75 (a list or map grown through a parameter stops at the
literal's capacity — the same parameter, the storage half), #90 (a buffer
grown past its capacity through a parameter is a use-after-free — the same
parameter, the memory half), and #87 (a buffer in a `value` carries its
struct pointer, not its bytes). Those three are about what crosses the call
*into* the callee; this one is about what the caller believes *after* it
returns. Also #45, and the stage-1b rule it settled ("static is a
proof; mixed is the default") which `tests/155_unknowable_append_widens.vox`
pins — this entry extends that rule from one function to the call edge.

**For the fuzzer.** Any leaf that builds a list and reads it back can now
also draw the shape "hand it to a function that appends to it" — the
invariant is unchanged (the element reads back as what it is), and the
generated program no longer has to keep every append in one function to be
correct. A leaf drawing a `.lib` consumer may pass a list to an imported
function without pinning the element type first.

### 98. An unrecognised format specifier is silently discarded — `{n:q}`, `{n:#x}` and `{n:zzz}` render as a bare `{n}`, no warning, no error

**Status:** **fixed in 0.4.11**. Severity: **silent, no diagnostic** — a
typo in a format spec (the obvious `#x` for hex) compiles clean and prints
the wrong thing with nothing to say so. Regression tests:
`tests/541_unknown_specifier_fix_leaves_valid_forms_alone.vox`,
`tests/compile_fail/252_unrecognised_format_specifier_q.vox`,
`tests/compile_fail/253_unrecognised_format_specifier_hash_x.vox`,
`tests/compile_fail/254_unrecognised_format_specifier_zzz.vox`. Found while
checking candidate 7 during the round-4 audit (`c7-badspec.vox`,
`vox-notes/REPORT-CANDIDATES-ROUND-4.md` §N1); reproduced and verified by
the master 2026-08-23 (`vox-notes/VERIFIED-ROUND-4.md` §#98); approved by
Josj the same day (WhatsApp: "all are real bugs … please get those fixed
for vox 0.4.11").

```vox
a number called n is 255.
Print "{n:q}|{n:#x}|{n:zzz}|{n:x}|{n:8}|".
```
→ **`255|255|255|0xff|     255|`** — the first three holes are not
specifiers Vox defines at all (not a width, not a precision, not a base
letter) and each renders as if the `:SPEC` were never written; the last two
prove the spec parser is working when it does recognise the text.

**Root cause.** The base-specifier match at the end of `read_format_spec`
(`src/codegen/format.rs`, formerly lines 661–666) is:

```rust
match remaining {
    "x" => spec.base = IntegerBase::HexLower,
    "X" => spec.base = IntegerBase::HexUpper,
    "b" => spec.base = IntegerBase::Binary,
    "o" => spec.base = IntegerBase::Octal,
    _ => {
        if has_width { spec.base = IntegerBase::Decimal; }
    }
}
```

The catch-all accepts anything: no `FormatSpecFault` comes out of it, so
nothing downstream — codegen or the analyzer — can ever report the text was
wrong. The Format Specifiers table (LANGUAGE.md's specifier table) is a
closed enumeration, and the section's own principle for a specifier the
compiler cannot honour is stated twice, once for an over-large count and
once for the wrong type: a compile error naming the way out, "not a width
that quietly does nothing" and "not a wrong answer". A specifier that
matches nothing in the table is the same wrong under that principle — it
was just the one case the catch-all still let through.

**The fix.** A new `FormatSpecFault::UnknownSpecifier(String)` variant
carries the clause exactly as written; the catch-all raises it whenever
`remaining` is non-empty, matches none of the base letters, and no
more-specific count fault (`WidthTooLarge`/`PrecisionTooLarge`) already
claimed the spot. The analyzer (`check_format_spec`,
`src/analyzer/expressions.rs`) turns it into a named diagnostic, riding the
same path #46/#61/#85 already built for a spec fault: quote what was
written, caret on the `:SPEC` clause, and a `help:` line listing the actual
forms (a width, a zero-padded width, a decimal precision, and the four base
letters, alone or with a width):

```
error: 'q' is not a format specifier Vox knows
  --> n1-repro.vox:2:11
  |
2 | Print "{n:q}|{n:#x}|{n:zzz}|{n:x}|{n:8}|".
  |           ^--- here
  |
  help: the specifiers are a width (`N`), a zero-padded width (`0N`), a
  decimal precision (`.N`), and a whole number's base - `x` (hexadecimal),
  `X` (hexadecimal, uppercase), `b` (binary) or `o` (octal), which a width
  can precede (`04x`). Drop the specifier to render the value plainly.
```

`{n:#x}` and `{n:zzz}` are each refused the same way, caret on their own
clause. `codegen`'s `parse_format_spec` keeps dropping the fault exactly as
it already dropped `WidthTooLarge`/`PrecisionTooLarge` — the analyzer has
already refused the program by the time codegen would see it.

**A boundary this fix does not move.** A width followed by a `.` that is
not itself a count — `{n:8.}`, `{n:8.2z}` — stays the quiet no-op it was
before #85 settled that shape (`read_format_spec`'s own test,
`a_width_followed_by_something_that_is_not_a_count_is_not_a_fault`): the
new fault only fires when `remaining` does not start with `.`, so that
already-settled boundary is untouched.

**Found in the wild.** `examples/format_strings.vox` already carried three
live instances of exactly this bug: `{small:<6}`, `{small:>6}` and
`{small:^6}`, labelled "Left aligned" / "Right aligned" / "Center aligned".
Vox has no alignment specifier — the table has a width and a zero-padded
width and nothing else — and all three silently rendered as the bare,
unpadded `[42]`, which the shipped example printed and called "aligned".
The example now shows only the padding forms that are real; the false
alignment lines are removed rather than made to compile, since nothing in
LANGUAGE.md ever promised them.

**Family.** #45/#62/#63 (name what the author wrote and the way out, the
house standard this diagnostic follows), #46 (the caret-on-the-spec
anchoring this reuses), #61 (`WidthTooLarge` — the sibling fault for a
count past what Vox can hold), #71 (a specifier the value's *type* cannot
answer — this entry is the specifier itself not existing, one check
earlier), #85/#86 (the format-spec fault family this variant joins).

**LANGUAGE.md.** Line 3289 stated the rule for a specifier the wrong
*type* asks for, but never said what happens to a clause that is not in
the table at all — the same gap this entry closes in the compiler. One
line, run long rather than split, states both:

> **A specifier has to be one in the table, and one the value's type can
> answer.** A clause after the colon that is none of them is a compile
> error naming the valid forms. A width asks nothing of a type: …

Nothing new is promised beyond what the section's own principle already
implied for the other two cases (an over-large count, the wrong type); this
is the sentence naming the third.

**Incidental.**
- The manual's specifier table and the compiler's now agree on every entry
  checked; no other disagreement found.
- An empty spec, `{n:}`, is not ruled on anywhere in LANGUAGE.md — the
  table lists specifier *shapes*, not what a bare trailing `:` with nothing
  after it means, and no sentence elsewhere addresses it either. Left as
  before (renders exactly as a bare `{n}`) rather than guessed at; a ruling
  belongs to Josj, not to this fix.
- A sibling silent gap exists one branch earlier: `read_format_spec`'s
  leading-`.` path (`fmt_str.starts_with('.')`) returns immediately when
  what follows is not a count, so `{n:.z}` also renders as a bare `{n}`
  with no diagnostic — the same family as this entry, but outside the
  catch-all this fix targets and guarded by the same "not a count" boundary
  #85 already settled for `8.`/`8.2z`. Not fixed here; flagged for its own
  entry rather than widening this one.


---

### 99. A bare `.lib` name in `see` never finds an installed interface — `/usr/include/vox` is not in the search order, though every doc says installed interfaces live there

**Status:** **Fixed in 0.4.12** — logged 2026-08-23 on Josj's instruction,
verified by the master the same day (minimal repro below re-run against vox
0.4.11 and the installed vox-libs 0.2.0). Severity: **usability / doc-behaviour
mismatch** — every consumer of an installed library must pass
`--lib-path /usr/include/vox` by hand, which no documentation tells them
and the language designer expected not to be needed ("no path, should auto
resolve" — Josj, 2026-08-23).

**Repro.** With vox-libs installed (`json.lib` in `/usr/include/vox`,
`libjson.so` in `/usr/lib64`):

```vox
see json version "0.1" from "json.lib".
Print 'to json' of 42.
```

```
$ vox consumer.vox -o consumer
Error: could not find the library interface file 'json.lib'.
Paths tried:
  json.lib
Use --lib-path <dir> to add directories to this search.
```

The same program with `--lib-path /usr/include/vox` compiles, links
dynamically (`NEEDED [libjson.so]`, resolved via the `.lib`'s `Location`),
and runs correctly.

**Why it is a bug and not a reading.** LANGUAGE.md's search-path rule for a
`.lib` ("relative or bare, it is tried against the containing file's
directory first and then each `--lib-path` directory") is implemented
faithfully — but it contradicts the rest of the project's own story:
`docs/INSTALL.md` installs interfaces into `/usr/include/vox/` and calls it
where consumers find them; `man vox` lists `/usr/include/vox/*.lib` under
FILES as "interface files of installed Vox libraries"; and a bare `.vox`
source include DOES get a system default (`/usr/share/vox/lib` is checked
first). The `.lib` shape is the one kind of `see` with no system location,
which makes `sudo make install` produce libraries nothing can find without
a flag.

**Incidental, fix together:** the emitted `RUNPATH` copies every
`--lib-path` directory verbatim, so an interface directory ends up on the
runtime library search path (`RUNPATH [/usr/include/vox:/usr/lib64]`
observed). Interfaces and shared objects are different search spaces.

**Agreed fix shape (awaiting Josj's "fix #99" to start):** append
`/usr/include/vox` as the FINAL step of the `.lib` search order — containing
directory, then `--lib-path`, then the system directory — so a development
`.lib` beside the source or on `--lib-path` always shadows the installed
one (the deliberate inverse of the coreasm resolution order, whose
system-first trap is documented in the man page). Its `Location` `.so`
resolves as today. RUNPATH gains only directories that actually contain a
resolved `.so`. LANGUAGE.md:~5125 gains the one sentence; the error's
"Paths tried" lists the system directory too.

**Found by** the master's smoke test of the installed json library
(vox-libs 0.2.0), 2026-08-23, immediately after `make install` — the first
ever consumer of an installed Vox library from outside the vox-libs tree.

**Fixed**, exactly the agreed shape. `src/lib_file.rs`'s `resolve_lib_file`
now searches a bare or relative `.lib` name through a new `search_lib_paths`:
containing directory, then each `--lib-path`, then `crate::INSTALLED_LIB_DIR`
(a named constant in `src/main.rs`, next to `find_coreasm_path`'s own
`system_paths`, with a comment cross-referencing this entry and spelling out
why the order is the inverse of coreasm's). `resolve_location` (the `.lib`'s
`Location` `.so`) is untouched — a `.so` still has no system search step.
Absolute `.lib` paths are untouched too: they never entered a search list at
all. The not-found diagnostic's "Paths tried" now lists the system directory
because `search_lib_paths` puts it in the same `tried` vector the error
renders from — no separate message to keep in sync.

The RUNPATH half: `src/main.rs`'s executable link path (the non-`--shared`
branch) used to add `-rpath` for *every* `--lib-path` directory unconditionally.
That is now gated on `!link_libs.is_empty()` — `--link`'s documented behaviour
(LANGUAGE.md ~5459) keeps it, since `--link` names a `.so` by soname stem
alone and the compiler never learns which `--lib-path` directory it actually
lives in — while a `see` import instead relies on `import_rpaths`, built
per-import from the resolved `.so`'s own canonicalized directory, which was
already correct and unconditional. So a `--lib-path` that holds only `.lib`
interface files (the installed-library case: `/usr/include/vox` has no `.so`
in it) no longer reaches RUNPATH at all. The `--shared` build path was
already correct — it only ever added `import_rpaths`, never blanket
`--lib-path` — so it needed no change.

LANGUAGE.md gained the system directory as the stated final search step in
both the `see` "Search paths" paragraph (~5124) and the "Consuming a library"
numbered resolution list (~5300), present tense, on the existing lines.

**Tests.** Rust unit tests beside the resolver (`src/lib_file.rs`): the
ordered candidate list for a bare and for a relative name ends with the
system directory (using a probe name that is deliberately not a real
installed library — this dev box has vox-libs' `json.lib` genuinely
installed, so a test asserting "not found" against that name would pass or
fail depending on the box); an absolute path's error never mentions the
system directory; `resolve_location` errors never mention it either. Integration,
in `test.sh`'s shared-library style (`run_see_installed_lib_search_test`,
built on two new fixtures, `tests/shared/shadow_local.vox` and
`shadow_libpath.vox`, that answer differently so the test can tell which
copy actually linked): a `.lib` in the source's own directory wins over an
identical `<lib,version>` on `--lib-path`; a `--lib-path` `.lib` resolves
with no `/usr/include/vox` on the test box at all (proving the ordering
without needing the system directory to be real); a miss names all three
paths tried; and a `--lib-path` directory holding only a `.lib` (its
`Location` rewritten to an absolute path elsewhere) is proven absent from
`readelf -d`'s `RUNPATH` while the `.so`'s real directory is present. The
existing `run_see_diagnostics_test` "missing .lib" sub-case was extended to
also assert `/usr/include/vox` appears in that diagnostic. No numbered
`tests/*.vox` run case or `tests/compile_fail` case was needed: `.lib`
resolution is a driver-level (`main.rs`) step that runs before the analyzer
the `compile_fail` harness exercises, and a numbered run-test has no way to
pass `--lib-path`, so neither format could exercise this fix — the reserved
run 570+ / cf 275+ ranges go unused here.

---

### 100. A zero-width format specifier — `{n:0}`, `{n:00000}` — regressed to an unknown-specifier error in 0.4.11, though a width of 0 is a legal no-op

**Status:** **Fixed in 0.4.12**. Severity: **regression** — 0.4.10 compiled
and ran `{n:0}` and `{n:00000}` as a width of 0 (pad nothing); #98's fix,
which made an unrecognised specifier a compile error, swept these up with
it. Regression tests:
`tests/562_a_zero_width_specifier_is_a_legal_no_op.vox`,
`tests/compile_fail/270_zeros_then_junk_still_an_unrecognised_specifier.vox`.

```vox
a number called n is 42.
Print "[{n:0}]".
```
- **0.4.10:** compiles; prints `[42]`.
- **0.4.11:** `error: '0' is not a format specifier Vox knows`. Same for
  `{n:00000}`.

**Root cause.** `read_format_spec` (`src/codegen/format.rs`) reads a
zero-pad clause left to right: it strips every leading `0` off `remaining`
looking for the width's digits, then reads however many digits follow.
When the clause is nothing BUT zeros, stripping them leaves an empty
string — no digits follow, because there is nothing left to follow — so
the pre-#98 code left `width` unset and `remaining` untouched, and #98's
new catch-all (anything not consumed as a width, a precision or a base
letter is now a fault) caught the untouched `"0"` / `"00000"` as an
unknown specifier. #98's mandate was unknown LETTERS (`q`, `#x`, `zzz`);
zero counts were never part of that audit and nobody re-checked them
against the width rule until the fuzzer did.

**What the manual already said.** The width row, `{var:N}` → "Pad to N
characters", carries no floor on `N`; the only bound LANGUAGE.md states is
the top one, "a count the compiler can hold, at most
9223372036854775807" — zero is a count the compiler can hold. Nothing
anywhere said `N ≥ 1`. 0.4.10's behaviour and the manual's letter already
agreed; only the #98 fix disagreed with both.

**The fix.** The same branch now recognises "stripped every leading zero
and nothing is left" as its own case — a width of 0, not an absence of
one — rather than falling through unconsumed into #98's catch-all. It sets
`spec.width = Some(0)` and consumes the whole clause. Everything #98 was
actually written to catch is unmoved: a zero (or zeros) followed by
anything that is not a base letter — `{n:0q}`, `{n:00q}`, `{n:0x}` — is
still zeros-then-junk, still an unknown specifier, because the branch only
fires when nothing but zeros is left after stripping; a trailing letter
means something IS left, and the existing path (unchanged) carries it
through to the catch-all exactly as before. `{n:04x}` and every other
zero-padded width with a nonzero digit before its base letter never enters
the new branch at all, since `width_end > 0` for those and the original
path still runs first. Both were re-verified before and after: `{n:04x}`
still prints `[0x002a]`, `{n:0x}` still errors as an unknown specifier — a
bare `0x` has no width digit at all, so it was never a case this fix
touches.

**Found by** the fuzzer's own CI, on the pull request that re-pinned
vox-fuzz's CI to compile against 0.4.11
(`Vox-lang/vox-fuzz#56`): `280_gen_literals` emits format specifiers with
random widths, one of which rolled zero, and the run that had passed every
week since `random-unless-ruled` failed the moment CI built against the new
compiler — a regression in a fix, caught by the fuzzer catching itself, the
system working as designed. Verified by the master 2026-08-23
(`vox-notes/VERIFIED-ZERO-WIDTH-SPECIFIER.md`); ruled by Josj the same day:
"I completely agree width 0 is a legal no-op."

**Family.** #98 (the fix this narrows — its mandate was unknown letters,
never zero counts, and this entry is the correction, not a reversal),
#85/#86 (the format-spec fault family both belong to), #61 (`WidthTooLarge`
— the sibling fault for a count past what Vox can hold, on the same
`read_format_spec` function).

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

### 102. `Create a list called X.` (and `a list called X.` / the list default on a branch-declared name) emits a bare `HEAP_ALLOC` with `heap.asm` never included, so the program fails to assemble

**Status:** fixed in v0.4.14. Regression test:
`tests/563_no_initializer_list_default.vox`. Severity: **wrong rejection** — a
documented no-initializer `list` declaration compiled to invalid NASM.

```vox
Create a list called items.
Print "ok".
```

→ `NASM assembly failed` / `VAR-07.asm:44: error: instruction expected,
found 'HEAP_ALLOC 96'`. The manual documents this exact construct —
LANGUAGE.md:521-529:

```
Create a list called items.     (items is [])
```

and the `map` sibling (`Create a map called m.` → `m is {}`) compiles and
runs. The `list` equivalent used to assemble too — the probe
`vox-fuzz/docs/ledger/probes/variables/VAR-07.vox` was recorded green at
ledger commit `e10c36e` and now fails the probe re-run.

**Root cause.** A no-initializer declaration goes to codegen's
`emit_type_default` (`src/codegen/vars.rs:503`), whose `Type::List` arm
synthesizes an empty list literal:

```rust
Type::List(_) => {
    self.emit_empty_value_for(VarType::List);
    ...
}
```

`emit_empty_value_for(List)` calls `generate_expr(&Expr::ListLit{..})`,
and the empty-list literal codegen (`src/codegen/expr.rs:1015`) emits
`HEAP_ALLOC 96` **directly in the program body**. But `%include
"coreasm/x86_64/heap.asm"` is gated on `program.uses_heap`
(`src/codegen/statements.rs:151`), and the analyzer sets `uses_heap`
only when it walks a real `ListLit`/`MapLit` *expression*
(`src/analyzer/expressions.rs:1014`). The no-initializer default path
never walks one — so the macro the body calls is never defined.
`Type::Map` is immune because its default goes through `_map_new`,
which lives in `map.asm`, pulled in by `uses_maps`; the `list` default
is the one direct `HEAP_ALLOC` in this path.

Introduced in `fd5348a` (0.4.13, the coreasm macro-extraction sweep that
turned the empty-list-literal's raw `mmap` into the `HEAP_ALLOC` macro).
Before that the list default emitted the mmap syscall inline, needing no
included macro, which is why the probe was green through 0.4.12. The
sweep moved the allocation behind `HEAP_ALLOC` (defined in `heap.asm`)
without wiring the default path to set `uses_heap`. The probe re-run on
0.4.13 caught it within a day of the release.

**Also hit by:** `a list called x.` (the bare no-initializer form,
VAR-07's own second construct) and any `list` declared without an
initializer inside a branch (`emit_conditional_decl_defaults` → the same
`emit_type_default`), per bug #25's conditional-path defaults. The
generator never emits a no-initializer `list` for a builtin value type
(vox-fuzz `variables.md` VAR-12: "every emitted map carries a literal"),
which is why the fuzzer has not caught it — only the ledger probe did.

**Fix direction** (for the approved fixer): set `uses_heap` when a
no-initializer `list` default is emitted, in `emit_type_default`'s
`Type::List` arm (mirroring how the map path is safe via `uses_maps`), or
teach the analyzer to record `uses_heap` for a `VarDecl` whose declared
type is `list` with `value: None`. The conditional-defaults path
(`emit_conditional_decl_defaults`) must set it too.

---

### 103. A thing with a disallowed field type gets two errors, the first garbled — and the field-type surface itself is narrower than it should be

**Status:** Open — diagnostic fixed in v0.4.14 (regression tests
`tests/compile_fail/273`–`274`); the field-type surface awaits the owner's
ruling. Registered 2026-08-25 (GitHub #243). Severity: **diagnostic
bug + owner-declared design gap**. Verified on vox 0.4.13 (873daf8)
by the master, 2026-08-25.

```vox
A thing called 'file report' has
  a text called filename is "",
  a number called lines is 0.
```

- **Observed — two errors, the first asserts a mismatch between two identical
  things:**
  ```
  error: Field 'filename' of thing 'file report' is a text, but its default is a text
    A field's default must be a literal of the field's own type; a whole number is accepted for a float.

  error: Field 'filename' of thing 'file report' is a text, which a thing cannot hold yet
    A field's type may be number, float, boolean, time, or any thing defined earlier (plan 310 §6).
  ```

**Root cause.** The default-type-mismatch template fires even when the field's
type itself was already rejected as a field type. Both slots of "expected X,
got Y" therefore render the same word, and the sentence asserts a contradiction
between two identical things. The true error is the second one; the first is
noise in front of it. Suppressing the default-type check when the field's type
has already been rejected leaves the (excellent) single diagnostic.

**Owner ruling (Josj, 2026-08-25).** The garbled message is the symptom, but the
real defect is deeper: **every standard type should be a legal thing field, and
text missing from that set is a delivery gap, not a design limit.** The
deferral's stated rationale is unproven rather than false — plan 310 §6 keeps
`text` out pending verification that copying a text handle cannot observe
mutation (`docs/plans/310_user_defined_structures.md:214-217`), and keeps
buffer/list/map/file/timer/value out because they carry references under value
semantics (§5). If verification clears, text joins v1; the owner's direction is
to do the verification and deliver the full standard-type field surface.

**What the manual already said.** Field declarations and their literal defaults:
`LANGUAGE.md:954-959`. Field-type rule and its rationale:
`docs/plans/310_user_defined_structures.md:201-223`.

**Fix direction.** (a) immediate: skip the default-type check when the field
type is already rejected, leaving the single correct error. (b) the real work:
settle the text-handle copy semantics (deep-copy-on-assignment would unblock
text fields), then extend the allowed field-type set toward all standard types
per the owner's ruling.

**Fix.** `src/analyzer/things.rs:405-448` now checks `v1_field_type_supported`
before the default-mismatch template; an unsupported field type reports only
the "cannot hold yet" error and skips the default check entirely, instead of
falling through into a template with no arm for its own type. A field whose
type IS supported still gets the default-mismatch error when its literal
default doesn't match (pinned by `tests/compile_fail/274`). Only the
diagnostic ordering changed — the field-type surface itself is untouched, per
scope.

---

### 104. `each ... from` over a non-list anchors the error at the variable's declaration, not the loop — and there is no byte-iteration sentence at all

**Status:** Fixed in v0.4.15 — `each <name> from <buffer>` (and
`For each <name> from <buffer>,`) now walks a buffer's bytes as numbers
1..size, with `byte` itself legal as the loop-variable name; caret
anchoring landed earlier in v0.4.14 (regression tests
`tests/compile_fail/275`–`276`). Registered 2026-08-25 (GitHub #244).
Severity: **diagnostic-placement** + owner-raised feature. Verified on
vox 0.4.13 (873daf8) by the master, 2026-08-25.

```vox
Create a buffer called data.
set byte 1 of data to 'A'.
Print each octet from data.   (the offence is here, line 3)
```

**Observed** — the message and hint are right, the caret is on the wrong line:
```
error: Loop collection must be a list: data
  --> probe.vox:1:24
    |
  1 | Create a buffer called data.
    |                        ^--- here
  hint: data is a buffer - `each ... from` walks a list, a range, or `arguments's all`
```

**Root cause.** The diagnostic reports the loop collection *variable* and emits
its caret at the variable's declaration site, not at the `each ... from`
expression that misuses it. Every other diagnostic anchors at the offending use
site; in a large file the declaration can be hundreds of lines from the loop.

**What the manual already said.** `each...from` is a universal loop expansion
over a collection or range (`LANGUAGE.md:316`); the legal walks are a list, a
range, or `arguments's all`.

**Owner ruling (Josj, 2026-08-25).** The misplaced caret is a small bug, but
the broader ask is: **looping over the bytes of a buffer should be expressible.
There is no such sentence today.** Verified: `each byte of data`, `each octet
of data`, and `each byte from data` are all rejected (`byte` is even a reserved
keyword), leaving only a hand-written scalar loop
(`For each number from 1 to data's size, print byte {the number} of data.`).
A byte-iteration form — `For each byte of <buffer>` / `each octet from
<buffer>` — would give the language the natural loop and make the misanchor
case rare. Complements #249's bulk-primitive request (memchr for searches).

**Fix direction.** (1) immediate: anchor the caret at the `each ... from` use
site. (2) the owner's ask: add a byte/octet iteration form over a buffer to the
`each ... from` expansion, so byte loops are a sentence rather than a scalar
`For each N from 1 to size`.

**Fix.** `src/analyzer/scope.rs`'s `check_loop_collection` now anchors on the
`each ... from` clause's own use of the collection — `from {name}`, or
`each {variable} from` when the collection has no name of its own — instead
of the collection's textually-first mention. It builds that location with
`find_bind_site_location` and reports through `push_error_with_hint_at`
rather than the declaration-anchoring `push_error_with_hint`; every other
caller of `push_error_with_hint` is untouched. Message and hint text are
unchanged; pinned for both the buffer and map branches
(`tests/compile_fail/275`-`276`, buffer's case since moved to a `number`
collection once the byte-iteration form below made a buffer legal there).
The byte-iteration sentence itself remained unbuilt, per that pass's scope.

**Fix — the byte-iteration sentence (v0.4.15).** A buffer joins the list
and the range as a legal `each ... from` collection: `non_collection_kind`
(`src/analyzer/scope.rs`) no longer refuses a buffer identifier, and the
refusal hint for every other kind now names the walk — "a list, a range, a
buffer's bytes, or `arguments's all`". `byte` is claimed as the loop
variable by lexeme at both binding sites — `try_parse_each_from` and
`parse_for` (`src/parser/control_flow.rs`) — the same contextual-keyword
treatment `Token::Number` already gets there; inside the loop body, a bare
`byte` (not the start of `byte N of <buffer>`) is disambiguated back to an
ordinary identifier in `parse_primary`'s `Token::Byte` arm
(`src/parser/expressions.rs`) by trying the byte-access reading first and
rewinding on failure. The analyzer types the loop variable `Type::Integer`
over a buffer collection (`src/analyzer/statements.rs`). Codegen
(`Statement::ForEach`, `src/codegen/statements.rs`) walks 1..size reading
each byte through the same `BUFFER_LENGTH`/`BUFFER_DATA_ADDR` macros
(`core.asm`) `byte N of <buffer>` and `Set byte N of <buffer> to ...`
already use — no coreasm changes were needed. Fixed and dynamic buffers,
buffer parameters, and a released buffer (`_released_buffer_header`, size
0 — zero iterations) all take this same path. Tests: 587–594; compile_fail
280 pins `each byte from <map>` still refused, so the new `byte`
contextual-keyword parsing doesn't accidentally bypass the map refusal.

---

### 105. A call missing its `with` reports arity, not the missing preposition

**Status:** fixed in v0.4.14. Regression tests:
`tests/compile_fail/271_call_missing_preposition_bare_call.vox`,
`tests/compile_fail/272_call_missing_preposition_two_args.vox`. Registered
2026-08-25 (GitHub #245). Severity: **diagnostic accuracy**. Verified on
vox 0.4.13 (873daf8) by the master, 2026-08-25.

```vox
To 'write a blank pair to' with a buffer called output.
  set byte {output's size add 1} of output to ' '.

Create a buffer called staged.
'write a blank pair to' staged.
```

**Observed:**
```
error: Function 'write a blank pair to' expects 1 argument but was called with 0.

error: Unknown function: staged
```

**Root cause.** The parser finds no introduced arguments because none follow a
preposition, and reports arity 0 — the downstream symptom rather than the
cause. The bare `staged` is then parsed as a standalone statement, producing a
second, compounding error. "Called with 0" is confusing when the caller can see
one argument on the line.

**What the manual already said.** "In expressions, use the function name
followed by `of`, `to`, `with`, or `on` and arguments" (`LANGUAGE.md:766`);
"for calls with arguments, use `of`, `to`, `with`, or `on`"
(`LANGUAGE.md:876`).

**Fix direction.** When a call is followed by a bare identifier where arguments
could begin, name the missing preposition in the compiler's usual style:
"'staged' follows the call with no preposition — arguments are introduced with
`with`, `of`, `on`, or `to`." That one diagnostic removes the second error.

**Fix.** `parse_identifier_statement` (`src/parser/statements.rs`) is where a
call with no `of`/`to`/`with`/`on` connector used to fall straight through to
`Statement::FunctionCall { args: vec![] }` — a genuine zero-argument call and
a dropped preposition look identical at that point, and the parser picked the
former unconditionally. It now checks one token further: if a bare or quoted
identifier immediately follows with nothing between it and the callee, that
is the dropped-preposition shape, and the parser raises one error naming it,
anchored at that identifier, instead of returning the zero-arg call. Because
the error is raised here rather than after the fact, the identifier is never
handed to the statement-list loop as a leftover token, so it never gets a
second, independent parse of its own — the "Unknown function" error is gone
because nothing ever tries to parse `staged` as anything again. A true
zero-argument call (`'greet'.`, one at the end of a comma-chained clause, one
followed by a double period) is unaffected: the check only fires when the
next token is an identifier, and none of those shapes put one there.

---

### 106. `print`'s aliases are enforced unevenly: `show`/`display` reserved, `say`/`output` not

**Status:** fixed in v0.4.14. Regression tests:
`tests/compile_fail/277_show_reserved_print_alias.vox` + `.err` (`show`
rejected), `tests/compile_fail/278_display_reserved_print_alias.vox` +
`.err` (`display` rejected), `tests/577_say_and_output_are_variable_names.vox`
(`say`/`output` compile and print as ordinary variables), and three
`cargo test` cases beside the existing `string_is_keyword` tests in
`src/codegen/tests.rs`: `string_is_keyword_matches_the_live_lexer`,
`print_aliases_reserved_evenly`, `reserved_aliases_doc_matches_the_const`.

```vox
a number called show    is 1.   (rejected: reserved keyword)
a number called display is 1.   (rejected: reserved keyword)
a number called say     is 1.   (compiles)
a number called output  is 1.   (compiles)
```

**Root cause.** The live rejection path is `Token::as_keyword()`, fed by the
lexer's alias fold at `src/lexer/scan.rs:367`:
`"print" | "prints" | "display" | "show"`. `say` and `output` appear in the
documentation-source table (`src/lexer/tokens.rs:96`, `string_is_keyword`) but
are never folded by the lexer, so they lex as ordinary identifiers and are
usable as names. The split is an accident of two tables disagreeing, not a
deliberate design.

**What the manual already said.** The Reserved Aliases table
(`LANGUAGE.md:5002-5018`) lists only `ms`, `message`, `string` — it does not
name `show`/`display`/`say`/`output` at all, so no reader can predict the
split.

**Fix.** `show`, `display`, and `prints` are live print aliases (the lexer
folds them; `prints` was a second, previously unclaimed half of this same
split) and stay reserved. `say` and `output` are not live aliases — the
lexer never folds either — and stay ordinary variable names; no shipped
program's behaviour changes (`output` names a variable in six files:
`examples/greet.vox`, `examples/cat.vox`, `examples/args_and_env.vox`,
`tests/060_flag_schema_default_text.vox`,
`tests/428_forward_flag_read_in_a_function.vox`,
`tools/migrate-identifiers/tests/all_positions.vox`). The alias fold now
lives in exactly one place, a `RESERVED_ALIASES` const in
`src/lexer/tokens.rs`; `string_is_keyword` is a lookup into it, and a
`cargo test` fails the build if LANGUAGE.md's Reserved Aliases table (now
85 rows, generated from and checked against the same const) ever drifts
from it again, closing #238/#239 for good.

Auditing every other row of the old `string_is_keyword` against the live
lexer's fold turned up the identical bug throughout the table — words
claimed reserved the lexer never folds, live aliases the table never
claimed, and two rows attributing a real alias to the wrong canonical
keyword. All fixed alongside `print`'s:
- **Over-claimed** (dropped — not live aliases): `say`, `output`, `let`,
  `put`, `declare`, `over`, `increase`, `decrease`, `execute` (no
  `Token::Execute` exists at all — the whole row was spurious), `respond`,
  `reply`, `end`, `halt`, `abort`, `using`, `given`, `taking`, `higher`,
  `above`, `lower`, `below`, and the unreachable symbol spellings `==`,
  `!`, `&&`, `||` (`scan.rs` never lexes any of those four characters, and
  no identifier can spell one anyway).
- **Omitted** (added — live aliases the table missed entirely): `prints`
  (→ `print`), `store` (→ `set`), `returns` (→ `return`), `append`/`push`
  (→ `append`), `copy`, `map`/`dictionary` (→ `map`), `keys`, `values`,
  `element`, `without`, and the six `bit-and`/`bit-or`/`bit-xor`/`bit-not`/
  `bit-shift-left`/`bit-shift-right` forms.
- **Wrong canonical** (moved): `make` was claimed as a `set` alias but the
  lexer folds it to `create`; `times` was claimed as a `multiply` alias
  but the lexer treats it as its own keyword (the `Repeat N times` loop
  word); `equals`/`equal` were claimed as `is` aliases but the lexer folds
  them to their own `Equals` keyword.

**Second half (v0.4.15):** GitHub #239's other half - fourteen reserved
words absent from every table in the Keywords chapter (vox-fuzz
`docs/ledger/keywords.md`, Discrepancy 4) - is closed too. The five
statement-starter gaps (`read`, `write`, `open`, `close`, `wait`) are now
rows in the Statement Starters table; the remaining nine (`input`,
`standard`, `byte`, `each`, `without`, `elapsed`, `error`, `arguments`,
`environment`) went into Connectors and a new Reserved Nouns and
Properties table. Auditing the *whole* lexer against the chapter's tables,
rather than trusting the ledger's list of fourteen, turned up 87 more
reserved words with no table entry anywhere in the chapter - every type
name, every arithmetic/comparison/bitwise operator, and most of the File
I/O, Time and Timers, and Object Properties nouns. Three more tables
(`### Types`, `### Operators`, `### File, Buffer, List, and Time
Properties`) were added to cover them, each pointing its rows at the
chapter that already defines the word rather than re-deriving its
grammar. A new `cargo test`,
`codegen::tests::every_reserved_word_appears_in_a_keywords_chapter_table`,
parses every `| Keyword |`/`| Alias |` table in the chapter and fails the
build if a reserved spelling from `RESERVED_ALIASES` is ever missing from
all of them again.

---

### 107. A buffer, list, or format-string text declared inside a function or loop body is allocated on every entry and released only at program exit

**Status:** Not a compiler defect — a limitation, ruled by Josj 2026-08-28
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
Evidence programs and the emitted `.asm`:
`vox-notes/evidence/2026-08-28-scope-exit-free/`.

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
the same escape rule. (C) An explicit release verb. Master's
recommendation: A now (docs only), B for 0.5.

Remedied by the `Free` statement (v0.4.14): see LANGUAGE.md, Releasing a
Buffer.

---

### 108. `Set <text> to "<format string>"` allocates a fresh string on every evaluation and never frees the one it replaces — building a text up in a loop is quadratic

**Status:** fixed in v0.4.14. Regression tests: 564–576 (two memory
regressions reading `/proc/self/statm`, eleven aliasing probes with exact
expected output) and nine `collect_freeable_texts` unit tests in
`src/codegen/tests.rs`. Severity was **unbounded memory growth** — 4 KB per
evaluation for a short format, and O(n²) bytes for the natural accumulate
idiom. Verified on vox 0.4.13 (4c85e03).

```vox
a text called acc is "".
a number called n is 0.
While n is less than 20000, Set acc to "{acc}x", increment n.
Print "done {n}".
```

→ `done 20000`, exit 0, **maxrss 236 MB in 0.94 s**; 10 000 → 71 MB;
5 000 → 23 MB — quadratic. A constant-length format (`Set t to "n={n}"`)
leaks linearly: 40 000 evaluations → 160 MB. Flat controls (0.4 MB):
`Set t to "hello"` (a literal) and `Set t to src` (text from text) at
40 000, and the buffer spelling `append "x" to acc` at 20 000. Taking
`acc as text` *inside* the loop is a fresh independent copy each time
(2040) and is quadratic too (236 MB at 20 000); once after the loop, flat.

**What the manual already said.** "Used as a value, a format string
materializes into a fresh NUL-terminated string … Each evaluation
allocates a new string; the source buffer can be cleared and reused
without affecting texts already created from it" (LANGUAGE.md:3396–3416).
That is exactly what happens. Nothing says the string the variable held
before the `Set` is freed on reassignment — and nothing says it is not.
The documented growable accumulator is the dynamic buffer (3489–3499)
with `clear` (3017).

**Root cause.** Each format-string evaluation allocates a new string; the
`Set` overwrites the variable's pointer and the outgoing string is never
freed before exit (measured: memory never returns). One design constraint
for any fix, found while measuring: `Set t to src` (text from text)
allocates nothing, so two text variables can share one string — a
free-on-`Set` must know whether the outgoing string is shared (ownership
flag or count) or it frees a string another variable still names.

**How it was found.** The vox-fuzz Defect 17 worker (2026-08-28) hit it in
`gen_files.vox`'s `'gen build input'` (`Set gen_input to
"{gen_input}{c}"` per character); confirmed by the master's own
measurements above. Evidence: `vox-notes/evidence/2026-08-28-scope-exit-free/`
(`t_text_acc_*`, `u_*`, `v_*`, `w_*`, `x_*`, `y_*`).

**Fix.** Two independent checks, both required, combined at every `Set`/
declaration write of a top-level (global) text variable:

1. A whole-program, flow-insensitive static gate
   (`collect_freeable_texts`, `src/parser/ast.rs`) proves a text variable
   name *freeable* only if it is declared solely as `a text` (never a
   buffer, a `value`, a function parameter, a for-each/for-range loop
   variable — any of those poisons the name everywhere, flat-namespace,
   like a redeclared type already does for `collect_all_typed_decls`) and
   is never read anywhere in a position that could keep its string alive
   past a `Set` on it: the RHS of another declaration or assignment, a
   function argument, `Return`, an append to a LIST (a buffer append only
   copies bytes and does not count), a map key or value, a list/map
   literal element, or the operand of an expression that can hand back
   that operand's OWN pointer unchanged — `Cast` (`x as text` on an
   already-text `x` is a bare pass-through, LANGUAGE.md's Basic
   Conversions table) and `TreatingAs` (`treating` hands back `value`'s or
   `replacement`'s own pointer, never a copy) both close over their
   operand this way. One retaining read anywhere disables freeing for
   that name everywhere, including at a `Set` that runs before the
   retaining read ever does — the cost is a missed free, never a
   use-after-free.
2. A runtime ownership flag, one BSS byte per freeable global paired with
   its payload mirror (`ensure_global_text_owned_label`, mirroring how a
   `value` global's tag byte is paired). Set to 1 only when the value just
   written is a format-string evaluation, or an `as text`/bare conversion
   that copies a buffer's or a scalar's bytes into a brand-new buffer
   (`text_write_is_owned`); 0 for everything else (a literal, another
   variable, a buffer/scalar source that turned out to be a pass-through
   cast). Zero-filled BSS means a fresh declaration's first write always
   reads a 0, so declaration and every later `Set` share one code path
   (`emit_owned_text_global_store`) with no separate initialisation case.

At a `Set` on a freeable global: evaluate the new value first (the
accumulate idiom reads the old string while building the new one), save
it, free the OLD string if its flag says owned (struct pointer = data
pointer − 24; `_free_buffer`, `coreasm/x86_64/resource_buffer.asm`, now
always munmaps whether or not the struct is in `buf_table` — a buffer
allocated past `MAX_BUFFERS` live ones is never registered and a free
path that only munmapped the found case leaked it forever), then store
the new value and set its own flag from its provenance.

**Local-only limitation.** The free-on-`Set` path applies to top-level
(BSS-resident) text variables only. A function-local text variable keeps
the plain, unconditional store it always had — a local's ownership flag
would need to be initialised before its first read, and a declaration
that shares one compile-time stack slot across sibling `If`/`Otherwise`
branches, or a loop re-entering the same `VarDecl`, cannot prove that
reliably without risking a read of uninitialised stack memory as a
pointer. Every headline evidence program and aliasing probe in this
report is a top-level text, so this restriction costs a missed
optimisation for function-local accumulation, never a correctness gap.

**Caught in review.** An early version of the static gate recursed into a
`Cast`'s or `TreatingAs`'s operand instead of marking it retaining, so a
bare `Expr::Identifier` operand fell through the recursion's catch-all
and was never excluded: `a text called u is src as text.` left `src`
freeable, and `Set src to ...` afterward freed the string `u` still
named — a real use-after-free, found by the master reviewing the first
patch, before it shipped. Tests 573–576 and two `collect_freeable_texts`
unit tests pin this shape specifically.

---

### 109. `Free` on a list was a silent no-op for a global and a dangling-pointer segfault for a function-local — the buffer half of the released-buffer contract never reached lists

**Status:** Fixed in v0.4.15 — a list now gets the same released-buffer
contract a buffer already has (LANGUAGE.md, Releasing a Buffer), plus,
by owner ruling, a deep free that recursively releases every nested
list/map the list holds. Registered 2026-08-29 (verified by the master,
confirmed by the owner 2026-08-29). Severity: **memory safety** (dangling
pointer after `Free` on a function-local list) + silent no-op on a global
list.

```vox
(D4.vox - global, no-op)
a list called nums is [1, 2, 3].
Free nums.
print nums's length.
print nums's empty.
print nums.
append 9 to nums.
On error print "append to freed list refused".
print nums's length.
print nums.
```

→ on 0.4.14: `3` / `0` / `[1, 2, 3]` / (no "refused" line - the append
went through) / `4` / `[1, 2, 3, 9]`. `Free` compiled and ran but had no
observable effect at all.

```vox
(local_list_free.vox - function-local, segfault)
To 'try it'.
    a list called 'the local numbers' is [1, 2, 3].
    Free 'the local numbers'.
    print "freed".
    print 'the local numbers''s length.
    append 9 to 'the local numbers'.
    On error print "append refused".
    print 'the local numbers'.

'try it'.
print "back at top".
```

→ on 0.4.14: `freed`, then **segfault (rc 139)** at the very next read.

**Root cause.** `Statement::Free` (`src/codegen/statements.rs`, was
~1171–1185) handled a `list` no differently from an `Allocate`d raw block:
`else if let Some(offset) = self.get_var(name) { HEAP_FREE rdi }`.
`get_var` only looks in the current function frame's stack-slot table, so
a global - which lives in a `gvar_N` BSS mirror - matched neither this
arm nor the buffer arm above it and fell through with nothing emitted:
a silent no-op, unlike `Increment`/`Decrement` on the same statement,
which already fall back to `global_var_label`. For a function-local list,
`get_var` DID find the slot, so `HEAP_FREE` genuinely ran and released the
block - but nothing then repointed the slot, so it was left holding the
address of memory the kernel had already unmapped; the next `length`,
`print`, or `append` dereferenced it and segfaulted.

**Fix - mirrors the buffer contract (LANGUAGE.md, Releasing a Buffer;
`src/codegen/buffers.rs`'s `emit_free_buffer`) exactly.**

1. A shared static `_released_list_header: dq 0, 0, 8` in `list.asm`'s
   `.data` (capacity 0, length 0, element size 8), matching
   `_released_buffer_header`. Every list read on it is naturally empty:
   `LIST_GET_SAFE` and every property reader key off `length`
   (offset 8), which is 0, so `length` reads 0, `empty` reads true,
   `_list_print` takes its `length == 0` branch and prints `[]`, and an
   element read is refused by the SAME bounds check a real empty list
   already gets (LANGUAGE.md's Bounds Checking) - no new behaviour
   invented for reads.
2. **Refused by identity, not by shape.** `_list_append` - the only
   runtime growth path codegen ever calls (`LIST_APPEND`, the macro named
   in the original brief, is defined in `list.asm` but never invoked by
   codegen anywhere; left untouched, noted here rather than silently
   ignored) - now opens with an identity check: `cmp rdi, [rel
   _released_list_header address]`, and refuses with `SET_LAST_ERROR 1`
   before touching anything if it matches. This has to be identity, not
   shape: the released header's capacity 0/length 0 is exactly what a
   REAL list looks like the instant `_list_append` decides it needs to
   grow (`length == capacity`), so a shape check would have silently
   resurrected a freed list into a brand-new block instead of refusing
   it. Test 614 pins that a real list crossing that exact boundary still
   grows. `Set element N of L to value` (`Statement::ElementSet`,
   `src/codegen/statements.rs`) needed no change: contrary to the
   original brief's `LIST_SET_ELEM` guess, that statement was never
   generated through the `LIST_SET_ELEM` macro (only list-literal/argv
   fill loops use it) - it has always been an inline, LENGTH-bounded
   write (`index <= length` or refuse), and a released list's length is
   always 0, so every write to it was already refused before this fix,
   by the ordinary bounds check. No identity check was added there
   because none was needed; see "Where the brief was wrong" below.
3. `_free_list` (new, `list.asm`) replaces the generic `HEAP_FREE` for a
   list. It computes the block's total size from the list's OWN header
   (capacity, element size, +1 tag byte per slot) and unconditionally
   munmaps, rather than looking the pointer up in `heap.asm`'s
   `alloc_table` - that table only ever learns about a list's FIRST
   block (from the `HEAP_ALLOC` the literal/default codegen emits);
   every block a growth reallocated into came from a raw, untracked
   `mmap` in `_list_append`'s `.need_realloc` path, so `HEAP_FREE` would
   silently free nothing for any list that had ever grown - the exact
   leak class `_free_buffer` was already fixed to not have (#108's
   neighbour, bug #108 note above; the actual precedent is `_free_buffer`
   always munmapping "whether or not the buffer is currently in
   buf_table"). `_free_list` also carries its own identity check
   (refuses a second `Free`, `SET_LAST_ERROR 1`, unmaps nothing) and
   `CLEAR_LAST_ERROR` on every success path of both itself and
   `_list_append` - list.asm had never touched `_last_error` before this
   fix.
4. **Codegen.** `Statement::Free` gained a `VarType::List` arm
   (`emit_free_list`, `src/codegen/collections.rs`) parallel to the
   existing `VarType::Buffer` arm, resolving the name through
   `emit_load_named_var_addr` (local frame, THEN global mirror - the
   missing branch) and writing the result back through
   `emit_store_back_after_realloc`. The `Allocate`d-raw-block arm is
   unchanged (an `Allocate`d block never carries `VarType::List`, so it
   still falls through to the old, untouched `HEAP_FREE` path) and the
   buffer arm is untouched.
5. **List parameters (brief rule 4) - already had the mechanism, no
   compile error needed.** The brief flagged this as possibly requiring
   a compile-error fallback ("if lists have the same write-back cell
   mechanism ... follow the buffer precedent [...] if they do not, make
   `Free` on a list parameter a compile error"). Investigated first:
   #75 already gave `list`/`map` parameters an address-of-caller's-slot
   argument word (`collection_backing_slots`, a `{name}_backptr` shadow
   slot - the same shape a buffer parameter's `{name}_cell` has for
   #90) and `emit_store_back_after_realloc` ALREADY writes through both
   `buffer_param_cells` and `collection_backing_slots` unconditionally,
   in the one shared function. `emit_free_list` calling that function is
   the entire mechanism - zero new code was needed for the parameter
   case beyond what rules 1-4 already required. Test 615 proves the
   caller's own variable is empty and refuses after a callee frees its
   list parameter.

**Where the brief was wrong (as invited: "the spec/this brief may be
wrong ... say so").** Two things, both above: `LIST_SET_ELEM` is not
`Set element N of L to ...`'s path (nothing needed changing there), and
list parameters do NOT need the compile-error fallback (they already had
an equivalent write-back mechanism, just under a different name).

---

**Scope addition, owner ruling 2026-08-29 09:18: "Freeing a list should
free every item within the list as well — agreed."**

**Nested collections: copy-in or pointer-in?** Established first, as
asked, before building anything on it. Probed on this branch (0.4.14):

```vox
a list called inner is [1, 2].
a list called outer is [inner, 3].
Set element 1 of inner to 777.
print outer.
print inner.
```
→ `[[777, 2], 3]` / `[777, 2]` - mutating `inner` through its own name is
visible through `outer`. The emitted assembly confirms it directly: the
list-literal fill for `outer` does `mov rax, [rel gvar_0]` (loads
`inner`'s own pointer) then `LIST_SET_ELEM [rbx+24], rax` - `outer`'s
slot stores `inner`'s POINTER, tagged `LIST_TAG_LIST`, not a copy.
**(b) pointer-in.** Deep free was built anyway, per the ruling above -
this is the "build it anyway" branch the brief's own template
anticipated for this answer.

**What deep free does.** `_free_list` walks its own slots by their
per-element type tag before releasing itself: a `LIST_TAG_LIST` (4) or
`LIST_TAG_MAP` (5) slot is freed recursively (`_free_list`/the new
`_free_map`, `coreasm/x86_64/map.asm`), because both are unconditionally
heap blocks - nothing else ever allocates that shape, so no identity or
shape check is needed to know it is safe to recurse into one. A
`LIST_TAG_STRING` (1) slot is deliberately left alone and NOT freed - see
"Left out, on purpose: string/buffer elements" below. `_free_map` mirrors
`_free_list`: same recursion into LIST/MAP-tagged VALUES, same
size-from-header unconditional munmap, but carries none of `_free_list`'s
user-facing contract (no released header, no identity check for a
second `Free` of ITS OWN pointer) - a bare `Free <map>` statement is not
and remains not a supported language surface; `_free_map` is reachable
only from inside `_free_list`'s walk. Map KEYS are never freed at any
depth: `map.asm`'s own header comment states a key is always "a stable
C-string pointer (a string literal in .rodata) ... no strdup" - never
heap-owned, by this stage's own design, so there is nothing to free.

**Dedup, within one `Free` call tree.** Pointer-in aliasing means the
SAME nested block can be reachable through more than one slot inside one
`Free` - the same nested list appearing twice in one list's own literal,
or two different parents sharing one child. Freeing it twice in that one
walk would be a read of already-unmapped memory. `_free_visit_or_skip`
(`list.asm`) records every pointer a `Free` call tree has started
freeing in a 4096-entry table (`_free_visited`/`_free_visited_count`,
`.bss`); codegen (`emit_free_list`) zeroes the count immediately before
each TOP-LEVEL `Free`, so the table starts clean per statement and stays
populated across every recursive call that ONE statement's walk makes.
Past 4096 distinct collections touched by one `Free`, a new pointer is
conservatively treated as "already visited" (skipped, leaked) rather than
freed - the same leak-over-crash trade `_list_append`'s own
never-reclaimed grown-out blocks already make. Test 596 proves a list
holding the same nested list through two of its own slots does not
crash.

**Left out, on purpose: string/buffer elements — a real, load-bearing
limitation, not an oversight.** The scope addition named "buffers" and
"heap-allocated texts" as things deep free should reach. Investigated:
there is no `TAG_BUFFER` anywhere in the tag scheme (0=integer, 1=string,
2=float, 3=boolean, 4=list, 5=map, 6=nothing) - a `buffer` VALUE cannot be
stored as a list/map element at all; the only way "buffer" content ever
enters a list is `append <buffer> to <list>`, which duplicates the
buffer's bytes onto the heap via `_strdup_bounded`
(`src/codegen/statements.rs`, the `is_buffer_value` arm) and tags the
result `TAG_STRING` - indistinguishable, at the tag level, from a plain
string LITERAL element, which is a pointer into `.rodata` and must never
be freed. Nothing recorded per-slot (or per-map-entry) marks which is
which. Freeing a `.rodata` pointer risks unmapping part of the program's
own data segment (mmap/munmap both operate in whole pages, and `.rodata`
pages are real mappings); leaving a `_strdup`'d string unfreed is a leak.
The leak is the strictly safer of the two wrong answers, so `_free_list`/
`_free_map` stop at LIST/MAP and never touch a STRING-tagged slot. This
is a genuine, currently-unfixed leak for any list/map holding text or
buffer-derived string elements when it is `Free`d - distinguishing the
two would need a new per-slot ownership bit (the same shape #108's fix
added for top-level text globals) threaded through every place a string
element gets written, which is out of this brief's scope (lists only).

**A new, confirmed hazard: freeing a nested collection leaves ANY other
variable that still names it dangling.** Because nesting is pointer-in,
a variable that separately names the same block a deep free just
released is left holding a dead pointer - reading it segfaults exactly
like the original #109 defect did, just reached a new way:

```vox
a list called inner is [1, 2, 3].
a list called outer is [inner, "x"].
Free outer.
print inner's length.   (segfault, rc 139 - reproduced on this branch)
```

**Closed by #111, same day.** Carried to "Questions for the master" in
REPORT-109.md as the #34 ruling question; the owner ruled (A) copy-by-
default the same day (GitHub #34, Option 1) and #111 (this branch,
Round 2) implements it: a collection placed inside another collection is
now a copy, so `outer` above never held `inner`'s own block in the first
place - `Free outer.` deep-frees `outer`'s independent copy, and `inner`
stays fully valid. The repro above is kept as the historical record of
why the ruling was needed, not as current behaviour - see #111 below.

**Tests.** 584, 596, 611–619 (`tests/`; 587–595 collided with #104's
byte-iteration tests staked out the same day and were renumbered —
611–619 below): global list Free contract (611, mirrors
D4), function-local Free no longer segfaults (612, mirrors
local_list_free), a second Free flags (613), a real list still grows past
its literal capacity - identity not shape (614), Free through a list
parameter frees the caller (615), `Release`/`Deallocate` are the same
statement for a list (616), Free reaches a global from inside a function
(617), deep free reaches a nested list AND a nested map in one outer
Free (618), a second Free after a deep free flags and does not
double-unmap (619), deep free dedups a list holding the same nested list
twice (596). Test 584 (previously "free on a list is unchanged and pins
its after-state", written for #107/buffer-Free's original, list-untouched
scope) is rewritten in place to pin the NEW, fixed after-state instead of
the old undefined-read one it used to document.

**Not attempted.** A list-of-things: LANGUAGE.md 1891/2668 already state
"a `list` or `map` of user things ... is deferred" in 0.4.14, so this
shape does not exist yet and has no test. Reference-counting or a visited
set spanning SEPARATE `Free` statements (only the alias-dangling hazard
above, not the same-tree dedup, which IS handled): out of scope, and
likely the shape of the #34 ruling itself.

---

### 110. A single-quoted ONE-WORD name never resolved inside a `{...}` format-string slot — every type, quotes and all read back as the "variable"

**Status:** Fixed in v0.4.15 — `try_parse_expression`
(`src/parser/expressions.rs`) now routes a lone single-quoted slot token
through the same lexer/parser every other placeholder shape already used,
instead of returning early on it. Regression tests: 620–629.

Registered 2026-08-29 (verified by the master 2026-08-29; the owner ruled
the quoted one-word spelling legal the same day).

```vox
a number called 'tally' is 7.
Print 'tally'.              (prints 7)
Print "{'tally'}".          (error: Unknown variable: 'tally')

a text called 'label' is "AB".
Print "{'label'}".          (same error — every type)

a buffer called 'toolbox' is 8 bytes in size.
append "AB" to 'toolbox'.
Print "{'toolbox's size}".  (worked — a quoted name followed by a property resolves)
Print "{toolbox}".          (worked — bare)
Print "{'the toolbox'}".    (worked — multi-word quoted)
```

LANGUAGE.md:711 rule 4 says a single-word quoted identifier (`'tally'`)
"lexes identically to the bare form" — everywhere a name is legal, `'tally'`
and `tally` name the same thing. That held in statement position and in
every quoted shape that happened to contain a space; it silently stopped
holding the instant the same token sat alone inside a `{...}` slot.

**Root cause.** `parse_format_string` (`src/parser/expressions.rs`) splits
each `{...}` slot's content on the first unquoted `:` and hands the
variable/expression half to `try_parse_expression`, which decided whether
to run the content through the real lexer+parser or just use it verbatim
as a `FormatPart::Variable` name:

```rust
if !content.contains(' ') || content.chars().all(|c| c.is_alphanumeric() || c == '_') {
    return None;
}
```

The guard's only real test (the alphanumeric check can never fire once the
space check has not already returned — any string containing a space
already fails `.all(alphanumeric)`) was "does this contain a space". For
`'tally's size` and `'the toolbox'` that's true — both contain a space —
so they fell through to the lexer, which correctly reads the leading `'`
as the start of a quoted identifier and produces the right token stream.
For a bare quoted one-word token, `'tally'`, there is no space anywhere in
it, so the guard returned `None` before the lexer ever saw it. The caller's
fallback then built `FormatPart::Variable { name: "'tally'", .. }` — using
the placeholder's raw text, quote characters included, as the variable
name. Every later lookup (`is_variable_available`, `resolve_format_variable`
in codegen, which the file documents as "THE single name-resolution path
shared by every format-string sink") keys off that exact string, and no
variable is ever registered under a name with literal `'` characters in
it — hence "Unknown variable: 'tally'", the quotes baked into the message
because they were baked into the (wrong) name.

**Disambiguation chosen.** The brief that opened this bug guessed a slot
default of "a quoted token is always a name, never a character" for the
one-letter case (`'x'`). That is not what LANGUAGE.md rules; :691 rule 3 is
explicit and declared "no context-sensitivity": a single-quoted token
holding exactly one character is a **character literal** in every
position, slots included — "single-character quoted identifiers do not
exist. Write `x`, not `'x'`." Confirmed directly against the shipped
0.4.14 binary before writing the fix: `a number called 'x' is 5.` is
already a compile error ("Expected a name, got IntegerLiteral(120)"), and
bare `Print 'x'.` already prints `120`, not a variable read. So the fix
does not special-case slot position at all — it defers entirely to the
same lexer the rest of the language already uses, which was already
correctly distinguishing `'x'` (`is_char_literal`, exactly one character)
from `'tally'` (`is_single_quoted_identifier`, two or more) — the bug was
that the slot's fast path skipped the lexer altogether for anything
without a space, `'x'` included. Post-fix, `{'x'}` renders `120`, matching
`Print 'x'.` exactly, and `Set byte N of <buffer> to 'A'` — the manual's
own character-literal position — is untouched (test 629 pins both in one
program).

**Fix.** Narrowed the guard to only bypass the lexer for a genuinely bare
word — no quotes, no spaces:

```rust
if !content.contains(' ') && !content.contains('\'') {
    return None;
}
```

Anything else, a lone quoted token included, now falls through to the
existing lex-and-parse path (unchanged), which already handled the
multi-word and possessive-property shapes correctly and needed no new
code to handle the one-word shape too — the lexer's existing
`is_char_literal`/`is_single_quoted_identifier` split is the single source
of truth for the name-vs-character-literal question, in a slot exactly as
in statement position.

---

### 111. Nested collections were shared by pointer, not copied — a list or map placed inside another one aliased the SAME block, so mutating either side reached the other, and freeing the outer one dangled the original name

**Status:** Fixed in v0.4.15. Registered 2026-08-29, owner ruling
GitHub #34, Option 1 ("A" - copy by default), same day as #109. Severity:
**memory safety** (the #109 report's own "new, confirmed hazard": freeing
an outer collection deep-freed a nested block a separately-named variable
still pointed at, segfaulting on the next read) plus a silent
correctness surprise (mutating an extracted child, or the source of a
literal/append, reached back into the other side).

```vox
a list called inner is [1, 2].
a list called outer is [inner, 3].
Set element 1 of inner to 777.
print outer.
print inner.
```
→ on 0.4.14 (before this fix): `[[777, 2], 3]` then `[777, 2]` -
mutating `inner` through its own name changed `outer` too. Master-probed
directly on this branch before building anything: the emitted assembly
for `outer`'s literal fill loads `inner`'s own pointer (`mov rax, [rel
gvar_0]`) and stores THAT into `outer`'s slot (`LIST_SET_ELEM [rbx+24],
rax`), tagged `LIST_TAG_LIST` - not a copy.

```vox
a list called inner is [1, 2, 3].
a list called outer is [inner, "x"].
Free outer.
print inner's length.
```
→ on 0.4.14: **segfault (rc 139)** - #109's deep free (`Free` now
recursively releases every collection a list holds) released `inner`'s
own block, since `outer`'s slot held `inner`'s own pointer, not a copy.

**Root cause.** Every write site that places a collection VALUE into a
list slot or a map value stored the pointer the source expression
evaluated to, unchanged: the list-literal fill loop (`src/codegen/
expr.rs`, `Expr::ListLit`), the map-literal fill loop (`Expr::MapLit`),
`append <collection> to <list>` (`Statement::Append`, `src/codegen/
statements.rs`) via `_list_append`, and `Set <map>'s "key" to <collection>`
(`Statement::MapSet`) via `_map_insert` all forwarded the source's raw
pointer. Every read-out site did the same in reverse: `element N of L`
(`Expr::ElementAccess`), `L's first`/`last` (`ObjectProperty::First`/
`Last`), a map value read (`Expr::MapAccess`), and a `For each` loop
variable bound to a nested collection (`Statement::ForEach`) all handed
back the SAME pointer the parent's slot held. A collection is nothing but
a heap pointer (LANGUAGE.md: "a collection is nothing but one" - the same
sentence that makes a `list`/`map` parameter "the caller's collection"),
so every one of these sites was, correctly for the shape asked of it
before this ruling, sharing that one reference.

**Fix - "a collection placed inside another collection is a copy, not a
shared reference" (owner ruling, GitHub #34, Option 1), everywhere a
collection can be placed or read out.**

1. **Runtime.** `_copy_list` (new, `coreasm/x86_64/list.asm`) and
   `_copy_map` (new, `coreasm/x86_64/map.asm`): each allocates a fresh
   block of the source's own capacity/element_size (or hash_capacity/
   element_size for a map) via a raw `mmap` - the same allocation shape
   `_list_append`'s growth path already uses, so `_free_list`/`_free_map`
   (#109) can free the copy like any other block - bulk-copies the data/
   tag (or hash-table/entries) region verbatim, then walks the live slots
   and replaces any LIST- or MAP-tagged one with a RECURSIVE copy of its
   own block. Both are unconditionally heap blocks, so no identity/shape
   check is needed to know it is safe to recurse (mirrors #109's own
   deep-free walk). A STRING-tagged slot is left as a reference, matching
   #109's own decision not to own string/buffer-derived elements (no
   marker distinguishes a `.rodata` literal from a heap-owned string); a
   map KEY is never copied - `map.asm`'s own header comment already
   states a key is always a stable `.rodata` pointer, never heap-owned.
2. **Codegen write sites.** `emit_copy_if_collection_static`/
   `emit_copy_if_collection_reg`/`emit_copy_if_collection_mem`
   (`src/codegen/collections.rs`) copy the value already in `rax` when
   its tag - known at compile time (`emit_time_expr_tag`, the STATIC
   case) or only at runtime (a mixed source's shadow-slot/`r11` tag) -
   says LIST or MAP; every other tag passes through untouched, so a
   scalar/string/nothing element costs nothing extra. Wired into the
   list-literal fill, the map-literal fill, `Statement::Append`,
   `Statement::MapSet`, and `Statement::ElementSet` (`Set element N of L
   to <collection>` - not individually named by the ruling's own
   enumeration, extended for the same principle: any write INTO an
   existing slot, not only construction/append/map-insert).
3. **Codegen read-out sites.** `Expr::ElementAccess`, `ObjectProperty::
   First`/`Last`, `Expr::MapAccess`, and the `For each` loop-variable
   binding all copy the value on their success path before handing it
   to the caller, using the same static-tag-or-runtime-tag dispatch. A
   fallible read's MISS value (0, never a real pointer) is never handed
   to the copy: a miss's tag is TAG_INTEGER, which the runtime check
   never matches, and a proven-scalar static type never reaches the
   check at all.
4. **A real bug found and fixed mid-implementation: `r11` did not survive
   the copy call.** The x86-64 `syscall` instruction architecturally
   clobbers `rcx`/`r11` to hold the return RIP/RFLAGS - `_copy_list`/
   `_copy_map`'s own `mmap` therefore destroys `r11` regardless of
   anything codegen does, and `r11` is exactly where a read site's
   runtime tag lives for the NEXT consumer (a format-hole/print
   dispatcher, a declaration's own shadow-tag write) to read. The first
   pass broke eight otherwise-unrelated existing tests (mixed-value
   rendering, a buffer-and-map-through-a-parameter test, a for-each type-
   tag test) by silently misdispatching a copied list/map as a raw
   address once `r11` came back holding syscall debris instead of the
   tag. Fix: `emit_copy_if_collection_reg` restores the register it was
   given (TAG_LIST/TAG_MAP, whichever branch ran) immediately after the
   copy call returns, before any other code can observe the clobbered
   value. Caught by the regression suite, not by design - recorded here
   as the one place this brief shipped a real defect internally before
   the gate caught it.
5. **`uses_maps` set defensively inside the copy-in helpers themselves,**
   not just at the analyzer's own detection sites: codegen is single-pass
   (statements are walked once, in source order, and the prologue's
   `%include map.asm` decision reads `self.uses_maps`'s FINAL value only
   after every statement has been generated), but a MIXED source's
   runtime tag could turn out to be TAG_MAP even in a program where
   nothing generated so far has proven a map exists. The first pass hit
   this directly: a purely list-only program with a mixed nested-list
   read emitted a `call _copy_map` with `map.asm` never included -
   `symbol '_copy_map' not defined`. Both `emit_copy_if_collection_
   static`'s map branch and `emit_copy_if_collection_reg` now set
   `self.uses_maps = true` unconditionally before emitting anything, so
   the flag's FINAL value (read once, at prologue time) is always
   correct regardless of where in program order the branch fired.

**Nested collections: copy-in or pointer-in? - answered, then acted on.**
Established as instructed, before building anything: probed directly
(the `outer`/`inner` repro above) and confirmed from the emitted assembly
that 0.4.14 was pointer-in. Per the ruling, the answer is now copy-in,
unconditionally, everywhere a collection value can be placed into or read
out of a list/map slot.

**The dedup table (#109) - kept, now belt-and-braces, not load-bearing.**
#109's `_free_visit_or_skip` dedup table existed because pointer-in
nesting let the SAME block be reachable through two slots in one `Free`
call tree. Under copy-in, every "placed inside" event mints a fresh
block, so `[inner, inner]` (test 607) now produces TWO independent
copies, not one pointer twice - the table's original trigger no longer
occurs on the ordinary construction paths. It is kept anyway: it is
cheap (a linear scan of a `.bss` table, already implemented), and it
remains a genuine backstop against any future write site that reintroduces
sharing (a bug in a NEW copy-in call site, a future feature that shares
deliberately) turning into a crash instead of a caught duplicate. Removing
it would save nothing observable and would remove a safety net for free;
recommend keeping it.

**Performance.** A 1,000-element list of 1,000 single-element lists,
wrapped one level (`a list called outer is [big].`, forcing 1,000
recursive per-element copies) plus one read-out copy, completed in
`time`-measured 30 ms wall clock (`user 0.010s`, `sys 0.020s`) - one
allocation and a `rep movsb` per level, no observable cost at this scale.
1,000 iterations of re-wrapping a flat 1,000-integer list (1,000,000
total scalar element-copies, no recursion needed per element) completed
in 28 ms. Neither measurement suggests copy-in's extra allocation is a
practical concern at the sizes the fuzzer/test suite exercise; a
pathologically deep or wide structure would cost proportionally more
(one `mmap` per nested collection touched), which is the expected,
documented trade of copy semantics over reference semantics.

**Tests.** 597–609 (`tests/`): a list literal's nested-list element
copies in (597, the headline repro), append copies a nested list in
(598), `element N of` reads out a copy (599), `'s first`/`'s last` read
out copies (600), a map literal's value copies a nested list in (601),
`Set <map>'s "key" to <list>` copies in (602), a map value read-out
copies (603), `Set element N of L to <list>` copies in (604, the
consistency extension beyond the ruling's own named enumeration), three-
level nesting stays independent at every level (605), freeing the outer
list after copy-in leaves the ORIGINAL nested variable fully readable -
closing the #109 hazard directly (606), a list holding the same nested
list through two slots gets two independent copies, not one pointer
twice (607), a comprehensive deep-free-after-copy-in scenario with every
original name (list and map) still readable and writable afterward
(608), a `For each` loop variable bound to a nested list is independently
copied - isolated via a plain-assignment alias, since the analyzer does
not (independent of this brief) accept a loop variable as a direct
`Set element N of`/`append ... to` target (609).

Four PRE-EXISTING tests were rewritten in place, at the same numbers,
because their entire premise - that a list or map could be made to
contain itself - is no longer true: **171** (`append x to x` was a
literal self-cycle, truncated by `_list_print`'s depth guard; now `x`
becomes `[[]]`, a copy of its own prior empty state, no truncation, no
error), **186** (`set m's "self" to m.` was a self-cycle; now `m` gains a
"self" key holding a copy of its prior state, one level deep), **204**
(a mutual two-list cycle via `append aa to bb` then `append bb to aa`;
now `aa` ends up three levels deep - a copy of `bb`, holding a copy of
`aa`'s original empty state - not infinite), and **205** (a mixed map/
list mutual reference; `c1`'s "to_list" copies `c2`'s state at the moment
of the `set`, so the LATER `append c1 to c2` only changes `c2` and `c1`
stays a plain `{"to_list": []}`). All four's outputs were verified by
running the actual program before the `.expected` files were rewritten,
not derived by inspection.

**A pre-existing, unrelated bug found while writing the performance
test, NOT fixed here.** `print element N of L's length.` - the property
access chained directly onto an inline `element N of` expression,
without an intermediate variable - segfaults on 0.4.14 REGARDLESS of
this brief: reproduced with a plain list of strings, no nesting, no
copy-in involved at all (`a list called names is ["hi", "there",
"world"]. print element 1 of names's length.` → segfault, rc 139). The
emitted assembly shows the statement compiled as a bare `element 1 of
names` followed immediately by `PRINT_INT` - the `'s length` half is
lost somewhere in parsing, and the raw list pointer is read as though it
were the integer to print. Assigning to a variable first (`a list called
g is element 1 of names. print g's length.`) works correctly and was
used throughout this report's own tests instead. Narrow (#109/#111 are
lists-only and copy-in-only respectively): flagged here for the master
to verify and register separately, not registered or fixed on this
branch.

**Not attempted.** Reference-counting or any other sharing model:
Option 1 (copy by default) was the ruling; this entry implements it, not
an alternative. Making list/map fields legal inside a `thing`: still
deferred per LANGUAGE.md 1891/2668, unrelated to this ruling landing -
the Things chapter gained only the one clarifying sentence the brief
asked for, since a thing cannot hold a collection field to demonstrate
the point on yet.

---

### 112. A typed function that falls off its end hands back the empty value of every declared type — before this fix that was true for four of eleven, and the rest crashed

**Status:** Fixed in v0.4.15 — memory safety, a valid program (written in the
exact shape LANGUAGE.md itself shows) crashes. Registered 2026-08-29
(verified by the master 2026-08-29 00:50, confirmed by the owner
2026-08-29). Regression tests: 630–640 (one per declared type, plus the
manual's own `score` example pinned verbatim). Evidence:
`vox-notes/evidence/2026-08-29-fall-off-end/` (`j_list.vox`,
`k_list_print_only.vox`, `j_map.vox`, `k_buffer.vox`, plus the four that
already passed).

```vox
To 'maybe' with a boolean called 'the choice'.
    If 'the choice' then,
        Return a list, [1, 2].

a list called r is 'maybe' of false.
print r's empty.
```

LANGUAGE.md:2826–2830 promises: "If no branch fires and the function falls
off its end, it hands back the empty value of its declared type: empty
text, zero, or a `value` tagged as the number `0`." On v0.4.14, that
promise held for only four of the eleven expressible types
(LANGUAGE.md:797, "Parameters may use any of the 11 expressible types"),
plus `thing`, which was safe but not correct:

| Declared return type | v0.4.14 | v0.4.15 |
|---|---|---|
| `number` | `0` ✓ | `0` ✓ (unchanged) |
| `float` | `0.0` ✓ | `0.0` ✓ (unchanged) |
| `boolean` | `0` ✓ | `0` ✓ (unchanged) |
| `text` | `""` ✓ | `""` ✓ (unchanged) |
| `value` | tagged `0` ✓ | tagged `0` ✓ (unchanged) |
| `time` | raw garbage in rax, read as a timestamp | the zero time (Unix epoch) |
| `list` | **segfault** on first use | a real, fresh empty list (`[]`), takes `append` |
| `map` | **hang** walking a bogus header | a real, fresh empty map (`{}`), takes a key set |
| `buffer` | **segfault** on first use | a real, fresh, dynamic, zero-size buffer, takes `append` |
| `thing` | the caller's own destination storage, memory-safe but **never written** — reads whatever the caller's stack already held | the caller's destination storage, written with the thing's own all-defaults instance |
| `file` | raw garbage in rax, read as a file handle | unchanged — see "Left for a human" below |

**Cause.** Bug #43's fix (BUGS_FOUND ~2637–2645) added the implicit
epilogue that runs when a typed function's only `Return`s are nested
inside branches and none fired: `src/codegen/statements.rs` ~1485, "If no
explicit return, add a default epilogue." Its `match
self.current_function_return_type` only covered `Type::String`,
`Type::Value`, and `Type::Integer | Type::Float | Type::Boolean` — every
other declared type fell to a bare `_ => {}`, leaving rax (and, for
`value`, r11) holding whatever the last real computation left there. The
caller then read that stray value AS the declared type: a `list`/`buffer`
dereferenced it as a heap pointer (segfault); a `map` walked it as a
header with a garbage-sized bucket count (hang, or a crash on an unlucky
size).

`thing` was a half exception. Plan 310 §5 already made a thing-returning
function's epilogue emit `mov rax, [rbp-{slot}]` — the caller's OWN
destination address, passed in as a hidden first argument, so the
returned pointer was always valid caller storage and never wild. But
nothing had ever WRITTEN through that pointer on the fall-off path, so
its bytes were whatever the caller's freshly-`sub rsp`'d stack frame
already held — never the all-defaults instance every OTHER route to an
unwritten thing gets (`generate_thing_decl`, a `.bss` global). Safe, but
not what the manual promises ("a field without a default takes its
type's zero value", LANGUAGE.md:960).

**Fix.** `src/codegen/statements.rs`'s fall-off match gained arms for
every remaining declared type:

- `Type::Time` joins the existing `Integer | Float | Boolean` arm — a time
  field's own undefaulted zero is a bare `0` (`src/codegen/things.rs`'s
  `default_bits`), so `xor rax, rax` is already correct.
- `Type::List(_)` / `Type::Map(_)` call the existing
  `emit_empty_value_for(VarType::List | VarType::Map)`
  (`src/codegen/vars.rs`), which generates a real `Expr::ListLit`/`MapLit`
  with zero elements — the same fresh heap allocation the literal
  `[]`/`{}` makes, not a shared frozen sentinel, so `append`/a key set
  both work on the result.
- `Type::Buffer` calls `_alloc_buffer` directly — the same dynamic,
  zero-size, growable allocation `Create a buffer called x.` makes.
  Deliberately NOT `_released_buffer_header`
  (`coreasm/x86_64/resource_buffer.asm`): that shared header refuses
  every write (LANGUAGE.md's Truncation Behavior), so a fallen-off buffer
  built from it would make a later `append` a silent no-op.
- The `Type::Thing(_)` branch now writes the thing's all-defaults
  instance through the destination pointer before handing it back — a new
  `emit_thing_defaults_through_r10` (`src/codegen/things.rs`), the same
  `scalar_slots`/`default_bits` walk `generate_thing_decl` already uses
  for an unwritten declaration, retargeted to write through a pointer (in
  `r10`) instead of a named stack/`.bss` slot.

**Left for a human: `file`.** A `file` has no empty value anywhere in the
language — `src/parser/declarations.rs` refuses to even declare one
without an initializing path ("A file variable must be initialized with a
path"), and nothing in LANGUAGE.md's File I/O section describes a
closed/null file. There is no cheap, real value to fabricate here. Left
unchanged rather than worked around; a `file`-returning function that
falls off its end still hands the caller whatever rax held. In practice
this looks unreachable through every call-site shape this fix's own
testing tried — `a file called r is <file-returning call>.`, and `Set r
to <file-returning call>.` on a pre-declared `file`, both already fail to
compile today ("Property 'size' requires a buffer, list, map, or file
variable: r") independent of whether the callee falls off its end or
returns unconditionally. That is a separate, pre-existing gap in
`Return a file,`'s call-site support, not part of this fix, and is noted
here only so it isn't mistaken for this bug's blast radius. `timer` has
the same "no way to receive a call result" shape (`Create a timer called
t.` is its own statement, not an initializer expression) and was not
touched for the same reason.

---

### 114. Reading a number-valued map key into a `text` variable compiles clean and segfaults on first string use; the type check that fires for a literal map is absent for a dynamically-built one

**Status:** Fixed in v0.4.16. Memory safety, a program of individually-legal statements crashed with SIGSEGV (exit 139) on both the shipped 0.4.14 compiler and the 0.4.15 stack. Reported 2026-08-30 (found by the vox-fuzz adversarial hunt, seed 70296130; reduced clean-room by the master; **confirmed by the owner 2026-08-30**, who ruled the fix a cast: "I'd like the type to dynamically switch to the correct new type and be casted as such (since it's a dynamic type). Like 'as a text'.").

**Symptom.** Four lines:
```vox
a map called 'the store' is {}.
Set 'the store's "leftover" to 547.
a text called 'the reading' is 'the store's "leftover".
Print "{'the reading'}".
```
The declaration and the read alone run fine (a program that stops before using `'the reading'` exits 0). The crash is on **use**: the number `547`'s raw bits sit in the text slot, and the format slot `{'the reading'}` dereferences them as a `char*`, reading 547 as an address walks off into unmapped memory → SIGSEGV. Any string use (print, join, slot) triggers it.

**Why it is a real bug, not a mistyped program.** The language already treats this read as an error, but only statically. With a **literal** map the compiler catches it: `a map called s is {}. a text called t is s's "absent".` → compile error *"cannot initialise 't', which is a text, with a number read out of map 's'."* With a **dynamically-built** map (`{}` then `Set key to <number>`) the compiler cannot see the value's type through `Set`, emits no error, and the runtime copies the raw i64 into the text slot without consulting the value's runtime type tag.

**Root cause.** A dynamic map value carries a runtime type tag; the read of a map value into a typed variable never checks it against the destination type when that type is not known statically. The exact check that fires for the literal case is missing for the dynamic case.

**Fix (owner ruling 2026-08-30).** On a map-value read into a typed variable whose value type is not statically known, the value is CAST to the destination type, exactly as an explicit `... as a text` would, never the raw bits copied through. `a text called t is s's "k"` where `"k"` holds `547` yields `t = "547"`.

The cast reuses the exact runtime-tag dispatch `<value> as a <type>` already lowers to for a `value` (Mixed) variable, `emit_value_retype`, `src/codegen/tags.rs`, factored out of it as `emit_scalar_cast_from_runtime_tag`: given a payload in `rax` and its runtime tag in `r11` (both of which `_map_lookup` already leaves set), it dispatches on the source tag and converts to the target scalar type, exactly the sixteen `number`/`float`/`text`/`boolean` ↔ `number`/`float`/`text`/`boolean` conversions `Expr::Cast` defines. `emit_value_retype` now calls it and stores the result back into the `value`'s payload/tag slots, unchanged behavior.

Two new call-site helpers in `src/codegen/vars.rs`, invoked at every place a `MapAccess` value lands in a destination (`Statement::VarDecl`, covers both a declaration and the `Set` spelling, local and global; `Statement::Assignment`, local and global; `Statement::Return`; and a function-call argument in `src/codegen/functions.rs`), right before the existing `emit_empty_value_if_missed` (#91) at each of those sites:

- `emit_map_value_cast_if_needed`, for a scalar (`number`/`float`/`text`/`boolean`) destination: on a **hit** (`rax != 0`), loads the tag and calls `emit_scalar_cast_from_runtime_tag`. On a **miss** (`rax == 0`) it does nothing and falls through to #91's existing handling, a miss's tag is always `TAG_INTEGER` with payload 0, indistinguishable from a genuinely stored integer `0`, so casting it through this switch would turn "absent key into a text" into the text `"0"` instead of #91's empty text. This is a pre-existing ambiguity #91 already accepted (a real `0`/`false`/`0.0` map value read into a `text` destination is indistinguishable from a miss and answers the same empty text either way); this fix does not touch it.
- `emit_map_value_collection_guard`, the master's assumption for the fallback the owner flagged: a `list`/`map` destination whose value's runtime tag does **not** match (a number or text where a list/map is expected, `<number> as a list` has no defined meaning, unlike the four scalar casts) sets the error flag and gives the destination its own empty value (`emit_empty_value_for`, shared with #91), rather than storing a scalar payload where every later list/map operation expects a heap pointer. A matching tag is a no-op, `_map_lookup`'s existing `emit_copy_if_collection_reg` has already deep-copied the value correctly.

**Per-type table** (a map built with `Set`, one call per row, `a <type> called t is m's "k".`):

| destination | source value | before | after |
|---|---|---|---|
| `text` | `number` 547 | SIGSEGV | `"547"` |
| `number` | `text` "42" | SIGSEGV | `42` |
| `float` | `number` 7 | wrong (integer bits read as a double) | `7.0` |
| `text` | `boolean` true | SIGSEGV | `"true"` |
| `number` | `boolean` true | (already worked, 0/1 IS the representation) | unchanged |
| `text` | `float` 3.14 | SIGSEGV | `"3.14"` |
| `list` | `number` 547 | SIGSEGV (raw bits as a list pointer) | `[]`, error flag set |
| `text` | absent key (unprovable miss) | (already worked, #91) | unchanged: empty text, error flag set |
| `list` | a real list value | (already worked) | unchanged |

**This also closes a related, previously out-of-scope gap:** a *heterogeneous literal* map (`{"k": 42, "j": "text"}`) reached the identical runtime path, `check_declared_read_type`/`check_type_lock` can prove a homogeneous literal's value type but not a per-key one, and crashed the same way; `tests/p294_type_lock.rs`'s `heterogeneous_map_value_read_still_crashes_a_known_gap` pinned this as an explicitly out-of-scope known limitation. Because the fix keys off the read's runtime tag rather than whether the map is literal or `Set`-grown, that case now casts too, and the test is renamed `heterogeneous_map_value_read_now_casts_instead_of_crashing` and re-pinned to the new behavior.

**Undefined-cast fallback, still open for the owner (master's assumption, unchanged by this fix):** should a `number`/`text`/`boolean` read into a `list`/`map` destination (or the reverse) later be ruled to convert to something (e.g. `[547]` or a one-key map) rather than error? Left as the error-flag fallback per the brief; a follow-up if the owner rules otherwise.

**Tests.** `tests/641`–`646` (each scalar cast direction, the exact four-line repro, the undefined-cast fallback, and the unprovable-miss regression pin); `tests/p294_type_lock.rs`'s renamed test above.

**Provenance (precise chain).** The fuzz produced a **wrong-value** divergence, not a crash: the 1,280-line generated program (`--budget 40 --layout random`, seed 70296130) ran to `exit 91` because a type-mismatched read off a dynamic map failed to raise the error flag; the classifier flagged wrong-value. Reducing that program clean-room, the same construct **segfaulted** on string use, the two faces of one hole. Evidence: `vox-notes/evidence/2026-08-30-segv-map-text/` (4-line repro + literal/dynamic pair) and `vox-notes/evidence/2026-08-30-hunt/lst49-70296130/` (the fuzzer program). Artefact for confirmation: the master's bug page.
