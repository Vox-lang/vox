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

**Status:** the `but if`/period shape is fixed in v0.3.6 along with #14, its
underlying cause — `tests/butif_chain_period_shape_b_plain.vox` covers the
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
