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
| `To 'give it'. Return a float, 3.` + `print 'give it'.` | `3` — rendered as an integer, not `3.0` |
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
