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

**Status: fixed on `main` (Unreleased).** Found 2026-08-16 while building a
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

**Status: fixed on `main` (Unreleased).** Same session as #17; mild, no
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

**Status: fixed on `main` (Unreleased).** Found 2026-08-16 while isolating
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

**Status: fixed on `main` (Unreleased).** Found 2026-08-16 by a red team
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

**Status:** **fixed on `main` (Unreleased)** — the large-magnitude half
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

**Status:** **fixed on `main` (Unreleased).** Found 2026-08-20 against
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

**Status:** **fixed on `main` (Unreleased)** — the harm half: a width no
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

**Status:** **fixed on `main` (Unreleased).** Regression test:
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

**Status:** **open**, found 2026-08-20 against released v0.4.6 by the
red-team agent on the file-property surface, alongside #37. Reproduced
by the master, who tested the whole table rather than the one property.

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

**Status:** **fixed on `main` (Unreleased).** Found 2026-08-20 by an Opus
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
