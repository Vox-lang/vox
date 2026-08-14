# Vox compiler issues found while building a JSON library

Found while writing `json.vox` (a from-scratch JSON parser/serializer) against the
`vox` compiler built from this repo at the current `main`. Every repro below is a
minimal, standalone `.vox` file that reproduces the issue on its own — none depend
on the JSON library itself.

Toolchain: `rustc`/`cargo` 1.75.0 (Ubuntu 24.04 apt package). Note the crate's own
`rust-version = "1.87"` in `Cargo.toml`, and three call sites using stdlib methods
stabilized after 1.75 (`Option::is_none_or`, `usize::is_multiple_of` x2) — those are
environment/toolchain mismatches, not language bugs, so they're noted at the bottom
rather than numbered with the rest.

---

## 1. `Print` on an inlined float-returning call prints raw bit-pattern

```vox
To 'give one' with a number called n.
  a float called result is 1.0.
  Return a float, result.

Print 'give one' of 5.
```
Prints `4607182418800017408` (the IEEE-754 bits of `1.0` reinterpreted as an
integer) instead of `1.0`.

**Workaround:** assign to a declared `float` variable first, then print that.
```vox
a float called x is 'give one' of 5.
Print x.   (correctly prints 1.0)
```
Same underlying bug affects a `value`-typed variable holding a float in some
call shapes — see #5.

---

## 2. `Return a boolean, <A and B>.` fails to parse as an if-branch action

```vox
To test with a number called ch.
  If ch is greater than or equal to 97 then, Return a boolean, true.
  Return a boolean, ch is greater than or equal to 65 and ch is less than or equal to 70.
```
```
error: Expected a statement, got Is
```
The identical expression works fine as the *only* statement in a function:
```vox
To test1 with a number called ch.
  Return a boolean, ch is greater than or equal to 48 and ch is less than or equal to 57.
```
compiles and runs correctly. It also fails identically when it's the `Otherwise`
branch of an if/but-if/otherwise chain, not just after a preceding `If`.

**Workaround:** accumulate into a flag variable in each branch, return the flag
once, unconditionally, at the end:
```vox
To test with a number called ch.
  a boolean called result is false.
  If ch is greater than or equal to 65 and ch is less than or equal to 70 then, the result is true.
  Return a boolean, result.
```

---

## 3. A nested, self-terminated `If` cannot be one action inside another branch's comma-list

This was the single biggest time-sink. Any complete `If ... then, X.` (even
one-liner, no `Otherwise`) has its own terminating period. If it's placed as one
item in the middle of an *outer* branch's comma-separated action list, that period
closes the outer statement too — silently. Everything textually after it is then
parsed as fresh top-level code, which cascades into confusing errors (often
`Unknown variable` / `Unknown function`) that can be dozens of lines away from the
actual defect, in code that was previously compiling fine.

```vox
To 'append hex escape' with a buffer called out and a number called ch.
  Append "\u00" to out.
  a number called hi is ch bit-shift-right 4.
  a number called lo is ch bit-and 0xF.
  If hi is less than 10 then, Set byte {out's length add 1} of out to {48 add hi}. Otherwise, Set byte {out's length add 1} of out to {87 add hi}.
  If lo is less than 10 then, Set byte {out's length add 1} of out to {48 add lo}. Otherwise, Set byte {out's length add 1} of out to {87 add lo}.
```
When these two `If/Otherwise` lines are themselves nested one level deeper (as
actions inside a *different* outer `If`'s branch), the second one triggers
`error: Expected a statement, got Otherwise` pointing at the second line — even
though each line is independently valid.

This is not limited to `If` branches — it reproduces identically inside a `While`
loop body:
```vox
While i is less than or equal to n,
    If pretty is true then, Append "\n" to out, 'json indent' of out and depth.
    a value called elem is element i of lst,
    ...
```
The nested `If`'s period closes the `While` body early; everything after is
misparsed.

**Workaround:** extract any non-trivial nested conditional into its own function
(a single function call has no embedded period), or flatten into a sequence of
independent top-level `If` statements using flag variables, each with one simple
action. Both patterns are used throughout the JSON library.

---

## 4. A function call directly followed by an arithmetic operator absorbs the operator into its own argument

```vox
To 'state pos' with a list called state.
  Return a number, element 1 of state.

To 'advance state' with a list called state and a number called by.
  Set element 1 of state to {'state pos' of state add by}.
```
Calling `'advance state'` raises:
```
error: Cannot use list state in arithmetic.
```
`'state pos' of state add by` is parsed as `'state pos' of {state add by}` — the
call's argument greedily consumes the trailing arithmetic instead of the call
binding tighter than the operator. The error message names the wrong culprit
(a *type* error about the list, not a parse/precedence error), which makes this
particularly hard to trace back to its real cause.

Comparisons are **not** affected — `'some call' of x and y is false and ...`
parses as expected; only arithmetic operators (`add`/`subtract`/`multiply`/
`divide`/`modulo`/`bit-*`) trigger this.

**Workaround:** always brace the call explicitly before applying arithmetic to
its result:
```vox
Set element 1 of state to {{'state pos' of state} add by}.
```

---

## 5. `Set X to Y.` loses a `value`-local's tag across a function return; `the X is Y.` does not

**Status:** fixed in v0.3.5. Regression test: `tests/json_issue_05_value_set_retains_tag.vox`.

```vox
To 'make float value' with a float called f.
  Return a value, f.

To 'dispatch' with a boolean called wantfloat.
  a value called result is 0.
  If wantfloat is true then, set result to 'make float value' of 3.14.
  If wantfloat is false then, set result to 42.
  Return a value, result.

Print 'dispatch' of true.
```
Previously printed the raw bit-pattern (see #1) instead of `3.14`. It now
prints `3.14` correctly, and `Set ... to ...` on a `value`-typed local preserves
the returned tag the same way `the ... is ...` and `... is ...` do.

---

## 6. A blank line inside a function body silently ends the function early

```vox
To example with a number called n.
  a number called a is n.

  a number called b is a add 1.
  Return a number, b.
```
Fails with a genuinely excellent, precise diagnostic:
```
a paragraph break closes all open clauses, including the enclosing function,
so `a` is no longer in scope here
```
This directly contradicts the docs (`### Paragraph Breaks (Blank Lines)`):
> Blank lines ... can be used freely to organize code into logical sections.
> They are optional and have no effect on program execution.

In practice a blank line is only safe *between* two already-fully-terminated
top-level constructs (e.g. between two function definitions) — never inside one.
Given the diagnostic quality here, this feels more like the documentation being
wrong than the compiler being wrong; either the docs should say so explicitly, or
blank lines inside a body should be genuinely inert as written.

---

## 7. Same-named locals of mismatched type in two *different* functions corrupt an unrelated, actually-executed call site

This is the strangest bug found. Minimal repro:
```vox
To 'make map' with a buffer called src and a list called state.
  a map called result is {}.
  Set result's "hardcoded" to 99.
  Return a value, result.

To 'unrelated caller' with a buffer called src and a list called state.
  a value called result is 0.
  the result is 'make map' of src and state.
  Return a value, result.

a buffer called b is "test".
a list called s is [1, false, ""].
a value called v is 'make map' of b and s.
Print v.
```
`'unrelated caller' `is never invoked anywhere in the program. Its mere presence —
declaring its own local also named `result`, of a *different* type (`value`
vs. `map`), that gets assigned from a call to the same `'make map'` — corrupts the
**directly executed** call to `'make map'` at the bottom: `v` prints as `nothing`
instead of `{"hardcoded": 99}`.

Renaming *only* the unreached function's local (`result` → `output`, everything
else identical) makes the actually-executed call work correctly again.

Further isolation:
- Two functions sharing a `number`-typed local of the same name, both assigned
  from cross-function calls: **no bug**.
- Two functions sharing a `value`-typed local name where one function's `result`
  is `map`-typed and the other's is `value`-typed, and at least one is populated
  via `the result is 'other function' of ...`: **bug reproduces**.

This is a compile-time effect (an unreached code path changes the behavior of a
reached one), not a runtime one, which suggests some part of type/slot inference
is operating across function boundaries rather than per-function.

**Workaround:** give every `value`-typed (and, to be safe, every
collection-typed) local/parameter a name that's unique across the *entire file*,
not just within its own function. The JSON library now does this throughout
(`objmap`, `arrlist`, `dispatchval`, `entrymap`, `stepmap`, etc. instead of a
single generic `result` reused everywhere).

---

## 8. `element N of` / `For each` loses a collection element's type tag when read from a *parameter* into a `value`

Still being isolated in detail, so this section will likely grow, but the core
shape is solid:

```vox
To 'check element' with a list called lst and a number called idx.
  a value called elem is element idx of lst.
  a boolean called ismap is false.
  If elem is a map then, the ismap is true.
  Print ismap.
  Print elem.

a map called m1 is {"a": 1}.
a list called lst is [].
append m1 to lst.
'check element' of lst and 1.
```
Prints `0` then a raw pointer-looking integer, instead of `1` then
`{"a": 1}`.

What's been ruled out so far:
- **Not** about list construction — `append`-built lists (as opposed to inline
  list *literals*) behave correctly when read back at the top level.
- **Not** specific to `element N of` — `For each item in lst, ...` shows the
  identical symptom when `lst` arrived as a parameter.
- **Is** specific to the `value` intermediate — extracting straight into a
  concrete type, `a map called item is element idx of lst.`, works correctly
  every time, including through parameter chains and through a helper function
  that itself returns a concrete `map`.
- A mismatched concrete extraction (e.g. reading a map element into a `number`)
  does **not** trip Vox's own error flag — it silently returns garbage, so
  `On error` can't be used to detect/dispatch on the real type.

**Practical impact:** a generic "walk a `value` tree that may contain nested
lists/maps, read via a list/map parameter passed down through recursion" pattern
— exactly what a JSON serializer needs — is not reliable as written. The JSON
library's serializer currently produces correct output for scalar values,
strings (incl. full escaping and pretty-printing/indentation), and top-level
objects/arrays, but shows raw pointers instead of recursing correctly into
maps that are elements of a list one or more parameter-passes removed from
where they were built. Isolating a full workaround is in progress.

---

## Documentation says `{{` / `}}` escape to literal braces; they never do

```vox
a text called t is "{{x}}".
Print t.        (prints {{x}}, not {x})

a buffer called b is "{{x}}".
Print b.        (also {{x}})

Print "{{y}}".   (also {{y}}, not {y})
```
Tested across direct `text` initialization, direct `buffer` initialization, and
inline `Print` — the doubled braces are never collapsed, in any context, despite
the Escape Sequences table listing `{{` → "Literal `{`" and `}}` → "Literal `}`"
as supported escapes.

This isn't a functional bug in the sense of breaking working code, but it's a
real trap: every double-quoted string is always parsed as a potential format
string, so a single **unescaped** `{` or `}` anywhere in a string literal (not
just an unbalanced one — see below) is a compile error, and the documented way to
escape it doesn't work either. This matters a great deal for a JSON library,
since JSON's own syntax is mostly braces and brackets.

A related, sharper trap: even a properly *balanced* pair is not required to
trigger the failure — a single **unpaired** `{` or `}` in a string, with no
attempt at interpolation, also fails to parse:
```vox
a buffer called out.
Append "{" to out.
```
```
error: Unknown variable:
```
(empty name — the parser tried to read the content between `{` and end-of-string
as an interpolation expression, found nothing valid, and reported an unnamed
"unknown variable.")

**Workaround used throughout the JSON library:** never put a bare `{`, `}`, or
`{{`/`}}` in a string literal. Use character literals and byte-level writes
instead:
```vox
Set byte {out's length add 1} of out to '{'.   ('{' is 123, a plain integer)
```
and for JSON text embedded as Vox source (test fixtures, etc.), read it from a
file with `Read from ... into ...` rather than writing it as a source literal at
all — that sidesteps the whole issue, since it isn't about runtime string
*content*, only about how the compiler parses a `"..."` token in source.

---

## Undocumented reserved words

Found by hitting them and reading the resulting error, not by systematic search,
so this list is almost certainly incomplete. None of these appear in the
Keywords/reserved-words reference tables in `LANGUAGE.md`:

- `ms` (aliases to the `milliseconds` time-unit keyword — reasonable once you
  know it, but easy to hit by accident since it's such a common variable name)
- `message`
- `flag`

Each produces a clear "Cannot use 'X' as a variable name - it's a reserved
keyword" error — but for `ms`, the error names `milliseconds` rather than `ms`
itself, and for `message`, the error text says `'text'` rather than `message`
(pointing at a plausible-looking but wrong token), which makes the actual
offending identifier harder to spot than it should be from the message alone.

---

## Toolchain note (environment, not a language bug)

Ubuntu 24.04's apt-packaged `rustc`/`cargo` is 1.75.0; `Cargo.toml` declares
`rust-version = "1.87"`. Building from a clean clone in this environment fails
outright on that MSRV check. Beyond the MSRV gate itself, exactly three call
sites use stdlib methods stabilized after 1.75:

- `src/analyzer/mod.rs`: one use of `Option::is_none_or` (stabilized 1.82)
- `src/codegen/mod.rs`: two uses of `usize::is_multiple_of` (stabilized 1.87 —
  this is likely *why* the MSRV is set to exactly 1.87)

Rewriting these three call sites to their pre-1.82 equivalents
(`.map_or(true, f)` and `% n == 0`, respectively — verified behaviorally
identical) is enough to build cleanly on 1.75, for whatever that's worth in
environments that can't easily get a newer toolchain (no `rustup`/
`static.rust-lang.org` access, no PPA with a newer `rustc` than stock `noble`).
Also worth flagging separately: the checked-in `Cargo.lock` is in the v4 lock
format, which requires Cargo ≥ 1.78 to even read — `cargo generate-lockfile` on
1.75 regenerates a compatible v3 lock without incident, so this is a much
smaller issue than the MSRV itself, just worth knowing about.

**Update:** the three call sites were rewritten to their pre-1.82 equivalents
as suggested above. The real floor turned out to be gated by a dependency, not
vox's own code: `proc-macro2` (pulled in transitively via `thiserror` → `syn`)
requires rustc 1.71, one minor version above the 1.70.0 this note was
originally checking against. Verified empirically by building against rustc
1.70 (fails, `proc-macro2` needs 1.71) and 1.71 (succeeds) in clean containers.
`rust-version` is now `"1.71"`.
