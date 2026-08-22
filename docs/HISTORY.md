# Vox — spec history

[`LANGUAGE.md`](../LANGUAGE.md) states the language as it is now: every rule in
the present tense, stated once. This file keeps the history that used to sit
inside it — what changed in which release, the defect that drove a rule, and
the design notes raised for review.

Each entry names the release it belongs to, the `LANGUAGE.md` section the text
was cut from, and the register entry ([`BUGS_FOUND.md`](BUGS_FOUND.md)) or
[CHANGELOG](../CHANGELOG.md) bullet that carries the full account. Nothing here
is normative — if a sentence below disagrees with `LANGUAGE.md`, `LANGUAGE.md`
wins.

Opened 2026-08-22, moving the historical text out of `LANGUAGE.md` at 0.4.10.

---

## 0.4.10 — 2026-08-22

### A collection parameter is the caller's collection
*Cut from LANGUAGE.md, "Functions → A collection parameter is the caller's collection".*

Before 0.4.10 a collection grown through a parameter stopped at the size its
literal happened to allocate, and every append past that was silently dropped —
register entry [#75](BUGS_FOUND.md). An **exported** function's parameters
changed shape to fix it. The consequence of that shape change is still a live
rule and stays in the spec: a `.so` with a `list` or `map` parameter and the
programs that `see` it must be built by the same version of Vox.

### Buffer parameters
*Cut from LANGUAGE.md, "Functions → Parameter and Local Types".*

The buffer-parameter rule — a `buffer` parameter **is** the caller's buffer and
stays the caller's buffer across a growth — is newer than the rest of that
section: register entry [#90](BUGS_FOUND.md), where a `buffer` grown past its
capacity through a parameter was a use-after-free and the caller's next read of
its own buffer segfaulted.

---

## 0.4.9 — 2026-08-21

### Shared-library transcripts
*Cut from LANGUAGE.md, "Libraries and Imports → Shared libraries".*

The blockquote that opens that section used to pin its transcripts to a
release: "Every output below is real, captured from this compiler (vox
v0.4.9)." The transcripts stay; the version stamp lives here, and the spec's
own `**Version**` line at the top of `LANGUAGE.md` is the one place a release
number belongs.

---

## 0.4.3 — 2026-08-18

### `length` stopped being a reserved alias
*Cut from LANGUAGE.md, "Keywords → Reserved Aliases".*

`length` used to appear in the reserved-alias table as an alias of `size`. It
is now a contextual keyword, so `a number called length is 1.` compiles, and
`x's length` still means the same as `x's size`.

### The contextual-keyword treatment widened
*Cut from LANGUAGE.md, "Keywords → Two classes of special word".*

0.4.3 extended contextual-keyword treatment to the whole possessive/phrase
family: `capacity`, `raw`, `all`, `first`, `last`, `second`, `size` and its
synonym `length`, and `version`. The list of what is contextual today stays in
the spec; the date it happened lives here.

---

## 0.4.2 — 2026-08-18

### `count` became a contextual keyword
*Cut from LANGUAGE.md, "Keywords → Two classes of special word".*

The property word `count` was reserved before 0.4.2 and contextual from 0.4.2
on, so `a number called count is 0.` compiles while `arguments's count` keeps
its meaning.

---

## 0.4.0 — 2026-08-18

### Design notes for review (things)
*Cut wholesale from LANGUAGE.md, "Things → Design notes for review", along with
its four `<!-- REVIEW: ... -->` markers.*

Four judgement calls the things implementation made on the way, recorded here
so they stay visible without hunting. The rules they describe are all stated in
their own right in `LANGUAGE.md`; what is preserved below is the reasoning and
the open question.

1. **Members-only definitions are rejected.** A thing listing only
   `a function called ...` entries and no data fields is a zero-byte thing, so
   v1 refuses it (see LANGUAGE.md, "Definition diagnostics"). Conservative and
   reversible: a later version could admit a member-only thing as a pure
   interface.
   <!-- REVIEW: members-only definitions -->

2. **`.lib` export of a thing is refused.** An exported library signature
   cannot take or return a thing yet; the diagnostic says to pass its fields
   across the boundary instead (see LANGUAGE.md, "`.lib` export of a thing is
   not yet supported"). Ordinary compilation is unaffected. A cross-boundary
   type system that knows about user things would lift this.
   <!-- REVIEW: .lib export refused -->

3. **The `origin` naming question.** The tests (and STYLE.md's own model line
   `Print magnitude of origin.`) declare `a point called origin` then set it to
   `(3,4)`. The origin is `(0,0)`, so the name is arguably untruthful under the
   read-aloud guide. This is a guide-level question, not a things-feature one —
   flagged for a STYLE pass, not a compiler change.
   <!-- REVIEW: origin naming -->

4. **Acyclicity — corrected from the plan.** Plan 310 framed things as
   "acyclic by grammar"; that framing is wrong. Things are acyclic by two
   mechanisms: the within-file defined-earlier ordering rule (a field type must
   be defined above the line), and the analyzer's registry DFS across files
   reached by `see`. The DFS is load-bearing across the merged registry, not
   redundant — it is what proves the multi-file registry acyclic.
   <!-- REVIEW: acyclicity correction -->

### Two `see` behaviour tightenings landed with cross-file things
*Cut from LANGUAGE.md, "Things → Cross-file definitions".*

A `see` of a file that cannot be read became an error — it was previously
silent without `-v`. That rule stays in the spec. A duplicate type name across
a `see` began erroring at the second definition, naming the other file; that
rule is stated in the same section and needed no second telling.

---

## 0.3.6 — 2026-08-14

### In-place retype of a `value`
*Cut from LANGUAGE.md, "Variables → Type Immutability".*

The in-place retype statement `<valuevar> is a <type>.` (e.g.
`numstr is a number.`) arrived in 0.3.6. The statement itself is documented in
the spec; only the version tag moved here.

---

## 0.3.0 — 2026-08-07

### Names and strings: why one token cannot mean two things
*Cut from LANGUAGE.md, "Names and strings", which kept the rule and the
diagnostic and lost the narrative below.*

Before 0.3.0, a double-quoted token was *both* a string literal and an
identifier, decided by position. That single overload is the root of a family
of silent wrong answers. This is the one that decided the change:

```
a number called "x" is "get five".
print x.                              (prints: 4198480)
```

The author meant to call the function `get five` and store its result in `x`.
But `"get five"` in expression position was read as a string literal — a
pointer to the function's code — and `x` quietly received that pointer as a
number. A function pointer, printed as a number, silently. No error, no
warning; the program runs and gives a wrong answer that looks like data.

That is what one token meaning two things costs. So in 0.3.0 the two were
split: `"..."` is a string literal everywhere, and a name is a bare or
single-quoted identifier. The program above became a compile error. The cost is
that every program written before 0.3.0 had to be migrated; the payoff is that
this class of silent wrong answer is gone.

"Reading a result" in `LANGUAGE.md` used to close by pointing at Mixed-Type
Lists "for what the guess used to cost". The cross-reference stays; the target
section states in the present tense why an undeclared return type is refused
rather than guessed, so the backward glance was redundant.

### The static type check
*Cut from LANGUAGE.md, "Variables → Type Immutability → What this doesn't catch".*

The class of bug the check closes — a variable's compiler-tracked type
disagreeing with what it actually holds at runtime — previously produced a
wrong number on screen at best and a segfault at worst. What the check cannot
prove statically is still let through unchecked, exactly as it was before the
rule; that scope caveat stays in the spec because it is a rule about the
checker.

---

## 0.2.0 — 2026-08-03

### Three `see` forms that silently linked nothing
*Cut from LANGUAGE.md, "Libraries and Imports → The `see` Keyword".*

`see "./path.so".`, `see "lib" version "1.0" from "./path.so".`, and
`see "./path.so" for "lib" version "1.0".` all pointed `see` at a `.so`
directly. Before 0.2.0 they compiled while linking nothing — every call into
the library was simply missing, with no warning. From 0.2.0 they error and name
the canonical `.lib` form. See the CHANGELOG entry for
[0.2.0 → Removed](../CHANGELOG.md). `see` of a `.vox` source was unaffected.

---

## 0.1.23 — 2026-07-31

### Why the `value` type exists
*Cut from LANGUAGE.md, "Lists and Collections → Dynamic Values (`value`)".*

A mixed-list element keeps its tag while it stays in the list, but before the
`value` type the moment you passed one to a function the tag was lost —
parameters are statically typed, so a mixed element passed `as a number` was
reinterpreted and one passed `as a text` was dereferenced as a pointer.
`value` was introduced to fix exactly that: see the CHANGELOG entry for
[0.1.23](../CHANGELOG.md).

---

## 0.1.21 — 2026-07-28

### Format Strings Everywhere
*Cut from LANGUAGE.md, "Input/Output → Format Strings" (a heading version tag).*

Every statement that takes a string value has accepted a format string since
0.1.21.

### Declarations in Branches
*Cut from LANGUAGE.md, "Input/Output → Format Strings" (a heading version tag).*

A variable declared in every branch of an `if`/`otherwise` chain has definitely
existed afterwards since 0.1.21.

---

## 0.1.17 — before the CHANGELOG begins

### Format Strings as Values
*Cut from LANGUAGE.md, "Input/Output → Format Strings".*

Before 0.1.17, a format string outside `Print` compiled to a NULL pointer: it
printed as empty and corrupted `execve` argv arrays. From 0.1.17 a format
string used as a value materializes into a fresh NUL-terminated string.

---

## 0.1.16 — before the CHANGELOG begins

### Parameter and local types
*Cut from LANGUAGE.md, "Functions → Parameter and Local Types".*

Buffer parameters, function-local buffer declarations with initializers, and
reassignment from a function call were fixed in 0.1.16. In earlier versions the
first two were rejected by the analyzer and the third silently corrupted the
variable's tracked type.

The 11-type parameter and return vocabulary the section documents came from
plan 296 (`docs/plans/`); the spec now states the vocabulary without citing the
plan.
