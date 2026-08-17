# 310 — User-defined structures

**Status:** design approved in outline by Josj (2026-08-17); items marked
**PROPOSED** below still need his explicit yes/no at spec review before
implementation. Nothing in this document is implemented yet.

**Dependencies:** none (Track-independent). Interacts with the possessive
property machinery (`ObjectProperty`, `src/parser/ast.rs`) and the
function call/definition grammar.

**Design rationale:** Vox has eleven builtin types and no composition
mechanism. The owner's architectural position: languages provide
primitives plus a way to compose them — in C, `Process` is a struct plus
`sys/wait.h` functions; in Rust, a std struct plus methods. Vox's
builtins are already compiler-blessed structs (a buffer is
`[capacity:8][length:8][flags:8][data...]` with `'s` reading fields at
fixed offsets), so structures expose a mechanism the compiler already
uses internally. Everything below is resolved at compile time: no
vtables, no dispatch, no runtime component — inheritance and
class-style dynamism are permanently out of scope.

---

## 1. Definition (settled)

```
A type called point has
  a number called x is 0,
  a number called y is 0.
```

- The keyword is **type** (owner's choice, 2026-08-17: the honest word —
  users are defining a type, and usage then reads identically to the
  builtins. "record" rejected for its database connotation, "struct"
  rejected as jargon, "structure" considered but passed over).
- Two kinds of entry: **data fields** (`a <type> called <name>`, with an
  optional `is <literal>` default) and **function-member declarations**
  (`a function called <name>` — the manifest, section 4). Function
  *bodies* never appear inside the definition; only declarations do.
- A field without a default gets its type's zero/empty value.
- Closed by the same termination rules as other constructs.
- The structure name then works everywhere a type keyword works:
  `a point called p.`, function parameters (`with a point called p`),
  and return types (`Return a point, out.`).

## 2. Construction (settled)

**No init methods.** Two forms:

```
a point called p.                                  (defaults)
The example is a point's 'from polar' with 1.0 and 0.5.   (maker)
```

- Makers are ordinary functions that return the structure (section 4).
- `The <name> is <expr>.` with a previously unseen `<name>` declares it,
  type inferred from the expression. Precedent: `the label is classify
  of n.` already reassigns with return-type tracking; top-level `Set`
  already declares implicitly.

## 3. Field access (settled)

`p's x` reads a field; `Set p's x to 3.` writes it. Same possessive the
builtins use; offsets fixed at compile time.

Fields are ordinary expressions and lvalues everywhere the grammar
allows either: bare assignment (`origin's y is origin's y add 1.`),
`increment`/`decrement`, format-string interpolation (`"{origin's x}"`),
comparisons, and as call arguments. Whole-structure interpolation
(`"{p}"`) follows the printing rule (section 7). Field access can never
fail at runtime — offsets are compile-time constants, so unlike list
element access there is no error-flag path.

Structures defined in one file are usable from another via `see`
(definitions are parsed into the program like functions), and top-level
structures are globals with the same inside-function visibility as other
top-level variables.

## 4. Functions and namespaces (settled)

Three call forms, one rule each:

| Form | Example | Rule |
|---|---|---|
| Free call | `'some method' on p` | Unchanged, global namespace |
| Instance possessive | `p's 'some method'`, `p's 'scaled by' on 2` | Sugar: receiver fills the **first parameter**; remaining args follow any call preposition. Works for any function whose first parameter is that type, declared in the manifest or not. Compile-time rewrite, zero runtime cost. |
| Type possessive | `a point's 'from polar' with 1.0 and 0.5` | Calls a function member **declared in point's manifest**. Article + type name + `'s`. |

**Membership is declared in the type — the definition is the manifest
(owner's design, superseding the earlier possessive-tagged signature):**

```
A type called point has
  a function called 'from polar',
  a number called x is 0,
  a number called y is 0.
```

- `a function called <name>` declares a **function member** — the type's
  callable API listed in one place. Function members take **no
  storage**: layout, copy, printing, and equality see only the data
  fields. Reading a type's definition enumerates its full surface.
- Each declared member is then defined with **`To do the <type>'s
  <name>`**, referencing the known identifier from the manifest:

```
To do the point's 'from polar', with a float called r and a float called theta.
  a point called out.
  ...
  Return a point, out.
```

- **Article convention (owner's rule):** "a/an" pairs with *types* and
  values coming into being; "the" pairs with *known identifiers*. Hence
  the definition says `the point's 'from polar'` (the member is a known
  identifier, declared in the manifest) while a maker call says
  `a point's 'from polar'` (a new point comes into being).
- The manifest is checked both ways: a `To do` definition whose member
  is not declared errors at the definition ("point does not declare
  sparkle — add `a function called sparkle` to the type"); a declared
  member nothing defines errors at the type ("point declares
  'never written' but nothing defines it").
- A maker's `Return` type is cross-checked against its owner; mismatch
  is a compile error naming both lines.
- Makers (first parameter not the owner) are reachable **only** through
  the type possessive — the full name of `'from polar'` is `a point's
  'from polar'`. Declared *instance* members (first parameter is the
  owner) get both the type possessive and the instance possessive.
- **Plain global functions never auto-join a namespace** and need no
  manifest entry — `magnitude` stays an ordinary function, and the
  instance sugar still applies to it via its first parameter.
  (Membership by return type was considered and rejected: invisible at
  the signature, collision behaviour dependent on distant `Return`
  edits, and builtin-namespace spam.)

**One identifier space (settled):** type names, variable names, and
function names share a single global identifier namespace;
`a point called point.` is a first-come-first-serve error. This is what
makes `the point's` unambiguous. C and Rust keep types and values in
separate namespaces, but they can afford to — their types appear only in
dedicated syntactic slots. Vox's possessive puts types and variables in
the same grammatical position, so the unified space is required, not
stylistic.

**Collision rule (settled, first-come-first-serve):** each type owns one
member space containing its fields, its declared function members, and
every global function whose first parameter is that type. The second
definition of any name in that space is a compile error at its own
definition site, with a diagnostic pointing at the first. No shadowing,
no precedence order. (Precedent: the same refuse-ambiguity posture as
the `send`/`begin`/`stop` keyword lookaheads.)

**Parser notes:** `a <name>'s` where `<name>` is a defined type is the
type possessive; `a <name> called` is a declaration — one token of
lookahead separates them. `To do` followed by `the <typename>'s`
introduces a member definition; `do` stays an ordinary identifier
everywhere else (`send` treatment). The comma before the parameter list
(`'from polar', with ...`) follows the `Return a number, total.`
payload-comma precedent. Quoted identifiers take the possessive as
`'the point in question''s` — the quote-then-`s` lexing already has
precedent (LANGUAGE.md ~line 588). `type` becomes a keyword only in the
definition construct, an ordinary identifier elsewhere (same treatment
as `send`; verified: `type` is not a lexer keyword today, and type
predicates use the type nouns, never the bare word).

## 5. Copy semantics — **PROPOSED**

**Structures are value types: assignment and parameter passing copy the
whole value.**

```
a point called a.
Set a's x to 5.
a point called b is a.     (copy)
Set b's x to 9.
Print a's x.               (still 5)
```

Rationale: sizes are fixed at compile time, so copies are cheap, stack-
friendly, and need no allocation; and it avoids importing the aliasing
sharp edge the docs already warn about for lists (child references
invalidated by parent reallocation). No hidden sharing anywhere fits
Vox's explicitness. Functions receive copies; to give a caller a
modified structure, return it (`Return a point, out.`).

## 6. v1 field types — **PROPOSED**

v1 fields may be: **number, float, boolean, time**. Fixed 8-byte
scalars, making layout trivially `count × 8` with compile-time offsets.

- **text fields:** desired, but deferred pending verification of text
  handle-copy semantics (whether copying a text handle can observe
  mutation). If verification shows texts are safe to copy by handle,
  text joins v1 during implementation; otherwise v1.1.
- **Deferred to a later plan:** structure-in-structure fields, and
  buffer/list/map fields (these are reference-carrying and reopen the
  aliasing question section 5 deliberately avoids). Flat scalar
  structures first; nesting is a natural v2 once copy semantics have
  soaked.
- **Scope boundary of "works everywhere a type keyword works":** that
  clause covers *declaration positions* — `a point called p.`,
  `Create a point called p.`, declarations with initializers,
  parameters, and return types. It does **not** extend user types into
  the runtime tag system in v1: lists/maps *of* user types, `value`
  payloads, and `is a point` type predicates are all deferred with the
  collection fields above.

## 7. Printing — **PROPOSED**

`Print p.` prints fields in definition order, map-style:

```
{x: 5, y: 0}
```

Cheap to emit, immediately useful for debugging, and consistent with how
maps print. (Alternative if rejected: printing a structure is a compile
error directing the user to print fields individually.)

## 8. Equality — **PROPOSED**

`a is b` between two values of the same structure type compares
field-wise (compile-time expansion to per-field comparisons). Comparing
different structure types is a compile error. Ordering comparisons
(`greater than`) on structures are compile errors.

## 9. Storage (settled by consequence)

Function-local structures live on the stack; top-level structures in
`.bss`/`.data` like other globals. All field offsets are compile-time
constants. No runtime component of any kind.

## 10. Diagnostics for reserved wrong shapes (in scope)

The definition construct creates a family of sentences that are never
valid Vox. Each gets a targeted parser error that states the intent it
recognizes and names the canonical form — the established pattern from
the retired `see` forms, which error and point at the one correct
spelling rather than emitting a generic parse failure.

- `Create a type called point.` — never valid, in any version. Error:
  a type is defined, not created as a variable; write
  `A type called point has <fields>.`
- `A type called point is ...` — the learner reached for the
  declaration verb. Error: `is` declares a variable; a type definition
  uses `has`.
- `A type called point.` with no fields — v1 requires at least one
  field. Error says so and shows the shape.
- Declaring with an unknown type name keeps the existing unknown-type
  error, extended to suggest near-miss **user-defined** type names
  alongside the builtins.
- `a point called point.` (or any reuse of a type/function/variable
  name) — one identifier space, first-come-first-serve: error at the
  second definition naming the first.
- `To do the point's sparkle, ...` with no manifest entry — error at the
  definition: point does not declare sparkle; add
  `a function called sparkle` to the type.
- A manifest entry nothing defines — error at the type: point declares
  'sparkle' but nothing defines it.

And the positive counterpart, already implied by section 1's "works
everywhere a type keyword works" but stated here so it gets a test:
`Create a point called p.` **is valid**, equivalent to
`a point called p.` (all defaults), because user-defined type names
participate in every declaration form the builtin type keywords do.

## 11. Out of scope, permanently or for now

- Inheritance, virtual dispatch, runtime attribute lookup — permanently
  (requires a resident runtime, which Vox forbids by identity).
- Init methods — makers cover construction logic; field defaults cover
  the common case. Revisitable without breakage.
- Visibility/private fields — requires a module-visibility design Vox
  does not have.
- Auto-namespace membership by return type — rejected, see section 4.

## 12. Documentation and tests (for the implementation plan)

- LANGUAGE.md: new "Structures" chapter (definition, defaults, field
  access, the three call forms, tagging, collision rule, copy semantics,
  printing, equality); update the Types table; note `structure` and the
  type-possessive in the keyword/grammar sections. Restate the
  sentence-consumption interaction for multi-line definitions.
- vox-vscode: grammar additions for `structure` and the type possessive;
  keep the drift check green.
- Tests: definition/defaults; field read/write; all three call forms;
  manifest-declared maker + type possessive; To do definitions; both
  manifest mismatch errors (undeclared definition, undefined
  declaration); one-identifier-space collision; instance sugar with extra args via
  each preposition; per-structure duplicate `'from polar'` across two
  structures; collision errors (field vs field, field vs declared member,
  field vs global-first-param fn — each erroring at the second site);
  owner/Return mismatch; `The x is` inference; copy-on-assign observable
  test (mutate the copy, original unchanged); pass-by-value test;
  printing; equality; each reserved wrong shape from section 10 erroring
  with its targeted message; `Create a point called p.` working;
  `type` as an ordinary identifier outside the
  construct.

## 13. Open questions for review (the PROPOSED items)

1. Copy semantics: value types, full copy on assign/pass (§5)?
2. v1 field set: number/float/boolean/time, text pending verification,
   no nesting/collections in v1 (§6)?
3. Printing map-style (§7)?
4. Field-wise equality, no ordering (§8)?
