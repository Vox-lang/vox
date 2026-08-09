# Plan 296 — `list` and `buffer` across the `.lib` boundary: allow them as return types, and carry the element type

**Status:** specced 2026-08-08. Both halves verified against `23bc193`
(v0.3.3) by the plan author.

## Two defects, one piece of work

A shared library cannot usefully hand a collection back to its caller. There
are two separate reasons, and **fixing either alone leaves the feature
broken**, which is why they are one plan.

### Half 1 — `list`/`buffer` are rejected in return position

`src/lib_file.rs` accepts them as parameters and only as parameters:

```rust
Token::Buffer if position == "parameter" => Some(Type::Buffer),
Token::List   if position == "parameter" => Some(Type::List(Box::new(Type::Unknown))),
```

A `.lib` declaring `To f, returning a buffer.` is an error, and there is a
test pinning that behaviour:

```rust
#[test]
fn unsupported_return_type_is_named() { /* asserts "unsupported type" and "'buffer'" */ }
```

That test encodes the restriction this plan removes. **Updating it is expected
and correct** — do not treat it as a regression, and do not weaken the rest of
the test around it. If some type genuinely must stay unsupported in return
position, keep a case asserting *that* type instead, so the "named unsupported
type" diagnostic still has coverage.

### Half 2 — the element type is erased at the boundary

Even as a parameter, a list crosses with its element type hard-coded to
`Unknown` (the `Box::new(Type::Unknown)` above). The structure survives; the
typing does not.

Verified end to end. Library:

```vox
Library strkit version "1.0".

To 'split into' with a text called s and a list called out.
  Append s to out.
  Append "second" to out.
```

Consumer:

```vox
see strkit version "1.0" from "./libstrkit.lib".

a list called toks is [].
'split into' with "hello" and toks.
Print "count={toks's length}".
For each t from toks, print "tok=[{t}]".
```

**Actual:**

```
count=2
tok=[4206728]
tok=[139626265276507]
```

`count=2` is correct — the mutation crosses back, so the out-parameter shape
genuinely works. But the elements print as raw pointers, because the caller
has no way to learn they are text. This is the same element-type erasure
catalogued in plan 294 (findings 4, 14, 18), in a third location.

**A returned list would hit exactly this.** So half 1 without half 2 ships a
feature whose results are unreadable.

## What to build

1. **Allow `list` and `buffer` in return position** in `.lib` parse and emit,
   dropping the `position == "parameter"` guard for these two.
2. **Carry the element type** for lists across the boundary, in both parameter
   and return position, so `Type::List(Box::new(Type::Unknown))` becomes the
   declared element type.

Half 2 needs a surface syntax for a typed list. **Decide it and say why.** A
natural candidate is:

```
To 'split into' with a text called s and a list of text called out.
To 'tokens of' with a text called s, returning a list of text.
```

Before designing, establish what Vox source already accepts for a typed list
parameter — I tried three spellings and all three were rejected, but my test
harness also rejected the plain `a list called out` form that demonstrably
works, so **that test was broken and proves nothing**. Find out for real. If
Vox source has no typed-list syntax at all, then this plan needs it in the
language, not only in `.lib`, and that is a bigger decision — stop and tell me
rather than inventing `.lib`-only syntax that source cannot express.

Keep backward compatibility: an untyped `a list called out` in an existing
`.lib` must keep parsing, with the element type unknown as today.

## Acceptance criteria

1. A library can declare `, returning a list` and `, returning a buffer`, and
   a consumer can call it and use the result.
2. The verified repro above prints `tok=[hello]` and `tok=[second]` — real
   values, not pointers — for the **parameter** case.
3. The same holds for a **returned** list.
4. Round trip: emit a `.lib` with these signatures and parse it back
   (`lib_file.rs` already has round-trip tests; extend them).
5. `examples/mathkit_lib.vox` and the C-interop test still work — the ABI for
   existing scalar signatures must not shift.
6. Gate green: `cargo build --release` (0 warnings), `cargo test --release`,
   `./test.sh` (baseline **219 passed / 0 failed / 6 skipped**, includes a
   compile check over every file in `examples/`).
7. Plan 294 PoCs stay closed: `for d in tests/retype_audit_pocs/[0-9]*/; do
   bash "$d/poc.sh"; echo "$d -> $?"; done` — all **non-zero**.

## Documentation — I am auditing this myself, so get it right

`docs/SHARED_LIBRARIES_DESIGN.md` currently states the vocabulary as
`number`, `text`, `boolean`, `file`, `value` without distinguishing parameter
from return position — which is how I got this wrong in the first place.
Update it to state the rule precisely, per position, after your change.
I will check it against the code myself and send back anything that does not
match.

## Known adjacent gap — do NOT fix here

A `.lib`'s declared types are trusted, never verified against the `.so`
(plan 294 findings 19/20 — a library declaring a return type its
implementation does not provide crashes the consumer). This plan **widens**
what a `.lib` may declare, so it widens that hole. Note it in the plan doc as
a consequence; do not attempt to fix verification here.

## Hard constraints

- **Never `git add -A`.** Compiled Vox programs land in the CWD. Named paths
  only; build test programs in a temp dir.
- **Never `--no-gpg-sign`.** Hardware key; a hanging commit is waiting for a
  human.
- **No `Co-Authored-By:` trailers.**
- **Do not spawn workers.** You are the worker.
- Commit incrementally — one commit per half — so I can review as you go.

## Reporting

Report each half: done / not done, with the reason. Say plainly if this brief
is wrong about the code — I would rather fix the brief than have you build on
a false premise. Report what you could not do rather than silently reducing
scope.
