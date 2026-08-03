# Plan 270 — One identifier syntax, once and for all

**Status:** specced 2026-08-03, targeted at 0.3.0
**Breaking:** yes, deliberately. No backwards compatibility, no deprecation window.

## Problem

`LANGUAGE.md:3214` says it outright:

```
name ::= string | identifier
```

A double-quoted token is *both* a string literal and an identifier, decided by
position. That single overload is the root of a family of defects:

- `a number called "x" is "get five".` emits no call. It prints `4198480` — a
  function pointer — because `"get five"` was read as a string literal. Silent
  wrong answer, shipped in 0.2.0 as defect Q1 (`250_language_compiler_defects.md`).
- Function calls with arguments accept **only** a double-quoted name.
  `print calculate of 3.` and `print 'calculate' of 3.` are both parse errors,
  though `LANGUAGE.md:380` documents the bare form as valid.
- Quoting is near-universal ceremony with no informational content: of 788
  `called "X"` sites in the corpus, **767 are single words** that need no
  delimiter at all.

## The rule

Three forms, no overlap, no context-sensitivity:

| Form | Meaning | Example |
|---|---|---|
| `"..."` | **String literal. Always. Everywhere.** | `print "hello".` |
| `bare_word` | Identifier, single word | `a number called total is 5.` |
| `'multi word'` | Identifier, contains spaces | `a number called 'total items' is 5.` |

Normative details:

1. **`"..."` is never an identifier**, in any position. Where an identifier is
   expected and a string literal is found, that is a compile error (see §S1.5
   for the required diagnostic).
2. A **bare identifier** matches `[A-Za-z_][A-Za-z0-9_]*` and is not a reserved
   keyword. Reserved keywords remain rejected as names — unchanged behaviour.
3. A **quoted identifier** is `'` … `'` containing **two or more characters**
   and no newline. Exactly one character between single quotes remains a
   **character literal** (`'A'`) — unchanged, and the reason single-character
   quoted identifiers do not exist. Write `x`, not `'x'`.
4. Single-word quoted identifiers (`'total'`) are **legal but non-canonical**.
   They lex identically to the bare form. The codemod normalises them away; the
   compiler does not warn (a warning here would fire on machine-generated code
   for no safety benefit).
5. **Possessive.** `'name's length` is canonical and must work. After a closing
   identifier quote, an `s` *immediately* following (no space) and itself
   followed by a non-identifier character lexes as the possessive marker.
   `'name''s` also lexes correctly by the existing path; both are accepted, the
   codemod emits the single-apostrophe form.
   *Why this needs lexer work:* today `'my nums's length` fails with
   `Unknown function: s` and only the doubled `'my nums''s` works. `''s` on
   every property access of a multi-word name is unacceptable ergonomics for a
   language whose entire thesis is readability.
6. **Versions are string literals, not identifiers.** `Library 'math kit'
   version "1.0".` A version is data, not a name; `'1.0'` would read as a name
   and `1.0` bare is a float literal.
7. **Map keys are string literals.** `person's "name"` is unchanged and correct
   — a key is data.
8. **Paths are string literals.** `see "./utils.vox".` unchanged.
9. **Flag aliases are string literals.** `a flag called verbose is "-v" or
   "--verbose", it is a boolean.` The flag *name* is an identifier; `-v` is data.
10. **Format-string interpolation** takes a bare or multi-word identifier with
    no inner quoting: `"n={total items}"`. Inside `{}` an identifier is already
    the only legal thing, so a delimiter would be noise. Unchanged — already works.

### Canonical forms, for reference

```
a number called total is 5.
a number called 'total items' is 5.
Set 'total items' to 9.
print 'total items's length.

To 'add up' with a number called 'first one' and a number called 'second one'.
  Return a number, the 'first one' add the 'second one'.
print 'add up' of 3 and 4.

Library 'math kit' version "1.0".
see 'math kit' version "1.0" from "./libmathkit.lib".
see "./utils.vox".

a map called person is {"name": "Ada"}.
print person's "name".
```

---

## Baseline (measured 2026-08-03, commit 57c69e7)

Verified by matrix probe, not assumed. These already work with **both** bare and
`'multi word'` forms and must not regress:

variables (number/text/boolean/float/value) declare+reference; `Set`;
`Increment`; arithmetic; format strings; lists (declare, `element N of`,
`Append`, `'s length`); maps (declare, key access); loop variables (`For each
… in`, `Print each … from`); timers (`Create`/`Start`/`Stop`); buffers (dynamic
and sized); flags; **function parameters**; zero-argument statement calls
(`shout.`); `see "./path.vox"`.

Numeric baselines to hold: **0 build warnings**, **cargo ≥ 157**, **integration
≥ 208 passed / 0 failed / ≤ 6 skipped**, grammar checker **0 missing / 0
grammar-only**.

## The four gaps (measured)

| # | Gap | Evidence | Sites |
|---|---|---|---|
| G1 | Calls with arguments require a double-quoted name | `print calculate of 3.` and `print 'calculate' of 3.` → `Expected a statement, got Of`; `print "calculate" of 3.` → `4` | 298 |
| G2 | `Library` requires double quotes | `Library 'math kit' version '1.0'.` → `Expected version string` | 13 |
| G3 | `.lib` emission hardcodes double quotes | generated ToC reads `To "add two" with a number called "x", returning a number.` | all |
| G4 | Zero-arg call in expression position never calls | `is "get five"` → `4198480`; `is 'get five'` → `Unknown variable` | Q1 |

---

# Stages

Stages S1–S4 have **disjoint file sets** and run in parallel. S5 gates on S1.

---

## S1 — Compiler: the identifier token

**Owner:** worker `p270-compiler`  **Files:** `src/**` only.
**Out of scope:** `tests/*.vox`, `examples/`, `*.md`, `vox-vscode/`.

### Work

1. **Lexer.** Quoted identifiers already exist (`is_single_quoted_identifier`).
   Add the possessive rule from §5. Keep the one-character-is-a-char-literal
   rule. Remove the fragile `'s`-means-possessive lookahead *only* if the new
   rule subsumes it — prove with tests either way.
2. **G1 — call sites.** The call-site parser matches a string token for the
   callee. It must accept a bare identifier or a quoted identifier, and must
   **reject** a string literal. Applies to `of`, `with`, `to`, `on`, and the
   `"X" of each n from list` mapping form.
3. **G2 — `Library`.** Name becomes an identifier; version stays a string
   literal.
4. **G4 — zero-arg calls in expression position.** `a number called x is
   'get five'.` must emit a call, not a variable lookup. This is Q1; it closes
   here.
5. **Reject strings in identifier position, with a diagnostic that teaches.**
   Required shape:

   ```
   error: expected a name, found a string literal
     --> prog.vox:3:24
       |
     3 | a number called "total items" is 5.
       |                 ^^^^^^^^^^^^^^ strings are data; names are bare or 'single-quoted'
       |
     help: write `'total items'` (it contains spaces), or `total_items`
   ```

   The `help:` must pick the right suggestion: bare when the name is a legal
   bare identifier, `'…'` when it contains spaces or is otherwise not bare-legal.
6. **`.lib` emission (G3)** — `src/lib_file.rs` writes the canonical form. The
   `.lib` **reader** must accept only the canonical form; no dual parsing.

### Acceptance

- [ ] Every canonical form in §"Canonical forms" compiles and runs correctly.
- [ ] `"..."` in **every** identifier position is a compile error: `called`,
      `To`, call sites, `Library`, `see <lib>`, `Set`, `Start`/`Stop`, `For
      each … in`, `Print each … from`, `Append … to`, `element N of`, flag names,
      parameter names.
- [ ] Each of those positions has a `tests/compile_fail/` case with a paired
      `.err` asserting the §S1.5 diagnostic — **including the `help:` line**.
- [ ] `'name's length` works. A cargo test covers both `'name's` and `'name''s`.
- [ ] `'A'` still lexes as a character literal; a cargo test pins it.
- [ ] G4: `a number called x is 'get five'.` prints `5`. Regression test added.
- [ ] `.lib` round-trip: build a shared library, read the `.lib` back, link and
      run. Existing shared-library tests pass with canonical syntax.
- [ ] 0 build warnings. Cargo ≥ 157 (expect more — new lexer/parser tests).

### Success criteria

`verify.sh <repo> <commit> --shared` passes with baselines above. `git diff`
shows no change under `tests/*.vox` except newly added `compile_fail` cases.

> **Note for the worker:** the integration suite will be **red** at the end of
> this stage — 250 corpus files still use the old syntax and S5 migrates them.
> That is expected and is not a reason to soften the compiler. Report the
> failure count; do not fix corpus files. Cargo tests must be green.

---

## S2 — Documentation

**Owner:** worker `p270-docs`  **Files:** `LANGUAGE.md`, `README.md`,
`INSTALL.md`, `docs/**` except `docs/plans/`.
**Out of scope:** `src/`, any `.vox`, `vox-vscode/`, `CHANGELOG.md` (S6 owns it).

### Work

1. `LANGUAGE.md:3214` — grammar becomes `name ::= identifier` and
   `identifier ::= bare | quoted`, with the lexical rule spelled out.
2. `LANGUAGE.md:291` "Naming Rules" — rewritten to §"The rule" above.
3. **Fix the untrue claim at `LANGUAGE.md:380`**: it documents `calculate with
   x and y` (bare name + args) as valid. It is not, today. After S1 it will be
   — verify against the built compiler rather than assuming.
4. Every code sample in every doc migrated to canonical syntax. **215 lines in
   `LANGUAGE.md` alone** match a quoted-identifier pattern; 29 files under
   `docs/`.
5. A short "Names and strings" section explaining *why*: strings are data, names
   are names, and one token cannot be both. Include the `4198480` example — it
   is the most persuasive argument in the repo.

### Acceptance

- [ ] No doc contains `called "`, `To "`, `" of `, `" with `, or `Library "` —
      except where deliberately showing the *rejected* form, which must be
      labelled as such.
- [ ] Every runnable sample in `LANGUAGE.md` compiles against the S1 compiler.
      Extract and compile them; do not eyeball. If a sample cannot be made to
      compile, report it — it is either a doc bug or a compiler bug, and which
      one matters.
- [ ] Map keys, paths, flag aliases and versions still shown double-quoted.
- [ ] `docs/plans/` untouched.

### Success criteria

A script that extracts fenced `vox` blocks from `LANGUAGE.md` and compiles each
one reports zero failures. Commit that script as `docs/check-samples.sh` — the
same objective-gate approach as `vox-vscode/check-grammar.sh`.

---

## S3 — VS Code extension

**Owner:** worker `p270-vscode`  **Files:** `vox-vscode/**` only.

### Work

1. `syntaxes/vox.tmLanguage.json` — `'…'` scopes as
   `variable.other.vox` / `entity.name.function.vox` by position, **not** as
   `string.quoted.single.vox`. `"…"` stays `string.quoted.double.vox`.
2. Character literals `'A'` must still scope as
   `constant.character.vox` — a one-character single-quoted token is not a name.
3. The possessive `'name's` must not break highlighting of the rest of the line.
4. `check-grammar.sh` must still report **0 missing / 0 grammar-only**.

### Acceptance

- [ ] Tokenised with the real engine (`vscode-textmate` + `vscode-oniguruma`,
      harness at `/tmp/vox-tm/tokenize.js` — recreate it under
      `vox-vscode/` so it is not lost to `/tmp`), a canonical sample yields:
      `'multi word'` → an identifier scope, `"text"` → a string scope,
      `'A'` → a character scope.
- [ ] `check-grammar.sh` exits 0 with 0 missing / 0 grammar-only.
- [ ] `setup.sh` still installs cleanly.

### Success criteria

Objective tokenizer output committed as a fixture, so drift is caught later.
**Verification is the real tokenizer, never a screenshot or an assertion that it
"looks right".**

---

## S4 — Codemod

**Owner:** worker `p270-codemod`  **Files:** `tools/**` only.
**Explicitly must not touch `tests/` or `examples/` in this stage** — S5 does that.

### Work

Build `tools/migrate-identifiers` (Rust, in-repo, no new crates — same
constraint as the rest of the compiler) that rewrites a `.vox` file from old to
canonical syntax.

Rewrite these positions:

| Position | Action |
|---|---|
| `called "X"` | `X` if bare-legal, else `'X'` |
| `To "X"` | same |
| `"X" of/with/to/on` (callee) | same |
| `Library "X" version "V"` | name → identifier, `"V"` **unchanged** |
| `see "X" version "V" from "P"` | `"X"` → identifier; `"V"`, `"P"` unchanged |
| `Start/Stop/Begin/End/Finish the "X"` | → identifier |

**Must NOT rewrite** (verified counts in the corpus): map keys after `'s` (36),
paths in `see` (2), flag aliases `"-v"`/`"--verbose"` (81), the version in
`Library`/`see`, any string in `print`.

The ambiguous case is `is "X".` (87 sites): rewrite to `'X'` **only if `X`
names a function declared in the same compilation unit**, otherwise leave it —
it was always a string. This is decidable, so the codemod is exact, not
heuristic. If it cannot decide, it must **fail loudly on that file**, not guess.

### Acceptance

- [ ] Unit tests covering every row of both tables above, including each
      must-not-rewrite case.
- [ ] Idempotent: running it twice equals running it once. Test asserts this.
- [ ] A file already in canonical form is unchanged (byte-identical).
- [ ] Preserves comments, blank lines, and indentation exactly. Paragraph breaks
      are **semantic** in Vox (they terminate function bodies) — a codemod that
      reflows whitespace silently changes behaviour.
- [ ] Reports a per-file summary and a non-zero exit if any file failed to migrate.

### Success criteria

`cargo test` green for the tool. Dry-run over the whole corpus reports what it
would change, with zero "cannot decide" failures — or an explicit list of files
needing hand migration, which is a legitimate outcome to report rather than guess at.

---

## S5 — Corpus migration (gates on S1 + S4)

**Owner:** worker `p270-corpus`  **Files:** `tests/**`, `examples/**`.

**250 of 312 `.vox` files** are affected. Measured edits: `called "X"` 788,
callee sites 298, `To "X"` 95, `Library` 13, timer refs 4, `see … version` 1.

### Work

1. Run the S4 codemod across `tests/` and `examples/`.
2. **The 47 `compile_fail` tests with paired `.err` files are the trap.** Each
   asserts exact error text. If the `.vox` migrates and the `.err` does not,
   the test fails; worse, if an error message *changes* and both are
   regenerated blindly, the test passes while asserting nothing. Every `.err`
   change must be inspected and justified in the commit message.
3. Hand-migrate anything the codemod could not decide.
4. Fix `tests/lib/`, `tests/shared/`, `tests/include/` — these cross file
   boundaries, so a half-migrated pair fails in a confusing way.

### Acceptance

- [ ] `./test.sh` — **≥ 208 passed, 0 failed, ≤ 6 skipped.** The skip count is
      as important as the failure count: a test that starts skipping has
      stopped asserting while the suite still prints success.
- [ ] `grep -rE 'called "|^\s*To "|Library "' --include=*.vox tests/ examples/`
      returns **only** intentional `compile_fail` cases.
- [ ] Every `examples/*.vox` compiles and runs.
- [ ] No test's assertions were weakened to make it pass. Any test whose
      expected output changed must say why in the commit message.

### Success criteria

`verify.sh` green with `--shared`. Diff reviewed for tests that pass without
asserting.

---

## S6 — Release (master-owned, gates on S1–S5)

- Version → **0.3.0** in `Cargo.toml`, `vox-vscode/package.json`
  (**both must match** — 0.2.0 shipped mismatched and needed a follow-up PR).
- `CHANGELOG.md`: 0.3.0 with the breaking change stated plainly and a
  before/after migration table.
- Final `./test.sh`, `cargo test`, `check-grammar.sh`, `docs/check-samples.sh`.
- Branch, PR, merge on green CI.

---

## Hard constraints (all workers)

- **No libc, no new crates.** Hand-written runtime; this is not negotiable and
  is why `src/elf.rs` is a hand-rolled ELF reader rather than a dependency.
- **Zero build warnings.** Not "few".
- **Commits are GPG-signed by a hardware key.** If signing hangs, stop and say
  so. **Never** route around it with `--no-gpg-sign` — an unsigned commit is
  worse than no commit.
- **Never weaken a test to make it pass.** If a test blocks you and you believe
  it is wrong, say so and stop. Deleting or skipping an assertion to go green is
  the one unrecoverable failure mode here.
- **Report what you could not do.** Silently reducing scope is worse than
  failing loudly. If this spec is wrong — and it has been before, twice, on
  plans 230 and 250 — say so rather than implementing something you can see is
  broken.
- **Paragraph breaks are semantic.** A blank line terminates a function body.
  Do not reflow `.vox` files.
