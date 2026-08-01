# Plan 220 — audit: where the docs claim a `.so` can be used directly as a library

**This is an audit, not a fix.** Produce an inventory. Change no behaviour, correct
no wording. The target design is not settled yet, and edits made before it is
would have to be redone.

## Background — why direct `.so` linking cannot work

The original design linked a program straight to a `.so`. That was later found
to be unworkable, and `docs/SHARED_LIBRARIES_DESIGN.md` replaced it with a
`.lib` indirection. Documentation from before that change survives in several
places and still asserts the original, wrong model.

The reason it cannot work: **a `.so` is binary ELF.** The compiler can read
mangled symbol *names* out of `.dynsym`, but nothing about Vox types — how many
parameters a function takes, whether each is a number or a text, what it
returns. Without that it cannot check a call site, infer types, or produce a
useful diagnostic. `nm -D` on a Vox library today gives exactly
`add_two_numbers`, `greet`, `makebuf` and no more.

So a `.lib` is the typed interface — the `.h` equivalent:

```
Library "flags" version "0.1".
Location "/home/josj/scr/ec/libs/libflags.so".

Table of Contents:
    To "hasflag" with a text called "flag".
    To "isverbose".
```

The chain is **`.vox` → `see` a `.lib` → `Location` → `.so`**. A `.vox` file may
also `see` another `.vox`, which is a source include and already works.

## What counts as a finding

Flag a line **only** if it asserts or implies that a `.so` can serve as a
library interface — that a program can `see`/import/link one *as a library* and
call its functions. Examples of findings:

- `see "./path/to/lib.so".` presented as a working library import
- `see "libname" version "1.0" from "./path.so".` as the linking form
- prose stating a program links "directly to the `.so`"
- a parser comment, `--help` string, or error message offering a `.so` as the
  argument to `see`
- `docs/SHARED_LIBRARIES_DESIGN.md:71` — "parse `.so` files from top to bottom,
  treating each `Library "<name>" version "<ver>"` declaration as a separator".
  A `.so` is binary; this describes `.lib` parsing. Start here, it is confirmed.

**Do NOT flag** these — they are correct and must stay:

- `--link` / `--lib-path` against a `.so`. This works today and is verified.
- `vox lib.vox --shared -o lib.so` producing a `.so`. Correct.
- A `.so` carrying its own runtime, being loadable from C/Rust, `.fini_array`,
  the version script, `nm -D`/`readelf` checks. All correct.
- `Location "…/libflags.so"` inside a `.lib`. That is the intended chain.
- `see` of a **`.vox`** file. That is a source include and works.

When unsure, list it as **uncertain** with your reasoning rather than
guessing either way. A misclassification in either direction costs more than
an honest question.

## Where to look

`docs/` (including `docs/plans/`), `LANGUAGE.md`, `README.md`, `ROADMAP.md`,
`src/` (comments, `--help` text, diagnostics, parser doc-comments), `tests/`,
`examples/`. Search for `.so`, `see`, `See`, `Library`, `link`, and `.lib`.
Grep is a starting point, not the deliverable — read the surrounding context,
because the wrong assertions are often in prose that never names `.so` on the
same line.

## Deliverable

Append a `## Findings` section to **this file**. One entry per finding:

| field | content |
|---|---|
| location | `path:line` |
| quote | the asserting text, trimmed |
| why wrong | one sentence |
| suggested correction | what it should say, or "delete" — **do not apply it** |
| confidence | confirmed / uncertain |

Group by file, most-load-bearing file first — `LANGUAGE.md` is what users read,
so it outranks a plan document. Finish with a short count: findings per file,
and how many are uncertain.

Also note any place the docs are **silent** where they should not be — if
`LANGUAGE.md` documents `see` without mentioning `.lib` at all, that is a gap
worth recording even though no single line is wrong.

## Out of scope

No code changes. No wording changes. Do not implement plan 200 Phase 3, do not
create `.lib` parsing, do not touch the parser's accepted syntaxes. If you
notice a code defect while reading, record it at the end under
`## Incidental code observations` and keep going.

## Success criteria

- [ ] Every file in the search set has been read, not just grepped
- [ ] Each finding has a location, quote, reason, and confidence
- [ ] Correct `.so` usage (`--shared`, `--link`, `Location`) is not flagged
- [ ] Uncertain cases are marked uncertain rather than guessed
- [ ] `cargo build --release` 0 warnings; `cargo test --release` ≥ 116;
      `./test.sh` ≥ 196 passed, 0 failed, 6 skipped — unchanged, since this
      task changes no code
