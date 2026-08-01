# Plan 250 — compiler defects found by the LANGUAGE.md claim audit

Five defects surfaced by plans 240 (stages B4/B5). Each was found by running a
documented example and watching it fail, and each was **deliberately left
unfixed** by the docs track: the documented behaviour is the sensible one, so
editing the sample would have hidden a real defect behind corrected prose.

All four compiler findings were independently reproduced during review before
being written down here. Reproduce each yourself before fixing it, and confirm
your fix turns that reproduction around.

**Not part of plan 230.** These are unrelated to shared libraries and should
not be mixed into that work. Priority order below is by user impact.

---

## D1 — `append each x from <list> to <dest>` is broken by range ambiguity

**Severity: high.** A documented list operation that cannot be expressed.

`LANGUAGE.md:1303, 1341`. The parser reads `from source to dest` as a **range**
(`source to dest`), consuming the `to <dest>` as the range's end expression, so
the destination is swallowed and the statement is malformed.

```
$ cat f.vox
a list called "source" is [10, 20, 30].
a list called "dest" is [].
append each x from source to dest.

$ vox f.vox -o f
error: Expected 'to' after collection in append
```

The range-source form works and is the reason this is ambiguous rather than
simply missing:

```
append each n from 1 to 5 to rl.     → [1,2,3,4,5]
```

**Fix.** Disambiguate `from <expr> to <expr> to <dest>` from
`from <expr> to <dest>`. The cleanest discriminator is likely the *number* of
`to` clauses rather than the type of the source expression — a list variable
and a range start are both just expressions at parse time, and deciding on
type would push a parse decision into the analyzer. Whatever you choose, both
forms must keep working; add a test for each.

---

## D2 — `append` rejects arithmetic expressions

**Severity: high.** The docs list "expressions" as supported and they are not.

`LANGUAGE.md:1259, 1282`.

```
$ cat f.vox
a list called "s" is [].
a number called "i" is 2.
append i multiply i to s.

$ vox f.vox -o f
error: Expected 'to' after value in append statement
```

The braced form `append {i multiply i} to s` fails differently
(`Expected value to append`), which suggests the value slot is parsed by a
restricted rule rather than the general expression parser. `append i to s`
(a bare variable) works.

**Fix.** Parse the append value with the ordinary expression parser. Check
whether the braced form should also work — elsewhere in Vox braces are how you
force an expression into a value slot, so if the general parser lands, both
should follow. Test with a literal, a variable, an arithmetic expression, and
a braced expression.

---

## D3 — timer `start time` / `end time` cannot be reached

**Severity: medium.** The feature is *implemented* and unreachable.

`LANGUAGE.md:2316-2317, 2352, 2354`. `time` is a reserved keyword
(`src/lexer/mod.rs:220`) and tokenizes before the multi-word property handler
can match, so the property never resolves.

```
$ cat f.vox
a timer called "t".
Start t.
Stop t.
Print t's start time.

$ vox f.vox -o f
error: Expected a statement, got Time
```

This is a genuine compiler bug rather than a doc error, and the evidence is in
the parser: `ObjectProperty::StartTime` and `EndTime` are explicitly handled at
**four** sites — `src/parser/mod.rs:5113-5114`, `:5156-5173`, `:5700-5701`,
`:5754`. Somebody built this; tokenization defeats it. Verified during review.

`start` and `end` alone work (returning a unix timestamp), as do `duration`,
`elapsed` and `running`.

**Fix.** Let the multi-word property handler see `start`/`end` followed by the
`Time` token rather than requiring an identifier. Do not remove the `time`
keyword. If the fix turns out to need lexer changes with wide blast radius,
say so and stop — that is a bigger decision than this plan covers, and the
workaround (`start`/`end`) exists.

---

## D4 — `Set <newvar> to reap any child process` does not auto-declare

**Severity: low.** Inconsistent with every other expression.

`LANGUAGE.md:2173`.

```
$ vox f.vox -o f        # f.vox: Set reaped to reap any child process.
error: Unknown identifier 'reaped' (did you mean 'read'?)
```

`Set <newvar> to <expr>` creates the variable everywhere else — `Set newvar to
5.` and `Set pid to fork the process.` both work undeclared. Only `reap` is
special. Pre-declaring works around it.

**Fix.** Make `reap` behave like every other RHS expression in a
`Set`-declaration. Small, and worth doing precisely because the inconsistency
is invisible until it bites.

---

## D5 — `EC_CORE_PATH` survives the `ec` → `vox` rename

**Severity: low, but it is a user-facing name.**

`src/main.rs:30` reads `EC_CORE_PATH`, while the binary, the config directory
(`~/.config/vox/config`), and every system path (`/usr/local/share/vox/…`) are
now `vox`. The docs track correctly documented `EC_CORE_PATH` rather than
renaming it, because the doc must describe what the compiler reads.

**Fix.** Accept `VOX_CORE_PATH` as the documented name and keep `EC_CORE_PATH`
working as a deprecated alias — someone's shell profile or CI has the old one,
and a hard rename breaks them silently, with the failure surfacing as an
inscrutable coreasm-not-found error far from the cause. Update `docs/INSTALL.md`
in the same change so the two never disagree. Coordinate with the docs track
before touching that file.

---

## Out of scope

Do not fix the 13 documentation errors from plan 240 stage B4 — those are
already corrected on the docs branch. Do not start plan 230 work here.

## Success criteria

- [ ] Each of D1–D4 has its reproduction, and the reproduction now succeeds
- [ ] Both `append each` forms work: range source and list source
- [ ] `append` accepts literal, variable, arithmetic, and braced values
- [ ] `t's start time` and `t's end time` return what the four parser sites
      already intend
- [ ] `Set <newvar> to reap …` auto-declares
- [ ] `VOX_CORE_PATH` works; `EC_CORE_PATH` still works
- [ ] The LANGUAGE.md samples that exposed D1–D4 are restored to the forms the
      docs originally claimed, and each is covered by a test
- [ ] 0 warnings; cargo ≥ 120; `./test.sh` ≥ 196 passed, 0 failed, 6 skipped
