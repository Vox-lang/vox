# User Story
> As an author, I want key-value maps and an explicit "nothing" value so that I can represent JSON objects and absent fields.

---

## Feature/Problem Description

**Summary:**
Add a map (key-value) collection type using reserved tag 5, and a null /
"nothing" value using reserved tag 6, completing the data model that
JSON and YAML require.

**Context:**
`docs/COLLECTIONS_ROADMAP.md` identifies nesting, maps, and null as the
three things JSON needs beyond mixed lists. Nesting arrives in 1e-1; this
stage supplies the other two. Maps are a genuinely new collection type
and are the largest piece of Track 1 after 1d.

**Current Behavior (if bug):**
No map type exists. There is no way to express an absent or null value —
the closest workaround is a sentinel, which is exactly the kind of
silent-corruption pattern this track is removing.

**Expected Behavior:**
```
a map called "person" is {"name": "Ada", "age": 36, "email": nothing}.
print person's "name".
(prints: Ada)
print person's length.
(prints: 3)
If person's "email" is nothing, print "no email".
For each key in person's keys, print key.
```

---

## Scope
- [x] Backend (lexer, parser, analyzer, codegen, coreasm runtime)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope:**
- The JSON/YAML parser (stage 1e-3).
- Ordered-map guarantees beyond insertion order (decide and document).
- Non-text keys. Keys are texts in this stage; JSON requires nothing more.
- Map deletion/rehashing tuning beyond a correct first implementation.

---

## Technical Approach

**Proposed Solution:**
Two sub-features that ship together because JSON needs both.

**Null (tag 6):** a literal (`nothing`) whose slot payload is 0 and whose
tag is 6. Printing renders `nothing`. The stage 1c predicate `is nothing`
tests it. This is small — mostly lexer, parser, and one dispatch arm.

**Maps (tag 5):** a heap structure sibling to the list. Suggested layout,
mirroring the list's header discipline:

```
[capacity:8][length:8][flags:8][entries: capacity x (key_ptr:8, value:8, tag:1, ...)]
```

Start with open addressing and linear probing over a power-of-two
capacity, growing at a documented load factor by the same
allocate-copy-do-not-free discipline `_list_append` already uses (and for
the same aliasing reason, which must be repeated in the comments).
Hashing: FNV-1a over the key bytes is adequate and trivial to implement
in NASM.

Values are tagged exactly like list slots, so a map value may be a
number, text, decimal, boolean, list (tag 4), map (tag 5), or nothing
(tag 6) — which is precisely the JSON value set.

**Files/Components Affected:**
- `src/lexer/mod.rs` — `nothing`, `{`/`}` and `:` in map literals
- `src/parser/mod.rs`, `src/parser/ast.rs` — map literal, key access,
  `keys`/`values`/`length` properties
- `src/analyzer/mod.rs` — map type, key type validation
- `src/codegen/mod.rs` — map allocation, insertion, lookup, iteration
- `coreasm/x86_64/map.asm` (new) — hashing, probing, growth, printing
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stage 1a; plan 000 and stage 1e-1 for the recursive printer; stage 1c for
`is nothing` / `is a map`; stage 1d if map values are to be passed to
functions generically.

---

## Success Criteria
- [ ] Feature works as described in expected behavior
- [ ] All tests pass
- [ ] Map operations are bounds-safe and never read past an allocation
- [ ] Growth preserves all entries (stress test with 10,000 keys)
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** a map literal with text, number, and `nothing` values,
   **when** each key is read, **then** each value returns with its
   correct type.
2. **Given** a map, **when** a key is inserted that already exists,
   **then** the value is replaced and `length` does not change.
3. **Given** a lookup of a key that is not present, **when** executed,
   **then** the error flag is set (consistent with list bounds errors)
   rather than returning a garbage value.
4. **Given** 10,000 insertions, **when** all keys are read back, **then**
   every value is intact across all growth events.
5. **Given** a map containing a list and a nested map, **when** printed,
   **then** the whole structure renders recursively.
6. **Given** `nothing` stored in a list slot, **when** printed, **then**
   it renders as `nothing`, and `is nothing` is true for it.
7. **Given** the existing suite, **when** it runs, **then** all tests pass.

---

## Tasks
- [ ] Implement `nothing`: lexer, parser, tag 6, printing, predicate
- [ ] Design and document the map layout and growth policy
- [ ] `coreasm/x86_64/map.asm`: hash, insert, lookup, grow, iterate, print
- [ ] Map literal syntax and codegen
- [ ] Key access sentence form (`person's "name"`) plus `keys`, `values`,
      `length`, `empty` properties
- [ ] Iteration (`For each key in person's keys, ...`)
- [ ] Tests: literals, insert/replace, missing key, growth stress,
      nesting, `nothing` handling
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Decide early whether maps preserve insertion order. JSON does not
  require it, but authors will expect stable iteration; an insertion-order
  side table costs little and prevents surprising diffs in output.
- Reuse the list's "allocate, copy, do not free the old block" rule on
  growth, and copy the explanatory comment: freeing would turn a stale
  caller-held pointer into a use-after-free.
- `{` and `}` are also used by format strings. Check the lexer carefully
  for ambiguity between a map literal and an interpolation, and add a
  test that pins the disambiguation rule.
