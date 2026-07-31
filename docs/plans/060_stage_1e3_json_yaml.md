# User Story
> As an author, I want to parse and emit JSON (and later YAML) so that Vox programs can exchange data with the rest of the world.

---

## Feature/Problem Description

**Summary:**
Implement JSON parsing and serialization on top of the completed
collection model: mixed lists, nesting, maps, and `nothing`. YAML follows
as a second phase reusing the same value model.

**Context:**
This is the capstone of Track 1 and the reason the type-tag foundation
was designed the way it was: a JSON value is a tagged union, and Vox now
has one. Per the roadmap's "libraries before features" principle, this
should be written *in Vox* as a library wherever possible, not baked
into the compiler.

**Current Behavior (if bug):**
No JSON support. Any Vox program consuming JSON must hand-roll parsing
over buffers with no structured result type.

**Expected Behavior:**
```
a text called "raw" is "{\"name\": \"Ada\", \"tags\": [1, 2], \"note\": null}".
a value called "doc" is parse json from raw.
print doc's "name".
(prints: Ada)
print element 1 of doc's "tags".
(prints: 1)
If doc's "note" is nothing, print "no note".

a text called "out" is write json from doc.
```

---

## Scope
- [x] Backend (Vox library; compiler only if a builtin is needed)
- [ ] Frontend
- [ ] Database
- [ ] API
- [x] Documentation
- [x] Tests

**Out of Scope (this stage):**
- YAML — phase 2 of this stage, planned separately once JSON is proven.
- Streaming/incremental parsing of very large documents.
- Schema validation.
- Number precision beyond what Vox's number and decimal types provide;
  document the chosen behavior for large integers and exponents.

---

## Technical Approach

**Proposed Solution:**
Write the parser as a Vox library using the stage 1d dynamic `value`
type for recursion: a `parse_value` function that dispatches on the next
character and recurses into arrays and objects, returning a `value`.
Serialization is the mirror: a recursive walk dispatching on type
predicates.

If profiling shows the Vox-level parser is unacceptably slow, the
fallback is a `coreasm` tokenizer with the tree-building still in Vox —
but start in Vox, because doing so is the strongest possible evidence
that the collection model is genuinely usable, and it keeps the compiler
small.

Decide and document the escaping rules, UTF-8 handling, and error
reporting strategy (error flag plus position, consistent with the
existing `_last_error` convention).

**Files/Components Affected:**
- `examples/` or a new `lib/` directory — the Vox JSON library
- `src/codegen/mod.rs` — only if a builtin sentence form is added
- `coreasm/x86_64/` — only if a fast tokenizer proves necessary
- `LANGUAGE.md`, `docs/COLLECTIONS_ROADMAP.md`
- `tests/`

**Dependencies:**
Stages 1a–1e-2 complete. This stage cannot start before maps and the
dynamic `value` type exist.

---

## Success Criteria
- [ ] Round-trip fidelity: parse then serialize preserves semantics
- [ ] All tests pass
- [ ] Malformed input fails cleanly with a useful error, never a crash
      or a silently wrong value
- [ ] Code reviewed and approved
- [ ] Documentation updated

---

## Acceptance Criteria
1. **Given** a JSON object with nested objects and arrays, **when**
   parsed, **then** every leaf value is reachable with the correct type.
2. **Given** JSON `null`, **when** parsed, **then** the value is
   `nothing` and `is nothing` is true.
3. **Given** a parsed document, **when** serialized, **then** re-parsing
   the output yields an equivalent structure.
4. **Given** malformed JSON (unterminated string, trailing comma, bad
   escape), **when** parsed, **then** the error flag is set with a
   position and the program does not crash.
5. **Given** strings with escapes (`\n`, `\"`, `\u00e9`), **when**
   round-tripped, **then** the bytes are preserved.
6. **Given** a 1 MB document, **when** parsed, **then** it completes
   without exhausting memory or the stack.

---

## Tasks
- [ ] Specify the supported JSON subset and document deviations
- [ ] Implement the tokenizer in Vox
- [ ] Implement recursive `parse_value` returning a dynamic value
- [ ] Implement serialization with correct escaping
- [ ] Error reporting with position information
- [ ] Test corpus: valid documents, malformed documents, escapes, deep
      nesting, large document
- [ ] Benchmark; decide whether a `coreasm` tokenizer is warranted
- [ ] Update `LANGUAGE.md` and `docs/COLLECTIONS_ROADMAP.md`
- [ ] Plan YAML as a follow-on document reusing this value model
- [ ] Run `./test.sh` and `cargo test --release`

---

## Notes
- Recursion depth is the main safety hazard on adversarial input. Enforce
  the same documented depth limit used by nested-list printing and fail
  via the error flag.
- Consider publishing the parser as the first real demonstration of the
  "libraries written in Vox, not in the compiler" principle from
  `ROADMAP.md` — worth calling out in the README when it lands.
