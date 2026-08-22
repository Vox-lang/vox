# Collections Roadmap: Mixed Lists, Matrices, and Tuples

> **Status:** Living roadmap, partially built. Track 1 (mixed lists): stages
> 1a–1e2 are done; 1e3's `nothing`/tag-6 is live (`TAG_NOTHING`, `is nothing`),
> the JSON/YAML parser capstone is pending. Track 2 (matrices/tensors) and
> Track 3 (tuples) are not started. The per-stage markers in this document are
> current. _(assessed 2026-08, vox v0.1.23)_

This document maps the planned evolution of Vox's collection types across
three independent tracks, and records the type-inference model that makes
heterogeneous lists work without the author ever declaring them.

Terminology reminder: people who write Vox are **authors**. A core theme of
this plan is that *the author picks the data; the compiler picks the
representation* — and the compiler may only pick the fast representation
when it can prove it is safe.

Motivating context: `LANGUAGE.md` has always promised that "lists can
contain mixed types," but the implementation inferred a single element type
from the first element and dispatched every read on it. `[1, "two", 3.5]`
compiled, then printed a pointer and a raw IEEE 754 bit pattern — silent
data corruption in a language whose pitch is memory safety and
predictability. Track 1 makes the documented promise true. It also lays the
type-tag foundation that JSON and YAML parsing will need later: a JSON
value is inherently a tagged union, so the choice was never "tags or no
tags" but "tags designed deliberately now, or invented ad hoc later."

The three structures solve three different problems and must not be
conflated:

| Structure | Arity | Element types | Mutability | Primary use |
|-----------|-------|---------------|------------|-------------|
| List | Growable | Homogeneous *or* mixed (compiler-resolved) | Mutable | General collections; JSON/YAML data boundary |
| Matrix/tensor | Fixed shape (rows × cols) | Homogeneous (float64) | Mutable elements, fixed shape | Numerics, ML inference |
| Tuple | Fixed arity | Heterogeneous, per-position, static | Immutable | Records; multiple return values; `(value, error)` |

Notably: tuples are **not** the ML structure. ML wants tensors —
homogeneous elements packed contiguously so the inner loops have fixed
stride and can vectorize. Tuples are the record type. The tracks cross only
at the edges (e.g. an argmax returning an `(index, value)` tuple).

---

## Track 1 — Mixed lists (the foundation)

**Goal:** one `list` type in the grammar. Homogeneity is an inferred
optimization, never a declaration. Authors write the same sentence either
way; the compiler chooses the representation.

### Runtime representation

The list layout gains a type-tag region: one byte per slot, after the data
region.

```
[capacity:8][length:8][elem_size:8][values: capacity×8][tags: capacity×1]
```

Tag values (must match `LIST_TAG_*` in `coreasm/*/list.asm`):

| Tag | Meaning | Slot holds |
|-----|---------|-----------|
| 0 | integer (default) | the value |
| 1 | string | NUL-terminated C-string pointer |
| 2 | float | IEEE 754 double bit pattern |
| 3 | boolean | 0 or 1 |
| 4 | list | child list pointer — nesting (stage 1e1) |
| 5 | map | map struct pointer — key/value collection (stage 1e2) |
| 6 | null *(reserved)* | future JSON null |

All list allocations come from `mmap`, which zero-fills, so untouched tag
regions read as "integer" and cost nothing. Because `mmap` rounds to page
granularity, the extra bytes are effectively free. Homogeneous lists never
read or write tags and keep the statically-typed fast path bit-for-bit.

Tags 4–6 were reserved early, while the layout was young, so nested JSON
arrays/objects slot into the existing representation without a layout
change. Tag 4 (list) is **active** as of stage 1e1: a list slot may
hold a child list pointer, `_list_print` recurses on it, and `is a list`
recognises it. Tag 5 (map) is **active** as of stage 1e2: a list slot (or
a `value` payload) may hold a map struct pointer, `_map_print` recurses
on it, and `is a map` recognises it; tag 6 remains reserved for null.

### Stages

- **1a. Core mechanics** *(done)*. Tag region in every list
  allocation; tag-aware `_list_append` (tag in `dl`, preserved across
  realloc); tagged literal stores; tag-carrying reads (for-each,
  `element N of`, `first`/`last`) into per-variable shadow tag slots;
  runtime dispatch in `print` and format interpolation; regression suite
  plus new mixed-list tests; `LANGUAGE.md` update.
- **1b. Soundness flip** *(done)*. Invert the inference default (see "How
  the compiler decides" below): static becomes a proof, mixed becomes the
  safe fallback. Closes the "runtime-typed append still corrupts" gap.
  Compiler work only; the runtime layout already supports it.
- **1c. Type predicates.** *(done).* `If item is a number, ...` / `is a
  text` / `is a decimal` / `is a boolean` compile to a tag comparison (and
  fold to a compile-time constant when the operand is statically typed, so
  the sentence is legal on any value). This is the author-facing payoff that
  makes mixed lists usable rather than merely printable, and it reads as a
  natural Vox sentence. Negation `is not a …` reuses the existing
  `UnaryOp(Not)` path.
- **1d. Crossing function boundaries.** *(done).* A declared dynamic
  parameter and return type (name **`value`**) whose tag travels alongside
  the payload in the internal ABI. Largest sub-project in the track;
  prerequisite for writing a JSON parser in Vox functions. See
  [`docs/abi_value.md`](abi_value.md) for the ABI and `LANGUAGE.md` for the
  author-facing syntax.
- **1e. Nesting and JSON groundwork.** Lists inside lists (tag 4),
  recursive printing, maps (tag 5), null (tag 6), then the JSON/YAML
  parser as the capstone.
  - **1e1. Nested lists** *(done)*. Tag 4 activated: a list element may be
    a list; `_list_print` recurses with a depth-64 cycle guard that sets
    the error flag instead of overflowing the stack; `element N of` /
    `first` / `last` / iteration yield a usable child list; `is a list`
    predicate (folds on a static list, runtime `cmp` on a mixed element);
    homogeneous list-of-lists keeps the non-mixed fast path. See
    `LANGUAGE.md` (Nested Lists) and [`docs/plans/040_stage_1e1_nested_lists.md`](plans/040_stage_1e1_nested_lists.md).
  - **1e2. Maps** *(done)*. Tag 5 activated for key/value collections
    (JSON objects). A new `coreasm/x86_64/map.asm` runtime stores entries
    in an insertion-ordered array alongside an FNV-1a hash table (linear
    probing over power-of-two capacity, grow at load ≤ 1/2, allocate-copy-
    do-not-free-old-block like `_list_append`) for O(1) lookup. Map
    literals `{"k": v}`, `map's "k"` access, `set map's "k" to v`
    insert/replace (store-back on realloc), `map's keys`/`values` (fresh
    lists, insertion-ordered), `map's length`/`empty`, `for each key in
    … keys` / `for each v in … values`, `is a map` (folds on a static map,
    runtime `cmp r11, 5` on a mixed value), recursive `_map_print`
    (`{"k": v, …}`) sharing one 64-deep `_print_depth` budget with
    `_list_print` so a mixed map/list tree is cycle-safe, and `value`-ABI
    carriage (a map rides a `value` as payload + tag 5). Missing-key
    lookup sets `_last_error` (observed via `on error`), not a null
    return. Non-text keys and map deletion are out of scope (deferred to
    the JSON-parser stage). See `LANGUAGE.md` (Maps) and
    [`docs/plans/050_stage_1e2_maps_and_null.md`](plans/050_stage_1e2_maps_and_null.md).
  - **1e3. Null and the JSON/YAML parser** *(pending)*. Tag 6 for null;
    then a JSON/YAML parser written in Vox functions as the track capstone.

Sequencing: 1a → 1b → (1c ∥ 1d) → 1e.

Per-stage implementation plans live in [`docs/plans/`](plans/README.md),
one file per stage, following the project plan template.

### Known limitations to burn down (tracked, not hidden)

**A dynamic map key costs a 4 KiB page.** `set m's "key{i}" to v` builds the
key by allocating a fresh buffer per evaluation, and `_alloc_buffer` mmaps —
which is page-granular whatever size is requested. 10 000 dynamic keys
measure at 41 MB peak RSS for ~80 KB of key text, and the pages are never
released. Correctness is unaffected (measured, and the keys stay distinct);
this is purely footprint, and only for programs building many dynamic keys.

Now that `_map_insert` copies the key, the temp buffer is **dead the moment
the call returns**, so it can be reclaimed — which was impossible while the
map borrowed a pointer into it. Two routes:

- *Free after insert.* Emit `_free_buffer(key_ptr - BUF_DATA)` after
  `_map_insert`, only when the key expression allocated a temp (a
  `FormatString`, not a `StringLit` — freeing a `.data` literal would be
  fatal). Needs the key pointer preserved across the call; `_map_insert`
  saves `rbx`/`r12`-`r15`, so a callee-saved register works, but the
  surrounding codegen uses `rbx` as scratch, so verify rather than assume.
- *Reuse one scratch per site.* Cleaner in principle, but the format-string
  path builds through `_buffer_append_*`, which reallocate on growth and so
  need a real heap buffer, not a static region.

Deliberately not done in the same pass as the key copy: it is a
use-after-free risk in exactly the code path just hardened, and shrinking the
1024-byte request would achieve nothing since the page is the unit of cost.

Also worth knowing: `_register_buffer` silently no-ops when `buf_table` is
full (64 entries), so temp key buffers saturate the table and later buffers
go untracked. No observable consequence today — untracked buffers are
reclaimed by the OS at exit exactly as `_cleanup_buffers` would — but
freeing the temps also frees their table slots.

Remaining after 1c, in order of closure:

- ~~Appends whose value type is statically unknowable (e.g. function
  results) do not widen a list to mixed~~ *(closed by 1b — an unprovable
  write now widens the list to Mixed, and a declared-return function
  result is tagged with its return type at the write).*
- ~~Mixed lists are readable but not programmable: an author cannot
  branch on an element's type~~ *(closed by 1c — `If item is a
  number/text/decimal/boolean` reads the per-slot tag and branches on it,
  folding when the operand is statically typed).*
- ~~For a genuinely opaque value (no declared return type), the slot's own
  tag may still be a conservative `TAG_INTEGER` guess; the list widens
  and reads dispatch on tags, so the value prints correctly when it
  really is a number, but a non-number opaque value can still mis-render~~
  *(closed by 1d — a `value` return carries its real runtime tag out of
  the callee, so a value-returning function's result is tagged correctly
  when appended, not guessed).*
- ~~Mixed elements passed as function arguments lose their tag; parameters
  are statically typed~~ *(closed by 1d — a `value` parameter carries its
  tag into the callee as a second argument word, so predicates inside the
  callee classify each element correctly).*
- Arithmetic/comparisons on a mixed element still dispatch statically:
  `item add 1` where `item` holds a string is still wrong *unless the
  author guards it first* (`if item is a number, … item add 1 …`). 1c
  supplies the guard idiom. **1d adds the static rejection**: bare
  arithmetic on a `value` (unguarded) is a compile error pointing the
  author at the predicate idiom. Full flow-sensitive dispatch-on-tag
  (guarded arithmetic that narrows the type inside the branch) remains
  future work.
- **Nested-list limitations (documented by 1e1).** An extracted child
  (`a list called inner is element 2 of nested.`) is a *reference* to
  the child list, not a copy: if the parent is later grown past a
  reallocation, a child extracted before it may dangle. Extract after the
  parent finishes growing, or copy element-by-element. (The *expression*
  form of format interpolation — `print "{element 2 of nested}"` — was
  the other limitation 1e1 documented; it dispatches on the runtime tag
  in every sink as of 0.4.10, docs/BUGS_FOUND.md #68.) Flow-sensitive
  narrowing after `if item is a list` (using `item` as a list inside the
  branch) is also future work.

## Track 2 — Matrix / tensor (the ML and numerics track)

**Goal:** a shape-carrying, homogeneous, contiguous float64 structure.
Homogeneity is the entire performance story: fixed stride inner loops,
cache-friendly traversal, SIMD lanes. A 1000×1000 matrix of tagged slots
would be the worst possible layout for inference; hence a separate type.

Layout sketch (sibling of the list layout):

```
[rows:8][cols:8][data: rows×cols×8]   ; packed float64, row-major
```

### Stages

- **2a. Type and layout.** Construction sentences
  (`a matrix called m is 3 by 4.`, literals, zeros/identity); element
  get/set; `rows`/`columns` properties; formatted printing.
- **2b. Arithmetic.** Elementwise add/subtract, scalar multiply,
  transpose, matmul as the classic triple loop. Shape errors at compile
  time when dimensions are literals; runtime checks via the existing
  `_last_error` pattern otherwise. Compile-time "3×4 × 2×5 doesn't
  compose" errors are a headline ergonomic win.
- **2c. Performance.** SIMD via SSE2 (baseline x86_64, no feature
  detection needed) for elementwise ops and matmul inner loops; loop
  tiling; possibly stride metadata for zero-copy transpose.
- **2d. ML conveniences.** Dot product, argmax (returns a tuple — the
  Track 3 crossover), activation functions, weight-blob loading via the
  existing buffer/file machinery.

Track 2 is fully independent of Track 1 and can start at any time; 2a+2b
alone make a strong demo.

## Track 3 — Tuples (the record type)

**Goal:** small, fixed-arity, heterogeneous, immutable records. What makes
a tuple a tuple is fixed arity and immutability — *not* "can hold
different types per slot" (Vox lists already do that; Python's
`[1, "two", 3.0]` is a list, not a tuple).

### Stages

- **3a. Syntax and representation.** `a pair called p is (1, "two").` —
  arity and per-position types recorded statically in the symbol table.
  No runtime header needed: positions and types are fully static, so
  slots can live on the stack.
- **3b. Access and destructuring.** Positional properties and a sentence
  form for unpacking.
- **3c. Multiple return values.** Enables the `(value, error)` idiom.

Parser/type-checker-heavy, almost no runtime work. Slot after 1b; before
or alongside 2d (argmax wants it).

---

## How the compiler decides: inference without the author

The mechanism is a small type lattice with **one-way widening**.

Every list starts as `Unknown`. Each piece of evidence — a literal's
elements, an append, an element-set — *joins* the observed element type
into the list's current state:

- join into `Unknown` → that type
- join of an identical type → no change
- join of a different type → **`Mixed`**

Widening is one-way: nothing ever narrows a `Mixed` list back. That
monotonicity is what keeps the analysis simple and correct.

A pre-scan pass runs this join to a **fixed point** over the whole program
before any code is emitted. The fixed point handles aliases and
out-of-order evidence: `a list called b is the a.` makes both names
refer to one heap block, so mixedness must flow between them regardless of
declaration order. (Each pass can only add to the mixed set, so
termination is guaranteed.)

Codegen then reads the verdict:

- resolved to one concrete type → today's untagged fast path, bit-for-bit
  identical output and performance;
- resolved to `Mixed` → tags written at every store, dispatched at every
  read.

### The default when evidence is missing (the 1b flip)

What should happen when a write's type is unprovable — an append of a
function result, say? The default direction matters enormously:

- *Current (1a) rule:* "no evidence of mixing → stay static." Preserves
  existing behavior exactly, but also preserves the corruption bug for
  unprovable writes.
- *Sound (1b) rule:* **static is a proof; mixed is the default.** If every
  write to a list is provably one type, take the fast path. If even one
  write is unprovable, take the mixed path — because mixed is always
  *correct* and static is merely *faster*.

1b inverts the default to the sound rule. Homogeneity thereby becomes what
it really is: an optimization the compiler earns, never a guess it hopes
for.

### What Vox deliberately does not do

Vox does **not** go "full Python" — dynamism everywhere. Python's model
works because it committed to a boxed-object runtime (type pointer +
refcount on every value, interpreter dispatch on every operation), which
is exactly what Vox's no-resident-runtime, compile-to-plain-NASM identity
defines itself against; and Python has spent fifteen years growing type
hints to claw back static guarantees. Vox's position is **dynamic at the
data boundary, static in the core**: tagged values live inside containers
(lists and maps), scalars and arithmetic stay statically typed, and
extraction from the dynamic world is either implicitly dispatched
(printing) or explicitly checked (`If item is a number, ...`).
