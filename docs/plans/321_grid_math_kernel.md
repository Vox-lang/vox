# Plan 321 — The grid as a math kernel

**Status:** design record, not scheduled. Gated on Milestone 6's IR.
**Prompted by:** TheJostler, 2026-08-19, reading the assembly of a
double-nested loop expansion: *"would this be a good candidate for fast
advanced mathematics? Like Tensors and Vector Calculus?"*

**The honest two-part answer, which this plan records so it is not
re-litigated:** as *notation*, yes — arguably better placed than C. As
*machine code today*, no — scalar, with a taxed call per element. The
gap is a backend roadmap, and the notation is what makes the roadmap
tractable.

## What the language already gives us, for free

A chained loop expansion (plan 320, shipped 0.4.5):

```vox
'accumulate the cell' of each row from 1 to 100 and each col from 1 to 100.
```

desugars at parse time into a **perfect affine loop nest**:

- the **iteration space is explicit** — no pointer walking to reconstruct;
- the **bounds are affine** and hoisted (`cmp rax, [rbp-16]` against a
  value computed once before the loop);
- the **nesting order is fixed by clause order** — leftmost is outermost,
  by rule, so the compiler *knows* which loop is innermost rather than
  inferring it;
- the **body is a single pure call** with no induction machinery inside
  it for aliasing analysis to get lost in.

This is the exact shape vectorizers and polyhedral optimizers are built
to consume, and in Vox it arrives as **grammar** rather than as something
recovered from a C `for` nest. Semantically the sentence is closer to
index notation ("for all i, j: apply f") than an imperative loop is.

Two consequences worth stating plainly:

1. **Tiling needs no new syntax.** A cache-blocked kernel is just more
   clauses: `'f' of each iblock from ... and each jblock from ... and
   each i from ... and each j from ...`. The N-ary rule (320 rule 3)
   already permits it.
2. **The innermost loop is nameable by rule**, which is what makes
   automatic vectorization a lowering decision rather than a heuristic.

## What the assembly actually looks like today

Measured, not assumed — `vox --emit-asm` on a 100x100 grid whose body is
`Set total to total add row multiply col` (93 lines total). The nest
itself is clean:

```nasm
.for_start_0:                    ; row
    mov rax, [rbp-8]
    cmp rax, [rbp-16]            ; bound hoisted
    jge .for_end_2
.for_start_3:                    ; col
    ...
    call accumulate_the_cell
.for_continue_4:
    inc qword [rbp-24]
    jmp .for_start_3
```

The cost is entirely **inside the element**. Per cell, around thirty
instructions of ceremony wrap as few as two of real work:

| Per-element overhead | What it costs |
|---|---|
| `push`/`push`/`pop`/`pop` argument shuffle + `call` | a real call per element |
| `FUNC_PROLOGUE` / `FUNC_EPILOGUE` | frame setup per element |
| `_check_call_depth` + `_dec_call_depth` | **two further calls** per element |
| params spilled to `[rbp-8]`/`[rbp-16]`, then reloaded | avoidable memory traffic |
| expression evaluation via `push`/`pop` through the stack | not register-allocated |
| `_last_error` cleared **twice** (once per arithmetic op) | a peephole bug in its own right — see "Incidental" |
| loop counter as `inc qword [rbp-24]` | read-modify-write memory per iteration |

Against an AVX2/FMA kernel moving 4-8 doubles per cycle, matmul-shaped
work is realistically **50-200x off peak**. Nothing here is a design
flaw in the grid form; it is the generic call/arith lowering showing up
once per element instead of once per program.

## The work, in payoff order

All of it belongs **on the IR** (M6), not in per-architecture coreasm —
"optimize the IR, not the assembly." Doing it pre-IR means doing it
three times.

1. **Inline small callees at grid sites.** The desugar already owns the
   call it generated, so it knows the callee and the arity. Inlining
   deletes the call, prologue, epilogue, both depth checks, and the
   parameter spills in one stroke. Biggest single win; unblocks 2 and 3
   (there is nothing to vectorize while a call sits in the middle).
2. **Registerize induction variables.** Loop counters and bounds in
   registers; `inc qword [mem]` becomes `inc reg`.
3. **Vectorize the innermost clause.** The rightmost clause is
   known-innermost by language rule, so its iterations map to SIMD lanes.
   Requires: `float` arithmetic on the IR, `buffer` as the contiguous
   substrate (tensors are buffers plus a shape, not a new type — see
   the standing rule that library types never become builtins), and
   alignment/remainder handling. This is the point at which "vector
   calculus in Vox" stops being a metaphor.
4. **Cache tiling**, expressed in-language per above; the optimizer's
   job is choosing block sizes, not inventing the loop structure.

## Non-goals

- **No tensor builtin.** A tensor is a `buffer` plus a shape, built in a
  library. The language gains the loop form and the codegen; it does not
  gain a matrix type.
- **No auto-parallelism** (threads) under this plan. Vectorization is
  within a core; anything else is a separate decision.
- **No `-ffast-math` semantics.** Float behaviour stays predictable; we
  are removing overhead, not reassociating the user's arithmetic behind
  their back.

## Incidental finding, worth fixing regardless

The emitted body clears `_last_error` **once per arithmetic operation** —
two adjacent `mov qword [rel _last_error], 0` for a two-op expression.
One clear per expression (or per statement) is sufficient. Cheap
peephole, independent of everything above, and it costs a store per
operation in every arithmetic-heavy program Vox compiles today.

## Prerequisites and sequencing

Blocked on: **M6's IR** (all four items). Wants: `float` completeness
(M2's "richer numerics"). Unblocks: any serious numerical Vox, and it
raises the ceiling for M5's crypto, which is arithmetic-bound in the
same way.
