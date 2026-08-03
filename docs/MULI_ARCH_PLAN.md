> **Status:** Proposal/roadmap — not built. Depends on an IR layer (see
> IR_DESIGN.md) that does not yet exist; the compiler has no IR or multi-arch
> backend today (it lowers AST → x86_64 only). The Stage 0 "no-regret" x86_64
> items below are not verified item-by-item here. _(assessed 2026-08,
> vox v0.1.23)_

Here’s the clean way to thread optimizations into your migration so you get speed gains early, without painting yourself into an architecture-shaped corner.

## The big principle

**Do optimizations on IR, not on assembly.**
Assembly-level peepholes are still useful, but they’re dessert, not dinner. IR is where you can make optimizations portable across x86, ARM, MIPS, etc.

So the plan becomes:

1. build IR
2. lower IR → arch assembly (using your macro libs per arch)
3. optimize IR in between (and optionally a tiny arch peephole after)

---

# A practical staged roadmap (with “when optimizations happen”)

## Stage 0: Get immediate wins on x86_64 (now)

Before IR exists, you can still do two “no-regret” improvements that will carry forward:

### 0A) Stop float → GPR → float ping-pong

Change your x86 float macros / codegen contract so floats can be stored/loaded from memory as floats (`movsd`) without bit-casting through `rax`.

This isn’t “x86-only optimization” so much as “don’t sabotage yourself”. It will align with IR later.

### 0B) Add a tiny peephole pass on the emitted asm (optional, small)

Only remove absolutely safe patterns:

* `push rax` / `pop rax`
* redundant `mov reg, reg`
* `mov rax, imm; push rax; pop rbx` → `mov rbx, imm`
* pointless loads of constants inside loops (only if pattern is exact)

Keep it conservative. Don’t try register renaming here.

**Why do this now?** It makes your existing demos faster and reduces noise while you build IR.

---

## Stage 1: Design IR (spec first), but include “optimization hooks”

This is where most people accidentally design an IR that can’t be optimized cleanly.

### Your IR should have:

* Typed values: `i64`, `f64`, `bool`, `ptr`, maybe `str`
* Explicit ops: `add_i64`, `mul_f64`, `cmp_*`, `load`, `store`, `call`, `br`, `ret`
* Control flow as basic blocks with labels
* Function signatures + calling convention metadata
* A notion of “pure” vs “has side effects” (even minimal)

### Crucial IR design choice for optimizations:

Pick one of these:

**Option A: SSA-like IR** (recommended)

* Each instruction produces a new value id: `v17 = add_f64 v3, v9`
* Much easier CSE, constant folding, dead-code elimination.

**Option B: non-SSA “3-address code”**

* Still workable, but optimizations are harder.

You don’t need full LLVM SSA. Just “each instruction yields a virtual register id” is enough.

---

## Stage 2: Build IR → asm backend (x86_64 first)

You already have macro modules. Great: keep them.

**IR lowering pipeline (per arch):**

* Instruction selection: IR ops → macro invocations / concrete instructions
* Register allocation: map vregs → physical regs or stack slots
* Prologue/epilogue emission
* Spills/reloads
* Emit asm that uses your `float.asm`, `int.asm`, etc.

### Where optimizations fit here:

You can already do **two optimization layers**:

#### 2A) Target-independent optimizations on IR (before lowering)

Examples:

* constant folding: `add_i64 2, 3 → 5`
* algebraic simplification: `x + 0 → x`, `x * 1 → x`
* copy propagation: `v2 = v1; use v2 → use v1`
* dead code elimination for unused pure values
* strength reduction (later): replace div by const with mul by reciprocal when safe

These apply to every arch.

#### 2B) Target-aware peephole after lowering (optional)

Small, safe cleanup patterns that depend on the backend’s emission style.

---

## Stage 3: Rewrite compiler codegen to produce IR (front-end → IR)

Once your back end works, shift the frontend to emit IR instead of x86.

This is where your “virtual registers” idea becomes real:

* expression evaluation returns a value id
* statements produce sequences of IR instructions

### Optimizations here:

You can do some “smart codegen” (like not emitting obvious redundancies), but keep most optimizations in the IR pass so they stay portable.

---

# So: when do we add the “math optimizations” you want?

You’ll add them in **two waves**:

## Wave 1: IR-level “free speed” (as soon as IR exists)

These are simple and hugely beneficial:

1. **Constant folding**
2. **Algebraic identities** (`x*1`, `x+0`, `0-x`, etc.)
3. **Common subexpression elimination** (local block first)
4. **Dead code elimination** (pure instruction results)
5. **Loop-invariant code motion** (later, but very relevant to your Pi example)

These make your generated code smaller and faster on every architecture.

## Wave 2: Target-specific math tuning (after register allocation exists)

Examples:

* x86: use `xorpd` sign-bit flips, fused multiply-add if you want, better calling convention usage
* ARM: use FMA, choose appropriate FP regs, etc.

These go in the **backend**, either:

* as instruction selection rules
* or as a post-RA peephole pass

---

# The “best ordering” for your 4 items

You listed:

1. Design specs for IR
2. Working IR → asm module (per arch)
3. Translate macros to target arch libs
4. Rewrite codegen to emit IR

I’d reorder slightly to reduce risk:

### Recommended order

**A) IR spec + x86_64 IR→asm backend first**
Before thinking about ARM/MIPS, prove the pipeline.

**B) Add minimal IR optimizations immediately after backend works**
Constant folding + DCE can be tiny and gives huge payoff.

**C) Rewrite codegen to emit IR**
Now you can compare: old x86-only output vs new IR→x86 output.

**D) Only then start porting macro libs to other arches**
Because you’ll know exactly which macro semantics you need to preserve.

So optimizations land right after “IR exists and can be executed”, not at the very end.

---

# Concrete “milestone plan” you can put in a README

### Milestone 1: IR MVP (runs Pi)

* IR supports: functions, locals (stack slots), ints/floats, while/if, print, call
* IR→x86 lowering runs current test suite

### Milestone 2: IR Opt v1

* constant folding
* algebraic simplify
* local copy-prop
* dead code elimination (pure ops)
* loop-const hoisting (optional but great)

### Milestone 3: Register allocation v1

* per basic block allocator (simple)
* spills to stack slots
* calling convention clobber handling

### Milestone 4: New targets

* port macro libs
* implement backend register set + calling convention for each target

---

If you want, I can sketch a minimal IR instruction set (like 25–35 ops) that cleanly maps to your macro modules (`int.asm`, `float.asm`, `io.asm`, `time.asm`, etc.) and supports your current examples without overdesign.

