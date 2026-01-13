# Intermediate Representation (IR) Design Document

**Version:** Draft 1.0 | **Date:** January 2026

---

## 1. Current vs Proposed Architecture

**Current:**
```
Source → Lexer → Parser → AST → CodeGen → x86 Assembly
```

**Proposed:**
```
Source → Lexer → Parser → AST → IR Generator → IR → Backend → Target Assembly
                                                        ↓
                                                   x86-64 / ARM64 / WASM
```

**Benefits:** PIC as backend flag, multi-platform, optimization passes, cleaner separation.

---

## 2. IR Instruction Set

### Virtual Registers
- `VReg(u32)` - Unlimited virtual registers, backend handles allocation

### Types
- `I64` - 64-bit integer
- `Ptr` - Pointer/address
- `Void` - No value

### Instructions

| Category | Instructions |
|----------|-------------|
| **Constants** | `LoadImm(dst, i64)`, `LoadString(dst, StringId)`, `LoadGlobal(dst, GlobalId)` |
| **Memory** | `Load(dst, addr)`, `Store(addr, src)`, `StackAlloc(dst, size)` |
| **Arithmetic** | `Add`, `Sub`, `Mul`, `Div`, `Mod`, `Neg` |
| **Comparison** | `CmpEq`, `CmpNe`, `CmpLt`, `CmpLe`, `CmpGt`, `CmpGe` |
| **Logical** | `And`, `Or`, `Not` |
| **Control** | `Label(id)`, `Jump(id)`, `JumpIf(cond, id)`, `JumpIfNot(cond, id)` |
| **Functions** | `FuncStart`, `FuncEnd`, `Call(dst, func, args)`, `Return(value)` |
| **Platform** | `PlatformCall(op, args, dst)` - Abstract I/O, memory, syscalls |

### Platform Operations
```
PrintInt, PrintString, PrintNewline, FileOpen, FileRead, FileWrite, 
FileClose, FileDelete, FileExists, Alloc, Free, Exit
```

---

## 3. Translation Examples

### Print Statement
```
AST: Print { value: "Hello" }
IR:  LoadString(v0, str_0)
     PlatformCall(PrintString, [v0], _)
     PlatformCall(PrintNewline, [], _)
```

### Variable + Arithmetic
```
AST: VarDecl { name: "x", value: 5 }
IR:  LoadImm(v0, 5)
     StackAlloc(v1, 8)
     Store(v1, v0)

AST: x + 3
IR:  Load(v0, <x addr>)
     LoadImm(v1, 3)
     Add(v2, v0, v1)
```

### While Loop
```
IR:  Label(loop_start)
     Load(v0, <x>)
     LoadImm(v1, 10)
     CmpLt(v2, v0, v1)
     JumpIfNot(v2, loop_end)
     ; ... body ...
     Jump(loop_start)
     Label(loop_end)
```

---

## 4. x86-64 Backend

### Register Allocation
- Parameters: rdi, rsi, rdx, rcx, r8, r9 (System V ABI)
- Overflow: Spill to stack [rbp-8], [rbp-16], ...

### PIC Support
```nasm
; Non-PIC:          ; PIC:
mov rdi, str_0      lea rdi, [rel str_0]
```

Backend checks `config.pic_mode` when emitting memory references.

---

## 5. Migration Strategy

### Phase 1: Parallel (Safe)
1. Create `src/ir/mod.rs` - IR types
2. Create `src/ir/generator.rs` - AST → IR
3. Create `src/backend/x86.rs` - IR → asm
4. Add `--use-ir` flag (keep old codegen as default)

### Phase 2: Feature Parity
Migrate in order: print → variables → arithmetic → comparisons → if/else → loops → functions → file I/O → buffers

### Phase 3: Switch Default
- Full regression tests with IR
- Make IR default, deprecate old codegen

---

## 6. File Structure

```
src/
├── ir/
│   ├── mod.rs          # IR types
│   ├── generator.rs    # AST → IR
│   └── printer.rs      # Debug output
├── backend/
│   ├── mod.rs          # Backend trait
│   ├── x86_64.rs       # x86-64 implementation
│   └── config.rs       # PIC mode, etc.
```

---

## 7. Testing

- **Unit:** IR generator correctness, backend instruction output
- **Integration:** Compare both pipelines, run test suite with `--use-ir`
- **Regression:** All existing tests must pass

---

## 8. Open Questions

1. **SSA Form:** Start without, add later if optimization needs it
2. **Debug Info:** Add source spans to IR later
3. **Inline Assembly:** Defer until concrete need
