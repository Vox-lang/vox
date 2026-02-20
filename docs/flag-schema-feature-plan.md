# Flag Schema Runtime Parsing - Feature Plan

## User Story
As a CLI developer using EC, I want to declare a flag schema in source code (short/long names, type, defaults, required-ness) so that flags are parsed automatically at runtime, typed variables are assigned automatically, and positional arguments are exposed cleanly.

As a CLI end user, I want Unix-compatible behavior where `--` stops flag parsing and everything to its right remains positional.

## Current State
EC currently exposes raw argument helpers (`arguments's count`, `arguments's first`, `arguments's all`, `argument at`, `arguments has`) but does not provide declarative flag definitions.

Current behavior limitations:
- No schema-based flag declaration.
- No automatic typed assignment from flags into variables.
- No runtime separation of consumed flag tokens from positional arguments.
- No dedicated `arguments's raw` view distinct from parsed/filtered arguments.
- No built-in `--` stop-parsing behavior for a flag system (must be implemented manually in user programs).

## Affected Code
Primary touch points for the feature are:

1. AST expression model
- `src/parser/ast.rs` around argument/environment expression variants (`Expr::Argument*`, `Expr::Environment*`) @src/parser/ast.rs#79-115

2. Parser argument/property handling
- `src/parser/mod.rs` argument/environment parsing branches and `arguments's` property handling @src/parser/mod.rs#3569-3671
- identifier property parsing path for `arguments` aliases @src/parser/mod.rs#3655-3671

3. Analyzer dependency tracking for argument/environment nodes
- `src/analyzer/mod.rs` argument/environment handling in `analyze_expr` @src/analyzer/mod.rs#941-983

4. Codegen entry setup and argument expression lowering
- argument capture setup (`SAVE_ARGS`) in `_start` generation @src/codegen/mod.rs#324-328
- argument/environment expression codegen (`_get_argc`, `_get_arg`, `_get_env`, etc.) @src/codegen/mod.rs#2490-2662

5. Runtime asm argument/env helpers
- argument/env storage and access functions/macros in `coreasm/x86_64/args.asm` @coreasm/x86_64/args.asm#15-223

6. Language docs and examples
- `LANGUAGE.md` command-line argument section (to document schema syntax and semantics)
- `examples/args_and_env.en` (feature demonstration and migration from manual parsing)

## Scope of Changes
### Parse Orchestration Strategy (Design Decision)
- Default behavior: users should NOT need to write `parse flags.`
- Compiler inserts flag parsing automatically immediately after the final top-level `a flag ...` schema declaration and before first executable statement.
- Optional explicit override (if enabled in final syntax):
  - Allow user to write `parse flags.` manually.
  - If present, compiler uses that location instead of auto-insertion.
  - If absent, auto-placement still occurs.
- Rationale: keeps syntax ergonomic while preserving deterministic parse point.

### Parser / AST
- Add grammar for declarative flag schema statements, e.g.:
  - `a flag called "name" is "-n" or "--number", it is a boolean.`
  - `... it is a number and is required.`
  - `... it is a text with default "out.txt".`
- Add AST nodes for:
  - Flag schema declaration.
  - Optional explicit `parse flags` statement node (only if explicit override is supported).
  - Flag lookup variables/bindings.
  - New argument properties: at minimum `arguments's raw` and filtered positional list support.

### Analyzer
- Validate schema correctness:
  - Duplicate short/long aliases.
  - Invalid defaults for declared type.
  - Required + default conflicts (if disallowed by design).
  - Variable name collisions.
- Enforce schema ordering / phase rules:
  - All flag schema declarations must be in the schema section (before parse point).
  - If `parse flags.` is explicit, no additional `a flag ...` declarations are allowed after it.
  - If flag variables (or parsed positional view) are used before parse point, emit compile error.
  - If an `a flag` line appears after the parse point, emit compile error.
- Mark runtime dependencies (`uses_args`, strings, list support) for new nodes.

### Compiler Diagnostics (Helpful Errors)
- Add user-facing diagnostics with actionable guidance and source locations:
  - **Late schema declaration**:
    - `Flag schema declaration appears after flag parsing has started.`
    - Hint: `Move this 'a flag ...' declaration above the parse point.`
  - **Schema after explicit parse**:
    - `Cannot declare new flags after 'parse flags.'.`
    - Hint: `Group all flag declarations before 'parse flags.'.`
  - **Flag use before parse**:
    - `Flag variable 'X' is used before flags are parsed.`
    - Hint: `Move usage after schema block (or add 'parse flags.' earlier).`
  - **Multiple explicit parse statements**:
    - `Duplicate 'parse flags.' statement.`
    - Hint: `Keep only one parse point.`
- Error formatting should follow existing pretty compile error style with line/column and clear next-step hints.

### Runtime / Core ASM Macros
- Extend argument runtime with parsing helpers:
  - Initialize parser state from `_argv` and `_argc`.
  - Walk argv left-to-right.
  - Support short and long flags.
  - Support value-consuming flags (text/number).
  - Support boolean flags.
  - Stop parsing at `--`.
  - Track consumed tokens.
- Build two logical outputs:
  - `arguments's raw` (original argv user portion unchanged).
  - `arguments's all` (post-parse positional args only).

### Codegen
- Emit runtime initialization for declared schemas before program user logic executes.
- Emit schema table/static descriptors into assembly (aliases, type, default, required bits).
- Emit variable assignment from parser result memory into EC variables.
- Keep compatibility for existing argument expressions.

### Docs / Examples / Tests
- Document syntax and semantics in `LANGUAGE.md`.
- Update `examples/args_and_env.en` with supported syntax once implemented.
- Add parser/analyzer/codegen tests + integration tests for core scenarios.
- Add regression tests.

## Success Criteria
The feature is considered complete when all are true:

1. Developers can declare flags with:
- Short/long aliases.
- Type: boolean, number, text.
- Optional default.
- Optional required marker.

2. Runtime behavior is correct:
- Consumed flag tokens are removed from `arguments's all`.
- `arguments's raw` preserves original CLI inputs exactly (excluding argv[0] unless specified otherwise by final design).
- `--` stops flag parsing; all subsequent tokens are positional.
- Parse point is deterministic: auto-inserted after final schema declaration (or explicit parse point if supported and present).

3. Type behavior is correct:
- Number flags reject non-numeric inputs with clear compile/runtime error policy.
- Missing required flag produces deterministic error.
- Defaults apply only when flag absent.

4. Compatibility is preserved:
- Existing argument/environment expressions continue to work.
- Existing tests remain green.

5. Documentation and examples are updated to final syntax.

6. Ordering/phase safety is enforced:
- Compiler rejects schema declarations after parse point.
- Compiler rejects first use of parsed flag values before parse point.
- Diagnostics include actionable hints.

---

## Proposed Acceptance Criteria
- [ ] Parser accepts flag schema declarations in documented forms.
- [ ] Parse point behavior is specified and tested (auto after last schema, with explicit override semantics if supported).
- [ ] AST includes first-class nodes for flag schema and parsed/raw argument access.
- [ ] Analyzer validates schema and reports useful diagnostics with source locations.
- [ ] Analyzer enforces schema/parse ordering and rejects late declarations or pre-parse flag usage.
- [ ] Runtime parser honors short/long flags, boolean vs value flags, and `--` semantics.
- [ ] `arguments's all` returns only positional args after schema parse.
- [ ] `arguments's raw` returns original unfiltered user arguments.
- [ ] Required/missing/default behavior is implemented and tested.
- [ ] Integration tests cover at least the 8 example scenarios drafted in `examples/args_and_env.en`.
- [ ] `LANGUAGE.md` documents syntax, semantics, and edge cases.
- [ ] `./test.sh` passes with no regressions.
