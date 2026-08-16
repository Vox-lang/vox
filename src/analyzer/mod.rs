use crate::parser::ast::*;
use crate::errors::{CompileError, SourceFile, SourceLocation, find_similar_keyword, ENGLISH_KEYWORDS};
use std::collections::{HashMap, HashSet};

const FD_MAX: i64 = 2_147_483_647;

#[derive(Debug, Default)]
pub struct Dependencies {
    pub uses_io: bool,
    pub uses_heap: bool,
    pub uses_strings: bool,
    pub uses_args: bool,
    pub uses_funcs: bool,
}

#[cfg(test)]
mod buffer_append_copy_analysis_tests;
#[cfg(test)]
mod guard_env_tests;
mod scope;
mod expressions;
mod statements;

pub struct Analyzer {
    pub deps: Dependencies,
    pub variables: HashSet<String>,
    pub functions: HashSet<String>,
    /// Assembly symbol -> the function name that claimed it. Two names that
    /// differ only in characters the mangler folds to `_` ("my.helper" and
    /// "my helper") would emit one label and silently share a body.
    mangled_functions: std::collections::HashMap<String, String>,
    pub used_identifiers: HashSet<String>,  // Track all identifiers seen
    typo_candidates: HashSet<String>,
    pub errors: Vec<CompileError>,
    source_file: Option<SourceFile>,
    guarded_scopes: HashMap<String, HashSet<String>>,
    symbol_error_counts: HashMap<String, usize>,
    /// Where each concretely-typed variable was first declared, captured at
    /// declaration time for the type-lock check's "note: declared here"
    /// (a variable's type is fixed at declaration and never changes).
    declared_locations: HashMap<String, SourceLocation>,
    active_guards: Vec<String>,
    in_function_scope: bool,
    block_depth: usize,
    global_variables: HashSet<String>,
    flag_variables: HashSet<String>,
    buffer_variables: HashSet<String>,
    list_variables: HashSet<String>,
    map_variables: HashSet<String>,
    file_variables: HashSet<String>,
    timer_variables: HashSet<String>,
    /// Variables holding a raw heap pointer from `Allocate`. They are not
    /// buffers (no length/capacity header), but `Free` must accept them -
    /// that is the whole point of Allocate.
    allocated_variables: HashSet<String>,
    /// Declared/inferred scalar category (Integer/Float/String/Boolean) for
    /// non-buffer, non-list, non-file, non-timer variables. Vox is dynamically
    /// typed - a variable's runtime category is whatever its last assignment
    /// stored - so this map is updated on every VarDecl and Assignment to stay
    /// current. It lets the arithmetic type check distinguish a text variable
    /// (must be cast with `as a number`/`as a float` before arithmetic) from a
    /// numeric one, which the buffer/list/flag sets alone cannot do.
    scalar_types: HashMap<String, Type>,
    function_param_counts: HashMap<String, usize>,
    /// Names declared as the dynamic `value` type (value parameters and `a
    /// value called x` locals). A bare `value` is not usable in arithmetic
    /// without an explicit type check (stage 1c predicate); the arithmetic
    /// operand check uses this set to reject unguarded use with a clear error.
    value_typed_names: HashSet<String>,
    /// Lists proven heterogeneous from their own literal initializer at
    /// declaration time (plan 294 finding 18) - e.g. `a list called data is
    /// [42, "hello"].`. Deliberately narrower than codegen's `mixed_lists`
    /// pre-scan: this only looks at a direct `ListLit` initializer, not
    /// aliasing through other variables or widening via later `Append`s.
    /// That asymmetry is safe in the direction it's used (a `for each` loop
    /// variable over a list this set doesn't catch keeps today's existing,
    /// unchanged behaviour rather than being wrongly tightened), but it
    /// means a list built up entirely through `Append` calls of differing
    /// types is not detected as mixed here the way it would be by codegen.
    list_mixed: HashSet<String>,
    /// A map's value type, proven from its own literal initializer when
    /// every value shares one provable type (plan 294 findings 4, 14) -
    /// e.g. `{"k": 42}` is a map of number. `Type::Map` is otherwise never
    /// given a value type anywhere in the analyzer, so a mismatched read
    /// (`a text called s is m's "k".` where `m`'s values are numbers) was
    /// unprovable and silently passed the type lock. Absent (not `None`
    /// stored, just no entry) for a map whose literal has mixed value
    /// types, an empty map, or a non-literal initializer - `arithmetic_
    /// operand_type` then returns `None` for a read from it, same
    /// "can't prove it, so allow" policy as everywhere else in this file.
    /// Narrower than a full type system: only the map's own declaration
    /// site is consulted, not aliasing or later `Set <map>'s "k" to
    /// <value>` writes that could widen it.
    map_value_type: HashMap<String, Type>,
    loop_depth: usize,
    /// True when compiling `--shared`. A shared library has no `_start`, so a
    /// top-level executable statement would be generated into the discarded
    /// main body and silently dropped. Reject such statements up front rather
    /// than mislead the author.
    shared_mode: bool,
    /// The identity of the library whose function definitions surround the
    /// statement currently being analyzed, set by `Library` declarations as
    /// the walk proceeds. The per-function tables (`functions`,
    /// `function_param_counts`, `mangled_functions`) are keyed by the
    /// `<lib>_<ver>_<func>` mangled label, so a call resolves only against the
    /// current library's functions: a name defined in a DIFFERENT library of
    /// the same .so is not in this library's key set and stays the existing
    /// "Unknown function" error (cross-library calls are out of scope for A2).
    /// `None` outside shared mode, where the key is plain `mangle_symbol(name)`.
    current_library: Option<(String, String)>,
    /// Set right after analyzing a function whose body a blank line force-
    /// closed early. Consulted by errors in the top-level statements that
    /// follow, since that's where such a function's "missing" params actually
    /// surface as errors. Cleared as soon as the next FunctionDef or Library
    /// starts analysis, bounding it to just the orphaned statements in between.
    pending_blank_line_truncation: Option<(String, Vec<String>, SourceLocation)>,
    // (function_name, its parameter names, the blank line's location)
    /// Stage A4: functions imported by `see '<lib>' version "<ver>" from
    /// "...lib".`, resolved against the filesystem by the driver (parse +
    /// .dynsym verification) and handed here for name resolution and call
    /// checking. A call resolves local-first (a local definition SHADOWS a
    /// same-named import, with a warning naming the library), then by import
    /// (exactly one exporting <lib,version>), then ambiguity (two imports
    /// exporting the same name — an error by design, never a pick).
    imports: Vec<crate::lib_file::ImportedFunction>,
    /// Non-fatal diagnostics (currently: local-definitions-shadow-imports).
    /// Printed by the driver with a `warning:` prefix; they never stop a
    /// build, but shadowing is never silent either.
    pub warnings: Vec<String>,
}

#[derive(Clone, Default)]
pub(crate) struct AnalysisEnv {
    always: HashSet<String>,
    guarded: HashMap<String, HashSet<String>>,
}


impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            deps: Dependencies::default(),
            variables: HashSet::new(),
            functions: HashSet::new(),
            mangled_functions: std::collections::HashMap::new(),
            used_identifiers: HashSet::new(),
            typo_candidates: HashSet::new(),
            errors: Vec::new(),
            source_file: None,
            guarded_scopes: HashMap::new(),
            symbol_error_counts: HashMap::new(),
            declared_locations: HashMap::new(),
            active_guards: Vec::new(),
            in_function_scope: false,
            block_depth: 0,
            global_variables: HashSet::new(),
            flag_variables: HashSet::new(),
            buffer_variables: HashSet::new(),
            list_variables: HashSet::new(),
            map_variables: HashSet::new(),
            file_variables: HashSet::new(),
            timer_variables: HashSet::new(),
            allocated_variables: HashSet::new(),
            scalar_types: HashMap::new(),
            function_param_counts: HashMap::new(),
            value_typed_names: HashSet::new(),
            list_mixed: HashSet::new(),
            map_value_type: HashMap::new(),
            loop_depth: 0,
            shared_mode: false,
            current_library: None,
            pending_blank_line_truncation: None,
            imports: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }

    pub fn with_shared_mode(mut self, enabled: bool) -> Self {
        self.shared_mode = enabled;
        self
    }

    /// Register the functions imported by the program's `see ... from
    /// "*.lib"` statements (already parsed and .dynsym-verified by the
    /// driver). Names are authorship-level here: `imports` is matched by the
    /// authored name, and the `<lib>_<ver>_<func>` label only matters to the
    /// codegen, which gets the same list.
    pub fn with_imports(mut self, imports: Vec<crate::lib_file::ImportedFunction>) -> Self {
        self.imports = imports;
        self
    }

    /// The key under which a function DEFINED in the current library is filed
    /// in the per-function tables: the `<lib>_<ver>_<func>` mangled label in
    /// shared mode (with an identity set), else `mangle_symbol(name)`. This is
    /// the same rule codegen's `function_label` uses, so the two agree on a
    /// function's identity and a call that the analyzer accepts also resolves
    /// at the call site. Reads `current_library`, which the statement walk sets
    /// as it passes each `Library` declaration.

    
    




    /// Core of `find_write_site_location`/`find_bind_site_location`: search
    /// `patterns` in order, skipping `exclude_line` (the declaration, when
    /// known) and requiring a left word boundary so a shorter name doesn't
    /// match as a suffix of a longer one (symbol "x", pattern "x is "
    /// matching inside "max is " - each pattern's own trailing space
    /// already enforces the right boundary). `guard_against_called`
    /// additionally excludes a match immediately preceded by "called " -
    /// the canonical declaration syntax `a <type> called X is <value>.`
    /// contains `X is ` right after it, so an "X is "-shaped pattern needs
    /// this guard as a second line of defence alongside `exclude_line`
    /// (which only covers the *recorded* declaration line, e.g. if a
    /// declaration and something else ever shared one line). A
    /// construct-specific pattern that legitimately targets "called X"
    /// itself (`FileOpen`'s own syntax) must pass `false` here so it does
    /// not exclude its own match.
    /// Search `patterns` (each expected to contain `symbol` as a
    /// substring) for the statement that binds/writes `symbol`, returning
    /// the location of `symbol` itself within the match - not the
    /// pattern's own start. That distinction matters: a pattern like
    /// `"Set {symbol} to "` has the symbol sitting *inside* it, offset by
    /// `len("Set ")`, so anchoring on the pattern's start would draw the
    /// caret under `Set` while claiming to point at the variable. Boundary
    /// checks (word boundary on both sides of `symbol`, and optionally
    /// "not immediately preceded by `called `") are applied around the
    /// symbol's own span for the same reason - a boundary check anchored on
    /// the pattern's start protects the wrong substring whenever the symbol
    /// isn't at offset 0.

    /// Like `find_symbol_location`, but for pointing at the specific
    /// statement that *writes* to `symbol` (`Set symbol to ...` / `symbol is
    /// ...` / `the symbol is ...`), not just any occurrence of the name.
    /// `find_symbol_location`'s own preference order (`{symbol` first, for
    /// format-string interpolation) is wrong here: a name that also appears
    /// in an unrelated `Print "{n}"` elsewhere in the file would anchor the
    /// type-lock error there instead of at the offending assignment.

    /// Like `find_write_site_location`, for a statement that *binds* `name`
    /// through some construct-specific syntax rather than `is`/`to`
    /// (a for-range/for-each loop header, `open ... called X`, `Allocate N
    /// for X`). `patterns` are the construct's own syntax fragments
    /// (e.g. `"each {name} "`, `"called {name} "`); `guard_against_called`
    /// should be `false` when a pattern itself targets `"called X"`; a
    /// caller doing that must instead disambiguate the declaration via
    /// `exclude_line`.

    /// Where `name` was declared, for `declared_locations`. Deliberately
    /// does NOT use `find_symbol_location`: that function prefers `{name`
    /// (format-string interpolation) as its first pattern, which is right
    /// for "where is this name used" but wrong here - a `Print "{src}"`
    /// anywhere in the file would outrank the actual `a text called src
    /// is ...` declaration, since interpolation is usually textually
    /// earlier or just as likely to hit occurrence 0. Tries the `called
    /// NAME` declaration syntax first (typed declarations, `Allocate`,
    /// `FileOpen`, ...), then falls back to bare/loop-header forms that
    /// have no `called` keyword at all (`NAME is <value>.`, `each NAME `).





    /// Validate that a function call supplies exactly the number of
    /// arguments the function declares. A mismatch previously compiled
    /// to undefined runtime behaviour: too few arguments read stale
    /// register values (silently using 0 or garbage), while too many
    /// were silently dropped.

    /// How a call to `name` resolves under Stage A4's import rules.
    /// Local-first is deliberate: adding an unrelated `see` must never
    /// silently redirect an existing call, so a local definition shadows a
    /// same-named import (a pre-pass warning names the shadowed library).
    /// Two imports exporting the same name are ambiguous by identity — a
    /// re-see of the SAME <lib,version> is one import, but two different
    /// libraries, or two versions of one library, are two.


    /// Plan 270 G4: a bare or quoted identifier in *expression* position
    /// that names a zero-argument function is a call, not a variable lookup.
    /// True iff `name` resolves to a callable declaring zero parameters — a
    /// local function (looked up via `func_key`, so shared-mode mangling
    /// matches the definition) or a single unambiguous import. A name that is
    /// a variable in scope is decided by the caller *before* consulting this;
    /// a variable shadows a same-named zero-arg function.

    /// Resolve and validate a call site shared by `Statement::FunctionCall`
    /// and `Expr::FunctionCall`: local definition, then a single import (with
    /// the same arity message as any other call, plus argument-type checks,
    /// which an import needs at the call site because it has no body to fail
    /// in), then ambiguity, then the existing unknown-function error.

    /// Arity and argument-type validation for a call to an imported function.
    /// The arity message is the same one any Vox call gets. Type validation
    /// is static-only: an argument whose category is provably incompatible
    /// with the declared parameter type is an error (an import has no body
    /// whose arithmetic check would catch it, so the call site is the only
    /// place it can be caught); a dynamically-typed argument is trusted, as
    /// it is for local calls.

    /// The provable type category of an argument expression, if there is one:
    /// literals always, identifiers only when their tracked category is
    /// definite. Anything dynamic (a `value`, a call result, an expression)
    /// is `None` and skipped by the import type check.

    /// Whether a statically-known argument category may go to a parameter of
    /// the declared type. Booleans ride as numbers in the ABI (0/1) and file
    /// parameters accept number-like handles, so the rejects are the true
    /// category clashes: pointers where scalars are expected and the reverse.














    /// A "scalar" variable holds a raw 64-bit value (a number, a boolean
    /// flag, or a unix timestamp) rather than a pointer or handle. Number
    /// and time properties read the raw slot, so applying them to a
    /// buffer/list/file/timer loads a pointer or fd and yields garbage.

    /// Resolve a named reference (an `Identifier` or a quoted-name `StringLit`)
    /// to its tracked category. Buffer/list/file/timer/flag are detected from
    /// their dedicated sets; otherwise the dynamic `scalar_types` map supplies
    /// the current number/float/text/boolean category. Returns None for an
    /// unknown or untracked name (treated as "allow" by the arithmetic check to
    /// avoid false positives).
    fn named_value_type(&self, name: &str) -> Option<Type> {
        if self.is_buffer_variable(name) {
            Some(Type::Buffer)
        } else if self.is_list_variable(name) {
            Some(Type::List(Box::new(Type::Unknown)))
        } else if self.is_map_variable(name) {
            Some(Type::Map(Box::new(Type::Unknown)))
        } else if self.file_variables.contains(name) {
            Some(Type::File)
        } else if self.timer_variables.contains(name) {
            Some(Type::Timer)
        } else if self.flag_variables.contains(name) {
            Some(Type::Boolean)
        } else {
            self.scalar_types.get(name).cloned()
        }
    }

    /// Classify an expression's value category for the arithmetic type check.
    /// Returns the type, or None when it cannot be determined statically
    /// (function calls, property/element/byte access) - None means "allow",
    /// biasing against false positives. A bare text literal or a text variable
    /// resolves to `Type::String`; a cast resolves to its target type, so
    /// `s as a number` is accepted while bare `s` (text) is rejected.
    fn arithmetic_operand_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::IntegerLit(_)
            | Expr::LastError
            | Expr::ArgumentCount
            | Expr::EnvironmentVariableCount => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::BoolLit(_) => Some(Type::Boolean),
            Expr::StringLit(s) => {
                // A quoted name may reference a variable; otherwise this is a
                // bare text literal, which is not valid in arithmetic.
                if let Some(t) = self.scalar_types.get(s) {
                    if !matches!(t, Type::Value) {
                        return Some(t.clone());
                    }
                }
                if self.value_typed_names.contains(s) {
                    Some(Type::Value)
                } else {
                    self.named_value_type(s).or(Some(Type::String))
                }
            }
            Expr::FormatString { .. } => Some(Type::String),
            Expr::Identifier(name) => {
                // A `value`-typed name that has been explicitly retyped
                // (`v is a number.`) carries the concrete target type in
                // `scalar_types`; prefer that so arithmetic works after the
                // retype while the variable remains a `value` for all other
                // purposes (type lock, tag slot, etc.).
                if let Some(t) = self.scalar_types.get(name) {
                    if !matches!(t, Type::Value) {
                        return Some(t.clone());
                    }
                }
                // A `value`-typed name is dynamic: reject it from arithmetic
                // until the author checks its type with a predicate (stage 1c).
                if self.value_typed_names.contains(name) {
                    Some(Type::Value)
                } else {
                    self.named_value_type(name)
                }
            }
            Expr::Cast { target_type, .. } => Some(target_type.clone()),
            Expr::DurationCast { .. } => Some(Type::Integer),
            Expr::UnaryOp { op, operand } => match op {
                UnaryOperator::Negate => self.arithmetic_operand_type(operand),
                UnaryOperator::Not => Some(Type::Boolean),
            },
            Expr::BinaryOp { op, left, right } => match op {
                BinaryOperator::Equal
                | BinaryOperator::NotEqual
                | BinaryOperator::Greater
                | BinaryOperator::Less
                | BinaryOperator::GreaterEqual
                | BinaryOperator::LessEqual
                | BinaryOperator::And
                | BinaryOperator::Or => Some(Type::Boolean),
                _ => {
                    // Arithmetic result: float if either operand is float, else
                    // integer. Nested operands are checked separately when
                    // analyze_expr recurses into them.
                    if matches!(self.arithmetic_operand_type(left), Some(Type::Float))
                        || matches!(self.arithmetic_operand_type(right), Some(Type::Float))
                    {
                        Some(Type::Float)
                    } else {
                        Some(Type::Integer)
                    }
                }
            },
            // Plan 294 findings 4, 14: only resolvable when the map's own
            // literal initializer proved a single value type (see
            // `map_value_type`) - a map declared with a non-literal
            // initializer, an empty literal, or a literal with mixed value
            // types falls through to `None`, same "can't prove it, allow
            // it" policy as everywhere else in this function.
            Expr::MapAccess { map, .. } => self.map_value_type.get(map).cloned(),
            _ => None,
        }
    }

    /// A short, human-readable label for an operand, used in error messages.
    fn operand_label(&self, expr: &Expr) -> String {
        match expr {
            Expr::Identifier(name) => name.clone(),
            Expr::StringLit(s) => {
                if self.is_variable_available(s) {
                    s.clone()
                } else {
                    format!("\"{}\"", s)
                }
            }
            _ => "this value".to_string(),
        }
    }

    /// Reject text/buffer/list/file/timer operands in arithmetic. Without an
    /// explicit cast these compile to pointer/handle arithmetic and produce
    /// garbage at runtime; a cast (`s as a number`) routes through atoi/atof
    /// and is accepted because `arithmetic_operand_type` resolves it to a
    /// numeric type.
    fn check_arithmetic_operand(&mut self, expr: &Expr) {
        // `nothing` has no numeric value. It is not a `Type` (tag 6 exists
        // only at runtime), so it is matched here rather than through
        // `arithmetic_operand_type`. Unchecked it compiles to its payload, 0,
        // so `total add missing` silently yields `total` - a wrong number that
        // looks right, which is the failure this whole track exists to stop.
        // Operands that only turn out to be nothing at runtime cannot be
        // caught here; those set the error flag instead (see
        // `emit_nothing_operand_check` in codegen).
        if matches!(expr, Expr::NothingLit) {
            self.push_error(
                "Cannot use nothing in arithmetic; check it with 'is nothing' first."
                    .to_string(),
                None,
            );
            return;
        }
        let Some(ty) = self.arithmetic_operand_type(expr) else {
            return;
        };
        let label = self.operand_label(expr);
        let msg = match ty {
            Type::String => format!(
                "Cannot use text {} in arithmetic; cast it first with 'as a number' or 'as a float'.",
                label
            ),
            Type::Buffer => format!(
                "Cannot use buffer {} in arithmetic; cast it with 'as a number' to read its content.",
                label
            ),
            Type::List(_) => format!("Cannot use list {} in arithmetic.", label),
            Type::Map(_) => format!("Cannot use map {} in arithmetic.", label),
            Type::File => format!("Cannot use file {} in arithmetic.", label),
            Type::Timer => format!("Cannot use timer {} in arithmetic.", label),
            // Deliberately naming no escape hatch, after two rounds of
            // getting this wrong: "check its type with 'is a number'
            // first" was a dead end (a type-predicate guard does not
            // narrow the type inside its own body - still rejected there
            // too), and "convert it explicitly with 'as a number'" was
            // ALSO a dead end once finding 21's fix made exactly that cast
            // a compile error (plan 294 finding 21 - casting a
            // dynamically-tagged value doesn't dispatch on the runtime tag
            // in codegen, so it used to silently compute garbage; rejecting
            // it was the fix, but this message kept sending people to it
            // anyway). This is the value-typed case by construction - it
            // is the ONLY way this branch fires - so every occurrence of
            // this message hits both dead ends the same way, every time.
            // There is currently no supported way to use a dynamically-
            // tagged value in arithmetic; say only that, since a plausible-
            // sounding but unverified alternative is worse than none (that
            // is exactly how the previous two wordings went wrong).
            Type::Value => format!(
                "Cannot use a value {} in arithmetic: its type is only known at runtime, and arithmetic on a dynamically-tagged value is not currently supported.",
                label
            ),
            _ => return,
        };
        self.push_error(msg, None);
    }

    /// Arithmetic/bitwise operators require numeric operands. Comparisons and
    /// logical and/or are excluded (they are valid across types and handled
    /// elsewhere).
    fn is_arithmetic_op(&self, op: &BinaryOperator) -> bool {
        matches!(
            op,
            BinaryOperator::Add
                | BinaryOperator::Subtract
                | BinaryOperator::Multiply
                | BinaryOperator::Divide
                | BinaryOperator::Modulo
                | BinaryOperator::BitAnd
                | BinaryOperator::BitOr
                | BinaryOperator::BitXor
                | BinaryOperator::ShiftLeft
                | BinaryOperator::ShiftRight
        )
    }



    fn infer_simple_expr_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::IntegerLit(_) | Expr::LastError | Expr::ArgumentCount | Expr::EnvironmentVariableCount => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::StringLit(_) | Expr::FormatString { .. }
            | Expr::ArgumentName | Expr::ArgumentFirst | Expr::ArgumentSecond | Expr::ArgumentLast
            | Expr::ArgumentAt { .. } | Expr::EnvironmentVariable { .. }
            | Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
            | Expr::EnvironmentVariableAt { .. } => Some(Type::String),
            Expr::BoolLit(_) | Expr::ArgumentEmpty | Expr::EnvironmentVariableEmpty | Expr::EnvironmentVariableExists { .. }
            | Expr::PropertyCheck { .. } | Expr::TypeCheck { .. } => Some(Type::Boolean),
            Expr::PropertyAccess { property: ObjectProperty::Type, .. } => Some(Type::String),
            Expr::ListLit { .. } | Expr::ArgumentAll | Expr::ArgumentRaw => Some(Type::List(Box::new(Type::Unknown))),
            Expr::MapLit { .. } => Some(Type::Map(Box::new(Type::Unknown))),
            Expr::Identifier(name) => {
                if self.is_buffer_variable(name) {
                    Some(Type::Buffer)
                } else if self.is_list_variable(name) {
                    Some(Type::List(Box::new(Type::Unknown)))
                } else if self.is_map_variable(name) {
                    Some(Type::Map(Box::new(Type::Unknown)))
                } else if self.flag_variables.contains(name) {
                    Some(Type::Boolean)
                } else {
                    None
                }
            }
            Expr::BinaryOp { op, left, right } => {
                match op {
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                    | BinaryOperator::Greater | BinaryOperator::Less
                    | BinaryOperator::GreaterEqual | BinaryOperator::LessEqual
                    | BinaryOperator::And | BinaryOperator::Or => Some(Type::Boolean),
                    _ => {
                        let left_ty = self.infer_simple_expr_type(left);
                        let right_ty = self.infer_simple_expr_type(right);
                        if matches!(left_ty, Some(Type::Float)) || matches!(right_ty, Some(Type::Float)) {
                            Some(Type::Float)
                        } else if matches!(left_ty, Some(Type::Integer)) && matches!(right_ty, Some(Type::Integer)) {
                            Some(Type::Integer)
                        } else {
                            None
                        }
                    }
                }
            }
            Expr::UnaryOp { op, operand } => {
                match op {
                    UnaryOperator::Negate => self.infer_simple_expr_type(operand),
                    UnaryOperator::Not => Some(Type::Boolean),
                }
            }
            Expr::Cast { target_type, .. } => Some(target_type.clone()),
            Expr::DurationCast { .. } => Some(Type::Integer),
            Expr::TreatingAs { value, .. } => self.infer_simple_expr_type(value),
            _ => None,
        }
    }

    fn treating_types_compatible(&self, left: &Type, right: &Type) -> bool {
        matches!(
            (left, right),
            (Type::Integer, Type::Integer)
                | (Type::Float, Type::Float)
                | (Type::String, Type::String)
                | (Type::Boolean, Type::Boolean)
                | (Type::Buffer, Type::Buffer)
                | (Type::File, Type::File)
                | (Type::Time, Type::Time)
                | (Type::Timer, Type::Timer)
                | (Type::List(_), Type::List(_))
                | (Type::Map(_), Type::Map(_))
        )
    }

    /// Classify a list-literal element for the finding-18 homogeneity
    /// check. `None` means "can't prove a single tag" (an identifier,
    /// function call, property/element access, `nothing`, ...) and is
    /// treated as mixed by the caller - matching codegen's own
    /// `TagInfo::Unknowable` policy of widening to mixed rather than
    /// guessing when a value's tag can't be proven statically.
    fn list_element_kind(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::StringLit(_) => Some(Type::String),
            Expr::IntegerLit(_) => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::BoolLit(_) => Some(Type::Boolean),
            Expr::ListLit { .. } => Some(Type::List(Box::new(Type::Unknown))),
            Expr::MapLit { .. } => Some(Type::Map(Box::new(Type::Unknown))),
            _ => None,
        }
    }

    /// True iff a list literal's elements don't all share one provable
    /// type - see `list_element_kind` and `list_mixed`.
    fn list_literal_is_mixed(&self, elements: &[Expr]) -> bool {
        let mut seen: Option<Type> = None;
        for e in elements {
            let Some(t) = self.list_element_kind(e) else {
                return true;
            };
            match &seen {
                None => seen = Some(t),
                Some(prev) if !self.treating_types_compatible(prev, &t) => return true,
                Some(_) => {}
            }
        }
        false
    }

    /// The single provable value type shared by every pair in a map
    /// literal (keys are always text and don't factor in), or `None` for
    /// an empty map, a mixed one, or a value that isn't a simple literal.
    /// See `map_value_type`'s doc comment for how this is used and its
    /// limits.
    fn map_literal_value_type(&self, pairs: &[(Expr, Expr)]) -> Option<Type> {
        let mut seen: Option<Type> = None;
        for (_, v) in pairs {
            let t = self.list_element_kind(v)?;
            match &seen {
                None => seen = Some(t),
                Some(prev) if !self.treating_types_compatible(prev, &t) => return None,
                Some(_) => {}
            }
        }
        seen
    }

    fn type_name(&self, ty: &Type) -> &'static str {
        match ty {
            Type::Integer => "number",
            Type::Float => "float",
            Type::String => "text",
            Type::Boolean => "boolean",
            Type::List(_) => "list",
            Type::Map(_) => "map",
            Type::Buffer => "buffer",
            Type::File => "file",
            Type::Time => "time",
            Type::Timer => "timer",
            Type::Value => "value",
            Type::Void => "void",
            Type::Unknown => "unknown",
        }
    }

    /// Render a value expression back into Vox source syntax, for the
    /// "help: convert it explicitly" suggestion. Only handles the simple
    /// literal/identifier shapes that are common in a mismatched assignment;
    /// anything else falls back to a generic placeholder rather than
    /// fabricating source that wouldn't parse.
    fn render_value_hint(&self, expr: &Expr) -> String {
        match expr {
            Expr::StringLit(s) => format!("\"{}\"", s),
            Expr::IntegerLit(n) => n.to_string(),
            Expr::FloatLit(n) => n.to_string(),
            Expr::BoolLit(b) => if *b { "true".to_string() } else { "false".to_string() },
            Expr::Identifier(name) => name.clone(),
            _ => "<value>".to_string(),
        }
    }

    /// Type-lock check: a concretely-typed variable's type is fixed at
    /// declaration and never changes (the language owner's fix for the
    /// whole "tracked type disagrees with runtime type" bug family - see
    /// the plan 293 writeup). Reports a compile error naming the variable,
    /// its declared type, the mismatched type, and the exact cast that
    /// fixes it when `value`'s type is statically known to differ from
    /// `name`'s declared type. Returns true iff an error was reported.
    ///
    /// Deliberately permissive (returns false, i.e. "allow") when:
    /// - `name` is `value`-typed (`self.value_typed_names`): that is the
    ///   language's sanctioned dynamic-type mechanism and must keep
    ///   accepting varying types.
    /// - `name`'s declared type can't be resolved (untracked/unknown name -
    ///   some other check, e.g. unknown-variable, owns that case).
    /// - `value`'s type can't be determined statically (function calls,
    ///   property/element access, etc.) - this mirrors the existing
    ///   `arithmetic_operand_type`/`check_arithmetic_operand` policy of
    ///   biasing against false positives when static inference runs out,
    ///   rather than requiring a full type-inference pass this task did not
    ///   ask for.
    /// - `value`'s type resolves to `Type::Value` (a dynamically-typed
    ///   source flowing into a concretely-typed destination): the runtime
    ///   type isn't known until runtime, so this can't be verified
    ///   statically either, and there is no sanctioned narrowing syntax to
    ///   demand here.
    /// - `name` is a buffer: `X is <value>.` / `Set X to <value>.` on a
    ///   buffer is a content write (format the value's text into the
    ///   buffer), not a type change - a buffer legitimately accepts a
    ///   number, text, or another buffer's contents this way, already
    ///   special-cased throughout the analyzer/codegen (e.g. the
    ///   `is_buffer_variable` exclusions the old `Statement::Assignment`
    ///   arm used before this check replaced it). Locking buffers here
    ///   would reject `a buffer called b is "".` / `b is 42.`, which must
    ///   keep working.
    fn check_type_lock(&mut self, name: &str, value: &Expr) -> bool {
        if self.value_typed_names.contains(name) || self.is_buffer_variable(name) {
            return false;
        }
        let Some(declared) = self.named_value_type(name) else {
            return false;
        };
        let Some(actual) = self.arithmetic_operand_type(value) else {
            return false;
        };
        if matches!(actual, Type::Value) {
            return false;
        }
        if self.treating_types_compatible(&declared, &actual) {
            return false;
        }

        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let mut err = CompileError::new(&format!(
            "cannot assign {} to '{}', which is a {}",
            self.type_name(&actual),
            name,
            self.type_name(&declared)
        ));
        if let Some(loc) = self.find_write_site_location(name, occurrence) {
            err = err.with_underline_note(name.len().max(1), &format!("this assigns {}", self.typed_phrase(&actual)));
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);

        if let Some(decl_loc) = self.declared_locations.get(name) {
            err = err.with_note_line(&format!(
                "'{}' was declared as a {} at {}:{}:{}",
                name,
                self.type_name(&declared),
                decl_loc.file,
                decl_loc.line,
                decl_loc.column
            ));
        } else {
            err = err.with_note_line(&format!("'{}' was declared as a {}", name, self.type_name(&declared)));
        }
        // Canonical Vox cast phrasing (LANGUAGE.md): `as a number` / `as a
        // float` / `as a boolean` / `as a buffer`, but `as text` - no
        // article - specifically for text.
        let cast_target = if matches!(declared, Type::String) {
            "text".to_string()
        } else {
            format!("a {}", self.type_name(&declared))
        };
        err = err.with_help_line(&format!(
            "convert it explicitly:  {} is {} as {}.",
            name,
            self.render_value_hint(value),
            cast_target
        ));
        self.errors.push(err);

        // Poison the tracked type after reporting: the assignment was
        // rejected, so `name` never actually took on the new type, but
        // leaving the OLD type in place would make later, unrelated uses of
        // `name` in this same (already-failing) compile cascade into a
        // second, confusing error about the mistake that was just rejected
        // (e.g. `z is s add 1` after a rejected `Set s to 7` re-flagging `s`
        // as text in arithmetic). The program never reaches codegen once
        // `self.errors` is non-empty, so this only affects which additional
        // diagnostics get reported, not correctness.
        self.scalar_types.remove(name);

        true
    }

    /// `a {} number` / `text` / etc. - the article Vox's own cast syntax
    /// uses (`as a number`, but `as text` with none). Shared by
    /// `check_type_lock` and `bind_variable_type` so both error shapes
    /// agree.
    fn typed_phrase(&self, ty: &Type) -> String {
        if matches!(ty, Type::String) {
            "text".to_string()
        } else {
            format!("a {}", self.type_name(ty))
        }
    }

    /// Statement-level binder for constructs that put a new runtime value
    /// into `name` WITHOUT going through `Statement::Assignment`/`VarDecl`
    /// - a for-range/for-each loop header, `open ... called X`, `Allocate N
    /// for X`. A binding is not an assignment, but plan 294's audit found
    /// six such sites still segfault under a rule enforced only on
    /// assignment, because each one rebinds an existing name to a new
    /// runtime value without updating (or checking) its tracked type. Same
    /// rule, same rejection: if `name` is already declared with a type
    /// incompatible with `new_type`, this is a compile error. If `name` is
    /// new, this call IS the declaration - `new_type` becomes its locked
    /// type, exactly as a `VarDecl` would set it.
    ///
    /// `construct`/`bind_verb` describe the site in the error text (e.g.
    /// "this for-range loop" / "counts with"). `patterns` locate the
    /// binding statement for the caret, tried in order via
    /// `find_bind_site_location`; `guard_against_called` must be `false`
    /// when a pattern itself targets literal `"called X"` syntax (so it
    /// does not exclude its own match - see that function's docs).
    ///
    /// Exempt exactly like `check_type_lock`: `value`-typed names (the
    /// sanctioned dynamic mechanism) and buffers (binding into a buffer is
    /// a content write, not a type change).
    fn bind_variable_type(
        &mut self,
        name: &str,
        new_type: Type,
        construct: &str,
        bind_verb: &str,
        patterns: &[String],
        guard_against_called: bool,
    ) -> bool {
        if self.value_typed_names.contains(name) || self.is_buffer_variable(name) {
            return false;
        }
        let Some(declared) = self.named_value_type(name) else {
            // A brand-new name: this binding is the declaration.
            if matches!(new_type, Type::Integer | Type::Float | Type::Boolean | Type::String) {
                self.scalar_types.insert(name.to_string(), new_type);
            }
            if !self.declared_locations.contains_key(name) {
                if let Some(loc) = self.find_declaration_location(name) {
                    self.declared_locations.insert(name.to_string(), loc);
                }
            }
            return false;
        };
        if self.treating_types_compatible(&declared, &new_type) {
            return false;
        }

        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let mut err = CompileError::new(&format!(
            "cannot bind '{}' to {} in {}; '{}' is already declared as {}",
            name,
            self.typed_phrase(&new_type),
            construct,
            name,
            self.typed_phrase(&declared)
        ));
        if let Some(loc) = self.find_bind_site_location(name, patterns, occurrence, guard_against_called) {
            err = err.with_underline_note(
                name.len().max(1),
                &format!("this {} {}", bind_verb, self.typed_phrase(&new_type)),
            );
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);

        if let Some(decl_loc) = self.declared_locations.get(name) {
            err = err.with_note_line(&format!(
                "'{}' was declared as {} at {}:{}:{}",
                name,
                self.typed_phrase(&declared),
                decl_loc.file,
                decl_loc.line,
                decl_loc.column
            ));
        } else {
            err = err.with_note_line(&format!("'{}' was declared as {}", name, self.typed_phrase(&declared)));
        }
        err = err.with_help_line(&format!(
            "use a different name here, or declare '{}' as {} instead",
            name,
            self.typed_phrase(&new_type)
        ));
        self.errors.push(err);
        self.scalar_types.remove(name);
        true
    }

    fn validate_treating_expr(&mut self, value: &Expr, match_value: &Expr, replacement: &Expr) {
        if let (Some(match_ty), Some(replacement_ty)) = (
            self.infer_simple_expr_type(match_value),
            self.infer_simple_expr_type(replacement),
        ) {
            if !self.treating_types_compatible(&match_ty, &replacement_ty) {
                self.push_error(
                    format!(
                        "Treating match and replacement must be the same type (got {} vs {}).",
                        self.type_name(&match_ty),
                        self.type_name(&replacement_ty)
                    ),
                    None,
                );
            }
        }

        if let (Some(value_ty), Some(match_ty)) = (
            self.infer_simple_expr_type(value),
            self.infer_simple_expr_type(match_value),
        ) {
            if !self.treating_types_compatible(&value_ty, &match_ty) {
                self.push_error(
                    format!(
                        "Treating value and match must be the same type (got {} vs {}).",
                        self.type_name(&value_ty),
                        self.type_name(&match_ty)
                    ),
                    None,
                );
            }
        }
    }


    
}

