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
struct AnalysisEnv {
    always: HashSet<String>,
    guarded: HashMap<String, HashSet<String>>,
}

/// A short, human-readable name for a statement kind, used in the shared-mode
/// top-level diagnostic. Only called for statements that are NOT one of the
/// three allowed top-level forms (FunctionDef/LibraryDecl/See).
fn shared_top_level_label(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Print { .. } => "print statement",
        Statement::VarDecl { .. } => "variable declaration",
        Statement::Assignment { .. } => "assignment",
        Statement::If { .. } => "if statement",
        Statement::While { .. } => "while loop",
        Statement::ForRange { .. } | Statement::ForEach { .. } | Statement::Repeat { .. } => "loop",
        Statement::FunctionCall { .. } => "function call",
        Statement::Exit { .. } => "exit statement",
        Statement::OnError { .. } => "on error handler",
        Statement::FlagSchemaDecl { .. } | Statement::ParseFlags => "flag declaration",
        _ => "statement",
    }
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
    fn func_key(&self, name: &str) -> String {
        crate::codegen::make_function_label(self.shared_mode, self.current_library.as_ref(), name)
    }

    pub fn analyze(&mut self, program: &mut Program) {
        // A shared library has no `_start`, so top-level executable statements
        // would be generated into the discarded main body and silently dropped.
        // Reject them before any other analysis so the author gets one clear
        // diagnostic instead of a confusing cascade. Only function definitions,
        // `Library`, and `see` may appear at the top level of a library.
        if self.shared_mode {
            for stmt in &program.statements {
                if !matches!(
                    stmt,
                    Statement::FunctionDef { .. } | Statement::LibraryDecl { .. } | Statement::See { .. }
                ) {
                    self.push_error(
                        format!(
                            "Top-level {} is not allowed in a shared library: only function \
                             definitions, 'Library', and 'see' may appear at the top level.",
                            shared_top_level_label(stmt)
                        ),
                        // No source location: `Statement` carries no span (see
                        // plan 210 P3). The only location mechanism here is
                        // `find_symbol_location`, a text search keyed on a
                        // symbol name; a top-level print/if/while/exit has no
                        // name, and even the name-bearing kinds (assignment,
                        // call) would resolve to the first textual occurrence
                        // of that name anywhere in the file — usually inside a
                        // function body, i.e. a misleading line. A real fix
                        // needs spans threaded into the Statement AST (the
                        // parser has token positions but discards them), which
                        // is separate work.
                        None,
                    );
                    return;
                }
            }

            // A `--shared` compile with no `Library` declaration has no
            // identity: there is no mangling (so two libraries in one .so
            // could not both define `greet`) and no name/version for the
            // `.lib` A3 writes. Reject it before codegen, naming the
            // missing declaration so the author knows exactly what to add.
            if !program
                .statements
                .iter()
                .any(|s| matches!(s, Statement::LibraryDecl { .. }))
            {
                self.push_error(
                    "A shared library must declare its identity with a `Library` \
                     declaration giving its name and version — without one there is \
                     no mangling and no `.lib`. Add `Library name version \
                     \"x.y\".` before the function definitions and rebuild with \
                     --shared."
                        .to_string(),
                    // No source location: this reports an ABSENCE of a
                    // declaration, so there is no offending statement to anchor
                    // `find_symbol_location` on (plan 210 P3). A spanned AST
                    // would let this point at the file's first line; until then
                    // it stays a message-only diagnostic, deliberately.
                    None,
                );
                return;
            }

            // A `--shared` compile with no function definitions exports
            // nothing, so the version script main.rs writes comes out as
            // `{ global: local:*; };` — empty between `global:` and
            // `local:`. `ld` rejects that with "syntax error in VERSION
            // script", which tells the author nothing about what they
            // actually did wrong. Reject it here, at the same standard as
            // the top-level-statement diagnostic above, before codegen ever
            // writes the script.
            if !program
                .statements
                .iter()
                .any(|s| matches!(s, Statement::FunctionDef { .. }))
            {
                self.push_error(
                    "A shared library must export at least one function, but this \
                     file defines none. Add a function definition, or drop --shared \
                     to build an executable."
                        .to_string(),
                    // No source location: this reports an ABSENCE of function
                    // definitions, so there is no offending statement and no
                    // symbol to anchor `find_symbol_location` on (plan 210 P3).
                    // Spanning the Statement AST would let this point at the
                    // file/first line; until then it stays a message-only
                    // diagnostic, deliberately.
                    None,
                );
                return;
            }
        }

        // First pass: collect function definitions, global declarations, and flag schemas.
        let mut explicit_parse_seen = false;

        // Definite declarations - including names declared in EVERY branch
        // of an if/otherwise chain - behave as globals: they exist on all
        // control-flow paths, so functions may reference them and code
        // after the branch may use them. Names declared in only SOME
        // branches stay out of this set; the guard tracking below owns
        // those and reports cross-guard usage.
        for (name, kind) in collect_definite_decls(&program.statements) {
            self.global_variables.insert(name.clone());
            match kind {
                DefiniteDeclKind::Buffer => { self.buffer_variables.insert(name); }
                DefiniteDeclKind::List => { self.list_variables.insert(name); }
                DefiniteDeclKind::Map => { self.map_variables.insert(name); }
                DefiniteDeclKind::File => { self.file_variables.insert(name); }
                DefiniteDeclKind::Plain => {}
            }
        }

        // Track the library identity as we walk so each function is filed under
        // its OWN `<lib>_<ver>_<func>` key (a local, not `self.current_library`,
        // so this pre-pass does not disturb the identity the second-pass walk
        // manages). This scopes `functions`/`function_param_counts`: two
        // libraries in one .so each defining `greet` get distinct keys, so a
        // call in library A does not match library B's `greet`.
        let mut current_lib: Option<(String, String)> = None;
        for stmt in &program.statements {
            match stmt {
                Statement::LibraryDecl { name, version } => {
                    current_lib = Some((name.clone(), version.clone()));
                }
                Statement::FunctionDef { name, params, .. } => {
                    let key = crate::codegen::make_function_label(
                        self.shared_mode,
                        current_lib.as_ref(),
                        name,
                    );
                    self.functions.insert(key.clone());
                    self.function_param_counts.insert(key, params.len());
                }
                Statement::FlagSchemaDecl { name, .. } => {
                    self.flag_variables.insert(name.clone());
                    self.global_variables.insert(name.clone());
                    if explicit_parse_seen {
                        self.push_error(
                            "Cannot declare new flags after 'parse flags.'".to_string(),
                            Some(name),
                        );
                    }
                }
                Statement::ParseFlags => {
                    if explicit_parse_seen {
                        self.push_error("Duplicate 'parse flags.' statement".to_string(), None);
                    }
                    explicit_parse_seen = true;
                }
                _ => {}
            }
        }

        // Stage A4 shadow rule: a local definition wins over a same-named
        // import — but never silently. Warn once per (function, library)
        // pair, naming the shadowed library, so adding a `see` can never
        // redirect an existing call without a diagnostic. Order-independent:
        // functions and imports are both fully collected before this runs.
        if !self.imports.is_empty() {
            let mut warned: HashSet<(String, String, String)> = HashSet::new();
            for stmt in &program.statements {
                if let Statement::FunctionDef { name, .. } = stmt {
                    for imp in &self.imports {
                        if imp.name != *name {
                            continue;
                        }
                        let key = (name.clone(), imp.lib.clone(), imp.version.clone());
                        if warned.insert(key) {
                            self.warnings.push(format!(
                                "'{}' is defined in this program and also exported by \
                                 library \"{}\" version \"{}\"; the local definition wins — \
                                 calls to '{}' resolve to it, not to the library.",
                                name, imp.lib, imp.version, name
                            ));
                        }
                    }
                }
            }
        }

        let parse_point = if explicit_parse_seen {
            program
                .statements
                .iter()
                .position(|s| matches!(s, Statement::ParseFlags))
                .map(|i| i + 1)
                .unwrap_or(0)
        } else {
            program
                .statements
                .iter()
                .rposition(|s| matches!(s, Statement::FlagSchemaDecl { .. }))
                .map(|i| i + 1)
                .unwrap_or(0)
        };

        for stmt in program.statements.iter().take(parse_point) {
            if matches!(stmt, Statement::FlagSchemaDecl { .. } | Statement::ParseFlags) {
                continue;
            }
            if let Some(flag_name) = self.statement_uses_flag(stmt) {
                self.push_error(
                    format!("Flag variable '{}' is used before flags are parsed", flag_name),
                    Some(&flag_name),
                );
            }
        }

        self.variables = self.global_variables.clone();
        
        // Second pass: analyze all statements
        for stmt in &program.statements {
            self.analyze_statement(stmt);
        }
        
        // Third pass: check for typos in unknown identifiers
        self.check_for_typos();
        
        program.uses_io = self.deps.uses_io;
        program.uses_heap = self.deps.uses_heap;
        program.uses_strings = self.deps.uses_strings;
        program.uses_args = self.deps.uses_args;
    }
    
    fn check_for_typos(&mut self) {
        let unknown: Vec<String> = self.typo_candidates.iter().cloned().collect();
        let mut typo_errors = Vec::new();

        for id in unknown {
            // Skip if this identifier already has an error
            if self.errors.iter().any(|e| e.message.contains(&id)) {
                continue;
            }

            // Skip common internal identifiers
            if id.starts_with('_') || id == "stdin" || id == "stdout" || id == "stderr" {
                continue;
            }
            
            if let Some(suggestion) = find_similar_keyword(&id, ENGLISH_KEYWORDS) {
                let mut err = CompileError::new(&format!("Unknown identifier '{}'", id))
                    .with_suggestion(&suggestion);
                if let Some(loc) = self.find_symbol_location(&id, 0) {
                    err = err.with_location(loc);
                }
                typo_errors.push(err);
            }
        }
        
        // Prepend typo errors so they appear first
        typo_errors.append(&mut self.errors);
        self.errors = typo_errors;
    }
    
    fn track_identifier(&mut self, name: &str) {
        self.used_identifiers.insert(name.to_string());
    }

    fn track_typo_candidate(&mut self, name: &str) {
        self.typo_candidates.insert(name.to_string());
    }

    fn expr_uses_flag(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(name) => {
                if self.flag_variables.contains(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            Expr::FormatString { parts } => {
                for part in parts {
                    match part {
                        FormatPart::Variable { name, .. } => {
                            if self.flag_variables.contains(name) {
                                return Some(name.clone());
                            }
                        }
                        FormatPart::Expression { expr, .. } => {
                            if let Some(name) = self.expr_uses_flag(expr) {
                                return Some(name);
                            }
                        }
                        FormatPart::Literal(_) => {}
                    }
                }
                None
            }
            Expr::BinaryOp { left, right, .. } => self.expr_uses_flag(left).or_else(|| self.expr_uses_flag(right)),
            Expr::UnaryOp { operand, .. } => self.expr_uses_flag(operand),
            Expr::Range { start, end, .. } => self.expr_uses_flag(start).or_else(|| self.expr_uses_flag(end)),
            Expr::PropertyCheck { value, .. } => self.expr_uses_flag(value),
            Expr::TypeCheck { value, .. } => self.expr_uses_flag(value),
            Expr::FunctionCall { args, .. } => args.iter().find_map(|a| self.expr_uses_flag(a)),
            Expr::ListLit { elements } => elements.iter().find_map(|e| self.expr_uses_flag(e)),
            Expr::MapLit { pairs } => pairs.iter().find_map(|(k, v)| {
                self.expr_uses_flag(k).or_else(|| self.expr_uses_flag(v))
            }),
            Expr::MapAccess { key, .. } => self.expr_uses_flag(key),
            Expr::ListAccess { list, index } => self.expr_uses_flag(list).or_else(|| self.expr_uses_flag(index)),
            Expr::ByteAccess { buffer, index } => self.expr_uses_flag(buffer).or_else(|| self.expr_uses_flag(index)),
            Expr::ElementAccess { list, index } => self.expr_uses_flag(list).or_else(|| self.expr_uses_flag(index)),
            Expr::Cast { value, .. } => self.expr_uses_flag(value),
            Expr::DurationCast { value, .. } => self.expr_uses_flag(value),
            Expr::TreatingAs { value, match_value, replacement } => self
                .expr_uses_flag(value)
                .or_else(|| self.expr_uses_flag(match_value))
                .or_else(|| self.expr_uses_flag(replacement)),
            Expr::ArgumentAt { index } => self.expr_uses_flag(index),
            Expr::EnvironmentVariable { name } => self.expr_uses_flag(name),
            Expr::EnvironmentVariableAt { index } => self.expr_uses_flag(index),
            Expr::EnvironmentVariableExists { name } => self.expr_uses_flag(name),
            _ => None,
        }
    }

    fn statement_uses_flag(&self, stmt: &Statement) -> Option<String> {
        match stmt {
            Statement::Print { value, .. } => self.expr_uses_flag(value),
            Statement::VarDecl { value, .. } => value.as_ref().and_then(|v| self.expr_uses_flag(v)),
            Statement::Assignment { value, .. } => self.expr_uses_flag(value),
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                self.expr_uses_flag(condition)
                    .or_else(|| then_block.iter().find_map(|s| self.statement_uses_flag(s)))
                    .or_else(|| else_if_blocks.iter().find_map(|(c, b)| self.expr_uses_flag(c).or_else(|| b.iter().find_map(|s| self.statement_uses_flag(s)))))
                    .or_else(|| else_block.as_ref().and_then(|b| b.iter().find_map(|s| self.statement_uses_flag(s))))
            }
            Statement::While { condition, body } => self
                .expr_uses_flag(condition)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::ForRange { range, body, .. } => self
                .expr_uses_flag(range)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::ForEach { collection, body, .. } => self
                .expr_uses_flag(collection)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::Repeat { count, body } => self
                .expr_uses_flag(count)
                .or_else(|| body.iter().find_map(|s| self.statement_uses_flag(s))),
            Statement::Return { value, .. } => value.as_ref().and_then(|v| self.expr_uses_flag(v)),
            Statement::Exit { code } => self.expr_uses_flag(code),
            Statement::Allocate { size, .. } => self.expr_uses_flag(size),
            Statement::ByteSet { index, value, .. } => self.expr_uses_flag(index).or_else(|| self.expr_uses_flag(value)),
            Statement::ElementSet { index, value, .. } => self.expr_uses_flag(index).or_else(|| self.expr_uses_flag(value)),
            Statement::MapSet { key, value, .. } => self.expr_uses_flag(key).or_else(|| self.expr_uses_flag(value)),
            Statement::ListAppend { value, .. } => self.expr_uses_flag(value),
            Statement::FileOpen { path, .. } => self.expr_uses_flag(path),
            Statement::FileWrite { value, .. } => self.expr_uses_flag(value),
            Statement::OnError { actions } => actions.iter().find_map(|a| self.statement_uses_flag(a)),
            Statement::BufferResize { new_size, .. } => self.expr_uses_flag(new_size),
            Statement::FunctionCall { args, .. } => args.iter().find_map(|a| self.expr_uses_flag(a)),
            Statement::Wait { duration, .. } => self.expr_uses_flag(duration),
            _ => None,
        }
    }

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
    fn find_pattern_location(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        exclude_line: Option<usize>,
        guard_against_called: bool,
    ) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        for pattern in patterns {
            let Some(name_offset) = pattern.find(symbol) else {
                continue;
            };
            let mut seen = 0usize;
            for (idx, line) in source.content.lines().enumerate() {
                let line_no = idx + 1;
                if Some(line_no) == exclude_line {
                    continue;
                }
                let mut search_from = 0usize;
                while let Some(rel) = line[search_from..].find(pattern.as_str()) {
                    let pat_col = search_from + rel;
                    let name_col = pat_col + name_offset;
                    let name_end = name_col + symbol.len();
                    let left_ok = name_col == 0 || {
                        let prev = line.as_bytes()[name_col - 1];
                        !(prev.is_ascii_alphanumeric() || prev == b'_')
                    };
                    let right_ok = line
                        .as_bytes()
                        .get(name_end)
                        .map_or(true, |b| !(b.is_ascii_alphanumeric() || *b == b'_'));
                    let excluded_by_called = guard_against_called && line[..pat_col].ends_with("called ");
                    if left_ok && right_ok && !excluded_by_called {
                        if seen == occurrence {
                            return Some(SourceLocation::new(&source.filename, line_no, name_col + 1, line));
                        }
                        seen += 1;
                    }
                    search_from = pat_col + 1;
                }
            }
        }
        None
    }

    /// Like `find_symbol_location`, but for pointing at the specific
    /// statement that *writes* to `symbol` (`Set symbol to ...` / `symbol is
    /// ...` / `the symbol is ...`), not just any occurrence of the name.
    /// `find_symbol_location`'s own preference order (`{symbol` first, for
    /// format-string interpolation) is wrong here: a name that also appears
    /// in an unrelated `Print "{n}"` elsewhere in the file would anchor the
    /// type-lock error there instead of at the offending assignment.
    fn find_write_site_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        let write_patterns = [
            format!("Set {} to ", symbol),
            format!("the {} is ", symbol),
            format!("{} is ", symbol),
        ];
        self.find_pattern_location(symbol, &write_patterns, occurrence, decl_line, true)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

    /// Like `find_write_site_location`, for a statement that *binds* `name`
    /// through some construct-specific syntax rather than `is`/`to`
    /// (a for-range/for-each loop header, `open ... called X`, `Allocate N
    /// for X`). `patterns` are the construct's own syntax fragments
    /// (e.g. `"each {name} "`, `"called {name} "`); `guard_against_called`
    /// should be `false` when a pattern itself targets `"called X"`; a
    /// caller doing that must instead disambiguate the declaration via
    /// `exclude_line`.
    fn find_bind_site_location(
        &self,
        symbol: &str,
        patterns: &[String],
        occurrence: usize,
        guard_against_called: bool,
    ) -> Option<SourceLocation> {
        let decl_line = self.declared_locations.get(symbol).map(|l| l.line);
        self.find_pattern_location(symbol, patterns, occurrence, decl_line, guard_against_called)
            .or_else(|| self.find_symbol_location(symbol, occurrence))
    }

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
    fn find_declaration_location(&self, name: &str) -> Option<SourceLocation> {
        let called_patterns = [format!("called {} is", name), format!("called {} ", name)];
        self.find_pattern_location(name, &called_patterns, 0, None, false)
            .or_else(|| {
                let bare_patterns = [format!("{} is ", name), format!("each {} ", name)];
                self.find_pattern_location(name, &bare_patterns, 0, None, false)
            })
            .or_else(|| self.find_symbol_location(name, 0))
    }

    fn find_symbol_location(&self, symbol: &str, occurrence: usize) -> Option<SourceLocation> {
        let source = self.source_file.as_ref()?;
        let preferred_patterns = [
            format!("{{{}", symbol),
            format!("\"{}\"", symbol),
            symbol.to_string(),
        ];

        for pattern in preferred_patterns {
            let mut seen = 0usize;
            for (idx, line) in source.content.lines().enumerate() {
                if let Some(column) = line.find(&pattern) {
                    if seen == occurrence {
                        return Some(SourceLocation::new(
                            &source.filename,
                            idx + 1,
                            column + 1,
                            line,
                        ));
                    }
                    seen += 1;
                }
            }
        }

        None
    }

    fn push_error(&mut self, message: String, symbol: Option<&str>) {
        self.push_error_with_hint(message, symbol, None);
    }

    fn push_error_with_hint(&mut self, message: String, symbol: Option<&str>, hint: Option<&str>) {
        let mut err = CompileError::new(&message);
        if let Some(name) = symbol {
            let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
            if let Some(loc) = self.find_symbol_location(name, occurrence) {
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
        }
        if let Some(h) = hint {
            err = err.with_hint(h);
        }
        self.errors.push(err);
    }

    fn push_unknown_variable(&mut self, name: &str) {
        let hint = self.pending_blank_line_truncation.as_ref().and_then(|(func, params, loc)| {
            if params.iter().any(|p| p == name) {
                Some(format!(
                    "a blank line ended `{}`'s body early at line {} — a paragraph break closes all open clauses, including the enclosing function, so `{}` is no longer in scope here",
                    func, loc.line, name
                ))
            } else {
                None
            }
        });
        self.push_error_with_hint(format!("Unknown variable: {}", name), Some(name), hint.as_deref());
    }

    /// Validate that a function call supplies exactly the number of
    /// arguments the function declares. A mismatch previously compiled
    /// to undefined runtime behaviour: too few arguments read stale
    /// register values (silently using 0 or garbage), while too many
    /// were silently dropped.
    fn validate_function_call_args(&mut self, name: &str, args: &[Expr]) {
        if let Some(&expected) = self.function_param_counts.get(&self.func_key(name)) {
            if args.len() != expected {
                self.push_error(
                    format!(
                        "Function '{}' expects {} argument{} but was called with {}.",
                        name,
                        expected,
                        if expected == 1 { "" } else { "s" },
                        args.len()
                    ),
                    Some(name),
                );
            }
        }
    }

    /// How a call to `name` resolves under Stage A4's import rules.
    /// Local-first is deliberate: adding an unrelated `see` must never
    /// silently redirect an existing call, so a local definition shadows a
    /// same-named import (a pre-pass warning names the shadowed library).
    /// Two imports exporting the same name are ambiguous by identity — a
    /// re-see of the SAME <lib,version> is one import, but two different
    /// libraries, or two versions of one library, are two.
    fn imported_providers(&self, name: &str) -> Vec<&crate::lib_file::ImportedFunction> {
        let mut providers: Vec<&crate::lib_file::ImportedFunction> = Vec::new();
        for imp in &self.imports {
            if imp.name != name {
                continue;
            }
            if !providers
                .iter()
                .any(|p| p.lib == imp.lib && p.version == imp.version)
            {
                providers.push(imp);
            }
        }
        providers
    }

    fn is_local_function(&self, name: &str) -> bool {
        self.functions.contains(&self.func_key(name))
    }

    /// Plan 270 G4: a bare or quoted identifier in *expression* position
    /// that names a zero-argument function is a call, not a variable lookup.
    /// True iff `name` resolves to a callable declaring zero parameters — a
    /// local function (looked up via `func_key`, so shared-mode mangling
    /// matches the definition) or a single unambiguous import. A name that is
    /// a variable in scope is decided by the caller *before* consulting this;
    /// a variable shadows a same-named zero-arg function.
    fn is_zero_arg_function(&self, name: &str) -> bool {
        if self.is_local_function(name) {
            return self.function_param_counts.get(&self.func_key(name)) == Some(&0);
        }
        // An imported function: only treat as a zero-arg call when exactly one
        // library exports it (the same single-provider rule `check_function_call`
        // applies); an ambiguous name is left for an explicit call to report.
        let providers = self.imported_providers(name);
        providers.len() == 1 && providers[0].params.is_empty()
    }

    /// Resolve and validate a call site shared by `Statement::FunctionCall`
    /// and `Expr::FunctionCall`: local definition, then a single import (with
    /// the same arity message as any other call, plus argument-type checks,
    /// which an import needs at the call site because it has no body to fail
    /// in), then ambiguity, then the existing unknown-function error.
    fn check_function_call(&mut self, name: &str, args: &[Expr]) {
        let providers = self.imported_providers(name);
        if self.is_local_function(name) {
            self.validate_function_call_args(name, args);
        } else if providers.len() == 1 {
            let import = providers[0].clone();
            self.validate_import_call_args(&import, name, args);
        } else if providers.len() > 1 {
            let both = providers
                .iter()
                .map(|p| format!("library \"{}\" version \"{}\"", p.lib, p.version))
                .collect::<Vec<_>>()
                .join(" and ");
            self.push_error(
                format!(
                    "Call to '{}' is ambiguous: it is exported by {}. Vox never picks \
                     one by import order or by highest version — resolve it by defining \
                     a local '{}' (which shadows the imports, with a warning), or by \
                     renaming one library's export.",
                    name, both, name
                ),
                Some(name),
            );
        } else {
            let mut err = format!("Unknown function: {}", name);
            if let Some(suggestion) = find_similar_keyword(name, ENGLISH_KEYWORDS) {
                err.push_str(&format!(" (did you mean '{}'?)", suggestion));
            }
            self.push_error(err, Some(name));
        }
    }

    /// Arity and argument-type validation for a call to an imported function.
    /// The arity message is the same one any Vox call gets. Type validation
    /// is static-only: an argument whose category is provably incompatible
    /// with the declared parameter type is an error (an import has no body
    /// whose arithmetic check would catch it, so the call site is the only
    /// place it can be caught); a dynamically-typed argument is trusted, as
    /// it is for local calls.
    fn validate_import_call_args(
        &mut self,
        imp: &crate::lib_file::ImportedFunction,
        name: &str,
        args: &[Expr],
    ) {
        let expected = imp.params.len();
        if args.len() != expected {
            self.push_error(
                format!(
                    "Function '{}' expects {} argument{} but was called with {}.",
                    name,
                    expected,
                    if expected == 1 { "" } else { "s" },
                    args.len()
                ),
                Some(name),
            );
            return;
        }
        for (i, arg) in args.iter().enumerate() {
            let (pname, ptype) = &imp.params[i];
            let Some(actual) = self.static_expr_category(arg) else {
                continue; // dynamically typed — trusted, as local calls are
            };
            if !Self::param_accepts(ptype, &actual) {
                self.push_error(
                    format!(
                        "Function '{}' (library \"{}\" version \"{}\") expects a {} \
                         for argument {} (\"{}\") but was called with {}.",
                        name,
                        imp.lib,
                        imp.version,
                        Self::type_noun(ptype),
                        i + 1,
                        pname,
                        Self::type_noun(&actual)
                    ),
                    Some(name),
                );
            }
        }
    }

    /// The provable type category of an argument expression, if there is one:
    /// literals always, identifiers only when their tracked category is
    /// definite. Anything dynamic (a `value`, a call result, an expression)
    /// is `None` and skipped by the import type check.
    fn static_expr_category(&self, e: &Expr) -> Option<Type> {
        match e {
            Expr::IntegerLit(_) => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::StringLit(_) => Some(Type::String),
            Expr::BoolLit(_) => Some(Type::Boolean),
            Expr::Identifier(name) => {
                if let Some(t) = self.scalar_types.get(name) {
                    return Some(t.clone());
                }
                if self.buffer_variables.contains(name.as_str()) {
                    Some(Type::Buffer)
                } else if self.list_variables.contains(name.as_str()) {
                    Some(Type::List(Box::new(Type::Unknown)))
                } else if self.map_variables.contains(name.as_str()) {
                    Some(Type::Map(Box::new(Type::Unknown)))
                } else if self.file_variables.contains(name.as_str()) {
                    Some(Type::File)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Whether a statically-known argument category may go to a parameter of
    /// the declared type. Booleans ride as numbers in the ABI (0/1) and file
    /// parameters accept number-like handles, so the rejects are the true
    /// category clashes: pointers where scalars are expected and the reverse.
    fn param_accepts(param: &Type, actual: &Type) -> bool {
        use Type::*;
        match param {
            Integer | Float => !matches!(actual, String | File | Buffer | List(_) | Map(_)),
            String => matches!(actual, String),
            Boolean => !matches!(actual, String | File | Buffer | List(_) | Map(_)),
            File => !matches!(actual, String | Boolean | Buffer | List(_) | Map(_)),
            Buffer => matches!(actual, Buffer),
            List(_) => matches!(actual, List(_)),
            Map(_) => matches!(actual, Map(_)),
            // A `value` parameter takes any category (its tag rides alongside).
            Value | Void | Unknown | Time | Timer => true,
        }
    }

    fn type_noun(t: &Type) -> &'static str {
        match t {
            Type::Integer | Type::Float => "number",
            Type::String => "text",
            Type::Boolean => "boolean",
            Type::File => "file",
            Type::Buffer => "buffer",
            Type::List(_) => "list",
            Type::Map(_) => "map",
            Type::Value => "value",
            _ => "value",
        }
    }

    fn current_env(&self) -> AnalysisEnv {
        AnalysisEnv {
            always: self.variables.clone(),
            guarded: self.guarded_scopes.clone(),
        }
    }

    fn apply_env(&mut self, env: &AnalysisEnv) {
        self.variables = env.always.clone();
        self.guarded_scopes = env.guarded.clone();
    }

    fn is_variable_available(&self, name: &str) -> bool {
        if self.variables.contains(name) {
            return true;
        }

        self.active_guards.iter().any(|guard| {
            self.guarded_scopes
                .get(guard)
                .map(|vars| vars.contains(name))
                .unwrap_or(false)
        })
    }

    fn declare_variable_in_current_scope(&mut self, name: &str) {
        if name.starts_with('_') {
            self.push_error(
                format!(
                    "Variable name '{}' starts with '_', which is reserved for \
                     the Vox runtime; choose a name without the leading underscore.",
                    name
                ),
                Some(name),
            );
        }
        if self.active_guards.is_empty() {
            self.variables.insert(name.to_string());
        } else {
            for guard in &self.active_guards {
                self.guarded_scopes
                    .entry(guard.clone())
                    .or_default()
                    .insert(name.to_string());
            }
        }
    }

    fn merge_continuing_envs(&self, envs: &[AnalysisEnv], fallback: &AnalysisEnv) -> AnalysisEnv {
        if envs.is_empty() {
            return fallback.clone();
        }

        let mut merged_always = envs[0].always.clone();
        for env in envs.iter().skip(1) {
            merged_always.retain(|name| env.always.contains(name));
        }

        let mut merged_guarded: HashMap<String, HashSet<String>> = HashMap::new();
        for env in envs {
            for (guard, vars) in &env.guarded {
                merged_guarded
                    .entry(guard.clone())
                    .or_default()
                    .extend(vars.iter().cloned());
            }
        }

        AnalysisEnv {
            always: merged_always,
            guarded: merged_guarded,
        }
    }

    fn simple_guard_key(condition: &Expr) -> Option<String> {
        match condition {
            Expr::Identifier(name) => Some(name.clone()),
            Expr::StringLit(name) => Some(name.clone()),
            Expr::UnaryOp { op: UnaryOperator::Not, operand } => {
                Self::simple_guard_key(operand).map(|k| format!("not ({})", k))
            }
            Expr::BinaryOp { left, op, right } => {
                let connector = match op {
                    BinaryOperator::And => "and",
                    BinaryOperator::Or => "or",
                    _ => return None,
                };
                let left_key = Self::simple_guard_key(left)?;
                let right_key = Self::simple_guard_key(right)?;
                Some(format!("({}) {} ({})", left_key, connector, right_key))
            }
            _ => None,
        }
    }

    fn maybe_activate_true_guard(&mut self, name: &str, var_type: &Option<Type>, value: &Option<Expr>) {
        if self.block_depth == 0 {
            return;
        }

        let is_bool_typed = var_type
            .as_ref()
            .map(|t| matches!(t, Type::Boolean))
            .unwrap_or(true);
        let is_true = matches!(value, Some(Expr::BoolLit(true)));

        if is_bool_typed && is_true {
            if !self.active_guards.iter().any(|g| g == name) {
                self.active_guards.push(name.to_string());
            }
            self.guarded_scopes
                .entry(name.to_string())
                .or_default()
                .insert(name.to_string());
        }
    }

    fn analyze_block_in_scope(&mut self, block: &[Statement], input_env: &AnalysisEnv, active_guard: Option<&str>) -> (AnalysisEnv, bool) {
        let saved_env = self.current_env();
        let saved_guards = self.active_guards.clone();
        let saved_block_depth = self.block_depth;
        self.apply_env(input_env);
        self.block_depth += 1;
        if let Some(guard) = active_guard {
            self.active_guards.push(guard.to_string());
        }

        let mut terminates = false;
        for stmt in block {
            self.analyze_statement(stmt);
            if self.statement_always_terminates(stmt) {
                terminates = true;
                break;
            }
        }
        let resulting_env = self.current_env();
        self.block_depth = saved_block_depth;
        self.active_guards = saved_guards;
        self.apply_env(&saved_env);
        (resulting_env, terminates)
    }

    fn block_always_terminates(&self, block: &[Statement]) -> bool {
        for stmt in block {
            if self.statement_always_terminates(stmt) {
                return true;
            }
        }
        false
    }

    fn is_buffer_variable(&self, name: &str) -> bool {
        self.buffer_variables.contains(name)
    }

    fn is_list_variable(&self, name: &str) -> bool {
        self.list_variables.contains(name)
    }

    fn is_map_variable(&self, name: &str) -> bool {
        self.map_variables.contains(name)
    }

    /// A "scalar" variable holds a raw 64-bit value (a number, a boolean
    /// flag, or a unix timestamp) rather than a pointer or handle. Number
    /// and time properties read the raw slot, so applying them to a
    /// buffer/list/file/timer loads a pointer or fd and yields garbage.
    fn is_scalar_variable(&self, name: &str) -> bool {
        !self.is_buffer_variable(name)
            && !self.is_list_variable(name)
            && !self.is_map_variable(name)
            && !self.file_variables.contains(name)
            && !self.timer_variables.contains(name)
            && !self.allocated_variables.contains(name)
    }

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

    fn expr_integer_literal_value(&self, expr: &Expr) -> Option<i64> {
        match expr {
            Expr::IntegerLit(value) => Some(*value),
            Expr::UnaryOp {
                op: UnaryOperator::Negate,
                operand,
            } => {
                if let Expr::IntegerLit(value) = operand.as_ref() {
                    value.checked_neg()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn validate_function_condition_variable_refs(&mut self, expr: &Expr) {
        if !self.in_function_scope {
            return;
        }

        match expr {
            Expr::StringLit(name) => {
                self.track_identifier(name);
                if !self.is_variable_available(name) {
                    self.push_unknown_variable(name);
                }
            }
            Expr::UnaryOp {
                op: UnaryOperator::Not,
                operand,
            } => {
                self.validate_function_condition_variable_refs(operand);
            }
            Expr::BinaryOp { left, right, .. } => {
                self.validate_function_condition_variable_refs(left);
                self.validate_function_condition_variable_refs(right);
            }
            _ => {}
        }
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

    fn validate_file_open_path(&mut self, path: &Expr) {
        const OPEN_PATH_GUIDANCE: &str = "Open path must be either a text path like \"/path/to/file\" or a file descriptor number (0 = stdin, 1 = stdout, 2 = stderr).";

        if let Some(fd) = self.expr_integer_literal_value(path) {
            if !(0..=FD_MAX).contains(&fd) {
                self.push_error(
                    format!(
                        "File descriptor out of range after 'at': {}. Valid range is 0..{} (0 = stdin).",
                        fd, FD_MAX
                    ),
                    None,
                );
            }
            return;
        }

        match path {
            Expr::StringLit(_) | Expr::FormatString { .. } => {}
            Expr::Identifier(name) => {
                if self.is_buffer_variable(name) || self.is_list_variable(name) {
                    self.push_error(OPEN_PATH_GUIDANCE.to_string(), Some(name));
                }
            }
            Expr::FloatLit(_)
            | Expr::BoolLit(_)
            | Expr::ListLit { .. }
            | Expr::Range { .. }
            | Expr::PropertyCheck { .. }
            | Expr::TypeCheck { .. } => {
                self.push_error(OPEN_PATH_GUIDANCE.to_string(), None);
            }
            Expr::Cast { target_type, .. } => {
                if !matches!(target_type, Type::Integer | Type::String) {
                    self.push_error(OPEN_PATH_GUIDANCE.to_string(), None);
                }
            }
            _ => {}
        }
    }

    fn statement_always_terminates(&self, stmt: &Statement) -> bool {
        match stmt {
            Statement::Return { .. } | Statement::Exit { .. } => true,
            Statement::If { then_block, else_if_blocks, else_block, .. } => {
                if !self.block_always_terminates(then_block) {
                    return false;
                }
                for (_, block) in else_if_blocks {
                    if !self.block_always_terminates(block) {
                        return false;
                    }
                }
                if let Some(block) = else_block {
                    self.block_always_terminates(block)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
    
    fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::Print { value, .. } => {
                self.deps.uses_io = true;
                self.analyze_expr(value);
                
                if matches!(value, Expr::StringLit(_)) {
                    self.deps.uses_strings = true;
                }
            }
            
            Statement::VarDecl { name, var_type, value } => {
                // `Set x to <value>.` / `Create x to <value>.` parse into
                // this same statement with `var_type: None` regardless of
                // whether `x` is brand-new or already exists (no explicit
                // type keyword follows `Set`/`Create`). Only the
                // already-declared case is a reassignment that the type
                // lock applies to; a genuinely new `x` is a real
                // declaration and must infer/lock its type as usual.
                let was_already_declared = self.is_variable_available(name);
                // A second explicitly-typed declaration of an
                // already-declared name is a redeclaration, not scoping:
                // Vox has no block-level lexical scoping today - If/While/
                // etc. bodies share the enclosing scope's slots, so there
                // is no separate slot for an inner declaration to occupy
                // and no scope exit to restore the outer type at. Without
                // this check, `a text called n is "abc".` inside an
                // untaken `If` branch permanently overwrote the outer
                // `number` n's tracked type regardless of whether the
                // branch ever ran (plan 294 finding 12 - this is the
                // declaration-arm counterpart to what the type lock
                // already does for reassignment). A conflicting rebind is
                // rejected exactly like `Statement::Assignment`/`Set`
                // reusing an incompatible name; a same-type redeclaration
                // (or a genuinely new name) is unaffected - `bind_variable_
                // type` no-ops on either.
                let redeclaration_conflict = if let (true, Some(vt)) = (was_already_declared, var_type.as_ref()) {
                    self.bind_variable_type(
                        name,
                        vt.clone(),
                        "this declaration",
                        "declares as",
                        &[format!("called {} ", name)],
                        false,
                    )
                } else {
                    false
                };
                self.declare_variable_in_current_scope(name);
                if redeclaration_conflict {
                    if let Some(v) = value {
                        self.analyze_expr(v);
                    }
                    return;
                }
                // Register the declared type in the type-specific sets,
                // mirroring the top-level pre-pass. That pre-pass only
                // walks program.statements and never descends into
                // function bodies, so without this a `a buffer called x
                // is "..."` INSIDE a function was never recorded as a
                // buffer and property/byte access on it was rejected.
                // (`a buffer called x is N bytes in size.` parses as
                // BufferDecl - a different statement whose arm already
                // registers - which is why only the initializer form
                // failed.)
                if let Some(Type::Buffer) = var_type {
                    self.buffer_variables.insert(name.clone());
                }
                if let Some(Type::List(_)) = var_type {
                    self.list_variables.insert(name.clone());
                    // Plan 294 finding 18: a `for each` loop variable over
                    // a list this proves heterogeneous must be dynamically
                    // typed (see the ForEach arm) rather than silently
                    // allowing arithmetic that only some elements support.
                    if let Some(Expr::ListLit { elements }) = value {
                        if self.list_literal_is_mixed(elements) {
                            self.list_mixed.insert(name.clone());
                        }
                    }
                }
                if let Some(Type::Map(_)) = var_type {
                    self.map_variables.insert(name.clone());
                    // Plan 294 findings 4, 14: a homogeneous map literal's
                    // value type is provable, which makes a mismatched read
                    // from it a statically-detectable type-lock violation
                    // instead of a silently-allowed "can't prove it" case.
                    if let Some(Expr::MapLit { pairs }) = value {
                        if let Some(t) = self.map_literal_value_type(pairs) {
                            self.map_value_type.insert(name.clone(), t);
                        }
                    }
                }
                if let Some(Type::Value) = var_type {
                    // A declared `a value called x` is dynamic, like a value
                    // parameter: bare arithmetic on it is rejected until the
                    // author checks its type with a predicate.
                    self.value_typed_names.insert(name.clone());
                }
                self.maybe_activate_true_guard(name, var_type, value);
                if let Some(v) = value {
                    self.analyze_expr(v);
                }
                // Track the scalar category (number/float/text/boolean) for
                // the arithmetic type check. Numeric/boolean declarations are
                // recorded from the declared type (preferring the initializer's
                // type when it is clearly numeric). A text declaration is only
                // pinned as text when the initializer is positively text - a
                // function-call or property initializer of unknown type might
                // return a number, and pinning it as text would wrongly reject
                // later arithmetic on it.
                if let Some(vt) = var_type {
                    match vt {
                        Type::Integer | Type::Float | Type::Boolean => {
                            let t = value
                                .as_ref()
                                .and_then(|v| self.arithmetic_operand_type(v))
                                .unwrap_or_else(|| vt.clone());
                            self.scalar_types.insert(name.clone(), t);
                        }
                        Type::String => {
                            let is_text = value
                                .as_ref()
                                .map(|v| matches!(self.arithmetic_operand_type(v), Some(Type::String)))
                                .unwrap_or(false);
                            if is_text {
                                self.scalar_types.insert(name.clone(), Type::String);
                            } else {
                                self.scalar_types.remove(name);
                            }
                        }
                        _ => {}
                    }
                } else if was_already_declared {
                    // `Set n to <value>.` on an already-declared `n`: a
                    // reassignment wearing a declaration's syntax. Enforce
                    // the lock exactly like `Statement::Assignment` does,
                    // instead of leaving scalar_types untouched (which is
                    // how this exact case used to silently retype, or
                    // silently do nothing, depending on the value's shape).
                    if let Some(v) = value.as_ref() {
                        self.check_type_lock(name, v);
                    }
                }
                // Record the declaration site the first time we see a real
                // type for `name`, regardless of `was_already_declared`: a
                // global pre-pass (`self.variables = self.global_variables
                // .clone()` before the main walk, fed by
                // `collect_definite_decls`) makes every top-level name
                // "already available" from the very first statement, so
                // `was_already_declared` is always true here for a
                // top-level declaration and can't be used to gate this.
                if !self.declared_locations.contains_key(name) {
                    if let Some(loc) = self.find_declaration_location(name) {
                        self.declared_locations.insert(name.clone(), loc);
                    }
                }
            }

            Statement::FlagSchemaDecl { name, value_type, default, .. } => {
                self.deps.uses_args = true;
                self.declare_variable_in_current_scope(name);
                if let Some(v) = default {
                    self.analyze_expr(v);
                    // The default must match the flag's declared value
                    // type. A mismatch previously compiled and produced
                    // garbage at runtime: a number flag defaulted to
                    // text printed the string's address, and a boolean
                    // flag defaulted to a number printed the integer.
                    let expected = match value_type {
                        FlagValueType::Boolean => Type::Boolean,
                        FlagValueType::Number => Type::Integer,
                        FlagValueType::Text => Type::String,
                    };
                    if let Some(actual) = self.infer_simple_expr_type(v) {
                        if !self.treating_types_compatible(&expected, &actual) {
                            self.push_error(
                                format!(
                                    "Flag '{}' is a {} but its default is a {}.",
                                    name,
                                    self.type_name(&expected),
                                    self.type_name(&actual)
                                ),
                                Some(name),
                            );
                        }
                    }
                }
            }

            Statement::ParseFlags => {
                self.deps.uses_args = true;
            }
            
            Statement::Assignment { name, value } => {
                // A variable's type is fixed at declaration and never
                // changes (the fix for the whole "tracked type disagrees
                // with runtime type" bug family). `name is <value>.` is
                // ambiguous on its own between "declare a brand-new
                // variable" (valid at top level) and "reassign an existing
                // one" - which it is decides whether this write gets
                // type-checked at all, so capture it before the auto-declare
                // below can change the answer.
                let was_already_declared = self.is_variable_available(name);
                if !was_already_declared {
                    if self.in_function_scope {
                        self.push_unknown_variable(name);
                    } else {
                        self.declare_variable_in_current_scope(name);
                    }
                }

                if matches!(value, Expr::FormatString { .. })
                    && self.is_variable_available(name)
                    && !self.is_buffer_variable(name)
                {
                    self.push_error(
                        format!("Format-string assignment requires a buffer destination: {}", name),
                        Some(name),
                    );
                }

                self.analyze_expr(value);

                if was_already_declared {
                    // Reassignment of an existing name: enforce the lock
                    // instead of relabelling scalar_types to match. On a
                    // mismatch, check_type_lock has already reported the
                    // error; either way the declared type never changes
                    // here.
                    self.check_type_lock(name, value);
                } else {
                    // A brand-new name introduced by bare `name is <value>.`
                    // (valid at top level; the function-scope case above
                    // already reported "unknown variable") is a genuine
                    // declaration - infer and lock its type, exactly like an
                    // explicit `a <type> called name is <value>.` would.
                    if !self.is_buffer_variable(name)
                        && !self.is_list_variable(name)
                        && !self.is_map_variable(name)
                        && !self.file_variables.contains(name.as_str())
                        && !self.timer_variables.contains(name.as_str())
                    {
                        match self.arithmetic_operand_type(value) {
                            Some(t) => {
                                self.scalar_types.insert(name.clone(), t);
                            }
                            None => {
                                self.scalar_types.remove(name);
                            }
                        }
                    }
                    if !self.declared_locations.contains_key(name) {
                        if let Some(loc) = self.find_declaration_location(name) {
                            self.declared_locations.insert(name.clone(), loc);
                        }
                    }
                }
            }

            Statement::ValueRetype { name, target_type } => {
                if !self.is_variable_available(name) {
                    let mut err = CompileError::new(
                        &format!("Cannot retype '{}': it is not declared", name)
                    );
                    if let Some(loc) = self.find_write_site_location(name, 0) {
                        err = err.with_location(loc.clone());
                        err = err.with_underline_note(name.len().max(1), "this attempts an in-place retype");
                    }
                    err = err.with_help_line(
                        &format!("declare '{}' as a value first: a value called {} is <value>.", name, name)
                    );
                    self.errors.push(err);
                } else if !self.value_typed_names.contains(name) {
                    let declared = self.named_value_type(name).unwrap_or(Type::Unknown);
                    let mut err = CompileError::new(
                        &format!(
                            "In-place retyping applies only to variables declared as 'value'; '{}' is declared as a {}",
                            name,
                            self.type_name(&declared)
                        )
                    );
                    if let Some(loc) = self.find_write_site_location(name, 0) {
                        err = err.with_location(loc.clone());
                        err = err.with_underline_note(name.len().max(1), "this attempts an in-place retype");
                    }
                    if let Some(decl_loc) = self.declared_locations.get(name) {
                        err = err.with_note_line(
                            &format!(
                                "'{}' was declared as {} at {}:{}:{}",
                                name,
                                self.type_name(&declared),
                                decl_loc.file,
                                decl_loc.line,
                                decl_loc.column
                            )
                        );
                    }
                    err = err.with_help_line(
                        &format!(
                            "convert explicitly instead: a {} called t is {} as {}.",
                            self.type_name(target_type),
                            name,
                            self.type_name(target_type)
                        )
                    );
                    self.errors.push(err);
                } else {
                    // Record the concrete target type so subsequent reads and
                    // arithmetic see the variable as that type while it remains
                    // a `value` (runtime-tagged slot) for storage purposes.
                    self.scalar_types.insert(name.clone(), target_type.clone());
                }
            }

            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                self.validate_function_condition_variable_refs(condition);
                self.analyze_expr(condition);

                // Branches are analyzed with the same incoming scope.
                // Declarations inside one branch do not become visible in sibling
                // branches. After the if-statement, only variables that are
                // definitely available on all continuing paths remain visible.
                let branch_env = self.current_env();
                let mut continuing_envs: Vec<AnalysisEnv> = Vec::new();

                let guard_key = Self::simple_guard_key(condition);
                let (then_env, then_terminates) = self.analyze_block_in_scope(
                    then_block,
                    &branch_env,
                    guard_key.as_deref(),
                );
                if !then_terminates {
                    continuing_envs.push(then_env);
                }

                for (cond, block) in else_if_blocks {
                    let saved_env = self.current_env();
                    self.apply_env(&branch_env);
                    self.validate_function_condition_variable_refs(cond);
                    self.analyze_expr(cond);
                    self.apply_env(&saved_env);
                    let (elif_env, elif_terminates) = self.analyze_block_in_scope(block, &branch_env, None);
                    if !elif_terminates {
                        continuing_envs.push(elif_env);
                    }
                }

                if let Some(block) = else_block {
                    let (else_env, else_terminates) = self.analyze_block_in_scope(block, &branch_env, None);
                    if !else_terminates {
                        continuing_envs.push(else_env);
                    }
                } else {
                    // No else means the original incoming scope can continue unchanged.
                    continuing_envs.push(branch_env.clone());
                }

                let merged_env = self.merge_continuing_envs(&continuing_envs, &branch_env);
                self.apply_env(&merged_env);
            }
            
            Statement::While { condition, body } => {
                self.validate_function_condition_variable_refs(condition);
                self.analyze_expr(condition);
                self.loop_depth += 1;
                for s in body {
                    self.analyze_statement(s);
                }
                self.loop_depth -= 1;
            }

            Statement::ForRange { variable, range, body } => {
                self.variables.insert(variable.clone());
                // A range loop variable steps over integers - reusing a
                // name already declared with a different type is a rebind,
                // same rule as `Set`/`is` (plan 294 finding 2: this used to
                // leave the old label in place and segfault when the
                // formatter dereferenced the loop counter as a pointer).
                self.bind_variable_type(
                    variable,
                    Type::Integer,
                    "this for-range loop",
                    "counts with",
                    &[format!("each {} ", variable)],
                    true,
                );
                self.analyze_expr(range);
                self.loop_depth += 1;
                for s in body {
                    self.analyze_statement(s);
                }
                self.loop_depth -= 1;
            }

            Statement::ForEach { variable, collection, body } => {
                self.variables.insert(variable.clone());
                // The element category is unknown (lists may be mixed), so a
                // label left over from a previous use of this name - e.g. a
                // text variable reused as the loop variable over a numeric
                // list - must not linger and falsely reject arithmetic on the
                // loop variable inside the body.
                self.scalar_types.remove(variable);
                // Plan 294 finding 18: over a list PROVEN heterogeneous (see
                // `list_mixed`/`list_literal_is_mixed`), the loop variable
                // genuinely holds a different type each iteration - no
                // fixed type is correct, so route it into the same
                // dynamic/`value` mechanism a declared `a value called x`
                // uses, demanding an explicit check before arithmetic
                // instead of silently allowing it on whatever type the
                // element turns out not to be. A list this narrower,
                // single-pass check can't prove mixed (see `list_mixed`'s
                // own doc comment on what it does not catch) keeps today's
                // existing behaviour unchanged.
                let list_name = match collection {
                    Expr::Identifier(n) | Expr::StringLit(n) => Some(n.as_str()),
                    _ => None,
                };
                let is_mixed = match (list_name, collection) {
                    (Some(n), _) => self.list_mixed.contains(n),
                    (None, Expr::ListLit { elements }) => self.list_literal_is_mixed(elements),
                    (None, _) => false,
                };
                if is_mixed {
                    self.value_typed_names.insert(variable.clone());
                } else {
                    self.value_typed_names.remove(variable.as_str());
                }
                self.analyze_expr(collection);
                self.loop_depth += 1;
                for s in body {
                    self.analyze_statement(s);
                }
                self.loop_depth -= 1;
            }

            Statement::Repeat { count, body } => {
                self.analyze_expr(count);
                self.loop_depth += 1;
                for s in body {
                    self.analyze_statement(s);
                }
                self.loop_depth -= 1;
            }
            
            Statement::Return { value, .. } => {
                // `Return` is only meaningful inside a function. At top
                // level the codegen still emits a function epilogue
                // (leave/ret) which is undefined from _start, so reject
                // it here rather than produce broken output.
                if !self.in_function_scope {
                    let hint = self.pending_blank_line_truncation.as_ref().map(|(func, _, loc)| {
                        format!(
                            "a blank line ended `{}`'s body early at line {} — a paragraph break closes all open clauses, so this Return is no longer inside it",
                            func, loc.line
                        )
                    });
                    self.push_error_with_hint(
                        "Return is only valid inside a function".to_string(),
                        None,
                        hint.as_deref(),
                    );
                }
                if let Some(v) = value {
                    self.analyze_expr(v);
                }
            }
            
            Statement::Allocate { name, size } => {
                self.deps.uses_heap = true;
                self.variables.insert(name.clone());
                self.allocated_variables.insert(name.clone());
                // The variable now holds a raw pointer, rendered as a
                // number when printed - a rebind like any other (plan 294
                // finding 17: codegen used to leave a stale text label in
                // place, formatting the fresh allocation as a C string).
                self.bind_variable_type(
                    name,
                    Type::Integer,
                    "this Allocate statement",
                    "allocates",
                    &[format!("for {}", name)],
                    true,
                );
                self.analyze_expr(size);
            }

            Statement::Free { name } => {
                self.deps.uses_heap = true;
                if !self.is_variable_available(name) {
                    self.push_error(format!("Freeing unknown variable: {}", name), Some(name));
                } else if !self.is_buffer_variable(name)
                    && !self.is_list_variable(name)
                    && !self.allocated_variables.contains(name.as_str())
                {
                    self.push_error(
                        format!("Free requires a buffer or list: {}", name),
                        Some(name),
                    );
                }
            }
            
            Statement::FunctionCall { name, args } => {
                self.deps.uses_funcs = true; // Track that functions are used
                self.check_function_call(name, args);
                for arg in args {
                    self.analyze_expr(arg);
                }
            }
            
            Statement::FunctionDef { name, params, body, body_ended_early, .. } => {
                self.pending_blank_line_truncation = None;
                // A leading underscore is the runtime's namespace (see
                // docs/SYMBOL_MANGLING.md). A function name emits a label
                // verbatim, so `To _str_eq ...` redefines a coreasm symbol
                // and the author gets NASM's "label `_str_eq' inconsistently
                // redefined" - an assembler diagnostic about a symbol they
                // never wrote. Reject it here, in their terms.
                if name.starts_with('_') {
                    self.push_error(
                        format!(
                            "Function name '{}' starts with '_', which is reserved for \
                             the Vox runtime; choose a name without the leading underscore.",
                            name
                        ),
                        Some(name),
                    );
                }
                // Names that differ only in characters the mangler folds to
                // '_' would emit the same label, so one body would silently
                // win. Reject rather than miscompile. The check is scoped by
                // library: the key is the full `<lib>_<ver>_<func>` label, so
                // "my.helper" and "my helper" in the SAME library collide (and
                // are flagged), while the same two names in DIFFERENT libraries
                // of one .so produce distinct labels and are both fine — that
                // is the whole point of the mangling.
                let symbol = self.func_key(name);
                match self.mangled_functions.get(&symbol) {
                    Some(prev) if prev != name => {
                        self.push_error(
                            format!(
                                "Functions '{}' and '{}' both become the assembly symbol \
                                 '{}'; rename one so they stay distinct.",
                                prev, name, symbol
                            ),
                            Some(name),
                        );
                    }
                    _ => {
                        self.mangled_functions.insert(symbol, name.clone());
                    }
                }
                self.functions.insert(self.func_key(name));
                self.function_param_counts
                    .insert(self.func_key(name), params.len());
                self.deps.uses_funcs = true; // Track that functions are used

                // Functions can access top-level globals, but locals declared inside
                // the function must not leak back into top-level scope.
                let saved_env = self.current_env();
                let saved_guards = self.active_guards.clone();
                let saved_block_depth = self.block_depth;
                let saved_in_function_scope = self.in_function_scope;
                // Type labels are scoped like the variables themselves: a
                // parameter (or body-local declaration) named like a
                // top-level variable must not relabel it for the code after
                // the function - a text parameter "x" would otherwise make
                // top-level arithmetic on a number "x" a false error.
                let saved_scalar_types = self.scalar_types.clone();
                let saved_buffer_variables = self.buffer_variables.clone();
                let saved_list_variables = self.list_variables.clone();
                let saved_map_variables = self.map_variables.clone();
                let saved_file_variables = self.file_variables.clone();
                let saved_timer_variables = self.timer_variables.clone();
                let saved_allocated_variables = self.allocated_variables.clone();
                let saved_value_typed_names = self.value_typed_names.clone();
                self.variables = self.global_variables.clone();
                self.guarded_scopes.clear();
                self.active_guards.clear();
                self.in_function_scope = true;
                self.block_depth = 0;

                // Add function parameters to function scope. Buffer/list/file
                // typed parameters must also be recorded in their
                // type-specific sets, exactly like a VarDecl/BufferDecl at
                // top level would - otherwise `param's size`/`empty`/`full`
                // (and other buffer/list/file-only properties) incorrectly
                // report "requires a buffer, list, or file variable" for
                // the parameter itself. This previously only appeared to
                // work when a same-named top-level variable of the correct
                // type happened to already exist elsewhere in the program.
                for (param_name, param_type) in params {
                    self.variables.insert(param_name.clone());
                    match param_type {
                        Type::Buffer => { self.buffer_variables.insert(param_name.clone()); }
                        Type::List(_) => { self.list_variables.insert(param_name.clone()); }
                        Type::Map(_) => { self.map_variables.insert(param_name.clone()); }
                        Type::File => { self.file_variables.insert(param_name.clone()); }
                        Type::Integer | Type::Float | Type::String | Type::Boolean => {
                            self.scalar_types.insert(param_name.clone(), param_type.clone());
                        }
                        Type::Value => {
                            // A `value` parameter is dynamic: it carries a
                            // runtime tag but is not statically a number/text,
                            // so bare arithmetic on it must be rejected (the
                            // author guards with a stage-1c predicate first).
                            self.value_typed_names.insert(param_name.clone());
                        }
                        _ => {}
                    }
                }
                for s in body {
                    self.analyze_statement(s);
                }

                self.block_depth = saved_block_depth;
                self.active_guards = saved_guards;
                self.in_function_scope = saved_in_function_scope;
                self.scalar_types = saved_scalar_types;
                self.buffer_variables = saved_buffer_variables;
                self.list_variables = saved_list_variables;
                self.map_variables = saved_map_variables;
                self.file_variables = saved_file_variables;
                self.timer_variables = saved_timer_variables;
                self.allocated_variables = saved_allocated_variables;
                self.value_typed_names = saved_value_typed_names;
                self.apply_env(&saved_env);

                self.pending_blank_line_truncation = body_ended_early.as_ref().map(|loc| {
                    (name.clone(), params.iter().map(|(n, _)| n.clone()).collect(), loc.clone())
                });
            }

            Statement::Increment { name } | Statement::Decrement { name } => {
                if !self.is_variable_available(name) {
                    self.push_unknown_variable(name);
                } else if self.is_buffer_variable(name)
                    || self.is_list_variable(name)
                    || self.is_map_variable(name)
                    || self.file_variables.contains(name.as_str())
                    || self.flag_variables.contains(name.as_str())
                    || self.timer_variables.contains(name.as_str())
                    || matches!(self.named_value_type(name), Some(Type::String))
                {
                    // Increment/Decrement compile to an integer `inc/dec
                    // qword` on the variable's stack slot. Applied to a
                    // buffer/list/file variable that slot holds a pointer
                    // (which gets corrupted), to a timer it holds a 56-byte
                    // struct (also corrupted), and to a boolean flag it
                    // yields 2, 3, ... instead of a boolean. Reject these
                    // rather than emit undefined behaviour.
                    //
                    // A declared-text variable is the same defect the type
                    // lock elsewhere in this file exists to close, but this
                    // one is not a type CHANGE - tracking is correct, `name`
                    // really is text - so the lock doesn't see it (plan 294
                    // findings 5/15): the pointer just gets walked one byte
                    // at a time with no relationship to the string's bounds
                    // until it wanders off the mapping.
                    //
                    // Deliberately NOT rejecting `value`-typed names here:
                    // unlike bare arithmetic, Increment/Decrement on a
                    // `value` holding a number already worked correctly
                    // (inc/dec on its raw integer payload) before this
                    // check existed, and rejecting it would remove working
                    // behaviour outside findings 5/15, which are both about
                    // text. If `value` should eventually be rejected too,
                    // that is a separate decision, not folded in here.
                    let kw = if matches!(stmt, Statement::Increment { .. }) {
                        "Increment"
                    } else {
                        "Decrement"
                    };
                    // Built directly rather than via `push_error` so the
                    // pointer lands on the `Increment`/`Decrement` line
                    // itself: `push_error`'s `find_symbol_location` prefers
                    // `{name` (format-string interpolation) as its first
                    // pattern, which would anchor on an unrelated
                    // `Print "{s}"` elsewhere in the same program instead.
                    let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
                    let mut err = CompileError::new(&format!("{} requires a number variable: {}", kw, name));
                    let patterns = [format!("{} {}", kw, name)];
                    if let Some(loc) = self.find_bind_site_location(name, &patterns, occurrence, true) {
                        err = err.with_underline_note(name.len().max(1), "not a number here");
                        err = err.with_location(loc);
                    }
                    self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
                    self.errors.push(err);
                }
            }
            
            Statement::Break | Statement::Continue => {
                // Break/Continue are loop-control constructs. Outside a
                // loop the codegen silently emits nothing, so the author's
                // intent is lost with no signal - reject it at compile time.
                if self.loop_depth == 0 {
                    let kw = if matches!(stmt, Statement::Break) { "Break" } else { "Continue" };
                    self.push_error(
                        format!("{} is only valid inside a loop", kw),
                        None,
                    );
                }
            }
            
            // File I/O statements
            Statement::BufferDecl { name, size } => {
                self.variables.insert(name.clone());
                self.buffer_variables.insert(name.clone());
                self.analyze_expr(size);
                self.deps.uses_heap = true;
            }
            
            Statement::ByteSet { buffer, index, value } => {
                self.track_identifier(buffer);
                self.analyze_expr(index);
                self.analyze_expr(value);

                if !self.is_variable_available(buffer) {
                    self.push_error(format!("Unknown buffer: {}", buffer), Some(buffer));
                } else if !self.is_buffer_variable(buffer) {
                    self.push_error(
                        format!("Byte set target must be a buffer: {}", buffer),
                        Some(buffer),
                    );
                }
            }
            
            Statement::ElementSet { list, index, value } => {
                self.track_identifier(list);
                self.analyze_expr(index);
                self.analyze_expr(value);

                if !self.is_variable_available(list) {
                    self.push_error(format!("Unknown list: {}", list), Some(list));
                } else if !self.is_list_variable(list) {
                    self.push_error(
                        format!("Element set target must be a list: {}", list),
                        Some(list),
                    );
                }
            }

            // Set <map>'s "<key>" to <value>: insert or replace. The map may
            // reallocate on growth; codegen stores the returned pointer back
            // into the variable (mirroring ListAppend). Keys are text.
            Statement::MapSet { map, key, value } => {
                self.track_identifier(map);
                self.analyze_expr(key);
                self.analyze_expr(value);

                if !self.is_variable_available(map) {
                    self.push_error(format!("Unknown map: {}", map), Some(map));
                } else if !self.is_map_variable(map) {
                    self.push_error(
                        format!("Map set target must be a map: {}", map),
                        Some(map),
                    );
                }
                if let Some(Type::String) = self.infer_simple_expr_type(key) {
                    // ok: text key
                } else {
                    self.push_error(
                        "Map keys must be text".to_string(),
                        Some(map),
                    );
                }
            }
            
            Statement::ListAppend { list, value } => {
                self.track_identifier(list);
                self.analyze_expr(value);

                if self.is_buffer_variable(list) {
                    match value {
                        Expr::Identifier(source) => {
                            if !self.is_variable_available(source) {
                                self.push_error(format!("Unknown buffer: {}", source), Some(source));
                            } else if !self.is_buffer_variable(source)
                                && self.named_value_type(source) != Some(Type::String)
                            {
                                self.push_error(
                                    format!("Buffer append requires a buffer source: {}", source),
                                    Some(source),
                                );
                            }
                        }
                        Expr::StringLit(_) | Expr::FormatString { .. } => {
                            // Allowed: append text/format output into destination buffer.
                        }
                        _ => {
                            self.push_error(
                                "Buffer append requires a buffer source or format/literal text".to_string(),
                                Some(list),
                            );
                        }
                    }
                } else if self.is_list_variable(list) {
                    // Valid list append path.
                } else if !self.is_variable_available(list) {
                    self.push_error(format!("Unknown variable: {}", list), Some(list));
                } else {
                    self.push_error(
                        format!("Append target must be a buffer or list: {}", list),
                        Some(list),
                    );
                }
            }

            Statement::BufferCopy { source, destination } => {
                if let Expr::Identifier(source_name) = source {
                    self.track_identifier(source_name);
                }
                self.track_identifier(destination);

                self.analyze_expr(source);

                match source {
                    Expr::Identifier(source_name) => {
                        if !self.is_variable_available(source_name) {
                            self.push_error(format!("Unknown buffer: {}", source_name), Some(source_name));
                        } else if !self.is_buffer_variable(source_name) {
                            self.push_error(
                                format!("Copy source must be a buffer: {}", source_name),
                                Some(source_name),
                            );
                        }
                    }
                    Expr::StringLit(_) | Expr::FormatString { .. } => {
                        // Allowed: copy literal/format output into destination buffer.
                    }
                    _ => {
                        self.push_error(
                            "Copy source must be a buffer or format/literal text".to_string(),
                            Some(destination),
                        );
                    }
                }

                if !self.is_variable_available(destination) {
                    self.push_error(format!("Unknown buffer: {}", destination), Some(destination));
                } else if !self.is_buffer_variable(destination) {
                    self.push_error(
                        format!("Copy destination must be a buffer: {}", destination),
                        Some(destination),
                    );
                }
            }

            Statement::BufferClear { name } => {
                self.track_identifier(name);

                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown buffer: {}", name), Some(name));
                } else if !self.is_buffer_variable(name) {
                    self.push_error(
                        format!("Clear target must be a buffer: {}", name),
                        Some(name),
                    );
                }
            }
            
            Statement::FileOpen { name, path, .. } => {
                // `open ... called X` binds X to a file descriptor - a
                // rebind like any other if X already exists with an
                // incompatible type (plan 294 finding 3: this used to leave
                // a stale text label in place and dereference the fd as a
                // string pointer). Checked before registering `name` as a
                // file below, so it sees the pre-existing declared type.
                self.bind_variable_type(
                    name,
                    Type::File,
                    "this open statement",
                    "opens as",
                    &[format!("called {} ", name)],
                    false,
                );
                self.variables.insert(name.clone());
                self.file_variables.insert(name.clone());
                self.analyze_expr(path);
                self.validate_file_open_path(path);
                self.deps.uses_io = true;
            }
            
            Statement::FileRead { buffer, .. } => {
                if !self.is_variable_available(buffer) {
                    self.push_error(format!("Unknown buffer: {}", buffer), Some(buffer));
                } else if !self.is_buffer_variable(buffer) {
                    self.push_error(
                        format!("Read target must be a buffer: {}", buffer),
                        Some(buffer),
                    );
                }
                self.deps.uses_io = true;
            }

            Statement::FileReadLine { buffer, .. } => {
                if !self.is_variable_available(buffer) {
                    self.push_error(format!("Unknown buffer: {}", buffer), Some(buffer));
                } else if !self.is_buffer_variable(buffer) {
                    self.push_error(
                        format!("Read target must be a buffer: {}", buffer),
                        Some(buffer),
                    );
                }
                self.deps.uses_io = true;
            }

            Statement::FileSeekLine { file, line } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                } else if !self.file_variables.contains(file.as_str()) {
                    self.push_error(
                        format!("Seek target must be a file: {}", file),
                        Some(file),
                    );
                }
                self.analyze_expr(line);
                self.deps.uses_io = true;
            }

            Statement::FileSeekByte { file, byte } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                } else if !self.file_variables.contains(file.as_str()) {
                    self.push_error(
                        format!("Seek target must be a file: {}", file),
                        Some(file),
                    );
                }
                self.analyze_expr(byte);
                self.deps.uses_io = true;
            }

            Statement::FileWrite { file, value } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                } else if !self.file_variables.contains(file.as_str()) {
                    self.push_error(
                        format!("Write target must be a file: {}", file),
                        Some(file),
                    );
                }
                self.analyze_expr(value);
                self.deps.uses_io = true;
            }

            Statement::FileWriteNewline { file } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                } else if !self.file_variables.contains(file.as_str()) {
                    self.push_error(
                        format!("Write target must be a file: {}", file),
                        Some(file),
                    );
                }
                self.deps.uses_io = true;
            }

            Statement::FileClose { file } => {
                if !self.is_variable_available(file) {
                    self.push_error(format!("Unknown file: {}", file), Some(file));
                } else if !self.file_variables.contains(file.as_str()) {
                    self.push_error(
                        format!("Close target must be a file: {}", file),
                        Some(file),
                    );
                }
                self.deps.uses_io = true;
            }
            
            Statement::FileDelete { path } => {
                self.analyze_expr(path);
                self.deps.uses_io = true;
            }

            Statement::Rmdir { path } => {
                self.analyze_expr(path);
                self.deps.uses_io = true;
            }

            Statement::Mkdir { path } => {
                self.analyze_expr(path);
                self.deps.uses_io = true;
            }

            Statement::Chdir { path } => {
                self.analyze_expr(path);
                self.deps.uses_io = true;
            }

            Statement::Mount { source, target, fstype, options } => {
                self.analyze_expr(source);
                self.analyze_expr(target);
                self.analyze_expr(fstype);
                if let Some(o) = options {
                    self.analyze_expr(o);
                }
                self.deps.uses_io = true;
            }

            Statement::Unmount { target, .. } => {
                self.analyze_expr(target);
                self.deps.uses_io = true;
            }

            Statement::Shutdown | Statement::Reboot | Statement::Halt => {
                self.deps.uses_io = true;
            }

            Statement::PivotRoot { new_root, put_old } => {
                self.analyze_expr(new_root);
                self.analyze_expr(put_old);
                self.deps.uses_io = true;
            }

            Statement::Execute { path, args } => {
                self.analyze_expr(path);
                self.analyze_expr(args);
                self.deps.uses_io = true;
                // execve needs the process's real envp to properly inherit
                // the environment (NULL would give the child an empty one) -
                // this forces SAVE_ARGS to run and _envp to be captured.
                self.deps.uses_args = true;
            }

            Statement::Symlink { target, linkpath } => {
                self.analyze_expr(target);
                self.analyze_expr(linkpath);
                self.deps.uses_io = true;
            }

            Statement::Mknod { path, major, minor, .. } => {
                self.analyze_expr(path);
                self.analyze_expr(major);
                self.analyze_expr(minor);
                self.deps.uses_io = true;
            }
            
            Statement::OnError { actions } => {
                for action in actions {
                    self.analyze_statement(action);
                }
            }
            
            Statement::BufferResize { name, new_size } => {
                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown buffer: {}", name), Some(name));
                } else if !self.is_buffer_variable(name) {
                    self.push_error(
                        format!("Resize target must be a buffer: {}", name),
                        Some(name),
                    );
                }
                self.analyze_expr(new_size);
                self.deps.uses_heap = true;
            }
            
            Statement::LibraryDecl { name, version } => {
                self.pending_blank_line_truncation = None;
                // A `Library` declaration sets the identity for the function
                // definitions that follow it. The per-function tables are keyed
                // by the `<lib>_<ver>_<func>` label, so a call inside this
                // library's bodies resolves only against this library's
                // functions. The walk is in source order and a `Library`
                // precedes its functions, so the field is current when each
                // `FunctionDef` body is analyzed. (In a multi-input --shared
                // build the concatenated unit has one `Library` per input,
                // so each library's functions resolve in their own scope.)
                self.current_library = Some((name.clone(), version.clone()));
            }
            
            Statement::See { .. } => {
                // See statements are handled at compile time
            }
            
            Statement::Exit { code } => {
                self.analyze_expr(code);
            }
            
            // Time and Timer statements
            Statement::TimerDecl { name } => {
                self.variables.insert(name.clone());
                self.timer_variables.insert(name.clone());
            }

            Statement::TimerStart { name } => {
                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown timer: {}", name), Some(name));
                } else if !self.timer_variables.contains(name) {
                    self.push_error(
                        format!("Start requires a timer: {}", name),
                        Some(name),
                    );
                }
            }

            Statement::TimerStop { name } => {
                if !self.is_variable_available(name) {
                    self.push_error(format!("Unknown timer: {}", name), Some(name));
                } else if !self.timer_variables.contains(name) {
                    self.push_error(
                        format!("Stop requires a timer: {}", name),
                        Some(name),
                    );
                }
            }
            
            Statement::Wait { duration, .. } => {
                self.analyze_expr(duration);
            }
            
            Statement::GetTime { into } => {
                self.variables.insert(into.clone());
                // The variable now holds a unix timestamp.
                self.scalar_types.insert(into.clone(), Type::Integer);
            }
        }
    }
    
    fn analyze_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, op, right } => {
                self.analyze_expr(left);
                self.analyze_expr(right);
                // Arithmetic operators require numeric operands. Text,
                // buffer, list, file, and timer values compile to
                // pointer/handle arithmetic and yield garbage without an
                // explicit cast (`s as a number`).
                if self.is_arithmetic_op(op) {
                    self.check_arithmetic_operand(left);
                    self.check_arithmetic_operand(right);
                }
            }

            Expr::UnaryOp { op, operand } => {
                self.analyze_expr(operand);
                // Negation is arithmetic; `minus s` on a text/buffer/etc.
                // value has the same garbage problem as `0 subtract s`.
                if matches!(op, UnaryOperator::Negate) {
                    self.check_arithmetic_operand(operand);
                }
            }
            
            Expr::Range { start, end, .. } => {
                self.analyze_expr(start);
                self.analyze_expr(end);
            }
            
            Expr::PropertyCheck { value, .. } => {
                self.analyze_expr(value);
            }

            // Runtime type predicate (stage 1c). The type noun was validated
            // by the parser, so the analyzer only needs to recurse into the
            // operand.
            Expr::TypeCheck { value, .. } => {
                self.analyze_expr(value);
            }
            Expr::PropertyAccess { object, property } => {
                // _current_time is a synthetic object for "current time's X" - not a user variable
                if object == "_current_time" {
                    return;
                }
                self.track_identifier(object);
                if !self.is_variable_available(object) {
                    self.push_error(format!("Unknown variable: {}", object), Some(object));
                } else {
                    let is_buf = self.is_buffer_variable(object);
                    let is_list = self.is_list_variable(object);
                    let is_map = self.is_map_variable(object);
                    let is_file = self.file_variables.contains(object.as_str());
                    let is_scalar = self.is_scalar_variable(object);
                    // A text variable is "scalar" (its slot holds a raw
                    // 64-bit value), but that value is a string pointer -
                    // number/time properties on it read the pointer as a
                    // number and yield garbage. Only reject when the label
                    // is positively String; unknown stays allowed.
                    let is_text =
                        matches!(self.scalar_types.get(object.as_str()), Some(Type::String));
                    match property {
                        // `type` is a universal property: every variable,
                        // regardless of its declared type, reports its type as
                        // text. No further validation needed.
                        ObjectProperty::Type => {}
                        ObjectProperty::Size | ObjectProperty::Empty => {
                            if !is_buf && !is_list && !is_map && !is_file {
                                self.push_error(
                                    format!("Property '{}' requires a buffer, list, map, or file variable: {}",
                                        match property {
                                            ObjectProperty::Size => "size",
                                            ObjectProperty::Empty => "empty",
                                            _ => "unknown",
                                        }, object),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Full => {
                            if !is_buf && !is_list && !is_file {
                                self.push_error(
                                    format!("Property 'full' requires a buffer, list, or file variable: {}", object),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Keys | ObjectProperty::Values => {
                            if !is_map {
                                self.push_error(
                                    format!("Property '{}' requires a map variable: {}",
                                        if matches!(property, ObjectProperty::Keys) { "keys" } else { "values" }, object),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Capacity => {
                            if !is_buf && !is_list {
                                self.push_error(
                                    format!("Property 'capacity' requires a buffer or list variable: {}", object),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::First | ObjectProperty::Last => {
                            if !is_list {
                                self.push_error(
                                    format!("Property '{}' requires a list variable: {}",
                                        if matches!(property, ObjectProperty::First) { "first" } else { "last" }, object),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Descriptor | ObjectProperty::Modified |
                        ObjectProperty::Accessed | ObjectProperty::Permissions |
                        ObjectProperty::Readable | ObjectProperty::Writable => {
                            if !is_file {
                                self.push_error(
                                    format!("File property access requires a file variable: {}", object),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Absolute | ObjectProperty::Sign |
                        ObjectProperty::Even | ObjectProperty::Odd |
                        ObjectProperty::Positive | ObjectProperty::Negative |
                        ObjectProperty::Zero => {
                            if !is_scalar || is_text {
                                self.push_error(
                                    format!(
                                        "Property '{}' requires a number variable: {}",
                                        match property {
                                            ObjectProperty::Absolute => "absolute",
                                            ObjectProperty::Sign => "sign",
                                            ObjectProperty::Even => "even",
                                            ObjectProperty::Odd => "odd",
                                            ObjectProperty::Positive => "positive",
                                            ObjectProperty::Negative => "negative",
                                            ObjectProperty::Zero => "zero",
                                            _ => "unknown",
                                        },
                                        object,
                                    ),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Hour | ObjectProperty::Minute |
                        ObjectProperty::Second | ObjectProperty::Day |
                        ObjectProperty::Month | ObjectProperty::Year |
                        ObjectProperty::Unix => {
                            if !is_scalar || is_text {
                                self.push_error(
                                    format!(
                                        "Property '{}' requires a time value (number): {}",
                                        match property {
                                            ObjectProperty::Hour => "hour",
                                            ObjectProperty::Minute => "minute",
                                            ObjectProperty::Second => "second",
                                            ObjectProperty::Day => "day",
                                            ObjectProperty::Month => "month",
                                            ObjectProperty::Year => "year",
                                            ObjectProperty::Unix => "unix",
                                            _ => "unknown",
                                        },
                                        object,
                                    ),
                                    Some(object),
                                );
                            }
                        }
                        ObjectProperty::Duration | ObjectProperty::Elapsed |
                        ObjectProperty::StartTime | ObjectProperty::EndTime |
                        ObjectProperty::Running => {
                            if !self.timer_variables.contains(object.as_str()) {
                                self.push_error(
                                    format!(
                                        "Property '{}' requires a timer: {}",
                                        match property {
                                            ObjectProperty::Duration => "duration",
                                            ObjectProperty::Elapsed => "elapsed",
                                            ObjectProperty::StartTime => "start time",
                                            ObjectProperty::EndTime => "end time",
                                            ObjectProperty::Running => "running",
                                            _ => "unknown",
                                        },
                                        object,
                                    ),
                                    Some(object),
                                );
                            }
                        }
                    }
                }
            }
            
            Expr::FunctionCall { name, args } => {
                self.deps.uses_funcs = true; // Track that functions are used
                self.check_function_call(name, args);
                for arg in args {
                    self.analyze_expr(arg);
                }
            }
            
            Expr::ListAccess { list, index } => {
                self.analyze_expr(list);
                self.analyze_expr(index);

                if let Expr::Identifier(name) = list.as_ref() {
                    self.track_identifier(name);
                    if !self.is_variable_available(name) {
                        self.push_error(format!("Unknown list: {}", name), Some(name));
                    } else if !self.is_list_variable(name) {
                        self.push_error(
                            format!("List access target must be a list: {}", name),
                            Some(name),
                        );
                    }
                }
            }

            Expr::ByteAccess { buffer, index } => {
                self.analyze_expr(buffer);
                self.analyze_expr(index);

                if let Expr::Identifier(name) = buffer.as_ref() {
                    self.track_identifier(name);
                    if !self.is_variable_available(name) {
                        self.push_error(format!("Unknown buffer: {}", name), Some(name));
                    } else if !self.is_buffer_variable(name) {
                        self.push_error(
                            format!("Byte access target must be a buffer: {}", name),
                            Some(name),
                        );
                    }
                }
            }

            Expr::ElementAccess { list, index } => {
                self.analyze_expr(list);
                self.analyze_expr(index);

                if let Expr::Identifier(name) = list.as_ref() {
                    self.track_identifier(name);
                    if !self.is_variable_available(name) {
                        self.push_error(format!("Unknown list: {}", name), Some(name));
                    } else if !self.is_list_variable(name) {
                        self.push_error(
                            format!("Element access target must be a list: {}", name),
                            Some(name),
                        );
                    }
                }
            }
            
            Expr::ListLit { elements } => {
                self.deps.uses_heap = true;
                for elem in elements {
                    self.analyze_expr(elem);
                }
            }

            // Map literal {"k": v, ...}. Keys must be text; values are
            // analyzed (and may themselves be lists/maps -> uses_heap).
            Expr::MapLit { pairs } => {
                self.deps.uses_heap = true;
                for (key, value) in pairs {
                    self.analyze_expr(key);
                    self.analyze_expr(value);
                    if self.infer_simple_expr_type(key) != Some(Type::String) {
                        self.push_error(
                            "Map keys must be text".to_string(),
                            None,
                        );
                    }
                }
            }

            // Map key access: person's "name". The map operand must be a
            // map variable and the key must be text.
            Expr::MapAccess { map, key } => {
                self.track_identifier(map);
                self.analyze_expr(key);
                if !self.is_variable_available(map) {
                    self.push_error(format!("Unknown map: {}", map), Some(map));
                } else if !self.is_map_variable(map) {
                    self.push_error(
                        format!("Map access target must be a map: {}", map),
                        Some(map),
                    );
                }
                if self.infer_simple_expr_type(key) != Some(Type::String) {
                    self.push_error(
                        "Map keys must be text".to_string(),
                        Some(map),
                    );
                }
            }
            
            Expr::StringLit(_) => {
                self.deps.uses_strings = true;
            }
            
            Expr::FormatString { parts } => {
                self.deps.uses_strings = true;
                for part in parts {
                    match part {
                        FormatPart::Expression { expr, .. } => {
                            self.analyze_expr(expr);
                        }
                        FormatPart::Variable { name, .. } => {
                            if name.is_empty() {
                                // BUGS_FOUND #10: a bare or unmatched `{` in a
                                // string literal. The format parser found a `{`
                                // with no variable/expression before the closing
                                // `}` (or no closing `}` at all), producing an
                                // empty-named placeholder. Report the real cause
                                // and the `{{` escape instead of the old
                                // empty-named "Unknown variable: ". The caret
                                // still lands on the offending `{`:
                                // find_symbol_location("") matches the first
                                // `{` in the source.
                                self.push_error_with_hint(
                                    "Unmatched `{` in a string literal. A single \
                                     `{` begins a format interpolation, but no \
                                     variable or expression followed it. To write \
                                     a literal brace, double it: `{{` for `{` and \
                                     `}}` for `}`."
                                        .to_string(),
                                    Some(""),
                                    None,
                                );
                                continue;
                            }
                            self.track_identifier(name);
                            if !self.is_variable_available(name) && name != "_iter" {
                                if find_similar_keyword(name, ENGLISH_KEYWORDS).is_none() {
                                    self.push_unknown_variable(name);
                                } else {
                                    self.track_typo_candidate(name);
                                }
                            }
                        }
                        FormatPart::Literal(_) => {}
                    }
                }
            }
            
            Expr::Identifier(name) => {
                self.track_identifier(name);
                if !self.is_variable_available(name) && name != "_iter" {
                    // Plan 270 G4: a bare/quoted identifier naming a
                    // zero-argument function is a call in expression position,
                    // not a variable lookup. Validate it resolves and has zero
                    // arity via the shared call-site path.
                    if self.is_zero_arg_function(name) {
                        self.deps.uses_funcs = true;
                        self.check_function_call(name, &[]);
                    } else if find_similar_keyword(name, ENGLISH_KEYWORDS).is_none() {
                        // Don't report as unknown variable if it might be a
                        // keyword typo (that will be caught by check_for_typos)
                        self.push_unknown_variable(name);
                    } else {
                        self.track_typo_candidate(name);
                    }
                }
            }
            
            // Argument and environment variable expressions
            Expr::ArgumentCount | Expr::ArgumentName | Expr::ArgumentFirst | 
            Expr::ArgumentSecond | Expr::ArgumentLast | Expr::ArgumentEmpty |
            Expr::ArgumentAll | Expr::ArgumentRaw => {
                self.deps.uses_args = true;
            }

            Expr::ArgumentHas { value } => {
                self.deps.uses_args = true;
                self.deps.uses_strings = true;
                self.analyze_expr(value);
            }
            
            Expr::TreatingAs { value, match_value, replacement } => {
                self.analyze_expr(value);
                self.analyze_expr(match_value);
                self.analyze_expr(replacement);
                self.validate_treating_expr(value, match_value, replacement);
            }
            
            Expr::ArgumentAt { index } => {
                self.deps.uses_args = true;
                self.analyze_expr(index);
            }
            
            Expr::EnvironmentVariable { name } => {
                self.deps.uses_args = true;
                self.analyze_expr(name);
            }
            
            Expr::EnvironmentVariableCount | Expr::EnvironmentVariableFirst |
            Expr::EnvironmentVariableLast | Expr::EnvironmentVariableEmpty => {
                self.deps.uses_args = true;
            }
            
            Expr::EnvironmentVariableAt { index } => {
                self.deps.uses_args = true;
                self.analyze_expr(index);
            }
            
            Expr::EnvironmentVariableExists { name } => {
                self.deps.uses_args = true;
                self.analyze_expr(name);
            }

            Expr::DurationCast { value, .. } => {
                // `timer's duration in seconds` parses as a DurationCast
                // wrapping a PropertyAccess. Without recursing here the
                // inner property access was never analyzed, so a duration
                // cast on a non-timer (or referencing an unknown variable)
                // compiled silently and read stack garbage at runtime.
                self.analyze_expr(value);
            }

            Expr::Cast { value, target_type, .. } => {
                // Recurse so unknown variables / nested type errors inside
                // a cast (`missing as a number`) are reported instead of
                // compiling silently and emitting garbage.
                self.analyze_expr(value);

                // Plan 294 finding 21 (adjacent discovery, not one of the
                // original 18): a cast on a dynamically-tagged `value`
                // source (a declared `a value called x`, a `value`
                // parameter, or - as of finding 18's fix - a heterogeneous-
                // list loop variable) is codegen-unimplemented, not merely
                // unchecked. Verified on unmodified `main`: codegen's Cast
                // arm dispatches on the STATIC source type
                // (`infer_expr_type`), which is `VarType::Mixed` here, and
                // every target-type branch's fallback for an unrecognised
                // source type is to pass the raw payload through
                // unconverted. That is silently correct only when the
                // runtime tag happens to already match the target's native
                // representation (an Integer-tagged value cast `as a
                // number` is a no-op that looks like a real conversion);
                // for any other tag it reinterprets the bytes - a text
                // pointer read as an integer, the same failure mode this
                // whole track exists to close, just reached through the
                // suggested fix-it rather than around it. The properly
                // general fix is a runtime tag dispatch in codegen's Cast
                // arm (the tag-branch machinery already exists and is
                // proven correct for `Print`'s equivalent dispatch,
                // `emit_mixed_print_dispatch`) - tracked as its own follow-
                // up rather than attempted here under this session's time
                // pressure, in the single highest-risk area for a change
                // like that to go wrong. Loud and honest beats silently
                // wrong: reject the cast instead of emitting it.
                let is_dynamic_source = match value.as_ref() {
                    Expr::Identifier(name) | Expr::StringLit(name) => {
                        self.value_typed_names.contains(name.as_str())
                    }
                    _ => false,
                };
                if is_dynamic_source {
                    // Deliberately not suggesting a workaround: the type
                    // predicate guard ('X is a number') was checked and
                    // does NOT narrow X's type inside its own body (still
                    // rejected there too), so recommending it here would
                    // repeat the exact mistake this whole check exists to
                    // avoid - confidently pointing at a dead end. There is
                    // currently no supported way to convert a genuinely
                    // dynamically-tagged value; say so plainly rather than
                    // invent one.
                    self.push_error(
                        format!(
                            "Cannot cast {} to {}: {}'s type is only known at runtime, and casting a dynamically-tagged value is not currently supported by the compiler (a known gap, not yet resolvable from within the language).",
                            self.operand_label(value),
                            self.typed_phrase(target_type),
                            self.operand_label(value),
                        ),
                        None,
                    );
                }
            }

            Expr::FileAvailable { path } => {
                // `path is available` wraps the path expression; recurse so
                // an unknown variable used as the path is caught.
                self.analyze_expr(path);
            }

            Expr::ReapChild { pid } => {
                if let Some(p) = pid {
                    self.analyze_expr(p);
                }
            }

            _ => {}
        }
    }
}

