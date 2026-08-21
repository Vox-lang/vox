use super::*;
use super::untyped_returns::UntypedPosition;

/// A short, human-readable name for a statement kind, used in the shared-mode
/// top-level diagnostic. Only called for statements that are NOT one of the
/// three allowed top-level forms (FunctionDef/LibraryDecl/See).
fn shared_top_level_label(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Print { .. } => "print statement",
        Statement::VarDecl { .. } => "variable declaration",
        Statement::Assignment { .. } | Statement::SetThingField { .. } => "assignment",
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
    pub fn analyze(&mut self, program: &mut Program) {
        // A shared library has no `_start`, so top-level executable statements
        // would be generated into the discarded main body and silently dropped.
        // Reject them before any other analysis so the author gets one clear
        // diagnostic instead of a confusing cascade. Only function definitions,
        // `Library`, and `see` may appear at the top level of a library.
        if self.shared_mode {
            for stmt in &program.statements {
                // A thing definition belongs here with the other three: it
                // declares a type, allocates nothing, and emits no code, so
                // there is no executable statement to be dropped into the
                // discarded main body. Plan 310 §3 requires definitions to
                // cross files like functions do, which means a library's own
                // exports can take and return its things. A thing *variable*
                // is still rejected - that is a VarDecl, and its storage and
                // defaults would need main-line code that never runs.
                if !matches!(
                    stmt,
                    Statement::FunctionDef { .. }
                        | Statement::LibraryDecl { .. }
                        | Statement::See { .. }
                        | Statement::ThingDecl(_)
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

        // Bug #54: which lists can still be widened or aliased after their
        // declaration, so the element-type proof below is only offered for
        // the ones that cannot - plus the blunter question of whether any
        // function widens a list it was handed, which no name can be
        // pinned on. Whole-program and order-independent, so a read early
        // in the file gets the same answer as one after the append that
        // widens the list.
        self.widened_lists = collect_widened_lists(&program.statements);
        self.functions_widen_lists = any_function_widens_a_parameter(&program.statements);

        // Load and validate the thing registry before anything can consult it
        // for a size, an offset, or a field path (plan 310 §6, §10).
        self.load_things(program);

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
                Statement::FunctionDef { name, params, return_type, body, .. } => {
                    let key = crate::codegen::make_function_label(
                        self.shared_mode,
                        current_lib.as_ref(),
                        name,
                    );
                    self.functions.insert(key.clone());
                    self.function_param_counts.insert(key.clone(), params.len());
                    // Signatures are collected here, before the walk, so a
                    // call to a function defined further down the file still
                    // knows whether an argument is a thing to copy.
                    self.function_signatures
                        .insert(key.clone(), (params.clone(), return_type.clone()));
                    // Bug #45: whether the result of a call has a type to
                    // read is settled here too, for the same reason - a call
                    // above the definition must be judged the same as one
                    // below it.
                    self.record_untyped_result_function(key, return_type, body);
                }
                Statement::FlagSchemaDecl { name, value_type, .. } => {
                    self.flag_variables.insert(
                        name.clone(),
                        match value_type {
                            FlagValueType::Boolean => Type::Boolean,
                            FlagValueType::Number => Type::Integer,
                            FlagValueType::Text => Type::String,
                        },
                    );
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
            Statement::SetThingField { value, .. } => self.expr_uses_flag(value),
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

    pub(crate) fn analyze_statement(&mut self, stmt: &Statement) {
        match stmt {
            // A thing definition declares a type: it introduces no variable,
            // touches no runtime dependency, and emits no code. Registry
            // validation (sizes, offsets, cycles, the manifest checks) lands
            // with the declarations that need it; there is nothing to check
            // while a definition cannot yet be used.
            Statement::ThingDecl(_) => {}

            // A field write (plan 310 §3). The chain is validated exactly like
            // a read. A chain ending on a nested thing writes the whole thing,
            // which is a copy (§5); every other chain takes an ordinary value.
            Statement::SetThingField { base, path, value } => {
                match self.resolve_thing_field(base, path) {
                    Some(Type::Thing(inner)) => {
                        let target = things::render_chain(base, path);
                        self.check_thing_copy(&target, base, &inner, value);
                    }
                    _ => self.analyze_expr(value),
                }
            }

            Statement::Print { value, .. } => {
                self.deps.uses_io = true;
                // The one position that renders a whole thing (plan 310 §7).
                // Print writes the fields straight out, so a thing is welcome
                // here and in the interpolations of the string it prints;
                // every other position still wants a single value.
                match value {
                    Expr::FormatString { parts } => {
                        self.deps.uses_strings = true;
                        self.analyze_format_parts(parts, true);
                    }
                    _ => {
                        self.analyze_printed_expr(value);
                        // Bug #45: `print 'opaque label'.` has no type to
                        // print the result AS.
                        self.reject_untyped_call_result(value, UntypedPosition::Print);
                    }
                }

                if matches!(value, Expr::StringLit(_)) {
                    self.deps.uses_strings = true;
                }
            }
            
            Statement::VarDecl { name, var_type, value } => {
                // A thing variable is assigned by copying a whole thing into
                // the storage it already has (plan 310 §5). `Set origin to
                // <expr>.` names an existing thing variable; the typed
                // declaration form is handled with the declaration below,
                // which reserves the storage first.
                if var_type.is_none() {
                    if let Some(thing) = self.thing_of_variable(name) {
                        if self.is_variable_available(name) {
                            match value {
                                Some(v) => self.check_thing_copy(name, name, &thing, v),
                                // `Set origin.` with nothing to store: there
                                // is no value to write, and writing one would
                                // land a single quadword on the thing's first
                                // field.
                                None => self.push_whole_thing_not_a_value(name, name, &thing),
                            }
                            return;
                        }
                    }
                }
                // Bug #45: a `value` is the one declared type that supplies
                // no static type - it carries the payload's type as a runtime
                // tag, set from whatever was proven at the write. An
                // undeclared return type proves nothing, so the tag would be
                // the conservative "number" guess and the payload a text.
                // Both the declaration and a later `Set v to <call>` write
                // that tag, so both are checked.
                let writes_a_dynamic_value = matches!(var_type, Some(Type::Value))
                    || (var_type.is_none() && self.value_typed_names.contains(name));
                if writes_a_dynamic_value {
                    if let Some(v) = value {
                        self.reject_untyped_call_result(v, UntypedPosition::DynamicValue);
                    }
                }

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
                        // Bug #54: a homogeneous list literal's element type
                        // is provable, which makes a read of an element into
                        // a differently-typed variable a statically-detectable
                        // type-lock violation instead of the segfault it used
                        // to compile to.
                        if let Some(t) = self.list_literal_element_type(elements) {
                            self.list_element_type.insert(name.clone(), t);
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
                // An initialiser on a thing declaration copies a whole thing
                // of the same type into the storage the declaration reserves
                // (plan 310 §5). It is never an ordinary value, so it is
                // checked as a copy here instead of analyzed as one below.
                let declared_thing = match var_type {
                    Some(Type::Thing(thing)) => {
                        // A function's own thing local is not in the
                        // main-line pre-pass, so record it as the walk
                        // reaches it (plan 310 §3).
                        let thing = thing.clone();
                        self.declare_thing_variable(name, &thing);
                        Some(thing)
                    }
                    Some(_) => {
                        // Declared as something else: this name is not a
                        // thing variable, so it must not keep a stale thing
                        // label and report "holds a whole point" for an
                        // ordinary number.
                        self.thing_vars.remove(name);
                        None
                    }
                    None => None,
                };
                self.maybe_activate_true_guard(name, var_type, value);
                if let Some(v) = value {
                    match &declared_thing {
                        Some(thing) => {
                            let (name, thing) = (name.clone(), thing.clone());
                            self.check_thing_copy(&name, &name, &thing, v);
                        }
                        None => self.analyze_expr(v),
                    }
                }
                // Bug #54: a declaration initialised from a collection or
                // buffer read of a provably different type. The read is
                // checked here because the type lock below only guards
                // writes to an ALREADY-declared name, and this is the
                // declaration itself.
                if let (Some(vt), Some(v)) = (var_type.as_ref(), value.as_ref()) {
                    self.check_declared_read_type(name, vt, v);
                    // Bug #57: `a text called t is nothing.` (and the
                    // `Set`/`Create ... to nothing.` spellings, which parse
                    // into this same statement). Checked here for the same
                    // reason as the read above - the type lock guards writes
                    // to an already-declared name, and this is the
                    // declaration itself.
                    self.check_nothing_initialiser(name, vt, v);
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
                // `elsewhere is origin.` on a name that holds a thing copies
                // the whole thing into the storage it already has (plan 310
                // §5); anything that is not a whole thing of that type is a
                // write of one quadword over its first field.
                if was_already_declared {
                    if let Some(thing) = self.thing_of_variable(name) {
                        self.check_thing_copy(name, name, &thing, value);
                        return;
                    }
                }
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
                // The loop's own bounds, walked directly: `analyze_expr`
                // refuses a bare range everywhere a value is expected
                // (bug #56), and this is the one position where one belongs.
                if let Expr::Range { start, end, .. } = range {
                    self.analyze_expr(start);
                    self.analyze_expr(end);
                } else {
                    self.analyze_expr(range);
                }
                self.loop_depth += 1;
                for s in body {
                    self.analyze_statement(s);
                }
                self.loop_depth -= 1;
            }

            Statement::ForEach { variable, collection, body } => {
                // `each ... from <collection>` walks a list header. Refuse
                // the operands that would make codegen read one where there
                // is none (bug #49) before anything else in this arm, so the
                // rest of the pass is not reasoning about a loop that cannot
                // run.
                self.check_loop_collection(variable, collection);
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
                    // Bug #54: over a list whose element type IS provable,
                    // the loop variable holds that type on every iteration.
                    // Recording it is what makes `label is part.` inside the
                    // body - the loop spelling of an element read into a
                    // mistyped variable - reach the type lock instead of
                    // compiling to a number written into a text slot.
                    // Bug #55: an inline collection - `each item from
                    // ["a"]` - has no name to look up, so the same
                    // element type has to be read off the literal. Without
                    // it the loop variable stayed untyped and a
                    // type-mismatched `treating` clause over a list
                    // literal reached codegen.
                    let element_type = match (list_name, collection) {
                        (Some(n), _) => self.list_element_type_of(n),
                        (None, Expr::ListLit { elements }) => self.list_literal_element_type(elements),
                        (None, _) => None,
                    };
                    if let Some(t) = element_type {
                        self.scalar_types.insert(variable.clone(), t);
                    }
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
                    let mut location = None;
                    let hint = if let Some((func, _, loc)) = &self.pending_blank_line_truncation {
                        location = Some(loc.clone());
                        Some(format!(
                            "a blank line ended `{}`'s body early at line {} — a paragraph break closes all open clauses, so this Return is no longer inside it",
                            func, loc.line
                        ))
                    } else if let Some((func, loc)) = &self.pending_return_truncation {
                        location = Some(loc.clone());
                        Some(format!(
                            "a Return closed `{}`'s body early at line {} — a body-level Return ends the function it's in, so this Return is no longer inside it",
                            func, loc.line
                        ))
                    } else {
                        None
                    };
                    self.push_error_with_hint_at(
                        "Return is only valid inside a function".to_string(),
                        location,
                        hint.as_deref(),
                    );
                }
                // A function declaring a thing return hands the caller a copy
                // of a whole thing (plan 310 §5), so what is returned is
                // checked against the declared shape exactly like any other
                // copy - "the function's result" being the destination.
                match (self.current_function_return_type.clone(), value) {
                    (Some(Type::Thing(thing)), Some(v)) => {
                        self.check_thing_copy("this function's result", "Return", &thing, v);
                    }
                    // A buffer return hands back a pointer the caller reads as
                    // a buffer struct, so a text (or any other non-buffer)
                    // source is refused rather than compiled into an
                    // out-of-bounds read (bug #53).
                    (Some(Type::Buffer), Some(v)) => {
                        self.check_buffer_return_source(v);
                        self.analyze_expr(v);
                    }
                    // Bug #57: `Return text, nothing.` The caller reads the
                    // result as the declared type, so a text return handed
                    // back a null pointer to dereference and a number return
                    // quietly answered 0.
                    (Some(ref declared), Some(v)) if Analyzer::nothing_is_refused_for(declared) => {
                        let declared = declared.clone();
                        self.check_nothing_return(&declared, v);
                        self.analyze_expr(v);
                    }
                    (_, Some(v)) => self.analyze_expr(v),
                    (_, None) => {}
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
                // A call as a whole statement discards its result, so a thing
                // return needs no destination here; only the arguments are
                // checked, and a thing argument is a copy (plan 310 §5).
                self.analyze_call_arguments(name, args);
            }
            
            Statement::FunctionDef { name, params, return_type, body, body_ended_early, body_ended_via_return } => {
                self.pending_blank_line_truncation = None;
                self.pending_return_truncation = None;
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
                self.record_function_signature(name, params, return_type);
                self.deps.uses_funcs = true; // Track that functions are used

                // A thing crosses a library boundary as bytes with a layout
                // the `.lib` interface file has no vocabulary for: its Table
                // of Contents names types by noun, and no noun spells a
                // user-defined shape. Rejecting an exported signature that
                // uses one keeps a `--shared` build from writing a `.lib`
                // that cannot be read back (plan 310 §6 defers user types out
                // of the cross-boundary type system).
                if self.shared_mode {
                    for (param_name, param_type) in params {
                        if let Type::Thing(thing) = param_type {
                            self.push_error(
                                format!(
                                    "Exported function '{}' takes a {} ('{}'), which a \
                                     library interface cannot describe yet\n  \
                                     A thing is a layout private to one compilation; \
                                     pass its fields across the boundary instead.",
                                    name, thing, param_name
                                ),
                                Some(name),
                            );
                        }
                    }
                    if let Type::Thing(thing) = return_type {
                        self.push_error(
                            format!(
                                "Exported function '{}' returns a {}, which a library \
                                 interface cannot describe yet\n  \
                                 A thing is a layout private to one compilation; \
                                 return one of its fields instead.",
                                name, thing
                            ),
                            Some(name),
                        );
                    }
                }

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
                let saved_thing_vars = self.thing_vars.clone();
                let saved_return_type = self.current_function_return_type.take();
                let saved_function_name = self.current_function_name.take();
                self.current_function_return_type = Some(return_type.clone());
                self.current_function_name = Some(name.clone());
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
                    // A parameter of any other type must not inherit a
                    // same-named global thing variable's label, or `p's x`
                    // would resolve against a shape this parameter does not
                    // have. The thing arm below puts back the ones that do.
                    self.thing_vars.remove(param_name);
                    match param_type {
                        Type::Thing(thing) => {
                            // A thing parameter holds a copy of the caller's
                            // thing in this frame (plan 310 §5), so its
                            // fields read exactly like a local declaration's.
                            self.thing_vars.insert(param_name.clone(), thing.clone());
                        }
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
                self.thing_vars = saved_thing_vars;
                self.current_function_return_type = saved_return_type;
                self.current_function_name = saved_function_name;
                self.apply_env(&saved_env);

                self.pending_blank_line_truncation = body_ended_early.as_ref().map(|loc| {
                    (name.clone(), params.iter().map(|(n, _)| n.clone()).collect(), loc.clone())
                });
                self.pending_return_truncation = body_ended_via_return
                    .as_ref()
                    .map(|loc| (name.clone(), loc.clone()));
            }

            Statement::Increment { name } | Statement::Decrement { name } => {
                if !self.is_variable_available(name) {
                    self.push_unknown_variable(name);
                } else if self.reject_whole_thing_as_a_value(name) {
                    // A step on a whole thing would `inc qword` its first
                    // field. `increment origin's x.` is what it means, and
                    // that parses into a field write instead (plan 310 §3).
                } else if self.is_buffer_variable(name)
                    || self.is_list_variable(name)
                    || self.is_map_variable(name)
                    || self.file_variables.contains(name.as_str())
                    || self.flag_variables.contains_key(name.as_str())
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
                self.reject_untyped_call_result(value, UntypedPosition::ListElement);

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
                self.reject_untyped_call_result(value, UntypedPosition::MapValue);

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
                    // Valid list append path - except for bug #45's slot: the
                    // element's tag is written from the type proven here, and
                    // an undeclared return type proves nothing.
                    self.reject_untyped_call_result(value, UntypedPosition::ListAppend);
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
                self.check_file_write_operand(file, value);
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

            Statement::SendSignal { signal, pid } => {
                self.analyze_expr(signal);
                self.analyze_expr(pid);
                self.deps.uses_io = true;
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

}
