use super::*;
use super::untyped_returns::UntypedPosition;

impl Analyzer {
    /// The key under which a function DEFINED in the current library is filed
    /// in the per-function tables: the `<lib>_<ver>_<func>` mangled label in
    /// shared mode (with an identity set), else `mangle_symbol(name)`. This is
    /// the same rule codegen's `function_label` uses, so the two agree on a
    /// function's identity and a call that the analyzer accepts also resolves
    /// at the call site. Reads `current_library`, which the statement walk sets
    /// as it passes each `Library` declaration.
    pub(crate) fn func_key(&self, name: &str) -> String {
        crate::codegen::make_function_label(self.shared_mode, self.current_library.as_ref(), name)
    }

    pub(crate) fn expr_uses_flag(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(name) => {
                if self.flag_variables.contains_key(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            Expr::FormatString { parts } => {
                for part in parts {
                    match part {
                        FormatPart::Variable { name, .. } => {
                            if self.flag_variables.contains_key(name) {
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
    pub(crate) fn imported_providers(&self, name: &str) -> Vec<&crate::lib_file::ImportedFunction> {
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

    /// Record a function's declared parameter and return types, so a call
    /// site can check the shapes a thing argument or a thing result has to
    /// have (plan 310 §5).
    pub(crate) fn record_function_signature(
        &mut self,
        name: &str,
        params: &[(String, Type)],
        return_type: &Type,
    ) {
        let key = self.func_key(name);
        self.function_signatures
            .insert(key, (params.to_vec(), return_type.clone()));
    }

    /// The declared type of a call's result: a local definition first (which
    /// shadows a same-named import, as call resolution does), then a single
    /// unambiguous import.
    pub(crate) fn function_return_type(&self, name: &str) -> Option<Type> {
        if let Some((_, return_type)) = self.function_signatures.get(&self.func_key(name)) {
            return Some(return_type.clone());
        }
        let providers = self.imported_providers(name);
        match providers.as_slice() {
            [only] => Some(only.return_type.clone()),
            _ => None,
        }
    }

    /// A call's declared parameters, resolved the same way.
    fn function_params(&self, name: &str) -> Option<Vec<(String, Type)>> {
        if let Some((params, _)) = self.function_signatures.get(&self.func_key(name)) {
            return Some(params.clone());
        }
        let providers = self.imported_providers(name);
        match providers.as_slice() {
            [only] => Some(only.params.clone()),
            _ => None,
        }
    }

    /// Analyze a call's arguments. An argument landing on a `thing`
    /// parameter is a copy source rather than a value (plan 310 §5), so it
    /// is checked against the parameter's own thing; every other argument is
    /// an ordinary expression.
    pub(crate) fn analyze_call_arguments(&mut self, name: &str, args: &[Expr]) {
        let params = self.function_params(name).unwrap_or_default();
        for (index, arg) in args.iter().enumerate() {
            match params.get(index) {
                Some((param_name, Type::Thing(thing))) => {
                    let (param_name, thing) = (param_name.clone(), thing.clone());
                    let target = format!("{}'s {}", name, param_name);
                    self.check_thing_copy(&target, name, &thing, arg);
                }
                // Bug #57: `nothing` handed to a concretely-typed parameter.
                // The callee stores it in that parameter's slot and reads it
                // as the declared type, so a `text` parameter took a null
                // pointer and faulted on the callee's first read. Bug #65 is
                // the same hole for every other provable type - `greet with
                // 5.` on `a text called who` faulted identically - and is
                // checked only when the `nothing` check has not already
                // reported, so one argument never earns two diagnostics.
                //
                // A `value` parameter is the documented home for both, so
                // both checks leave it alone. An IMPORTED function's
                // arguments are deliberately skipped here: `check_function_call`
                // has already routed those through `validate_import_call_args`,
                // whose own type check would otherwise report the same
                // mismatch a second time.
                Some((param_name, param_type)) => {
                    let (param_name, param_type) = (param_name.clone(), param_type.clone());
                    if !self.check_nothing_argument(name, &param_name, &param_type, arg)
                        && self.is_local_function(name)
                    {
                        self.check_argument_type(name, &param_name, &param_type, arg);
                    }
                    self.analyze_expr(arg);
                }
                None => self.analyze_expr(arg),
            }
        }
    }

    /// Plan 270 G4: a bare or quoted identifier in *expression* position
    /// that names a zero-argument function is a call, not a variable lookup.
    /// True iff `name` resolves to a callable declaring zero parameters — a
    /// local function (looked up via `func_key`, so shared-mode mangling
    /// matches the definition) or a single unambiguous import. A name that is
    /// a variable in scope is decided by the caller *before* consulting this;
    /// a variable shadows a same-named zero-arg function.
    pub(crate) fn is_zero_arg_function(&self, name: &str) -> bool {
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
    pub(crate) fn check_function_call(&mut self, name: &str, args: &[Expr]) {
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
            // A thing parameter takes only that same thing: user-defined
            // types are value types with a fixed layout, so no other
            // category can fill the slot (plan 310 §5, §6).
            Thing(name) => matches!(actual, Thing(other) if other == name),
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

    /// The `SPEC` in `{value:SPEC}` names a count - `{x:N}` characters of
    /// padding, `{f:.N}` decimal places. LANGUAGE.md:3101-3119 puts no
    /// ceiling on either, and none is intended: a width renders literally,
    /// so a huge one is simply a huge amount of output. The one count that
    /// cannot be honoured is one too large for the compiler to hold, and
    /// that has to be *said*. Reading the width with a 32-bit parse and
    /// discarding the `Err` is what made `{n:2147483648}` compile to the
    /// same code as a bare `{n}` - no padding, no diagnostic, and a cliff
    /// between two adjacent literals (docs/BUGS_FOUND.md #61).
    ///
    /// The other count that cannot be honoured is one written beside a
    /// second count: `{f:8.2}` asks to pad AND to set decimal places, and
    /// Vox has no primitive that does both. That silently printed `2.5` -
    /// neither the width nor a precision that prints `2.50` on its own -
    /// until #85 made the reader see the pair and this say it.
    pub(crate) fn check_format_spec(&mut self, format: Option<&str>) {
        let Some(fault) = read_format_spec(format).1 else {
            return;
        };
        // Every fault names what was written, what Vox will not do with
        // it, and the way out; they differ only in what the spec's own
        // text supplies to each.
        // `symbol` is what the caret sits on - the count, or both counts.
        // `written` is the whole spec clause as it appears after the `:`,
        // which is what the search anchors on; the two differ only for a
        // precision, whose leading `.` belongs to the clause and not under
        // the caret.
        let count_past_the_limit = |subject: &str, unit: &str, written: String, digits: &str| {
            (
                format!(
                    "a {} of {} is more than Vox can count to - the largest is {} {}",
                    subject, digits, FORMAT_MAX_COUNT, unit
                ),
                digits.to_string(),
                written,
                format!(
                    "every one of those {} is written out, so a large {} is a large amount of output - but it still has to be a count Vox can hold. Write {} or less.",
                    unit, subject, FORMAT_MAX_COUNT
                ),
            )
        };
        let (message, symbol, written, help) = match &fault {
            FormatSpecFault::WidthTooLarge(digits) => {
                count_past_the_limit("pad width", "characters", digits.clone(), digits)
            }
            FormatSpecFault::PrecisionTooLarge(digits) => count_past_the_limit(
                "decimal precision",
                "decimal places",
                format!(".{}", digits),
                digits,
            ),
            FormatSpecFault::UnknownSpecifier(written) => (
                format!("'{}' is not a format specifier Vox knows", written),
                written.clone(),
                written.clone(),
                "the specifiers are a width (`N`), a zero-padded width (`0N`), a decimal precision (`.N`), and a whole number's base - `x` (hexadecimal), `X` (hexadecimal, uppercase), `b` (binary) or `o` (octal), which a width can precede (`04x`). Drop the specifier to render the value plainly.".to_string(),
            ),
        };
        let mut err = CompileError::new(&message);
        // Two spec faults writing the same text are two errors, each
        // pointing at its own `{...}` - the same occurrence bookkeeping
        // `push_error_with_hint` does for a repeated symbol.
        let occurrence = *self.symbol_error_counts.get(&symbol).unwrap_or(&0);
        // Anchor on the spec's own `:` so the scan keeps its comment
        // exclusion and still reaches into the text literal a format spec
        // lives in. Searching for the bare count found it in neither, and
        // the last-resort mention scan then put the caret on the first
        // matching text anywhere in the file - a fixture's own header
        // comment quoting the spec it tests, which is #46's miss exactly
        // (docs/BUGS_FOUND.md #85). The fallback stays for a spec that
        // reached here from something other than a `{name:SPEC}` clause.
        let location = self
            .find_pattern_location(&symbol, &[format!(":{}", written)], occurrence, None, false, true)
            .or_else(|| self.find_symbol_location(&symbol, occurrence));
        if let Some(loc) = location {
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(symbol, occurrence + 1);
        err = err.with_help_line(&help);
        self.errors.push(err);
    }

    /// Bug #71: a `{value:SPEC}` clause whose specifier the value's type
    /// cannot answer.
    ///
    /// A width asks nothing of a type - every rendering is some number of
    /// characters long - and v0.4.7 settled that a width on a float or a
    /// text renders the value and drops the padding (#36). The other two
    /// specifiers do ask something:
    ///
    /// - `{v:.N}` names N places in a NUMBER's decimal expansion. A text or
    ///   a buffer has no expansion, so there is no such thing as one of its
    ///   decimal places.
    /// - `{v:x}` / `:X` / `:b` / `:o` write a WHOLE number in another base.
    ///   A text has no base. Neither has a float: 2.5 has no digits in base
    ///   16 that Vox defines, and rendering the ones it has would mean
    ///   dropping the fraction, which is a loss the author has to ask for.
    ///
    /// Unanswerable used to mean the integer routine ran anyway on whatever
    /// the slot held: `{n:.2}` printed the integer's bits read as a double
    /// (`0.00`) and `{t:x}` printed the string's ADDRESS, which is an
    /// information leak as well as a wrong answer. Codegen no longer
    /// reinterprets anything (`emit_formatted_value`), so the value would
    /// now be right and the specifier silently dropped; that is the mildest
    /// wrong rather than none, and this compiler says so instead - the same
    /// judgement #45, #62, #63 and #65 make about a category error the
    /// compiler can see. The way out is named in the help line, because
    /// there always is one: cast the value, or drop the specifier.
    ///
    /// Deliberately silent where nothing is provable. A `value` is dynamic
    /// (its tag is not known until runtime) and renders through its own
    /// tag dispatch, which honours no specifier at all; a list or a map
    /// renders as its elements and ignores the specifier the same way; and
    /// an expression whose type cannot be proven answers `None`, which
    /// means allow, exactly as every other check in this analyzer treats
    /// an unproven type.
    pub(crate) fn check_format_spec_against_type(
        &mut self,
        format: Option<&str>,
        label: &str,
        subject: Option<&Expr>,
        ty: Option<&Type>,
    ) {
        let ask = read_format_spec_ask(format);
        let Some(ty) = ty else {
            return;
        };
        let (asked_for, needs) = match ask {
            FormatSpecAsk::AnyType => return,
            FormatSpecAsk::DecimalPlaces(places) => {
                if !matches!(ty, Type::String | Type::Buffer) {
                    return;
                }
                (
                    format!("to {} decimal places", places),
                    "`:.N` writes a number to N decimal places",
                )
            }
            FormatSpecAsk::Base(base) => {
                if !matches!(ty, Type::String | Type::Buffer | Type::Float) {
                    return;
                }
                (
                    format!("in {}", base),
                    "`:x`, `:X`, `:b` and `:o` write a whole number in another base",
                )
            }
        };
        // `operand_label` answers a name for the shapes it can write back
        // and "this value" for the rest - an arithmetic hole, a call
        // result. A name is quoted and is pasteable into the help; the
        // generic label is neither, so it is neither quoted nor pasted.
        let named = self.is_variable_available(label);
        let mut err = CompileError::new(&format!(
            "cannot render {}, which is {}, {}",
            if named {
                format!("'{}'", label)
            } else {
                label.to_string()
            },
            self.typed_phrase(ty),
            asked_for
        ));
        // The caret goes on the offending hole - the name inside the braces
        // of the `{name:SPEC}` that was written, not the declaration and not
        // the string literal that holds it (#46). The pattern is the hole's
        // own source text, so `{ratio:b}` anchors on the `:b` hole even when
        // the same name is rendered plainly a line above; and counting
        // occurrences of THAT pattern, not of the bare name, is what puts
        // two identical holes on two different carets.
        // A hole with no name of its own is anchored on the first name
        // INSIDE it - `{ratio multiply 2.0:x}` points at `ratio` - which is
        // the start of the offending hole even though the whole hole cannot
        // be written back as a pattern.
        let anchor = if named {
            Some(label.to_string())
        } else {
            subject.and_then(first_named_operand)
        };
        if let Some(anchor) = anchor {
            let hole = if named {
                format!("{{{}:{}", anchor, format.unwrap_or_default())
            } else {
                format!("{{{}", anchor)
            };
            let occurrence = *self.symbol_error_counts.get(&hole).unwrap_or(&0);
            let located = self
                .find_pattern_location(&anchor, &[hole.clone()], occurrence, None, false, true)
                .or_else(|| self.find_symbol_location(&anchor, occurrence));
            if let Some(loc) = located {
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(hole, occurrence + 1);
        }
        err = err.with_note_line(&format!(
            "{}, and {} is not one",
            needs,
            self.typed_phrase(ty)
        ));
        // A buffer holds bytes, and LANGUAGE.md's Basic Conversions table
        // has no buffer-to-number cast to send anyone to, so it is offered
        // the cast that does exist. A text and a float both convert
        // directly.
        let (convert, plainly) = match ty {
            _ if !named => (
                // A cast cannot be written inside an expression hole - the
                // braces a whole-expression cast needs (LANGUAGE.md:1860)
                // are the hole's own - so the way out is a named number,
                // computed once and rendered.
                "work it out into a number first - `a number called total is {...} as a number.` - and render that"
                    .to_string(),
                "the value itself".to_string(),
            ),
            Type::Buffer => (
                format!(
                    "read it out first - `a text called contents is \"{{{}}}\".` - then convert that",
                    label
                ),
                format!("`{{{}}}`", label),
            ),
            // The specifier is quoted back exactly as it was written, so
            // `{n:04x}` is answered with `{n as a number:04x}` and not with
            // a rewrite that quietly drops the author's width.
            _ => (
                format!(
                    "convert it first - `{{{} as a number:{}}}`",
                    label,
                    format.unwrap_or_default()
                ),
                format!("`{{{}}}`", label),
            ),
        };
        err = err.with_help_line(&format!(
            "{}, or drop the specifier to render {}",
            convert, plainly
        ));
        self.errors.push(err);
    }

    /// Every interpolation of one format string. `whole_things_render` says
    /// whether this string's sink can render a whole thing: `Print` writes
    /// the fields straight out (plan 310 §7), while every other sink builds
    /// text and has nothing to build a thing's rendering into.
    pub(crate) fn analyze_format_parts(&mut self, parts: &[FormatPart], whole_things_render: bool) {
        self.deps.uses_strings = true;
        for part in parts {
            match part {
                FormatPart::Expression { expr, format } => {
                    self.check_format_spec(format.as_deref());
                    // `"{span's start}"` - a chain ending on a nested thing
                    // parses as an expression part, and renders exactly as
                    // the thing it names does.
                    if whole_things_render {
                        self.analyze_printed_expr(expr);
                    } else {
                        self.analyze_expr(expr);
                    }
                    // Bug #45: `"got {'opaque label'}"` renders the result as
                    // whatever type it is told the value has, and an
                    // undeclared return type tells it nothing.
                    self.reject_untyped_call_result(expr, UntypedPosition::Interpolation);
                    // Bug #71: and a specifier the proven type cannot
                    // answer. `provable_value_type` answers None for
                    // anything it cannot settle, which this check reads as
                    // "allow" - so an unproven expression keeps rendering
                    // exactly as it did.
                    self.check_format_spec_against_type(
                        format.as_deref(),
                        &self.operand_label(expr),
                        Some(expr),
                        self.provable_value_type(expr).as_ref(),
                    );
                }
                FormatPart::Variable { name, format } => {
                    self.check_format_spec(format.as_deref());
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
                    } else if let Some(thing) = self.thing_of_variable(name) {
                        // `"{origin}"` interpolates a whole thing, which
                        // renders as its fields (plan 310 §7). A field of it
                        // (`"{origin's x}"`) parses as an Expression part
                        // instead and is an ordinary value either way.
                        if !whole_things_render {
                            self.push_whole_thing_not_interpolable(name, &thing);
                        }
                    } else {
                        // Bug #71: `{t:x}` on a text used to print the
                        // string's address. Only reached once the name is
                        // known to exist and is not a whole thing, so an
                        // unknown name still reports only that.
                        self.check_format_spec_against_type(
                            format.as_deref(),
                            name,
                            None,
                            self.named_value_type(name).as_ref(),
                        );
                    }
                }
                FormatPart::Literal(_) => {}
            }
        }
    }

    pub(crate) fn analyze_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::BinaryOp { left, op, right } => {
                // A comparison with a whole thing on either side follows the
                // equality rule (plan 310 §8) rather than the ordinary value
                // rules, and analyzes its own operands.
                if self.check_thing_comparison(left, op, right) {
                    return;
                }
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
            
            // A range is a loop's counter bounds, not a value: LANGUAGE.md:262
            // says ranges are "**not** allocated as lists - they compile
            // directly to efficient loop constructs". Only a loop header may
            // hold one, and `Statement::ForRange` walks its bounds itself
            // rather than coming through here. Anything else reaching this arm
            // wrote `all the numbers from/between ...` where a value belongs,
            // which codegen has no value to emit for - it left whatever was in
            // the accumulator, and a list initialiser or a print then read that
            // as a list header and segfaulted (bug #56).
            Expr::Range { start, end, .. } => {
                self.analyze_expr(start);
                self.analyze_expr(end);
                // The caret is placed by searching the source for the phrase
                // itself: `all` alone matches inside `called`, and nothing
                // else in the language builds a range in expression position,
                // so the whole phrase is both safe and exact.
                self.push_error_with_hint(
                    "A range is not a value: `all the numbers from/between ...`".to_string(),
                    Some("all the numbers"),
                    Some(
                        "a range counts, it does not hold - iterate it with `For each n from 1 to 3,`, or write the items out as a list, `[1, 2, 3]`",
                    ),
                );
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
                    // Through `push_unknown_variable`, not `push_error`: the
                    // caret belongs on the possessive that failed, not on the
                    // (textually earlier) declaration that happens to spell
                    // the same name (docs/BUGS_FOUND.md #46, #89, #92).
                    self.push_unknown_variable(object);
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
                self.analyze_call_arguments(name, args);
                // Bugs #62/#63: reaching this arm at all means the call's
                // result is being read - a call run for its effect alone is
                // `Statement::FunctionCall` and never comes through here. A
                // function that returns nothing has no result to read.
                self.reject_void_call_result(name);
                // A call returning a whole thing is a copy source, not a
                // value: this is a position that wants one value, and a thing
                // has none (plan 310 §5). `analyze_thing_source` is the path
                // that accepts it.
                if let Some(thing) = self.thing_returned_by(name) {
                    self.push_error(
                        format!(
                            "A call to '{}' returns a whole {}, which is not a value\n  \
                             What a call returns is copied into a {}: write `a {} \
                             called <name> is {} of ...` or `The <name> is {} of ...` \
                             (plan 310 §5).",
                            name, thing, thing, thing, name, name
                        ),
                        Some(name),
                    );
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
                    // Bug #45: a literal's slot is tagged from the type
                    // proven here, exactly as `append` is.
                    self.reject_untyped_call_result(elem, UntypedPosition::ListElement);
                }
            }

            // Map literal {"k": v, ...}. Keys must be text; values are
            // analyzed (and may themselves be lists/maps -> uses_heap).
            Expr::MapLit { pairs } => {
                self.deps.uses_heap = true;
                for (key, value) in pairs {
                    self.analyze_expr(key);
                    self.analyze_expr(value);
                    self.reject_untyped_call_result(value, UntypedPosition::MapValue);
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

            // A field read (plan 310 §3). Never fails at runtime - the offset
            // is a compile-time constant - so unlike element access there is
            // no error-flag path to declare here.
            Expr::ThingField { base, path } => {
                self.analyze_thing_field(base, path);
            }

            Expr::FormatString { parts } => {
                // A format string reached as an ordinary expression builds
                // text, which is the sink a whole thing cannot render into
                // yet - the print statement's own arm is the one that allows
                // it (plan 310 §7).
                self.analyze_format_parts(parts, false);
            }

            Expr::Identifier(name) => {
                self.track_identifier(name);
                // A thing variable's bare name is not a value (plan 310 §5/§7).
                if let Some(thing) = self.thing_of_variable(name) {
                    if self.is_variable_available(name) {
                        self.push_whole_thing_not_a_value(name, name, &thing);
                        return;
                    }
                }
                if !self.is_variable_available(name) && name != "_iter" {
                    // Plan 270 G4: a bare/quoted identifier naming a
                    // zero-argument function is a call in expression position,
                    // not a variable lookup. Validate it resolves and has zero
                    // arity via the shared call-site path.
                    if self.is_zero_arg_function(name) {
                        self.deps.uses_funcs = true;
                        self.check_function_call(name, &[]);
                        // Bugs #62/#63: the bare-name call form, in the same
                        // value position as the `of`-form arm above.
                        self.reject_void_call_result(name);
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
            // ArgumentAll / ArgumentRaw build a Vox list from argv via
            // HEAP_ALLOC, so they need the heap runtime (heap.asm) included
            // alongside args.asm.
            Expr::ArgumentAll | Expr::ArgumentRaw => {
                self.deps.uses_args = true;
                self.deps.uses_heap = true;
            }

            Expr::ArgumentCount | Expr::ArgumentName | Expr::ArgumentFirst |
            Expr::ArgumentSecond | Expr::ArgumentLast | Expr::ArgumentEmpty => {
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

            Expr::ReapChild { pid, .. } => {
                if let Some(p) = pid {
                    self.analyze_expr(p);
                }
            }

            _ => {}
        }
    }

}

/// The first variable name mentioned inside an expression, for anchoring a
/// caret on a format hole that has no name of its own (docs/BUGS_FOUND.md
/// #71). `{ratio multiply 2.0:x}` cannot be written back as a source
/// pattern, but `ratio` is where the hole starts, and pointing at the start
/// of the offending hole beats pointing nowhere - which in this renderer
/// also costs the `note:` and `help:` lines.
///
/// Left-to-right and shallow on purpose: the leftmost name is the one the
/// reader's eye lands on. Shapes that carry no name answer `None`, and so
/// does an expression made only of literals, which simply gets no caret.
fn first_named_operand(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(name) => Some(name.clone()),
        Expr::StringLit(name) => Some(name.clone()),
        Expr::BinaryOp { left, right, .. } => {
            first_named_operand(left).or_else(|| first_named_operand(right))
        }
        Expr::UnaryOp { operand, .. } => first_named_operand(operand),
        Expr::Cast { value, .. } => first_named_operand(value),
        Expr::PropertyAccess { object, .. } => Some(object.clone()),
        Expr::MapAccess { map, .. } => Some(map.clone()),
        Expr::ElementAccess { list, .. } | Expr::ListAccess { list, .. } => {
            first_named_operand(list)
        }
        Expr::FunctionCall { name, .. } => Some(name.clone()),
        _ => None,
    }
}
