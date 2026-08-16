use super::*;

/// One exported function's signature for the `.lib` table of contents: the
/// authored name, the full parameter list (name + type), and the declared
/// return type. The return type is read from the `Return a <type>,` annotation
/// (the only place Vox source states it); a bodiless `.lib` declaration has no
/// body, hence `, returning a <type>` existing only in `.lib` files.
#[derive(Debug, Clone, PartialEq)]
pub struct LibFunction {
    pub name: String,
    pub params: Vec<(String, Type)>,
    pub return_type: Type,
}

/// One `Library` block in a `.lib`: a <library, version> identity and the
/// exported functions declared under it, in source order. A multi-input
/// `--shared` build produces several blocks in one `.lib`, one per input.
#[derive(Debug, Clone, PartialEq)]
pub struct LibBlock {
    pub lib: String,
    pub version: String,
    pub funcs: Vec<LibFunction>,
}

/// Author-facing noun for a scalar (non-collection) type — shared by
/// `type_noun` itself and its `List`-element rendering.
fn scalar_type_noun(t: &Type) -> Option<&'static str> {
    match t {
        Type::Integer => Some("number"),
        Type::Float => Some("float"),
        Type::String => Some("text"),
        Type::Boolean => Some("boolean"),
        Type::File => Some("file"),
        Type::Buffer => Some("buffer"),
        Type::Time => Some("time"),
        Type::Timer => Some("timer"),
        Type::Value => Some("value"),
        _ => None,
    }
}

/// Author-facing noun for a `.lib` parameter or return type — the same
/// 11-type vocabulary in both positions (plan 296; the vocabulary used to
/// differ by position — five types in return, eight in parameter — mirroring
/// a restriction Vox source's own `Return a <type>,` no longer has). Returns
/// `None` for `Void` (no `, returning` clause: the function returns nothing)
/// and `Unknown` (an untyped `with n` parameter has no noun to render;
/// callers fall back to `number`, matching `emit_function_call`'s untyped-
/// param word count). A `List` renders `list of <elem>` when its element
/// type is known — inferred by `collect_function_signatures` from the
/// exporting library's own source, never author-declared (plan 296) — or
/// bare `list` otherwise, exactly as before.
fn type_noun(t: &Type) -> Option<String> {
    match t {
        Type::List(elem) => Some(match scalar_type_noun(elem) {
            Some(en) => format!("list of {}", en),
            None => "list".to_string(),
        }),
        Type::Map(_) => Some("map".to_string()),
        _ => scalar_type_noun(t).map(|s| s.to_string()),
    }
}

/// Whether `t` is one of the scalar types this scan can credit as evidence
/// for a list's element type: a parameter's or local's declared type, or a
/// called function's declared return type. The same set `scalar_expr_type`'s
/// `Identifier` arm has always trusted (plan 296) — factored out so the new
/// `FunctionCall` arm and the local-declared-type collector (plan 303 phase
/// 2) apply the identical rule instead of drifting from it.
fn is_trackable_scalar_type(t: &Type) -> bool {
    matches!(
        t,
        Type::Integer
            | Type::Float
            | Type::String
            | Type::Boolean
            | Type::File
            | Type::Buffer
            | Type::Time
            | Type::Timer
            | Type::Value
    )
}

/// A scalar expression's `Type`, for the handful of shapes this scan
/// understands: a literal; a format string (always text — BUGS_FOUND #17
/// made the element itself sound, so the TOC can now say so too); a
/// reference to a name (parameter or local) whose own declared
/// (non-collection) type is already known; or a call to a function in the
/// same library whose declared return type is known. Anything else — an
/// element/property read, a call whose callee isn't in `fn_return_types`
/// (an import, or a forward reference this narrow scan didn't resolve), a
/// local built from something this scan didn't already trace — is `None`,
/// which the caller treats as "give up."
fn scalar_expr_type(
    expr: &Expr,
    scalar_types: &HashMap<String, Type>,
    fn_return_types: &HashMap<String, Type>,
) -> Option<Type> {
    match expr {
        Expr::StringLit(_) => Some(Type::String),
        Expr::IntegerLit(_) => Some(Type::Integer),
        Expr::FloatLit(_) => Some(Type::Float),
        Expr::BoolLit(_) => Some(Type::Boolean),
        Expr::FormatString { .. } => Some(Type::String),
        Expr::Identifier(n) => scalar_types
            .get(n)
            .filter(|t| is_trackable_scalar_type(t))
            .cloned(),
        Expr::FunctionCall { name, .. } => fn_return_types
            .get(name)
            .filter(|t| is_trackable_scalar_type(t))
            .cloned(),
        _ => None,
    }
}

/// Join one observed element type into the running verdict: the first
/// observation wins, a disagreeing later one (or an unclassifiable
/// observation, `None`) taints the whole scan to `Unknown` via `conflict`.
fn note_element_type(found: &mut Option<Type>, conflict: &mut bool, observed: Option<Type>) {
    match observed {
        None => *conflict = true,
        Some(t) => match found {
            Some(prev) if *prev != t => *conflict = true,
            Some(_) => {}
            None => *found = Some(t),
        },
    }
}

/// Recurse into a statement list's control-flow bodies the same shape
/// `prescan_walk` does, collecting every `VarDecl` with an explicit,
/// trackable scalar `var_type` into `found` — a local's declared type is
/// authoritative for its reads, the same way a parameter's is (plan 303
/// phase 2). A name declared with two disagreeing scalar types (e.g. once in
/// each arm of an `if`) is dropped from `found` entirely rather than
/// guessed: this scan is non-flow-sensitive and can't tell which
/// declaration a later read sees, so neither is trustworthy evidence.
fn collect_declared_scalar_types_walk(
    body: &[Statement],
    found: &mut HashMap<String, Type>,
    conflicted: &mut std::collections::HashSet<String>,
) {
    for stmt in body {
        match stmt {
            Statement::VarDecl {
                name,
                var_type: Some(t),
                ..
            } if is_trackable_scalar_type(t) => match found.get(name) {
                Some(prev) if prev != t => {
                    conflicted.insert(name.clone());
                }
                Some(_) => {}
                None => {
                    found.insert(name.clone(), t.clone());
                }
            },
            Statement::If {
                then_block,
                else_if_blocks,
                else_block,
                ..
            } => {
                collect_declared_scalar_types_walk(then_block, found, conflicted);
                for (_, blk) in else_if_blocks {
                    collect_declared_scalar_types_walk(blk, found, conflicted);
                }
                if let Some(blk) = else_block {
                    collect_declared_scalar_types_walk(blk, found, conflicted);
                }
            }
            Statement::While { body, .. }
            | Statement::ForRange { body, .. }
            | Statement::ForEach { body, .. }
            | Statement::Repeat { body, .. } => {
                collect_declared_scalar_types_walk(body, found, conflicted);
            }
            Statement::OnError { actions } => {
                collect_declared_scalar_types_walk(actions, found, conflicted);
            }
            _ => {}
        }
    }
}

/// Every `VarDecl`-declared scalar local's `Type` in `body`, regardless of
/// nesting or control-flow position — see `collect_declared_scalar_types_walk`.
fn collect_declared_scalar_types(body: &[Statement]) -> HashMap<String, Type> {
    let mut found = HashMap::new();
    let mut conflicted = std::collections::HashSet::new();
    collect_declared_scalar_types_walk(body, &mut found, &mut conflicted);
    for name in &conflicted {
        found.remove(name);
    }
    found
}

/// Recurse into a statement list's control-flow bodies the same shape
/// `prescan_walk` does, collecting every `Append <expr> to target` and every
/// `a list called target is [...]` literal that names `target`.
fn scan_list_element_type(
    target: &str,
    scalar_types: &HashMap<String, Type>,
    fn_return_types: &HashMap<String, Type>,
    body: &[Statement],
    found: &mut Option<Type>,
    conflict: &mut bool,
) {
    for stmt in body {
        match stmt {
            Statement::ListAppend { list, value } if list == target => {
                note_element_type(
                    found,
                    conflict,
                    scalar_expr_type(value, scalar_types, fn_return_types),
                );
            }
            Statement::VarDecl {
                name,
                value: Some(Expr::ListLit { elements }),
                ..
            } if name == target => {
                for e in elements {
                    note_element_type(
                        found,
                        conflict,
                        scalar_expr_type(e, scalar_types, fn_return_types),
                    );
                }
            }
            Statement::If {
                then_block,
                else_if_blocks,
                else_block,
                ..
            } => {
                scan_list_element_type(target, scalar_types, fn_return_types, then_block, found, conflict);
                for (_, blk) in else_if_blocks {
                    scan_list_element_type(target, scalar_types, fn_return_types, blk, found, conflict);
                }
                if let Some(blk) = else_block {
                    scan_list_element_type(target, scalar_types, fn_return_types, blk, found, conflict);
                }
            }
            Statement::While { body, .. }
            | Statement::ForRange { body, .. }
            | Statement::ForEach { body, .. }
            | Statement::Repeat { body, .. } => {
                scan_list_element_type(target, scalar_types, fn_return_types, body, found, conflict);
            }
            Statement::OnError { actions } => {
                scan_list_element_type(target, scalar_types, fn_return_types, actions, found, conflict);
            }
            _ => {}
        }
    }
}

/// Infer a homogeneous element type for the list built through `target`
/// (a parameter name, most often — the plan's own verified repro appends a
/// parameter: `Append s to out.`) within one function's body. `Unknown`
/// when the scan finds disagreement or nothing at all. `param_types` and
/// `body`'s own declared-scalar locals are merged into one lookup table (a
/// local re-declaring a parameter's name shadows it, matching codegen's own
/// slot-reuse for that case); `fn_return_types` is this function's library,
/// scoped by `collect_lib_function_return_types` so a same-named function in
/// a different library/version never leaks in.
pub(crate) fn infer_list_element_type(
    target: &str,
    param_types: &HashMap<String, Type>,
    fn_return_types: &HashMap<String, Type>,
    body: &[Statement],
) -> Type {
    let mut scalar_types = param_types.clone();
    scalar_types.extend(collect_declared_scalar_types(body));
    let mut found: Option<Type> = None;
    let mut conflict = false;
    scan_list_element_type(target, &scalar_types, fn_return_types, body, &mut found, &mut conflict);
    if conflict {
        Type::Unknown
    } else {
        found.unwrap_or(Type::Unknown)
    }
}

/// Collect every `Return <expr>.`'s value expression, recursing into
/// control-flow bodies the same way `scan_list_element_type` does — a
/// function may return from more than one branch.
fn scan_return_values<'a>(body: &'a [Statement], out: &mut Vec<&'a Expr>) {
    for stmt in body {
        match stmt {
            Statement::Return { value: Some(v), .. } => out.push(v),
            Statement::If {
                then_block,
                else_if_blocks,
                else_block,
                ..
            } => {
                scan_return_values(then_block, out);
                for (_, blk) in else_if_blocks {
                    scan_return_values(blk, out);
                }
                if let Some(blk) = else_block {
                    scan_return_values(blk, out);
                }
            }
            Statement::While { body, .. }
            | Statement::ForRange { body, .. }
            | Statement::ForEach { body, .. }
            | Statement::Repeat { body, .. } => {
                scan_return_values(body, out);
            }
            Statement::OnError { actions } => {
                scan_return_values(actions, out);
            }
            _ => {}
        }
    }
}

/// Infer a homogeneous element type for a function's returned list: every
/// `Return <list-literal>.` classifies its elements directly; every
/// `Return <identifier>.` re-runs the parameter/append scan for that name
/// (covering both `Return out.` for an appended-to parameter and a plain
/// local list built and returned in the same function, as in the plan's own
/// bare-return baseline). Anything else (a call result, disagreement across
/// several `Return`s) gives up, same as `infer_list_element_type`. See
/// `infer_list_element_type` for what `param_types`/`fn_return_types` cover.
pub(crate) fn infer_return_list_element_type(
    param_types: &HashMap<String, Type>,
    fn_return_types: &HashMap<String, Type>,
    body: &[Statement],
) -> Type {
    let mut returns = Vec::new();
    scan_return_values(body, &mut returns);
    let mut scalar_types = param_types.clone();
    scalar_types.extend(collect_declared_scalar_types(body));
    let mut found: Option<Type> = None;
    let mut conflict = false;
    for expr in returns {
        match expr {
            Expr::ListLit { elements } => {
                for e in elements {
                    note_element_type(
                        &mut found,
                        &mut conflict,
                        scalar_expr_type(e, &scalar_types, fn_return_types),
                    );
                }
            }
            Expr::Identifier(name) => {
                let mut sub_found: Option<Type> = None;
                let mut sub_conflict = false;
                scan_list_element_type(name, &scalar_types, fn_return_types, body, &mut sub_found, &mut sub_conflict);
                if sub_conflict {
                    conflict = true;
                } else {
                    note_element_type(&mut found, &mut conflict, sub_found);
                }
            }
            _ => conflict = true,
        }
    }
    if conflict {
        Type::Unknown
    } else {
        found.unwrap_or(Type::Unknown)
    }
}

/// Every function's declared return `Type`, scoped by the `(library,
/// version)` it's defined in. Built once, ahead of the per-function pass in
/// `collect_function_signatures`, so `scalar_expr_type`'s `FunctionCall` arm
/// can credit a call to a function defined LATER in source order than its
/// caller — Vox places no ordering requirement on function definitions, so a
/// single forward pass over the program would miss those. Scoped per library
/// identity (not a flat name -> Type map) so two libraries in one file
/// defining a same-named function with different return types can't leak
/// into each other's `.lib` inference.
pub(crate) fn collect_lib_function_return_types(program: &Program) -> HashMap<(String, String), HashMap<String, Type>> {
    let mut out: HashMap<(String, String), HashMap<String, Type>> = HashMap::new();
    let mut current_lib: Option<(String, String)> = None;
    for stmt in &program.statements {
        match stmt {
            Statement::LibraryDecl { name, version } => {
                current_lib = Some((name.clone(), version.clone()));
            }
            Statement::FunctionDef { name, return_type, .. } => {
                if let Some(lib) = &current_lib {
                    out.entry(lib.clone())
                        .or_default()
                        .insert(name.clone(), return_type.clone());
                }
            }
            _ => {}
        }
    }
    out
}

/// Map a `.lib`-declared list element `Type` to the `VarType` a for-each
/// loop variable / print site should use — mirrors the scalar mapping used
/// for a declared local's own `VarType` elsewhere in this module (`VarDecl`,
/// function parameters). `Value` maps to `Mixed`: a `list of value`
/// element genuinely carries its own runtime tag, so this routes it through
/// the SAME per-iteration tag-dispatch a heterogeneous list already uses.
/// `File`/`Time`/`Timer` fall through to `Unknown`, which already prints an
/// opaque handle as a plain integer — correct for all three. `list of
/// <type>` only ever names one of these nine scalar nouns (`take_list_type`
/// on the `.lib` side), so `List`/`Map` never reach here in practice.
pub(crate) fn list_element_vartype(t: &Type) -> VarType {
    match t {
        Type::Integer => VarType::Integer,
        Type::Float => VarType::Float,
        Type::String => VarType::String,
        Type::Boolean => VarType::Boolean,
        // Buffer content is a NUL-terminated pointer, printed exactly like
        // text (`type_to_tag`'s existing `VarType::String | VarType::Buffer
        // => TAG_STRING` rule).
        Type::Buffer => VarType::String,
        Type::Value => VarType::Mixed,
        _ => VarType::Unknown,
    }
}

/// Render the `.lib` text for `blocks` (one per library identity, in order)
/// whose `.so` is named `so_filename` (basename only — the `.lib` sits beside
/// it, so the `Location` is `./<so_filename>`, relative to the `.lib`). Each
/// table-of-contents entry is exactly one line, however long; entries are never
/// wrapped. A parameterless, void-returning function reads `To 'name'.`; a
/// `value` parameter or return needs only its type name (`a value called 'v'`,
/// `, returning a value`). Names are identifiers (bare or `'quoted'`); the
/// version and `Location` path remain `"string literals"` — they are data.
pub fn render_lib_file(blocks: &[LibBlock], so_filename: &str) -> String {
    let mut out = String::new();
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "Library {} version \"{}\".\n",
            format_lib_name(&block.lib),
            block.version
        ));
        out.push_str(&format!("Location \"./{}\".\n", so_filename));
        out.push_str("\nTable of Contents:\n");
        for func in &block.funcs {
            out.push_str("    To ");
            out.push_str(&format_lib_name(&func.name));
            if !func.params.is_empty() {
                out.push_str(" with ");
                let joined = func
                    .params
                    .iter()
                    .map(|(pname, ptype)| {
                        // An untyped (`Unknown`) parameter has no noun the `.lib`
                        // can express; render it as `number`, the 1-word scalar
                        // default an untyped parameter occupies (see
                        // `emit_function_call`'s `word_count`). Library authors
                        // should type their exports; see the A3 report for the
                        // caveat.
                        let noun = type_noun(ptype).unwrap_or_else(|| "number".to_string());
                        format!("a {} called {}", noun, format_lib_name(pname))
                    })
                    .collect::<Vec<_>>()
                    .join(" and ");
                out.push_str(&joined);
            }
            if let Some(rnoun) = type_noun(&func.return_type) {
                out.push_str(&format!(", returning a {}", rnoun));
            }
            out.push_str(".\n");
        }
    }
    out
}

/// Author-facing name for a type-predicate noun, for asm comments.
pub(crate) fn type_noun_name(t: &Type) -> &'static str {
    match t {
        Type::Integer => "number",
        Type::Float => "decimal",
        Type::String => "text",
        Type::Boolean => "boolean",
        Type::List(_) => "list",
        Type::Map(_) => "map",
        _ => "type",
    }
}

