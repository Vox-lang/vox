//! Layout of user-defined things (plan 310 §6 and §9): sizes, field offsets,
//! and the cycle check that keeps both finite.
//!
//! Everything here is a pure compile-time function over the thing registry -
//! there is no runtime component of any kind. A scalar field is one 8-byte
//! slot and a nested thing contributes its own size inline, so
//! `route's leg's start's x` is a sum of constants, never a pointer chase.
//!
//! These functions live in the analyzer (which validates a definition and
//! every field path against them) and are read by codegen, so both sides
//! compute one layout from one place: a size or offset that disagreed between
//! validation and emission would be a silently wrong load.

use super::*;

/// Every thing defined in a program, keyed by name. Built once from
/// `Program.things`, which the parser filled in definition order.
pub(crate) type ThingRegistry = HashMap<String, ThingDef>;

/// A scalar field occupies one fixed 8-byte slot, matching every other Vox
/// value: a number, a float's IEEE-754 bits, a boolean's 0/1, and a time's
/// epoch seconds all fit exactly, so no field needs padding or alignment
/// beyond what this gives it.
pub(crate) const SLOT_BYTES: u64 = 8;

/// Where a resolved field path lands: its byte offset from the base thing's
/// first byte, and the type stored there.
pub(crate) struct FieldRef {
    pub(crate) offset: u64,
    pub(crate) field_type: Type,
}

/// Why a field path did not resolve. The analyzer turns each of these into a
/// diagnostic; codegen never sees one, because a program with an unresolvable
/// path does not reach it.
pub(crate) enum FieldPathError {
    /// The path walks into a thing that is not in the registry. Unreachable
    /// through the parser (which only writes `Type::Thing` for a registered
    /// name), kept so the resolver is total rather than panicking.
    UnknownThing { thing: String },
    /// `<thing>` has no field `<field>`; `known` lists what it does have, in
    /// layout order, so the diagnostic can name the alternatives.
    UnknownField {
        thing: String,
        field: String,
        known: Vec<String>,
    },
    /// The path continues past a scalar field (`origin's x's y`): only a
    /// nested thing can be gone through.
    ThroughScalar {
        thing: String,
        field: String,
        field_type: Type,
        next: String,
    },
}

/// Size in bytes of one field: 8 for a scalar, the whole nested size for a
/// thing field.
fn field_size(defs: &ThingRegistry, field_type: &Type, stack: &mut Vec<String>) -> u64 {
    match field_type {
        Type::Thing(inner) => size_with(defs, inner, stack),
        _ => SLOT_BYTES,
    }
}

fn size_with(defs: &ThingRegistry, name: &str, stack: &mut Vec<String>) -> u64 {
    // A name already on the stack means a cycle, which has no finite size.
    // `validate_definitions` rejects those before anything asks for a size,
    // so returning 0 here is unreachable in a compiled program - but it is
    // what keeps this function total instead of recursing until the stack
    // dies, which is the failure mode a future forward-reference or
    // cross-file definition could otherwise reintroduce.
    if stack.iter().any(|n| n == name) {
        return 0;
    }
    let Some(def) = defs.get(name) else {
        return 0;
    };
    stack.push(name.to_string());
    let total = def
        .fields
        .iter()
        .map(|f| field_size(defs, &f.field_type, stack))
        .sum();
    stack.pop();
    total
}

/// Total size in bytes of a thing: the sum of its fields' sizes, with nested
/// things contributing their own size inline. Function members take no
/// storage (plan 310 §4), so they never appear in this sum.
pub(crate) fn thing_size(defs: &ThingRegistry, name: &str) -> u64 {
    size_with(defs, name, &mut Vec::new())
}

/// Resolve a possessive chain against the registry, returning the byte offset
/// of the field it names and the type stored there. An empty path names the
/// thing itself (offset 0).
pub(crate) fn resolve_field_path(
    defs: &ThingRegistry,
    thing: &str,
    path: &[String],
) -> Result<FieldRef, FieldPathError> {
    let mut current = thing.to_string();
    let mut offset = 0u64;
    let mut field_type = Type::Thing(thing.to_string());

    for (index, step) in path.iter().enumerate() {
        let def = defs.get(&current).ok_or_else(|| FieldPathError::UnknownThing {
            thing: current.clone(),
        })?;

        // Walk the fields in layout order, accumulating the offset of each
        // one we pass over. This is the only place layout order is turned
        // into an offset, so a field's position in the definition is the
        // single source of truth for where its bytes live.
        let mut cursor = 0u64;
        let mut found: Option<&FieldDef> = None;
        for field in &def.fields {
            if field.name == *step {
                found = Some(field);
                break;
            }
            cursor += field_size(defs, &field.field_type, &mut Vec::new());
        }
        let field = found.ok_or_else(|| FieldPathError::UnknownField {
            thing: current.clone(),
            field: step.clone(),
            known: def.fields.iter().map(|f| f.name.clone()).collect(),
        })?;

        offset += cursor;
        field_type = field.field_type.clone();

        if index + 1 < path.len() {
            match &field.field_type {
                Type::Thing(inner) => current = inner.clone(),
                other => {
                    return Err(FieldPathError::ThroughScalar {
                        thing: current.clone(),
                        field: step.clone(),
                        field_type: other.clone(),
                        next: path[index + 1].clone(),
                    })
                }
            }
        }
    }

    Ok(FieldRef { offset, field_type })
}

/// Byte offset of `path` within `thing`. Codegen's address arithmetic: call
/// it only for a path the analyzer has already accepted - an unresolvable
/// path is a compiler bug, and a made-up offset would emit a wrong load
/// rather than report one.
pub(crate) fn field_offset(defs: &ThingRegistry, thing: &str, path: &[String]) -> u64 {
    match resolve_field_path(defs, thing, path) {
        Ok(field) => field.offset,
        Err(_) => panic!(
            "internal error: field path {:?} on thing '{}' reached codegen unresolved",
            path, thing
        ),
    }
}

/// Every scalar slot of `thing`, flattened through nesting in layout order,
/// as (byte offset, the field that owns the slot). This is what makes a
/// declaration's defaults apply recursively: a nested thing's fields
/// contribute their own defaults at their own base offset, with no special
/// case for depth.
pub(crate) fn scalar_slots(defs: &ThingRegistry, thing: &str) -> Vec<(u64, FieldDef)> {
    fn walk(
        defs: &ThingRegistry,
        name: &str,
        base: u64,
        stack: &mut Vec<String>,
        out: &mut Vec<(u64, FieldDef)>,
    ) {
        // Same cycle guard as `size_with`, for the same reason.
        if stack.iter().any(|n| n == name) {
            return;
        }
        let Some(def) = defs.get(name) else {
            return;
        };
        stack.push(name.to_string());
        let mut cursor = base;
        for field in &def.fields {
            match &field.field_type {
                Type::Thing(inner) => {
                    walk(defs, inner, cursor, stack, out);
                    cursor += size_with(defs, inner, &mut Vec::new());
                }
                _ => {
                    out.push((cursor, field.clone()));
                    cursor += SLOT_BYTES;
                }
            }
        }
        stack.pop();
    }

    let mut out = Vec::new();
    walk(defs, thing, 0, &mut Vec::new(), &mut out);
    out
}

/// The chain of thing names closing a cycle that starts at `name`, or None
/// when `name`'s nesting is finite. The returned chain begins and ends with
/// the same name, so a diagnostic can print it verbatim ("ouroboros contains
/// ouroboros").
pub(crate) fn find_cycle(defs: &ThingRegistry, name: &str) -> Option<Vec<String>> {
    fn walk(defs: &ThingRegistry, name: &str, stack: &mut Vec<String>) -> Option<Vec<String>> {
        if let Some(at) = stack.iter().position(|n| n == name) {
            let mut chain: Vec<String> = stack[at..].to_vec();
            chain.push(name.to_string());
            return Some(chain);
        }
        let def = defs.get(name)?;
        stack.push(name.to_string());
        for field in &def.fields {
            if let Type::Thing(inner) = &field.field_type {
                if let Some(chain) = walk(defs, inner, stack) {
                    return Some(chain);
                }
            }
        }
        stack.pop();
        None
    }

    walk(defs, name, &mut Vec::new())
}

/// Whether a field type is in the v1 set (plan 310 §6): number, float,
/// boolean, time, and any previously defined thing.
///
/// The excluded types are deferred by §6, not forgotten: `text` waits on the
/// handle-copy verification §6 asks for, and buffer/list/map (plus the
/// file/timer/value handles, which are the same reference-carrying shape)
/// reopen the aliasing question §5's value semantics deliberately avoid. A
/// field of one of those types would need eight bytes holding a pointer this
/// task cannot copy, print, or compare correctly, so a definition using one
/// is rejected rather than silently declared and read as garbage.
pub(crate) fn v1_field_type_supported(field_type: &Type) -> bool {
    matches!(
        field_type,
        Type::Integer | Type::Float | Type::Boolean | Type::Time | Type::Thing(_)
    )
}

/// Which thing each main-line thing variable holds, by variable name.
///
/// Function bodies are deliberately not entered: their declarations are that
/// frame's own locals, registered as the body is walked. Everything else -
/// including a declaration inside an if/while/for body - is main-line, the
/// same reach `collect_definite_decls` has, so a thing variable is known to
/// the whole walk regardless of where in the file its declaration sits.
pub(crate) fn collect_thing_vars(stmts: &[Statement]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    fn walk(stmts: &[Statement], out: &mut HashMap<String, String>) {
        for stmt in stmts {
            match stmt {
                Statement::VarDecl {
                    name,
                    var_type: Some(Type::Thing(thing)),
                    ..
                } => {
                    out.insert(name.clone(), thing.clone());
                }
                Statement::If {
                    then_block,
                    else_if_blocks,
                    else_block,
                    ..
                } => {
                    walk(then_block, out);
                    for (_, block) in else_if_blocks {
                        walk(block, out);
                    }
                    if let Some(block) = else_block {
                        walk(block, out);
                    }
                }
                Statement::While { body, .. }
                | Statement::ForRange { body, .. }
                | Statement::ForEach { body, .. }
                | Statement::Repeat { body, .. } => walk(body, out),
                Statement::OnError { actions } => walk(actions, out),
                _ => {}
            }
        }
    }
    walk(stmts, &mut out);
    out
}

/// A registry built from the program's definitions, in definition order.
pub(crate) fn registry(things: &[ThingDef]) -> ThingRegistry {
    things
        .iter()
        .map(|def| (def.name.clone(), def.clone()))
        .collect()
}

impl Analyzer {
    /// Load the program's definitions and validate them (plan 310 §6, §10),
    /// then seed the main line's thing variables. Runs before the statement
    /// walk, because a size or a field path can only be checked against a
    /// registry that is already complete.
    pub(crate) fn load_things(&mut self, program: &Program) {
        self.things = registry(&program.things);
        self.thing_vars = collect_thing_vars(&program.statements);

        for def in &program.things {
            // A cycle has no finite size, so it is reported before anything
            // asks for one. The parser's "defined earlier" rule means source
            // cannot express one today (a self-reference is an unknown type
            // where it is written, and a mutual pair needs one of the two to
            // be a forward reference), so this is the check that keeps that
            // true if definitions ever arrive from somewhere else - a `see`d
            // file, or a later task's forward references. One report is
            // enough: every thing on the chain would otherwise report it.
            if let Some(chain) = find_cycle(&self.things, &def.name) {
                if chain.first().map(String::as_str) == Some(def.name.as_str()) {
                    self.push_error(
                        format!(
                            "A thing cannot contain itself: {}\n  \
                             A thing's fields are stored inline, so this definition \
                             has no finite size.\n  \
                             Hold something that names the other thing instead, or \
                             split the shape in two.",
                            chain.join(" contains ")
                        ),
                        Some(&def.name),
                    );
                    break;
                }
            }

            for field in &def.fields {
                // A default is a literal (plan 310 §1), and it must be a
                // literal of the field's own type: the field's declared type
                // decides how its eight bytes are read, so a mismatch has no
                // honest representation - storing a float's bits in a number
                // field would read back as a huge number, and silently
                // dropping the default would ignore what the author wrote.
                // Rejecting is the reversible reading; §1 does not say which
                // literals a given field type accepts.
                if let Some(default) = &field.default {
                    if !default_matches_field_type(default, &field.field_type) {
                        self.push_error(
                            format!(
                                "Field '{}' of thing '{}' is a {}, but its default is a {}\n  \
                                 A field's default must be a literal of the field's own \
                                 type; a whole number is accepted for a float.",
                                field.name,
                                def.name,
                                self.type_name(&field.field_type),
                                literal_type_name(default)
                            ),
                            Some(&field.name),
                        );
                    }
                }

                if v1_field_type_supported(&field.field_type) {
                    continue;
                }
                self.push_error(
                    format!(
                        "Field '{}' of thing '{}' is a {}, which a thing cannot hold yet\n  \
                         A field's type may be number, float, boolean, time, or any thing \
                         defined earlier (plan 310 §6).\n  \
                         text is deferred until copying a text handle is verified not to \
                         observe mutation; buffer, list, map, file, timer, and value carry \
                         references, which value semantics (§5) deliberately keep out.",
                        field.name,
                        def.name,
                        self.type_name(&field.field_type)
                    ),
                    Some(&field.name),
                );
            }
        }
    }

    /// Which thing a variable holds, if it holds one.
    pub(crate) fn thing_of_variable(&self, name: &str) -> Option<String> {
        self.thing_vars.get(name).cloned()
    }

    /// Record a thing declaration as the walk reaches it, so a function's own
    /// local is known inside that function.
    pub(crate) fn declare_thing_variable(&mut self, name: &str, thing: &str) {
        self.thing_vars.insert(name.to_string(), thing.to_string());
    }

    /// Validate a field chain and return the type it lands on.
    ///
    /// The parser rejects an unresolvable chain as it consumes it (it has to:
    /// whether to keep consuming `'s` depends on the field it just read), so
    /// the paths that reach here are already well-formed. These checks are the
    /// analyzer's own guarantee about a shape it will hand to codegen, not a
    /// second opinion on the parse - codegen turns a path straight into an
    /// address, so nothing may reach it unvalidated.
    pub(crate) fn analyze_thing_field(&mut self, base: &str, path: &[String]) -> Option<Type> {
        self.track_identifier(base);
        if !self.is_variable_available(base) {
            self.push_unknown_variable(base);
            return None;
        }
        let Some(thing) = self.thing_of_variable(base) else {
            self.push_error(
                format!(
                    "'{}' is not a thing, so it has no fields\n  \
                     Only a variable declared as a thing can be read with a possessive.",
                    base
                ),
                Some(base),
            );
            return None;
        };

        match resolve_field_path(&self.things, &thing, path) {
            Ok(field) => match &field.field_type {
                Type::Thing(inner) => {
                    let known = self
                        .things
                        .get(inner)
                        .map(|def| {
                            def.fields
                                .iter()
                                .map(|f| f.name.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    self.push_error(
                        format!(
                            "'{}' holds a whole {}, not a value\n  \
                             Reading a whole thing lands with copy semantics (plan 310 \
                             §5) and printing (§7).\n  \
                             {}'s fields are: {}",
                            render_chain(base, path),
                            inner,
                            inner,
                            known
                        ),
                        Some(base),
                    );
                    None
                }
                scalar => Some(scalar.clone()),
            },
            Err(FieldPathError::UnknownField { thing, field, known }) => {
                self.push_error(
                    format!(
                        "Thing '{}' has no field '{}'\n  \
                         A thing's fields are its whole member space: its fields are: {}",
                        thing,
                        field,
                        known.join(", ")
                    ),
                    Some(base),
                );
                None
            }
            Err(FieldPathError::ThroughScalar {
                thing,
                field,
                field_type,
                next,
            }) => {
                self.push_error(
                    format!(
                        "Field '{}' of thing '{}' is a {}, so '{}' cannot be read out of it\n  \
                         Only a field that holds a thing can be gone through with another \
                         possessive.",
                        field,
                        thing,
                        self.type_name(&field_type),
                        next
                    ),
                    Some(base),
                );
                None
            }
            Err(FieldPathError::UnknownThing { thing }) => {
                self.push_error(format!("Unknown thing '{}'", thing), Some(base));
                None
            }
        }
    }

    /// Reject a statement that treats a whole thing as a single value: a bare
    /// assignment, an untyped `Set`, or an increment/decrement step. Each of
    /// those writes one quadword, which would land on the thing's first field
    /// and silently corrupt it - `Set origin's x to 5.` is what they mean.
    /// Returns true when the statement was rejected.
    pub(crate) fn reject_whole_thing_as_a_value(&mut self, name: &str) -> bool {
        if !self.is_variable_available(name) {
            return false;
        }
        let Some(thing) = self.thing_of_variable(name) else {
            return false;
        };
        self.push_whole_thing_not_a_value(name, &thing);
        true
    }

    /// The error for using a thing variable's bare name as a value. A thing
    /// has no single value: what that would mean is copying (§5) or printing
    /// (§7), both later tasks, so it is rejected rather than read as the first
    /// eight bytes of the thing's storage.
    pub(crate) fn push_whole_thing_not_a_value(&mut self, name: &str, thing: &str) {
        let known = self
            .things
            .get(thing)
            .map(|def| {
                def.fields
                    .iter()
                    .map(|f| f.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        self.push_error(
            format!(
                "'{}' holds a whole {}, not a value\n  \
                 Copying a whole thing lands with plan 310 §5 and printing with §7; \
                 name one of its fields for now.\n  \
                 its fields are: {}",
                name, thing, known
            ),
            Some(name),
        );
    }
}

/// Whether a field's literal default can be stored as the field's declared
/// type. A whole number is accepted for a float (`is 0` reads naturally for
/// one, and the widening is exact); everything else must match.
fn default_matches_field_type(default: &Expr, field_type: &Type) -> bool {
    matches!(
        (default, field_type),
        (Expr::IntegerLit(_), Type::Integer | Type::Float | Type::Time)
            | (Expr::FloatLit(_), Type::Float)
            | (Expr::BoolLit(_), Type::Boolean)
    )
}

/// What kind of literal this default is, for the mismatch diagnostic.
fn literal_type_name(default: &Expr) -> &'static str {
    match default {
        Expr::IntegerLit(_) => "number",
        Expr::FloatLit(_) => "float",
        Expr::BoolLit(_) => "boolean",
        Expr::StringLit(_) => "text",
        Expr::NothingLit => "nothing",
        // `parse_field_default` accepts only the literals above.
        _ => "value",
    }
}

/// `origin's leg's start` - a chain as written, for a diagnostic.
fn render_chain(base: &str, path: &[String]) -> String {
    let mut out = base.to_string();
    for step in path {
        out.push_str("'s ");
        out.push_str(step);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, field_type: Type) -> FieldDef {
        FieldDef {
            name: name.to_string(),
            field_type,
            default: None,
        }
    }

    fn def(name: &str, fields: Vec<FieldDef>) -> ThingDef {
        ThingDef {
            name: name.to_string(),
            fields,
            members: Vec::new(),
            line: 1,
        }
    }

    fn nested_registry() -> ThingRegistry {
        registry(&[
            def(
                "point",
                vec![field("x", Type::Integer), field("y", Type::Integer)],
            ),
            def(
                "segment",
                vec![
                    field("start", Type::Thing("point".into())),
                    field("end", Type::Thing("point".into())),
                ],
            ),
            def(
                "route",
                vec![
                    field("leg", Type::Thing("segment".into())),
                    field("id", Type::Integer),
                ],
            ),
        ])
    }

    #[test]
    fn a_nested_thing_contributes_its_own_size_inline() {
        let defs = nested_registry();
        assert_eq!(thing_size(&defs, "point"), 16);
        assert_eq!(thing_size(&defs, "segment"), 32);
        assert_eq!(thing_size(&defs, "route"), 40);
    }

    #[test]
    fn a_chain_composes_offsets() {
        let defs = nested_registry();
        let path: Vec<String> = ["leg", "end", "y"].iter().map(|s| s.to_string()).collect();
        // leg at 0, its `end` point at +16, that point's `y` at +8.
        assert_eq!(field_offset(&defs, "route", &path), 24);
        assert_eq!(
            field_offset(&defs, "route", &["id".to_string()]),
            32,
            "id sits after the whole nested segment"
        );
    }

    #[test]
    fn defaults_flatten_through_nesting_in_layout_order() {
        let defs = nested_registry();
        let slots = scalar_slots(&defs, "route");
        let offsets: Vec<u64> = slots.iter().map(|(off, _)| *off).collect();
        let names: Vec<&str> = slots.iter().map(|(_, f)| f.name.as_str()).collect();
        assert_eq!(offsets, vec![0, 8, 16, 24, 32]);
        assert_eq!(names, vec!["x", "y", "x", "y", "id"]);
    }

    #[test]
    fn an_unknown_field_names_what_the_thing_does_have() {
        let defs = nested_registry();
        match resolve_field_path(&defs, "point", &["z".to_string()]) {
            Err(FieldPathError::UnknownField { thing, field, known }) => {
                assert_eq!(thing, "point");
                assert_eq!(field, "z");
                assert_eq!(known, vec!["x".to_string(), "y".to_string()]);
            }
            _ => panic!("an unknown field should not resolve"),
        }
    }

    #[test]
    fn a_chain_cannot_continue_past_a_scalar() {
        let defs = nested_registry();
        let path: Vec<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(
            resolve_field_path(&defs, "point", &path),
            Err(FieldPathError::ThroughScalar { .. })
        ));
    }

    /// The DFS is the guarantee that every size is finite. The parser's
    /// "defined earlier" rule is what makes a cycle unreachable from Vox
    /// source today (a self-reference is an unknown type at the point it is
    /// written), so the check is exercised here against a registry built
    /// directly - which is also what a future forward-referencing or
    /// cross-file definition path would hand it.
    #[test]
    fn a_cycle_is_reported_as_the_chain_that_closes_it() {
        let direct = registry(&[def(
            "ouroboros",
            vec![field("tail", Type::Thing("ouroboros".into()))],
        )]);
        assert_eq!(
            find_cycle(&direct, "ouroboros"),
            Some(vec!["ouroboros".to_string(), "ouroboros".to_string()])
        );

        let indirect = registry(&[
            def("a", vec![field("b", Type::Thing("b".into()))]),
            def("b", vec![field("a", Type::Thing("a".into()))]),
        ]);
        assert_eq!(
            find_cycle(&indirect, "a"),
            Some(vec!["a".to_string(), "b".to_string(), "a".to_string()])
        );
        assert_eq!(find_cycle(&nested_registry(), "route"), None);
    }

    /// A cyclic registry must not hang or blow the stack even in the size and
    /// slot walks, which run before/independently of the cycle diagnostic.
    #[test]
    fn layout_walks_terminate_on_a_cyclic_registry() {
        let defs = registry(&[def(
            "ouroboros",
            vec![field("tail", Type::Thing("ouroboros".into()))],
        )]);
        assert_eq!(thing_size(&defs, "ouroboros"), 0);
        assert!(scalar_slots(&defs, "ouroboros").is_empty());
    }

    #[test]
    fn only_the_v1_field_types_are_supported() {
        for ok in [
            Type::Integer,
            Type::Float,
            Type::Boolean,
            Type::Time,
            Type::Thing("point".into()),
        ] {
            assert!(v1_field_type_supported(&ok), "{:?} is a v1 field", ok);
        }
        for deferred in [
            Type::String,
            Type::Buffer,
            Type::List(Box::new(Type::Unknown)),
            Type::Map(Box::new(Type::Unknown)),
            Type::File,
            Type::Timer,
            Type::Value,
        ] {
            assert!(
                !v1_field_type_supported(&deferred),
                "{:?} is deferred by §6",
                deferred
            );
        }
    }

    /// The registry travels on the `Program`, so it must be derived by
    /// `Program::new` rather than attached by one caller: the `--shared`
    /// driver builds a Program directly from the combined statements of every
    /// input and never goes through `Parser::parse`, which is how a
    /// multi-input build ended up with no things at all while every layout
    /// consumer silently agreed there were none.
    #[test]
    fn every_program_construction_path_derives_the_registry() {
        let program = Program::new(vec![
            Statement::ThingDecl(def("point", vec![field("x", Type::Integer)])),
            Statement::ThingDecl(def("segment", vec![field("start", Type::Thing("point".into()))])),
        ]);
        let names: Vec<&str> = program.things.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["point", "segment"],
            "things are carried in definition order, which is layout order"
        );
    }

    #[test]
    fn thing_variables_are_collected_from_every_main_line_position() {
        let decl = |name: &str, thing: &str| Statement::VarDecl {
            name: name.to_string(),
            var_type: Some(Type::Thing(thing.to_string())),
            value: None,
        };
        let stmts = vec![
            decl("origin", "point"),
            Statement::If {
                condition: Expr::BoolLit(true),
                then_block: vec![decl("branch", "point")],
                else_if_blocks: Vec::new(),
                else_block: None,
            },
            Statement::FunctionDef {
                name: "f".to_string(),
                params: Vec::new(),
                return_type: Type::Void,
                body: vec![decl("local", "point")],
                body_ended_early: None,
            },
        ];
        let vars = collect_thing_vars(&stmts);
        assert_eq!(vars.get("origin"), Some(&"point".to_string()));
        assert_eq!(vars.get("branch"), Some(&"point".to_string()));
        assert!(
            !vars.contains_key("local"),
            "a function's own local is not main-line"
        );
    }
}
