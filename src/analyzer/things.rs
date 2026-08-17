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
    // A name that reaches layout but is not in the registry is the exact
    // divergence that finding 01 rode: the size came back 0, a parameter of
    // the thing took frame offset 0, and the callee's store landed on the
    // saved base pointer. Every `Type::Thing` the parser writes names a thing
    // it registered, and `check_thing_registry` proves the program's registry
    // holds that same set, so there is no program that arrives here - which is
    // why this says "compiler bug" instead of laying out a 0-byte thing.
    let Some(def) = defs.get(name) else {
        panic!(
            "compiler bug: thing '{}' reached layout but is not in the \
             registry; a size of 0 would put its storage at frame offset 0, \
             which is the saved base pointer, not storage",
            name
        );
    };
    // Every thing has at least one data field (plan 310 §10, enforced at the
    // definition), so a definition with none is a registry that lost its
    // fields rather than a thing that legitimately occupies nothing - and a
    // zero-byte thing is exactly what puts storage at frame offset 0.
    assert!(
        !def.fields.is_empty(),
        "compiler bug: thing '{}' reached layout with no data fields; \
         a definition with nothing in it is rejected at the definition",
        name
    );
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

    /// Validate a field chain and return the type it lands on, which may be
    /// a nested thing: whether a whole thing is allowed here is the caller's
    /// question, not the chain's.
    ///
    /// The parser rejects an unresolvable chain as it consumes it (it has to:
    /// whether to keep consuming `'s` depends on the field it just read), so
    /// the paths that reach here are already well-formed. These checks are the
    /// analyzer's own guarantee about a shape it will hand to codegen, not a
    /// second opinion on the parse - codegen turns a path straight into an
    /// address, so nothing may reach it unvalidated.
    pub(crate) fn resolve_thing_field(&mut self, base: &str, path: &[String]) -> Option<Type> {
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
            Ok(field) => Some(field.field_type),
            Err(FieldPathError::UnknownField { thing, field, known }) => {
                self.push_error(
                    format!(
                        "Thing '{}' has no field '{}'\n  \
                         A possessive reads one of the thing's fields, or calls a \
                         function whose first parameter is a {} (plan 310 §4); its \
                         fields are: {}",
                        thing,
                        field,
                        thing,
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

    /// A field chain in value position: it must land on a field that holds a
    /// value, because a whole thing has no single value to read. Copying one
    /// goes through `analyze_thing_source` instead (plan 310 §5).
    pub(crate) fn analyze_thing_field(&mut self, base: &str, path: &[String]) -> Option<Type> {
        match self.resolve_thing_field(base, path)? {
            Type::Thing(inner) => {
                let chain = render_chain(base, path);
                self.push_whole_thing_not_a_value(&chain, base, &inner);
                None
            }
            scalar => Some(scalar),
        }
    }

    /// Analyze an expression written where a whole thing is wanted, and say
    /// which thing it names. Every branch analyzes what it looked at, so a
    /// copy site never analyzes the same expression twice (which would
    /// double-report an error inside it).
    pub(crate) fn analyze_thing_source(&mut self, value: &Expr) -> ThingSource {
        match value {
            Expr::Identifier(name) => {
                self.track_identifier(name);
                match self.thing_of_variable(name) {
                    Some(thing) if self.is_variable_available(name) => ThingSource::Whole(thing),
                    _ => {
                        self.analyze_expr(value);
                        ThingSource::NotAThing
                    }
                }
            }
            Expr::ThingField { base, path } => match self.resolve_thing_field(base, path) {
                Some(Type::Thing(inner)) => ThingSource::Whole(inner),
                Some(_) => ThingSource::NotAThing,
                None => ThingSource::Reported,
            },
            Expr::FunctionCall { name, args } => {
                self.deps.uses_funcs = true;
                self.check_function_call(name, args);
                self.analyze_call_arguments(name, args);
                match self.thing_returned_by(name) {
                    Some(thing) => ThingSource::Whole(thing),
                    None => ThingSource::NotAThing,
                }
            }
            other => {
                self.analyze_expr(other);
                ThingSource::NotAThing
            }
        }
    }

    /// Check a whole-thing copy into `target`, which holds `thing`, and
    /// report a source that is a different thing or no thing at all (plan
    /// 310 §5). `target` is the destination as the author wrote it, so the
    /// message names `moved` or `span's start` rather than a slot; `symbol`
    /// is the word in the source the caret lands on.
    pub(crate) fn check_thing_copy(
        &mut self,
        target: &str,
        symbol: &str,
        thing: &str,
        value: &Expr,
    ) {
        match self.analyze_thing_source(value) {
            ThingSource::Whole(source) if source == thing => {}
            ThingSource::Whole(source) => {
                self.push_error(
                    format!(
                        "'{}' holds a {}, but this copies a {}\n  \
                         Both sides of a copy are the same thing (plan 310 §5); \
                         a {} and a {} are different shapes.",
                        target, thing, source, thing, source
                    ),
                    Some(symbol),
                );
            }
            ThingSource::NotAThing => {
                self.push_error(
                    format!(
                        "'{}' holds a whole {}, so only a whole {} can be copied into it\n  \
                         A copy source is a variable holding a {}, a field that holds \
                         one, or a call that returns one (plan 310 §5).\n  \
                         To write one field instead, name it - {}'s fields are: {}",
                        target,
                        thing,
                        thing,
                        thing,
                        thing,
                        self.fields_of(thing)
                    ),
                    Some(symbol),
                );
            }
            ThingSource::Reported => {}
        }
    }

    /// Which thing a call to `name` returns, if it returns one.
    pub(crate) fn thing_returned_by(&self, name: &str) -> Option<String> {
        match self.function_return_type(name) {
            Some(Type::Thing(thing)) => Some(thing),
            _ => None,
        }
    }

    /// Which thing an expression names as a whole one, asked without
    /// analyzing or reporting anything.
    ///
    /// A print position and a comparison both have to know this *before* they
    /// choose which check to run, and asking must not itself be the error the
    /// answer decides against. A call is deliberately not one of these: what a
    /// call returns is a copy source, not a place, so it is still copied into
    /// a variable first (§5).
    pub(crate) fn whole_thing_named(&self, value: &Expr) -> Option<String> {
        match value {
            Expr::Identifier(name) if self.is_variable_available(name) => {
                self.thing_of_variable(name)
            }
            Expr::ThingField { base, path } => {
                let thing = self.thing_of_variable(base)?;
                match resolve_field_path(&self.things, &thing, path) {
                    Ok(FieldRef {
                        field_type: Type::Thing(inner),
                        ..
                    }) => Some(inner),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Analyze an expression in a position that accepts a whole thing: a
    /// print, or an interpolation inside one (plan 310 §7). A whole thing is
    /// validated as a thing, so the "not a value" rule that governs every
    /// other position does not apply here; anything else is an ordinary value.
    pub(crate) fn analyze_printed_expr(&mut self, value: &Expr) {
        if self.whole_thing_named(value).is_some() {
            self.analyze_thing_source(value);
        } else {
            self.analyze_expr(value);
        }
    }

    /// Check a comparison that has a whole thing on either side (plan 310 §8),
    /// and say whether it was handled here. Returning true means both operands
    /// have been analyzed and any error reported, so the caller skips the
    /// ordinary walk - which would report a whole thing as "not a value" and
    /// bury the real message under it.
    pub(crate) fn check_thing_comparison(
        &mut self,
        left: &Expr,
        op: &BinaryOperator,
        right: &Expr,
    ) -> bool {
        let equality = matches!(op, BinaryOperator::Equal | BinaryOperator::NotEqual);
        let ordering = matches!(
            op,
            BinaryOperator::Greater
                | BinaryOperator::Less
                | BinaryOperator::GreaterEqual
                | BinaryOperator::LessEqual
        );
        if !equality && !ordering {
            return false;
        }
        let left_thing = self.whole_thing_named(left);
        let right_thing = self.whole_thing_named(right);
        if left_thing.is_none() && right_thing.is_none() {
            return false;
        }

        let reported_before = self.errors.len();
        self.analyze_printed_expr(left);
        self.analyze_printed_expr(right);
        if self.errors.len() > reported_before {
            // An operand named its own problem - a misspelled variable, a
            // field that does not exist. Whatever it turned out not to be is
            // that message's business; a second, vaguer one about the
            // comparison would only bury it.
            return true;
        }

        // Whichever side is the thing carries the diagnostic: it is the
        // operand that made this comparison different from an ordinary one.
        let (thing_side, thing) = match (&left_thing, &right_thing) {
            (Some(thing), _) => (left, thing.clone()),
            (None, Some(thing)) => (right, thing.clone()),
            (None, None) => unreachable!("one side is a thing"),
        };

        if ordering {
            self.push_thing_has_no_order(thing_side, &thing);
            return true;
        }
        match (&left_thing, &right_thing) {
            // The feature: the same thing on both sides, compared field by
            // field and recursing through whatever those fields nest.
            (Some(left_thing), Some(right_thing)) if left_thing == right_thing => {}
            (Some(left_thing), Some(right_thing)) => {
                self.push_error(
                    format!(
                        "'{}' holds a {} and '{}' holds a {}, so they cannot be compared\n  \
                         `is` between two things compares them field by field (plan 310 §8), \
                         and only two of the same thing have the same fields.",
                        render_thing_operand(left),
                        left_thing,
                        render_thing_operand(right),
                        right_thing
                    ),
                    Some(thing_operand_symbol(left)),
                );
            }
            // A whole thing has no single value to hold up against one,
            // whatever the other side turned out to be - unless that side is
            // a name nothing resolved, which has already been reported as the
            // unknown variable it is (and reported only once, so the operand
            // walk above stayed silent about it).
            _ if self.is_unresolved_name(left) || self.is_unresolved_name(right) => {}
            _ => {
                self.push_error(
                    format!(
                        "'{}' holds a whole {}, so it cannot be compared with a single value\n  \
                         `is` between two things compares them field by field (plan 310 §8); \
                         a whole {} and one value have no fields in common.\n  \
                         Compare a field instead - {}'s fields are: {}",
                        render_thing_operand(thing_side),
                        thing,
                        thing,
                        thing,
                        self.fields_of(&thing)
                    ),
                    Some(thing_operand_symbol(thing_side)),
                );
            }
        }
        true
    }

    /// Whether an operand is a name the walk could not resolve to anything.
    /// A comparison against one is not really a comparison against a value;
    /// the unknown-variable message is the true one, and a mismatch stacked
    /// on top would describe the consequence rather than the cause.
    fn is_unresolved_name(&self, value: &Expr) -> bool {
        match value {
            Expr::Identifier(name) => {
                !self.is_variable_available(name) && self.function_return_type(name).is_none()
            }
            Expr::ThingField { base, .. } => !self.is_variable_available(base),
            _ => false,
        }
    }

    /// `origin is greater than marker.` - things are compared for equality
    /// only (plan 310 §8). Nothing orders one shape against another, and
    /// comparing their first eight bytes would answer a question nobody asked.
    fn push_thing_has_no_order(&mut self, operand: &Expr, thing: &str) {
        self.push_error(
            format!(
                "'{}' holds a whole {}, which nothing puts in order\n  \
                 Two things are compared for equality only (plan 310 §8): `is` compares \
                 them field by field, and no rule makes one whole {} greater than another.\n  \
                 Compare a field instead - {}'s fields are: {}",
                render_thing_operand(operand),
                thing,
                thing,
                thing,
                self.fields_of(thing)
            ),
            Some(thing_operand_symbol(operand)),
        );
    }

    /// `a text called note is "at {origin}".` - a whole thing renders as its
    /// fields (plan 310 §7), which `Print` writes straight out; building text
    /// from one would have to append those fields into a buffer, which is not
    /// written. Rejected rather than interpolated as the first eight bytes of
    /// the thing's storage.
    pub(crate) fn push_whole_thing_not_interpolable(&mut self, name: &str, thing: &str) {
        self.push_error(
            format!(
                "'{}' holds a whole {}, which only `Print` can interpolate\n  \
                 A whole thing renders as its fields (plan 310 §7) and `Print` writes \
                 that straight out; building text from one is not written yet.\n  \
                 Interpolate a field instead - {}'s fields are: {}",
                name,
                thing,
                thing,
                self.fields_of(thing)
            ),
            Some(name),
        );
    }

    /// Reject a statement that treats a whole thing as a single value: an
    /// increment or decrement step. Stepping a thing would `inc qword` its
    /// first field; `increment origin's x.` is what it means. Returns true
    /// when the statement was rejected.
    pub(crate) fn reject_whole_thing_as_a_value(&mut self, name: &str) -> bool {
        if !self.is_variable_available(name) {
            return false;
        }
        let Some(thing) = self.thing_of_variable(name) else {
            return false;
        };
        self.push_whole_thing_not_a_value(name, name, &thing);
        true
    }

    /// The error for using a whole thing where a value is wanted - a step, an
    /// arithmetic operand, a list element, a type predicate, a `Set` with
    /// nothing to store. A thing has no single value: it is copied, passed,
    /// and returned whole (§5), printed as its fields (§7), and compared field
    /// by field (§8), and every one of those reads all of it. Rejected rather
    /// than read as the first eight bytes of its storage.
    pub(crate) fn push_whole_thing_not_a_value(
        &mut self,
        name: &str,
        symbol: &str,
        thing: &str,
    ) {
        self.push_error(
            format!(
                "'{}' holds a whole {}, not a value\n  \
                 A whole thing is copied, passed, and returned whole (plan 310 §5), \
                 printed as its fields (§7), and compared field by field (§8); \
                 no other position reads it as one value.\n  \
                 its fields are: {}",
                name,
                thing,
                self.fields_of(thing)
            ),
            Some(symbol),
        );
    }

    /// A thing's fields in layout order, for the diagnostics that offer them
    /// as what to name instead of the whole shape.
    fn fields_of(&self, thing: &str) -> String {
        self.things
            .get(thing)
            .map(|def| {
                def.fields
                    .iter()
                    .map(|f| f.name.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    }
}

/// What an expression written where a whole thing is wanted turned out to
/// be. `Reported` keeps a copy site from stacking a second, vaguer message
/// on top of a precise one (an unknown variable, a misspelled field).
pub(crate) enum ThingSource {
    /// A whole thing of this type.
    Whole(String),
    /// Analyzed, and not a whole thing: the copy site names the mismatch.
    NotAThing,
    /// Analyzed, and already reported.
    Reported,
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

/// A whole-thing operand as the author wrote it - a bare name or a chain -
/// so a comparison's diagnostic names `span's start` rather than `span`.
fn render_thing_operand(value: &Expr) -> String {
    match value {
        Expr::ThingField { base, path } => render_chain(base, path),
        Expr::Identifier(name) => name.clone(),
        // Only the two forms `whole_thing_named` recognises reach here.
        _ => String::new(),
    }
}

/// The word in the source a whole-thing operand's caret lands on: the base
/// name, which is the one token a chain and a bare name share.
fn thing_operand_symbol(value: &Expr) -> &str {
    match value {
        Expr::ThingField { base, .. } => base,
        Expr::Identifier(name) => name,
        _ => "",
    }
}

/// `origin's leg's start` - a chain as written, for a diagnostic.
pub(crate) fn render_chain(base: &str, path: &[String]) -> String {
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

    /// A size of 0 for a thing that reached layout means the registry lost
    /// it, not that the thing is empty: layout would then put its storage at
    /// frame offset 0, which is the saved base pointer. The parser refuses
    /// every source that could ask for one, so this says "compiler bug"
    /// rather than answering.
    #[test]
    #[should_panic(expected = "compiler bug")]
    fn a_thing_missing_from_the_registry_is_not_laid_out_as_nothing() {
        let defs = nested_registry();
        thing_size(&defs, "ghost");
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
