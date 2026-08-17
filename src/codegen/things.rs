use super::*;
use crate::analyzer::things::{
    collect_thing_vars, field_offset, registry, resolve_field_path, scalar_slots, thing_size,
};

impl CodeGenerator {
    /// Load the thing registry and every main-line thing declaration, before
    /// anything asks for a size (plan 310 §9). The label pass needs this: a
    /// thing global's `.bss` reservation is sized from its definition, and a
    /// function generated before the declaration's own statement must still
    /// resolve `origin's x` against it - exactly like any other global.
    ///
    /// A function's own thing locals are deliberately not collected here; they
    /// are registered as their declaration is generated, and dropped again with
    /// the rest of that function's tables.
    pub(crate) fn collect_things(&mut self, program: &Program) {
        self.things = registry(&program.things);
        self.thing_vars = collect_thing_vars(&program.statements);
    }

    /// Which thing a variable holds, if it holds one.
    pub(crate) fn thing_of_variable(&self, name: &str) -> Option<String> {
        self.thing_vars.get(name).cloned()
    }

    /// Size in bytes to reserve for a thing variable's global label, or None
    /// for a name that is not a thing variable (which gets the ordinary
    /// one-quadword slot).
    pub(crate) fn thing_global_size(&self, name: &str) -> Option<u64> {
        let thing = self.thing_of_variable(name)?;
        Some(thing_size(&self.things, &thing))
    }

    /// The assembly memory operand for one field of a thing variable: this
    /// frame's stack region for a local, the `.bss` reservation for a global.
    /// Both are `base + constant`, the whole of what a possessive chain costs.
    fn thing_field_operand(&self, base: &str, path: &[String]) -> Option<String> {
        let thing = self.thing_of_variable(base)?;
        let offset = field_offset(&self.things, &thing, path) as i64;
        // Local first, then the global mirror - the same resolution order as
        // every other read, so a function-local thing shadows a global of the
        // same name.
        if let Some(slot) = self.get_var(base) {
            // A local thing's storage runs upward from `[rbp-slot]`, so the
            // field's own address is that much less deep in the frame.
            return Some(format!("[rbp-{}]", slot - offset));
        }
        let label = self.global_var_label(base)?;
        if offset == 0 {
            Some(format!("[rel {}]", label))
        } else {
            Some(format!("[rel {}+{}]", label, offset))
        }
    }

    /// The declared type stored at the end of a field chain, for the type
    /// dispatches (float printing, format specs, slot tags) that ask what an
    /// expression yields.
    pub(crate) fn thing_field_type(&self, base: &str, path: &[String]) -> Option<Type> {
        let thing = self.thing_of_variable(base)?;
        resolve_field_path(&self.things, &thing, path)
            .ok()
            .map(|field| field.field_type)
    }

    /// `a point called origin.` - reserve the thing's storage and write every
    /// field's default into it, nested things included (plan 310 §1, §9).
    pub(crate) fn generate_thing_decl(&mut self, name: &str, thing: &str) {
        let size = thing_size(&self.things, thing);
        self.thing_vars.insert(name.to_string(), thing.to_string());
        self.declared_types
            .insert(name.to_string(), Type::Thing(thing.to_string()));

        // A main-line declaration lives in `.bss` (its label reserves the
        // whole size, so the label IS the storage); anything else - inside a
        // function, or a branch-only declaration with no mirror - takes a
        // stack region in this frame. A typed declaration inside a function
        // shadows a global of the same name, matching every other declaration.
        let global = self.global_var_label(name).is_some() && !self.in_function_codegen;
        if !global {
            self.stack_offset += size as i64;
            self.variables.insert(name.to_string(), self.stack_offset);
        }

        self.emit_indent(&format!(
            "; {} is a {} ({} bytes{})",
            name,
            thing,
            size,
            if global { " in .bss" } else { " on the stack" }
        ));
        // Defaults are written slot by slot rather than by clearing the region
        // first: every scalar slot is accounted for here, so a field with no
        // default gets its type's zero from the same store as one that has a
        // default. `.bss` is already zero, but a stack region is not, and one
        // path for both is what keeps them agreeing.
        for (offset, field) in scalar_slots(&self.things, thing) {
            let Some(operand) = self.thing_field_operand_at(name, offset) else {
                continue;
            };
            let (bits, rendered) = default_bits(&field);
            self.emit_indent(&format!("mov rax, {}", bits));
            self.emit_indent(&format!(
                "mov qword {}, rax  ; {}'s {} is {}",
                operand, name, field.name, rendered
            ));
            if matches!(field.field_type, Type::Float) {
                self.uses_floats = true;
            }
        }
    }

    /// The memory operand for a byte offset into a thing variable, used by the
    /// declaration's default stores (which walk offsets, not paths).
    fn thing_field_operand_at(&self, base: &str, offset: u64) -> Option<String> {
        if let Some(slot) = self.get_var(base) {
            return Some(format!("[rbp-{}]", slot - offset as i64));
        }
        let label = self.global_var_label(base)?;
        if offset == 0 {
            Some(format!("[rel {}]", label))
        } else {
            Some(format!("[rel {}+{}]", label, offset))
        }
    }

    /// `origin's x` - one load from a compile-time address into rax. A float
    /// field arrives as its bit pattern, exactly like a float variable's slot.
    pub(crate) fn generate_thing_field(&mut self, base: &str, path: &[String]) {
        if let Some(operand) = self.thing_field_operand(base, path) {
            if matches!(self.thing_field_type(base, path), Some(Type::Float)) {
                self.uses_floats = true;
            }
            self.emit_indent(&format!(
                "mov rax, {}  ; {}",
                operand,
                render_chain(base, path)
            ));
        }
        // else: the analyzer rejected this chain, and a rejected program never
        // reaches codegen.
    }

    /// `Set origin's x to 3.` - evaluate the value, then one store to a
    /// compile-time address. There is no reallocation and no error path: the
    /// address cannot change and cannot fail (plan 310 §3).
    pub(crate) fn generate_set_thing_field(&mut self, base: &str, path: &[String], value: &Expr) {
        self.generate_expr(value);
        if let Some(operand) = self.thing_field_operand(base, path) {
            if matches!(self.thing_field_type(base, path), Some(Type::Float)) {
                self.uses_floats = true;
            }
            self.emit_indent(&format!(
                "mov qword {}, rax  ; {} is now this value",
                operand,
                render_chain(base, path)
            ));
        }
    }
}

/// The bytes a field's declared default occupies, and how to spell it in the
/// emitted comment. A field with no default takes its type's zero.
///
/// A whole-number literal in a float field is widened here (`is 0` reads
/// naturally for a float), which is the only conversion: the analyzer rejects
/// any other mismatch between a default and its field's type, so nothing else
/// arrives needing a guess about what the author meant.
fn default_bits(field: &FieldDef) -> (String, String) {
    match (&field.default, &field.field_type) {
        (Some(Expr::FloatLit(value)), _) => (
            format!("0x{:016X}", value.to_bits()),
            format!("{:?}", value),
        ),
        (Some(Expr::IntegerLit(value)), Type::Float) => {
            let widened = *value as f64;
            (
                format!("0x{:016X}", widened.to_bits()),
                format!("{:?}", widened),
            )
        }
        (Some(Expr::IntegerLit(value)), _) => (value.to_string(), value.to_string()),
        (Some(Expr::BoolLit(value)), _) => (
            if *value { "1".to_string() } else { "0".to_string() },
            value.to_string(),
        ),
        // No default, or a literal the analyzer has already rejected for this
        // field's type: the type's zero.
        _ => ("0".to_string(), "0".to_string()),
    }
}

/// `origin's leg's start` - a chain as written, for the emitted comment.
fn render_chain(base: &str, path: &[String]) -> String {
    let mut out = base.to_string();
    for step in path {
        out.push_str("'s ");
        out.push_str(step);
    }
    out
}
