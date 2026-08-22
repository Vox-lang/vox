use super::*;
use crate::analyzer::things::{
    collect_thing_vars, field_offset, registry, resolve_field_path, scalar_slots, thing_size,
    SLOT_BYTES,
};

/// How many 8-byte slots a copy unrolls before it is worth the string move
/// instead. Eight covers every shape written by hand so far (a point is two,
/// a route is five); past that the two-instruction `rep movsq` is shorter
/// than the moves it replaces.
const UNROLLED_COPY_SLOTS: u64 = 8;

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

    /// Size in bytes of a thing, for the storage a frame reserves.
    pub(crate) fn thing_storage_size(&self, thing: &str) -> u64 {
        thing_size(&self.things, thing)
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

    /// `a point called origin.` - reserve the thing's storage and fill it: an
    /// initialiser copies a whole thing into it (plan 310 §5), and without one
    /// every field takes its declared default, nested things included (§1, §9).
    pub(crate) fn generate_thing_decl(&mut self, name: &str, thing: &str, value: Option<&Expr>) {
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

        // An initialiser overwrites every byte the defaults would have
        // written, so writing them first would be dead work.
        if let Some(source) = value {
            self.generate_thing_assignment(name, thing, source);
            return;
        }

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

    /// `moved is origin.` - copy a whole thing into a thing variable's own
    /// storage (plan 310 §5).
    pub(crate) fn generate_thing_assignment(&mut self, name: &str, thing: &str, source: &Expr) {
        let Some(destination) = self.thing_field_operand_at(name, 0) else {
            return;
        };
        self.emit_thing_copy_into(&destination, thing, source, name);
    }

    /// Which thing a variable holds when the statement being generated is a
    /// bare assignment to it, rather than a declaration.
    pub(crate) fn thing_assigned_to(&self, name: &str) -> Option<String> {
        self.thing_of_variable(name)
    }

    /// Which thing a call to `name` returns, if it returns one. Read from the
    /// same signature table the call itself resolves through, so the caller's
    /// hidden destination word and the callee's slot always agree.
    pub(crate) fn thing_returned_by_call(&self, name: &str) -> Option<String> {
        match self
            .function_return_full_types
            .get(&self.resolved_call_label(name))
        {
            Some(Type::Thing(thing)) => Some(thing.clone()),
            _ => None,
        }
    }

    /// Leave the address of a whole thing in rax, and say which thing it is.
    /// This is the one rule behind every copy: a thing-valued expression
    /// yields where its bytes are, never the bytes themselves. Returns None
    /// for an expression that names no thing, which a rejected program never
    /// reaches codegen with.
    pub(crate) fn emit_thing_address(&mut self, value: &Expr) -> Option<String> {
        match value {
            Expr::Identifier(name) => {
                let thing = self.thing_of_variable(name)?;
                let operand = self.thing_field_operand_at(name, 0)?;
                self.emit_indent(&format!("lea rax, {}  ; {}", operand, name));
                Some(thing)
            }
            Expr::ThingField { base, path } => {
                let Some(Type::Thing(inner)) = self.thing_field_type(base, path) else {
                    return None;
                };
                let operand = self.thing_field_operand(base, path)?;
                self.emit_indent(&format!(
                    "lea rax, {}  ; {}",
                    operand,
                    render_chain(base, path)
                ));
                Some(inner)
            }
            // A call writes its result into a slot this call site owns and
            // hands the address back, so the result is already a thing
            // address like any other.
            Expr::FunctionCall { name, args } => {
                let thing = self.thing_returned_by_call(name)?;
                self.uses_funcs = true;
                self.emit_function_call(name, args);
                Some(thing)
            }
            _ => None,
        }
    }

    /// Copy a whole thing into `destination`, an assembly memory operand.
    /// The source's address is computed first because computing it may be a
    /// whole call; the destination is always `rbp`- or RIP-relative, so
    /// nothing the source does can disturb it.
    pub(crate) fn emit_thing_copy_into(
        &mut self,
        destination: &str,
        thing: &str,
        source: &Expr,
        what: &str,
    ) {
        // A source naming no thing means the analyzer rejected this program,
        // and a rejected program never reaches codegen.
        if self.emit_thing_address(source).is_none() {
            return;
        }
        self.emit_indent("mov rsi, rax  ; the thing being copied");
        self.emit_indent(&format!("lea rdi, {}", destination));
        self.emit_thing_copy(thing_size(&self.things, thing), what);
    }

    /// Copy `size` bytes from the address in rsi to the address in rdi.
    ///
    /// Every field is a whole 8-byte slot and a nested thing is a sum of
    /// them, so a thing's size is always a whole number of quadwords and the
    /// copy never has a tail. There is no runtime call and no allocation:
    /// the size is a compile-time constant, which is exactly what makes
    /// value semantics cheap (plan 310 §5).
    pub(crate) fn emit_thing_copy(&mut self, size: u64, what: &str) {
        let slots = size / SLOT_BYTES;
        self.emit_indent(&format!("; copy {} ({} bytes)", what, size));
        if slots <= UNROLLED_COPY_SLOTS {
            for slot in 0..slots {
                let at = slot * SLOT_BYTES;
                self.emit_indent(&format!("mov rax, [rsi+{}]", at));
                self.emit_indent(&format!("mov [rdi+{}], rax", at));
            }
            return;
        }
        // `rep movsq` needs the direction flag clear, which the System V ABI
        // guarantees on entry and at every call - the same assumption the
        // runtime's own `rep movsb` copies make.
        self.emit_indent(&format!("mov rcx, {}", slots));
        self.emit_indent("rep movsq");
    }

    /// Where a whole-thing expression's bytes are, and which thing they hold.
    /// Both printing and equality address the same fields the same way, so
    /// they resolve the expression once, here, and then ask the place for an
    /// operand per field.
    ///
    /// A call is deliberately not one of these: it hands back an address, not
    /// a place, and the analyzer keeps one out of these positions (plan 310
    /// §5 - what a call returns is copied into a variable first).
    pub(crate) fn thing_place(&self, value: &Expr) -> Option<(String, ThingPlace)> {
        let (thing, base, offset) = match value {
            Expr::Identifier(name) => (self.thing_of_variable(name)?, name, 0u64),
            Expr::ThingField { path, base } => {
                let Some(Type::Thing(inner)) = self.thing_field_type(base, path) else {
                    return None;
                };
                let thing = self.thing_of_variable(base)?;
                (inner, base, field_offset(&self.things, &thing, path))
            }
            _ => return None,
        };
        // Local first, then the global mirror - the same resolution order as
        // every other read.
        if let Some(slot) = self.get_var(base) {
            // A local thing's storage runs upward from `[rbp-slot]`, so a
            // field deeper into it is that much less deep in the frame.
            return Some((thing, ThingPlace::Frame(slot - offset as i64)));
        }
        let label = self.global_var_label(base)?.clone();
        Some((thing, ThingPlace::Reserved { label, base: offset }))
    }

    /// `Print origin.` - `{x: 5, y: 0}`: the thing's fields in definition
    /// order, recursing into the things they hold (plan 310 §7).
    ///
    /// Every field name is a literal in the emitted program and every field's
    /// address is a compile-time constant, so the recursion happens here, in
    /// the compiler. Nothing is read from a descriptor at runtime and nothing
    /// is allocated. Function members never appear: they are the type's
    /// manifest, held apart from `fields` precisely because they take no
    /// storage and are not state (§4).
    pub(crate) fn emit_thing_print(&mut self, thing: &str, place: &ThingPlace, base: u64) {
        let Some(def) = self.things.get(thing).cloned() else {
            return;
        };
        self.emit_print_literal("{");
        let mut at = base;
        for (index, field) in def.fields.iter().enumerate() {
            if index > 0 {
                self.emit_print_literal(", ");
            }
            self.emit_print_literal(&format!("{}: ", render_field_name(&field.name)));
            match &field.field_type {
                Type::Thing(inner) => {
                    self.emit_thing_print(inner, place, at);
                    at += thing_size(&self.things, inner);
                }
                field_type => {
                    let operand = place.operand(at);
                    self.emit_indent(&format!(
                        "mov rdi, qword {}  ; {}'s {}",
                        operand, thing, field.name
                    ));
                    if matches!(field_type, Type::Float) {
                        self.emit_indent("movq xmm0, rdi");
                        self.emit_indent("PRINT_FLOAT");
                        self.uses_floats = true;
                    } else {
                        self.emit_indent("PRINT_INT rdi");
                    }
                    at += SLOT_BYTES;
                }
            }
        }
        self.emit_print_literal("}");
    }

    /// `origin is marker` - 1 or 0 in rax, from comparing the two things one
    /// field at a time (plan 310 §8).
    ///
    /// `scalar_slots` already flattens a thing's nesting into its slots in
    /// layout order, so the recursion §8 asks for is the same walk a copy and
    /// a set of defaults make - depth costs nothing extra here. A float slot
    /// is compared as a float rather than as its bits, so `is` between two
    /// things says exactly what `is` between the two fields says: -0.0 equals
    /// 0.0, and a NaN equals nothing, including itself.
    pub(crate) fn emit_thing_equality(&mut self, left: &Expr, right: &Expr, negated: bool) {
        let (Some((thing, left_place)), Some((_, right_place))) =
            (self.thing_place(left), self.thing_place(right))
        else {
            // Both sides name a place, or the analyzer rejected this program,
            // and a rejected program never reaches codegen.
            return;
        };
        let differs = self.new_label("things_differ");
        let done = self.new_label("things_compared");

        for (offset, field) in scalar_slots(&self.things, &thing) {
            let left_operand = left_place.operand(offset);
            let right_operand = right_place.operand(offset);
            self.emit_indent(&format!("mov rax, qword {}  ; {}", left_operand, field.name));
            if matches!(field.field_type, Type::Float) {
                self.uses_floats = true;
                self.emit_indent("movq xmm0, rax");
                self.emit_indent(&format!("mov rax, qword {}", right_operand));
                self.emit_indent("movq xmm1, rax");
                self.emit_indent("FLOAT_EQ");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}", differs));
            } else {
                self.emit_indent(&format!("cmp rax, qword {}", right_operand));
                self.emit_indent(&format!("jne {}", differs));
            }
        }

        self.emit_indent("mov rax, 1  ; every field matched");
        self.emit_indent(&format!("jmp {}", done));
        self.emit(&format!("{}:", differs));
        self.emit_indent("xor rax, rax  ; a field differed");
        self.emit(&format!("{}:", done));
        if negated {
            self.emit_indent("xor rax, 1  ; 1=equal -> 0=not equal");
        }
    }

    /// Which thing both sides of a comparison hold, when both hold the same
    /// one. The analyzer has already rejected every other pairing (plan 310
    /// §8), so this is codegen asking which emission to make, not a check.
    pub(crate) fn thing_compared(&self, left: &Expr, right: &Expr) -> Option<String> {
        let (left_thing, _) = self.thing_place(left)?;
        let (right_thing, _) = self.thing_place(right)?;
        (left_thing == right_thing).then_some(left_thing)
    }

    /// One run of fixed bytes on its way to stdout - a brace, a separator, or
    /// a field's name. Each is a string constant in the emitted program.
    fn emit_print_literal(&mut self, text: &str) {
        let label = self.add_string(text);
        self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
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
        // A chain ending on a nested thing names the whole thing, so the
        // write is a copy of every one of its bytes (plan 310 §5).
        if let Some(Type::Thing(inner)) = self.thing_field_type(base, path) {
            let Some(destination) = self.thing_field_operand(base, path) else {
                return;
            };
            let what = render_chain(base, path);
            self.emit_thing_copy_into(&destination, &inner, value, &what);
            return;
        }
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

/// Where a whole thing's bytes are, as something that can name any byte
/// offset inside them. Both forms are `base + constant`, which is the whole
/// of what addressing a field costs (plan 310 §6).
pub(crate) enum ThingPlace {
    /// This frame's storage: the thing's first byte is at `[rbp-slot]`, and
    /// its bytes run upward from there.
    Frame(i64),
    /// A `.bss` reservation: the thing's first byte is `base` into `label`.
    Reserved { label: String, base: u64 },
}

impl ThingPlace {
    /// The assembly memory operand for one byte offset into the thing.
    fn operand(&self, offset: u64) -> String {
        match self {
            ThingPlace::Frame(slot) => format!("[rbp-{}]", slot - offset as i64),
            ThingPlace::Reserved { label, base } => match base + offset {
                0 => format!("[rel {}]", label),
                at => format!("[rel {}+{}]", label, at),
            },
        }
    }
}

/// A field's name as a printed thing spells it: bare when it is one plain
/// word, and in the single quotes the author writes it with when it is not.
///
/// `{'day sent': 25}` is then exactly the name a reader would type to read
/// that field back, which `{day sent: 25}` is not - a bare multi-word name
/// reads as two names with a space between them.
fn render_field_name(name: &str) -> String {
    let bare = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_alphanumeric() || c == '_');
    if bare {
        name.to_string()
    } else {
        format!("'{}'", name)
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
