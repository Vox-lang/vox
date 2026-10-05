//! A text cast to a number whose text is only known when the program runs
//! (LANGUAGE.md "Casting Rules"): when the text is not a number, the cast
//! raises the error flag and the sentence storing it changes nothing.
//!
//! A cast cannot skip the store itself, because it may sit deep inside the
//! value (`{reply as a number} add 1`). So the statement owns a marker slot:
//! cleared before the value is generated, set by any cast in it whose parse
//! failed, and read once just before the store, which then puts back what
//! the destination already held. The flag is raised again there, because an
//! operation later in the same value (a division) may have cleared it.

use super::*;

impl CodeGenerator {
    /// Give `stmt` a cleared marker slot when it stores a value that casts a
    /// text to a number, and hand back the enclosing statement's marker for
    /// the caller to restore.
    pub(crate) fn begin_cast_failure_marker(&mut self, stmt: &Statement) -> Option<i64> {
        let outer = self.cast_failure_marker.take();
        let value = match stmt {
            Statement::VarDecl { value: Some(value), .. }
            | Statement::Assignment { value, .. }
            | Statement::SetThingField { value, .. } => value,
            _ => return outer,
        };
        // A runtime-tagged value read into a number is cast by its tag, and
        // that tag may be a text's.
        if self.casts_text_to_number(value) || self.expr_has_runtime_only_tag(value) {
            self.stack_offset += 8;
            let marker = self.stack_offset;
            self.emit_indent(&format!(
                "mov qword [rbp-{}], 0  ; no cast of a text to a number has failed yet",
                marker
            ));
            self.cast_failure_marker = Some(marker);
        }
        outer
    }

    /// Whether `value` reads a number out of a text or a buffer anywhere in
    /// it, which only the running program can judge. A `value` counts: it
    /// may hold a text when the program runs.
    fn casts_text_to_number(&self, value: &Expr) -> bool {
        match value {
            Expr::Cast { value: source, target_type, .. } => {
                (matches!(target_type, Type::Integer | Type::Float)
                    && !self.is_float_expr(source)
                    && matches!(
                        self.infer_expr_type(source),
                        Some(VarType::String) | Some(VarType::Buffer) | Some(VarType::Mixed)
                    ))
                    || self.casts_text_to_number(source)
            }
            Expr::BinaryOp { left, right, .. } => {
                self.casts_text_to_number(left) || self.casts_text_to_number(right)
            }
            Expr::UnaryOp { operand, .. } => self.casts_text_to_number(operand),
            Expr::FunctionCall { args, .. } => args.iter().any(|arg| self.casts_text_to_number(arg)),
            _ => false,
        }
    }

    /// After a text or a buffer has been read as a number: if it was not
    /// one, mark the statement storing it.
    pub(crate) fn emit_mark_failed_cast(&mut self) {
        let Some(marker) = self.cast_failure_marker else {
            return;
        };
        let read = self.new_label("cast_read_a_number");
        self.emit_indent("cmp qword [rel _last_error], 0");
        self.emit_indent(&format!("je {}", read));
        self.emit_indent(&format!(
            "mov qword [rbp-{}], 1  ; the text was not a number",
            marker
        ));
        self.emit(&format!("{}:", read));
    }

    /// Just before a store of a value in rax: if a cast in the value failed,
    /// put back `kept` (the destination's operand), or the type's default 0
    /// when the store is a declaration and there is nothing to keep.
    pub(crate) fn emit_keep_value_if_cast_failed(&mut self, kept: Option<&str>) {
        let Some(marker) = self.cast_failure_marker else {
            return;
        };
        let stored = self.new_label("cast_stored");
        self.emit_indent(&format!("cmp qword [rbp-{}], 0", marker));
        self.emit_indent(&format!("je {}", stored));
        match kept {
            Some(operand) => self.emit_indent(&format!(
                "mov rax, qword {}  ; a text was not a number: keep what was there",
                operand
            )),
            None => self.emit_indent("xor eax, eax  ; a text was not a number: the default"),
        }
        self.emit_indent("SET_LAST_ERROR 1  ; the cast's failure outlives the rest of the value");
        self.emit(&format!("{}:", stored));
    }
}
