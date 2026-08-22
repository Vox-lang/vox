use super::*;

impl CodeGenerator {
    /// Resolve a `{name}` format part: emit code leaving the runtime value
    /// (or pointer) in rax, and classify what was found. This is THE single
    /// name-resolution path shared by every format-string sink - Print, the
    /// buffer set/copy/append writers, and the expression materializer that
    /// write payloads, paths, and text initializers go through. Special
    /// names, variable/global lookup, and the constant fallback must never
    /// be re-implemented per sink: that duplication is exactly how the
    /// buffer sinks shipped without `{current time's hour}` support while
    /// Print had it.
    pub(crate) fn resolve_format_variable(&mut self, name: &str) -> FormatPartValue {
        match name {
            "current time's hour" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_HOUR rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "current time's minute" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_MINUTE rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "current time's second" => {
                self.emit_indent("TIME_GET");
                self.emit_indent("TIME_GET_SECOND rax");
                self.uses_time = true;
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "arguments's count" | "argument's count" => {
                self.generate_expr(&Expr::ArgumentCount);
                FormatPartValue::Loaded(Some(VarType::Integer))
            }
            "arguments's name" | "argument's name" => {
                self.generate_expr(&Expr::ArgumentName);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            "arguments's first" | "argument's first" => {
                self.generate_expr(&Expr::ArgumentFirst);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            "arguments's last" | "argument's last" => {
                self.generate_expr(&Expr::ArgumentLast);
                FormatPartValue::Loaded(Some(VarType::String))
            }
            _ => {
                if let Some(offset) = self.get_var(name) {
                    self.emit_indent(&format!("mov rax, [rbp-{}]", offset));
                    FormatPartValue::Loaded(self.variable_types.get(name).cloned())
                } else if let Some(label) = self.global_var_label(name).cloned() {
                    self.emit_indent(&format!("mov rax, [rel {}]", label));
                    FormatPartValue::Loaded(self.variable_types.get(name).cloned())
                } else if let Some(expr) = self.global_constants.get(name).cloned() {
                    match expr {
                        Expr::StringLit(s) => FormatPartValue::Literal(s),
                        Expr::IntegerLit(n) => {
                            self.emit_indent(&format!("mov rax, {}", n));
                            FormatPartValue::Loaded(Some(VarType::Integer))
                        }
                        Expr::BoolLit(b) => {
                            self.emit_indent(&format!("mov rax, {}", if b { 1 } else { 0 }));
                            FormatPartValue::Loaded(Some(VarType::Integer))
                        }
                        _ => FormatPartValue::Unknown,
                    }
                } else {
                    FormatPartValue::Unknown
                }
            }
        }
    }

    pub(crate) fn emit_format_parts_into_buffer_slot(&mut self, offset: i64, parts: &[FormatPart], clear_first: bool) {
        if clear_first {
            self.emit_clear_buffer_slot(offset);
        }

        for part in parts {
            match part {
                FormatPart::Literal(s) => self.emit_append_literal_to_buffer_slot(offset, s),
                FormatPart::Variable { name, format } => {
                    match self.resolve_format_variable(name) {
                        FormatPartValue::Loaded(value_type) => {
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            self.emit_append_runtime_value_to_buffer_slot(offset, value_type, fmt_spec);
                        }
                        FormatPartValue::Literal(s) => {
                            self.emit_append_literal_to_buffer_slot(offset, &s);
                        }
                        FormatPartValue::Unknown => {
                            // Same placeholder Print renders for unknown names
                            let placeholder = format!("{{{}}}", name);
                            self.emit_append_literal_to_buffer_slot(offset, &placeholder);
                        }
                    }
                }
                FormatPart::Expression { expr, format } => {
                    self.generate_expr(expr);
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    self.emit_append_runtime_value_to_buffer_slot(offset, expr_type, fmt_spec);
                }
            }
        }
    }

    pub(crate) fn emit_format_parts_into_buffer(
        &mut self,
        dst_local: Option<i64>,
        dst_global: Option<&str>,
        parts: &[FormatPart],
    ) {
        let load_dst = |this: &mut Self| {
            if let Some(offset) = dst_local {
                this.emit_indent(&format!("mov rdi, [rbp-{}]", offset));
            } else if let Some(label) = dst_global {
                this.emit_indent(&format!("mov rdi, [rel {}]", label));
            }
        };

        // Every `_buffer_append_*` helper takes the destination buffer in rdi,
        // and resolving a part's value is free to destroy rdi on the way: the
        // shared name resolver lowers `{arguments's first}` to `mov rdi, 1` /
        // `call _get_arg` (src/codegen/expr.rs), and an arbitrary `{expression}`
        // lowers to whatever generate_expr needs. Loading the destination once
        // before resolution and appending afterwards therefore called the
        // helper with an argument index — or any other leftover — in place of
        // the buffer, and the append dereferenced it: a segfault on a legal,
        // documented program (docs/BUGS_FOUND.md #52). The destination is now
        // loaded from its home slot immediately before each append, once the
        // value is settled in rax - the same order the buffer-slot sink above
        // already used, which is why that one never crashed. (The
        // loop used to push rdi here and pop it into rsi afterwards, saving a
        // copy it never restored; reading the home slot picks up a destination
        // that resolution itself reallocated, which a saved copy would not.)
        for part in parts {
            match part {
                FormatPart::Literal(s) => {
                    let label = self.add_string(s);
                    self.emit_indent(&format!("lea rsi, [rel {}]", label));
                    self.emit_indent(&format!("mov rdx, {}_len", label));
                    load_dst(self);
                    self.emit_indent("call _buffer_append_bytes");
                }
                FormatPart::Variable { name, format } => {
                    match self.resolve_format_variable(name) {
                        FormatPartValue::Loaded(value_type) => {
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            load_dst(self);
                            self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt_spec);
                        }
                        FormatPartValue::Literal(s) => {
                            let label = self.add_string(&s);
                            self.emit_indent(&format!("lea rsi, [rel {}]", label));
                            self.emit_indent(&format!("mov rdx, {}_len", label));
                            load_dst(self);
                            self.emit_indent("call _buffer_append_bytes");
                        }
                        FormatPartValue::Unknown => {
                            let placeholder = format!("{{{}}}", name);
                            let label = self.add_string(&placeholder);
                            self.emit_indent(&format!("lea rsi, [rel {}]", label));
                            self.emit_indent(&format!("mov rdx, {}_len", label));
                            load_dst(self);
                            self.emit_indent("call _buffer_append_bytes");
                        }
                    }
                }
                FormatPart::Expression { expr, format } => {
                    self.generate_expr(expr);
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    load_dst(self);
                    self.emit_append_runtime_value_to_buffer_ptr(expr_type, fmt_spec);
                }
            }
            if let Some(offset) = dst_local {
                self.emit_indent(&format!("mov [rbp-{}], rax", offset));
            } else if let Some(label) = dst_global {
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
    }

    /// Read a `{value:SPEC}` clause for codegen. Any fault the reader found
    /// is dropped here on purpose: the analyzer has already refused the
    /// program (`check_format_spec`), and the spec the reader returns
    /// alongside a fault is saturated rather than emptied, so even a path
    /// that reached codegen unanalyzed renders the largest width Vox can
    /// count to instead of silently rendering none.
    pub(crate) fn parse_format_spec(&self, fmt: Option<&str>) -> FormatSpec {
        read_format_spec(fmt).0
    }

    pub(crate) fn emit_formatted_value(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
        // Handle precision format for floats
        if let Some(precision) = fmt.precision {
            self.emit_indent("movq xmm0, rdi");
            self.emit_indent(&format!("mov rdi, {}", precision));
            self.emit_indent("call _print_float_precision");
            self.uses_floats = true;
            self.uses_format = true;
            return;
        }
        
        // A width must never change what a value IS (docs/BUGS_FOUND.md #36).
        //
        // The integer paths further down reinterpret rdi as a signed 64-bit
        // integer, which is right for a `number` and catastrophic for anything
        // else: a `float` printed its raw IEEE-754 bits, and a `text` printed
        // the string's ADDRESS - silent wrong data, and an information leak in
        // the text case. This dispatch used to be gated on `fmt.width.is_none()`,
        // so writing a width skipped the type check entirely, precisely when
        // the compiler knows the type best.
        //
        // Non-integer types are therefore rendered by type whether or not a
        // width was given. The width itself is not yet APPLIED to them - there
        // is no string/float padding primitive in coreasm, only the integer and
        // hex ones - so a width on a float or text is currently ignored rather
        // than honoured. That matches what the runtime-tagged `value` path
        // already does, so both paths now agree, and it turns the worst class
        // of defect (a wrong value) into the mildest (a cosmetic gap).
        if matches!(fmt.base, IntegerBase::Decimal) {
            match value_type {
                Some(VarType::Float) => {
                    self.emit_indent("movq xmm0, rdi");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                    return;
                }
                Some(VarType::String) => {
                    self.emit_indent("PRINT_CSTR rdi");
                    return;
                }
                Some(VarType::Buffer) if fmt.width.is_some() => {
                    // With a spec present, print.rs has already advanced rdi to
                    // the buffer's DATA area, so the struct-pointer macro
                    // PRINT_BUF would read the header as bytes. The data area is
                    // NUL-terminated, so print it as a C string. The no-width
                    // case below still receives the struct pointer and still
                    // uses PRINT_BUF - the two callers differ, deliberately.
                    self.emit_indent("PRINT_CSTR rdi");
                    return;
                }
                _ => {}
            }
        }

        // If no specific format (default case), handle by type
        if fmt.width.is_none() && matches!(fmt.base, IntegerBase::Decimal) {
            match value_type {
                Some(VarType::Float) => {
                    self.emit_indent("movq xmm0, rdi");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                }
                Some(VarType::Buffer) => {
                    // rdi must be the struct pointer (not data area) here.
                    // The fixed call sites guarantee this; it's documented on
                    // each one. Kept separate from VarType::String to make the
                    // contract explicit and catch any future callers that get
                    // it wrong (PRINT_BUF on a data pointer would print garbage).
                    self.emit_indent("PRINT_BUF rdi");
                }
                Some(VarType::String) => {
                    self.emit_indent("PRINT_CSTR rdi");
                }
                _ => {
                    self.emit_indent("PRINT_INT rdi");
                }
            }
            return;
        }
        
        // Handle integer formatting with width and base
        match fmt.base {
            IntegerBase::Decimal => {
                match (fmt.width, fmt.zero_pad) {
                    (Some(width), true) => {
                        self.emit_indent(&format!("PRINT_INT_ZEROPAD rdi, {}", width));
                    }
                    (Some(width), false) => {
                        self.emit_indent(&format!("PRINT_INT_PADDED rdi, {}", width));
                    }
                    _ => {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
                self.uses_format = true;
            }
            IntegerBase::HexLower => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_HEX_LOWER_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_HEX_LOWER_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_HEX_LOWER rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_HEX_LOWER rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::HexUpper => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_HEX_UPPER_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_HEX_UPPER_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_HEX_UPPER rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_HEX_UPPER rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::Binary => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_BINARY_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_BINARY_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_BINARY rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_BINARY rdi");
                }
                self.uses_format = true;
            }
            IntegerBase::Octal => {
                if fmt.width.is_some() {
                    match (fmt.width, fmt.zero_pad) {
                        (Some(width), true) => {
                            self.emit_indent(&format!("PRINT_OCTAL_ZEROPAD rdi, {}", width));
                        }
                        (Some(width), false) => {
                            self.emit_indent(&format!("PRINT_OCTAL_PADDED rdi, {}", width));
                        }
                        _ => {
                            self.emit_indent("PRINT_OCTAL rdi");
                        }
                    }
                } else {
                    self.emit_indent("PRINT_OCTAL rdi");
                }
                self.uses_format = true;
            }
        }
    }

}

/// The largest count a `{value:SPEC}` clause can name. A width is a number
/// of characters and a precision a number of decimal places; both are
/// rendered literally and neither is capped by the manual, so the limit is
/// simply the largest count the runtime can hold and count down.
pub(crate) const FORMAT_MAX_COUNT: i64 = i64::MAX;

/// A count in a `{value:SPEC}` clause that the compiler read but cannot
/// honour as written. Carries the digits the author actually wrote, so the
/// diagnostic can quote them and the caret can find them.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum FormatSpecFault {
    /// `{x:N}` or `{x:0N}` with N past `FORMAT_MAX_COUNT` characters.
    WidthTooLarge(String),
    /// `{f:.N}` with N past `FORMAT_MAX_COUNT` decimal places.
    PrecisionTooLarge(String),
}

/// Read the text after the `:` in `{value:SPEC}`.
///
/// Returns the spec every sink formats from, and - separately - whatever
/// the author wrote that it could not honour. A too-large count still comes
/// back saturated to `FORMAT_MAX_COUNT` rather than absent, because every
/// caller of this function renders from the spec alone: an absent width is
/// indistinguishable from a width that was never written, which is exactly
/// how `{n:2147483648}` came to print with no padding and no diagnostic
/// (docs/BUGS_FOUND.md #61). The fault is what the analyzer turns into the
/// error the author actually sees.
///
/// A count that is not all digits (`{x:.2z}`) is not a fault - it is not a
/// count at all, and is left alone for the base-specifier match below,
/// exactly as before.
pub(crate) fn read_format_spec(fmt: Option<&str>) -> (FormatSpec, Option<FormatSpecFault>) {
    let mut spec = FormatSpec {
        width: None,
        zero_pad: false,
        base: IntegerBase::Decimal,
        precision: None,
    };
    let Some(fmt_str) = fmt else {
        return (spec, None);
    };

    // Check for precision format first (starts with '.')
    if fmt_str.starts_with('.') {
        // Float precision format like .2, .4, etc.
        let digits = &fmt_str[1..];
        return match read_count(digits) {
            CountRead::None => (spec, None),
            CountRead::Count(n) => {
                spec.precision = Some(n);
                (spec, None)
            }
            CountRead::TooLarge => {
                spec.precision = Some(FORMAT_MAX_COUNT);
                (spec, Some(FormatSpecFault::PrecisionTooLarge(digits.to_string())))
            }
        };
    }

    // Parse width and zero padding
    let mut remaining = fmt_str;
    let mut has_width = false;
    let mut fault = None;

    // Check if it starts with digit or '0' for width/padding
    if remaining.chars().next().map(|c| c.is_ascii_digit() || c == '0').unwrap_or(false) {
        let zero_pad = remaining.starts_with('0');
        let width_str = if zero_pad {
            remaining.trim_start_matches('0')
        } else {
            remaining
        };

        // Extract digits for width
        let width_end = width_str.chars().take_while(|c| c.is_ascii_digit()).count();
        if width_end > 0 {
            let width_digits = &width_str[..width_end];
            let width = match read_count(width_digits) {
                CountRead::Count(n) => Some(n),
                CountRead::TooLarge => {
                    fault = Some(FormatSpecFault::WidthTooLarge(width_digits.to_string()));
                    Some(FORMAT_MAX_COUNT)
                }
                CountRead::None => None,
            };
            if let Some(width) = width {
                spec.width = Some(width);
                spec.zero_pad = zero_pad;
                has_width = true;
                let consumed = fmt_str.len() - width_str.len() + width_end;
                remaining = &fmt_str[consumed..];
            }
        }
    }

    // Parse base specifier from remaining characters
    if !remaining.is_empty() {
        match remaining {
            "x" => spec.base = IntegerBase::HexLower,
            "X" => spec.base = IntegerBase::HexUpper,
            "b" => spec.base = IntegerBase::Binary,
            "o" => spec.base = IntegerBase::Octal,
            _ => {
                // If we parsed a width but no base, treat as decimal
                if has_width {
                    spec.base = IntegerBase::Decimal;
                }
            }
        }
    }

    (spec, fault)
}

enum CountRead {
    /// Not a count at all (empty, or something other than digits follows).
    None,
    Count(i64),
    /// All digits, but more of them than `FORMAT_MAX_COUNT` can hold.
    TooLarge,
}

/// A count in a format spec is written as plain digits and nothing else, so
/// once the string is known to be all digits the only way it can fail to
/// parse is by being too large - which is the case that must not be
/// mistaken for "no count was written".
fn read_count(digits: &str) -> CountRead {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return CountRead::None;
    }
    match digits.parse::<i64>() {
        Ok(n) => CountRead::Count(n),
        Err(_) => CountRead::TooLarge,
    }
}
