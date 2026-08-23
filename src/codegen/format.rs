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
                            // A `value` keeps its type in a shadow tag slot, not
                            // in its static type - render by the tag, the way
                            // Print already does (src/codegen/print.rs, the
                            // Mixed arm). Without this the pointer fell to the
                            // integer formatter and a text `value` interpolated
                            // as its own address (docs/BUGS_FOUND.md #68).
                            match self.mixed_value_tag_location(name, value_type.clone()) {
                                Some(operand) => {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; value's runtime type tag", operand
                                    ));
                                    self.emit_append_mixed_value_to_buffer_slot(offset, fmt_spec);
                                }
                                None => {
                                    self.emit_append_runtime_value_to_buffer_slot(offset, value_type, fmt_spec);
                                }
                            }
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
                    // Where the value's type is only known at runtime - a mixed
                    // list's element, a `value`, a map read - the tag is the
                    // answer and the static guess is not. Asked before the value
                    // is generated, because `runtime_tag_source` reports where
                    // the tag WILL be (docs/BUGS_FOUND.md #68).
                    let tag_source = self.runtime_tag_source(expr);
                    self.generate_expr(expr);
                    // #91: a format hole has no declared destination either.
                    self.emit_empty_value_if_missed(expr, self.tagless_read_type(expr));
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    match tag_source {
                        Some(src) => {
                            if let Some(operand) = src.shadow_operand() {
                                self.emit_indent(&format!(
                                    "movzx r11, byte {}  ; value's runtime type tag", operand
                                ));
                            }
                            self.emit_append_mixed_value_to_buffer_slot(offset, fmt_spec);
                        }
                        None => {
                            self.emit_append_runtime_value_to_buffer_slot(offset, expr_type, fmt_spec);
                        }
                    }
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
                            // The tag load and `load_dst` are both `mov`s, so
                            // r11 still holds the tag when the dispatch runs
                            // (docs/BUGS_FOUND.md #68).
                            match self.mixed_value_tag_location(name, value_type.clone()) {
                                Some(operand) => {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; value's runtime type tag", operand
                                    ));
                                    load_dst(self);
                                    self.emit_append_mixed_value_to_buffer_ptr(fmt_spec);
                                }
                                None => {
                                    load_dst(self);
                                    self.emit_append_runtime_value_to_buffer_ptr(value_type, fmt_spec);
                                }
                            }
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
                    // The pointer-sink twin of the buffer-slot arm above
                    // (docs/BUGS_FOUND.md #68).
                    let tag_source = self.runtime_tag_source(expr);
                    self.generate_expr(expr);
                    // #91: a format hole has no declared destination either.
                    self.emit_empty_value_if_missed(expr, self.tagless_read_type(expr));
                    let expr_type = self.infer_expr_type(expr);
                    let fmt_spec = self.parse_format_spec(format.as_deref());
                    match tag_source {
                        Some(src) => {
                            if let Some(operand) = src.shadow_operand() {
                                self.emit_indent(&format!(
                                    "movzx r11, byte {}  ; value's runtime type tag", operand
                                ));
                            }
                            load_dst(self);
                            self.emit_append_mixed_value_to_buffer_ptr(fmt_spec);
                        }
                        None => {
                            load_dst(self);
                            self.emit_append_runtime_value_to_buffer_ptr(expr_type, fmt_spec);
                        }
                    }
                }
            }
            if let Some(offset) = dst_local {
                self.emit_store_buffer_ptr_to_slot(offset, "rax", "");
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

    /// Render one `{value:SPEC}` hole to stdout.
    ///
    /// **The value's type decides the routine; the specifier only decorates
    /// it** (docs/BUGS_FOUND.md #71). Every arm below dispatches on
    /// `value_type` FIRST, exactly as the buffer sink's
    /// `emit_append_runtime_value_to_buffer_ptr` has always done, because a
    /// specifier that reaches an integer routine holding a float or a
    /// pointer prints the raw 64 bits: a `float` printed its IEEE-754
    /// pattern and a `text` printed the string's ADDRESS.
    ///
    /// v0.4.7 fixed that for the WIDTH specifier only (#36), by gating the
    /// type check on `IntegerBase::Decimal` - so a precision, which was
    /// handled before any type check at all, and a radix, which is by
    /// definition not `Decimal`, both still fell through to the integer
    /// routines. `{n:.2}` on a number rendered the integer's bits as a
    /// double (`0.00`), and `{t:x}` on a text emitted a live pointer.
    ///
    /// The analyzer refuses the combinations that have no meaning at all -
    /// a radix on a float or a text, a precision on a text
    /// (`check_format_spec_against_type`) - so most of them never arrive
    /// here. These arms are what makes the wrong answer impossible rather
    /// than merely unreachable: a type the analyzer could not prove still
    /// renders as its own type, never as raw bits.
    pub(crate) fn emit_formatted_value(&mut self, value_type: Option<VarType>, fmt: FormatSpec) {
        match value_type {
            Some(VarType::Float) => {
                self.emit_indent("movq xmm0, rdi");
                if let Some(precision) = fmt.precision {
                    self.emit_indent(&format!("mov rdi, {}", precision));
                    self.emit_indent("call _print_float_precision");
                    self.uses_format = true;
                } else {
                    // A width or a radix on a float is not applied: there is
                    // no float padding primitive in coreasm (#36's residue),
                    // and a radix is refused before it gets here. The VALUE
                    // is what matters and it is now always right.
                    self.emit_indent("PRINT_FLOAT");
                }
                self.uses_floats = true;
                return;
            }
            Some(VarType::String) => {
                self.emit_indent("PRINT_CSTR rdi");
                return;
            }
            Some(VarType::Buffer) => {
                // The two callers differ, deliberately. With a spec present
                // print.rs has already advanced rdi to the buffer's DATA
                // area, which is NUL-terminated, so it prints as a C string;
                // the struct-pointer macro PRINT_BUF would read the header
                // as bytes. With no spec at all rdi is still the struct
                // pointer and PRINT_BUF is the length-bounded, correct one.
                if fmt.width.is_none()
                    && fmt.precision.is_none()
                    && matches!(fmt.base, IntegerBase::Decimal)
                {
                    self.emit_indent("PRINT_BUF rdi");
                } else {
                    self.emit_indent("PRINT_CSTR rdi");
                }
                return;
            }
            _ => {}
        }

        // The integer family: a `number`, a `boolean` (which renders as its
        // 1/0, LANGUAGE.md:2229), and anything whose type codegen could not
        // name. rdi holds the value itself, so every routine below is safe.

        // `{n:.2}` on a whole number is `255.00`, not `0.00`. A precision is
        // a count of decimal places (LANGUAGE.md:3175) and the manual writes
        // it of `{var:.N}` with no type attached; number and float are one
        // family by the designer's ruling recorded on #65, so the count
        // applies to a whole number the same way. It is rendered as the
        // integer, a point, and N zeros rather than by converting to a
        // double first: an i64 past 2^53 has no exact double, and rounding a
        // value on its way to being printed "exactly, correctly rounded" is
        // the very defect #34 records. Digits then zeros is exact for every
        // i64, because a whole number's decimal expansion IS the integer
        // followed by zeros.
        if let Some(precision) = fmt.precision {
            // `{n:8.2}` - a width AND a precision. #71's rule is that the
            // width "applies to any value and is ignored where no padding
            // exists for that type yet", and for a whole number a padder
            // does exist, so both halves are honoured (docs/BUGS_FOUND.md
            // #85). The rendering is `<digits>.<zeros>`, whose length is
            // the digit count + 1 + precision, so padding the DIGITS out to
            // `width - 1 - precision` brings the whole rendering to exactly
            // `width`. A width too small to hold the digits and the places
            // pads nothing, which is what every other padder here does.
            let digit_width = fmt.width.map(|w| w - 1 - precision).unwrap_or(0);
            match (digit_width > 0, fmt.zero_pad) {
                (true, true) => {
                    self.emit_indent(&format!("PRINT_INT_ZEROPAD rdi, {}", digit_width))
                }
                (true, false) => {
                    self.emit_indent(&format!("PRINT_INT_PADDED rdi, {}", digit_width))
                }
                _ => self.emit_indent("PRINT_INT rdi"),
            }
            if precision > 0 {
                let point = self.add_string(".");
                self.emit_indent(&format!("PRINT_STR {}, {}_len", point, point));
                self.emit_indent(&format!("PRINT_INT_ZEROPAD 0, {}", precision));
            }
            self.uses_format = true;
            return;
        }

        // If no specific format (default case), handle by type
        if fmt.width.is_none() && matches!(fmt.base, IntegerBase::Decimal) {
            self.emit_indent("PRINT_INT rdi");
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

/// What a `{value:SPEC}` clause ASKS OF THE VALUE, which is the only part
/// of a spec the analyzer's type check needs to see (docs/BUGS_FOUND.md
/// #71). Kept as its own small vocabulary so `FormatSpec` and `IntegerBase`
/// stay private to codegen: the analyzer decides whether the ask is
/// answerable by a type, not how the answer is emitted.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum FormatSpecAsk {
    /// No specifier, or a width alone. A width is a count of characters,
    /// which any rendering has, so it asks nothing of the type - v0.4.7
    /// settled that a width on a float or a text renders the value and
    /// drops the padding rather than reinterpreting anything (#36).
    AnyType,
    /// `{v:.N}` - N decimal places. A decimal place is a place in a
    /// NUMBER's expansion; a text has none.
    DecimalPlaces(i64),
    /// `{v:x}` / `{v:X}` / `{v:b}` / `{v:o}` - the value written in another
    /// base. Carries the base's English name for the diagnostic.
    Base(&'static str),
}

/// Read a `{value:SPEC}` clause for the type check. Any count fault is
/// dropped here for the same reason `parse_format_spec` drops it: the count
/// check is `check_format_spec`'s job and reports separately.
pub(crate) fn read_format_spec_ask(fmt: Option<&str>) -> FormatSpecAsk {
    let spec = read_format_spec(fmt).0;
    if let Some(places) = spec.precision {
        return FormatSpecAsk::DecimalPlaces(places);
    }
    match spec.base {
        IntegerBase::Decimal => FormatSpecAsk::AnyType,
        IntegerBase::HexLower | IntegerBase::HexUpper => FormatSpecAsk::Base("hexadecimal"),
        IntegerBase::Binary => FormatSpecAsk::Base("binary"),
        IntegerBase::Octal => FormatSpecAsk::Base("octal"),
    }
}

/// A count in a `{value:SPEC}` clause that the compiler read but cannot
/// honour as written. Carries the digits the author actually wrote, so the
/// diagnostic can quote them and the caret can find them.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum FormatSpecFault {
    /// `{x:N}` or `{x:0N}` with N past `FORMAT_MAX_COUNT` characters.
    WidthTooLarge(String),
    /// `{f:.N}` with N past `FORMAT_MAX_COUNT` decimal places.
    PrecisionTooLarge(String),
    /// `{x:SPEC}` where SPEC is none of the specifiers in the table - not a
    /// width, not a `0`-padded width, not a precision, not a base letter.
    /// Carries the clause exactly as written after the `:`, so the
    /// diagnostic can quote it and the caret can find it (docs/BUGS_FOUND.md
    /// #98).
    UnknownSpecifier(String),
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
///
/// Two counts that ARE both there is the other fault: `{f:8.2}` writes a
/// width and a precision, and nothing can render both (#85). That pair is
/// read out of the spec rather than walked past, so it can be reported.
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

    // A precision that FOLLOWS a width - `{f:8.2}`. `remaining` is ".2"
    // here, which matches none of the base specifiers below, so the spec
    // used to fall through to their catch-all and `precision` was never
    // assigned: writing a width silently destroyed a precision that works
    // perfectly on its own (`{f:.2}` prints 2.50, `{f:8.2}` printed 2.5),
    // and the width was not applied to the float either
    // (docs/BUGS_FOUND.md #85, #36).
    //
    // Both halves are now READ and both are kept. They compose under the
    // rule #71 already states for the width: "the width is the one
    // exception - it applies to any value and is ignored where no padding
    // exists for that type yet". So the precision decides the DIGITS and
    // the width decides the PADDING, and each is honoured wherever its own
    // primitive exists:
    //
    // - a whole number: the digits are rendered to M places by #71's
    //   integer-precision path, and the result padded out to N - both.
    // - a float: rendered to M places by `_print_float_precision`; the
    //   width is dropped, because coreasm has no float padder (#36's
    //   recorded residue), exactly as a bare `{f:8}` already drops it.
    // - a text: neither applies, and a bare `{t:8}` already drops the
    //   width for the same reason.
    //
    // No diagnostic: a width that finds no padder is silence by #71's
    // rule, not an error, and refusing the pair turned a quarter of the
    // fuzzer's legal-looking programs into compile errors. A specifier
    // asked of a type that cannot answer it at all is still refused - that
    // is #71's check and it is untouched.
    if has_width && remaining.starts_with('.') {
        let precision_digits = &remaining[1..];
        match read_count(precision_digits) {
            CountRead::None => {}
            CountRead::Count(n) => {
                spec.precision = Some(n);
                remaining = "";
            }
            CountRead::TooLarge => {
                spec.precision = Some(FORMAT_MAX_COUNT);
                fault = Some(FormatSpecFault::PrecisionTooLarge(
                    precision_digits.to_string(),
                ));
                remaining = "";
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
                // Not a base letter, and not consumed as a width or a
                // precision above: `remaining` is the part of the clause
                // that matches none of the specifiers in the table (`q`,
                // `#x`, `zzz`, a stray suffix after a width like `8q`). A
                // width-too-large or precision-too-large fault already read
                // from an earlier part of the same clause is the more
                // specific complaint, so it wins and this one is dropped
                // (docs/BUGS_FOUND.md #98).
                //
                // A `remaining` that still starts with `.` only gets here
                // by way of the width+precision block above deciding what
                // follows is not a count (`8.`, `8.2z`) and leaving it
                // untouched on purpose - that boundary is already settled
                // (`a_width_followed_by_something_that_is_not_a_count_is_not_a_fault`)
                // and #98 does not move it: a dangling `.` after a width is
                // a different clause shape from an unknown specifier letter,
                // not one more instance of it.
                if fault.is_none() && !remaining.starts_with('.') {
                    fault = Some(FormatSpecFault::UnknownSpecifier(fmt_str.to_string()));
                }
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
