use super::*;

impl CodeGenerator {
    pub(crate) fn generate_print(&mut self, value: &Expr, without_newline: bool) {
        self.uses_io = true;
        // `Print origin.` / `Print span's start.` - a whole thing prints as
        // its fields, map-style and recursive (plan 310 §7). This precedes
        // the match because both spellings otherwise fall to arms that would
        // print the first eight bytes of the thing's storage as a number.
        if let Some((thing, place)) = self.thing_place(value) {
            self.emit_thing_print(&thing, &place, 0);
            if !without_newline {
                self.emit_indent("PRINT_NEWLINE");
            }
            return;
        }
        match value {
            Expr::FormatString { parts } => {
                // Print each part of the format string
                for part in parts {
                    match part {
                        FormatPart::Literal(s) => {
                            let label = self.add_string(s);
                            self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                        }
                        FormatPart::Variable { name, format } => {
                            // `"{origin}"` renders the thing exactly as
                            // `Print origin.` does (plan 310 §7): the same
                            // emission, straight into the same stream.
                            if let Some((thing, place)) =
                                self.thing_place(&Expr::Identifier(name.clone()))
                            {
                                self.emit_thing_print(&thing, &place, 0);
                                continue;
                            }
                            let var_type: Option<VarType> = match self.resolve_format_variable(name) {
                                FormatPartValue::Loaded(t) => {
                                    self.emit_indent("mov rdi, rax");
                                    t
                                }
                                FormatPartValue::Literal(s) => {
                                    let label = self.add_string(&s);
                                    self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                    continue;
                                }
                                FormatPartValue::Unknown => {
                                    let placeholder = format!("{{{}}}", name);
                                    let label = self.add_string(&placeholder);
                                    self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                                    continue;
                                }
                            };

                            // Parse format spec and emit formatted value.
                            // Buffer: use PRINT_BUF with the struct pointer (length-bounded,
                            // avoids the NUL-scan stale-byte bug). For all other types, rdi
                            // already holds the correct value/pointer.
                            if var_type == Some(VarType::Mixed) {
                                // Heterogeneous-list element or `value`:
                                // dispatch on its runtime tag (local shadow
                                // slot, or a top-level `value` global's BSS
                                // mirror). Format specs are parsed but only
                                // the default spec is honored for now.
                                if let Some(loc) =
                                    self.mixed_element_tag_slot(&Expr::Identifier(name.clone()))
                                {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; element's runtime type tag",
                                        loc.operand()
                                    ));
                                    self.emit_mixed_print_dispatch("r11");
                                } else {
                                    self.emit_indent("PRINT_INT rdi");
                                }
                            } else if var_type == Some(VarType::Buffer) {
                                let fmt_spec = self.parse_format_spec(format.as_deref());
                                if fmt_spec.width.is_none() && matches!(fmt_spec.base, IntegerBase::Decimal) && fmt_spec.precision.is_none() {
                                    self.emit_indent("PRINT_BUF rdi");
                                } else {
                                    // Format spec: value is formatted as a number, so point
                                    // rdi at the data area so the formatter reads the string.
                                    self.emit_indent(&format!(
                                        "add rdi, {}  ; buffer data area (header is {} bytes)",
                                        BUF_DATA_OFFSET, BUF_DATA_OFFSET
                                    ));
                                    self.emit_formatted_value(var_type, fmt_spec);
                                }
                            } else if var_type == Some(VarType::List) {
                                // Whole-list interpolation: rdi holds the list
                                // pointer; _list_print renders [elem, elem, ...].
                                // Format specs on a list are not honored (out of
                                // scope for stage 000 - the default rendering only).
                                self.uses_lists = true;
                                self.emit_indent("call _list_print");
                            } else if var_type == Some(VarType::Map) {
                                // Whole-map interpolation: rdi holds the map
                                // pointer; _map_print renders {"k": v, ...}.
                                // (stage 1e2)
                                self.uses_maps = true;
                                self.emit_indent("call _map_print");
                            } else {
                                let fmt_spec = self.parse_format_spec(format.as_deref());
                                self.emit_formatted_value(var_type, fmt_spec);
                            }
                        }
                        FormatPart::Expression { expr, format } => {
                            // `"{span's start}"` - a chain ending on a nested
                            // thing names the whole thing, and renders as one.
                            if let Some((thing, place)) = self.thing_place(expr) {
                                self.emit_thing_print(&thing, &place, 0);
                                continue;
                            }
                            let expr_type = self.infer_expr_type(expr);
                            let fmt_spec = self.parse_format_spec(format.as_deref());
                            // A value that carries a runtime tag - a mixed
                            // list's element, a `value`, a map read, a tagged
                            // `treating` result - must be rendered by that tag
                            // and not by its static type. The Variable arm
                            // above and the statement arms below already do
                            // this; the expression form did not, so
                            // `Print "{element 2 of nested}"` threw away the
                            // very tag the element load had just put in r11
                            // and printed the payload as an integer - a rodata
                            // address for a text element, a live heap address
                            // for a nested list (docs/BUGS_FOUND.md #68). Asked
                            // before the value is generated, because
                            // `runtime_tag_source` reports where the tag WILL
                            // be, and taken first because a runtime tag
                            // outranks a static guess (the same order the
                            // catch-all arm below uses).
                            let tag_source = self.runtime_tag_source(expr);

                            // A bare `nothing` literal interpolated into a
                            // format string renders `nothing` (it would else
                            // infer as Integer and print `0`). A `value`/
                            // mixed expression that *holds* nothing is
                            // already handled by the mixed dispatch below
                            // via VarType::Mixed; this is only for the literal
                            // itself. (stage 1e3)
                            if matches!(expr.as_ref(), Expr::NothingLit) {
                                let label = self.add_string("nothing");
                                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
                            } else if let Some(src) = tag_source {
                                self.generate_expr(expr);
                                // #91: no declared destination here either.
                                self.emit_empty_value_if_missed(
                                    expr, self.tagless_read_type(expr));
                                if let Some(operand) = src.shadow_operand() {
                                    self.emit_indent(&format!(
                                        "movzx r11, byte {}  ; value's runtime type tag", operand
                                    ));
                                }
                                self.emit_indent("mov rdi, rax");
                                // #81: the hole's own spec travels into the
                                // dispatch, so a tagged number pads or changes
                                // base here exactly as it does in a buffer.
                                self.emit_mixed_print_dispatch_spec("r11", fmt_spec);
                            } else if expr_type == Some(VarType::Buffer) {
                                // For buffer expressions: generate the struct pointer,
                                // not the data-area pointer - PRINT_BUF reads its own
                                // length from the struct, so it needs the base pointer.
                                self.generate_expr(expr);
                                // #91: a format hole has no declared
                                // destination; the value is read as the
                                // collection's element type.
                                self.emit_empty_value_if_missed(
                                    expr, self.tagless_read_type(expr));
                                self.emit_indent("mov rdi, rax");
                                if fmt_spec.width.is_none() && matches!(fmt_spec.base, IntegerBase::Decimal) && fmt_spec.precision.is_none() {
                                    self.emit_indent("PRINT_BUF rdi");
                                } else {
                                    // Format spec present: adjust to data area for
                                    // the NUL-scanned formatter.
                                    self.emit_indent(&format!("add rdi, {}  ; buffer data area", BUF_DATA_OFFSET));
                                    self.emit_formatted_value(expr_type, fmt_spec);
                                }
                            } else if expr_type == Some(VarType::List) {
                                // List expression interpolation: rdi holds the
                                // list pointer; _list_print renders it, exactly
                                // as the Variable arm above does.
                                //
                                // A `{name}` whose name is QUOTED - `{'the
                                // spaced list'}` - parses as an expression, not
                                // a variable part, so it arrives here and not
                                // above; so does a bare list literal
                                // `{[1, 2, 3]}`. Without this arm both fell to
                                // the integer formatter and Print emitted the
                                // list's heap address, the same wrong answer
                                // docs/BUGS_FOUND.md #44 reports for the other
                                // sinks - and once those were fixed, Print was
                                // the only sink still getting it wrong. The Map
                                // arm below has been here since stage 1e2; this
                                // is its list twin.
                                self.generate_expr(expr);
                                // #91: a format hole has no declared
                                // destination; the value is read as the
                                // collection's element type.
                                self.emit_empty_value_if_missed(
                                    expr, self.tagless_read_type(expr));
                                self.emit_indent("mov rdi, rax");
                                self.uses_lists = true;
                                self.emit_indent("call _list_print");
                            } else if expr_type == Some(VarType::Map) {
                                // Map expression interpolation: rdi holds the map
                                // pointer; _map_print renders it. (stage 1e2)
                                self.generate_expr(expr);
                                // #91: a format hole has no declared
                                // destination; the value is read as the
                                // collection's element type.
                                self.emit_empty_value_if_missed(
                                    expr, self.tagless_read_type(expr));
                                self.emit_indent("mov rdi, rax");
                                self.uses_maps = true;
                                self.emit_indent("call _map_print");
                            } else {
                                // Non-buffer: generate_cstr_expr adds +24 for buffer
                                // (irrelevant here), then falls through to normal path.
                                self.generate_cstr_expr(expr);
                                // #91: a format hole has no declared
                                // destination; the value is read as the
                                // collection's element type.
                                self.emit_empty_value_if_missed(
                                    expr, self.tagless_read_type(expr));
                                self.emit_indent("mov rdi, rax");
                                self.emit_formatted_value(expr_type, fmt_spec);
                            }
                        }
                    }
                }
                if !without_newline {
                    self.emit_indent("PRINT_NEWLINE");
                }
                return;
            }
            
            // A string literal prints its own bytes, unconditionally - its
            // content is never resolved against a same-spelled variable or
            // global constant (BUGS_FOUND #19). The `emit_global_constant_-
            // format_fallback` call this arm used to make on `s` was the
            // same violation through a second mechanism: `s` is data that
            // happens to have been typed by the author, not a name lookup
            // key, even when it coincides with a folded top-level constant's
            // name.
            Expr::StringLit(s) => {
                let label = self.add_string(s);
                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
            }
            
            Expr::IntegerLit(n) => {
                self.emit_indent(&format!("mov rdi, {}", n));
                self.emit_indent("PRINT_INT rdi");
            }
            
            Expr::FloatLit(n) => {
                let label = self.add_float(*n);
                self.emit_indent(&format!("FLOAT_LOAD {}", label));
                self.emit_indent("PRINT_FLOAT");
                self.uses_floats = true;
            }

            // `print nothing.` — the literal null (stage 1e3, tag 6). It
            // would otherwise fall to the catch-all (infer_expr_type maps it
            // to Integer) and print `0`, so handle it explicitly. Inside a
            // list/map slot or a `value`, the mixed print dispatch already
            // renders `nothing`; this arm is for a bare literal argument.
            Expr::NothingLit => {
                let label = self.add_string("nothing");
                self.emit_indent(&format!("PRINT_STR {}, {}_len", label, label));
            }
            
            Expr::Identifier(name)
                if self.get_var(name).is_some()
                    || self.global_var_label(name).is_some()
                    || name == "_iter" =>
            {
                if self.emit_load_named_var_into_rax(name) {
                    self.emit_indent("mov rdi, rax");
                    let var_type = self.variable_types.get(name).cloned();
                    match var_type {
                        Some(VarType::Mixed) => {
                            if let Some(loc) = self.mixed_element_tag_slot(value) {
                                self.emit_indent(&format!(
                                    "movzx r11, byte {}  ; element's runtime type tag",
                                    loc.operand()
                                ));
                                self.emit_mixed_print_dispatch("r11");
                            } else {
                                self.emit_indent("PRINT_INT rdi");
                            }
                        }
                        Some(VarType::Buffer) => {
                            // Dynamic buffer - PRINT_BUF reads length/data directly
                            // from the struct, no NUL-scan needed
                            self.emit_indent("PRINT_BUF rdi");
                        }
                        Some(VarType::String) => {
                            // Raw string pointer (from lists, etc.)
                            self.emit_indent("PRINT_CSTR rdi");
                        }
                        Some(VarType::Float) => {
                            self.emit_indent("movq xmm0, rdi");
                            self.emit_indent("PRINT_FLOAT");
                            self.uses_floats = true;
                        }
                        Some(VarType::List) => {
                            // Whole-list print: rdi holds the list pointer;
                            // _list_print walks the slots and renders
                            // [elem, elem, ...] with per-tag dispatch.
                            self.uses_lists = true;
                            self.emit_indent("call _list_print");
                        }
                        Some(VarType::Map) => {
                            // Whole-map print: rdi holds the map pointer;
                            // _map_print walks the entries and renders
                            // {"key": value, ...} with per-tag dispatch.
                            // (stage 1e2)
                            self.uses_maps = true;
                            self.emit_indent("call _map_print");
                        }
                        _ => {
                            self.emit_indent("PRINT_INT rdi");
                        }
                    }
                } else if name == "_iter" {
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("PRINT_INT rdi");
                }
            }
            
            Expr::ElementAccess { list, .. } => {
                // Get the list's element type for proper printing. For a
                // named list this is the recorded element type; for a list
                // literal it is the literal's homogeneous element type (or
                // Mixed if the literal is heterogeneous); for any other
                // mixed list expression (e.g. a chained `element 2 of
                // element 2 of deep`) the elements are runtime-tagged, so
                // `generate_expr` left the slot's tag in r11 and we dispatch
                // on it (stage 1e1).
                let elem_type = self.static_list_element_type(list);

                self.generate_expr(value);
                // #91: Print has no declared destination, so it reads the miss
                // as the list's element type. A pointer type must not be handed
                // the 0 the read yields.
                self.emit_empty_value_if_missed(value, self.tagless_read_type(value));
                self.emit_indent("mov rdi, rax");

                match elem_type {
                    Some(VarType::Mixed) => {
                        // generate_expr left the slot's type tag in r11
                        // (captured immediately - nothing can clobber it
                        // between the element load and this dispatch).
                        self.emit_mixed_print_dispatch("r11");
                    }
                    Some(VarType::List) => {
                        // A homogeneous list-of-lists: rdi already holds the
                        // child list pointer, so recurse into `_list_print`
                        // (stage 1e1).
                        self.emit_indent("call _list_print");
                        self.uses_lists = true;
                    }
                    Some(VarType::Map) => {
                        // A homogeneous list-of-maps: rdi already holds the
                        // child map pointer, so recurse into `_map_print`
                        // (stage 1e2).
                        self.emit_indent("call _map_print");
                        self.uses_maps = true;
                    }
                    Some(VarType::String) => {
                        self.emit_indent("PRINT_CSTR rdi");
                    }
                    Some(VarType::Float) => {
                        self.emit_indent("movq xmm0, rdi");
                        self.emit_indent("PRINT_FLOAT");
                        self.uses_floats = true;
                    }
                    _ => {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
            }
            
            Expr::MapAccess { .. } => {
                // A map value read leaves its runtime tag in r11 (mirroring
                // ElementAccess), so dispatch on it immediately. The map's
                // value may be any tagged type (stage 1e2).
                self.generate_expr(value);
                self.emit_indent("mov rdi, rax");
                self.uses_maps = true;
                self.emit_mixed_print_dispatch("r11");
            }

            _ => {
                let is_float = self.is_float_expr(value);
                let expr_type = self.infer_expr_type(value);
                // A value carrying a runtime tag - `mixed's first`/`last`, a
                // mixed element read, or a `value`-returning call - must be
                // rendered by that tag, not by its static type. The tag is only
                // valid until the next call or syscall, so capture it here.
                let tag_source = self.runtime_tag_source(value);
                self.generate_expr(value);
                if let Some(src) = tag_source {
                    if let Some(operand) = src.shadow_operand() {
                        self.emit_indent(&format!(
                            "movzx r11, byte {}  ; value tag (shadow slot)", operand
                        ));
                    }
                    self.emit_indent("mov rdi, rax");
                    self.emit_mixed_print_dispatch("r11");
                } else if is_float {
                    self.emit_indent("movq xmm0, rax");
                    self.emit_indent("PRINT_FLOAT");
                    self.uses_floats = true;
                } else {
                    self.emit_indent("mov rdi, rax");
                    if matches!(expr_type, Some(VarType::String)) {
                        self.emit_indent("PRINT_CSTR rdi");
                    } else if matches!(expr_type, Some(VarType::Buffer)) {
                        // rdi holds a buffer struct pointer, so PRINT_BUF
                        // reads the length out of the header - the same arm
                        // the buffer-variable path above has had all along.
                        // A declared `buffer` return printed directly reaches
                        // Print only here, and without this arm the integer
                        // formatter rendered the struct's address
                        // (BUGS_FOUND #67).
                        self.emit_indent("PRINT_BUF rdi");
                    } else if matches!(expr_type, Some(VarType::List)) {
                        // A bare list literal, or `first`/`last` of a
                        // homogeneous list-of-lists: rdi holds a list pointer,
                        // so recurse into `_list_print` (stage 1e1).
                        self.emit_indent("call _list_print");
                        self.uses_lists = true;
                    } else if matches!(expr_type, Some(VarType::Map)) {
                        // A bare map literal: rdi holds a map pointer, so
                        // recurse into `_map_print` (stage 1e2).
                        self.emit_indent("call _map_print");
                        self.uses_maps = true;
                    } else {
                        self.emit_indent("PRINT_INT rdi");
                    }
                }
            }
        }
        if !without_newline {
            self.emit_indent("PRINT_NEWLINE");
        }
    }

}
