use super::*;

/// Map a known `VarType` to its list slot tag. Returns `None` for `Mixed`
/// and `Unknown` (and anything without a single static tag): those need a
/// runtime tag (stage 1d) or the `TAG_INTEGER` fallback at the append site.
/// A `List` value in a slot is provably tag 4 (stage 1e1 activated the
/// reserved LIST tag for nested lists).
fn vartype_to_tag(vt: VarType) -> Option<u8> {
    match vt {
        VarType::Integer => Some(TAG_INTEGER),
        VarType::Float => Some(TAG_FLOAT),
        VarType::String | VarType::Buffer => Some(TAG_STRING),
        VarType::Boolean => Some(TAG_BOOLEAN),
        VarType::List => Some(TAG_LIST),
        VarType::Map => Some(TAG_MAP),
        // Mixed/Unknown: no single static tag — runtime tag (1d) or fallback.
        _ => None,
    }
}

/// Map a declared `Type` to the list slot tag a value of that type would
/// carry. Used to seed the pre-scan env from a variable's declared type
/// (a static proof) when the initializer's own type can't be inferred — e.g.
/// `a buffer called b is 4 bytes in size.` (the size expr is opaque, but
/// the declared type `buffer` proves the slot tag is `TAG_STRING`). Returns
/// `None` for non-scalar, non-list types (File/Time/Timer/Void/Unknown). A
/// `List` value carries tag 4 (stage 1e1) — this arm is load-bearing for the
/// `is a list` predicate, whose codegen does
/// `type_to_tag(type_noun).expect("type predicate noun is scalar")`.
pub(crate) fn type_to_tag(t: &Type) -> Option<u8> {
    match t {
        Type::Integer => Some(TAG_INTEGER),
        Type::Float => Some(TAG_FLOAT),
        Type::String => Some(TAG_STRING),
        Type::Boolean => Some(TAG_BOOLEAN),
        Type::Buffer => Some(TAG_STRING),
        Type::List(_) => Some(TAG_LIST),
        Type::Map(_) => Some(TAG_MAP),
        // File/Time/Timer/Void/Unknown: no scalar slot tag.
        _ => None,
    }
}

impl RuntimeTagSource {
    /// The `movzx r11, byte <operand>` source operand for a shadow-slot tag,
    /// or `None` for `R11` (the tag is already there - nothing to load).
    pub(crate) fn shadow_operand(&self) -> Option<String> {
        match self {
            RuntimeTagSource::ShadowSlot(off) => Some(format!("[rbp-{}]", off)),
            RuntimeTagSource::ShadowSlotGlobal(label) => Some(format!("[rel {}]", label)),
            RuntimeTagSource::R11 => None,
        }
    }
}

impl ShadowTagLoc {
    pub(crate) fn operand(&self) -> String {
        match self {
            ShadowTagLoc::Local(off) => format!("[rbp-{}]", off),
            ShadowTagLoc::Global(label) => format!("[rel {}]", label),
        }
    }
}

impl CodeGenerator {
    /// Static classification of an expression into a list slot tag, using
    /// only what is provable without emitting code. `env` maps scalar
    /// variable names to their inferred `TagInfo`; `list_seen_tags` records
    /// the single proven element type of each homogeneous list, so reads of
    /// `first`/`last`/`element N of` such a list are themselves provable.
    ///
    /// Sound by design: only literals, tracked scalars, functions with a
    /// declared return type, casts, provable binary/unary ops, and reads of
    /// homogeneous lists yield `Known`. Everything else is `Unknowable`, so
    /// the join in `prescan_note_list_value` widens the list to `Mixed`
    /// rather than guessing (stage 1b — "static is a proof; mixed is the
    /// default").
    pub(crate) fn prescan_expr_tag(
        &self,
        e: &Expr,
        env: &HashMap<String, TagInfo>,
        list_seen_tags: &HashMap<String, u8>,
    ) -> TagInfo {
        match e {
            Expr::IntegerLit(_) => TagInfo::Known(TAG_INTEGER),
            Expr::FloatLit(_) => TagInfo::Known(TAG_FLOAT),
            Expr::BoolLit(_) => TagInfo::Known(TAG_BOOLEAN),
            // The nothing/null literal is tag 6 (stage 1e3).
            Expr::NothingLit => TagInfo::Known(TAG_NOTHING),
            // A list value in a slot is tag 4 (stage 1e1). This makes a
            // homogeneous list-of-lists `[[1,2],[3,4]]` prove a single tag
            // (4) and stay non-mixed, while a mixed `[1, [2,3], "four"]` still
            // widens (tags {0, 4, 1}).
            Expr::ListLit { .. } => TagInfo::Known(TAG_LIST),
            // A map value in a slot is tag 5 (stage 1e2).
            Expr::MapLit { .. } => TagInfo::Known(TAG_MAP),
            // A type predicate yields a boolean, so appending its result to a
            // list does not widen the list (stage 1c).
            Expr::TypeCheck { .. } => TagInfo::Known(TAG_BOOLEAN),
            // A format string always materializes text (bug #17), so it
            // proves TAG_STRING the same way a literal does - unlike an
            // opaque expression, its result type isn't in doubt.
            Expr::FormatString { .. } => TagInfo::Known(TAG_STRING),
            Expr::StringLit(s) => {
                // A quoted name can be a variable reference in Vox; if we
                // tracked it as a scalar, use that. Otherwise it's a string.
                match env.get(s) {
                    Some(info) => *info,
                    None => TagInfo::Known(TAG_STRING),
                }
            }
            Expr::Identifier(name) => match env.get(name) {
                Some(info) => *info,
                None => TagInfo::Unknowable,
            },
            // Function results and casts: their type comes from declared
            // metadata (function_return_types / the cast target), not from
            // operand variable_types, so infer_expr_type is sound here and
            // agrees with the tag written at emit time.
            Expr::FunctionCall { .. } | Expr::Cast { .. } => {
                match self.infer_expr_type(e).and_then(vartype_to_tag) {
                    Some(t) => TagInfo::Known(t),
                    None => TagInfo::Unknowable,
                }
            }
            Expr::UnaryOp { op, operand } => {
                // Logical negation is always a boolean, regardless of the
                // operand's type (`not 5` is a boolean), so tag it TAG_BOOLEAN
                // and keep `prescan_expr_tag` consistent with
                // `emit_time_expr_tag`. Other unary ops (e.g. arithmetic
                // negation) keep the operand's tag.
                if matches!(op, UnaryOperator::Not) {
                    TagInfo::Known(TAG_BOOLEAN)
                } else {
                    self.prescan_expr_tag(operand, env, list_seen_tags)
                }
            }
            Expr::BinaryOp { left, op, right } => {
                let lt = self.prescan_expr_tag(left, env, list_seen_tags);
                let rt = self.prescan_expr_tag(right, env, list_seen_tags);
                match (lt, rt) {
                    (TagInfo::Unknowable, _) | (_, TagInfo::Unknowable) => {
                        TagInfo::Unknowable
                    }
                    (TagInfo::Known(lt), TagInfo::Known(rt)) => {
                        let arithmetic = matches!(
                            op,
                            BinaryOperator::Add | BinaryOperator::Subtract
                            | BinaryOperator::Multiply | BinaryOperator::Divide
                            | BinaryOperator::Modulo
                        );
                        if arithmetic && (lt == TAG_FLOAT || rt == TAG_FLOAT) {
                            TagInfo::Known(TAG_FLOAT)
                        } else {
                            // Non-arithmetic ops (comparison/logical/bitwise)
                            // yield 0/1 integers, matching infer_expr_type's
                            // `_ => Some(VarType::Integer)` arm for them.
                            TagInfo::Known(TAG_INTEGER)
                        }
                    }
                }
            }
            Expr::PropertyAccess { object, property } => match property {
                ObjectProperty::First | ObjectProperty::Last => {
                    self.prescan_list_read_tag(object, list_seen_tags)
                }
                ObjectProperty::Size | ObjectProperty::Capacity => {
                    TagInfo::Known(TAG_INTEGER)
                }
                _ => TagInfo::Unknowable,
            },
            Expr::ElementAccess { list, .. } => match list.as_ref() {
                Expr::Identifier(name) | Expr::StringLit(name) => {
                    self.prescan_list_read_tag(name, list_seen_tags)
                }
                _ => TagInfo::Unknowable,
            },
            _ => TagInfo::Unknowable,
        }
    }

    /// Proven slot tag for reading one element out of `name` (`element N of`,
    /// `first`, `last`). `list_seen_tags` records the first element tag proven
    /// for a list and is deliberately never retracted, so it alone is NOT a
    /// proof of homogeneity: a list that starts `[1, 2]` and is later appended
    /// a text still has `Known(TAG_INTEGER)` recorded. Consulting
    /// `mixed_lists` is what makes the read sound — a widened list yields
    /// `Unknowable`, so whatever receives the element widens too rather than
    /// reinterpreting a string pointer as a number. The fixed-point loop in
    /// `prescan_mixed_lists` guarantees the widening is visible here even when
    /// the read appears earlier in the program than the write that widens.
    pub(crate) fn prescan_list_read_tag(
        &self,
        name: &str,
        list_seen_tags: &HashMap<String, u8>,
    ) -> TagInfo {
        if self.mixed_lists.contains(name) {
            return TagInfo::Unknowable;
        }
        match list_seen_tags.get(name) {
            Some(t) => TagInfo::Known(*t),
            None => TagInfo::Unknowable,
        }
    }

    /// Proven slot tag for a `For each <var> in <collection>` loop variable,
    /// derived from the collection's element type. A range yields integers;
    /// a list literal yields its (single) element tag; a homogeneous list
    /// variable yields its recorded tag; `arguments` yields strings. Anything
    /// else is `Unknowable`, so appending the loop variable widens rather
    /// than guesses. Used to seed `env` before walking the loop body.
    pub(crate) fn foreach_loop_var_tag(
        &self,
        collection: &Expr,
        env: &HashMap<String, TagInfo>,
        list_seen_tags: &HashMap<String, u8>,
    ) -> TagInfo {
        match collection {
            Expr::Range { .. } => TagInfo::Known(TAG_INTEGER),
            Expr::ArgumentAll | Expr::ArgumentRaw => TagInfo::Known(TAG_STRING),
            Expr::ListLit { elements } => {
                if elements.is_empty() {
                    return TagInfo::Unknowable;
                }
                let mut tags: Vec<u8> = Vec::new();
                for e in elements {
                    match self.prescan_expr_tag(e, env, list_seen_tags) {
                        TagInfo::Known(t) => {
                            if !tags.contains(&t) {
                                tags.push(t);
                            }
                        }
                        TagInfo::Unknowable => return TagInfo::Unknowable,
                    }
                }
                if tags.len() == 1 {
                    TagInfo::Known(tags[0])
                } else {
                    TagInfo::Unknowable
                }
            }
            Expr::Identifier(name) | Expr::StringLit(name) => {
                self.prescan_list_read_tag(name, list_seen_tags)
            }
            _ => TagInfo::Unknowable,
        }
    }

    /// Where the runtime type tag of `e` can be found immediately after
    /// `generate_expr(e)` has run, or `None` when `e` carries no tag at all.
    ///
    /// A Mixed *variable* keeps its tag in a shadow stack slot, which survives
    /// anything. Everything else that has a tag leaves it in r11 (see
    /// `expr_leaves_tag_in_r11`), where it is only valid until the next call or
    /// syscall. For any other expression r11 holds an unrelated value, so
    /// comparing against it reads garbage - callers must fall back to a static
    /// answer instead.
    pub(crate) fn runtime_tag_source(&self, e: &Expr) -> Option<RuntimeTagSource> {
        if let Some(loc) = self.mixed_element_tag_slot(e) {
            return Some(match loc {
                ShadowTagLoc::Local(off) => RuntimeTagSource::ShadowSlot(off),
                ShadowTagLoc::Global(label) => RuntimeTagSource::ShadowSlotGlobal(label),
            });
        }
        if self.expr_leaves_tag_in_r11(e) {
            return Some(RuntimeTagSource::R11);
        }
        None
    }

    /// Static tag for a *type predicate* operand. Identical to
    /// `emit_time_expr_tag` except that it still trusts a variable's declared
    /// type for an unprovable scalar: a predicate only reads a tag, it never
    /// writes one, so an over-confident answer here cannot produce the wild
    /// dereference `unprovable_scalars` guards against. Stage 1d gives these
    /// values real runtime tags and makes the answer exact.
    pub(crate) fn predicate_static_tag(&self, e: &Expr) -> Option<u8> {
        if let Expr::StringLit(name) | Expr::Identifier(name) = e {
            if self.unprovable_scalars.contains(name) {
                return self.variable_types.get(name).cloned().and_then(vartype_to_tag);
            }
        }
        self.emit_time_expr_tag(e)
    }

    /// If `e` is a reference to a Mixed-typed variable with a shadow tag
    /// slot, return that slot's rbp offset.
    pub(crate) fn mixed_element_tag_slot(&self, e: &Expr) -> Option<ShadowTagLoc> {
        match e {
            Expr::Identifier(name) | Expr::StringLit(name) => {
                if self.variable_types.get(name) == Some(&VarType::Mixed) {
                    if let Some(&off) = self.mixed_tag_slots.get(name) {
                        Some(ShadowTagLoc::Local(off))
                    } else {
                        self.global_value_tag_labels
                            .get(name)
                            .cloned()
                            .map(ShadowTagLoc::Global)
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Where a `{name}` format hole's runtime tag lives, for a name whose
    /// resolved type is `Mixed` - a `value` local's shadow stack slot or a
    /// top-level `value`'s BSS mirror, as the `movzx r11, byte <operand>`
    /// source. `None` means there is no tag to read (the name is not a
    /// `value`, or it is one with no shadow slot), and the caller must fall
    /// back to its static rendering rather than dispatch on whatever r11
    /// happens to hold - the same fallback Print takes.
    pub(crate) fn mixed_value_tag_location(
        &self,
        name: &str,
        value_type: Option<VarType>,
    ) -> Option<String> {
        if value_type != Some(VarType::Mixed) {
            return None;
        }
        self.mixed_element_tag_slot(&Expr::Identifier(name.to_string()))
            .map(|loc| loc.operand())
    }

    /// Best-effort static tag for a value being written into a list slot
    /// at emit time (richer than the pre-scan version: consults
    /// `variable_types`/`list_element_types`, which are populated by the
    /// time code is emitted). Returns `None` when only a runtime tag would
    /// do (a `Mixed` value's shadow-slot tag, or a genuinely opaque value
    /// whose actual type can't be proven — the latter falls back to
    /// `TAG_INTEGER` at the append site, with correct rendering deferred to
    /// stage 1d's runtime tag propagation).
    pub(crate) fn emit_time_expr_tag(&self, e: &Expr) -> Option<u8> {
        match e {
            Expr::IntegerLit(_) => Some(TAG_INTEGER),
            Expr::FloatLit(_) => Some(TAG_FLOAT),
            Expr::BoolLit(_) => Some(TAG_BOOLEAN),
            // The nothing/null literal is tag 6 (stage 1e3).
            Expr::NothingLit => Some(TAG_NOTHING),
            // A list literal value in a slot is tag 4 (stage 1e1). This is the
            // tag written to a nested-list element's slot at emit time.
            Expr::ListLit { .. } => Some(TAG_LIST),
            // A map literal value in a slot is tag 5 (stage 1e2).
            Expr::MapLit { .. } => Some(TAG_MAP),
            // A type predicate result is a boolean (stage 1c).
            Expr::TypeCheck { .. } => Some(TAG_BOOLEAN),
            // Logical negation is always a boolean. `infer_expr_type` maps
            // `Not` to `Integer` (codegen treats booleans as 0/1), which would
            // mis-tag a negated predicate — or any `not <expr>` list element —
            // as `TAG_INTEGER`. Tag it `TAG_BOOLEAN` explicitly so it matches
            // `prescan_expr_tag`, which recurses to the (boolean) operand.
            Expr::UnaryOp { op: UnaryOperator::Not, .. } => Some(TAG_BOOLEAN),
            // A string literal is data, never a name (bug #29 / #19's
            // family). It must be tagged TAG_STRING unconditionally, before
            // any lookup of its text against variable names — a literal that
            // happens to spell an in-scope variable name is still a literal,
            // and resolving it would write the colliding variable's type tag
            // onto the slot (an integer tag over a string pointer = silent
            // wrong data; a list tag = a later wild dereference). Only an
            // `Identifier` may be looked up.
            Expr::StringLit(_) => Some(TAG_STRING),
            Expr::Identifier(name)
                if self.unprovable_scalars.contains(name)
                    && self.variable_types.get(name) != Some(&VarType::List) =>
            {
                // The pre-scan could not prove what this variable holds, so
                // its declared type must not be turned into a slot tag. `None`
                // writes the integer tag, which a reader renders as a number -
                // wrong for a string, but never a wild dereference. Stage 1d's
                // runtime tag propagation replaces the guess with the real tag.
                //
                // Lists are exempt: the hazard is a declared type claiming a
                // pointer tag over bits that are not a pointer, and a list
                // variable's slot always holds a list pointer. Suppressing
                // TAG_LIST here would silently un-nest a nested list.
                None
            }
            Expr::Identifier(name) => {
                match self.variable_types.get(name) {
                    Some(VarType::Integer) => Some(TAG_INTEGER),
                    Some(VarType::Float) => Some(TAG_FLOAT),
                    Some(VarType::Boolean) => Some(TAG_BOOLEAN),
                    Some(VarType::String) | Some(VarType::Buffer) => Some(TAG_STRING),
                    Some(VarType::List) => Some(TAG_LIST),
                    Some(VarType::Map) => Some(TAG_MAP),
                    Some(VarType::Mixed) => None, // runtime tag in shadow slot
                    _ => {
                        if matches!(e, Expr::StringLit(_))
                            && !self.variables.contains_key(name)
                            && self.global_var_label(name).is_none()
                        {
                            Some(TAG_STRING) // a genuine string literal
                        } else if let Some(vt) = self.zero_arg_func_return_type(name) {
                            // Plan 270 G4: an identifier naming a zero-argument
                            // function is a call; its result tag is the
                            // function's declared return type. Mixed/Unknown map
                            // to None (runtime tag, like a written call).
                            vartype_to_tag(vt)
                        } else {
                            // An identifier not in variable_types and not a
                            // genuine string literal. Every declared variable
                            // is in variable_types during codegen, so this is
                            // an edge (e.g. a global int mirror); defaulting to
                            // the zero (integer) tag is the same runtime effect
                            // as returning None (the append path writes 0).
                            Some(TAG_INTEGER)
                        }
                    }
                }
            }
            // A `treating` clause that dispatches on runtime tags has no
            // single tag to write at emit time: the result is the element or
            // the replacement, and which one - and what it is - is settled by
            // the hardware (#59, #69). `infer_expr_type` would answer with the
            // subject's static type, which is right for the element and wrong
            // for a `value` replacement that turned out to hold something
            // else. `expr_leaves_tag_in_r11` agrees on exactly this condition,
            // so every tag consumer takes the real tag out of r11 instead.
            Expr::TreatingAs { value, match_value, replacement }
                if self.treating_dispatches_on_runtime_tag(value, match_value, replacement) =>
            {
                None
            }
            // Function results, binary/unary ops, casts, and property/element
            // reads: infer_expr_type resolves these from declared metadata and
            // the populated variable_types/list_element_types, so the written
            // tag matches the actual type. Mixed/Unknown map to None (runtime
            // tag or the TAG_INTEGER fallback); List maps to TAG_LIST via
            // vartype_to_tag.
            _ => self.infer_expr_type(e).and_then(vartype_to_tag),
        }
    }

    /// Load the runtime type tag of `expr` into r11, the single source of
    /// truth used by value-parameter passing, value returns, and (via the
    /// 1c predicates) type checks. Three cases, in priority order:
    ///
    /// 1. **Static tag** (`emit_time_expr_tag` returns `Some`): literals,
    ///    statically-typed variables, homogeneous-list element reads, and
    ///    scalar-returning function calls → `mov r11, <tag>`.
    /// 2. **Shadow tag slot** (`mixed_element_tag_slot` returns `Some`): a
    ///    `Mixed` *identifier* — a value parameter, a for-each variable over a
    ///    mixed list, or a declared `value` local — keeps its tag in a shadow
    ///    stack slot → `movzx r11, byte [rbp-<off>]`.
    /// 3. **Already in r11** (both return `None`, and `expr_leaves_tag_in_r11`
    ///    agrees): a freshly-read mixed-list element (ElementAccess/First/Last
    ///    leaves the slot's tag in r11) and a value-returning function call (the
    ///    callee leaves r11=tag; `call` and `FUNC_EPILOGUE`/`_dec_call_depth` do
    ///    not clobber r11). No emit needed.
    /// 4. **Nothing holds the tag**: r11 is unrelated garbage, so fall back to
    ///    `TAG_INTEGER` rather than write that garbage into a tag slot.
    ///
    /// Register discipline: callers consume r11 immediately — between this
    /// load and the consumer there must be no `call`/syscall that clobbers r11.
    /// The inbound/return paths below respect this; if a future clobbering
    /// helper is inserted between the load and the consumer, spill r11 to a
    /// shadow slot first.
    pub(crate) fn emit_load_value_tag(&mut self, expr: &Expr) {
        match self.emit_time_expr_tag(expr) {
            Some(t) => self.emit_indent(&format!("mov r11, {}  ; value tag (static)", t)),
            None => match self.mixed_element_tag_slot(expr) {
                Some(loc) => self.emit_indent(&format!(
                    "movzx r11, byte {}  ; value tag (shadow slot)",
                    loc.operand()
                )),
                None => {
                    // r11 already holds the tag — but ONLY for the expressions
                    // `expr_leaves_tag_in_r11` names (a fresh mixed element or
                    // map read, a value-returning call). For anything else that
                    // reaches here, r11 holds whatever the last unrelated
                    // instruction left in it, and writing that byte into a
                    // value's tag slot mislabels the payload. BUGS_FOUND #43:
                    // a function whose only `Return a value` sat inside an `If`
                    // never got `Type::Value` as its return type, so the callee
                    // never set r11 and the caller stored the callee's stale
                    // PARAMETER tag (text) over an integer payload — the caller
                    // then printed 99 as a `char*` and the program segfaulted.
                    // The integer tag is the safe default: it makes the payload
                    // print as the number it is instead of being dereferenced.
                    if !self.expr_leaves_tag_in_r11(expr) {
                        self.emit_indent(&format!(
                            "mov r11, {}  ; value tag (integer default: no tag in r11)",
                            TAG_INTEGER
                        ));
                    }
                }
            },
        }
    }

    /// Emit an in-place cast of a `value` variable: load the runtime tag,
    /// dispatch on it to the conversion that already exists for that source
    /// type, store the converted payload back, and update the shadow tag slot.
    /// On an unconvertible source tag or a failed text-to-number/float parse,
    /// set `_last_error` and leave the payload at 0.
    pub(crate) fn emit_value_retype(&mut self, name: &str, target_type: &Type) {
        let target_tag = match target_type {
            Type::Integer => TAG_INTEGER,
            Type::Float => TAG_FLOAT,
            Type::String => TAG_STRING,
            Type::Boolean => TAG_BOOLEAN,
            _ => {
                self.emit_indent("; value retype to non-scalar target is unsupported");
                self.emit_indent("SET_LAST_ERROR 1");
                return;
            }
        };

        // Locate the payload and tag slots.
        let payload_op = if let Some(offset) = self.get_var(name) {
            format!("[rbp-{}]", offset)
        } else if let Some(label) = self.global_var_label(name).cloned() {
            format!("[rel {}]", label)
        } else {
            self.emit_indent("; value retype target variable not found");
            self.emit_indent("SET_LAST_ERROR 1");
            return;
        };
        let tag_loc = match self.mixed_element_tag_slot(&Expr::Identifier(name.to_string())) {
            Some(loc) => loc,
            None => {
                self.emit_indent("; value retype target has no tag slot");
                self.emit_indent("SET_LAST_ERROR 1");
                return;
            }
        };

        let is_text_target = target_tag == TAG_STRING;

        self.emit_indent(&format!(
            "; in-place retype of '{}' to {}",
            name,
            type_noun_name(target_type)
        ));

        // Load payload and tag.
        self.emit_indent(&format!("mov rax, {}  ; value payload", payload_op));
        self.emit_load_value_tag(&Expr::Identifier(name.to_string()));

        let l_int = self.new_label("vr_int");
        let l_flt = self.new_label("vr_flt");
        let l_str = self.new_label("vr_str");
        let l_bool = self.new_label("vr_bool");
        let l_fail = self.new_label("vr_fail");
        let l_store = self.new_label("vr_store");
        let l_done = self.new_label("vr_done");

        self.emit_indent(&format!("cmp r11, {}  ; integer?", TAG_INTEGER));
        self.emit_indent(&format!("je {}", l_int));
        self.emit_indent(&format!("cmp r11, {}  ; float?", TAG_FLOAT));
        self.emit_indent(&format!("je {}", l_flt));
        self.emit_indent(&format!("cmp r11, {}  ; string/text?", TAG_STRING));
        self.emit_indent(&format!("je {}", l_str));
        self.emit_indent(&format!("cmp r11, {}  ; boolean?", TAG_BOOLEAN));
        self.emit_indent(&format!("je {}", l_bool));
        // list/map/nothing fall through to failure
        self.emit_indent(&format!("jmp {}", l_fail));

        // ---- integer source ----
        self.emit(&format!("{}:", l_int));
        match target_tag {
            TAG_INTEGER => {
                self.emit_indent("; integer -> integer (no-op)");
            }
            TAG_FLOAT => {
                self.emit_indent("; integer -> float");
                self.emit_indent("cvtsi2sd xmm0, rax");
                self.emit_indent("XMM0_TO_RAX");
                self.uses_floats = true;
            }
            TAG_STRING => {
                self.emit_indent("; integer -> text");
                self.stack_offset += 8;
                let tmp = self.stack_offset;
                self.uses_buffers = true;
                self.emit_indent("push rax  ; integer to format");
                self.emit_indent("mov rdi, 1024");
                self.emit_indent("call _alloc_buffer");
                self.emit_indent(&format!("mov [rbp-{}], rax  ; format buffer", tmp));
                self.emit_indent(&format!("mov rdi, [rbp-{}]", tmp));
                self.emit_indent("pop rax  ; restore integer");
                self.emit_indent("mov rsi, rax");
                self.emit_indent("xor rdx, rdx");
                self.emit_indent("xor rcx, rcx");
                self.emit_indent("xor r8, r8");
                self.emit_indent("xor r9, r9");
                self.emit_indent("call _buffer_append_formatted_int");
                self.emit_indent(&format!("mov rax, [rbp-{}]", tmp));
                self.emit_indent("BUFFER_DATA_ADDR rax  ; buffer data area");
            }
            TAG_BOOLEAN => {
                self.emit_indent("; integer -> boolean");
                self.emit_indent("BOOL_FROM_RAX");
            }
            _ => unreachable!(),
        }
        self.emit_indent(&format!("mov r11b, {}  ; new tag", target_tag));
        self.emit_indent(&format!("jmp {}", l_done));

        // ---- float source ----
        self.emit(&format!("{}:", l_flt));
        match target_tag {
            TAG_INTEGER => {
                self.emit_indent("; float -> integer");
                self.emit_indent("RAX_TO_XMM0");
                self.emit_indent("cvttsd2si rax, xmm0");
                self.uses_floats = true;
            }
            TAG_FLOAT => {
                self.emit_indent("; float -> float (no-op)");
            }
            TAG_STRING => {
                self.emit_indent("; float -> text");
                self.stack_offset += 8;
                let tmp = self.stack_offset;
                self.uses_buffers = true;
                self.uses_floats = true;
                self.emit_indent("push rax  ; float bits to format");
                self.emit_indent("mov rdi, 1024");
                self.emit_indent("call _alloc_buffer");
                self.emit_indent(&format!("mov [rbp-{}], rax  ; format buffer", tmp));
                self.emit_indent(&format!("mov rdi, [rbp-{}]", tmp));
                self.emit_indent("pop rax  ; restore float bits");
                self.emit_indent("call _buffer_append_float");
                self.emit_indent(&format!("mov rax, [rbp-{}]", tmp));
                self.emit_indent("BUFFER_DATA_ADDR rax  ; buffer data area");
            }
            TAG_BOOLEAN => {
                self.emit_indent("; float -> boolean");
                self.emit_indent("BOOL_FROM_RAX");
            }
            _ => unreachable!(),
        }
        self.emit_indent(&format!("mov r11b, {}  ; new tag", target_tag));
        self.emit_indent(&format!("jmp {}", l_done));

        // ---- string/text source ----
        self.emit(&format!("{}:", l_str));
        match target_tag {
            TAG_INTEGER => {
                self.emit_indent("; text -> number");
                self.uses_ints = true;
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _parse_i64");
            }
            TAG_FLOAT => {
                self.emit_indent("; text -> float");
                self.uses_floats = true;
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _parse_f64");
            }
            TAG_STRING => {
                self.emit_indent("; text -> text (no-op)");
            }
            TAG_BOOLEAN => {
                self.emit_indent("; text -> boolean");
                self.uses_strings = true;
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jz {}_str_false", l_bool));
                self.emit_indent("mov rdi, rax");
                self.emit_indent("call _text_to_boolean");
                // rax now holds 1 for "true", 0 for anything else.
                // Skip over the null/failure path so we keep the helper result.
                self.emit_indent(&format!("jmp {}", l_store));
                self.emit(&format!("{}_str_false:", l_bool));
                self.emit_indent("xor rax, rax");
            }
            _ => unreachable!(),
        }
        self.emit(&format!("{}:", l_store));
        self.emit_indent(&format!("mov r11b, {}  ; new tag", target_tag));
        self.emit_indent(&format!("jmp {}", l_done));

        // ---- boolean source ----
        self.emit(&format!("{}:", l_bool));
        match target_tag {
            TAG_INTEGER => {
                self.emit_indent("; boolean -> integer (no-op)");
            }
            TAG_FLOAT => {
                self.emit_indent("; boolean -> float");
                self.emit_indent("cvtsi2sd xmm0, rax");
                self.emit_indent("XMM0_TO_RAX");
                self.uses_floats = true;
            }
            TAG_STRING => {
                self.emit_indent("; boolean -> text");
                let true_label = self.add_string("true");
                let false_label = self.add_string("false");
                let l_true = self.new_label("vr_bool_true");
                let l_bool_done = self.new_label("vr_bool_done");
                self.emit_indent("test rax, rax");
                self.emit_indent(&format!("jnz {}", l_true));
                self.emit_indent(&format!("lea rax, [rel {}]", false_label));
                self.emit_indent(&format!("jmp {}", l_bool_done));
                self.emit(&format!("{}:", l_true));
                self.emit_indent(&format!("lea rax, [rel {}]", true_label));
                self.emit(&format!("{}:", l_bool_done));
            }
            TAG_BOOLEAN => {
                self.emit_indent("; boolean -> boolean (no-op)");
            }
            _ => unreachable!(),
        }
        self.emit_indent(&format!("mov r11b, {}  ; new tag", target_tag));
        self.emit_indent(&format!("jmp {}", l_done));

        // ---- failure (list/map/nothing or future unsupported) ----
        self.emit(&format!("{}:", l_fail));
        self.emit_indent("; unsupported source tag for retype");
        if is_text_target {
            let empty_label = self.add_string("");
            self.emit_indent(&format!("lea rax, [rel {}]  ; empty text on failure", empty_label));
        } else {
            self.emit_indent("xor rax, rax");
        }
        self.emit_indent("SET_LAST_ERROR 1");
        self.emit_indent(&format!("mov r11b, {}  ; new tag", target_tag));

        // ---- store result back ----
        self.emit(&format!("{}:", l_done));
        self.emit_indent(&format!("mov {}, rax  ; updated payload", payload_op));
        self.emit_indent(&format!(
            "mov byte {}, r11b  ; updated tag",
            tag_loc.operand()
        ));
    }

    /// Whether `generate_expr(expr)` leaves the value's runtime tag in r11, so a
    /// consumer can read the tag from r11 without an explicit load. True for:
    /// - a value-returning function call (the callee leaves r11=tag; `call`
    ///   and the epilogue do not clobber it), and
    /// - a freshly-read mixed-list element (`ElementAccess`, or `First`/`Last`
    ///   of a mixed list) — `generate_expr` captures the slot's tag into r11, and
    /// - a `treating` clause over a runtime-tagged subject, which carries the
    ///   subject's own tag (or the replacement's, when the substitution fires)
    ///   through to r11 — see `treating_dispatches_on_runtime_tag`.
    /// Homogeneous reads never reach this question: `emit_time_expr_tag`
    /// returns their static tag (`Some`), so the caller never falls through to
    /// the no-slot path that consults this predicate.
    pub(crate) fn expr_leaves_tag_in_r11(&self, e: &Expr) -> bool {
        match e {
            Expr::FunctionCall { name, .. } => {
                self.function_return_types.get(&self.resolved_call_label(name)) == Some(&VarType::Mixed)
            }
            // Plan 270 G4: a zero-argument function name used as an identifier
            // in expression position emits a call (see `generate_expr`), so a
            // `value`-returning one leaves its result tag in r11 just like a
            // written `Expr::FunctionCall`. Only consult this when the name is
            // NOT a variable — a variable identifier never calls.
            Expr::Identifier(name)
                if self.variables.contains_key(name)
                    || self.global_var_label(name).is_some() =>
            {
                false
            }
            Expr::Identifier(name) => {
                self.zero_arg_func_return_type(name) == Some(VarType::Mixed)
            }
            Expr::ElementAccess { list, .. } | Expr::ListAccess { list, .. } => {
                self.list_expr_is_mixed(list)
            }
            // A map key read: `_map_lookup` leaves the value in rax and its
            // runtime tag in r11 (stage 1e2), mirroring a mixed-list element.
            Expr::MapAccess { .. } => true,
            Expr::PropertyAccess { object, property }
                if matches!(property, ObjectProperty::First | ObjectProperty::Last) =>
            {
                self.mixed_lists.contains(object)
                    || self.list_element_types.get(object) == Some(&VarType::Mixed)
            }
            Expr::TreatingAs { value, match_value, replacement } => {
                self.treating_dispatches_on_runtime_tag(value, match_value, replacement)
            }
            _ => false,
        }
    }

    /// Whether a `treating` clause must dispatch on its subject's runtime tag
    /// rather than on a static type (bug #59).
    ///
    /// A `treating` subject is the loop variable, and over a mixed list, a
    /// map's values, or a `value` it has no static type to dispatch on — only
    /// the per-slot tag LANGUAGE.md:2226-2228 promises ("every element prints
    /// and reads back as what it is"). Reporting the subject's static type
    /// there made the comparison a raw pointer `cmp` (so a text element never
    /// matched a text match) and left the result untagged (so Print rendered a
    /// text element's address as an integer) — for every element, including
    /// the ones the clause never matched.
    ///
    /// All three operands must carry a tag - the match's is what the
    /// subject's is compared against, and the replacement's is the tag the
    /// result carries when the substitution fires - but the tag may now be a
    /// runtime one on any of them (bug #69), not only on the subject. Without
    /// a tag somewhere for each there is nothing to dispatch on and the static
    /// path stands; when every tag is known at emit time the static path is
    /// already right, so the tagged path is reserved for the case where at
    /// least one of the three is only known at runtime. This predicate is the
    /// single condition under which `generate_expr` emits the tagged path, so
    /// it is also exactly when the result leaves its tag in r11.
    pub(crate) fn treating_dispatches_on_runtime_tag(
        &self,
        value: &Expr,
        match_value: &Expr,
        replacement: &Expr,
    ) -> bool {
        let (Some(subject), Some(matched), Some(replaced)) = (
            self.treating_subject_tag(value),
            self.treating_clause_tag(match_value),
            self.treating_clause_tag(replacement),
        ) else {
            return false;
        };
        [subject, matched, replaced]
            .iter()
            .any(|tag| matches!(tag, ClauseTag::Runtime(_)))
    }

    /// The tag of a `treating` clause's match or replacement: at emit time
    /// where the operand's type is fixed, at runtime where it is a `value`
    /// (bug #69).
    ///
    /// Emit time first, deliberately - a literal or a statically-typed
    /// variable is proven, and asking the runtime what it already knows would
    /// only cost instructions. `None` means the operand carries no tag by
    /// either route, and the clause has nothing to dispatch on.
    pub(crate) fn treating_clause_tag(&self, e: &Expr) -> Option<ClauseTag> {
        match self.emit_time_expr_tag(e) {
            Some(tag) => Some(ClauseTag::Static(tag)),
            None => self.runtime_tag_source(e).map(ClauseTag::Runtime),
        }
    }

    /// The tag of a `treating` clause's subject. Runtime first here, the
    /// mirror image of `treating_clause_tag`: the subject is the loop
    /// variable, and where it has a per-slot tag that tag is the only truth
    /// about what this iteration holds - a static answer would be the wrong
    /// one, which was bug #59.
    ///
    /// A buffer is excluded: its payload is a struct pointer rather than the
    /// bytes, so it compares by `_mem_eq` over the tracked length (a NUL scan
    /// would read stale bytes past the logical end). The tagged path compares
    /// text with `_str_eq`, so a buffer subject keeps the static path that
    /// knows how to reach its data.
    pub(crate) fn treating_subject_tag(&self, e: &Expr) -> Option<ClauseTag> {
        if let Some(src) = self.runtime_tag_source(e) {
            return Some(ClauseTag::Runtime(src));
        }
        if let Expr::Identifier(name) = e {
            if self.variable_types.get(name) == Some(&VarType::Buffer) {
                return None;
            }
        }
        self.emit_time_expr_tag(e).map(ClauseTag::Static)
    }

}
