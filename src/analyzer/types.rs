use super::*;

impl Analyzer {
    /// Resolve a named reference (an `Identifier` or a quoted-name `StringLit`)
    /// to its tracked category. Buffer/list/file/timer/flag are detected from
    /// their dedicated sets; otherwise the dynamic `scalar_types` map supplies
    /// the current number/float/text/boolean category. Returns None for an
    /// unknown or untracked name (treated as "allow" by the arithmetic check to
    /// avoid false positives).
    pub(crate) fn named_value_type(&self, name: &str) -> Option<Type> {
        if self.is_buffer_variable(name) {
            Some(Type::Buffer)
        } else if self.is_list_variable(name) {
            Some(Type::List(Box::new(Type::Unknown)))
        } else if self.is_map_variable(name) {
            Some(Type::Map(Box::new(Type::Unknown)))
        } else if self.file_variables.contains(name) {
            Some(Type::File)
        } else if self.timer_variables.contains(name) {
            Some(Type::Timer)
        } else if let Some(t) = self.flag_variables.get(name) {
            // A flag answers with the type it was DECLARED with. This used
            // to hardcode Boolean, so `it is a text` / `it is a number`
            // flags were mis-typed everywhere this path is consulted -
            // which is every read inside a function body (#32).
            Some(t.clone())
        } else {
            self.scalar_types.get(name).cloned()
        }
    }

    /// Classify an expression's value category for the arithmetic type check.
    /// Returns the type, or None when it cannot be determined statically
    /// (function calls, property/element/byte access) - None means "allow",
    /// biasing against false positives. A bare text literal or a text variable
    /// resolves to `Type::String`; a cast resolves to its target type, so
    /// `s as a number` is accepted while bare `s` (text) is rejected.
    pub(crate) fn arithmetic_operand_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::IntegerLit(_)
            | Expr::LastError
            | Expr::ArgumentCount
            | Expr::EnvironmentVariableCount => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::BoolLit(_) => Some(Type::Boolean),
            Expr::StringLit(s) => {
                // A quoted name may reference a variable; otherwise this is a
                // bare text literal, which is not valid in arithmetic.
                if let Some(t) = self.scalar_types.get(s) {
                    if !matches!(t, Type::Value) {
                        return Some(t.clone());
                    }
                }
                if self.value_typed_names.contains(s) {
                    Some(Type::Value)
                } else {
                    self.named_value_type(s).or(Some(Type::String))
                }
            }
            Expr::FormatString { .. } => Some(Type::String),
            Expr::Identifier(name) => {
                // A `value`-typed name that has been explicitly retyped
                // (`v is a number.`) carries the concrete target type in
                // `scalar_types`; prefer that so arithmetic works after the
                // retype while the variable remains a `value` for all other
                // purposes (type lock, tag slot, etc.).
                if let Some(t) = self.scalar_types.get(name) {
                    if !matches!(t, Type::Value) {
                        return Some(t.clone());
                    }
                }
                // A `value`-typed name is dynamic: reject it from arithmetic
                // until the author checks its type with a predicate (stage 1c).
                if self.value_typed_names.contains(name) {
                    Some(Type::Value)
                } else {
                    self.named_value_type(name)
                }
            }
            Expr::Cast { target_type, .. } => Some(target_type.clone()),
            Expr::DurationCast { .. } => Some(Type::Integer),
            Expr::UnaryOp { op, operand } => match op {
                UnaryOperator::Negate => self.arithmetic_operand_type(operand),
                UnaryOperator::Not => Some(Type::Boolean),
            },
            Expr::BinaryOp { op, left, right } => match op {
                BinaryOperator::Equal
                | BinaryOperator::NotEqual
                | BinaryOperator::Greater
                | BinaryOperator::Less
                | BinaryOperator::GreaterEqual
                | BinaryOperator::LessEqual
                | BinaryOperator::And
                | BinaryOperator::Or => Some(Type::Boolean),
                _ => {
                    // Arithmetic result: float if either operand is float, else
                    // integer. Nested operands are checked separately when
                    // analyze_expr recurses into them.
                    if matches!(self.arithmetic_operand_type(left), Some(Type::Float))
                        || matches!(self.arithmetic_operand_type(right), Some(Type::Float))
                    {
                        Some(Type::Float)
                    } else {
                        Some(Type::Integer)
                    }
                }
            },
            // Plan 294 findings 4, 14: only resolvable when the map's own
            // literal initializer proved a single value type (see
            // `map_value_type`) - a map declared with a non-literal
            // initializer, an empty literal, or a literal with mixed value
            // types falls through to `None`, same "can't prove it, allow
            // it" policy as everywhere else in this function.
            Expr::MapAccess { map, .. } => self.map_value_type.get(map).cloned(),
            // Bug #54: a read of one element out of a collection. The type
            // is the element type when the list's own literal initializer
            // proved one (`list_element_type`) and nothing can widen the
            // list; unprovable lists answer `None` and stay allowed, the
            // same policy the `MapAccess` arm above follows. A byte is a
            // number by construction, whatever buffer it came out of.
            Expr::ElementAccess { list, .. } | Expr::ListAccess { list, .. } => {
                match list.as_ref() {
                    Expr::Identifier(name) => self.list_element_type_of(name),
                    _ => None,
                }
            }
            Expr::PropertyAccess { object, property: ObjectProperty::First }
            | Expr::PropertyAccess { object, property: ObjectProperty::Last } => {
                self.list_element_type_of(object)
            }
            Expr::ByteAccess { .. } => Some(Type::Integer),
            _ => None,
        }
    }

    /// A short, human-readable label for an operand, used in error messages.
    pub(crate) fn operand_label(&self, expr: &Expr) -> String {
        match expr {
            Expr::Identifier(name) => name.clone(),
            Expr::StringLit(s) => {
                if self.is_variable_available(s) {
                    s.clone()
                } else {
                    format!("\"{}\"", s)
                }
            }
            _ => "this value".to_string(),
        }
    }

    /// Reject text/buffer/list/file/timer operands in arithmetic. Without an
    /// explicit cast these compile to pointer/handle arithmetic and produce
    /// garbage at runtime; a cast (`s as a number`) routes through atoi/atof
    /// and is accepted because `arithmetic_operand_type` resolves it to a
    /// numeric type.
    pub(crate) fn check_arithmetic_operand(&mut self, expr: &Expr) {
        // `nothing` has no numeric value. It is not a `Type` (tag 6 exists
        // only at runtime), so it is matched here rather than through
        // `arithmetic_operand_type`. Unchecked it compiles to its payload, 0,
        // so `total add missing` silently yields `total` - a wrong number that
        // looks right, which is the failure this whole track exists to stop.
        // Operands that only turn out to be nothing at runtime cannot be
        // caught here; those set the error flag instead (see
        // `emit_nothing_operand_check` in codegen).
        if matches!(expr, Expr::NothingLit) {
            self.push_error(
                "Cannot use nothing in arithmetic; check it with 'is nothing' first."
                    .to_string(),
                None,
            );
            return;
        }
        let Some(ty) = self.arithmetic_operand_type(expr) else {
            return;
        };
        let label = self.operand_label(expr);
        let msg = match ty {
            Type::String => format!(
                "Cannot use text {} in arithmetic; cast it first with 'as a number' or 'as a float'.",
                label
            ),
            Type::Buffer => format!(
                "Cannot use buffer {} in arithmetic; cast it with 'as a number' to read its content.",
                label
            ),
            Type::List(_) => format!("Cannot use list {} in arithmetic.", label),
            Type::Map(_) => format!("Cannot use map {} in arithmetic.", label),
            Type::File => format!("Cannot use file {} in arithmetic.", label),
            Type::Timer => format!("Cannot use timer {} in arithmetic.", label),
            // Deliberately naming no escape hatch, after two rounds of
            // getting this wrong: "check its type with 'is a number'
            // first" was a dead end (a type-predicate guard does not
            // narrow the type inside its own body - still rejected there
            // too), and "convert it explicitly with 'as a number'" was
            // ALSO a dead end once finding 21's fix made exactly that cast
            // a compile error (plan 294 finding 21 - casting a
            // dynamically-tagged value doesn't dispatch on the runtime tag
            // in codegen, so it used to silently compute garbage; rejecting
            // it was the fix, but this message kept sending people to it
            // anyway). This is the value-typed case by construction - it
            // is the ONLY way this branch fires - so every occurrence of
            // this message hits both dead ends the same way, every time.
            // There is currently no supported way to use a dynamically-
            // tagged value in arithmetic; say only that, since a plausible-
            // sounding but unverified alternative is worse than none (that
            // is exactly how the previous two wordings went wrong).
            Type::Value => format!(
                "Cannot use a value {} in arithmetic: its type is only known at runtime, and arithmetic on a dynamically-tagged value is not currently supported.",
                label
            ),
            _ => return,
        };
        self.push_error(msg, None);
    }

    /// Bug #40: `Write` hands its operand to FILE_WRITE_STR, which reads it as
    /// a pointer to text. A text or a buffer holds one, so both write their
    /// contents; a number, float, or boolean holds a value, and that value
    /// gets used as an address - `Write n to out` with n = 72 reads address
    /// 72 and segfaults the generated program. LANGUAGE.md documents `Write`
    /// for text, buffers, and format strings, so a bare scalar is refused
    /// here instead, the way `append` refuses a number source. Rendering a
    /// scalar directly is a language decision that has not been taken; the
    /// message names the spelling that works today, `Write "{n}" to out`.
    ///
    /// Only a named operand is judged. The parser admits a string literal, a
    /// format string, an identifier, or a `treating ... as ...` wrapper round
    /// one - the first two are text by construction. A name it cannot resolve
    /// answers None and is allowed through, the same "can't prove it, allow
    /// it" policy `check_arithmetic_operand` follows.
    pub(crate) fn check_file_write_operand(&mut self, file: &str, value: &Expr) {
        let operand = match value {
            Expr::TreatingAs { value, .. } => value.as_ref(),
            other => other,
        };
        let Expr::Identifier(name) = operand else {
            return;
        };
        // A `value` name answers through `value_typed_names`, the same
        // precedence `arithmetic_operand_type` uses: a concrete type recorded
        // for the name wins (a retyped value is judged as what it was retyped
        // to), and only an otherwise-unresolved dynamic name reads as Value.
        let ty = match self.named_value_type(name) {
            Some(Type::Value) | None if self.value_typed_names.contains(name) => Type::Value,
            Some(t) => t,
            None => return,
        };
        let message = match ty {
            Type::Integer | Type::Float | Type::Boolean => format!(
                "Cannot write {} {} to a file; Write takes text, a buffer, or a \
                 format string. Render it as text: Write \"{{{}}}\" to {}.",
                self.type_name(&ty),
                name,
                name,
                file,
            ),
            // A value crashes the same way when it holds a number or nothing,
            // and writes correctly when it holds text - which the compiler
            // cannot tell apart, so the whole category goes, as it does in
            // arithmetic. Deliberately NOT suggesting `Write "{v}"` here: on
            // the file-write path that format renders a value's raw payload,
            // so a text-holding value writes its pointer as a decimal number
            // and `nothing` writes 0 (the print path renders both correctly -
            // a separate defect, noted under #40 in the register). Copying
            // into a typed variable is verified to work for both.
            Type::Value => format!(
                "Cannot write value {} to a file; a value's type is only known at \
                 runtime, and Write must know whether it holds text (which it \
                 writes) or a number (whose value it would use as an address). \
                 Copy it into a typed variable first - 'a text called plain is \
                 {}.' - and write that.",
                name, name,
            ),
            _ => return,
        };
        self.push_error(message, Some(name));
    }

    /// Bug #53: `Return a buffer, <expr>` leaves whatever the expression
    /// evaluates to in rax and the caller reads that as the address of a
    /// buffer struct - capacity at +0, length at +8, bytes from +24. A text
    /// literal's address points at its characters instead, so the caller
    /// reads the eight bytes that follow the string as a length: with one
    /// string in the program those are zeroed `.bss` and the call quietly
    /// answers an EMPTY buffer, and with another string laid down after it
    /// those characters become the length (4.6 MB in the register's repro)
    /// and the copy walks off the end of the mapping (segfault). A text
    /// VARIABLE returns the same kind of address and fails identically.
    ///
    /// A declaration initializer (`a buffer called made is "ABC".`) is the
    /// one place LANGUAGE.md gives text a buffer meaning: it allocates a
    /// buffer and appends the bytes. Nothing promises that conversion in a
    /// return, so the source is refused here and the message names the
    /// spelling that works - the same treatment `Write` gives a scalar
    /// (bug #40). Whether a return should convert the way a declaration does
    /// is a language decision that has not been taken.
    ///
    /// Only a source this can PROVE is not a buffer is refused - a call, a
    /// property read, a `value` name, an unresolved name all answer None and
    /// pass, the same "can't prove it, allow it" policy
    /// `check_arithmetic_operand` follows.
    pub(crate) fn check_buffer_return_source(&mut self, value: &Expr) {
        let ty = match value {
            // A double-quoted literal is text by construction unless the
            // name it spells is a variable in scope (`operand_label` draws
            // the same distinction when it decides whether to quote).
            Expr::StringLit(s) => match self.named_value_type(s) {
                Some(t) if self.is_variable_available(s) => t,
                _ => Type::String,
            },
            Expr::FormatString { .. } => Type::String,
            Expr::IntegerLit(_) => Type::Integer,
            Expr::FloatLit(_) => Type::Float,
            Expr::BoolLit(_) => Type::Boolean,
            // A bare name that resolves to nothing tracked is left alone: a
            // zero-argument function name reads as an identifier here and is
            // a call by the time codegen sees it (plan 270 G4).
            Expr::Identifier(name) => match self.named_value_type(name) {
                Some(t) => t,
                None => return,
            },
            _ => return,
        };
        // A `value` carries its type at runtime, so nothing can be proved
        // about it here. `Unknown` is the same answer wearing a different
        // name, and refusing it would print "Cannot return unknown x as a
        // buffer", which tells the author nothing they can act on.
        if matches!(ty, Type::Buffer | Type::Value | Type::Unknown) {
            return;
        }
        // A buffer declaration is the remedy for every one of these types -
        // `a buffer called made is <text/number/float/boolean>.` allocates a
        // buffer and writes the value's bytes into it (see `check_type_lock`,
        // which lets a buffer destination take any of them). So the message
        // says the same thing whatever was returned, spelled with the source
        // actually written where that can be rendered back faithfully.
        let named = self.type_name(&ty);
        let message = match self.render_buffer_return_source(value) {
            Some(source) => format!(
                "Cannot return {} {} as a buffer; the caller reads what Return \
                 hands back as a buffer, and {} is not one. Build the buffer \
                 first: 'a buffer called made is {}. Return a buffer, made.'",
                named, source, named, source,
            ),
            // A format string (and anything else with no faithful one-line
            // spelling) is described rather than quoted back - fabricating
            // source that would not parse is worse than naming no source at
            // all, the same call `render_value_hint` makes.
            None => format!(
                "Cannot return {} as a buffer; the caller reads what Return hands \
                 back as a buffer, and {} is not one. Build the buffer first - \
                 'a buffer called made is <that {}>.' - and return made.",
                named, named, named,
            ),
        };
        let symbol = match value {
            Expr::Identifier(name) => Some(name.as_str()),
            Expr::StringLit(s) if self.is_variable_available(s) => Some(s.as_str()),
            _ => None,
        };
        self.push_error(message, symbol);
    }

    /// Spell a rejected buffer-return source back the way the author wrote
    /// it, for the "build the buffer first" remedy. `None` means there is no
    /// faithful single-line spelling (a format string, an expression), and
    /// the caller words the message without one.
    fn render_buffer_return_source(&self, value: &Expr) -> Option<String> {
        match value {
            Expr::Identifier(name) => Some(name.clone()),
            Expr::StringLit(s) if self.is_variable_available(s) => Some(s.clone()),
            Expr::StringLit(s) => Some(format!("\"{}\"", s)),
            Expr::IntegerLit(n) => Some(n.to_string()),
            Expr::FloatLit(n) => Some(n.to_string()),
            Expr::BoolLit(b) => Some(if *b { "true".to_string() } else { "false".to_string() }),
            _ => None,
        }
    }

    /// Arithmetic/bitwise operators require numeric operands. Comparisons and
    /// logical and/or are excluded (they are valid across types and handled
    /// elsewhere).
    pub(crate) fn is_arithmetic_op(&self, op: &BinaryOperator) -> bool {
        matches!(
            op,
            BinaryOperator::Add
                | BinaryOperator::Subtract
                | BinaryOperator::Multiply
                | BinaryOperator::Divide
                | BinaryOperator::Modulo
                | BinaryOperator::BitAnd
                | BinaryOperator::BitOr
                | BinaryOperator::BitXor
                | BinaryOperator::ShiftLeft
                | BinaryOperator::ShiftRight
        )
    }

    pub(crate) fn infer_simple_expr_type(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::IntegerLit(_) | Expr::LastError | Expr::ArgumentCount | Expr::EnvironmentVariableCount => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::StringLit(_) | Expr::FormatString { .. }
            | Expr::ArgumentName | Expr::ArgumentFirst | Expr::ArgumentSecond | Expr::ArgumentLast
            | Expr::ArgumentAt { .. } | Expr::EnvironmentVariable { .. }
            | Expr::EnvironmentVariableFirst | Expr::EnvironmentVariableLast
            | Expr::EnvironmentVariableAt { .. } => Some(Type::String),
            Expr::BoolLit(_) | Expr::ArgumentEmpty | Expr::EnvironmentVariableEmpty | Expr::EnvironmentVariableExists { .. }
            | Expr::PropertyCheck { .. } | Expr::TypeCheck { .. } => Some(Type::Boolean),
            Expr::PropertyAccess { property: ObjectProperty::Type, .. } => Some(Type::String),
            Expr::ListLit { .. } | Expr::ArgumentAll | Expr::ArgumentRaw => Some(Type::List(Box::new(Type::Unknown))),
            Expr::MapLit { .. } => Some(Type::Map(Box::new(Type::Unknown))),
            Expr::Identifier(name) => {
                if self.is_buffer_variable(name) {
                    Some(Type::Buffer)
                } else if self.is_list_variable(name) {
                    Some(Type::List(Box::new(Type::Unknown)))
                } else if self.is_map_variable(name) {
                    Some(Type::Map(Box::new(Type::Unknown)))
                } else if let Some(t) = self.flag_variables.get(name) {
                    Some(t.clone())
                } else {
                    None
                }
            }
            Expr::BinaryOp { op, left, right } => {
                match op {
                    BinaryOperator::Equal | BinaryOperator::NotEqual
                    | BinaryOperator::Greater | BinaryOperator::Less
                    | BinaryOperator::GreaterEqual | BinaryOperator::LessEqual
                    | BinaryOperator::And | BinaryOperator::Or => Some(Type::Boolean),
                    _ => {
                        let left_ty = self.infer_simple_expr_type(left);
                        let right_ty = self.infer_simple_expr_type(right);
                        if matches!(left_ty, Some(Type::Float)) || matches!(right_ty, Some(Type::Float)) {
                            Some(Type::Float)
                        } else if matches!(left_ty, Some(Type::Integer)) && matches!(right_ty, Some(Type::Integer)) {
                            Some(Type::Integer)
                        } else {
                            None
                        }
                    }
                }
            }
            Expr::UnaryOp { op, operand } => {
                match op {
                    UnaryOperator::Negate => self.infer_simple_expr_type(operand),
                    UnaryOperator::Not => Some(Type::Boolean),
                }
            }
            Expr::Cast { target_type, .. } => Some(target_type.clone()),
            Expr::DurationCast { .. } => Some(Type::Integer),
            Expr::TreatingAs { value, .. } => self.infer_simple_expr_type(value),
            _ => None,
        }
    }

    pub(crate) fn treating_types_compatible(&self, left: &Type, right: &Type) -> bool {
        matches!(
            (left, right),
            (Type::Integer, Type::Integer)
                | (Type::Float, Type::Float)
                | (Type::String, Type::String)
                | (Type::Boolean, Type::Boolean)
                | (Type::Buffer, Type::Buffer)
                | (Type::File, Type::File)
                | (Type::Time, Type::Time)
                | (Type::Timer, Type::Timer)
                | (Type::List(_), Type::List(_))
                | (Type::Map(_), Type::Map(_))
        )
    }

    /// Classify a list-literal element for the finding-18 homogeneity
    /// check. `None` means "can't prove a single tag" (an identifier,
    /// function call, property/element access, `nothing`, ...) and is
    /// treated as mixed by the caller - matching codegen's own
    /// `TagInfo::Unknowable` policy of widening to mixed rather than
    /// guessing when a value's tag can't be proven statically.
    fn list_element_kind(&self, expr: &Expr) -> Option<Type> {
        match expr {
            Expr::StringLit(_) => Some(Type::String),
            Expr::IntegerLit(_) => Some(Type::Integer),
            Expr::FloatLit(_) => Some(Type::Float),
            Expr::BoolLit(_) => Some(Type::Boolean),
            Expr::ListLit { .. } => Some(Type::List(Box::new(Type::Unknown))),
            Expr::MapLit { .. } => Some(Type::Map(Box::new(Type::Unknown))),
            _ => None,
        }
    }

    /// True iff a list literal's elements don't all share one provable
    /// type - see `list_element_kind` and `list_mixed`.
    pub(crate) fn list_literal_is_mixed(&self, elements: &[Expr]) -> bool {
        let mut seen: Option<Type> = None;
        for e in elements {
            let Some(t) = self.list_element_kind(e) else {
                return true;
            };
            match &seen {
                None => seen = Some(t),
                Some(prev) if !self.treating_types_compatible(prev, &t) => return true,
                Some(_) => {}
            }
        }
        false
    }

    /// The single provable element type shared by every element of a list
    /// literal (bug #54), or `None` for an empty literal, a mixed one, or
    /// any element that isn't a simple literal. The `Some` case is exactly
    /// the complement of `list_literal_is_mixed`'s `true`, read off the
    /// same `list_element_kind` classifier, so the two can never disagree
    /// about which lists are homogeneous.
    pub(crate) fn list_literal_element_type(&self, elements: &[Expr]) -> Option<Type> {
        let mut seen: Option<Type> = None;
        for e in elements {
            let t = self.list_element_kind(e)?;
            match &seen {
                None => seen = Some(t),
                Some(prev) if !self.treating_types_compatible(prev, &t) => return None,
                Some(_) => {}
            }
        }
        seen
    }

    /// The element type a read from `name` yields, or `None` when it is not
    /// provable - because the list's initializer never proved one, because
    /// something in the program can widen or alias the list after its
    /// declaration (`collect_widened_lists`), or because some function
    /// appends to a list it was handed and so could have widened this one
    /// (`any_function_widens_a_parameter`).
    pub(crate) fn list_element_type_of(&self, name: &str) -> Option<Type> {
        if self.functions_widen_lists || self.widened_lists.contains(name) {
            return None;
        }
        self.list_element_type.get(name).cloned()
    }

    /// The single provable value type shared by every pair in a map
    /// literal (keys are always text and don't factor in), or `None` for
    /// an empty map, a mixed one, or a value that isn't a simple literal.
    /// See `map_value_type`'s doc comment for how this is used and its
    /// limits.
    pub(crate) fn map_literal_value_type(&self, pairs: &[(Expr, Expr)]) -> Option<Type> {
        let mut seen: Option<Type> = None;
        for (_, v) in pairs {
            let t = self.list_element_kind(v)?;
            match &seen {
                None => seen = Some(t),
                Some(prev) if !self.treating_types_compatible(prev, &t) => return None,
                Some(_) => {}
            }
        }
        seen
    }

    pub(crate) fn type_name(&self, ty: &Type) -> &'static str {
        match ty {
            Type::Integer => "number",
            Type::Float => "float",
            Type::String => "text",
            Type::Boolean => "boolean",
            Type::List(_) => "list",
            Type::Map(_) => "map",
            Type::Buffer => "buffer",
            Type::File => "file",
            Type::Time => "time",
            Type::Timer => "timer",
            Type::Value => "value",
            // The thing's own name would read better here, but this returns
            // a `&'static str` and the name is owned by the `Type`. No
            // diagnostic reaches a thing yet (definitions declare a type and
            // nothing else); revisit the signature when declarations land.
            Type::Thing(_) => "thing",
            Type::Void => "void",
            Type::Unknown => "unknown",
        }
    }

    /// Render a value expression back into Vox source syntax, for the
    /// "help: convert it explicitly" suggestion. Only handles the simple
    /// literal/identifier shapes that are common in a mismatched assignment;
    /// anything else falls back to a generic placeholder rather than
    /// fabricating source that wouldn't parse.
    fn render_value_hint(&self, expr: &Expr) -> String {
        match expr {
            Expr::StringLit(s) => format!("\"{}\"", s),
            Expr::IntegerLit(n) => n.to_string(),
            Expr::FloatLit(n) => n.to_string(),
            Expr::BoolLit(b) => if *b { "true".to_string() } else { "false".to_string() },
            Expr::Identifier(name) => name.clone(),
            // The collection and buffer reads bug #54 added to
            // `arithmetic_operand_type`: without these the help line for a
            // mismatched element read read `label is <value> as text.`,
            // which is not source anyone can paste.
            Expr::ElementAccess { list, index } | Expr::ListAccess { list, index } => format!(
                "element {} of {}",
                self.render_value_hint(index),
                self.render_value_hint(list)
            ),
            Expr::ByteAccess { buffer, index } => format!(
                "byte {} of {}",
                self.render_value_hint(index),
                self.render_value_hint(buffer)
            ),
            Expr::PropertyAccess { object, property: ObjectProperty::First } => {
                format!("{}'s first", object)
            }
            Expr::PropertyAccess { object, property: ObjectProperty::Last } => {
                format!("{}'s last", object)
            }
            Expr::MapAccess { map, key } => {
                format!("{}'s {}", map, self.render_value_hint(key))
            }
            _ => "<value>".to_string(),
        }
    }

    /// Bug #54: a declaration whose initializer READS one element out of a
    /// collection or a buffer - `a text called label is element 1 of
    /// counts.`, `... is counts's first.`, `... is ages's "bo".`, `... is
    /// byte 1 of raw.` - and whose declared type differs from the element
    /// type the read provably yields. Codegen copies the element's payload
    /// into the variable's slot with no conversion and no tag, so a number
    /// element read into a `text` is then dereferenced as a text pointer
    /// and the program segfaults; the reverse (a text element read into a
    /// `number`) prints the pointer as a decimal number. Both are refused
    /// here, naming the two types, in the shape #40's `Write` operand and
    /// #49's `For each` collection are refused.
    ///
    /// Only the READ forms are judged, and only when the element type is
    /// provable (see `list_element_type_of` / `map_value_type`). This is
    /// deliberately NOT a general declaration-site type check: a
    /// declaration initialised from a plain literal or another variable
    /// (`a text called t is 42.`) is unchecked too, and crashes the same
    /// way, but that is a separate defect of much wider blast radius -
    /// recorded under #54 in docs/BUGS_FOUND.md as its own discrepancy
    /// rather than fixed here.
    ///
    /// Permissive in the same places `check_type_lock` is: a `value`
    /// destination is the language's sanctioned dynamic-type mechanism and
    /// must keep accepting an element of any type, and a `buffer`
    /// destination takes a content write rather than a typed value. A
    /// `thing` destination is excluded too - an initializer there is a
    /// whole-thing copy, which `check_thing_copy` already judges and would
    /// otherwise report twice.
    pub(crate) fn check_declared_read_type(&mut self, name: &str, declared: &Type, value: &Expr) {
        if matches!(declared, Type::Value | Type::Buffer | Type::Thing(_)) {
            return;
        }
        if !matches!(
            value,
            Expr::ElementAccess { .. }
                | Expr::ListAccess { .. }
                | Expr::ByteAccess { .. }
                | Expr::MapAccess { .. }
                | Expr::PropertyAccess { property: ObjectProperty::First, .. }
                | Expr::PropertyAccess { property: ObjectProperty::Last, .. }
        ) {
            return;
        }
        let Some(actual) = self.arithmetic_operand_type(value) else {
            return;
        };
        if matches!(actual, Type::Value) || self.treating_types_compatible(declared, &actual) {
            return;
        }

        // `symbol_error_counts` is deliberately not touched: it indexes
        // WRITE sites for `find_write_site_location`, and this error is
        // anchored on the declaration instead. Bumping it here would make
        // a later type-lock error on the same name underline the wrong
        // line.
        let mut err = CompileError::new(&format!(
            "cannot initialise '{}', which is a {}, with a {} read out of {}",
            name,
            self.type_name(declared),
            self.type_name(&actual),
            self.read_source_label(value)
        ));
        if let Some(loc) = self.find_declaration_location(name) {
            err = err.with_underline_note(
                name.len().max(1),
                &format!("this reads {}", self.typed_phrase(&actual)),
            );
            err = err.with_location(loc);
        }
        err = err.with_note_line(&format!(
            "the read yields a {}, and '{}' is declared as a {}",
            self.type_name(&actual),
            name,
            self.type_name(declared)
        ));
        let hint = self.render_value_hint(value);
        if !hint.contains("<value>") {
            err = err.with_help_line(&format!(
                "declare it as a {} - `a {} called {} is {}.` - or convert it \
explicitly:  a {} called {} is {} as {}.",
                self.type_name(&actual),
                self.type_name(&actual),
                name,
                hint,
                self.type_name(declared),
                name,
                hint,
                if matches!(declared, Type::String) {
                    "text".to_string()
                } else {
                    format!("a {}", self.type_name(declared))
                }
            ));
        }
        self.errors.push(err);
    }

    /// A short label naming what a bug #54 read came out of, for the
    /// diagnostic's first line: the collection or buffer's own name when
    /// the read names one, or a generic noun when it does not.
    fn read_source_label(&self, value: &Expr) -> String {
        match value {
            Expr::ElementAccess { list, .. } | Expr::ListAccess { list, .. } => match list.as_ref() {
                Expr::Identifier(n) => format!("list '{}'", n),
                _ => "a list".to_string(),
            },
            Expr::PropertyAccess { object, .. } => format!("list '{}'", object),
            Expr::MapAccess { map, .. } => format!("map '{}'", map),
            Expr::ByteAccess { buffer, .. } => match buffer.as_ref() {
                Expr::Identifier(n) => format!("buffer '{}'", n),
                _ => "a buffer".to_string(),
            },
            _ => "a collection".to_string(),
        }
    }

    /// Type-lock check: a concretely-typed variable's type is fixed at
    /// declaration and never changes (the language owner's fix for the
    /// whole "tracked type disagrees with runtime type" bug family - see
    /// the plan 293 writeup). Reports a compile error naming the variable,
    /// its declared type, the mismatched type, and the exact cast that
    /// fixes it when `value`'s type is statically known to differ from
    /// `name`'s declared type. Returns true iff an error was reported.
    ///
    /// Deliberately permissive (returns false, i.e. "allow") when:
    /// - `name` is `value`-typed (`self.value_typed_names`): that is the
    ///   language's sanctioned dynamic-type mechanism and must keep
    ///   accepting varying types.
    /// - `name`'s declared type can't be resolved (untracked/unknown name -
    ///   some other check, e.g. unknown-variable, owns that case).
    /// - `value`'s type can't be determined statically (function calls,
    ///   property/element access, etc.) - this mirrors the existing
    ///   `arithmetic_operand_type`/`check_arithmetic_operand` policy of
    ///   biasing against false positives when static inference runs out,
    ///   rather than requiring a full type-inference pass this task did not
    ///   ask for.
    /// - `value`'s type resolves to `Type::Value` (a dynamically-typed
    ///   source flowing into a concretely-typed destination): the runtime
    ///   type isn't known until runtime, so this can't be verified
    ///   statically either, and there is no sanctioned narrowing syntax to
    ///   demand here.
    /// - `name` is a buffer: `X is <value>.` / `Set X to <value>.` on a
    ///   buffer is a content write (format the value's text into the
    ///   buffer), not a type change - a buffer legitimately accepts a
    ///   number, text, or another buffer's contents this way, already
    ///   special-cased throughout the analyzer/codegen (e.g. the
    ///   `is_buffer_variable` exclusions the old `Statement::Assignment`
    ///   arm used before this check replaced it). Locking buffers here
    ///   would reject `a buffer called b is "".` / `b is 42.`, which must
    ///   keep working.
    pub(crate) fn check_type_lock(&mut self, name: &str, value: &Expr) -> bool {
        if self.value_typed_names.contains(name) || self.is_buffer_variable(name) {
            return false;
        }
        let Some(declared) = self.named_value_type(name) else {
            return false;
        };
        let Some(actual) = self.arithmetic_operand_type(value) else {
            return false;
        };
        if matches!(actual, Type::Value) {
            return false;
        }
        if self.treating_types_compatible(&declared, &actual) {
            return false;
        }

        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let mut err = CompileError::new(&format!(
            "cannot assign {} to '{}', which is a {}",
            self.type_name(&actual),
            name,
            self.type_name(&declared)
        ));
        if let Some(loc) = self.find_write_site_location(name, occurrence) {
            err = err.with_underline_note(name.len().max(1), &format!("this assigns {}", self.typed_phrase(&actual)));
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);

        if let Some(decl_loc) = self.declared_locations.get(name) {
            err = err.with_note_line(&format!(
                "'{}' was declared as a {} at {}:{}:{}",
                name,
                self.type_name(&declared),
                decl_loc.file,
                decl_loc.line,
                decl_loc.column
            ));
        } else {
            err = err.with_note_line(&format!("'{}' was declared as a {}", name, self.type_name(&declared)));
        }
        // Canonical Vox cast phrasing (LANGUAGE.md): `as a number` / `as a
        // float` / `as a boolean` / `as a buffer`, but `as text` - no
        // article - specifically for text.
        let cast_target = if matches!(declared, Type::String) {
            "text".to_string()
        } else {
            format!("a {}", self.type_name(&declared))
        };
        err = err.with_help_line(&format!(
            "convert it explicitly:  {} is {} as {}.",
            name,
            self.render_value_hint(value),
            cast_target
        ));
        self.errors.push(err);

        // Poison the tracked type after reporting: the assignment was
        // rejected, so `name` never actually took on the new type, but
        // leaving the OLD type in place would make later, unrelated uses of
        // `name` in this same (already-failing) compile cascade into a
        // second, confusing error about the mistake that was just rejected
        // (e.g. `z is s add 1` after a rejected `Set s to 7` re-flagging `s`
        // as text in arithmetic). The program never reaches codegen once
        // `self.errors` is non-empty, so this only affects which additional
        // diagnostics get reported, not correctness.
        self.scalar_types.remove(name);

        true
    }

    /// `a {} number` / `text` / etc. - the article Vox's own cast syntax
    /// uses (`as a number`, but `as text` with none). Shared by
    /// `check_type_lock` and `bind_variable_type` so both error shapes
    /// agree.
    pub(crate) fn typed_phrase(&self, ty: &Type) -> String {
        if matches!(ty, Type::String) {
            "text".to_string()
        } else {
            format!("a {}", self.type_name(ty))
        }
    }

    /// Statement-level binder for constructs that put a new runtime value
    /// into `name` WITHOUT going through `Statement::Assignment`/`VarDecl`
    /// - a for-range/for-each loop header, `open ... called X`, `Allocate N
    /// for X`. A binding is not an assignment, but plan 294's audit found
    /// six such sites still segfault under a rule enforced only on
    /// assignment, because each one rebinds an existing name to a new
    /// runtime value without updating (or checking) its tracked type. Same
    /// rule, same rejection: if `name` is already declared with a type
    /// incompatible with `new_type`, this is a compile error. If `name` is
    /// new, this call IS the declaration - `new_type` becomes its locked
    /// type, exactly as a `VarDecl` would set it.
    ///
    /// `construct`/`bind_verb` describe the site in the error text (e.g.
    /// "this for-range loop" / "counts with"). `patterns` locate the
    /// binding statement for the caret, tried in order via
    /// `find_bind_site_location`; `guard_against_called` must be `false`
    /// when a pattern itself targets literal `"called X"` syntax (so it
    /// does not exclude its own match - see that function's docs).
    ///
    /// Exempt exactly like `check_type_lock`: `value`-typed names (the
    /// sanctioned dynamic mechanism) and buffers (binding into a buffer is
    /// a content write, not a type change).
    pub(crate) fn bind_variable_type(
        &mut self,
        name: &str,
        new_type: Type,
        construct: &str,
        bind_verb: &str,
        patterns: &[String],
        guard_against_called: bool,
    ) -> bool {
        if self.value_typed_names.contains(name) || self.is_buffer_variable(name) {
            return false;
        }
        let Some(declared) = self.named_value_type(name) else {
            // A brand-new name: this binding is the declaration.
            if matches!(new_type, Type::Integer | Type::Float | Type::Boolean | Type::String) {
                self.scalar_types.insert(name.to_string(), new_type);
            }
            if !self.declared_locations.contains_key(name) {
                if let Some(loc) = self.find_declaration_location(name) {
                    self.declared_locations.insert(name.to_string(), loc);
                }
            }
            return false;
        };
        if self.treating_types_compatible(&declared, &new_type) {
            return false;
        }

        let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
        let mut err = CompileError::new(&format!(
            "cannot bind '{}' to {} in {}; '{}' is already declared as {}",
            name,
            self.typed_phrase(&new_type),
            construct,
            name,
            self.typed_phrase(&declared)
        ));
        if let Some(loc) = self.find_bind_site_location(name, patterns, occurrence, guard_against_called) {
            err = err.with_underline_note(
                name.len().max(1),
                &format!("this {} {}", bind_verb, self.typed_phrase(&new_type)),
            );
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(name.to_string(), occurrence + 1);

        if let Some(decl_loc) = self.declared_locations.get(name) {
            err = err.with_note_line(&format!(
                "'{}' was declared as {} at {}:{}:{}",
                name,
                self.typed_phrase(&declared),
                decl_loc.file,
                decl_loc.line,
                decl_loc.column
            ));
        } else {
            err = err.with_note_line(&format!("'{}' was declared as {}", name, self.typed_phrase(&declared)));
        }
        err = err.with_help_line(&format!(
            "use a different name here, or declare '{}' as {} instead",
            name,
            self.typed_phrase(&new_type)
        ));
        self.errors.push(err);
        self.scalar_types.remove(name);
        true
    }

    /// The type a `treating` clause's subject holds, for the value-vs-match
    /// check below. A plain name is resolved through `named_value_type`
    /// rather than `infer_simple_expr_type`, because the latter answers
    /// None for a scalar name - and `scalar_types` is exactly where an
    /// `each` loop records the element type of the collection it walks. So
    /// long as the check could only see literal subjects, `each item from
    /// ["a"] treating 98 as 31` walked straight past it and the generated
    /// `_str_eq` dereferenced 98 (bug #55).
    ///
    /// A `value`-typed name genuinely holds a different type from one
    /// iteration to the next - a loop over a mixed list is the case that
    /// matters here - so it answers None and is left to the runtime rather
    /// than pinned to whatever type it happened to hold first.
    fn treating_subject_type(&self, expr: &Expr) -> Option<Type> {
        let ty = match expr {
            Expr::Identifier(name) if self.value_typed_names.contains(name.as_str()) => None,
            Expr::Identifier(name) => self.named_value_type(name),
            other => self.infer_simple_expr_type(other),
        };
        ty.filter(|t| !matches!(t, Type::Value | Type::Unknown))
    }

    pub(crate) fn validate_treating_expr(&mut self, value: &Expr, match_value: &Expr, replacement: &Expr) {
        if let (Some(match_ty), Some(replacement_ty)) = (
            self.infer_simple_expr_type(match_value),
            self.infer_simple_expr_type(replacement),
        ) {
            if !self.treating_types_compatible(&match_ty, &replacement_ty) {
                self.push_error(
                    format!(
                        "Treating match and replacement must be the same type (got {} vs {}).",
                        self.type_name(&match_ty),
                        self.type_name(&replacement_ty)
                    ),
                    None,
                );
            }
        }

        if let (Some(value_ty), Some(match_ty)) = (
            self.treating_subject_type(value),
            self.infer_simple_expr_type(match_value),
        ) {
            if !self.treating_types_compatible(&value_ty, &match_ty) {
                // Name the subject when there is one to name: over a loop
                // this is the loop variable, and the type it reports is the
                // element type of the collection being walked, which is the
                // half of the mismatch the author cannot see in the clause
                // itself.
                let subject = match value {
                    Expr::Identifier(name) => Some(name.as_str()),
                    _ => None,
                };
                let hint = subject.map(|name| {
                    format!(
                        "'{}' holds {} here, so it can never equal {} - the substitution would never fire, and comparing the two reads one as the other",
                        name,
                        self.typed_phrase(&value_ty),
                        self.typed_phrase(&match_ty)
                    )
                });
                self.push_error_with_hint(
                    format!(
                        "Treating value and match must be the same type (got {} vs {}).",
                        self.type_name(&value_ty),
                        self.type_name(&match_ty)
                    ),
                    subject,
                    hint.as_deref(),
                );
            }
        }
    }

}
