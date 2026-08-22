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
            Expr::MapAccess { map, .. } => {
                // Bug #72: a read of a key the map's literal provably does
                // NOT have yields the number 0 (LANGUAGE.md:2429), not a
                // value of the map's type - the value type is what the read
                // would have yielded had the key been there. Asked first,
                // because it is the one case where the map's own value type
                // is the wrong answer.
                if self.absent_read_reason(expr).is_some() {
                    return Some(Type::Integer);
                }
                self.map_value_type.get(map).cloned()
            }
            // Bug #54: a read of one element out of a collection. The type
            // is the element type when the list's own literal initializer
            // proved one (`list_element_type`) and nothing can widen the
            // list; unprovable lists answer `None` and stay allowed, the
            // same policy the `MapAccess` arm above follows. A byte is a
            // number by construction, whatever buffer it came out of.
            Expr::ElementAccess { list, .. } | Expr::ListAccess { list, .. } => {
                // Bug #72, as for `MapAccess` above: an index the list's
                // literal provably does not reach reads 0
                // (LANGUAGE.md:2855), whatever the elements are - which is
                // why this is asked even for a mixed literal, where no
                // element type is provable at all.
                if self.absent_read_reason(expr).is_some() {
                    return Some(Type::Integer);
                }
                match list.as_ref() {
                    Expr::Identifier(name) => self.list_element_type_of(name),
                    _ => None,
                }
            }
            Expr::PropertyAccess { object, property: ObjectProperty::First }
            | Expr::PropertyAccess { object, property: ObjectProperty::Last } => {
                // Bug #72: `xs's first` on a list whose literal is empty is
                // the same miss as an out-of-range index.
                if self.absent_read_reason(expr).is_some() {
                    return Some(Type::Integer);
                }
                self.list_element_type_of(object)
            }
            // Bug #74: every OTHER property read used to fall to `_ =>
            // None` below, so `a text called t is xs's length.` proved
            // nothing, #65's declaration and argument checks stayed silent,
            // and codegen stored a list length in a text slot for the first
            // read to dereference. `property_value_type` answers for the
            // properties whose type is fixed by construction, the way the
            // `ByteAccess` arm below is; the ones whose type follows their
            // base keep answering None.
            Expr::PropertyAccess { property, .. } => Self::property_value_type(property),
            Expr::ByteAccess { .. } => Some(Type::Integer),
            _ => None,
        }
    }

    /// Bug #74: the type a `'s <property>` read yields, for the properties
    /// whose answer is the same type whatever the base is - `xs's length`
    /// is a number on a list, a map, a buffer and a file alike, which is
    /// what the manual's four property tables say and what codegen emits.
    /// `None` is the same "can't prove it, allow it" answer the rest of
    /// `arithmetic_operand_type` gives, and it is what the properties whose
    /// type follows their BASE get: `first`/`last` are the list's element
    /// type (`list_element_type_of` resolves those in the arm above), and
    /// `absolute` is a float for a float. A timer's `duration`/`elapsed`
    /// are a Duration - not a `Type`, and read only through a unit cast
    /// (LANGUAGE.md's Timer Properties table) - so they stay unproven too.
    fn property_value_type(property: &ObjectProperty) -> Option<Type> {
        match property {
            // Measurements. LANGUAGE.md's List, Buffer, File, Time and
            // Timer property tables all type these Number, and every one
            // of them leaves codegen with a plain integer in rax.
            ObjectProperty::Size
            | ObjectProperty::Capacity
            | ObjectProperty::Descriptor
            | ObjectProperty::Modified
            | ObjectProperty::Accessed
            | ObjectProperty::Permissions
            | ObjectProperty::Sign
            | ObjectProperty::Hour
            | ObjectProperty::Minute
            | ObjectProperty::Second
            | ObjectProperty::Day
            | ObjectProperty::Month
            | ObjectProperty::Year
            | ObjectProperty::Unix
            | ObjectProperty::StartTime
            | ObjectProperty::EndTime => Some(Type::Integer),
            // Questions. The same tables type these Boolean, and codegen
            // leaves 0 or 1 in rax for each.
            ObjectProperty::Empty
            | ObjectProperty::Full
            | ObjectProperty::Readable
            | ObjectProperty::Writable
            | ObjectProperty::Even
            | ObjectProperty::Odd
            | ObjectProperty::Positive
            | ObjectProperty::Negative
            | ObjectProperty::Zero
            | ObjectProperty::Running => Some(Type::Boolean),
            // A map's keys and values are freshly built lists. The element
            // type is deliberately not claimed here - a list is all
            // `treating_types_compatible` asks a list destination for.
            ObjectProperty::Keys | ObjectProperty::Values => {
                Some(Type::List(Box::new(Type::Unknown)))
            }
            // The universal property reports the variable's declared type
            // as text ("Number (static)").
            ObjectProperty::Type => Some(Type::String),
            // Typed by their base, not by the property.
            ObjectProperty::First
            | ObjectProperty::Last
            | ObjectProperty::Absolute
            | ObjectProperty::Duration
            | ObjectProperty::Elapsed => None,
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

    /// How many elements `name`'s own literal initializer wrote, or `None`
    /// when the length is no longer provable. The guard is
    /// `list_element_type_of`'s, for the same reason: an `Append` makes the
    /// list longer, so "index N is past the end" only holds while nothing
    /// in the program can grow or alias it (bug #72).
    pub(crate) fn list_literal_len_of(&self, name: &str) -> Option<usize> {
        if self.functions_widen_lists || self.widened_lists.contains(name) {
            return None;
        }
        self.list_literal_len.get(name).copied()
    }

    /// The complete key set `name`'s own map literal wrote, or `None` when
    /// it is not provable - no literal initializer, a key that was not a
    /// string literal, some `Set <name>'s "k" to <value>.` that can insert
    /// into it, some function that inserts into a map it was handed, or a
    /// copy/call that can alias it. `widened_lists` answers that last one
    /// for maps as well as lists: the scan behind it is name-keyed and
    /// type-blind, so it collects every name copied into or out of a
    /// variable, returned, or passed to a call (bug #72).
    pub(crate) fn map_literal_keys_of(&self, name: &str) -> Option<&HashSet<String>> {
        if self.functions_write_map_keys
            || self.map_key_writers.contains(name)
            || self.widened_lists.contains(name)
        {
            return None;
        }
        self.map_literal_keys.get(name)
    }

    /// Bug #72: whether the number 0 that an absent read yields fits a slot
    /// declared as `declared`.
    ///
    /// A `number` holds 0. A `float` holds it as +0.0 - the same bit
    /// pattern, and the declaration check already rules a number and a
    /// float "one family" (`initialiser_type_is_refused`). A `boolean`
    /// holds it as false: Vox represents a boolean as 0/1 and prints it
    /// that way, and `examples/lists.vox` has read an out-of-range element
    /// into a boolean since long before this entry.
    ///
    /// A `text`, `list` or `map` slot holds a POINTER, and 0 as an address
    /// is the segfault this entry is about. Those are the only
    /// destinations a proven miss is refused into. (`value`, `buffer` and
    /// `thing` never reach here - `check_declared_read_type` excuses them
    /// before any of this.)
    fn absent_zero_fits(declared: &Type) -> bool {
        matches!(declared, Type::Integer | Type::Float | Type::Boolean)
    }

    /// Bug #72: true when `value` is a read the collection's own literal
    /// proves MISSES and `declared` is a slot that can hold the number 0
    /// such a read yields.
    ///
    /// Every declaration-shaped check consults this one predicate - #54's
    /// read check (`check_declared_read_type`), the type lock
    /// (`check_type_lock`), and #65's initialiser, argument and return
    /// checks - so a proven miss is judged in exactly one place. Without
    /// it, typing the miss `number` (which it is) would newly refuse the
    /// `boolean` and `float` destinations that have always compiled and
    /// always answered `false` and `0.0` - including
    /// `examples/lists.vox:27`.
    pub(crate) fn absent_read_fits(&self, declared: &Type, value: &Expr) -> bool {
        Self::absent_zero_fits(declared) && self.absent_read_reason(value).is_some()
    }

    /// Bug #72: whether a collection read provably asks for something the
    /// collection's own literal does not contain - a map key the literal
    /// never wrote, or a list index past the literal's last element - and
    /// if so, why, phrased for the diagnostic's `note:` line.
    ///
    /// The manual says what such a read yields, and it is not a value of
    /// the collection's type. LANGUAGE.md:2429: "A missing key does not
    /// crash: the lookup yields the number 0 and sets the error flag".
    /// LANGUAGE.md:2857: "Out-of-bounds access sets an error flag and
    /// returns the number 0". It writes the shape itself twice -
    /// `a number called x is m's "never_set".`
    /// (:2758) and `a number called bad is element 100 of items.` (:2863) -
    /// and both times the destination is a `number`, because 0 is a number.
    ///
    /// So where absence is provable the read's static type is `number`,
    /// whatever the collection holds. Without this, `arithmetic_operand_type`
    /// answered with the collection's value type, which made #54's check
    /// refuse the manual's own idiom into a `number` and recommend the
    /// `text` spelling - the one destination that then dereferences 0 as a
    /// pointer and segfaults.
    ///
    /// Provable means all of: the collection was declared with a literal
    /// whose keys (or length) are known; the key or index written in the
    /// read is itself a literal; and nothing in the whole program can add
    /// to the collection or alias it. Anything less answers `None`, which
    /// leaves the behaviour exactly as it was - the same "can't prove it,
    /// allow it" policy as everywhere else in this file.
    ///
    /// The literal shapes themselves come from
    /// `collect_literal_collection_shapes`, which runs before the walk and
    /// offers a shape only for a name the program declares exactly once -
    /// see its doc comment for why an absence proof, unlike #54's element
    /// type, cannot be recorded as the walk reaches each declaration.
    pub(crate) fn absent_read_reason(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::MapAccess { map, key } => {
                let Expr::StringLit(key) = key.as_ref() else {
                    return None;
                };
                let keys = self.map_literal_keys_of(map)?;
                if keys.contains(key.as_str()) {
                    return None;
                }
                Some(format!(
                    "map '{}' has no key \"{}\", and a missing key yields the number 0 \
and sets the error flag",
                    map, key
                ))
            }
            Expr::ElementAccess { list, index } | Expr::ListAccess { list, index } => {
                let Expr::Identifier(name) = list.as_ref() else {
                    return None;
                };
                let Expr::IntegerLit(n) = index.as_ref() else {
                    return None;
                };
                let len = self.list_literal_len_of(name)?;
                // Lists are 1-indexed (LANGUAGE.md's element access), so
                // anything below 1 is as out of range as anything past the
                // end.
                if *n >= 1 && (*n as u64) <= len as u64 {
                    return None;
                }
                Some(format!(
                    "list '{}' has {} element{}, so element {} is out of range, and an \
out-of-range read yields the number 0 and sets the error flag",
                    name,
                    len,
                    if len == 1 { "" } else { "s" },
                    n
                ))
            }
            Expr::PropertyAccess {
                object,
                property: ObjectProperty::First | ObjectProperty::Last,
            } => {
                if self.list_literal_len_of(object)? != 0 {
                    return None;
                }
                Some(format!(
                    "list '{}' is empty, so there is nothing to read, and the read \
yields the number 0 and sets the error flag",
                    object
                ))
            }
            _ => None,
        }
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

    /// Bug #74: how to spell a property back as Vox source, for
    /// `render_value_hint`. One word each, except `size`/`length`, which
    /// are the same property under two names: the manual leads with
    /// `length` for a list and a map (and calls `'s length` the canonical
    /// possessive) and with `size` for a buffer and a file, so the hint is
    /// spelled the way the author's own base is documented rather than
    /// swapping their word for its synonym.
    fn property_word(&self, object: &str, property: &ObjectProperty) -> &'static str {
        match property {
            ObjectProperty::Size => {
                if self.is_list_variable(object) || self.is_map_variable(object) {
                    "length"
                } else {
                    "size"
                }
            }
            ObjectProperty::Capacity => "capacity",
            ObjectProperty::Empty => "empty",
            ObjectProperty::Full => "full",
            ObjectProperty::Descriptor => "descriptor",
            ObjectProperty::Modified => "modified",
            ObjectProperty::Accessed => "accessed",
            ObjectProperty::Permissions => "permissions",
            ObjectProperty::Readable => "readable",
            ObjectProperty::Writable => "writable",
            ObjectProperty::First => "first",
            ObjectProperty::Last => "last",
            ObjectProperty::Keys => "keys",
            ObjectProperty::Values => "values",
            ObjectProperty::Absolute => "absolute",
            ObjectProperty::Sign => "sign",
            ObjectProperty::Even => "even",
            ObjectProperty::Odd => "odd",
            ObjectProperty::Positive => "positive",
            ObjectProperty::Negative => "negative",
            ObjectProperty::Zero => "zero",
            ObjectProperty::Hour => "hour",
            ObjectProperty::Minute => "minute",
            ObjectProperty::Second => "second",
            ObjectProperty::Day => "day",
            ObjectProperty::Month => "month",
            ObjectProperty::Year => "year",
            ObjectProperty::Unix => "unix",
            ObjectProperty::Duration => "duration",
            ObjectProperty::Elapsed => "elapsed",
            ObjectProperty::StartTime => "start time",
            ObjectProperty::EndTime => "end time",
            ObjectProperty::Running => "running",
            ObjectProperty::Type => "type",
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
            // A whole-valued float renders as `8`, which is a NUMBER
            // literal - pasting the help line's suggestion back would then
            // be rejected as a number where a float belongs (bug #65). Vox
            // recognizes a float by its decimal point (LANGUAGE.md:1803),
            // so keep one.
            Expr::FloatLit(n) => {
                let rendered = n.to_string();
                if rendered.contains(['.', 'e', 'E', 'n', 'i']) {
                    rendered
                } else {
                    format!("{}.0", rendered)
                }
            }
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
            // Bug #74 widened this from `first`/`last` to every property,
            // because #74 widened what the oracle can prove: without it the
            // help line for `a text called t is xs's length.` read `t is
            // <value> as text.`, which is not source anyone can paste.
            // `current time's hour` parses with a synthetic object name, so
            // it is spelled back the way it was written, and a multi-word
            // name gets the quotes it needs to be a name at all
            // (`'job timer''s start time`).
            Expr::PropertyAccess { object, property } => {
                let base = if object == "_current_time" {
                    "current time".to_string()
                } else if object.contains(char::is_whitespace) {
                    format!("'{}'", object)
                } else {
                    object.clone()
                };
                format!("{}'s {}", base, self.property_word(object, property))
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
    pub(crate) fn check_declared_read_type(&mut self, name: &str, declared: &Type, value: &Expr) -> bool {
        if matches!(declared, Type::Value | Type::Buffer | Type::Thing(_)) {
            return false;
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
            return false;
        }
        let Some(actual) = self.arithmetic_operand_type(value) else {
            return false;
        };
        // Bug #72: a read the collection's own literal proves MISSES yields
        // the number 0, not a value of the collection's type - so it is
        // judged by what can hold 0, not by whether `number` happens to be
        // the destination's spelling. See `absent_zero_fits`.
        if self.absent_read_fits(declared, value) {
            return false;
        }
        if matches!(actual, Type::Value) || self.treating_types_compatible(declared, &actual) {
            return false;
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
        // Bug #72: the read provably MISSES - an absent map key, an index
        // past the literal's end, a `first` on an empty literal. It still
        // yields a number, so it is still refused into a text/list/map
        // slot, but the reason is not "the collection holds numbers" and
        // the help line must not send the author to the destination type
        // that dereferences 0 as a pointer. Say what actually happens, and
        // point at the destination the manual itself uses for this idiom
        // (LANGUAGE.md:2756, :2859).
        let absent = self.absent_read_reason(value);
        let underline = match &absent {
            Some(_) => "this reads the number 0".to_string(),
            None => format!("this reads {}", self.typed_phrase(&actual)),
        };
        if let Some(loc) = self.find_declaration_location(name) {
            err = err.with_underline_note(name.len().max(1), &underline);
            err = err.with_location(loc);
        }
        if let Some(reason) = &absent {
            err = err.with_note_line(reason);
            let hint = self.render_value_hint(value);
            if !hint.contains("<value>") {
                err = err.with_help_line(&format!(
                    "declare it as a number - `a number called {} is {}.` - and catch \
the miss with `on error`",
                    name, hint
                ));
            }
            self.errors.push(err);
            return true;
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
        true
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

    /// Bug #57: `nothing` is not a value any concretely-typed variable can
    /// hold, so it is refused wherever the literal is written into one.
    ///
    /// LANGUAGE.md:2659-2661 says where the literal may sit - it "can sit in
    /// a list slot, a map value, or a `value` parameter or return" - and the
    /// bare-`Create` defaults table (LANGUAGE.md:489-501) hands `nothing` to
    /// `value` alone, giving `text`, `list` and `map` the empty string, `[]`
    /// and `{}` instead. A concretely-typed slot therefore has no
    /// representation for it. Vox wrote one anyway: codegen's
    /// `Expr::NothingLit` arm materialises the payload, 0, and the tag that
    /// says "this is nothing" is only stored where a `value`, a list slot or
    /// a map slot has a place to put it. So a `text` took a null pointer, a
    /// `list` a header at address 0, a `map` a map at 0 - and the next read
    /// dereferenced it (SIGSEGV). `number`, `float`, `boolean` and `buffer`
    /// do not fault; they answer `0`, which is the other half of the same
    /// mistake and the one LANGUAGE.md:2685 names outright: "`nothing` is
    /// not zero".
    ///
    /// Refused rather than guarded in codegen because there is nothing to
    /// guard: the manual gives these types no `nothing` to print or compare
    /// against, and inventing one - "a text holding nothing prints
    /// `nothing`" - would add a second inhabitant to every concrete type
    /// that the manual does not describe, and would make `is nothing` a
    /// meaningful question about a `text`. `value` is exactly the type for a
    /// slot that may be absent, and it already works.
    ///
    /// `Type::Value` is the sanctioned home and is allowed through.
    /// `Type::Thing` is left to `check_thing_copy`, which owns every write
    /// into a thing's storage; `Void`/`Unknown` name no storage to reject.
    pub(crate) fn nothing_is_refused_for(declared: &Type) -> bool {
        matches!(
            declared,
            Type::Integer
                | Type::Float
                | Type::String
                | Type::Boolean
                | Type::List(_)
                | Type::Map(_)
                | Type::Buffer
                | Type::File
                | Type::Time
                | Type::Timer
        )
    }

    /// The `nothing` diagnostics' shared second line: what the literal is,
    /// and the positions the manual gives it.
    fn nothing_note_line(&self, declared: &Type) -> String {
        format!(
            "nothing is the absent value: it sits in a list slot, a map value, or a value parameter or return - never in {}",
            self.typed_phrase(declared)
        )
    }

    /// The `nothing` diagnostics' shared help line: the two ways out - the
    /// type that can be absent, or this type's own empty value. `buffer`,
    /// `file`, `time` and `timer` have no empty literal to name, so they get
    /// the first half only.
    fn nothing_help_line(&self, declared: &Type, subject: &str) -> String {
        let empty = match declared {
            Type::Integer => Some("0"),
            Type::Float => Some("0.0"),
            Type::String => Some("\"\""),
            Type::Boolean => Some("false"),
            Type::List(_) => Some("[]"),
            Type::Map(_) => Some("{}"),
            _ => None,
        };
        match empty {
            Some(empty) => format!(
                "declare {} as a value, the type that can be absent - or give it {}'s own empty value, {}",
                subject,
                self.type_name(declared),
                empty
            ),
            None => format!("declare {} as a value, the type that can be absent", subject),
        }
    }

    /// Bug #57 at a declaration: `a text called t is nothing.` and the
    /// `Set`/`Create ... to nothing.` spellings that parse into the same
    /// statement. Anchored on the declaration, like bug #54's
    /// `check_declared_read_type` - and for the same reason, that the type
    /// lock only guards writes to an ALREADY-declared name.
    pub(crate) fn check_nothing_initialiser(&mut self, name: &str, declared: &Type, value: &Expr) -> bool {
        if !matches!(value, Expr::NothingLit) || !Self::nothing_is_refused_for(declared) {
            return false;
        }
        // `symbol_error_counts` is deliberately not touched, exactly as in
        // `check_declared_read_type`: it indexes WRITE sites, and this error
        // is anchored on the declaration instead.
        let mut err = CompileError::new(&format!(
            "cannot initialise '{}', which is {}, with nothing",
            name,
            self.typed_phrase(declared)
        ));
        if let Some(loc) = self.find_declaration_location(name) {
            err = err.with_underline_note(
                name.len().max(1),
                &format!("this {} is given nothing", self.type_name(declared)),
            );
            err = err.with_location(loc);
        }
        err = err.with_note_line(&self.nothing_note_line(declared));
        err = err.with_help_line(&self.nothing_help_line(declared, &format!("'{}'", name)));
        self.errors.push(err);
        true
    }

    /// Bug #57 at a call site: `greet with nothing.` where `greet`'s
    /// parameter is declared `a text called who`. The callee stores the
    /// argument in the parameter's concretely-typed slot, so this is the
    /// declaration case reached through the call - and it faulted the same
    /// way, on the callee's first read.
    pub(crate) fn check_nothing_argument(
        &mut self,
        function: &str,
        param_name: &str,
        param_type: &Type,
        arg: &Expr,
    ) -> bool {
        if !matches!(arg, Expr::NothingLit) || !Self::nothing_is_refused_for(param_type) {
            return false;
        }
        let mut err = CompileError::new(&format!(
            "cannot pass nothing to '{}', which '{}' declares as {}",
            param_name,
            function,
            self.typed_phrase(param_type)
        ));
        let occurrence = *self.symbol_error_counts.get(param_name).unwrap_or(&0);
        if let Some(loc) = self.find_symbol_location(param_name, occurrence) {
            err = err.with_underline_note(
                param_name.len().max(1),
                &format!("this parameter is {}", self.typed_phrase(param_type)),
            );
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(param_name.to_string(), occurrence + 1);
        err = err.with_note_line(&self.nothing_note_line(param_type));
        err = err.with_help_line(&self.nothing_help_line(param_type, &format!("'{}'", param_name)));
        self.errors.push(err);
        true
    }

    /// Bug #57 at a return: `Return text, nothing.` The caller reads the
    /// result as the declared type, so a text return handed back a null
    /// pointer and a number return quietly answered `0`.
    pub(crate) fn check_nothing_return(&mut self, declared: &Type, value: &Expr) -> bool {
        if !matches!(value, Expr::NothingLit) || !Self::nothing_is_refused_for(declared) {
            return false;
        }
        let mut err = CompileError::new(&format!(
            "cannot return nothing from a function that returns {}",
            self.typed_phrase(declared)
        ));
        // The caret goes on the signature line: that is where the return
        // type is declared, and where the author changes it to a `value`.
        // It also earns the `note:`/`help:` lines, which the renderer only
        // draws for a located error.
        if let Some(function) = self.current_function_name.clone() {
            let occurrence = *self.symbol_error_counts.get(&function).unwrap_or(&0);
            if let Some(loc) = self.find_symbol_location(&function, occurrence) {
                err = err.with_underline_note(
                    function.len().max(1),
                    &format!("this function returns {}", self.typed_phrase(declared)),
                );
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(function, occurrence + 1);
        }
        err = err.with_note_line(&self.nothing_note_line(declared));
        err = err.with_help_line(&self.nothing_help_line(declared, "the return"));
        self.errors.push(err);
        true
    }

    /// Bug #65: the type an initialiser, an argument or a returned value
    /// provably yields, or `None` when nothing can be proven statically -
    /// the same "can't prove it, allow it" policy `arithmetic_operand_type`
    /// follows, and for the same reason: a false positive here rejects a
    /// correct program. Two differences from that function, both of which
    /// matter only in a storage position:
    ///
    /// - a double-quoted token is a string literal everywhere since 0.3.0
    ///   (LANGUAGE.md:612-620), so it is classified as text here instead of
    ///   being looked up as a variable name the way the arithmetic check
    ///   still does. Without this, `a number called count is "count".`
    ///   proved itself a number by finding the name it was declaring.
    /// - a call answers with the return type its function declares, so
    ///   `a text called got is five.` is judged against what `five`
    ///   promises. A function that declares no return type answers `void`,
    ///   which proves nothing about what it hands back - that is bug #45's
    ///   hole, not this one's - so it is mapped back to `None`.
    pub(crate) fn provable_value_type(&self, expr: &Expr) -> Option<Type> {
        let proven = match expr {
            Expr::StringLit(_) => Some(Type::String),
            Expr::ListLit { .. } => Some(Type::List(Box::new(Type::Unknown))),
            Expr::MapLit { .. } => Some(Type::Map(Box::new(Type::Unknown))),
            Expr::FunctionCall { name, .. } => self.function_return_type(name),
            // A bare name that is not a variable but names a zero-argument
            // function is a call (LANGUAGE.md's `a text called got is
            // five.`); a variable of that name shadows the function, which
            // is why the variable lookup goes first.
            Expr::Identifier(name) => self.arithmetic_operand_type(expr).or_else(|| {
                if self.is_zero_arg_function(name) {
                    self.function_return_type(name)
                } else {
                    None
                }
            }),
            _ => self.arithmetic_operand_type(expr),
        };
        match proven {
            Some(Type::Void) | Some(Type::Unknown) => None,
            other => other,
        }
    }

    /// Bug #65: whether a provable value of type `actual` is refused in a
    /// slot declared as `declared`. The rule is the type lock's own
    /// (LANGUAGE.md:531-532, a variable's type is fixed at its
    /// declaration), so it shares the lock's compatibility predicate and
    /// its exemptions - the point of this bug's fix is that the lock
    /// guarded every write to an already-declared name and nothing at all
    /// at the declaration itself, where the type is decided.
    ///
    /// Permissive in the same places `check_type_lock` is:
    /// - a `value` destination is the language's sanctioned dynamic-type
    ///   mechanism and must keep taking any type;
    /// - a `buffer` destination takes a content write rather than a typed
    ///   value, so `a buffer called b is "seed".` and `b is 42.` are
    ///   correct programs, not mismatches;
    /// - a `thing` destination is a whole-thing copy, which
    ///   `check_thing_copy` already judges and would otherwise report twice;
    /// - a `value` source is dynamic: its runtime type is not known until
    ///   runtime, so there is nothing to prove either way.
    ///
    /// And permissive in four places of its own:
    /// - **`number` and `float` are one family.** The language designer's
    ///   ruling (Josj, 2026-08-21): "in human language we call 1 a number
    ///   and pi a number; it should be the same in Vox - dynamic casting as
    ///   and when needed". So `a number called n is 3.5.` keeps the 3.5,
    ///   and `a float called ratio is 3.` takes the 3 - converted to 3.0 at
    ///   the store (codegen's `VarDecl` arm), not stored as raw integer bits
    ///   for the next read to render as `0.0`. The type lock still refuses
    ///   `Set f to 3.` and `Set n to 3.5.` one line later; that
    ///   disagreement is the designer's own static-int64 gap, left with
    ///   them, and deliberately not closed from this side.
    /// - a `file`, `time` or `timer` destination. These are handles, not
    ///   values: they have no literal spelling, no conversion in the Basic
    ///   Conversions table, and their documented initialisers are of
    ///   another type outright - LANGUAGE.md:503-519 makes `a file called
    ///   source is "input.txt".` the canonical way to open one, so a text
    ///   into a file is a correct program, and `a time called now is
    ///   current time.` is the same shape. `param_accepts` records the same
    ///   judgement for arguments ("file parameters accept number-like
    ///   handles"; `Time | Timer => true`).
    /// - a buffer read into a text without the cast, which is bug #51 -
    ///   still open, and whose two candidate fixes (copy the bytes, or
    ///   reject and name `as text`) are a human's call. Refusing it here
    ///   would decide that open question as a side effect of this one, so
    ///   it is left exactly as it is.
    fn initialiser_type_is_refused(&self, declared: &Type, actual: &Type) -> bool {
        if matches!(
            declared,
            Type::Value
                | Type::Buffer
                | Type::Thing(_)
                | Type::File
                | Type::Time
                | Type::Timer
                | Type::Void
                | Type::Unknown
        ) {
            return false;
        }
        if matches!(actual, Type::Value | Type::Void | Type::Unknown) {
            return false;
        }
        if matches!((declared, actual), (Type::String, Type::Buffer)) {
            return false;
        }
        // A number and a float are one family, per the designer's ruling
        // above: neither direction is a mismatch to refuse.
        if matches!(
            (declared, actual),
            (Type::Integer, Type::Float) | (Type::Float, Type::Integer)
        ) {
            return false;
        }
        !self.treating_types_compatible(declared, actual)
    }

    /// Bug #65's help line: the two ways out of a mismatch. Declaring the
    /// name as the type the value actually yields always works; converting
    /// is only offered where LANGUAGE.md's Basic Conversions table
    /// (LANGUAGE.md:1902-1918) documents a cast between the two types, so
    /// the diagnostic never sends an author to a conversion that does not
    /// exist. `render_value_hint` falls back to a placeholder for shapes it
    /// cannot write back as source, and a help line containing that
    /// placeholder would not be pasteable, so those get the prose half only.
    fn documented_cast_phrase(&self, from: &Type, to: &Type) -> Option<String> {
        use Type::*;
        let documented = matches!(
            (from, to),
            (Float, Integer)
                | (Integer, Float)
                | (Integer, String)
                | (String, Integer)
                | (Float, String)
                | (String, Float)
                | (Boolean, Integer)
                | (Integer, Boolean)
                | (Boolean, String)
                | (String, Boolean)
                | (Buffer, String)
        );
        documented.then(|| self.typed_phrase(to))
    }

    /// Bug #65 at a declaration: `a text called n is 5.` - a concretely
    /// typed slot initialised with a provable value of another type.
    ///
    /// Codegen stores whatever the initialiser yields into the slot with no
    /// conversion and no tag, and the first read takes it for the declared
    /// type: a number in a `text` was dereferenced as a pointer (SIGSEGV),
    /// a text in a `number` printed the literal's address, a text in a
    /// `float` printed `0.0`, and a number in a `float` printed `0.0` too.
    /// LANGUAGE.md:531-532 fixes a variable's type at its declaration and
    /// the type lock has enforced that on every write to an already
    /// declared name since 0.3.0 - `Set n to "x".` is refused - but the
    /// declaration itself, which is where the type is chosen, was never
    /// checked at all. LANGUAGE.md:647-667 is the whole reason the 0.3.0
    /// split happened: "a function pointer, printed as a number, silently".
    ///
    /// Anchored on the declaration, like bug #54's
    /// `check_declared_read_type` and bug #57's
    /// `check_nothing_initialiser`, and permissive in the same places (see
    /// `initialiser_type_is_refused`). Returns true iff it reported.
    pub(crate) fn check_initialiser_type(
        &mut self,
        name: &str,
        declared: &Type,
        value: &Expr,
    ) -> bool {
        let Some(actual) = self.provable_value_type(value) else {
            return false;
        };
        // Bug #72: a proven miss yields the number 0, and a number, float
        // or boolean slot holds it - see `absent_read_fits`.
        if self.absent_read_fits(declared, value) {
            return false;
        }
        if !self.initialiser_type_is_refused(declared, &actual) {
            return false;
        }
        // `symbol_error_counts` is deliberately not touched, exactly as in
        // `check_declared_read_type` and `check_nothing_initialiser`: it
        // indexes WRITE sites, and this error is anchored on the
        // declaration instead.
        let mut err = CompileError::new(&format!(
            "cannot initialise '{}', which is {}, with {}",
            name,
            self.typed_phrase(declared),
            self.typed_phrase(&actual)
        ));
        if let Some(loc) = self.find_declaration_location(name) {
            err = err.with_underline_note(
                name.len().max(1),
                &format!(
                    "this {} is given {}",
                    self.type_name(declared),
                    self.typed_phrase(&actual)
                ),
            );
            err = err.with_location(loc);
        }
        err = err.with_note_line(&format!(
            "a variable's type is fixed at its declaration, so '{}' can only be initialised with {}",
            name,
            self.typed_phrase(declared)
        ));
        let hint = self.render_value_hint(value);
        let help = if hint.contains("<value>") {
            format!("declare '{}' as {}", name, self.typed_phrase(&actual))
        } else {
            let redeclare = format!(
                "declare it as {} - `a {} called {} is {}.`",
                self.typed_phrase(&actual),
                self.type_name(&actual),
                name,
                hint
            );
            match self.documented_cast_phrase(&actual, declared) {
                Some(cast) => format!(
                    "{} - or convert it explicitly:  a {} called {} is {} as {}.",
                    redeclare,
                    self.type_name(declared),
                    name,
                    hint,
                    cast
                ),
                None => redeclare,
            }
        };
        err = err.with_help_line(&help);
        self.errors.push(err);
        true
    }

    /// Bug #65 at a call site: `greet with 5.` where `greet` declares `a
    /// text called who`. The callee stores the argument in that parameter's
    /// concretely typed slot and reads it as the declared type, so this is
    /// the declaration case reached through the call - and it faulted the
    /// same way, on the callee's first read, one frame from the sentence
    /// that caused it. Same shape as bug #57's `check_nothing_argument`.
    pub(crate) fn check_argument_type(
        &mut self,
        function: &str,
        param_name: &str,
        param_type: &Type,
        arg: &Expr,
    ) -> bool {
        let Some(actual) = self.provable_value_type(arg) else {
            return false;
        };
        // Bug #72, as in `check_initialiser_type`.
        if self.absent_read_fits(param_type, arg) {
            return false;
        }
        if !self.initialiser_type_is_refused(param_type, &actual) {
            return false;
        }
        let mut err = CompileError::new(&format!(
            "cannot pass {} to '{}', which '{}' declares as {}",
            self.typed_phrase(&actual),
            param_name,
            function,
            self.typed_phrase(param_type)
        ));
        let occurrence = *self.symbol_error_counts.get(param_name).unwrap_or(&0);
        if let Some(loc) = self.find_symbol_location(param_name, occurrence) {
            err = err.with_underline_note(
                param_name.len().max(1),
                &format!("this parameter is {}", self.typed_phrase(param_type)),
            );
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(param_name.to_string(), occurrence + 1);
        err = err.with_note_line(&format!(
            "a parameter's type is fixed by the signature, so '{}' can only be given {}",
            param_name,
            self.typed_phrase(param_type)
        ));
        let hint = self.render_value_hint(arg);
        let help = match self.documented_cast_phrase(&actual, param_type) {
            Some(cast) if !hint.contains("<value>") => format!(
                "convert it at the call site - `{} as {}` - or declare '{}' as {}",
                hint,
                cast,
                param_name,
                self.typed_phrase(&actual)
            ),
            _ => format!(
                "pass {} - or declare '{}' as {}",
                self.typed_phrase(param_type),
                param_name,
                self.typed_phrase(&actual)
            ),
        };
        err = err.with_help_line(&help);
        self.errors.push(err);
        true
    }

    /// Bug #65 at a return: `Return a text, 5.` The caller reads the result
    /// as the declared type, so a text return handed back the literal's
    /// address for `Print` to dereference. Same shape as bug #57's
    /// `check_nothing_return`, caret on the signature line for the same
    /// reason: that is where the return type is declared, and where the
    /// author changes it.
    pub(crate) fn check_return_type(&mut self, declared: &Type, value: &Expr) -> bool {
        let Some(actual) = self.provable_value_type(value) else {
            return false;
        };
        // Bug #72, as in `check_initialiser_type`.
        if self.absent_read_fits(declared, value) {
            return false;
        }
        if !self.initialiser_type_is_refused(declared, &actual) {
            return false;
        }
        let mut err = CompileError::new(&format!(
            "cannot return {} from a function that returns {}",
            self.typed_phrase(&actual),
            self.typed_phrase(declared)
        ));
        if let Some(function) = self.current_function_name.clone() {
            let occurrence = *self.symbol_error_counts.get(&function).unwrap_or(&0);
            if let Some(loc) = self.find_symbol_location(&function, occurrence) {
                err = err.with_underline_note(
                    function.len().max(1),
                    &format!("this function returns {}", self.typed_phrase(declared)),
                );
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(function, occurrence + 1);
        }
        err = err.with_note_line(&format!(
            "a function's return type is fixed by its signature, so it can only hand back {}",
            self.typed_phrase(declared)
        ));
        let hint = self.render_value_hint(value);
        let help = match self.documented_cast_phrase(&actual, declared) {
            Some(cast) if !hint.contains("<value>") => format!(
                "convert it explicitly:  Return {}, {} as {}.",
                self.typed_phrase(declared),
                hint,
                cast
            ),
            _ => format!(
                "return {} - or declare the return as {}",
                self.typed_phrase(declared),
                self.typed_phrase(&actual)
            ),
        };
        err = err.with_help_line(&help);
        self.errors.push(err);
        true
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
    ///   keep working. A buffer is *not* excused from the `nothing` check
    ///   below: a content write formats the value's text into the buffer,
    ///   and `nothing` has no text - it formatted its payload and wrote
    ///   `0`, which is the "`nothing` is not zero" mistake again and would
    ///   have contradicted the same statement's rejection at the buffer's
    ///   declaration (bug #57).
    pub(crate) fn check_type_lock(&mut self, name: &str, value: &Expr) -> bool {
        if self.value_typed_names.contains(name) {
            return false;
        }
        let Some(declared) = self.named_value_type(name) else {
            return false;
        };
        // Bug #57: `nothing` is not a `Type`, so `arithmetic_operand_type`
        // answers None for it and the lock used to wave it straight through
        // - `set t to nothing.` on a text stored a null pointer that the
        // next read dereferenced, exactly as the declaration form did. Same
        // rule, reported against the write site the lock already locates.
        if matches!(value, Expr::NothingLit) {
            if !Self::nothing_is_refused_for(&declared) {
                return false;
            }
            let occurrence = *self.symbol_error_counts.get(name).unwrap_or(&0);
            let mut err = CompileError::new(&format!(
                "cannot assign nothing to '{}', which is {}",
                name,
                self.typed_phrase(&declared)
            ));
            if let Some(loc) = self.find_write_site_location(name, occurrence) {
                err = err.with_underline_note(name.len().max(1), "this assigns nothing");
                err = err.with_location(loc);
            }
            self.symbol_error_counts.insert(name.to_string(), occurrence + 1);
            // A `CompileError` carries one `note:` line, and this is the one
            // worth having: the mismatched-assignment case below spends its
            // note on the declaration site, but `find_write_site_location`
            // has already put the caret there, and what the author needs is
            // what `nothing` actually is.
            err = err.with_note_line(&self.nothing_note_line(&declared));
            err = err.with_help_line(&self.nothing_help_line(&declared, &format!("'{}'", name)));
            self.errors.push(err);
            // Same reason as the mismatched-assignment case below: the write
            // was rejected, and leaving the old type in place would cascade
            // a second error out of a mistake already reported.
            self.scalar_types.remove(name);
            return true;
        }
        // A buffer's content write is exempt from the type lock proper (see
        // the doc comment above), but not from the `nothing` check that has
        // already run.
        if self.is_buffer_variable(name) {
            return false;
        }
        let Some(actual) = self.arithmetic_operand_type(value) else {
            return false;
        };
        if matches!(actual, Type::Value) {
            return false;
        }
        // A buffer written into a text is a CONVERSION, not a retype. The
        // destination keeps its declared type and takes a copy of the
        // buffer's bytes - the one meaning LANGUAGE.md's Basic Conversions
        // table gives `buffer -> text` ("a copy of the buffer's bytes"), and
        // the meaning `"{b}"` has carried since v0.1.17. The language
        // owner's ruling on BUGS_FOUND #51 is that the cast-free spellings
        // say the same thing as `as text`, so `Set t to b.` / `the t is b.`
        // are accepted here and copy in codegen instead of demanding a cast
        // that would not change what the sentence means. Type immutability
        // (LANGUAGE.md:531-532) is untouched: `t` is text before the write
        // and text after it.
        if matches!(declared, Type::String) && matches!(actual, Type::Buffer) {
            return false;
        }
        // Bug #72, the assignment spelling of the same read - see
        // `check_declared_read_type`.
        if self.absent_read_fits(&declared, value) {
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

    /// Bug #78: the size a buffer declaration asks for, checked against the
    /// bound the manual states under "Fixed-Size Buffers" - at least one
    /// byte, at most 1 GiB.
    ///
    /// The bound existed before this check, but only in the parser's
    /// literal arm, so it was a rule about a SPELLING rather than about a
    /// size: `a buffer called b is wanted bytes in size.` walked past it
    /// whatever `wanted` held, and `Create a buffer called b with capacity
    /// 1073741825.` was never bounded at all. Both reached
    /// `_alloc_buffer_sized` unchecked - a negative size reported a
    /// negative capacity (the shape of #58), and one past what mmap can map
    /// stored a null buffer pointer that the next read dereferenced.
    ///
    /// Three things are refused here, each only where the compiler can
    /// prove it:
    ///
    /// - a literal size past the ceiling in a spelling the parser does not
    ///   check (`Create ... with size N`),
    /// - a named size whose value is fixed for the whole program
    ///   (`collect_constant_numbers`) and outside the bound,
    /// - a named size of a type that is not a whole number of bytes - a
    ///   text sized the buffer by its address, and a float by its bit
    ///   pattern, which faulted.
    ///
    /// What is NOT refused: `Expr::IntegerLit(0)`. That is not the author
    /// writing `0` - the parser gives every sizeless buffer (`a buffer
    /// called b.`, `Create a buffer called b.`) exactly that AST, so the
    /// two are indistinguishable here, and a literal `0 bytes` is already
    /// refused where they can be told apart, in the parser. A size the
    /// compiler cannot prove either way is not refused either: codegen
    /// guards that one at run time.
    pub(crate) fn check_buffer_size(&mut self, buffer: &str, size: &Expr) {
        match size {
            // The dynamic-buffer AST, not a size the author wrote.
            Expr::IntegerLit(0) => {}
            Expr::IntegerLit(n) => {
                if *n < MIN_BUFFER_SIZE || *n > MAX_BUFFER_SIZE {
                    self.push_buffer_size_error(buffer, &n.to_string(), *n, None);
                }
            }
            Expr::Identifier(name) => {
                let name = name.clone();
                if let Some(ty) = self.named_value_type(&name) {
                    if !matches!(ty, Type::Integer | Type::Value | Type::Unknown) {
                        self.push_buffer_size_type_error(buffer, &name, &ty);
                        return;
                    }
                }
                if let Some(&value) = self.number_constants.get(&name) {
                    if value < MIN_BUFFER_SIZE || value > MAX_BUFFER_SIZE {
                        self.push_buffer_size_error(buffer, &name, value, Some(&name));
                    }
                }
            }
            _ => {}
        }
    }

    /// The out-of-bound half of `check_buffer_size`. `written` is the size
    /// exactly as the author spelled it - the digits, or the name - so the
    /// caret lands on the token they have to change; `value` is what that
    /// spelling comes to. The help line names the way out, in the family of
    /// #45/#62/#63: too small means they wanted a dynamic buffer, too large
    /// means they have to ask for less.
    fn push_buffer_size_error(
        &mut self,
        buffer: &str,
        written: &str,
        value: i64,
        named: Option<&str>,
    ) {
        let mut err = CompileError::new(&format!(
            "cannot give the buffer '{}' a size of {} bytes",
            buffer, value
        ));
        let occurrence = *self.symbol_error_counts.get(written).unwrap_or(&0);
        let patterns = [
            format!("{} bytes", written),
            format!("size {}", written),
            format!("capacity {}", written),
            written.to_string(),
        ];
        if let Some(loc) = self.find_pattern_location(written, &patterns, occurrence, None, false, false) {
            let note = match named {
                Some(name) => format!("'{}' is {} here", name, value),
                None => "asked for here".to_string(),
            };
            err = err.with_underline_note(written.len().max(1), &note);
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(written.to_string(), occurrence + 1);
        err = err.with_note_line(&format!(
            "a fixed buffer's size must be between {} and {} bytes (1 GiB)",
            MIN_BUFFER_SIZE, MAX_BUFFER_SIZE
        ));
        err = err.with_help_line(&if value < MIN_BUFFER_SIZE {
            format!(
                "for a buffer with no fixed capacity, declare it with no size at all: 'a buffer called {}.'",
                buffer
            )
        } else {
            format!(
                "ask for at most {} bytes, and read the rest in further passes through the same buffer",
                MAX_BUFFER_SIZE
            )
        });
        self.errors.push(err);
    }

    /// The wrong-type half of `check_buffer_size`. A size is a count of
    /// bytes; a text sized the buffer by the address of its characters and
    /// a float by the bits of its mantissa, neither of which the author
    /// wrote.
    fn push_buffer_size_type_error(&mut self, buffer: &str, size_name: &str, ty: &Type) {
        let mut err = CompileError::new(&format!(
            "cannot size the buffer '{}' from '{}', which is {}",
            buffer,
            size_name,
            self.typed_phrase(ty)
        ));
        let occurrence = *self.symbol_error_counts.get(size_name).unwrap_or(&0);
        let patterns = [
            format!("{} bytes", size_name),
            format!("size {}", size_name),
            format!("capacity {}", size_name),
            size_name.to_string(),
        ];
        if let Some(loc) = self.find_pattern_location(size_name, &patterns, occurrence, None, false, false)
        {
            err = err.with_underline_note(
                size_name.len().max(1),
                &format!("this is {}", self.typed_phrase(ty)),
            );
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(size_name.to_string(), occurrence + 1);
        err = err.with_note_line("a buffer's size is a whole number of bytes");
        err = err.with_help_line(&match ty {
            Type::Float => format!(
                "round it to whole bytes first: 'a number called count is {} as a number.', then size '{}' from count",
                size_name, buffer
            ),
            Type::String => format!(
                "read the number out of the text first: 'a number called count is {} as a number.', then size '{}' from count",
                size_name, buffer
            ),
            _ => format!(
                "give the size as a number: 'a number called count is <how many bytes>.', then size '{}' from count",
                buffer
            ),
        });
        self.errors.push(err);
    }
}
