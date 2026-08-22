use super::*;

impl Parser {
    pub(crate) fn parse_resize(&mut self) -> Result<Statement, Box<CompileError>> {
        // "resize buffer to N bytes" or "resize buffer to N"
        self.advance(); // consume 'resize'
        self.skip_noise();
        
        // Get buffer name
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(n) => { self.advance(); n }
                    _ => return Err(self.err("Expected buffer name after 'the'")),
                }
            }
            _ => return Err(self.err("Expected buffer name after 'resize'")),
        };
        
        self.skip_noise();
        self.expect(&Token::To);
        self.skip_noise();
        
        // Parse new size
        let new_size = self.parse_expression()?;
        
        self.skip_noise();
        // Skip optional "bytes"
        if *self.current() == Token::Bytes {
            self.advance();
        }
        
        Ok(Statement::BufferResize { name, new_size })
    }

    /// Parse one value in append position - any primary the language has,
    /// read with `to` reserved, because `to` is the append separator and
    /// must not be consumed as part of the value. A quoted name followed
    /// by of/with/on is a function call (`append "f" of x to items`); `to`
    /// is NOT a call trigger here, unlike the general expression parser,
    /// so that `append "s" to items` stays an append of the literal "s".
    /// Braces force the general expression parser for the enclosed tokens
    /// (`append {i multiply i} to s`), matching how braces put an expression
    /// into a value slot elsewhere in Vox.
    ///
    /// BUGS_FOUND #77: every arm below the string literal used to be written
    /// out here - a hand-rolled copy of `parse_primary` that had fallen
    /// behind it. A leading `-`, `nothing`, `element N of L`, `byte N of b`
    /// and every `'s` possessive were value forms the copy had never
    /// learned, so `append -5 to xs.` answered "Expected value to append"
    /// while `append {-5} to xs.` - the same tokens, routed to
    /// `parse_primary` - compiled. They read one primary now, so a value
    /// form is added or diagnosed in exactly one place (the lesson of #64).
    /// The separator protection is unchanged: it lives in
    /// `suppress_to_connector`, which `parse_primary_reserving` sets for the
    /// whole subtree, not in the arm list. The arm list stays explicit so a
    /// token that cannot start a value still gets the append slot's own
    /// diagnostic rather than the general parser's "expected a statement".
    pub(crate) fn parse_append_value_primary(&mut self) -> Result<Expr, Box<CompileError>> {
        match self.current().clone() {
            Token::StringLiteral(s) => {
                // Plan 270 §S1.5: a string literal is data, not a name, so it
                // cannot be a callee. Capture the literal's location now (before
                // advancing) so the §S1.5 underline can still point at it.
                let s_loc = self.current_location();
                self.advance();
                self.skip_noise();
                // A format string can't be a function name - resolve it first.
                let resolved = self.string_value_expr(s.clone());
                if matches!(resolved, Expr::FormatString { .. }) {
                    Ok(resolved)
                } else if matches!(self.current(), Token::Of | Token::With | Token::On) {
                    // `append "<name>" of 3 to s` — a string used as a callee.
                    let mut err = CompileError::new("expected a name, found a string literal");
                    if let Some(loc) = s_loc {
                        err = err.with_location(loc);
                    }
                    let span = s.chars().count() + 2;
                    err = err
                        .with_underline_note(span, "strings are data; names are bare or 'single-quoted'")
                        .with_help_line(&Self::suggest_name_form(&s));
                    Err(Box::new(err))
                } else {
                    Ok(resolved)
                }
            }
            // One primary, with `to` reserved for the append separator.
            // Reserving it is what keeps a bare name from reading the
            // separator as its own call connector (`append id of item to
            // out`), and it covers the whole subtree, so an index's list
            // (`element 1 of ys to xs`) is protected by the same flag.
            Token::OpenBrace
            | Token::Minus
            | Token::IntegerLiteral(_)
            | Token::IntegerLiteralOverflow(_)
            | Token::FloatLiteral(_)
            | Token::True
            | Token::False
            | Token::Nothing
            | Token::Element
            | Token::Byte
            | Token::Identifier(_)
            | Token::The => self.parse_primary_reserving(true, false),
            _ => Err(self.err("Expected value to append")),
        }
    }

    /// Continue an append value over any binary operators that follow it.
    /// Precedence matches the general expression parser (bitwise tighter
    /// than multiplicative, multiplicative tighter than additive); right
    /// operands reuse the restricted append primary so the separator can
    /// never be eaten. `to` is never an operator here, so the walk always
    /// stops at it.
    pub(crate) fn parse_append_value_ops(&mut self, mut left: Expr, min_prec: u8) -> Result<Expr, Box<CompileError>> {
        loop {
            self.skip_noise();
            let (op, prec) = match self.current() {
                Token::Add => (BinaryOperator::Add, 1),
                Token::Subtract => (BinaryOperator::Subtract, 1),
                Token::Multiply => (BinaryOperator::Multiply, 2),
                // BUGS_FOUND #77: `multiply` and `times` are two spellings of
                // one operator (LANGUAGE.md's operator table) but two tokens,
                // because `Repeat N times` claims the second. This list had
                // only the first, so `append v1 times v2 to l1.` stopped at
                // `times` and reported "Expected 'to' after value" with the
                // `to` written right there. The list now matches
                // `parse_multiplicative`'s exactly.
                Token::Times => (BinaryOperator::Multiply, 2),
                Token::Divide => (BinaryOperator::Divide, 2),
                Token::Modulo => (BinaryOperator::Modulo, 2),
                Token::BitAnd => (BinaryOperator::BitAnd, 3),
                Token::BitOr => (BinaryOperator::BitOr, 3),
                Token::BitXor => (BinaryOperator::BitXor, 3),
                Token::BitShiftLeft => (BinaryOperator::ShiftLeft, 3),
                Token::BitShiftRight => (BinaryOperator::ShiftRight, 3),
                _ => break,
            };
            if prec < min_prec {
                break;
            }
            self.advance();
            self.skip_noise();
            let primary = self.parse_append_value_primary()?;
            let right = self.parse_append_value_ops(primary, prec + 1)?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    pub(crate) fn parse_append(&mut self) -> Result<Statement, Box<CompileError>> {
        // "append <expr> to <list>" or "append each <var> from <collection> to <list>"
        self.advance(); // consume 'append'
        self.skip_noise();
        
        // Check for loop expansion: "append each X from Y to Z"
        if let Some((variable, collection, treating)) = self.try_parse_each_from(true)? {
            // `append` has one source value slot, so a grid of two or more
            // `each` clauses is an arity error, not a multi-source append
            // (plan 320 rule 12). The separator `to` must follow the single
            // collection; an `and` here starts a second clause.
            self.skip_noise();
            if *self.current() == Token::And {
                return Err(self.one_slot_arity_error("append"));
            }
            // Get target list name after "to"
            if *self.current() != Token::To {
                return Err(self.err("Expected 'to' after collection in append"));
            }
            self.advance();
            self.skip_noise();
            
            let list_name = match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                Token::The => {
                    self.advance();
                    self.skip_noise();
                    match self.current().clone() {
                        Token::Identifier(n) => { self.advance(); n }
                        Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                        _ => return Err(self.err("Expected list name after 'the'")),
                    }
                }
                _ => return Err(self.err("Expected list name after 'to'")),
            };

            // A `treating` clause written here, after the destination, is in
            // the wrong place: it substitutes for the loop variable, so it
            // belongs to the `each ... from ...` clause that binds the
            // variable (`loop_expansion`, LANGUAGE.md), which is where
            // `print`/`open`/a call all spell it. Left to fall through it
            // reached the top level as "Expected a statement, got Treating",
            // which named neither the clause nor the way out (BUGS_FOUND #70;
            // diagnostic in the #45/#62/#63 family, caret on the offending
            // token per #46).
            self.skip_noise();
            if *self.current() == Token::Treating {
                let mut err = *self.err(
                    "A `treating` clause belongs to the `each` clause, not after the append destination"
                );
                err = err
                    .with_underline_note(
                        "treating".chars().count(),
                        "this substitutes for the loop variable, so it goes where the variable is bound",
                    )
                    .with_help_line(&format!(
                        "write `append each {} from <collection> treating <match> as <replacement> to {}.`",
                        variable, list_name
                    ));
                return Err(Box::new(err));
            }

            // Create the append statement for loop body. A `treating` clause
            // on the `each` wraps the loop variable exactly as it does in
            // `print each ... treating ...` and `open ... at each ...`.
            let append_stmt = Statement::ListAppend {
                list: list_name,
                value: Self::each_arg_expr(&variable, &treating),
            };

            return self.wrap_in_loop_expansion(variable, collection, append_stmt);
        }
        
        // Parse just the value, then any arithmetic that applies to it
        // (`append i multiply i to s`). The operator walk never treats `to`
        // as an operator, so it always stops at the append separator.
        let mut value = self.parse_append_value_primary()?;
        value = self.parse_append_value_ops(value, 0)?;

        self.skip_noise();

        // Stage 1c: a type predicate as the append value, e.g.
        // `append item is a number to flags` or `append item is not a text
        // to flags`. The article `a`/`an` and the noun are keywords, and
        // `to` (the append separator) is not one of them, so this cannot
        // accidentally swallow the separator — `append "s" to items`
        // (current token `to`, not `is`) skips this branch unchanged.
        if matches!(self.current(), Token::Is | Token::Are) {
            self.advance();
            self.skip_noise();
            let negated = *self.current() == Token::Not;
            if negated {
                self.advance();
                self.skip_noise();
            }
            if !matches!(self.current(), Token::A | Token::An) {
                return Err(self.err(
                    "Expected 'a'/'an' and a type noun after 'is' in append value"
                ));
            }
            let type_noun = self.parse_type_noun_after_article()?;
            let check = Expr::TypeCheck {
                value: Box::new(value),
                type_noun,
            };
            value = if negated {
                Expr::UnaryOp { op: UnaryOperator::Not, operand: Box::new(check) }
            } else {
                check
            };
        }

        // Expect "to"
        if *self.current() != Token::To {
            return Err(self.err("Expected 'to' after value in append statement"));
        }
        self.advance();
        self.skip_noise();
        
        // Get list name
        let list = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(n) => { self.advance(); n }
                    Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                    _ => return Err(self.err("Expected list name after 'the'")),
                }
            }
            _ => return Err(self.err("Expected list name after 'to'")),
        };

        Ok(Statement::ListAppend { list, value })
    }

    pub(crate) fn parse_copy(&mut self) -> Result<Statement, Box<CompileError>> {
        // "copy <source> to <buffer>"
        self.advance(); // consume 'copy'
        self.skip_noise();

        // Parse just the source value, preserving `to` as separator.
        let source = match self.current().clone() {
            Token::IntegerLiteral(n) => {
                self.advance();
                Expr::IntegerLit(n)
            }
            Token::IntegerLiteralOverflow(raw) => {
                return Err(self.integer_literal_overflow_error(&raw));
            }
            Token::FloatLiteral(n) => {
                self.advance();
                Expr::FloatLit(n)
            }
            Token::StringLiteral(s) => {
                self.advance();
                self.string_value_expr(s)
            }
            Token::True => {
                self.advance();
                Expr::BoolLit(true)
            }
            Token::False => {
                self.advance();
                Expr::BoolLit(false)
            }
            Token::Identifier(name) => {
                self.advance();
                Expr::Identifier(name)
            }
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(name) => {
                        self.advance();
                        Expr::Identifier(name)
                    }
                    Token::StringLiteral(s) => {
                        self.advance();
                        Expr::StringLit(s)
                    }
                    _ => return Err(self.err("Expected source value after 'the'")),
                }
            }
            _ => return Err(self.err("Expected source value after 'copy'")),
        };

        self.skip_noise();
        if *self.current() != Token::To {
            return Err(self.err("Expected 'to' after source in copy statement"));
        }
        self.advance();
        self.skip_noise();

        let destination = match self.current().clone() {
            Token::Identifier(n) => {
                self.advance();
                n
            }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(n) => {
                        self.advance();
                        n
                    }
                    Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                    _ => return Err(self.err("Expected destination buffer name after 'the'")),
                }
            }
            _ => return Err(self.err("Expected destination buffer name after 'to'")),
        };

        Ok(Statement::BufferCopy { source, destination })
    }

    pub(crate) fn parse_clear(&mut self) -> Result<Statement, Box<CompileError>> {
        // "clear <buffer>"
        self.advance(); // consume 'clear'
        self.skip_noise();

        let name = match self.current().clone() {
            Token::Identifier(n) => {
                self.advance();
                n
            }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(n) => {
                        self.advance();
                        n
                    }
                    Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                    _ => return Err(self.err("Expected buffer name after 'the'")),
                }
            }
            _ => return Err(self.err("Expected buffer name after 'clear'")),
        };

        Ok(Statement::BufferClear { name })
    }

}
