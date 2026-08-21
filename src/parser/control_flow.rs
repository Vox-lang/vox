use super::*;

impl Parser {
    /// Detects an optional `, but if ...` / `but if ...` conditional-sugar
    /// suffix after a fully-parsed base statement and, if present, dispatches
    /// to `parse_conditional_suffix`.  If no `but if` follows, restores the
    /// parser position and returns `base` unchanged so outer constructs can
    /// consume the separator normally (e.g. a plain trailing comma belonging
    /// to an enclosing sentence-consuming construct).
    ///
    /// When `suppress_conditional_suffix` is set (while parsing a `but if`
    /// branch body), the suffix is ignored unconditionally so that the outer
    /// chain keeps ownership of every condition.
    pub(crate) fn maybe_parse_conditional_suffix(&mut self, base: Statement) -> Result<Statement, Box<CompileError>> {
        if self.suppress_conditional_suffix {
            return Ok(base);
        }

        let start_pos = self.pos;

        // The conditional continuation sugar is `but if ...` with an optional
        // leading comma. Consume the comma if present, but do not commit to it
        // until we see the `but if` that proves this is a suffix. A bare
        // `, if ... then, ...` is a nested `If` as the next item in an
        // enclosing comma-separated body, so we always restore `start_pos`
        // when `but if` is absent.
        if *self.current() == Token::Comma {
            self.advance();
            self.skip_noise();
        }

        if *self.current() == Token::But {
            self.advance();
            self.skip_noise();

            if *self.current() == Token::If {
                return self.parse_conditional_suffix(base);
            }
        }

        // Not a conditional continuation; restore parser position so
        // outer constructs can consume the separator normally.
        self.pos = start_pos;
        Ok(base)
    }

    /// Builds the nested `Statement::If` chain for `but if` conditional
    /// sugar. `base` is the already-parsed default statement (used as-is in
    /// the innermost `else`); each branch's own statement is parsed by
    /// `parse_conditional_branch` using the normal statement parser.
    pub(crate) fn parse_conditional_suffix(&mut self, base: Statement) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'if'
        self.skip_noise();

        let mut conditions = Vec::new();

        let cond = self.parse_condition()?;
        self.skip_noise();
        conditions.push((cond, self.parse_conditional_branch(&base)?));

        // Skip newlines before checking for continuation (allows multi-line but if)
        self.skip_noise();
        loop {
            // Check for continuation: comma, but, and — or a period that
            // belongs to a nested clause rather than closing the chain. Per
            // LANGUAGE.md termination rule 1, a period closes only the
            // innermost open clause; when the branch body opened its own
            // clause (e.g. `On error ...`), that period is *its* terminator,
            // not the chain's. Only treat the period as chain continuation
            // when it is immediately followed by `but` — a period with
            // nothing but blank-line/EOF/anything else after it still ends
            // the whole chain.
            if *self.current() == Token::Period {
                let saved = self.pos;
                self.advance();
                self.skip_noise();
                if *self.current() != Token::But {
                    self.pos = saved;
                    break;
                }
            } else if !matches!(
                self.current(),
                Token::But | Token::Comma | Token::And | Token::Else | Token::Otherwise
            ) {
                break;
            }

            // A bare `otherwise`/`else` is the clause keyword itself, not a
            // separator standing in front of one. `parse_block`'s
            // trailing-comma arm already ate the comma and stopped ON the
            // keyword, so only the terse `append` branch ever hands this loop
            // a comma to consume. Advancing here in the bare case would skip
            // the keyword and leave the branch's own action current, which is
            // what made `print x, otherwise print y` a parse error (bug #50).
            let at_bare_alternative = matches!(self.current(), Token::Else | Token::Otherwise);

            // Remember if we started with comma (for ", but if" syntax)
            let started_with_comma = *self.current() == Token::Comma;
            if !at_bare_alternative {
                self.advance();
                self.skip_noise();
            }

            // After comma, we might have "but if" or just "if"
            if started_with_comma && *self.current() == Token::But {
                self.advance();
                self.skip_noise();
            }

            if *self.current() == Token::If {
                self.advance();
                self.skip_noise();
                let cond = self.parse_condition()?;
                self.skip_noise();
                conditions.push((cond, self.parse_conditional_branch(&base)?));
            } else if *self.current() == Token::Else || *self.current() == Token::Otherwise {
                self.advance();
                self.skip_noise();
                conditions.push((Expr::BoolLit(true), self.parse_conditional_branch(&base)?));
                break;
            } else {
                break;
            }
        }

        let mut result = base;

        for (cond, val) in conditions.into_iter().rev() {
            result = Statement::If {
                condition: cond,
                then_block: val,
                else_if_blocks: vec![],
                else_block: Some(vec![result]),
            };
        }

        Ok(result)
    }

    /// Parses one `but if`/`otherwise` branch's body.
    ///
    /// A branch body can be more than one action — `open a file ..., On
    /// error print ...` is the fallible-action-plus-handler shape (bug
    /// #14). We reuse `parse_block`'s comma-separated, on-error-aware body
    /// parser so a branch can hold its own trailing clause the same way an
    /// `If`/`otherwise if` branch does, with conditional-suffix parsing
    /// suppressed so that chained `but if`s stay owned by the outer
    /// `parse_conditional_suffix` loop. `parse_block` leaves a genuinely
    /// chain-ending terminator (period, paragraph break, EOF) for the
    /// caller — it does not consume it.
    ///
    /// The only special case is the terse `append <value>` form, where the
    /// branch may omit `to <name>` and inherit the base statement's target.
    /// That inheritance is handled here as a narrow fallback rather than a
    /// growing match over every statement kind.
    pub(crate) fn parse_conditional_branch(
        &mut self,
        base: &Statement,
    ) -> Result<Vec<Statement>, Box<CompileError>> {
        // The terse append form is the one place where a branch is allowed to
        // leave out a target and inherit it from the base.  `append <value>`
        // is not a valid standalone statement (the full grammar requires
        // `to <list>`), so it cannot be handed to the generic parser.
        if *self.current() == Token::Append {
            return Ok(vec![self.parse_terse_append_branch(base)?]);
        }

        // Every other branch body is parsed like an `If` branch, but with
        // conditional-suffix parsing disabled so that chained `but if`s are
        // owned by the outer `parse_conditional_suffix` loop.
        let saved = self.suppress_conditional_suffix;
        self.suppress_conditional_suffix = true;
        let result = self.parse_block();
        self.suppress_conditional_suffix = saved;
        result
    }

    /// Parses `append <value> [to <name>]` as a `but if`/`otherwise` branch.
    /// The target is optional when the base statement is an append whose
    /// target can be inherited; if the branch does name a target, it must
    /// match the base's.  If the base is not an append statement, an
    /// explicit target is required.
    pub(crate) fn parse_terse_append_branch(
        &mut self,
        base: &Statement,
    ) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'append'
        self.skip_noise();

        let mut value = self.parse_append_value_primary()?;
        value = self.parse_append_value_ops(value, 0)?;
        self.skip_noise();

        // Optional type predicate on the append value, e.g.
        // `append item is a number to flags`.
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

        self.skip_noise();

        // Resolve the target: inherit from the base if omitted, or check that
        // an explicit target matches the base's list/buffer.
        let list = if *self.current() == Token::To {
            self.advance();
            self.skip_noise();
            let target = match self.current().clone() {
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
                _ => return Err(self.err("Expected list name after 'to' in 'but if' branch")),
            };

            if let Statement::ListAppend { list: base_list, .. } = base {
                if target != *base_list {
                    return Err(self.err(&format!(
                        "'but if' append branch targets '{}', but the base statement targets '{}' — \
                         a conditional append branch cannot retarget to a different list/buffer",
                        target, base_list
                    )));
                }
                base_list.clone()
            } else {
                // The base is not an append, so the branch is fully explicit.
                target
            }
        } else if let Statement::ListAppend { list, .. } = base {
            // Terse form: no `to` on the branch, inherit from the base.
            list.clone()
        } else {
            return Err(self.err(
                "Expected 'to <list>' after value in 'but if' append branch"
            ));
        };

        Ok(Statement::ListAppend { list, value })
    }

    pub(crate) fn parse_if(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let condition = self.parse_condition()?;
        self.skip_noise();
        
        self.expect(&Token::Then);
        self.expect(&Token::Comma);
        self.skip_noise();
        
        let then_block = self.parse_block()?;
        
        let mut else_if_blocks = Vec::new();
        let mut else_block = None;
        
        self.skip_noise();
        self.consume_period_before_else_chain();

        while matches!(self.current(), Token::But | Token::Else | Token::Otherwise) {
            self.advance();
            self.skip_noise();

            if *self.current() == Token::If || *self.current() == Token::When {
                self.advance();
                self.skip_noise();
                let cond = self.parse_condition()?;
                self.skip_noise();
                self.expect(&Token::Then);
                self.expect(&Token::Comma);
                self.skip_noise();
                let block = self.parse_block()?;
                else_if_blocks.push((cond, block));
                self.skip_noise();
                self.consume_period_before_else_chain();
            } else {
                self.expect(&Token::Comma);
                self.skip_noise();
                // Else block consumes the rest of the sentence (comma-separated
                // actions, ending at the first top-level period). A nested `If`
                // that owns its own trailing period is parsed as a single action.
                let block = self.parse_sentence_body()?;
                else_block = Some(block);
                break;
            }
        }

        // Standalone if-sentences own their trailing period.
        // This prevents outer sentence-consuming constructs (e.g., while/for)
        // from treating the inner if's period as their own terminator.
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }
        
        Ok(Statement::If {
            condition,
            then_block,
            else_if_blocks,
            else_block,
        })
    }

    /// Parse the comma-separated body of a single-sentence loop — `While` or
    /// `Repeat` — after the leading preamble (the condition, or
    /// `count times,`) and its comma have been consumed. Comma continues to
    /// the next action; a period ends the body unconditionally (LANGUAGE.md
    /// termination rule 1); a paragraph break or EOF ends it; and — inside a
    /// function body — a following `Return` ends it.
    ///
    /// `While` and `Repeat` are specified to terminate identically: rule 1
    /// (LANGUAGE.md:135) names `repeat` in the clause list, and :150 says the
    /// blank-line rule applies uniformly across `while`, `for each`, `repeat`,
    /// and `on error`. Before this was shared, `parse_repeat` had its own body
    /// loop that only broke on a period when a block terminator or paragraph
    /// break followed — so a period never closed a `Repeat` body and the next
    /// statement was silently absorbed (BUGS_FOUND #27). One body loop for
    /// both keeps them from drifting apart again.
    pub(crate) fn parse_loop_body(&mut self) -> Result<Vec<Statement>, Box<CompileError>> {
        let mut body = Vec::new();
        loop {
            if *self.current() == Token::EOF {
                break;
            }
            if !body.is_empty() && self.is_block_terminator() {
                break;
            }

            let stmt = self.parse_statement()?;
            body.push(stmt);
            self.skip_noise();

            // Consume the separator and decide whether to continue.
            if *self.current() == Token::Comma {
                // A comma continues to the next action in the same sentence.
                self.advance();
                self.skip_noise();
                // Paragraph breaks after a comma are visual spacing within
                // the still-open sentence (rule 2's one exception).
                while *self.current() == Token::ParagraphBreak {
                    self.advance();
                    self.skip_noise();
                }
            } else if *self.current() == Token::Period {
                // A period ends this loop's body, full stop (rule 1).
                self.advance();
                self.skip_noise();
                break;
            } else if *self.current() == Token::ParagraphBreak {
                break;
            } else if *self.current() == Token::EOF {
                break;
            }
        }
        Ok(body)
    }

    pub(crate) fn parse_while(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        let condition = self.parse_condition()?;
        self.skip_noise();
        self.expect(&Token::Comma);
        self.skip_noise();

        // Comma continues actions, a period ends this while statement, a
        // paragraph break or EOF ends it. See `parse_loop_body`.
        let body = self.parse_loop_body()?;

        Ok(Statement::While { condition, body })
    }

    /// Check if current token indicates end of a loop body inside a function
    /// Only Return truly ends a loop body - other statements can be part of the loop
    pub(crate) fn is_block_terminator(&self) -> bool {
        matches!(self.current(), Token::Return)
    }

    pub(crate) fn parse_for(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        if *self.current() != Token::Each {
            return Err(self.err(
                "Expected 'each' after 'for'\n  \
                 Syntax: For each <variable> from <start> to <end>, <action>.\n  \
                 Example: For each number from 1 to 10, print the number."
            ));
        }
        self.advance();
        self.skip_noise();
        
        let variable_pos = self.pos;
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
            Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
            _ => {
                // The variable is either genuinely absent or the user
                // typed a reserved keyword where a name belonged (e.g.
                // `for each arg from ...` where `arg` is an alias of
                // `argument`). Distinguish: when the current token is
                // one of this loop's own range delimiters (`from` /
                // `between`) the variable was simply omitted, so fall
                // through to "Missing loop variable"; any other keyword
                // was typed as a name, so check_not_keyword gives the
                // accurate "reserved keyword" diagnostic instead of the
                // misleading "Missing loop variable" (BUGS_FOUND #6
                // family). Everything else is genuinely absent.
                if *self.current() != Token::From
                    && *self.current() != Token::Between
                {
                    if let Err(e) = self.check_not_keyword(self.current()) {
                        return Err(e);
                    }
                }
                return Err(self.err(
                    "Missing loop variable after 'for each'\n  \
                     Syntax: For each <variable> from <start> to <end>, <action>.\n  \
                     Example: For each number from 1 to 10, print the number."
                ));
            }
        };
        // A loop variable is a variable, so it claims the one identifier
        // space like any other declaration (plan 310 §4, §10).
        self.claim_name(&variable, NameKind::Variable, variable_pos)?;

        self.skip_noise();
        
        if *self.current() == Token::From || *self.current() == Token::Between {
            let inclusive = true;
            self.advance();
            self.skip_noise();

            let start = self.parse_primary_reserving(true, false)?;
            self.skip_noise();

            // Check if this is a range (has "to") or a collection iteration
            if *self.current() == Token::To || matches!(self.current(), Token::Identifier(s) if s == "to") {
                // Range: from X to Y
                self.advance(); // consume "to"
                self.skip_noise();
                
                let end = self.parse_primary()?;
                self.skip_noise();
                self.expect(&Token::Comma);
                self.skip_noise();
                
                // Parse body - terminated by period (single sentence loop body)
                let mut body = Vec::new();
                loop {
                    if matches!(self.current(), Token::EOF) {
                        break;
                    }
                    if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) {
                        break;
                    }
                    
                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        // Comma continues to next action in same for loop
                        self.advance();
                        self.skip_noise();
                    } else if *self.current() == Token::Period {
                        // Period ends this for loop's body
                        self.advance();
                        self.skip_noise();
                        break;
                    } else if *self.current() == Token::ParagraphBreak {
                        break;
                    }
                }
                
                Ok(Statement::ForRange {
                    variable,
                    range: Expr::Range {
                        start: Box::new(start),
                        end: Box::new(end),
                        inclusive,
                    },
                    body,
                })
            } else {
                // Collection iteration: from <collection>
                // start is actually the collection
                let collection = match start {
                    Expr::StringLit(s) => Expr::Identifier(s),
                    other => other,
                };
                
                // Check for optional "treating X as Y" clause before the comma
                let treating = self.try_parse_treating()?;
                
                self.expect(&Token::Comma);
                self.skip_noise();
                
                // Parse body - terminated by period
                let mut body = Vec::new();
                loop {
                    if matches!(self.current(), Token::EOF) {
                        break;
                    }
                    if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) {
                        break;
                    }
                    
                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                    } else if *self.current() == Token::Period {
                        self.advance();
                        self.skip_noise();
                        break;
                    } else if *self.current() == Token::ParagraphBreak {
                        break;
                    }
                }
                
                // If treating clause present, wrap variable references in body
                let body = if let Some((match_val, replacement)) = treating {
                    self.apply_treating_to_body(body, &variable, match_val, replacement)
                } else {
                    body
                };
                
                // `all the numbers from/between ...` parses as a range,
                // and a range is a loop's counter bounds, never a list
                // header (LANGUAGE.md:262). Route it to the range loop the
                // same way the loop-expansion clause does, or codegen walks
                // it as a list and segfaults (bug #56).
                Ok(Self::for_each_loop(variable, collection, body))
            }
        } else if *self.current() == Token::In {
            self.advance();
            self.skip_noise();
            
            // Parse collection - convert StringLit to Identifier (quoted var names)
            let collection = match self.parse_expression()? {
                Expr::StringLit(s) => Expr::Identifier(s),
                other => other,
            };
            self.skip_noise();
            self.expect(&Token::Comma);
            self.skip_noise();
            
            // Parse body - terminated by period (single sentence loop body)
            let mut body = Vec::new();
            loop {
                if matches!(self.current(), Token::EOF) {
                    break;
                }
                if !body.is_empty() && matches!(self.current(), Token::ParagraphBreak) {
                    break;
                }
                
                let stmt = self.parse_statement()?;
                body.push(stmt);
                self.skip_noise();
                
                if *self.current() == Token::Comma {
                    // Comma continues to next action in same for loop
                    self.advance();
                    self.skip_noise();
                } else if *self.current() == Token::Period {
                    // Period ends this for loop's body
                    self.advance();
                    self.skip_noise();
                    break;
                } else if *self.current() == Token::ParagraphBreak {
                    break;
                }
            }
            
            // Same range-collection routing as the `from` spelling above
            // (bug #56).
            Ok(Self::for_each_loop(variable, collection, body))
        } else {
            Err(self.err("Expected 'from', 'between', or 'in' after for each"))
        }
    }

    pub(crate) fn parse_repeat(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        let count = self.parse_primary()?;
        self.skip_noise();
        self.expect(&Token::Times);
        self.skip_noise();
        self.expect(&Token::Comma);
        self.skip_noise();

        // `Repeat` terminates its body exactly as `While` does — a period
        // closes the innermost open clause (rule 1 names `repeat`), a comma
        // continues, a blank line closes (rule 2, applied uniformly at :150).
        // Share `parse_loop_body` so the two cannot drift apart again.
        let body = self.parse_loop_body()?;

        Ok(Statement::Repeat { count, body })
    }

    /// Try to parse optional "treating X as Y" clause.
    /// Returns Some((match_value, replacement)) if found, None otherwise.
    pub(crate) fn try_parse_treating(&mut self) -> Result<Option<TreatingClause>, Box<CompileError>> {
        if *self.current() != Token::Treating {
            return Ok(None);
        }
        self.advance();
        self.skip_noise();
        
        // Parse match value (simple scalar expressions)
        let match_value = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            Token::IntegerLiteral(n) => { self.advance(); Expr::IntegerLit(n) }
            Token::IntegerLiteralOverflow(raw) => return Err(self.integer_literal_overflow_error(&raw)),
            Token::FloatLiteral(n) => { self.advance(); Expr::FloatLit(n) }
            Token::True => { self.advance(); Expr::BoolLit(true) }
            Token::False => { self.advance(); Expr::BoolLit(false) }
            _ => return Err(self.err(
                "Missing match value after 'treating'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\""
            )),
        };
        self.skip_noise();
        
        // Expect "as"
        let has_as = if *self.current() == Token::As {
            self.advance();
            self.skip_noise();
            true
        } else if let Token::Identifier(s) = self.current() {
            if s.to_lowercase() == "as" {
                self.advance();
                self.skip_noise();
                true
            } else {
                false
            }
        } else {
            false
        };
        
        if !has_as {
            return Err(self.err(&format!(
                "Missing 'as' after 'treating {:?}'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\"",
                match_value
            )));
        }
        
        // Parse replacement (simple scalar expressions)
        let replacement = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            Token::IntegerLiteral(n) => { self.advance(); Expr::IntegerLit(n) }
            Token::IntegerLiteralOverflow(raw) => return Err(self.integer_literal_overflow_error(&raw)),
            Token::FloatLiteral(n) => { self.advance(); Expr::FloatLit(n) }
            Token::True => { self.advance(); Expr::BoolLit(true) }
            Token::False => { self.advance(); Expr::BoolLit(false) }
            _ => return Err(self.err(
                "Missing replacement value after 'as'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\" (or treating \"-\" as 0 for fd stdin)"
            )),
        };
        self.skip_noise();
        
        Ok(Some((match_value, replacement)))
    }

    /// Apply treating substitution to all references of a variable in a statement body.
    /// Wraps Identifier references to the variable with TreatingAs expressions.
    pub(crate) fn apply_treating_to_body(&self, body: Vec<Statement>, variable: &str, match_val: Expr, replacement: Expr) -> Vec<Statement> {
        body.into_iter().map(|stmt| {
            self.apply_treating_to_statement(stmt, variable, &match_val, &replacement)
        }).collect()
    }

    pub(crate) fn apply_treating_to_statement(&self, stmt: Statement, variable: &str, match_val: &Expr, replacement: &Expr) -> Statement {
        match stmt {
            Statement::Print { value, without_newline } => {
                Statement::Print {
                    value: self.apply_treating_to_expr(value, variable, match_val, replacement),
                    without_newline,
                }
            }
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                Statement::If {
                    condition: self.apply_treating_to_expr(condition, variable, match_val, replacement),
                    then_block: self.apply_treating_to_body(then_block, variable, match_val.clone(), replacement.clone()),
                    else_if_blocks: else_if_blocks.into_iter().map(|(cond, block)| {
                        (self.apply_treating_to_expr(cond, variable, match_val, replacement),
                         self.apply_treating_to_body(block, variable, match_val.clone(), replacement.clone()))
                    }).collect(),
                    else_block: else_block.map(|b| self.apply_treating_to_body(b, variable, match_val.clone(), replacement.clone())),
                }
            }
            Statement::Assignment { name, value } => {
                Statement::Assignment {
                    name,
                    value: self.apply_treating_to_expr(value, variable, match_val, replacement),
                }
            }
            Statement::FunctionCall { name, args } => {
                Statement::FunctionCall {
                    name,
                    args: args.into_iter().map(|a| self.apply_treating_to_expr(a, variable, match_val, replacement)).collect(),
                }
            }
            Statement::FileWrite { file, value } => {
                Statement::FileWrite {
                    file,
                    value: self.apply_treating_to_expr(value, variable, match_val, replacement),
                }
            }
            other => other,
        }
    }

    pub(crate) fn apply_treating_to_expr(&self, expr: Expr, variable: &str, match_val: &Expr, replacement: &Expr) -> Expr {
        match expr {
            Expr::Identifier(ref name) if name == variable => {
                Expr::TreatingAs {
                    value: Box::new(expr),
                    match_value: Box::new(match_val.clone()),
                    replacement: Box::new(replacement.clone()),
                }
            }
            Expr::FormatString { parts } => {
                Expr::FormatString {
                    parts: parts.into_iter().map(|part| {
                        match part {
                            FormatPart::Expression { expr, format } => {
                                FormatPart::Expression {
                                    expr: Box::new(self.apply_treating_to_expr(*expr, variable, match_val, replacement)),
                                    format,
                                }
                            }
                            FormatPart::Variable { name, format } if name == variable => {
                                FormatPart::Expression {
                                    expr: Box::new(Expr::TreatingAs {
                                        value: Box::new(Expr::Identifier(name)),
                                        match_value: Box::new(match_val.clone()),
                                        replacement: Box::new(replacement.clone()),
                                    }),
                                    format,
                                }
                            }
                            other => other,
                        }
                    }).collect()
                }
            }
            Expr::BinaryOp { left, op, right } => {
                Expr::BinaryOp {
                    left: Box::new(self.apply_treating_to_expr(*left, variable, match_val, replacement)),
                    op,
                    right: Box::new(self.apply_treating_to_expr(*right, variable, match_val, replacement)),
                }
            }
            other => other,
        }
    }

    /// Try to parse "each <variable> from <collection> [treating X as Y]" pattern.
    /// Returns Some((variable, collection, optional_treating)) if found.
    /// This is the universal loop expansion syntax that works with any action.
    /// Parse `each <var> from <collection>`. When `expect_trailing_to` is set
    /// (the append statement), a `to <dest>` clause follows the collection, so
    /// a range source (`from 1 to 5 to rl`, two `to`s) must be told apart from
    /// a list source (`from source to dest`, one `to`).
    pub(crate) fn try_parse_each_from(&mut self, expect_trailing_to: bool) -> Result<Option<LoopExpansion>, Box<CompileError>> {
        if *self.current() != Token::Each {
            return Ok(None);
        }
        
        self.advance(); // consume 'each'
        self.skip_noise();
        
        // Get loop variable name
        let variable_pos = self.pos;
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
            Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
            _ => {
                // The variable is either genuinely absent or the user
                // typed a reserved keyword where a name belonged (e.g.
                // `each arg from ...` where `arg` is an alias of
                // `argument`). Distinguish: when the current token is
                // this loop's own `from` delimiter the variable was
                // simply omitted, so fall through to "Missing loop
                // variable"; any other keyword was typed as a name, so
                // check_not_keyword gives the accurate "reserved
                // keyword" diagnostic instead of the misleading
                // "Missing loop variable" (BUGS_FOUND #6 family).
                // Everything else is genuinely absent.
                if *self.current() != Token::From {
                    if let Err(e) = self.check_not_keyword(self.current()) {
                        return Err(e);
                    }
                }
                return Err(self.err(
                    "Missing loop variable after 'each'\n  \
                     Syntax: each <variable> from <collection>\n  \
                     Example: each filename from arguments's all"
                ));
            }
        };
        // A loop variable is a variable, so it claims the one identifier
        // space like any other declaration (plan 310 §4, §10).
        self.claim_name(&variable, NameKind::Variable, variable_pos)?;

        self.skip_noise();
        
        // Expect "from"
        if *self.current() != Token::From {
            return Err(self.err(&format!(
                "Missing 'from' after 'each {}'\n  \
                 Syntax: each {} from <collection>\n  \
                 Example: each {} from arguments's all",
                variable, variable, variable
            )));
        }
        self.advance();
        self.skip_noise();
        
        // Get collection to iterate over - could be a range (1 to 15) or a collection expression
        // First parse a primary/simple expression. `to` is reserved here
        // (not available as a nested call connector) because the very next
        // check is for a literal `to` marking either a range bound or, in
        // append-each position, the append separator itself.
        let first = self.parse_primary_reserving(true, false)?;
        self.skip_noise();

        // Check if this is a range: <start> to <end>
        // But only if first is a simple value (number/identifier), not a list or other collection
        let is_list_or_collection = matches!(first, Expr::ListLit { .. } | Expr::PropertyAccess { .. });
        let collection = if *self.current() == Token::To && !is_list_or_collection {
            if expect_trailing_to {
                // Range source (`from 1 to 5 to rl`) vs list source
                // (`from source to dest`): parse the would-be range end
                // speculatively and keep the range only when a second `to`
                // follows. Otherwise the first `to` is the caller's
                // separator - rewind and leave it for the caller. `to` stays
                // reserved for `end` too, so it can't eat the second `to`
                // this disambiguation depends on.
                let saved = self.pos;
                self.advance();
                self.skip_noise();
                let end = self.parse_primary_reserving(true, false)?;
                self.skip_noise();
                if *self.current() == Token::To {
                    Expr::Range {
                        start: Box::new(first),
                        end: Box::new(end),
                        inclusive: true,
                    }
                } else {
                    self.pos = saved;
                    first
                }
            } else {
                self.advance();
                self.skip_noise();
                let end = self.parse_primary_reserving(true, false)?;
                self.skip_noise();
                Expr::Range {
                    start: Box::new(first),
                    end: Box::new(end),
                    inclusive: true,
                }
            }
        } else {
            // Not a range - could be a more complex expression, but we already have first
            // Check if there are binary operators to continue parsing
            first
        };
        self.skip_noise();
        
        // Check for optional "treating X as Y" clause
        let treating = self.try_parse_treating()?;
        
        Ok(Some((variable, collection, treating)))
    }

    /// Wrap a statement in a ForEach loop with the given variable and collection.
    /// Parses any additional comma-separated statements as part of the loop body.
    /// Supports "but if" conditional branching for any action in the loop.
    pub(crate) fn wrap_in_loop_expansion(&mut self, variable: String, collection: Expr, base_stmt: Statement) -> Result<Statement, Box<CompileError>> {
        let body = self.parse_loop_body_tail(base_stmt)?;
        Ok(Self::for_each_loop(variable, collection, body))
    }

    /// After the base action of a loop expansion, parse the optional
    /// `, but if ...` conditional or `, <more statements>` body and the
    /// terminating period. Returns the loop body - the base statement,
    /// wrapped in a conditional chain when `but if` is present, plus any
    /// extra comma-separated statements. A loop expansion is a
    /// self-terminating statement, so it owns its trailing period the way
    /// `If`/`While`/`For` do; the top-level loop's `expect(Period)` is
    /// tolerant of that.
    fn parse_loop_body_tail(&mut self, base_stmt: Statement) -> Result<Vec<Statement>, Box<CompileError>> {
        let mut body = vec![base_stmt];

        // Check for comma to parse additional body statements or "but if" conditionals
        if *self.current() == Token::Comma {
            self.advance();
            self.skip_noise();

            // Check for "but if" conditional branching (wraps the base statement
            // in a conditional chain, regardless of what kind of statement it is).
            if *self.current() == Token::But {
                self.advance();
                self.skip_noise();

                if *self.current() == Token::If {
                    let base_stmt = body.pop().unwrap();
                    let conditional_stmt = self.parse_conditional_suffix(base_stmt)?;
                    body.push(conditional_stmt);
                } else {
                    return Err(self.err("Expected 'if' after 'but'"));
                }
            } else {
                // Parse remaining statements in the sentence
                loop {
                    if matches!(self.current(), Token::EOF) {
                        break;
                    }
                    if *self.current() == Token::ParagraphBreak {
                        self.advance();
                        self.skip_noise();
                        continue;
                    }
                    if *self.current() == Token::Period {
                        break;
                    }

                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();

                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                        // Paragraph breaks are visual spacing and may appear after commas.
                        while *self.current() == Token::ParagraphBreak {
                            self.advance();
                            self.skip_noise();
                        }
                    } else if *self.current() == Token::ParagraphBreak {
                        self.advance();
                        self.skip_noise();
                    }
                }
            }
        }

        // Consume period if present
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }

        Ok(body)
    }

    /// Build the single loop statement for one expansion clause: `ForRange`
    /// for a range collection, `ForEach` for anything else. An associated
    /// function (no `self`): it only assembles a statement.
    fn for_each_loop(variable: String, collection: Expr, body: Vec<Statement>) -> Statement {
        match collection {
            Expr::Range { .. } => Statement::ForRange {
                variable,
                range: collection,
                body,
            },
            _ => Statement::ForEach {
                variable,
                collection,
                body,
            },
        }
    }

    /// The argument expression a loop expansion contributes to its call:
    /// the loop variable, optionally wrapped in a `treating X as Y`
    /// substitution when the clause had one.
    pub(crate) fn each_arg_expr(variable: &str, treating: &Option<TreatingClause>) -> Expr {
        if let Some((match_val, replacement)) = treating {
            Expr::TreatingAs {
                value: Box::new(Expr::Identifier(variable.to_string())),
                match_value: Box::new(match_val.clone()),
                replacement: Box::new(replacement.clone()),
            }
        } else {
            Expr::Identifier(variable.to_string())
        }
    }

    /// Parse a call's argument clauses after a connector (`of`/`to`/`with`/
    /// `on`): a non-empty sequence of clauses joined by `and`, where each
    /// clause is either a loop expansion (`each <name> from <collection>
    /// [treating X as Y]`) or a plain expression. The expansions become
    /// nested loops (left-to-right = outermost-to-innermost); the fixed
    /// expressions ride along as per-call arguments (plan 320).
    ///
    /// Two `each` clauses that bind the same variable are a compile error
    /// named for the variable - the nested loops would shadow, and the
    /// sentence does not say which collection a bare use of the name means.
    pub(crate) fn parse_arg_clauses(&mut self) -> Result<Vec<ArgClause>, Box<CompileError>> {
        let mut clauses = Vec::new();
        let mut expansion_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            // The position of `each`, so a duplicate-variable diagnostic can
            // land its caret on the offending clause.
            let each_pos = self.pos;
            if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
                if !expansion_vars.insert(variable.clone()) {
                    self.pos = each_pos;
                    return Err(self.err(&format!(
                        "Loop variable '{}' is bound twice in one sentence.\n  \
                         Each `each` clause must use a different name; for paired \
                         iteration use separate statements.",
                        variable
                    )));
                }
                clauses.push(ArgClause::Expansion((variable, collection, treating)));
            } else {
                let expr = self.parse_expression()?;
                clauses.push(ArgClause::Fixed(expr));
            }

            self.skip_noise();
            if *self.current() == Token::And {
                self.advance();
                self.skip_noise();
            } else {
                break;
            }
        }
        Ok(clauses)
    }

    /// Split parsed clauses into the call's argument list and the loop
    /// expansions to wrap around it, in source order (outermost first).
    pub(crate) fn clauses_to_args_and_expansions(
        clauses: &[ArgClause],
    ) -> (Vec<Expr>, Vec<LoopExpansion>) {
        let mut args = Vec::new();
        let mut expansions = Vec::new();
        for clause in clauses {
            match clause {
                ArgClause::Expansion((variable, collection, treating)) => {
                    args.push(Self::each_arg_expr(variable, treating));
                    expansions.push((variable.clone(), collection.clone(), treating.clone()));
                }
                ArgClause::Fixed(expr) => {
                    args.push(expr.clone());
                }
            }
        }
        (args, expansions)
    }

    /// Wrap an inner statement in the nested loops of a grid: one loop per
    /// expansion clause, the first clause outermost. The inner statement is
    /// the call (or a `print` of a call); the `, but if ...` / body / period
    /// tail attaches to that innermost iteration, and its conditions can
    /// reference every loop variable because every loop is outside it.
    pub(crate) fn finish_grid(
        &mut self,
        inner_stmt: Statement,
        expansions: Vec<LoopExpansion>,
    ) -> Result<Statement, Box<CompileError>> {
        let mut body = self.parse_loop_body_tail(inner_stmt)?;
        // Wrap innermost-first so the first clause ends up outermost.
        for (variable, collection, _treating) in expansions.iter().rev() {
            let wrapped = Self::for_each_loop(
                variable.clone(),
                collection.clone(),
                std::mem::take(&mut body),
            );
            body = vec![wrapped];
        }
        // `parse_loop_body_tail` always returns at least the base statement,
        // and every caller passes a non-empty `expansions`, so there is a
        // wrapped loop to hand back.
        Ok(body.into_iter().next().unwrap())
    }

    /// The diagnostic for a one-value-slot action (`print`, `append`, `open`)
    /// given more than one argument clause: those forms take a single value,
    /// so a grid of two or more `each` clauses is an arity error, not a
    /// concatenation. Worded without a count so it stays honest whether the
    /// extra clauses are `each` clauses, fixed arguments, or a mix — `print`
    /// of one value plus anything else is the same mistake (plan 320 rule 4).
    pub(crate) fn one_slot_arity_error(&self, action: &str) -> Box<CompileError> {
        self.err(&format!(
            "`{}` takes one value but this sentence supplies more than one argument clause.",
            action
        ))
    }

    pub(crate) fn parse_on_error(&mut self) -> Result<Statement, Box<CompileError>> {
        // "On error <action>, <action>, <action>." - consumes full sentence
        self.advance(); // consume 'on'
        self.skip_noise();
        
        if *self.current() != Token::Error {
            return Err(self.err(
                "Expected 'error' after 'on'\n  \
                 Syntax: On error <action>.\n  \
                 Example: On error print \"Something went wrong\", exit 1."
            ));
        }
        self.advance();
        self.skip_noise();
        
        // Parse comma-separated actions until end of sentence
        let actions = self.parse_sentence_body()?;
        
        if actions.is_empty() {
            return Err(self.err(
                "Missing action after 'on error'\n  \
                 Syntax: On error <action>.\n  \
                 Example: On error print \"Read failed\", exit 1."
            ));
        }
        
        Ok(Statement::OnError { actions })
    }

    pub(crate) fn parse_auto_error(&mut self) -> Result<Statement, Box<CompileError>> {
        // Feature deferred - auto error catching not yet implemented
        Err(self.err(
            "'auto error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }

    pub(crate) fn parse_enable(&mut self) -> Result<Statement, Box<CompileError>> {
        // Feature deferred - enable error catching not yet implemented
        Err(self.err(
            "'enable error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }

    pub(crate) fn parse_disable(&mut self) -> Result<Statement, Box<CompileError>> {
        // Feature deferred - disable error catching not yet implemented
        Err(self.err(
            "'disable error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }

    /// Parse the body of an `If`/`otherwise if` branch.
    ///
    /// A branch body is a comma-separated sequence of statements. Each statement
    /// may itself be a nested construct (e.g. another `If`) that owns its own
    /// trailing period. The body ends when we reach a top-level else-chain
    /// keyword (`But`, `Else`, `Otherwise`), `EOF`, or a paragraph break. A
    /// trailing comma immediately before the boundary is allowed.
    pub(crate) fn parse_block(&mut self) -> Result<Vec<Statement>, Box<CompileError>> {
        let mut statements = Vec::new();

        loop {
            // The next token starts the enclosing `If`'s else-chain, or we
            // have reached the end of the input.
            if matches!(
                self.current(),
                Token::But | Token::Else | Token::Otherwise | Token::EOF
            ) {
                break;
            }

            let stmt = self.parse_statement()?;
            let is_on_error = matches!(stmt, Statement::OnError { .. });
            // A self-terminating nested construct (If/While/For/Repeat)
            // consumes its own trailing period; see the note below for why we
            // track this. `Repeat` now consumes its period the same way
            // `While`/`For` do (BUGS_FOUND #27), so it belongs here too —
            // without it, a `Repeat` that is not the last action in a branch
            // would orphan the action following it.
            let is_self_terminated = matches!(
                stmt,
                Statement::If { .. } | Statement::While { .. }
                    | Statement::ForRange { .. } | Statement::ForEach { .. }
                    | Statement::Repeat { .. }
            );
            statements.push(stmt);

            self.skip_noise();

            // `On error` can chain directly into the next action without an
            // intervening comma or period.
            if is_on_error {
                if matches!(
                    self.current(),
                    Token::But
                        | Token::Else
                        | Token::Otherwise
                        | Token::EOF
                        | Token::Period
                        | Token::ParagraphBreak
                ) {
                    break;
                }
                continue;
            }

            // A self-terminating nested construct — `If`, `While`, `For each`,
            // `For ... to`, `Repeat` — owns and consumes its own trailing period
            // (see `parse_if`'s final period consume, and `parse_loop_body`,
            // shared by `parse_while`/`parse_repeat`, plus the body loops in
            // `parse_for`). When such a construct is an action in
            // a comma-separated branch, the next action therefore follows with
            // NO comma separator: the nested construct's period already served
            // as the separator. Without this, a complete nested `If ... then,
            // X.` followed by another action in the same branch would orphan
            // that action (and every later one), closing the enclosing
            // statement early. Only continue when the next token genuinely
            // starts another action; boundaries (else-chain, period, comma,
            // paragraph, EOF) are handled by the loop top or the arms below.
            if is_self_terminated && !matches!(
                self.current(),
                Token::Comma
                    | Token::Period
                    | Token::ParagraphBreak
                    | Token::EOF
                    | Token::But
                    | Token::Else
                    | Token::Otherwise
            ) {
                continue;
            }

            // A comma continues the body, a period ends the current statement
            // and therefore the body (the period is left for the caller so
            // standalone `if` sentences can own their own terminator).
            if *self.current() == Token::Comma {
                self.advance();
                self.skip_all_whitespace();

                // Trailing comma right before the else-chain boundary.
                if matches!(
                    self.current(),
                    Token::But | Token::Else | Token::Otherwise | Token::EOF | Token::ParagraphBreak
                ) {
                    break;
                }

                continue;
            }

            // Period, paragraph break, EOF, or an unexpected token ends the
            // body. Leave the terminator for the caller.
            break;
        }

        Ok(statements)
    }

    /// Parse comma-separated statements until end of sentence (period).
    /// This is the standard pattern for action-consuming constructs like:
    /// - on error <action>, <action>, <action>.
    /// - while <cond>, <action>, <action>.
    /// - for each X, <action>, <action>.
    ///
    /// The loop also stops at the start of an enclosing `If` else-chain so a
    /// trailing comma before `But`/`Else`/`Otherwise` does not swallow the
    /// boundary token.
    pub(crate) fn parse_sentence_body(&mut self) -> Result<Vec<Statement>, Box<CompileError>> {
        let mut statements = Vec::new();

        loop {
            // Stop at end of sentence markers or at an enclosing if-chain.
            if matches!(
                self.current(),
                Token::Period | Token::EOF | Token::ParagraphBreak
                    | Token::But | Token::Else | Token::Otherwise
            ) {
                break;
            }

            let stmt = self.parse_statement()?;
            statements.push(stmt);
            self.skip_noise();

            // Comma continues to next action, period ends. A comma immediately
            // followed by an if-chain boundary ends the sentence here.
            if *self.current() == Token::Comma {
                self.advance();
                self.skip_noise();

                if matches!(
                    self.current(),
                    Token::But | Token::Else | Token::Otherwise | Token::EOF | Token::ParagraphBreak
                ) {
                    break;
                }
            } else {
                break;
            }
        }

        // Consume the period if present
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }

        Ok(statements)
    }

}
