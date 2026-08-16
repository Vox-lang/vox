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
            } else if !matches!(self.current(), Token::But | Token::Comma | Token::And) {
                break;
            }

            // Remember if we started with comma (for ", but if" syntax)
            let started_with_comma = *self.current() == Token::Comma;
            self.advance();
            self.skip_noise();

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

    pub(crate) fn parse_while(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let condition = self.parse_condition()?;
        self.skip_noise();
        self.expect(&Token::Comma);
        self.skip_noise();
        
        // Parse body: comma continues actions, period ends this while statement.
        // Paragraph breaks are visual spacing and may appear after commas.
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
            
            // Consume separator and decide whether to continue
            if *self.current() == Token::Comma {
                // Comma continues to next action in same sentence
                self.advance();
                self.skip_noise();
                // Skip paragraph breaks after comma (visual spacing within sentence)
                while *self.current() == Token::ParagraphBreak {
                    self.advance();
                    self.skip_noise();
                }
            } else if *self.current() == Token::Period {
                self.advance();
                self.skip_noise();
                break;
            } else if *self.current() == Token::ParagraphBreak {
                break;
            } else if *self.current() == Token::EOF {
                break;
            }
        }
        
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
        
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
            Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
            _ => return Err(self.err(
                "Missing loop variable after 'for each'\n  \
                 Syntax: For each <variable> from <start> to <end>, <action>.\n  \
                 Example: For each number from 1 to 10, print the number."
            )),
        };
        
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
                
                Ok(Statement::ForEach {
                    variable,
                    collection,
                    body,
                })
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
            
            Ok(Statement::ForEach {
                variable,
                collection,
                body,
            })
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
        
        // Parse body - terminated by period followed by major keyword or paragraph break
        let mut body = Vec::new();
        loop {
            if matches!(self.current(), Token::ParagraphBreak | Token::EOF) {
                break;
            }
            if !body.is_empty() && self.is_block_terminator() {
                break;
            }
            
            let stmt = self.parse_statement()?;
            body.push(stmt);
            self.skip_noise();
            
            if matches!(self.current(), Token::Period) {
                self.advance();
                self.skip_noise();
                if self.is_block_terminator() || matches!(self.current(), Token::ParagraphBreak | Token::EOF) {
                    break;
                }
            }
        }
        
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
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
            Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
            _ => return Err(self.err(
                "Missing loop variable after 'each'\n  \
                 Syntax: each <variable> from <collection>\n  \
                 Example: each filename from arguments's all"
            )),
        };
        
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
        
        // Use ForRange for range collections, ForEach otherwise
        match collection {
            Expr::Range { .. } => Ok(Statement::ForRange {
                variable,
                range: collection,
                body,
            }),
            _ => Ok(Statement::ForEach {
                variable,
                collection,
                body,
            }),
        }
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
            // A self-terminating nested construct (If/While/For) consumes its
            // own trailing period; see the note below for why we track this.
            let is_self_terminated = matches!(
                stmt,
                Statement::If { .. } | Statement::While { .. }
                    | Statement::ForRange { .. } | Statement::ForEach { .. }
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
            // `For ... to` — owns and consumes its own trailing period (see
            // `parse_if`'s final period consume, and the body loops in
            // `parse_while`/`parse_for`). When such a construct is an action in
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
