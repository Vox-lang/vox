use super::*;

impl Parser {
    pub(crate) fn make_error(&self, message: &str) -> Box<CompileError> {
        let mut err = CompileError::new(message);
        if let Some(loc) = self.current_location() {
            err = err.with_location(loc);
        }
        Box::new(err)
    }

    pub(crate) fn make_error_with_suggestion(&self, message: &str, got: &str) -> Box<CompileError> {
        let mut err = *self.make_error(message);
        if let Some(suggestion) = find_similar_keyword(got, ENGLISH_KEYWORDS) {
            err = err.with_suggestion(&suggestion);
        }
        Box::new(err)
    }

    pub(crate) fn err(&self, message: &str) -> Box<CompileError> {
        self.make_error(message)
    }

    pub(crate) fn err_expected(&self, expected: &str, got: &Token) -> Box<CompileError> {
        let got_str = format!("{:?}", got);
        let msg = format!("Expected {}, got {:?}", expected, got);
        self.make_error_with_suggestion(&msg, &got_str)
    }

    /// Creates an error for invalid buffer size specifications
    pub fn error_invalid_buffer_size(
        &self,
        buffer_name: &str,
        reason: &str,
        example: &str,
    ) -> Box<CompileError> {
        self.err(&format!(
            "Invalid buffer size for \"{}\": {}\n  \
             Hint: {}\n  \
             Example: {}",
            buffer_name, reason, 
            "Buffer sizes must be positive integer literals for memory safety.",
            example
        ))
    }

    /// Creates an error for expected token mismatches
    pub fn error_expected_token(&self, expected: &str, actual: &Token) -> Box<CompileError> {
        self.err(&format!(
            "Expected '{}' but found '{:?}'\n  \
             Check your syntax and ensure all keywords are spelled correctly.",
            expected, actual
        ))
    }

    /// Emits a warning for uninitialized buffers (zero capacity)
    pub fn warn_uninitialized_buffer(&self, buffer_name: &str) {
        eprintln!(
            "Warning: Buffer \"{}\" declared without size or initializer.\n  \
             This creates a zero-capacity buffer which may not be useful.\n  \
             Consider: a buffer called '{}' is 1024 bytes.",
            buffer_name, buffer_name
        );
    }

    /// Check if a token is a reserved keyword and return an error if so.
    /// This catches ALL language keywords, not just a hardcoded subset.
    ///
    /// The diagnostic names the identifier the user *actually typed*, not
    /// the compiler's internal canonical keyword: the lexer folds aliases
    /// like `length` onto `Token::Size` before this runs, so without
    /// recovering the source spelling the message would blame `size` for a
    /// `length` the user wrote (BUGS_FOUND #6). When the typed spelling is
    /// an alias of the canonical keyword, the message says so.
    pub(crate) fn check_not_keyword(&self, token: &Token) -> Result<(), Box<CompileError>> {
        if let Some(keyword) = token.as_keyword() {
            let typed = self.current_lexeme().unwrap_or_else(|| keyword.to_string());
            let alias_note = if typed != keyword {
                format!(
                    "\n  '{}' is an alternate spelling of the reserved keyword '{}'.",
                    typed, keyword
                )
            } else {
                String::new()
            };
            Err(self.make_error(&format!(
                "Cannot use '{}' as a variable name - it's a reserved keyword.{}\n  \
                 Tip: Try a more descriptive name like '{}_value' or 'my_{}'",
                typed, alias_note, typed, typed
            )))
        } else {
            Ok(())
        }
    }

    /// Whether a string is a legal *bare* identifier (plan 270 §2:
    /// `[A-Za-z_][A-Za-z0-9_]*`). Used to pick the `help:` suggestion form.
    pub(crate) fn is_bare_legal_name(s: &str) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// Build the `help:` text for the §S1.5 diagnostic: bare when the name is
    /// bare-legal, `'quoted'` (plus an underscore alternative) when it has
    /// spaces, `'quoted'` alone otherwise.
    pub(crate) fn suggest_name_form(s: &str) -> String {
        if Self::is_bare_legal_name(s) {
            format!("write `{}`", s)
        } else {
            let underscored: String = s
                .chars()
                .map(|c| if c == ' ' { '_' } else { c })
                .collect();
            if s.contains(' ') && Self::is_bare_legal_name(&underscored) {
                format!("write `'{}'` (it contains spaces), or `{}`", s, underscored)
            } else {
                format!("write `'{}'`", s)
            }
        }
    }

    /// The plan-270 §S1.5 diagnostic: a string literal was found where a name
    /// is expected. The underline spans the whole `"..."` token; the `help:`
    /// line suggests the right replacement.
    pub(crate) fn err_string_as_name(&self, s: &str) -> Box<CompileError> {
        let mut err = CompileError::new("expected a name, found a string literal");
        if let Some(loc) = self.current_location() {
            err = err.with_location(loc);
        }
        // The lexer records the column of the opening `"`. Span the whole
        // literal: content chars + the two quote characters.
        let span = s.chars().count() + 2;
        err = err
            .with_underline_note(span, "strings are data; names are bare or 'single-quoted'")
            .with_help_line(&Self::suggest_name_form(s));
        Box::new(err)
    }

    /// Parse a name in an identifier position (plan 270 §S1.5). Accepts a bare
    /// or quoted identifier (both lex as `Token::Identifier`); rejects a
    /// string literal with the teaching diagnostic; rejects reserved
    /// keywords (unchanged behaviour). Use this everywhere a *name* is
    /// expected — declarations, callees, targets, parameters.
    pub(crate) fn parse_name(&mut self) -> Result<String, Box<CompileError>> {
        // Reserved keywords remain rejected as names.
        self.check_not_keyword(self.current())?;
        match self.current().clone() {
            Token::Identifier(n) => {
                self.advance();
                Ok(n)
            }
            Token::StringLiteral(s) => Err(self.err_string_as_name(&s)),
            other => Err(self.err_expected("a name", &other)),
        }
    }

    pub(crate) fn parse_var_decl(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume Set/Create
        self.skip_noise();
        
        // Handle "Set byte N of buffer to value"
        if *self.current() == Token::Byte {
            self.advance();
            self.skip_noise();
            let index = self.parse_primary_reserving(false, true)?;
            self.skip_noise();
            if *self.current() != Token::Of {
                return Err(self.err("Expected 'of' after byte index"));
            }
            self.advance();
            self.skip_noise();
            let buffer = self.parse_name()?;
            self.skip_noise();
            self.skip_noise();
            if *self.current() != Token::To {
                return Err(self.err("Expected 'to' after buffer name"));
            }
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::ByteSet { buffer, index, value });
        }
        
        // Handle "Set element N of list to value"
        if *self.current() == Token::Element {
            self.advance();
            self.skip_noise();
            let index = self.parse_primary_reserving(false, true)?;
            self.skip_noise();
            if *self.current() != Token::Of {
                return Err(self.err("Expected 'of' after element index"));
            }
            self.advance();
            self.skip_noise();
            let list = self.parse_name()?;
            self.skip_noise();
            if *self.current() != Token::To {
                return Err(self.err("Expected 'to' after list name"));
            }
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::ElementSet { list, index, value });
        }

        // `Set origin's x to 3.` writes a field of a thing (plan 310 §3). This
        // sits before the map-access attempt below because that one swallows a
        // failed parse to fall through to the generic path: a mistyped field
        // name must reach its own diagnostic, not be re-read as something else.
        if let Some((base, path, _)) = self.try_parse_thing_field_target()? {
            self.skip_noise();
            if !matches!(self.current(), Token::To | Token::Is | Token::Equals) {
                return Err(self.err_expected("'to' after a field of a thing", self.current()));
            }
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::SetThingField { base, path, value });
        }

        // Handle "Set <map>'s \"<key>\" to <value>" (map insert/replace).
        // The target `<map>'s \"<key>\"` parses as an Expr::MapAccess, so we
        // tentatively parse a primary and commit only if it is a MapAccess
        // followed by `to`. Otherwise we restore position and let the
        // generic declaration/assignment path below handle it (e.g.
        // `Set x to 5.`). (stage 1e2, tag 5)
        if matches!(self.current(), Token::Identifier(_)) {
            let saved = self.pos;
            let target = self.parse_primary();
            if let Ok(Expr::MapAccess { map, key }) = target {
                self.skip_noise();
                if *self.current() == Token::To {
                    self.advance();
                    self.skip_noise();
                    let value = self.parse_expression()?;
                    return Ok(Statement::MapSet { map, key: *key, value });
                }
            }
            self.pos = saved;
        }

        // Handle "the/a/an <type> called <name>" pattern
        if matches!(self.current(), Token::The | Token::A | Token::An) {
            self.advance();
            self.skip_noise();
        }

        // `Create a thing called point.` is never valid Vox, in any version
        // (plan 310 §10): a thing is defined, not created as a variable.
        // This reaches `Set`/`store`/`assign` too, since `define a thing
        // called point has ...` lexes as `Create` and both verbs express
        // the same wrong intent.
        if self.thing_definition_follows() {
            return Err(self.err_thing_created_as_variable());
        }

        // Check for typed declaration: "<type> called <name>". A defined
        // thing's name is a type noun here exactly like a builtin one, which
        // is what makes `Create a point called p.` valid and equivalent to
        // `a point called p.` (plan 310 §10).
        let var_type = self
            .try_parse_type_noun()
            .or_else(|| self.try_parse_thing_type_noun());

        if let Some(var_type) = var_type {
            // Types that must be followed by `called` in declaration position
            // get their existing specific diagnostic before the generic expect.
            match var_type {
                Type::Buffer => self.require_called_after_type(
                    "buffer",
                    "a buffer called name",
                )?,
                Type::Time => self.require_called_after_type(
                    "time",
                    "a time called name is current time",
                )?,
                Type::Timer => self.require_called_after_type(
                    "timer",
                    "a timer called name",
                )?,
                _ => {}
            }

            self.skip_noise();
            self.expect(&Token::Called);
            self.skip_noise();

            // Check for keyword used as variable name
            self.check_not_keyword(self.current())?;

            let name_pos = self.pos;
            let name = self.parse_name()?;

            self.skip_noise();

            // A thing declaration takes no initializer in this task, and its
            // name may not reuse the thing's own (plan 310 §5, §10).
            if let Type::Thing(thing) = var_type {
                return self.finish_thing_declaration(thing, name, name_pos);
            }

            // Timer has its own statement type.
            if var_type == Type::Timer {
                return Ok(Statement::TimerDecl { name });
            }

            // Time and file variables are meaningless without an initializer.
            if var_type == Type::Time {
                if !matches!(self.current(), Token::Is | Token::Equals) {
                    return Err(self.err(
                        "A time variable must be initialized\n  \
                         Example: a time called now is current time."
                    ));
                }
                self.advance();
                self.skip_noise();
                let value = Some(self.parse_expression()?);
                return Ok(Statement::VarDecl {
                    name,
                    var_type: Some(Type::Time),
                    value,
                });
            }

            if var_type == Type::File {
                if !matches!(self.current(), Token::Is | Token::Equals) {
                    return Err(self.err(
                        "A file variable must be initialized with a path\n  \
                         Example: a file called source is \"input.txt\"."
                    ));
                }
                self.advance();
                self.skip_noise();
                let value = Some(self.parse_expression()?);
                return Ok(Statement::VarDecl {
                    name,
                    var_type: Some(Type::File),
                    value,
                });
            }

            // Handle buffer creation with size: "Create a buffer called X with/of size N"
            if var_type == Type::Buffer {
                // Check for "with size N" or "of size N" syntax
                if *self.current() == Token::With || *self.current() == Token::Of {
                    self.advance();
                    self.skip_noise();
                    self.expect(&Token::Size);
                    self.skip_noise();
                    let size = self.parse_primary()?;
                    return Ok(Statement::BufferDecl { name, size });
                }
                // No size specified - dynamic buffer
                return Ok(Statement::BufferDecl {
                    name,
                    size: Expr::IntegerLit(0),
                });
            }

            // Other types: parse value or leave it as None to get the type's default.
            let value = if matches!(self.current(), Token::To | Token::Equals | Token::Is) {
                self.advance();
                self.skip_noise();
                Some(self.parse_expression()?)
            } else if matches!(self.current(), Token::Period | Token::Comma | Token::EOF | Token::ParagraphBreak) {
                None
            } else {
                // Try to parse an expression (for cases without explicit "to")
                Some(self.parse_expression()?)
            };

            return Ok(Statement::VarDecl {
                name,
                var_type: Some(var_type),
                value,
            });
        }

        // No type noun: parse the name directly (with optional "called" for
        // the bare untyped forms).
        let name = if *self.current() == Token::Called {
            self.advance();
            self.skip_noise();
            self.parse_name()
        } else {
            self.parse_name()
        }?;

        self.skip_noise();

        // Check if there's a value assignment
        let value = if matches!(self.current(), Token::To | Token::Equals | Token::Is) {
            self.advance();
            self.skip_noise();
            Some(self.parse_expression()?)
        } else if matches!(self.current(), Token::Period | Token::Comma | Token::EOF | Token::ParagraphBreak) {
            None
        } else {
            // Try to parse an expression (for cases without explicit "to")
            Some(self.parse_expression()?)
        };

        Ok(Statement::VarDecl {
            name,
            var_type,
            value,
        })
    }

    /// Resolve a type noun at the current token position.
    ///
    /// If the current token names a declarable type, consumes it and returns
    /// `Some(Type)`.  For the identifier `value`, this only happens when it
    /// sits directly before `called`, so that `a value is 5.` still declares
    /// a variable named `value`.  The function does *not* consume that `called`
    /// token, leaving it for the caller.  If the current token is not a type
    /// noun, returns `None` without consuming anything.
    pub(crate) fn try_parse_type_noun(&mut self) -> Option<Type> {
        match self.current() {
            Token::Number | Token::Int => { self.advance(); Some(Type::Integer) }
            Token::Float => { self.advance(); Some(Type::Float) }
            Token::Text => { self.advance(); Some(Type::String) }
            Token::Boolean => { self.advance(); Some(Type::Boolean) }
            Token::File => { self.advance(); Some(Type::File) }
            Token::List => { self.advance(); Some(Type::List(Box::new(Type::Unknown))) }
            Token::Map => { self.advance(); Some(Type::Map(Box::new(Type::Unknown))) }
            Token::Buffer => { self.advance(); Some(Type::Buffer) }
            Token::Time => { self.advance(); Some(Type::Time) }
            Token::Timer => { self.advance(); Some(Type::Timer) }
            // `value` is not a reserved keyword, so it only denotes the dynamic
            // type when it sits directly before `called`.  `a value is 5.` still
            // declares a variable named `value`.
            Token::Identifier(n) if n == "value" && *self.peek(1) == Token::Called => {
                self.advance();
                Some(Type::Value)
            }
            _ => None,
        }
    }

    /// Verify that a type noun which requires `called` in declaration position
    /// is actually followed by it.  Callers that resolve a type via
    /// `try_parse_type_noun` use this for `buffer`, `time`, and `timer` to keep
    /// their diagnostic messages specific.
    pub(crate) fn require_called_after_type(
        &mut self,
        type_name: &str,
        syntax: &str,
    ) -> Result<(), Box<CompileError>> {
        self.skip_noise();
        if *self.current() != Token::Called {
            return Err(self.err(
                &format!(
                    "Missing 'called' after '{}'\n  Syntax: {}.",
                    type_name, syntax
                )
            ));
        }
        Ok(())
    }

    pub(crate) fn parse_typed_var_decl(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'a' or 'an'
        self.skip_noise();

        if *self.current() == Token::Flag {
            return self.parse_flag_schema_decl();
        }

        // `A thing called <name> has ...` defines a type, not a variable
        // (plan 310 §1). `thing` is not a lexer keyword, so the construct is
        // recognised by sentence shape and `thing` stays an ordinary
        // identifier everywhere else.
        if self.thing_definition_follows() {
            return self.parse_thing_definition();
        }

        // Parse type noun: number, int, float, text, boolean, list, map,
        // buffer, file, time, timer, value - or a defined thing's name, which
        // works everywhere a type keyword works (plan 310 §1).
        let var_type = self
            .try_parse_type_noun()
            .or_else(|| self.try_parse_thing_type_noun());

        // Types that must be followed by `called` in declaration position
        // get their existing specific diagnostic before the generic expect.
        if let Some(ref var_type) = var_type {
            match var_type {
                Type::Buffer => self.require_called_after_type(
                    "buffer",
                    "a buffer called name",
                )?,
                Type::Time => self.require_called_after_type(
                    "time",
                    "a time called name is current time",
                )?,
                Type::Timer => self.require_called_after_type(
                    "timer",
                    "a timer called name",
                )?,
                _ => {}
            }
        }

        self.skip_noise();
        self.expect(&Token::Called);
        self.skip_noise();

        // Check for keyword used as variable name
        self.check_not_keyword(self.current())?;

        // Get variable name (plan 270: bare or quoted identifier, never a
        // string literal).
        let name_pos = self.pos;
        let name = self.parse_name()?;

        self.skip_noise();

        // A thing declaration takes no initializer in this task, and its name
        // may not reuse the thing's own (plan 310 §5, §10).
        if let Some(Type::Thing(thing)) = var_type {
            return self.finish_thing_declaration(thing, name, name_pos);
        }

        // Timer has its own statement type.
        if var_type == Some(Type::Timer) {
            return Ok(Statement::TimerDecl { name });
        }

        // File and time variables are meaningless without an initializer.
        if var_type == Some(Type::File) {
            if !matches!(self.current(), Token::Is | Token::Equals) {
                return Err(self.err(
                    "A file variable must be initialized with a path\n  \
                     Example: a file called source is \"input.txt\"."
                ));
            }
            self.advance();
            self.skip_noise();
            let value = Some(self.parse_expression()?);
            return Ok(Statement::VarDecl {
                name,
                var_type: Some(Type::File),
                value,
            });
        }

        if var_type == Some(Type::Time) {
            if !matches!(self.current(), Token::Is | Token::Equals) {
                return Err(self.err(
                    "A time variable must be initialized\n  \
                     Example: a time called now is current time."
                ));
            }
            self.advance();
            self.skip_noise();
            let value = Some(self.parse_expression()?);
            return Ok(Statement::VarDecl {
                name,
                var_type: Some(Type::Time),
                value,
            });
        }

        // Handle buffer creation with size or initializer.
        if var_type == Some(Type::Buffer) {
            if self.expect(&Token::Is) {
                self.skip_noise();
                let expr = self.parse_primary()?;
                self.skip_noise();

                // Check if this is a size clause (has "bytes" keyword) or an initializer
                if *self.current() == Token::Bytes {
                    // Size clause
                    self.advance();
                    self.skip_noise();

                    // Handle optional "in size" suffix
                    if *self.current() == Token::In {
                        self.advance();
                        self.skip_noise();
                        if !self.expect(&Token::Size) {
                            return Err(self.error_expected_token("size", self.current()));
                        }
                    }

                    // Validate that the size expression is a positive integer literal
                    // or constant variable. This is critical for memory safety.
                    match &expr {
                        Expr::IntegerLit(n) => {
                            if *n <= 0 {
                                return Err(self.error_invalid_buffer_size(
                                    &name,
                                    "Buffer size must be a positive integer",
                                    "a buffer called buf is 1024 bytes."
                                ));
                            }
                            const MAX_BUFFER_SIZE: i64 = 1024 * 1024 * 1024; // 1 GB limit
                            if *n > MAX_BUFFER_SIZE {
                                return Err(self.error_invalid_buffer_size(
                                    &name,
                                    &format!("Buffer size exceeds maximum allowed ({} bytes)", MAX_BUFFER_SIZE),
                                    "Consider using smaller buffers or streaming for large data."
                                ));
                            }
                        }
                        Expr::Identifier(_var_name) => {
                            // Allow variable references for size - validated at compile time
                        }
                        _ => {
                            return Err(self.error_invalid_buffer_size(
                                &name,
                                "Buffer size must be a numeric literal or constant variable",
                                "a buffer called buf is 1024 bytes."
                            ));
                        }
                    }

                    return Ok(Statement::BufferDecl { name, size: expr });
                } else {
                    // No "bytes" keyword - this is an initializer expression
                    return Ok(Statement::VarDecl {
                        name,
                        var_type: Some(Type::Buffer),
                        value: Some(expr),
                    });
                }
            } else {
                // No "is" clause - this is a zero-capacity dynamic buffer
                self.warn_uninitialized_buffer(&name);
                return Ok(Statement::BufferDecl {
                    name,
                    size: Expr::IntegerLit(0),
                });
            }
        }

        // Parse value if present: "is <value>"
        let value = if matches!(self.current(), Token::Is | Token::Equals) {
            self.advance();
            self.skip_noise();
            Some(self.parse_expression()?)
        } else {
            None
        };

        Ok(Statement::VarDecl {
            name,
            var_type,
            value,
        })
    }

    pub(crate) fn parse_the_statement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'the'
        self.skip_noise();

        // Could be "the <type> called <name>" (typed reference) or just a name.
        let var_type = self.try_parse_type_noun();
        let name = if let Some(_) = var_type {
            self.skip_noise();
            if *self.current() == Token::Called {
                self.advance();
                self.skip_noise();
                self.parse_name()?
            } else if matches!(self.current(), Token::Identifier(_) | Token::StringLiteral(_)) {
                self.parse_name()?
            } else {
                // "the number" without "called" - could be loop iterator reference
                // But as a statement, this needs "is" to be an assignment
                "_iter".to_string()
            }
        } else {
            self.parse_name()?
        };

        self.skip_noise();

        // Check for assignment: "is <value>"
        if matches!(self.current(), Token::Is | Token::Equals) {
            self.advance();
            self.skip_noise();
            // In-place retype of a `value` variable: `the name is a number.`.
            if let Some(target_type) = self.try_parse_scalar_type_noun_after_is() {
                return Ok(Statement::ValueRetype { name, target_type });
            }
            let value = self.parse_expression()?;
            return Ok(Statement::Assignment { name, value });
        }

        // Otherwise it's just a reference (shouldn't be a statement on its own)
        Err(self.err(&format!("Expected 'is' after 'the {}'", name)))
    }

    /// The 11-type declaration vocabulary shared by a function parameter
    /// type (`with a <type> called x`) and a declared return type (`Return
    /// a <type>,`, both the inline path in `parse_function_def` and the
    /// Gate-B path here in `parse_return`). One table so these call sites
    /// cannot drift into accepting different sets again — they had: Gate B
    /// recognized only number/text/boolean while the inline return path
    /// separately also took file/value, and the parameter path separately
    /// took buffer/list/map but neither took float/time/timer. Does not
    /// consume the token; callers advance after matching. `list`/`map`
    /// declared this way stay element-untyped (`Unknown`) — Vox source has
    /// no generic/typed-collection declaration syntax (plan 296).
    pub(crate) fn declaration_type_token(&self) -> Option<Type> {
        match self.current() {
            Token::Number => Some(Type::Integer),
            Token::Float => Some(Type::Float),
            Token::Text => Some(Type::String),
            Token::Boolean => Some(Type::Boolean),
            Token::File => Some(Type::File),
            Token::Buffer => Some(Type::Buffer),
            Token::List => Some(Type::List(Box::new(Type::Unknown))),
            Token::Map => Some(Type::Map(Box::new(Type::Unknown))),
            Token::Time => Some(Type::Time),
            Token::Timer => Some(Type::Timer),
            // `value` is not a reserved keyword (it stays a usable
            // identifier everywhere else); in a type position it denotes
            // the dynamic `value` type.
            Token::Identifier(n) if n == "value" => Some(Type::Value),
            _ => None,
        }
    }

    /// After an `is`/`equals` in a statement, check whether the next tokens
    /// form a scalar type noun (`a number`, `a text`, `a float`, `a boolean`).
    /// If so, consume them and return the target `Type` so the caller can
    /// produce `Statement::ValueRetype`.  Non-scalar types (list/map) and
    /// anything else are left untouched so they follow their normal path.
    pub(crate) fn try_parse_scalar_type_noun_after_is(&mut self) -> Option<Type> {
        if !matches!(self.current(), Token::A | Token::An) {
            return None;
        }
        let saved = self.pos;
        self.advance(); // consume a/an
        self.skip_noise();
        let t = match self.current() {
            Token::Number | Token::Int => { self.advance(); Type::Integer }
            Token::Float => { self.advance(); Type::Float }
            Token::Text => { self.advance(); Type::String }
            Token::Boolean => { self.advance(); Type::Boolean }
            _ => {
                self.pos = saved;
                return None;
            }
        };
        Some(t)
    }

    /// Parse the type-noun part of `is a/an <noun>` (stage 1c). Assumes the
    /// current token is `A` or `An`; consumes the article and the noun and
    /// returns the corresponding `Type`. Type-noun tokens map to `Type` the
    /// same way the Cast parser does (see `parse_postfix`, ~line 4571).
    /// Shared by `parse_comparison` (`if item is a text`) and `parse_append`
    /// (`append item is a number to flags`).
    pub(crate) fn parse_type_noun_after_article(&mut self) -> Result<Type, Box<CompileError>> {
        // current is A or An
        self.advance();
        self.skip_noise();
        match self.current() {
            Token::Number | Token::Int => { self.advance(); Ok(Type::Integer) }
            Token::Text => { self.advance(); Ok(Type::String) }
            Token::Boolean => { self.advance(); Ok(Type::Boolean) }
            Token::Float => { self.advance(); Ok(Type::Float) }
            // `is a list` type predicate (stage 1e1): a list value carries
            // tag 4, so this folds/compares against TAG_LIST.
            Token::List => { self.advance(); Ok(Type::List(Box::new(Type::Unknown))) }
            // `is a map` type predicate (stage 1e2): a map value carries
            // tag 5, so this folds/compares against TAG_MAP.
            Token::Map => { self.advance(); Ok(Type::Map(Box::new(Type::Unknown))) }
            _ => Err(self.err(
                "Expected a type noun (number, text, decimal, boolean, list, or map) after 'is a'"
            )),
        }
    }

}
