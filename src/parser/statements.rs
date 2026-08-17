use super::*;

impl Parser {
    /// True when the token after the current one (skipping newline noise)
    /// can be the name operand of a timer statement: `the` or an
    /// identifier. Decides whether a statement-initial `start`/`begin`/
    /// `stop`/`finish` is a timer statement or an ordinary call.
    pub(crate) fn timer_name_follows(&self) -> bool {
        let mut off = 1;
        while matches!(self.peek(off), Token::Newline) {
            off += 1;
        }
        matches!(self.peek(off), Token::The | Token::Identifier(_))
    }

    pub fn parse(&mut self) -> Result<Program, Box<CompileError>> {
        let mut statements = Vec::new();
        
        while *self.current() != Token::EOF {
            self.skip_all_whitespace();
            if *self.current() == Token::EOF {
                break;
            }
            
            match self.parse_statement() {
                Ok(stmt) => {
                    // Function definitions handle their own period and paragraph break
                    let is_func_def = matches!(stmt, Statement::FunctionDef { .. });
                    statements.push(stmt);
                    
                    if !is_func_def {
                        self.skip_noise();
                        self.expect(&Token::Period);
                    }
                }
                Err(e) => return Err(e),
            }
            
            self.skip_all_whitespace();
        }

        let mut program = Program::new(statements);
        // Carry the thing registry onto the program in definition order, so
        // consumers get a stable layout order without re-deriving it from a
        // HashMap's iteration order.
        program.things = program
            .statements
            .iter()
            .filter_map(|s| match s {
                Statement::ThingDecl(def) => Some(def.clone()),
                _ => None,
            })
            .collect();
        Ok(program)
    }

    pub(crate) fn parse_statement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.skip_all_whitespace();

        let stmt = match self.current().clone() {
            Token::Print => self.parse_print(),
            Token::Set => self.parse_var_decl(),
            Token::Create => {
                // Disambiguate: "Create a directory" vs "Create symbolic link" vs variable creation
                let saved = self.pos;
                self.advance(); // consume 'create'
                self.skip_noise();

                // Skip optional "a"
                if *self.current() == Token::A {
                    self.advance();
                    self.skip_noise();
                }

                // Check for "directory" or "symbolic" or "device"
                if let Token::Identifier(ref id) = self.current() {
                    if id.eq_ignore_ascii_case("directory") {
                        self.pos = saved; // reset to parse with mkdir
                        return self.parse_mkdir();
                    } else if id.eq_ignore_ascii_case("symbolic") {
                        self.pos = saved; // reset to parse with symlink
                        return self.parse_symlink();
                    } else if id.eq_ignore_ascii_case("device") {
                        self.pos = saved; // reset to parse with mknod
                        return self.parse_mknod();
                    }
                }

                self.pos = saved; // reset to parse as var decl
                self.parse_var_decl()
            }
            Token::A | Token::An => self.parse_typed_var_decl(),
            Token::Parse => self.parse_parse_flags(),
            Token::The => self.parse_the_statement(),
            Token::If | Token::When => self.parse_if(),
            Token::While => self.parse_while(),
            Token::For => self.parse_for(),
            Token::Repeat => self.parse_repeat(),
            Token::Return => self.parse_return(),
            Token::Break => { self.advance(); Ok(Statement::Break) }
            Token::Continue => { self.advance(); Ok(Statement::Continue) }
            Token::Exit => self.parse_exit(),
            Token::Allocate => self.parse_allocate(),
            Token::Free => self.parse_free(),
            Token::Increment => self.parse_increment(),
            Token::Decrement => self.parse_decrement(),
            Token::To => self.parse_function_def(),
            // File I/O
            Token::Open => self.parse_file_open(),
            Token::Read => self.parse_file_read(),
            Token::Write => self.parse_file_write(),
            Token::Close => self.parse_file_close(),
            Token::Delete => {
                // Disambiguate: "Delete/Remove the file <path>" vs "Delete/Remove the directory <path>"
                let saved = self.pos;
                self.advance(); // consume 'delete'/'remove'
                self.skip_noise();

                if *self.current() == Token::The {
                    self.advance();
                    self.skip_noise();
                }

                if let Token::Identifier(ref id) = self.current() {
                    if id.eq_ignore_ascii_case("directory") {
                        self.pos = saved;
                        return self.parse_rmdir();
                    }
                }

                self.pos = saved;
                self.parse_file_delete()
            }
            Token::Seek => self.parse_file_seek(),
            Token::On => self.parse_on_error(),
            Token::Auto => self.parse_auto_error(),
            Token::Enable => self.parse_enable(),
            Token::Disable => self.parse_disable(),
            Token::Resize => self.parse_resize(),
            Token::Append => self.parse_append(),
            Token::Copy => self.parse_copy(),
            Token::Clear => self.parse_clear(),
            Token::Library => self.parse_library_decl(),
            Token::See => self.parse_see(),
            // Time and Timer statements
            Token::Wait | Token::Sleep => self.parse_wait(),
            Token::Get => self.parse_get(),
            // start/begin/stop/finish are contextual identifiers, not
            // reserved words: they open a timer statement only when a name
            // operand follows (`Start the t.`, `stop t.`). A bare `stop.`
            // or `begin of x` falls through to the ordinary call path, and
            // all four words stay usable as variable and function names.
            Token::Identifier(ref s)
                if (s == "start" || s == "begin") && self.timer_name_follows() =>
            {
                self.parse_timer_start()
            }
            Token::Identifier(ref s)
                if (s == "stop" || s == "finish") && self.timer_name_follows() =>
            {
                self.parse_timer_stop()
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("change") => self.parse_chdir(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("mount") => self.parse_mount(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("unmount") || s.eq_ignore_ascii_case("umount") => self.parse_unmount(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("shutdown") || s.eq_ignore_ascii_case("poweroff") => {
                self.advance();
                Ok(Statement::Shutdown)
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("reboot") || s.eq_ignore_ascii_case("restart") => {
                self.advance();
                Ok(Statement::Reboot)
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("halt") => {
                self.advance();
                Ok(Statement::Halt)
            }
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("pivot") => self.parse_pivot_root(),
            Token::Identifier(ref s) if s.eq_ignore_ascii_case("execute") => self.parse_execute(),
            Token::Identifier(_) => self.parse_identifier_statement(),
            // A statement cannot start with a string literal: the old
            // `"get five".` / `"calc" of 3.` forms are gone (plan 270). A
            // string is data; a callee must be a bare or quoted identifier.
            Token::StringLiteral(s) => {
                let s = s.clone();
                Err(self.err_string_as_name(&s))
            }
            _ => Err(self.err_expected("a statement", self.current())),
        };

        // After parsing any statement, give it a chance to carry a `but if`/
        // `otherwise` conditional-sugar suffix.  This is the single central
        // hook that makes the *base* action generic; individual statement
        // parsers no longer need to repeat the suffix logic.  Loop-expansion
        // still handles its own `but if` because the suffix applies to the loop
        // action rather than the loop statement itself.
        //
        // `maybe_parse_conditional_suffix` restores parser position when no
        // suffix is present, and `suppress_conditional_suffix` keeps branch
        // bodies from consuming an outer chain's suffix.
        match stmt {
            Ok(base) => self.maybe_parse_conditional_suffix(base),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn parse_print(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        // Check for loop expansion: "print each X from Y [treating X as Y]"
        if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
            // Create the variable expression, with optional treating substitution
            let var_expr = if let Some((match_val, replacement)) = treating {
                Expr::TreatingAs {
                    value: Box::new(Expr::Identifier(variable.clone())),
                    match_value: Box::new(match_val),
                    replacement: Box::new(replacement),
                }
            } else {
                Expr::Identifier(variable.clone())
            };
            let print_stmt = Statement::Print { value: var_expr, without_newline: false };
            return self.wrap_in_loop_expansion(variable, collection, print_stmt);
        }
        
        // Check for function call with loop expansion: "print func of each X from Y"
        // The callee is a bare or quoted identifier (plan 270). A string
        // literal here is data, not a callee; it is left for parse_expression
        // to handle as a value (and reject if followed by `of/with/to/on`).
        if let Token::Identifier(func_name) = self.current().clone() {
            let saved_pos = self.pos;
            self.advance();
            self.skip_noise();

            if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
                self.advance();
                self.skip_noise();

                // Check if next is "each" for loop expansion
                if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
                    // Create function call with loop variable as argument
                    let arg_expr = if let Some((match_val, replacement)) = treating {
                        Expr::TreatingAs {
                            value: Box::new(Expr::Identifier(variable.clone())),
                            match_value: Box::new(match_val),
                            replacement: Box::new(replacement),
                        }
                    } else {
                        Expr::Identifier(variable.clone())
                    };
                    let func_call = Expr::FunctionCall {
                        name: func_name,
                        args: vec![arg_expr]
                    };
                    let print_stmt = Statement::Print { value: func_call, without_newline: false };
                    return self.wrap_in_loop_expansion(variable, collection, print_stmt);
                } else {
                    // Not a loop expansion, restore position and parse normally
                    self.pos = saved_pos;
                }
            } else {
                // Not a function call pattern, restore position
                self.pos = saved_pos;
            }
        }
        
        let value = self.parse_expression()?;
        
        // Check for "without newline" modifier
        self.skip_noise();
        let without_newline = if *self.current() == Token::Without {
            self.advance();
            self.skip_noise();
            // Expect "newline" after "without"
            if *self.current() == Token::Newline || 
               matches!(self.current(), Token::Identifier(s) if s.to_lowercase() == "newline") {
                self.advance();
                true
            } else {
                false
            }
        } else {
            false
        };
        
        Ok(Statement::Print { value, without_newline })
    }

    pub(crate) fn parse_return(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        if matches!(self.current(), Token::Period | Token::EOF | Token::Newline) {
            Ok(Statement::Return { value: None, declared_type: None })
        } else {
            // Handle "Return a type, expr." syntax (type declaration is optional)
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();

                // Check if this is a type keyword followed by comma
                if let Some(declared_type) = self.declaration_type_token() {
                    self.advance();
                    self.skip_noise();

                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                        // Now parse the actual return expression. Use
                        // `parse_condition` (not `parse_expression`) so a typed
                        // return whose body is a comparison or boolean
                        // conjunction — `Return a boolean, A and B.` — parses
                        // the whole condition. `parse_expression` stops at
                        // `is`/`and`/`or`, which is why this only failed when
                        // the Return was NOT the function's first statement: the
                        // first-statement inline path in `parse_function_def`
                        // already uses `parse_condition`, so the two paths must
                        // agree.
                        let value = self.parse_condition()?;
                        return Ok(Statement::Return { value: Some(value), declared_type: Some(declared_type) });
                    }
                }
                // If not "a type,", backtrack isn't possible, so error
                return Err(self.err("Expected type after 'a' in return statement"));
            }

            // Match the inline first-statement path: parse the value as a
            // full condition so an untyped `Return A and B.` or `Return x is y.`
            // parses the same whether or not it is the first body statement.
            let value = self.parse_condition()?;
            Ok(Statement::Return { value: Some(value), declared_type: None })
        }
    }

    pub(crate) fn parse_exit(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume 'exit'
        self.skip_noise();
        
        // Allow optional 'with' keyword: "Exit with 1."
        if matches!(self.current(), Token::With) {
            self.advance();
            self.skip_noise();
        }
        
        // Parse exit code (default to 0 if not provided)
        let code = if matches!(self.current(), Token::Period | Token::EOF | Token::Newline) {
            Expr::IntegerLit(0)
        } else {
            self.parse_expression()?
        };
        
        Ok(Statement::Exit { code })
    }

    pub(crate) fn parse_allocate(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let size = self.parse_primary()?;
        self.skip_noise();
        
        if *self.current() == Token::For {
            self.advance();
        }
        self.skip_noise();
        
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected variable name for allocation")),
        };
        
        Ok(Statement::Allocate { name, size })
    }

    pub(crate) fn parse_free(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();
        
        let name = self.parse_name()?;

        Ok(Statement::Free { name })
    }

    pub(crate) fn parse_increment(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        let name = self.parse_name()?;

        Ok(Statement::Increment { name })
    }

    pub(crate) fn parse_decrement(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance();
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        let name = self.parse_name()?;

        Ok(Statement::Decrement { name })
    }

    pub(crate) fn parse_identifier_statement(&mut self) -> Result<Statement, Box<CompileError>> {
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected identifier")),
        };

        self.skip_noise();

        // Assignment: `name is value` / `name = value`.
        if matches!(self.current(), Token::Is | Token::Equals) {
            self.advance();
            self.skip_noise();
            // In-place retype of a `value` variable: `name is a number.`.
            // The same words in condition position (`If name is a number`)
            // still parse as a TypeCheck predicate because they go through
            // `parse_condition`, not this statement path.
            if let Some(target_type) = self.try_parse_scalar_type_noun_after_is() {
                return Ok(Statement::ValueRetype { name, target_type });
            }
            let value = self.parse_expression()?;
            return Ok(Statement::Assignment { name, value });
        }

        // Call with arguments: `name of/with/to/on args ...` (plan 270 G1).
        // A bare or quoted identifier callee is accepted; a string literal
        // callee is rejected at the statement dispatch above.
        if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
            self.advance();
            self.skip_noise();

            // Loop-expansion: `name of each X from Y [treating X as Y]`.
            if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
                let arg_expr = if let Some((match_val, replacement)) = treating {
                    Expr::TreatingAs {
                        value: Box::new(Expr::Identifier(variable.clone())),
                        match_value: Box::new(match_val),
                        replacement: Box::new(replacement),
                    }
                } else {
                    Expr::Identifier(variable.clone())
                };
                let call_stmt = Statement::FunctionCall {
                    name: name.clone(),
                    args: vec![arg_expr],
                };
                return self.wrap_in_loop_expansion(variable, collection, call_stmt);
            }

            let mut args = Vec::new();
            loop {
                let arg = self.parse_expression()?;
                args.push(arg);

                self.skip_noise();
                if *self.current() == Token::And {
                    self.advance();
                    self.skip_noise();
                } else {
                    break;
                }
            }
            return Ok(Statement::FunctionCall { name, args });
        }

        // Zero-argument call: `name.`
        Ok(Statement::FunctionCall {
            name,
            args: vec![],
        })
    }

    pub(crate) fn parse_wait(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume Wait/Sleep
        self.skip_noise();
        
        // Optional "for"
        self.expect(&Token::For);
        self.skip_noise();
        
        // Parse duration value
        let duration = self.parse_primary()?;
        self.skip_noise();
        
        // Parse unit: second(s), millisecond(s)
        let unit = match self.current() {
            Token::Second | Token::Seconds => {
                self.advance();
                ast::TimeUnit::Seconds
            }
            Token::Millisecond | Token::Milliseconds => {
                self.advance();
                ast::TimeUnit::Milliseconds
            }
            _ => return Err(self.err("Expected 'second', 'seconds', 'millisecond', or 'milliseconds' after duration")),
        };
        
        Ok(Statement::Wait { duration, unit })
    }

    pub(crate) fn parse_timer_start(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume the contextual start/begin identifier
        self.skip_noise();
        
        // Optional "the"
        self.expect(&Token::The);
        self.skip_noise();
        
        // Timer name (a bare or quoted identifier, never a string)
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            _ => return Err(self.err("Expected timer name after 'start'")),
        };

        Ok(Statement::TimerStart { name })
    }

    pub(crate) fn parse_timer_stop(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume the contextual stop/finish identifier
        self.skip_noise();
        
        // Optional "the"
        self.expect(&Token::The);
        self.skip_noise();
        
        // Timer name (a bare or quoted identifier, never a string)
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            _ => return Err(self.err("Expected timer name after 'stop'")),
        };

        Ok(Statement::TimerStop { name })
    }

    pub(crate) fn parse_get(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume Get
        self.skip_noise();
        
        // "Get current time into <name>"
        if *self.current() == Token::Current {
            self.advance();
            self.skip_noise();
            
            if *self.current() == Token::Time {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Into {
                    self.advance();
                    self.skip_noise();
                    
                    let name = match self.current().clone() {
                        Token::Identifier(n) => { self.advance(); n }
                        Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                        _ => return Err(self.err("Expected variable name after 'into'")),
                    };

                    return Ok(Statement::GetTime { into: name });
                }
            }
        }
        
        Err(self.err("Expected 'current time into <name>' after 'get'"))
    }

}
