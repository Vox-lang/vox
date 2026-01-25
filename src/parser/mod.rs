pub mod ast;

use crate::lexer::{Token, TokenInfo, Lexer};
use crate::errors::{CompileError, SourceLocation, SourceFile, find_similar_keyword, ENGLISH_KEYWORDS};
use ast::*;

pub struct Parser {
    tokens: Vec<TokenInfo>,
    pos: usize,
    source_file: Option<SourceFile>,
}

impl Parser {
    pub fn new(tokens: Vec<TokenInfo>) -> Self {
        Parser { tokens, pos: 0, source_file: None }
    }
    
    pub fn with_source(mut self, filename: &str, content: &str) -> Self {
        self.source_file = Some(SourceFile::new(filename, content));
        self
    }
    
    fn current(&self) -> &Token {
        self.tokens.get(self.pos).map(|t| &t.token).unwrap_or(&Token::EOF)
    }
    
    fn current_info(&self) -> Option<&TokenInfo> {
        self.tokens.get(self.pos)
    }
    
    fn current_location(&self) -> Option<SourceLocation> {
        if let (Some(info), Some(ref src)) = (self.current_info(), &self.source_file) {
            Some(src.make_location(info.line, info.column))
        } else {
            None
        }
    }
    
    fn make_error(&self, message: &str) -> CompileError {
        let mut err = CompileError::new(message);
        if let Some(loc) = self.current_location() {
            err = err.with_location(loc);
        }
        err
    }
    
    fn make_error_with_suggestion(&self, message: &str, got: &str) -> CompileError {
        let mut err = self.make_error(message);
        if let Some(suggestion) = find_similar_keyword(got, ENGLISH_KEYWORDS) {
            err = err.with_suggestion(&suggestion);
        }
        err
    }
    
    fn err(&self, message: &str) -> CompileError {
        self.make_error(message)
    }
    
    fn err_expected(&self, expected: &str, got: &Token) -> CompileError {
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
    ) -> CompileError {
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
    pub fn error_expected_token(&self, expected: &str, actual: &Token) -> CompileError {
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
             Consider: a buffer called \"{}\" is 1024 bytes.",
            buffer_name, buffer_name
        );
    }
    
    /// Check if a token is a reserved keyword and return an error if so.
    /// This catches ALL language keywords, not just a hardcoded subset.
    fn check_not_keyword(&self, token: &Token) -> Result<(), CompileError> {
        if let Some(keyword) = token.as_keyword() {
            Err(self.make_error(&format!(
                "Cannot use '{}' as a variable name - it's a reserved keyword.\n  \
                 Tip: Try a more descriptive name like '{}_value' or 'my_{}'",
                keyword, keyword, keyword
            )))
        } else {
            Ok(())
        }
    }
    
    fn peek(&self, offset: usize) -> &Token {
        self.tokens.get(self.pos + offset).map(|t| &t.token).unwrap_or(&Token::EOF)
    }
    
    fn advance(&mut self) -> Token {
        let tok = self.current().clone();
        self.pos += 1;
        tok
    }
    
    fn skip_noise(&mut self) {
        while matches!(self.current(), Token::Newline) {
            self.advance();
        }
    }
    
    fn skip_all_whitespace(&mut self) {
        while matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
            self.advance();
        }
    }
    
    #[allow(dead_code)]
    fn skip_newlines(&mut self) {
        while matches!(self.current(), Token::Newline | Token::ParagraphBreak) {
            self.advance();
        }
    }
    
    fn expect(&mut self, expected: &Token) -> bool {
        if self.current() == expected {
            self.advance();
            true
        } else {
            false
        }
    }
    
    pub fn parse(&mut self) -> Result<Program, CompileError> {
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
        
        Ok(Program::new(statements))
    }
    
    fn parse_statement(&mut self) -> Result<Statement, CompileError> {
        self.skip_all_whitespace();
        
        match self.current().clone() {
            Token::Print => self.parse_print(),
            Token::Set | Token::Create => self.parse_var_decl(),
            Token::A | Token::An => self.parse_typed_var_decl(),
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
            Token::Delete => self.parse_file_delete(),
            Token::On => self.parse_on_error(),
            Token::Auto => self.parse_auto_error(),
            Token::Enable => self.parse_enable(),
            Token::Disable => self.parse_disable(),
            Token::Resize => self.parse_resize(),
            Token::Append => self.parse_append(),
            Token::Library => self.parse_library_decl(),
            Token::See => self.parse_see(),
            // Time and Timer statements
            Token::Wait | Token::Sleep => self.parse_wait(),
            Token::Begin => self.parse_timer_start(),
            Token::Stop | Token::Finish => self.parse_timer_stop(),
            Token::Get => self.parse_get(),
            Token::Identifier(ref s) if s == "start" => self.parse_timer_start(),
            Token::Identifier(_) => self.parse_identifier_statement(),
            Token::StringLiteral(_) => self.parse_function_call_statement(),
            _ => Err(self.err_expected("a statement", self.current())),
        }
    }
    
    fn parse_print(&mut self) -> Result<Statement, CompileError> {
        self.advance();
        self.skip_noise();
        
        // Check for loop expansion: "print each X from Y [treating X as Y]"
        if let Some((variable, collection, treating)) = self.try_parse_each_from()? {
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
        
        // Check for function call with loop expansion: "print "func" of each X from Y"
        if let Token::StringLiteral(func_name) = self.current().clone() {
            let saved_pos = self.pos;
            self.advance();
            self.skip_noise();
            
            if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
                self.advance();
                self.skip_noise();
                
                // Check if next is "each" for loop expansion
                if let Some((variable, collection, treating)) = self.try_parse_each_from()? {
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
        
        // Check for conditional print patterns: "print X, but if Y" or "print X but if Y"
        if matches!(self.current(), Token::But | Token::Comma) {
            self.advance();
            self.skip_noise();
            
            // Handle "but if" or just "if"
            if *self.current() == Token::But {
                self.advance();
                self.skip_noise();
            }
            
            if *self.current() == Token::If {
                return self.parse_conditional_print(value);
            }
        }
        
        Ok(Statement::Print { value, without_newline })
    }
    
    fn parse_conditional_print(&mut self, default_value: Expr) -> Result<Statement, CompileError> {
        self.advance();
        self.skip_noise();
        
        let mut conditions = Vec::new();
        
        let cond = self.parse_condition()?;
        self.skip_noise();
        self.expect(&Token::Print);
        self.skip_noise();
        let val = self.parse_primary()?;
        conditions.push((cond, val));
        
        // Skip newlines before checking for continuation (allows multi-line but if)
        self.skip_noise();
        loop {
            // Check for continuation: comma, but, or and
            if !matches!(self.current(), Token::But | Token::Comma | Token::And) {
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
                self.expect(&Token::Print);
                self.skip_noise();
                let val = self.parse_primary()?;
                conditions.push((cond, val));
            } else if *self.current() == Token::Else || *self.current() == Token::Otherwise {
                self.advance();
                self.skip_noise();
                self.expect(&Token::Print);
                self.skip_noise();
                let val = self.parse_primary()?;
                conditions.push((Expr::BoolLit(true), val));
                break;
            } else {
                break;
            }
        }
        
        let mut result = Statement::Print { value: default_value, without_newline: false };
        
        for (cond, val) in conditions.into_iter().rev() {
            result = Statement::If {
                condition: cond,
                then_block: vec![Statement::Print { value: val, without_newline: false }],
                else_if_blocks: vec![],
                else_block: Some(vec![result]),
            };
        }
        
        Ok(result)
    }
    
    fn parse_var_decl(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume Set/Create
        self.skip_noise();
        
        // Handle "Set byte N of buffer to value"
        if *self.current() == Token::Byte {
            self.advance();
            self.skip_noise();
            let index = self.parse_primary()?;
            self.skip_noise();
            if *self.current() != Token::Of {
                return Err(self.err("Expected 'of' after byte index"));
            }
            self.advance();
            self.skip_noise();
            let buffer = match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::StringLiteral(n) => { self.advance(); n }
                _ => return Err(self.err("Expected buffer name after 'of'")),
            };
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
            let index = self.parse_primary()?;
            self.skip_noise();
            if *self.current() != Token::Of {
                return Err(self.err("Expected 'of' after element index"));
            }
            self.advance();
            self.skip_noise();
            let list = match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::StringLiteral(n) => { self.advance(); n }
                _ => return Err(self.err("Expected list name after 'of'")),
            };
            self.skip_noise();
            if *self.current() != Token::To {
                return Err(self.err("Expected 'to' after list name"));
            }
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::ElementSet { list, index, value });
        }
        
        // Handle "the/a/an <type> called <name>" pattern
        if matches!(self.current(), Token::The | Token::A | Token::An) {
            self.advance();
            self.skip_noise();
        }
        
        // Check for typed declaration: "<type> called <name>"
        // Handle Timer specially - it has its own statement type
        if *self.current() == Token::Timer {
            self.advance();
            self.skip_noise();
            
            if *self.current() != Token::Called {
                return Err(self.err("Expected 'called' after 'timer'"));
            }
            self.advance();
            self.skip_noise();
            
            let name = match self.current().clone() {
                Token::StringLiteral(n) => { self.advance(); n }
                Token::Identifier(n) => { self.advance(); n }
                _ => return Err(self.err("Expected timer name after 'called'")),
            };
            
            return Ok(Statement::TimerDecl { name });
        }
        
        let var_type = if matches!(self.current(), Token::Number | Token::Text | Token::Boolean | Token::Buffer) {
            let t = match self.current() {
                Token::Number => Type::Integer,
                Token::Text => Type::String,
                Token::Boolean => Type::Boolean,
                Token::Buffer => Type::Buffer,
                _ => Type::Unknown,
            };
            self.advance();
            self.skip_noise();
            Some(t)
        } else {
            None
        };
        
        // If we have "called", get name from there
        let name = if *self.current() == Token::Called {
            self.advance();
            self.skip_noise();
            // Check for keyword used as variable name (both token and string content)
            self.check_not_keyword(self.current())?;
            match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::StringLiteral(n) => {
                    // Also check if the string content is a keyword
                    if let Some(kw) = Token::string_is_keyword(&n) {
                        return Err(self.make_error(&format!(
                            "Cannot use '{}' as a variable name - it's a reserved keyword.\n  \
                             Tip: Try a more descriptive name like '{}_value' or 'my_{}'",
                            n, kw, kw
                        )));
                    }
                    self.advance(); n
                }
                _ => return Err(self.err("Expected variable name after 'called'")),
            }
        } else {
            // Check for keyword used as variable name
            self.check_not_keyword(self.current())?;
            // Otherwise expect identifier directly
            match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                _ => return Err(self.err("Expected variable name")),
            }
        };
        
        self.skip_noise();
        
        // Handle buffer creation with size: "Create a buffer called X with/of size N"
        if var_type == Some(Type::Buffer) {
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
            return Ok(Statement::BufferDecl { name, size: Expr::IntegerLit(0) });
        }
        
        // Check if there's a value assignment
        let value = if matches!(self.current(), Token::To | Token::Equals | Token::Is) {
            self.advance();
            self.skip_noise();
            Some(self.parse_expression()?)
        } else if matches!(self.current(), Token::Period | Token::Comma | Token::EOF | Token::ParagraphBreak) {
            // No value - valid for buffers and other types with defaults
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
    
    fn parse_typed_var_decl(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume 'a' or 'an'
        self.skip_noise();
        
        // Parse type: number, int, float, text, boolean, list, buffer, file
        let var_type = match self.current() {
            Token::Number | Token::Int => { self.advance(); Some(Type::Integer) }
            Token::Float => { self.advance(); Some(Type::Float) }
            Token::Text => { self.advance(); Some(Type::String) }
            Token::Boolean => { self.advance(); Some(Type::Boolean) }
            Token::List => { self.advance(); Some(Type::List(Box::new(Type::Unknown))) }
            Token::Buffer => { 
                self.advance();
                self.skip_noise();
                
                if *self.current() != Token::Called {
                    return Err(self.err(
                        "Missing 'called' after 'buffer'\n  \
                         Syntax: a buffer called \"name\".\n  \
                         Example: a buffer called \"content\"."
                    ));
                }
                self.advance();
                self.skip_noise();
                
                // Check for keyword used as buffer name
                self.check_not_keyword(self.current())?;
                
                let name = match self.current().clone() {
                    Token::StringLiteral(n) => {
                        if let Some(kw) = Token::string_is_keyword(&n) {
                            return Err(self.make_error(&format!(
                                "Cannot use '{}' as a buffer name - it's a reserved keyword.\n  \
                                 Tip: Try a more descriptive name like '{}_buffer' or 'my_{}'",
                                n, kw, kw
                            )));
                        }
                        self.advance(); n
                    }
                    Token::Identifier(n) => { self.advance(); n }
                    _ => return Err(self.err(
                        "Missing buffer name after 'called'\n  \
                         Syntax: a buffer called \"name\".\n  \
                         Example: a buffer called \"content\"."
                    )),
                };
                
                self.skip_noise();
                
                // Parse first, classify second - check for "is" clause
                if self.expect(&Token::Is) {
                    self.skip_noise();
                    let expr = self.parse_primary()?;
                    self.skip_noise();
                    
                    // Check if this is a size clause (has "bytes" keyword) or an initializer
                    if *self.current() == Token::Bytes {
                        // This is a size clause - advance past "bytes"
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
                        // This is critical for memory safety - we need compile-time known sizes
                        match &expr {
                            Expr::IntegerLit(n) => {
                                if *n <= 0 {
                                    return Err(self.error_invalid_buffer_size(
                                        &name,
                                        "Buffer size must be a positive integer",
                                        "a buffer called \"buf\" is 1024 bytes."
                                    ));
                                }
                                // Check for unreasonably large buffer sizes (prevent DoS via memory exhaustion)
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
                                // Allow variable references for size - will be validated at compile time
                                // This enables patterns like: a buffer called "buf" is config_size bytes.
                                // The type checker must verify this is a compile-time constant integer
                            }
                            _ => {
                                return Err(self.error_invalid_buffer_size(
                                    &name,
                                    "Buffer size must be a numeric literal or constant variable",
                                    "a buffer called \"buf\" is 1024 bytes."
                                ));
                            }
                        }
                        
                        return Ok(Statement::BufferDecl { name, size: expr });
                    } else {
                        // No "bytes" keyword - this is an initializer expression
                        // The buffer will be sized based on the initializer at compile time
                        return Ok(Statement::VarDecl {
                            name,
                            var_type: Some(Type::Buffer),
                            value: Some(expr),
                        });
                    }
                } else {
                    // No "is" clause - this is a zero-capacity dynamic buffer
                    // Emit a warning as this is likely unintentional
                    self.warn_uninitialized_buffer(&name);
                    return Ok(Statement::BufferDecl { 
                        name, 
                        size: Expr::IntegerLit(0) 
                    });
                }
            }
            Token::Timer => {
                self.advance();
                self.skip_noise();
                
                if *self.current() != Token::Called {
                    return Err(self.err(
                        "Missing 'called' after 'timer'\n  \
                         Syntax: a timer called \"name\".\n  \
                         Example: Create a timer called \"job timer\"."
                    ));
                }
                self.advance();
                self.skip_noise();
                
                let name = match self.current().clone() {
                    Token::StringLiteral(n) => { self.advance(); n }
                    Token::Identifier(n) => { self.advance(); n }
                    _ => return Err(self.err(
                        "Missing timer name after 'called'\n  \
                         Syntax: a timer called \"name\"."
                    )),
                };
                
                return Ok(Statement::TimerDecl { name });
            }
            Token::Time => {
                self.advance();
                self.skip_noise();
                
                if *self.current() != Token::Called {
                    return Err(self.err(
                        "Missing 'called' after 'time'\n  \
                         Syntax: a time called \"name\" is current time."
                    ));
                }
                self.advance();
                self.skip_noise();
                
                let name = match self.current().clone() {
                    Token::StringLiteral(n) => { self.advance(); n }
                    Token::Identifier(n) => { self.advance(); n }
                    _ => return Err(self.err("Missing time variable name after 'called'")),
                };
                
                self.skip_noise();
                
                // Parse "is current time" or similar
                let value = if matches!(self.current(), Token::Is | Token::Equals) {
                    self.advance();
                    self.skip_noise();
                    Some(self.parse_expression()?)
                } else {
                    None
                };
                
                return Ok(Statement::VarDecl {
                    name,
                    var_type: Some(Type::Time),
                    value,
                });
            }
            _ => None,
        };
        
        self.skip_noise();
        self.expect(&Token::Called);
        self.skip_noise();
        
        // Check for keyword used as variable name
        self.check_not_keyword(self.current())?;
        
        // Get variable name (quoted string)
        let name = match self.current().clone() {
            Token::StringLiteral(n) => {
                // Check if the string content is a keyword
                if let Some(kw) = Token::string_is_keyword(&n) {
                    return Err(self.make_error(&format!(
                        "Cannot use '{}' as a variable name - it's a reserved keyword.\n  \
                         Tip: Try a more descriptive name like '{}_value' or 'my_{}'",
                        n, kw, kw
                    )));
                }
                self.advance(); n
            }
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err(
                "Missing variable name after 'called'\n  \
                 Syntax: a <type> called \"<name>\" is <value>.\n  \
                 Example: a number called \"x\" is 5."
            )),
        };
        
        self.skip_noise();
        
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
    
    fn parse_the_statement(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume 'the'
        self.skip_noise();
        
        // Could be "the <name> is <value>" (assignment) or just a reference
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => { self.advance(); n }
            // Handle "the number called <name>" or "the number" (loop iterator)
            Token::Number | Token::Text | Token::Boolean => {
                self.advance(); // consume type
                self.skip_noise();
                if *self.current() == Token::Called {
                    self.advance();
                    self.skip_noise();
                    match self.current().clone() {
                        Token::StringLiteral(n) => { self.advance(); n }
                        Token::Identifier(n) => { self.advance(); n }
                        _ => return Err(self.err("Expected variable name after 'called'")),
                    }
                } else {
                    // "the number" without "called" - could be loop iterator reference
                    // But as a statement, this needs "is" to be an assignment
                    "_iter".to_string()
                }
            }
            _ => return Err(self.err_expected("identifier after 'the'", self.current())),
        };
        
        self.skip_noise();
        
        // Check for assignment: "is <value>"
        if matches!(self.current(), Token::Is | Token::Equals) {
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::Assignment { name, value });
        }
        
        // Otherwise it's just a reference (shouldn't be a statement on its own)
        Err(self.err(&format!("Expected 'is' after 'the {}'", name)))
    }
    
    fn parse_if(&mut self) -> Result<Statement, CompileError> {
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
        // Consume period after then block if followed by else/otherwise
        if *self.current() == Token::Period {
            if matches!(self.peek(1), Token::But | Token::Else | Token::Otherwise) {
                self.advance(); // consume period
                self.skip_noise();
            }
        }
        
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
            } else {
                self.expect(&Token::Comma);
                self.skip_noise();
                // Else block consumes rest of sentence (comma-separated actions)
                let block = self.parse_sentence_body()?;
                else_block = Some(block);
                break;
            }
        }
        
        Ok(Statement::If {
            condition,
            then_block,
            else_if_blocks,
            else_block,
        })
    }
    
    fn parse_while(&mut self) -> Result<Statement, CompileError> {
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
                self.advance();
                self.skip_noise();
            } else if *self.current() == Token::EOF {
                break;
            }
        }
        
        Ok(Statement::While { condition, body })
    }
    
    /// Check if current token indicates end of a loop body inside a function
    /// Only Return truly ends a loop body - other statements can be part of the loop
    fn is_block_terminator(&self) -> bool {
        matches!(self.current(), Token::Return)
    }
    
    fn parse_for(&mut self) -> Result<Statement, CompileError> {
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
            
            let start = self.parse_primary()?;
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
                    } else {
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
                    } else {
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
                } else {
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
    
    fn parse_repeat(&mut self) -> Result<Statement, CompileError> {
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
    
    fn parse_return(&mut self) -> Result<Statement, CompileError> {
        self.advance();
        self.skip_noise();
        
        if matches!(self.current(), Token::Period | Token::EOF | Token::Newline) {
            Ok(Statement::Return { value: None })
        } else {
            // Handle "Return a type, expr." syntax (type declaration is optional)
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();
                
                // Check if this is a type keyword followed by comma
                if matches!(self.current(), Token::Number | Token::Text | Token::Boolean) {
                    self.advance();
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                        // Now parse the actual return expression
                        let value = self.parse_expression()?;
                        return Ok(Statement::Return { value: Some(value) });
                    }
                }
                // If not "a type,", backtrack isn't possible, so error
                return Err(self.err("Expected type after 'a' in return statement"));
            }
            
            let value = self.parse_expression()?;
            Ok(Statement::Return { value: Some(value) })
        }
    }
    
    fn parse_exit(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume 'exit'
        self.skip_noise();
        
        // Parse exit code (default to 0 if not provided)
        let code = if matches!(self.current(), Token::Period | Token::EOF | Token::Newline) {
            Expr::IntegerLit(0)
        } else {
            self.parse_expression()?
        };
        
        Ok(Statement::Exit { code })
    }
    
    fn parse_allocate(&mut self) -> Result<Statement, CompileError> {
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
    
    fn parse_free(&mut self) -> Result<Statement, CompileError> {
        self.advance();
        self.skip_noise();
        
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected variable name to free")),
        };
        
        Ok(Statement::Free { name })
    }
    
    fn parse_increment(&mut self) -> Result<Statement, CompileError> {
        self.advance();
        self.skip_noise();
        
        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }
        
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => { self.advance(); n }
            _ => return Err(self.err("Expected variable name after 'increment'")),
        };
        
        Ok(Statement::Increment { name })
    }
    
    fn parse_decrement(&mut self) -> Result<Statement, CompileError> {
        self.advance();
        self.skip_noise();
        
        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }
        
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => { self.advance(); n }
            _ => return Err(self.err("Expected variable name after 'decrement'")),
        };
        
        Ok(Statement::Decrement { name })
    }
    
    // File I/O parsing functions
    
    fn parse_file_open(&mut self) -> Result<Statement, CompileError> {
        // "open a file" followed by any combination of:
        //   - "for reading/writing/appending" (mode)
        //   - "called <name>" (handle name)  
        //   - "at <path>" or "at each <var> from <list>" (path/loop)
        // in any order!
        self.advance(); // consume 'open'
        self.skip_noise();
        
        // Skip "a"
        if *self.current() == Token::A {
            self.advance();
            self.skip_noise();
        }
        
        // Expect "file"
        self.expect(&Token::File);
        self.skip_noise();
        
        // Parse the three optional clauses in any order
        let mut mode: Option<FileMode> = None;
        let mut name: Option<String> = None;
        let mut path_info: Option<Result<Expr, (String, Expr, Option<(Expr, Expr)>)>> = None; // Ok=simple path, Err=loop expansion
        
        loop {
            match self.current() {
                Token::For => {
                    if mode.is_some() {
                        return Err(self.err("Duplicate 'for' clause - mode already specified"));
                    }
                    self.advance();
                    self.skip_noise();
                    mode = Some(match self.current() {
                        Token::Reading => { self.advance(); FileMode::Reading }
                        Token::Writing => { self.advance(); FileMode::Writing }
                        Token::Appending => { self.advance(); FileMode::Appending }
                        Token::Identifier(ref id) => {
                            // Check for typos in mode keywords
                            let mode_keywords = &["reading", "writing", "appending"];
                            if let Some(suggestion) = crate::errors::find_similar_keyword(id, mode_keywords) {
                                return Err(self.err(&format!(
                                    "Unknown file mode '{}' - did you mean '{}'?\n  Valid modes: reading, writing, appending",
                                    id, suggestion
                                )));
                            }
                            return Err(self.err(
                                "Expected file mode after 'for'\n  Valid modes: reading, writing, appending"
                            ));
                        }
                        _ => return Err(self.err(
                            "Expected file mode after 'for'\n  Valid modes: reading, writing, appending"
                        )),
                    });
                }
                Token::Called => {
                    if name.is_some() {
                        return Err(self.err("Duplicate 'called' clause - name already specified"));
                    }
                    self.advance();
                    self.skip_noise();
                    name = Some(match self.current().clone() {
                        Token::StringLiteral(n) => { self.advance(); n }
                        Token::Identifier(n) => { self.advance(); n }
                        Token::File => { self.advance(); "File".to_string() }
                        Token::Input => { self.advance(); "input".to_string() }
                        _ => return Err(self.err("Expected file handle name after 'called'")),
                    });
                }
                Token::On => {  // "at" is tokenized as On
                    if path_info.is_some() {
                        return Err(self.err("Duplicate 'at' clause - path already specified"));
                    }
                    self.advance();
                    self.skip_noise();
                    
                    // Check for loop expansion: "at each X from Y"
                    if let Some((variable, collection, treating)) = self.try_parse_each_from()? {
                        path_info = Some(Err((variable, collection, treating)));
                    } else {
                        path_info = Some(Ok(self.parse_primary()?));
                    }
                }
                Token::Identifier(ref id) => {
                    // Check for typos of expected keywords
                    let keywords = &["called", "for", "at"];
                    if let Some(suggestion) = crate::errors::find_similar_keyword(id, keywords) {
                        return Err(self.err(&format!(
                            "Unknown keyword '{}' - did you mean '{}'?",
                            id, suggestion
                        )));
                    }
                    break;
                }
                _ => break,
            }
            self.skip_noise();
        }
        
        // Validate required parts and give helpful errors
        let mode = mode.ok_or_else(|| self.err(
            "Missing file mode - add 'for reading', 'for writing', or 'for appending'"
        ))?;
        
        let name = name.ok_or_else(|| self.err(
            "Missing file handle name - add 'called <name>' to give the file a name you can reference"
        ))?;
        
        let path_info = path_info.ok_or_else(|| self.err(
            "Missing file path - add 'at <path>' to specify which file to open"
        ))?;
        
        // Build the statement
        match path_info {
            Ok(path) => Ok(Statement::FileOpen { name, path, mode }),
            Err((variable, collection, treating)) => {
                let path_expr = if let Some((match_val, replacement)) = treating {
                    Expr::TreatingAs {
                        value: Box::new(Expr::Identifier(variable.clone())),
                        match_value: Box::new(match_val),
                        replacement: Box::new(replacement),
                    }
                } else {
                    Expr::Identifier(variable.clone())
                };
                let file_open = Statement::FileOpen { 
                    name: name.clone(), 
                    path: path_expr, 
                    mode 
                };
                self.wrap_in_loop_expansion(variable, collection, file_open)
            }
        }
    }
    
    /// Try to parse optional "treating X as Y" clause.
    /// Returns Some((match_value, replacement)) if found, None otherwise.
    fn try_parse_treating(&mut self) -> Result<Option<(Expr, Expr)>, CompileError> {
        if *self.current() != Token::Treating {
            return Ok(None);
        }
        self.advance();
        self.skip_noise();
        
        // Parse match value (simple: string or identifier only)
        let match_value = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); Expr::StringLit(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
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
        
        // Parse replacement (simple: string or identifier only)
        let replacement = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); Expr::StringLit(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            _ => return Err(self.err(
                "Missing replacement value after 'as'\n  \
                 Syntax: treating <match> as <replacement>\n  \
                 Example: treating \"-\" as \"/dev/stdin\""
            )),
        };
        self.skip_noise();
        
        Ok(Some((match_value, replacement)))
    }
    
    /// Apply treating substitution to all references of a variable in a statement body.
    /// Wraps Identifier references to the variable with TreatingAs expressions.
    fn apply_treating_to_body(&self, body: Vec<Statement>, variable: &str, match_val: Expr, replacement: Expr) -> Vec<Statement> {
        body.into_iter().map(|stmt| {
            self.apply_treating_to_statement(stmt, variable, &match_val, &replacement)
        }).collect()
    }
    
    fn apply_treating_to_statement(&self, stmt: Statement, variable: &str, match_val: &Expr, replacement: &Expr) -> Statement {
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
    
    fn apply_treating_to_expr(&self, expr: Expr, variable: &str, match_val: &Expr, replacement: &Expr) -> Expr {
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
    fn try_parse_each_from(&mut self) -> Result<Option<(String, Expr, Option<(Expr, Expr)>)>, CompileError> {
        if *self.current() != Token::Each {
            return Ok(None);
        }
        
        self.advance(); // consume 'each'
        self.skip_noise();
        
        // Get loop variable name
        let variable = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::Number => { self.advance(); "number".to_string() }
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
        // First parse a primary/simple expression
        let first = self.parse_primary()?;
        self.skip_noise();
        
        // Check if this is a range: <start> to <end>
        // But only if first is a simple value (number/identifier), not a list or other collection
        let is_list_or_collection = matches!(first, Expr::ListLit { .. } | Expr::PropertyAccess { .. });
        let collection = if *self.current() == Token::To && !is_list_or_collection {
            self.advance();
            self.skip_noise();
            let end = self.parse_primary()?;
            self.skip_noise();
            Expr::Range {
                start: Box::new(first),
                end: Box::new(end),
                inclusive: true,
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
    /// Supports "but if" conditional branching for print statements.
    fn wrap_in_loop_expansion(&mut self, variable: String, collection: Expr, base_stmt: Statement) -> Result<Statement, CompileError> {
        let mut body = vec![base_stmt];
        
        // Check for comma to parse additional body statements or "but if" conditionals
        if *self.current() == Token::Comma {
            self.advance();
            self.skip_noise();
            
            // Check for "but if" conditional branching (modifies the base print statement)
            if *self.current() == Token::But {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::If {
                    // Extract the default value from the base print statement
                    if let Statement::Print { value: default_value, .. } = body.pop().unwrap() {
                        let conditional_print = self.parse_conditional_print(default_value)?;
                        body.push(conditional_print);
                    } else {
                        return Err(self.err("'but if' conditional branching only works with print statements"));
                    }
                } else {
                    return Err(self.err("Expected 'if' after 'but'"));
                }
            } else {
                // Parse remaining statements in the sentence
                loop {
                    if matches!(self.current(), Token::Period | Token::EOF | Token::ParagraphBreak) {
                        break;
                    }
                    
                    let stmt = self.parse_statement()?;
                    body.push(stmt);
                    self.skip_noise();
                    
                    if *self.current() == Token::Comma {
                        self.advance();
                        self.skip_noise();
                    } else {
                        break;
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
    
    fn parse_file_read(&mut self) -> Result<Statement, CompileError> {
        // "Read from <source> into <buffer>"
        self.advance(); // consume 'read'
        self.skip_noise();
        
        // Expect "from"
        self.expect(&Token::From);
        self.skip_noise();
        
        // Parse source: "standard input" or file name
        let source = if *self.current() == Token::Standard {
            self.advance();
            self.skip_noise();
            self.expect(&Token::Input);
            "stdin".to_string()
        } else {
            match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::StringLiteral(n) => { self.advance(); n }
                Token::Input => { self.advance(); "input".to_string() }
                _ => return Err(self.err_expected("file name or 'standard input' after 'from'", self.current())),
            }
        };
        
        self.skip_noise();
        
        // Expect "into"
        self.expect(&Token::Into);
        self.skip_noise();
        
        // Get buffer name
        let buffer = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => { self.advance(); n }
            _ => return Err(self.err("Expected buffer name after 'into'")),
        };
        
        Ok(Statement::FileRead { source, buffer })
    }
    
    fn parse_file_write(&mut self) -> Result<Statement, CompileError> {
        // "Write <value> to <file>" or "Write a newline to <file>"
        self.advance(); // consume 'write'
        self.skip_noise();
        
        // Check for "a newline"
        if *self.current() == Token::A {
            self.advance();
            self.skip_noise();
            
            // Check if it's "newline" (as identifier)
            if let Token::Identifier(ref s) = self.current() {
                if s.to_lowercase() == "newline" {
                    self.advance();
                    self.skip_noise();
                    
                    // Expect "to"
                    self.expect(&Token::To);
                    self.skip_noise();
                    
                    // Get file name
                    let file = match self.current().clone() {
                        Token::Identifier(n) => { self.advance(); n }
                        Token::StringLiteral(n) => { self.advance(); n }
                        Token::File => { self.advance(); "File".to_string() }
                        _ => return Err(self.err("Expected file name after 'to'")),
                    };
                    
                    return Ok(Statement::FileWriteNewline { file });
                }
            }
        }
        
        // Parse value to write (string literal or identifier)
        let mut value = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); Expr::StringLit(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
                    _ => return Err(self.err("Expected identifier after 'the'")),
                }
            }
            _ => return Err(self.err("Expected value to write")),
        };
        self.skip_noise();
        
        // Check for "treating X as Y" modifier on the value
        if *self.current() == Token::Treating {
            self.advance();
            self.skip_noise();
            
            // Parse match value (simple: string or identifier only)
            let match_value = match self.current().clone() {
                Token::StringLiteral(s) => { self.advance(); Expr::StringLit(s) }
                Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
                _ => return Err(self.err("Expected string or identifier after 'treating'")),
            };
            self.skip_noise();
            
            // Expect "as"
            if *self.current() == Token::As {
                self.advance();
                self.skip_noise();
            } else if let Token::Identifier(s) = self.current() {
                if s.to_lowercase() == "as" {
                    self.advance();
                    self.skip_noise();
                }
            }
            
            // Parse replacement (simple: string or identifier only)
            let replacement = match self.current().clone() {
                Token::StringLiteral(s) => { self.advance(); Expr::StringLit(s) }
                Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
                _ => return Err(self.err("Expected string or identifier after 'as'")),
            };
            self.skip_noise();
            
            value = Expr::TreatingAs {
                value: Box::new(value),
                match_value: Box::new(match_value),
                replacement: Box::new(replacement),
            };
        }
        
        // Expect "to"
        if !self.expect(&Token::To) {
            return Err(self.err_expected("'to' after value", self.current()));
        }
        self.skip_noise();
        
        // Get file name
        let file = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => { self.advance(); n }
            Token::File => { self.advance(); "File".to_string() }
            _ => return Err(self.err_expected("file name after 'to'", self.current())),
        };
        
        Ok(Statement::FileWrite { file, value })
    }
    
    fn parse_file_close(&mut self) -> Result<Statement, CompileError> {
        // "Close the <file>" or "Close <file>"
        self.advance(); // consume 'close'
        self.skip_noise();
        
        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }
        
        // Get file name (can be identifier or keywords used as names)
        let file = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::StringLiteral(n) => { self.advance(); n }
            Token::File => { self.advance(); "File".to_string() }
            Token::Input => { self.advance(); "input".to_string() }
            _ => return Err(self.err_expected("file name after 'close'", self.current())),
        };
        
        Ok(Statement::FileClose { file })
    }
    
    fn parse_file_delete(&mut self) -> Result<Statement, CompileError> {
        // "Delete the file <path>"
        self.advance(); // consume 'delete'
        self.skip_noise();
        
        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }
        
        // Expect "file"
        self.expect(&Token::File);
        self.skip_noise();
        
        // Get path
        let path = self.parse_primary()?;
        
        Ok(Statement::FileDelete { path })
    }
    
    fn parse_on_error(&mut self) -> Result<Statement, CompileError> {
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
    
    fn parse_auto_error(&mut self) -> Result<Statement, CompileError> {
        // Feature deferred - auto error catching not yet implemented
        Err(self.err(
            "'auto error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }
    
    fn parse_enable(&mut self) -> Result<Statement, CompileError> {
        // Feature deferred - enable error catching not yet implemented
        Err(self.err(
            "'enable error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }
    
    fn parse_disable(&mut self) -> Result<Statement, CompileError> {
        // Feature deferred - disable error catching not yet implemented
        Err(self.err(
            "'disable error catching' is not yet implemented.\n  \
             Use 'on error <action>.' for manual error handling instead."
        ))
    }
    
    fn parse_resize(&mut self) -> Result<Statement, CompileError> {
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
    
    fn parse_append(&mut self) -> Result<Statement, CompileError> {
        // "append <expr> to <list>" or "append each <var> from <collection> to <list>"
        self.advance(); // consume 'append'
        self.skip_noise();
        
        // Check for loop expansion: "append each X from Y to Z"
        if let Some((variable, collection, _treating)) = self.try_parse_each_from()? {
            // Get target list name after "to"
            self.skip_noise();
            if *self.current() != Token::To {
                return Err(self.err("Expected 'to' after collection in append"));
            }
            self.advance();
            self.skip_noise();
            
            let list_name = match self.current().clone() {
                Token::Identifier(n) => { self.advance(); n }
                Token::The => {
                    self.advance();
                    self.skip_noise();
                    match self.current().clone() {
                        Token::Identifier(n) => { self.advance(); n }
                        _ => return Err(self.err("Expected list name after 'the'")),
                    }
                }
                _ => return Err(self.err("Expected list name after 'to'")),
            };
            
            // Create the append statement for loop body
            let append_stmt = Statement::ListAppend {
                list: list_name,
                value: Expr::Identifier(variable.clone()),
            };
            
            return self.wrap_in_loop_expansion(variable, collection, append_stmt);
        }
        
        // Parse just the value (literal, identifier, or simple expression)
        // We need to be careful not to consume 'to' which is the separator
        let value = match self.current().clone() {
            Token::IntegerLiteral(n) => {
                self.advance();
                Expr::IntegerLit(n)
            }
            Token::FloatLiteral(n) => {
                self.advance();
                Expr::FloatLit(n)
            }
            Token::StringLiteral(s) => {
                self.advance();
                // Check for format string
                if s.contains('{') && !s.starts_with("{{") {
                    let parts = self.parse_format_string(&s);
                    if !parts.is_empty() && parts.iter().any(|p| matches!(p, FormatPart::Variable { .. } | FormatPart::Expression { .. })) {
                        Expr::FormatString { parts }
                    } else {
                        Expr::StringLit(s)
                    }
                } else {
                    Expr::StringLit(s)
                }
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
                if let Token::Identifier(name) = self.current().clone() {
                    self.advance();
                    Expr::Identifier(name)
                } else {
                    return Err(self.err("Expected identifier after 'the' in append"));
                }
            }
            _ => return Err(self.err("Expected value to append")),
        };
        
        self.skip_noise();
        
        // Expect "to"
        if *self.current() != Token::To {
            return Err(self.err("Expected 'to' after value in append statement"));
        }
        self.advance();
        self.skip_noise();
        
        // Get list name
        let list = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            Token::The => {
                self.advance();
                self.skip_noise();
                match self.current().clone() {
                    Token::Identifier(n) => { self.advance(); n }
                    _ => return Err(self.err("Expected list name after 'the'")),
                }
            }
            _ => return Err(self.err("Expected list name after 'to'")),
        };
        
        Ok(Statement::ListAppend { list, value })
    }
    
    fn parse_library_decl(&mut self) -> Result<Statement, CompileError> {
        // Library "name" version "1.0".
        self.advance(); // consume 'library'
        self.skip_noise();
        
        // Get library name
        let name = match self.current().clone() {
            Token::StringLiteral(n) => { self.advance(); n }
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected library name")),
        };
        
        self.skip_noise();
        
        // Parse version
        let version = if *self.current() == Token::Version {
            self.advance();
            self.skip_noise();
            match self.current().clone() {
                Token::StringLiteral(v) => { self.advance(); v }
                _ => return Err(self.err("Expected version string")),
            }
        } else {
            "1.0".to_string() // Default version
        };
        
        Ok(Statement::LibraryDecl { name, version })
    }
    
    fn parse_see(&mut self) -> Result<Statement, CompileError> {
        // Supported syntaxes:
        // see "./path/to/file.en".
        // see "math" version "1.0" from "./path.so".
        // see "./path.so" for "math" version "1.0".
        // see "./path.so" for math version 1.0.
        self.advance(); // consume 'see'
        self.skip_noise();
        
        let mut path = String::new();
        let mut lib_name: Option<String> = None;
        let mut lib_version: Option<String> = None;
        
        // Helper to get string or identifier value
        let get_name_or_string = |token: &Token| -> Option<String> {
            match token {
                Token::StringLiteral(s) => Some(s.clone()),
                Token::Identifier(s) => Some(s.clone()),
                _ => None,
            }
        };
        
        // Helper to get version (string, identifier, or number)
        let get_version = |token: &Token| -> Option<String> {
            match token {
                Token::StringLiteral(s) => Some(s.clone()),
                Token::Identifier(s) => Some(s.clone()),
                Token::IntegerLiteral(n) => Some(n.to_string()),
                _ => None,
            }
        };
        
        // Get first token - could be path or library name
        let first = get_name_or_string(self.current())
            .ok_or_else(|| self.err(
                "Missing path or library name after 'see'\n  \
                 Syntax: see \"./path/to/file.en\".\n  \
                 Or: see \"libname\" version \"1.0\" from \"./path.so\"."
            ))?;
        self.advance();
        self.skip_noise();
        
        // Check what comes next
        if *self.current() == Token::Version {
            // "see libname version X from path"
            lib_name = Some(first);
            self.advance();
            self.skip_noise();
            
            lib_version = get_version(self.current());
            if lib_version.is_some() {
                self.advance();
                self.skip_noise();
            }
            
            // Expect "from"
            if *self.current() == Token::From {
                self.advance();
                self.skip_noise();
                path = get_name_or_string(self.current()).unwrap_or_default();
                if !path.is_empty() {
                    self.advance();
                }
            }
        } else if *self.current() == Token::From {
            // "see libname from path"
            lib_name = Some(first);
            self.advance();
            self.skip_noise();
            
            path = get_name_or_string(self.current()).unwrap_or_default();
            if !path.is_empty() {
                self.advance();
            }
        } else if *self.current() == Token::For {
            // "see path for libname version X"
            path = first;
            self.advance();
            self.skip_noise();
            
            lib_name = get_name_or_string(self.current());
            if lib_name.is_some() {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Version {
                    self.advance();
                    self.skip_noise();
                    lib_version = get_version(self.current());
                    if lib_version.is_some() {
                        self.advance();
                    }
                }
            }
        } else {
            // Simple "see path"
            path = first;
        }
        
        Ok(Statement::See { path, lib_name, lib_version })
    }
    
    fn parse_identifier_statement(&mut self) -> Result<Statement, CompileError> {
        let name = match self.current().clone() {
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected identifier")),
        };
        
        self.skip_noise();
        
        if matches!(self.current(), Token::Is | Token::Equals) {
            self.advance();
            self.skip_noise();
            let value = self.parse_expression()?;
            return Ok(Statement::Assignment { name, value });
        }
        
        Ok(Statement::FunctionCall {
            name,
            args: vec![],
        })
    }
    
    fn parse_function_def(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume 'To'
        self.skip_noise();
        
        // Get function name (quoted string or single-word identifier)
        let name = match self.current().clone() {
            Token::StringLiteral(n) => { self.advance(); n }
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err(
                "Missing function name after 'To'\n  \
                 Syntax: To \"function name\" with parameters. Return a type, expression.\n  \
                 Example: To \"add\" with a number called \"x\" and a number called \"y\". Return a number, x add y."
            )),
        };
        
        self.skip_noise();
        
        // Parse parameters: "with <name>" or "with a <type> called <name> and ..."
        let mut params = Vec::new();
        if *self.current() == Token::With || *self.current() == Token::Of {
            self.advance();
            self.skip_noise();
            
            loop {
                self.skip_noise();
                
                // Check for simple parameter: just an identifier
                if let Token::Identifier(n) = self.current().clone() {
                    // Simple parameter without type
                    self.advance();
                    params.push((n, Type::Unknown));
                } else {
                    // Full syntax: "a <type> called <name>"
                    // Skip optional article before type
                    if matches!(self.current(), Token::A | Token::An) {
                        self.advance();
                        self.skip_noise();
                    }
                    
                    let param_type = match self.current() {
                        Token::Number => { self.advance(); Type::Integer }
                        Token::Text => { self.advance(); Type::String }
                        Token::Boolean => { self.advance(); Type::Boolean }
                        Token::List => { self.advance(); Type::List(Box::new(Type::Unknown)) }
                        _ => Type::Unknown,
                    };
                    
                    self.skip_noise();
                    if *self.current() == Token::Called {
                        self.advance();
                        self.skip_noise();
                    }
                    
                    let param_name = match self.current().clone() {
                        Token::StringLiteral(n) => { self.advance(); n }
                        Token::Identifier(n) => { self.advance(); n }
                        _ => return Err(self.err(
                            "Missing parameter name\n  \
                             Syntax: a <type> called \"<name>\"\n  \
                             Example: a number called \"x\""
                        )),
                    };
                    
                    params.push((param_name, param_type));
                }
                
                self.skip_noise();
                if *self.current() == Token::And {
                    self.advance();
                    self.skip_noise();
                } else {
                    break;
                }
            }
        }
        
        self.skip_noise();
        // Period after function signature is optional
        if *self.current() == Token::Period {
            self.advance();
            self.skip_noise();
        }
        
        // Parse return type: "Return a <type>, <body>"
        let mut return_type = Type::Void;
        let mut body = Vec::new();
        
        if *self.current() == Token::Return {
            self.advance();
            self.skip_noise();
            
            // Check for return type declaration: "Return a number," or "Return number,"
            // Skip optional article
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();
            }
            
            if matches!(self.current(), Token::Number | Token::Text | Token::Boolean) {
                return_type = match self.current() {
                    Token::Number => { self.advance(); Type::Integer }
                    Token::Text => { self.advance(); Type::String }
                    Token::Boolean => { self.advance(); Type::Boolean }
                    _ => Type::Void,
                };
                self.skip_noise();
                self.expect(&Token::Comma);
                self.skip_noise();
            }
            
            // Parse the return expression
            let expr = self.parse_condition()?;
            body.push(Statement::Return { value: Some(expr) });
        }
        
        // Continue parsing body until paragraph break
        while !matches!(self.current(), Token::ParagraphBreak | Token::EOF) {
            self.skip_noise();
            if matches!(self.current(), Token::Period) {
                self.advance();
                self.skip_noise();
            }
            if matches!(self.current(), Token::ParagraphBreak | Token::EOF) {
                break;
            }
            let stmt = self.parse_statement()?;
            body.push(stmt);
        }
        
        // Consume paragraph break
        if *self.current() == Token::ParagraphBreak {
            self.advance();
        }
        
        Ok(Statement::FunctionDef {
            name,
            params,
            return_type,
            body,
        })
    }
    
    fn parse_function_call_statement(&mut self) -> Result<Statement, CompileError> {
        let name = match self.current().clone() {
            Token::StringLiteral(n) => { self.advance(); n }
            _ => return Err(self.err("Expected function name")),
        };
        
        self.skip_noise();
        
        let mut args = Vec::new();
        // Allow 'of', 'to', 'with', 'on' as function call connectors
        if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
            self.advance();
            self.skip_noise();
            
            // Check for loop expansion: "function" of each X from Y [treating X as Y]
            if let Some((variable, collection, treating)) = self.try_parse_each_from()? {
                // Create the argument expression, with optional treating substitution
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
                    args: vec![arg_expr]
                };
                return self.wrap_in_loop_expansion(variable, collection, call_stmt);
            }
            
            // Parse arguments separated by 'and'
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
        }
        
        Ok(Statement::FunctionCall { name, args })
    }
    
    fn parse_block(&mut self) -> Result<Vec<Statement>, CompileError> {
        let mut statements = Vec::new();
        
        let stmt = self.parse_statement()?;
        statements.push(stmt);
        
        while matches!(self.current(), Token::Period | Token::Comma) && 
              !matches!(self.peek(1), Token::But | Token::Else | Token::Otherwise | Token::EOF | Token::ParagraphBreak) {
            self.advance();
            self.skip_noise();
            
            if matches!(self.current(), Token::But | Token::Else | Token::Otherwise | Token::EOF | Token::Period | Token::ParagraphBreak) {
                break;
            }
            
            let stmt = self.parse_statement()?;
            statements.push(stmt);
        }
        
        Ok(statements)
    }
    
    /// Parse comma-separated statements until end of sentence (period).
    /// This is the standard pattern for action-consuming constructs like:
    /// - on error <action>, <action>, <action>.
    /// - while <cond>, <action>, <action>.
    /// - for each X, <action>, <action>.
    fn parse_sentence_body(&mut self) -> Result<Vec<Statement>, CompileError> {
        let mut statements = Vec::new();
        
        loop {
            // Stop at end of sentence markers
            if matches!(self.current(), Token::Period | Token::EOF | Token::ParagraphBreak) {
                break;
            }
            
            let stmt = self.parse_statement()?;
            statements.push(stmt);
            self.skip_noise();
            
            // Comma continues to next action, period ends
            if *self.current() == Token::Comma {
                self.advance();
                self.skip_noise();
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
    
    fn parse_condition(&mut self) -> Result<Expr, CompileError> {
        self.parse_or_expr()
    }
    
    fn parse_or_expr(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_and_expr()?;
        
        while *self.current() == Token::Or {
            self.advance();
            self.skip_noise();
            let right = self.parse_and_expr()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::Or,
                right: Box::new(right),
            };
        }
        
        Ok(left)
    }
    
    fn parse_and_expr(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_comparison()?;
        
        while *self.current() == Token::And {
            self.advance();
            self.skip_noise();
            let right = self.parse_comparison()?;
            left = Expr::BinaryOp {
                left: Box::new(left),
                op: BinaryOperator::And,
                right: Box::new(right),
            };
        }
        
        Ok(left)
    }
    
    /// Look ahead to check if "are" token appears within the next few tokens
    /// Used to determine if we should try parsing the multi-subject "x, y, z are" pattern
    fn has_are_ahead(&self) -> bool {
        for i in 1..20 {
            match self.peek(i) {
                Token::Are => return true,
                Token::Period | Token::EOF | Token::ParagraphBreak => return false,
                Token::Is => return false, // "is" means single subject, not multi
                _ => continue,
            }
        }
        false
    }
    
    fn parse_comparison(&mut self) -> Result<Expr, CompileError> {
        let left = self.parse_expression()?;
        self.skip_noise();
        
        // Check for "subject1, subject2, and subject3 are predicate" pattern
        // Only enter this pattern if we can see "are" coming up ahead
        if *self.current() == Token::Comma && self.has_are_ahead() {
            // Collect subjects for potential "are" pattern
            let mut subjects = vec![left.clone()];
            
            while *self.current() == Token::Comma {
                self.advance();
                self.skip_noise();
                
                // Check for "and" before last subject
                if *self.current() == Token::And {
                    self.advance();
                    self.skip_noise();
                }
                
                // Check if next is "are" - means we're done with subjects
                if *self.current() == Token::Are {
                    break;
                }
                
                let subject = self.parse_primary()?;
                subjects.push(subject);
                self.skip_noise();
            }
            
            // If we have "are" after collecting subjects, expand to ANDed conditions
            if *self.current() == Token::Are && subjects.len() > 1 {
                self.advance();
                self.skip_noise();
                
                let negated = *self.current() == Token::Not;
                if negated {
                    self.advance();
                    self.skip_noise();
                }
                
                // Parse the predicate (e.g., "true", "false", property, or value)
                let predicate = self.parse_primary()?;
                
                // Build ANDed conditions: subject1 is predicate AND subject2 is predicate ...
                let mut result: Option<Expr> = None;
                for subject in subjects {
                    let comparison = if negated {
                        Expr::BinaryOp {
                            left: Box::new(subject),
                            op: BinaryOperator::NotEqual,
                            right: Box::new(predicate.clone()),
                        }
                    } else {
                        Expr::BinaryOp {
                            left: Box::new(subject),
                            op: BinaryOperator::Equal,
                            right: Box::new(predicate.clone()),
                        }
                    };
                    
                    result = Some(match result {
                        None => comparison,
                        Some(left) => Expr::BinaryOp {
                            left: Box::new(left),
                            op: BinaryOperator::And,
                            right: Box::new(comparison),
                        },
                    });
                }
                
                return Ok(result.unwrap());
            }
            
            // Not an "are" pattern, return left as-is (shouldn't normally happen)
            return Ok(left);
        }
        
        if *self.current() == Token::Is || *self.current() == Token::Are {
            self.advance();
            self.skip_noise();
            
            let negated = *self.current() == Token::Not;
            if negated {
                self.advance();
                self.skip_noise();
            }
            
            let property = match self.current() {
                Token::Even => Some(Property::Even),
                Token::Odd => Some(Property::Odd),
                Token::Positive => Some(Property::Positive),
                Token::Negative => Some(Property::Negative),
                Token::Zero => Some(Property::Zero),
                Token::Empty => Some(Property::Empty),
                _ => None,
            };
            
            if let Some(prop) = property {
                self.advance();
                let check = Expr::PropertyCheck {
                    value: Box::new(left),
                    property: prop,
                };
                return if negated {
                    Ok(Expr::UnaryOp {
                        op: UnaryOperator::Not,
                        operand: Box::new(check),
                    })
                } else {
                    Ok(check)
                };
            }
            
            if *self.current() == Token::Greater || *self.current() == Token::Less {
                let is_greater = *self.current() == Token::Greater;
                self.advance();
                self.skip_noise();
                self.expect(&Token::Than);
                self.skip_noise();
                
                let mut is_equal = false;
                if *self.current() == Token::Or {
                    self.advance();
                    self.skip_noise();
                    self.expect(&Token::Equal);
                    self.expect(&Token::Equals);
                    self.expect(&Token::To);
                    self.skip_noise();
                    is_equal = true;
                }
                
                let right = self.parse_expression()?;
                let op = match (is_greater, is_equal, negated) {
                    (true, false, false) => BinaryOperator::Greater,
                    (true, true, false) => BinaryOperator::GreaterEqual,
                    (false, false, false) => BinaryOperator::Less,
                    (false, true, false) => BinaryOperator::LessEqual,
                    (true, false, true) => BinaryOperator::LessEqual,
                    (true, true, true) => BinaryOperator::Less,
                    (false, false, true) => BinaryOperator::GreaterEqual,
                    (false, true, true) => BinaryOperator::Greater,
                };
                
                return Ok(Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                });
            }
            
            // Handle "is equal to" / "is equals" explicitly
            if *self.current() == Token::Equals || *self.current() == Token::Equal {
                self.advance();
                self.skip_noise();
                // Skip optional "to"
                if *self.current() == Token::To {
                    self.advance();
                    self.skip_noise();
                }
                
                let right = self.parse_expression()?;
                let op = if negated {
                    BinaryOperator::NotEqual
                } else {
                    BinaryOperator::Equal
                };
                
                return Ok(Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                });
            }
            
            let right = self.parse_expression()?;
            let op = if negated {
                BinaryOperator::NotEqual
            } else {
                BinaryOperator::Equal
            };
            
            return Ok(Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            });
        }
        
        Ok(left)
    }
    
    fn parse_expression(&mut self) -> Result<Expr, CompileError> {
        let mut expr = self.parse_additive()?;
        
        // Check for type casting with 'as' keyword
        self.skip_noise();
        if *self.current() == Token::As {
            self.advance();
            self.skip_noise();
            
            // Optional 'a'/'an' before type
            if matches!(self.current(), Token::A | Token::An) {
                self.advance();
                self.skip_noise();
            }
            
            // Parse target type
            let target_type = match self.current() {
                Token::Number | Token::Int => { self.advance(); Type::Integer }
                Token::Text => { self.advance(); Type::String }
                Token::Boolean => { self.advance(); Type::Boolean }
                Token::Float => { self.advance(); Type::Float }
                _ => return Err(self.err("Expected type after 'as'")),
            };
            
            expr = Expr::Cast {
                value: Box::new(expr),
                target_type,
            };
        }
        
        Ok(expr)
    }
    
    fn parse_additive(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_multiplicative()?;
        
        loop {
            self.skip_noise();
            let op = match self.current() {
                Token::Add => Some(BinaryOperator::Add),
                Token::Subtract => Some(BinaryOperator::Subtract),
                _ => None,
            };
            
            if let Some(operator) = op {
                self.advance();
                self.skip_noise();
                let right = self.parse_multiplicative()?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: operator,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_multiplicative(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_bitwise()?;
        
        loop {
            self.skip_noise();
            let op = match self.current() {
                Token::Multiply => Some(BinaryOperator::Multiply),
                Token::Divide => Some(BinaryOperator::Divide),
                Token::Modulo => Some(BinaryOperator::Modulo),
                _ => None,
            };
            
            if let Some(operator) = op {
                self.advance();
                self.skip_noise();
                let right = self.parse_bitwise()?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: operator,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_bitwise(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.parse_primary()?;
        
        loop {
            self.skip_noise();
            let op = match self.current() {
                Token::BitAnd => Some(BinaryOperator::BitAnd),
                Token::BitOr => Some(BinaryOperator::BitOr),
                Token::BitXor => Some(BinaryOperator::BitXor),
                Token::BitShiftLeft => Some(BinaryOperator::ShiftLeft),
                Token::BitShiftRight => Some(BinaryOperator::ShiftRight),
                _ => None,
            };
            
            if let Some(operator) = op {
                self.advance();
                self.skip_noise();
                let right = self.parse_primary()?;
                left = Expr::BinaryOp {
                    left: Box::new(left),
                    op: operator,
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        
        Ok(left)
    }
    
    fn parse_format_string(&self, s: &str) -> Vec<FormatPart> {
        let mut parts = Vec::new();
        let mut current_literal = String::new();
        let mut chars = s.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '{' {
                // Check for escaped brace {{
                if chars.peek() == Some(&'{') {
                    chars.next();
                    current_literal.push('{');
                    continue;
                }
                
                // Save any accumulated literal
                if !current_literal.is_empty() {
                    parts.push(FormatPart::Literal(current_literal.clone()));
                    current_literal.clear();
                }
                
                // Parse content until closing brace
                let mut placeholder_content = String::new();
                while let Some(&c) = chars.peek() {
                    if c == '}' {
                        chars.next();
                        break;
                    }
                    placeholder_content.push(c);
                    chars.next();
                }
                
                // Split on first : to separate variable/expression from format spec
                // The format spec is preserved exactly as written, with no interpretation
                let (content, format) = if let Some(colon_pos) = placeholder_content.find(':') {
                    let content = placeholder_content[..colon_pos].trim().to_string();
                    // Preserve format spec verbatim - no trimming, no interpretation
                    let format = placeholder_content[colon_pos + 1..].to_string();
                    (content, Some(format))
                } else {
                    (placeholder_content.trim().to_string(), None)
                };
                
                // Determine if content is an expression or a simple variable name
                // The format spec (if any) is attached verbatim without any parsing
                if let Some(expr) = self.try_parse_expression(&content) {
                    parts.push(FormatPart::Expression { 
                        expr: Box::new(expr), 
                        format 
                    });
                } else {
                    parts.push(FormatPart::Variable { 
                        name: content, 
                        format 
                    });
                }
            } else if ch == '}' {
                // Check for escaped brace }}
                if chars.peek() == Some(&'}') {
                    chars.next();
                    current_literal.push('}');
                } else {
                    current_literal.push(ch);
                }
            } else {
                current_literal.push(ch);
            }
        }
        
        // Add any remaining literal
        if !current_literal.is_empty() {
            parts.push(FormatPart::Literal(current_literal));
        }
        
        parts
    }
    
    fn try_parse_expression(&self, content: &str) -> Option<Expr> {
        // Simple heuristic: if it contains spaces, it might be an expression
        // Single identifiers are likely just variable names
        if !content.contains(' ') || content.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        
        // Try to parse as an English expression (including comparisons)
        let mut lexer = Lexer::new(content);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        // Use parse_and_expr to handle comparisons like "0 is equal to 0"
        match parser.parse_and_expr() {
            Ok(expr) => {
                // Check if we consumed all tokens (successful parse)
                if *parser.current() == Token::EOF {
                    Some(expr)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
    
    fn parse_primary(&mut self) -> Result<Expr, CompileError> {
        self.skip_noise();
        
        match self.current().clone() {
            Token::Not => {
                self.advance();
                self.skip_noise();
                let operand = self.parse_primary()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Not,
                    operand: Box::new(operand),
                })
            }
            Token::Minus => {
                self.advance();
                self.skip_noise();
                let operand = self.parse_primary()?;
                Ok(Expr::UnaryOp {
                    op: UnaryOperator::Negate,
                    operand: Box::new(operand),
                })
            }
            Token::Byte => {
                // byte N of buffer
                self.advance();
                self.skip_noise();
                let index = self.parse_primary()?;
                self.skip_noise();
                if *self.current() != Token::Of {
                    return Err(self.err("Expected 'of' after byte index"));
                }
                self.advance();
                self.skip_noise();
                let buffer = self.parse_primary()?;
                Ok(Expr::ByteAccess {
                    buffer: Box::new(buffer),
                    index: Box::new(index),
                })
            }
            Token::Element => {
                // element N of list
                self.advance();
                self.skip_noise();
                let index = self.parse_primary()?;
                self.skip_noise();
                if *self.current() != Token::Of {
                    return Err(self.err("Expected 'of' after element index"));
                }
                self.advance();
                self.skip_noise();
                let list = self.parse_primary()?;
                Ok(Expr::ElementAccess {
                    list: Box::new(list),
                    index: Box::new(index),
                })
            }
            Token::IntegerLiteral(n) => {
                self.advance();
                Ok(Expr::IntegerLit(n))
            }
            Token::FloatLiteral(n) => {
                self.advance();
                Ok(Expr::FloatLit(n))
            }
            Token::StringLiteral(s) => {
                self.advance();
                self.skip_noise();
                
                // Check if this is a format string (contains {variable})
                if s.contains('{') && !s.starts_with("{{") {
                    let parts = self.parse_format_string(&s);
                    if !parts.is_empty() && parts.iter().any(|p| matches!(p, FormatPart::Variable { .. } | FormatPart::Expression { .. })) {
                        return Ok(Expr::FormatString { parts });
                    }
                }
                
                // Check if this is a function call: "name" of/to/with/on args
                if matches!(self.current(), Token::Of | Token::To | Token::With | Token::On) {
                    self.advance();
                    self.skip_noise();
                    
                    let mut args = Vec::new();
                    loop {
                        let arg = self.parse_expression()?;
                        args.push(arg);
                        
                        self.skip_noise();

                        if *self.current() == Token::Comma {
                            self.advance();        // <-- NEW: comma terminates the argument
                            self.skip_noise();
                            // do NOT break; comma means “argument ended”, but you might
                            // still have `and` for another argument OR you might just continue
                            // parsing the surrounding expression after the call.
                            // For call-args specifically, comma usually means:
                            // - end current arg, and continue parsing more args only if "and" follows
                            if *self.current() == Token::And {
                                self.advance();
                                self.skip_noise();
                                continue;
                            } else {
                                break;             // comma used as terminator without "and"
                            }
                        }
                        
                        if *self.current() == Token::And {
                            self.advance();
                            self.skip_noise();
                        } else {
                            break;
                        }
                    }
                    
                    Ok(Expr::FunctionCall { name: s, args })
                } else if *self.current() == Token::Apostrophe {
                    // Property access on quoted variable: "job timer"'s duration
                    self.advance();
                    if let Token::Identifier(prop_s) = self.current().clone() {
                        if prop_s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            let property = match self.current() {
                                // Buffer properties
                                Token::Size => ObjectProperty::Size,
                                Token::Capacity => ObjectProperty::Capacity,
                                Token::Empty => ObjectProperty::Empty,
                                Token::Full => ObjectProperty::Full,
                                // Time properties
                                Token::Hour => ObjectProperty::Hour,
                                Token::Minute => ObjectProperty::Minute,
                                Token::Second => ObjectProperty::Second,
                                Token::Day => ObjectProperty::Day,
                                Token::Month => ObjectProperty::Month,
                                Token::Year => ObjectProperty::Year,
                                Token::Unix => ObjectProperty::Unix,
                                // Timer properties
                                Token::Duration => ObjectProperty::Duration,
                                Token::Elapsed => ObjectProperty::Elapsed,
                                Token::Running => ObjectProperty::Running,
                                // Handle single-quoted multi-word property names and 'start'
                                Token::Identifier(ref prop_name) => {
                                    match prop_name.to_lowercase().as_str() {
                                        "start" => ObjectProperty::StartTime,
                                        "start time" => ObjectProperty::StartTime,
                                        "end time" => ObjectProperty::EndTime,
                                        "duration" => ObjectProperty::Duration,
                                        "elapsed" => ObjectProperty::Elapsed,
                                        "running" => ObjectProperty::Running,
                                        _ => return Err(self.err_expected("property name", self.current())),
                                    }
                                }
                                _ => return Err(self.err_expected("property name", self.current())),
                            };
                            self.advance();
                            
                            // Check for "in seconds" / "in milliseconds" or just "seconds"/"milliseconds" for duration/elapsed
                            if matches!(property, ObjectProperty::Duration | ObjectProperty::Elapsed) {
                                self.skip_noise();
                                // Handle both "elapsed in seconds" and "elapsed seconds"
                                if *self.current() == Token::In {
                                    self.advance();
                                    self.skip_noise();
                                }
                                // Now check for unit
                                if matches!(self.current(), Token::Seconds | Token::Second | Token::Milliseconds | Token::Millisecond) {
                                    let unit = match self.current() {
                                        Token::Seconds | Token::Second => {
                                            self.advance();
                                            ast::TimeUnit::Seconds
                                        }
                                        Token::Milliseconds | Token::Millisecond => {
                                            self.advance();
                                            ast::TimeUnit::Milliseconds
                                        }
                                        _ => unreachable!(),
                                    };
                                    return Ok(Expr::DurationCast {
                                        value: Box::new(Expr::PropertyAccess { object: s, property }),
                                        unit,
                                    });
                                }
                            }
                            
                            return Ok(Expr::PropertyAccess { object: s, property });
                        }
                    }
                    // Handle "start time" and "end time" as multi-word properties
                    if let Token::Identifier(ref id) = self.current() {
                        if id == "start" {
                            self.advance();
                            self.skip_noise();
                            if *self.current() == Token::Time {
                                self.advance();
                                return Ok(Expr::PropertyAccess { object: s, property: ObjectProperty::StartTime });
                            }
                        }
                    }
                    if let Token::Identifier(ref id) = self.current() {
                        if id.to_lowercase() == "end" {
                            self.advance();
                            self.skip_noise();
                            if *self.current() == Token::Time {
                                self.advance();
                                return Ok(Expr::PropertyAccess { object: s, property: ObjectProperty::EndTime });
                            }
                        }
                    }
                    Err(self.err("Expected 's after apostrophe for property access"))
                } else {
                    Ok(Expr::StringLit(s))
                }
            }
            Token::True => {
                self.advance();
                Ok(Expr::BoolLit(true))
            }
            Token::False => {
                self.advance();
                Ok(Expr::BoolLit(false))
            }
            // Handle "current time" expression
            Token::Current => {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Time {
                    self.advance();
                    self.skip_noise();
                    
                    // Check for property access: "current time's hour"
                    if *self.current() == Token::Apostrophe {
                        self.advance();
                        if let Token::Identifier(s) = self.current().clone() {
                            if s.to_lowercase() == "s" {
                                self.advance();
                                self.skip_noise();
                                
                                let property = match self.current() {
                                    Token::Hour => ObjectProperty::Hour,
                                    Token::Minute => ObjectProperty::Minute,
                                    Token::Second => ObjectProperty::Second,
                                    Token::Day => ObjectProperty::Day,
                                    Token::Month => ObjectProperty::Month,
                                    Token::Year => ObjectProperty::Year,
                                    Token::Unix => ObjectProperty::Unix,
                                    _ => return Err(self.err_expected("time property (hour, minute, second, day, month, year)", self.current())),
                                };
                                self.advance();
                                
                                // Return property access on current time
                                return Ok(Expr::PropertyAccess {
                                    object: "_current_time".to_string(),
                                    property,
                                });
                            }
                        }
                    }
                    
                    Ok(Expr::CurrentTime)
                } else {
                    Err(self.err("Expected 'time' after 'current'"))
                }
            }
            // Handle arguments's and environment's property access directly from tokens
            Token::Arguments | Token::Argument => {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Apostrophe {
                    self.advance();
                    if let Token::Identifier(s) = self.current().clone() {
                        if s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            return match self.current() {
                                Token::Count => { self.advance(); Ok(Expr::ArgumentCount) }
                                Token::Identifier(ref id) if id.to_lowercase() == "name" => { 
                                    self.advance(); Ok(Expr::ArgumentName) 
                                }
                                Token::First => { self.advance(); Ok(Expr::ArgumentFirst) }
                                Token::Identifier(ref id) if id.to_lowercase() == "second" => { 
                                    self.advance(); Ok(Expr::ArgumentSecond) 
                                }
                                Token::Last => { self.advance(); Ok(Expr::ArgumentLast) }
                                Token::Empty => { self.advance(); Ok(Expr::ArgumentEmpty) }
                                Token::All => { self.advance(); Ok(Expr::ArgumentAll) }
                                _ => Err(self.err_expected("arguments property (count, first, last, empty, all)", self.current())),
                            };
                        }
                    }
                }
                Err(self.err("Expected 's after 'arguments'"))
            }
            
            Token::Environment => {
                self.advance();
                self.skip_noise();
                
                if *self.current() == Token::Apostrophe {
                    self.advance();
                    if let Token::Identifier(s) = self.current().clone() {
                        if s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            return match self.current() {
                                Token::Count => { self.advance(); Ok(Expr::EnvironmentVariableCount) }
                                Token::First => { self.advance(); Ok(Expr::EnvironmentVariableFirst) }
                                Token::Last => { self.advance(); Ok(Expr::EnvironmentVariableLast) }
                                Token::Empty => { self.advance(); Ok(Expr::EnvironmentVariableEmpty) }
                                Token::StringLiteral(env_name) => {
                                    let env_name = env_name.clone();
                                    self.advance();
                                    Ok(Expr::EnvironmentVariable { name: Box::new(Expr::StringLit(env_name)) })
                                }
                                _ => Err(self.err_expected("environment property", self.current())),
                            };
                        }
                    }
                }
                Err(self.err("Expected 's after 'environment'"))
            }
            
            Token::Identifier(name) => {
                self.advance();
                self.skip_noise();
                
                // Check for property access: identifier's property
                if *self.current() == Token::Apostrophe {
                    self.advance();
                    // Expect 's' followed by property name
                    if let Token::Identifier(s) = self.current().clone() {
                        if s.to_lowercase() == "s" {
                            self.advance();
                            self.skip_noise();
                            
                            // Special handling for arguments's and environment's
                            let name_lower = name.to_lowercase();
                            if name_lower == "arguments" || name_lower == "args" {
                                return match self.current() {
                                    Token::Count => { self.advance(); Ok(Expr::ArgumentCount) }
                                    Token::Identifier(ref id) if id.to_lowercase() == "name" => { 
                                        self.advance(); Ok(Expr::ArgumentName) 
                                    }
                                    Token::First => { self.advance(); Ok(Expr::ArgumentFirst) }
                                    Token::Identifier(ref id) if id.to_lowercase() == "second" => { 
                                        self.advance(); Ok(Expr::ArgumentSecond) 
                                    }
                                    Token::Last => { self.advance(); Ok(Expr::ArgumentLast) }
                                    Token::Empty => { self.advance(); Ok(Expr::ArgumentEmpty) }
                                    Token::All => { self.advance(); Ok(Expr::ArgumentAll) }
                                    _ => Err(self.err_expected("arguments property (count, first, last, empty, all)", self.current())),
                                };
                            }
                            
                            if name_lower == "environment" || name_lower == "env" {
                                return match self.current() {
                                    Token::Count => { self.advance(); Ok(Expr::EnvironmentVariableCount) }
                                    Token::First => { self.advance(); Ok(Expr::EnvironmentVariableFirst) }
                                    Token::Last => { self.advance(); Ok(Expr::EnvironmentVariableLast) }
                                    Token::Empty => { self.advance(); Ok(Expr::EnvironmentVariableEmpty) }
                                    Token::StringLiteral(env_name) => {
                                        let env_name = env_name.clone();
                                        self.advance();
                                        Ok(Expr::EnvironmentVariable { name: Box::new(Expr::StringLit(env_name)) })
                                    }
                                    _ => Err(self.err_expected("environment property", self.current())),
                                };
                            }
                            
                            // Check if user meant 'arguments' or 'environment' but made a typo
                            // If so, the property they're accessing might be valid for that object
                            let is_arguments_property = matches!(self.current(), 
                                Token::Count | Token::First | Token::Last | Token::Empty | Token::All);
                            let is_env_property = matches!(self.current(),
                                Token::Count | Token::First | Token::Last | Token::Empty);
                            
                            if is_arguments_property {
                                if let Some(suggestion) = find_similar_keyword(&name, &["arguments", "args"]) {
                                    return Err(self.err(&format!(
                                        "Unknown identifier '{}' - did you mean '{}'?",
                                        name, suggestion
                                    )));
                                }
                            }
                            if is_env_property {
                                if let Some(suggestion) = find_similar_keyword(&name, &["environment", "env"]) {
                                    return Err(self.err(&format!(
                                        "Unknown identifier '{}' - did you mean '{}'?",
                                        name, suggestion
                                    )));
                                }
                            }
                            
                            // Parse property name for other objects
                            let property = match self.current() {
                                // Buffer properties
                                Token::Size => ObjectProperty::Size,
                                Token::Capacity => ObjectProperty::Capacity,
                                Token::Empty => ObjectProperty::Empty,
                                Token::Full => ObjectProperty::Full,
                                
                                // File properties
                                Token::Descriptor => ObjectProperty::Descriptor,
                                Token::Modified => ObjectProperty::Modified,
                                Token::Accessed => ObjectProperty::Accessed,
                                Token::Permissions => ObjectProperty::Permissions,
                                Token::Readable => ObjectProperty::Readable,
                                Token::Writable => ObjectProperty::Writable,
                                
                                // List properties
                                Token::First => ObjectProperty::First,
                                Token::Last => ObjectProperty::Last,
                                
                                // Number properties
                                Token::Absolute => ObjectProperty::Absolute,
                                Token::Sign => ObjectProperty::Sign,
                                Token::Even => ObjectProperty::Even,
                                Token::Odd => ObjectProperty::Odd,
                                Token::Positive => ObjectProperty::Positive,
                                Token::Negative => ObjectProperty::Negative,
                                Token::Zero => ObjectProperty::Zero,
                                
                                // Time properties
                                Token::Hour => ObjectProperty::Hour,
                                Token::Minute => ObjectProperty::Minute,
                                Token::Second => ObjectProperty::Second,
                                Token::Day => ObjectProperty::Day,
                                Token::Month => ObjectProperty::Month,
                                Token::Year => ObjectProperty::Year,
                                Token::Unix => ObjectProperty::Unix,
                                
                                // Timer properties
                                Token::Duration => ObjectProperty::Duration,
                                Token::Elapsed => ObjectProperty::Elapsed,
                                Token::Identifier(ref id) if id.to_lowercase() == "start" => ObjectProperty::StartTime,
                                Token::Identifier(ref id) if id.to_lowercase() == "end" => ObjectProperty::EndTime,
                                Token::Running => ObjectProperty::Running,
                                
                                _ => return Err(self.err_expected("property name", self.current())),
                            };
                            self.advance();
                            return Ok(Expr::PropertyAccess {
                                object: name,
                                property,
                            });
                        }
                    }
                }
                
                Ok(Expr::Identifier(name))
            }
            Token::OpenBracket => {
                self.advance();
                self.skip_noise();
                
                let mut elements = Vec::new();
                
                // Empty list
                if *self.current() == Token::CloseBracket {
                    self.advance();
                    return Ok(Expr::ListLit { elements });
                }
                
                // Parse first element
                elements.push(self.parse_expression()?);
                self.skip_noise();
                
                // Parse remaining elements
                while *self.current() == Token::Comma {
                    self.advance();
                    self.skip_noise();
                    elements.push(self.parse_expression()?);
                    self.skip_noise();
                }
                
                self.expect(&Token::CloseBracket);
                Ok(Expr::ListLit { elements })
            }
            Token::All => {
                self.advance();
                self.skip_noise();
                self.expect(&Token::The);
                self.skip_noise();
                self.expect(&Token::Number);
                self.skip_noise();
                
                if *self.current() == Token::From || *self.current() == Token::Between {
                    let inclusive = *self.current() == Token::Between;
                    self.advance();
                    self.skip_noise();
                    
                    let start = self.parse_primary()?;
                    self.skip_noise();
                    self.expect(&Token::To);
                    self.expect(&Token::And);
                    self.skip_noise();
                    
                    let end = self.parse_primary()?;
                    
                    Ok(Expr::Range {
                        start: Box::new(start),
                        end: Box::new(end),
                        inclusive,
                    })
                } else {
                    Err(self.err("Expected 'from' or 'between' after 'all the numbers'"))
                }
            }
            Token::Number => {
                self.advance();
                Ok(Expr::Identifier("_iter".to_string()))
            }
            Token::The => {
                self.advance(); // consume 'the'
                self.skip_noise();
                // "the x" or "the number called x" -> variable reference
                match self.current().clone() {
                    // "the argument count" or "the argument at N"
                    Token::Argument => {
                        self.advance();
                        self.skip_noise();
                        
                        if *self.current() == Token::Count {
                            self.advance();
                            Ok(Expr::ArgumentCount)
                        } else if *self.current() == Token::On { // "at" maps to Token::On
                            self.advance();
                            self.skip_noise();
                            let index = self.parse_expression()?;
                            Ok(Expr::ArgumentAt { index: Box::new(index) })
                        } else {
                            Err(self.err("Expected 'count' or 'at' after 'the argument'"))
                        }
                    }
                    // "the environment variable ..." 
                    Token::Environment => {
                        self.advance();
                        self.skip_noise();
                        
                        // Skip optional "variable"
                        if *self.current() == Token::Variable {
                            self.advance();
                            self.skip_noise();
                        }
                        
                        // "the environment variable count"
                        if *self.current() == Token::Count {
                            self.advance();
                            Ok(Expr::EnvironmentVariableCount)
                        }
                        // "the environment variable at N"
                        else if *self.current() == Token::On { // "at" maps to Token::On
                            self.advance();
                            self.skip_noise();
                            let index = self.parse_expression()?;
                            Ok(Expr::EnvironmentVariableAt { index: Box::new(index) })
                        }
                        // "the environment variable "NAME"" or "the environment variable exists"
                        else {
                            let name = self.parse_primary()?;
                            self.skip_noise();
                            
                            // Check for "exists" after the name
                            if *self.current() == Token::Exists {
                                self.advance();
                                Ok(Expr::EnvironmentVariableExists { name: Box::new(name) })
                            } else {
                                Ok(Expr::EnvironmentVariable { name: Box::new(name) })
                            }
                        }
                    }
                    Token::Identifier(name) => {
                        self.advance();
                        self.skip_noise();
                        
                        // Check for property access: "the now's hour"
                        if *self.current() == Token::Apostrophe {
                            self.advance();
                            if let Token::Identifier(prop_s) = self.current().clone() {
                                if prop_s.to_lowercase() == "s" {
                                    self.advance();
                                    self.skip_noise();
                                    
                                    let property = match self.current() {
                                        // Time properties
                                        Token::Hour => ObjectProperty::Hour,
                                        Token::Minute => ObjectProperty::Minute,
                                        Token::Second => ObjectProperty::Second,
                                        Token::Day => ObjectProperty::Day,
                                        Token::Month => ObjectProperty::Month,
                                        Token::Year => ObjectProperty::Year,
                                        Token::Unix => ObjectProperty::Unix,
                                        // Timer properties
                                        Token::Duration => ObjectProperty::Duration,
                                        Token::Elapsed => ObjectProperty::Elapsed,
                                        Token::Running => ObjectProperty::Running,
                                        // Other properties
                                        Token::Size => ObjectProperty::Size,
                                        Token::Capacity => ObjectProperty::Capacity,
                                        Token::Empty => ObjectProperty::Empty,
                                        Token::Full => ObjectProperty::Full,
                                        // Handle single-quoted multi-word property names and 'start'
                                        Token::Identifier(ref prop_name) => {
                                            match prop_name.to_lowercase().as_str() {
                                                "start" => ObjectProperty::StartTime,
                                                "start time" => ObjectProperty::StartTime,
                                                "end time" => ObjectProperty::EndTime,
                                                "duration" => ObjectProperty::Duration,
                                                "elapsed" => ObjectProperty::Elapsed,
                                                "running" => ObjectProperty::Running,
                                                _ => return Err(self.err_expected("property name", self.current())),
                                            }
                                        }
                                        _ => return Err(self.err_expected("property name", self.current())),
                                    };
                                    self.advance();
                                    
                                    return Ok(Expr::PropertyAccess { object: name, property });
                                }
                            }
                            return Err(self.err("Expected 's after apostrophe for property access"));
                        }
                        
                        Ok(Expr::Identifier(name))
                    }
                    Token::StringLiteral(name) => {
                        self.advance();
                        self.skip_noise();
                        
                        // Check for property access: "the "job timer"'s duration"
                        if *self.current() == Token::Apostrophe {
                            self.advance();
                            if let Token::Identifier(prop_s) = self.current().clone() {
                                if prop_s.to_lowercase() == "s" {
                                    self.advance();
                                    self.skip_noise();
                                    
                                    let property = match self.current() {
                                        // Time properties
                                        Token::Hour => ObjectProperty::Hour,
                                        Token::Minute => ObjectProperty::Minute,
                                        Token::Second => ObjectProperty::Second,
                                        Token::Day => ObjectProperty::Day,
                                        Token::Month => ObjectProperty::Month,
                                        Token::Year => ObjectProperty::Year,
                                        Token::Unix => ObjectProperty::Unix,
                                        // Timer properties
                                        Token::Duration => ObjectProperty::Duration,
                                        Token::Elapsed => ObjectProperty::Elapsed,
                                        Token::Running => ObjectProperty::Running,
                                        // Other properties
                                        Token::Size => ObjectProperty::Size,
                                        Token::Capacity => ObjectProperty::Capacity,
                                        Token::Empty => ObjectProperty::Empty,
                                        Token::Full => ObjectProperty::Full,
                                        // Handle single-quoted multi-word property names and 'start'
                                        Token::Identifier(ref prop_name) => {
                                            match prop_name.to_lowercase().as_str() {
                                                "start" => ObjectProperty::StartTime,
                                                "start time" => ObjectProperty::StartTime,
                                                "end time" => ObjectProperty::EndTime,
                                                "duration" => ObjectProperty::Duration,
                                                "elapsed" => ObjectProperty::Elapsed,
                                                "running" => ObjectProperty::Running,
                                                _ => return Err(self.err_expected("property name", self.current())),
                                            }
                                        }
                                        _ => return Err(self.err_expected("property name", self.current())),
                                    };
                                    self.advance();
                                    
                                    // Check for "in seconds" / "in milliseconds" or just "seconds"/"milliseconds" for duration/elapsed
                                    if matches!(property, ObjectProperty::Duration | ObjectProperty::Elapsed) {
                                        self.skip_noise();
                                        // Handle both "elapsed in seconds" and "elapsed seconds"
                                        if *self.current() == Token::In {
                                            self.advance();
                                            self.skip_noise();
                                        }
                                        // Now check for unit
                                        if matches!(self.current(), Token::Seconds | Token::Second | Token::Milliseconds | Token::Millisecond) {
                                            let unit = match self.current() {
                                                Token::Seconds | Token::Second => {
                                                    self.advance();
                                                    ast::TimeUnit::Seconds
                                                }
                                                Token::Milliseconds | Token::Millisecond => {
                                                    self.advance();
                                                    ast::TimeUnit::Milliseconds
                                                }
                                                _ => unreachable!(),
                                            };
                                            return Ok(Expr::DurationCast {
                                                value: Box::new(Expr::PropertyAccess { object: name, property }),
                                                unit,
                                            });
                                        }
                                    }
                                    
                                    return Ok(Expr::PropertyAccess { object: name, property });
                                }
                            }
                            // Handle "start time" and "end time" as multi-word properties
                            if let Token::Identifier(ref id) = self.current() {
                                if id == "start" {
                                    self.advance();
                                    self.skip_noise();
                                    if *self.current() == Token::Time {
                                        self.advance();
                                        return Ok(Expr::PropertyAccess { object: name, property: ObjectProperty::StartTime });
                                    }
                                }
                            }
                            if let Token::Identifier(ref id) = self.current() {
                                if id.to_lowercase() == "end" {
                                    self.advance();
                                    self.skip_noise();
                                    if *self.current() == Token::Time {
                                        self.advance();
                                        return Ok(Expr::PropertyAccess { object: name, property: ObjectProperty::EndTime });
                                    }
                                }
                            }
                            return Err(self.err("Expected 's after apostrophe for property access"));
                        }
                        
                        Ok(Expr::Identifier(name))
                    }
                    Token::Number | Token::Text | Token::Boolean => {
                        self.advance(); // consume type
                        self.skip_noise();
                        
                        // "the number called x" -> variable reference
                        // "the number" alone -> loop iterator reference
                        if *self.current() == Token::Called {
                            self.advance();
                            self.skip_noise();
                            match self.current().clone() {
                                Token::StringLiteral(name) => {
                                    self.advance();
                                    Ok(Expr::Identifier(name))
                                }
                                Token::Identifier(name) => {
                                    self.advance();
                                    Ok(Expr::Identifier(name))
                                }
                                _ => Err(self.err("Expected variable name after 'called'")),
                            }
                        } else {
                            // "the number" without "called" refers to loop iterator
                            Ok(Expr::Identifier("_iter".to_string()))
                        }
                    }
                    _ => Err(self.err_expected("identifier after 'the'", self.current())),
                }
            }
            Token::A | Token::An => {
                // Check if this is an article before a type, or just the letter "a"/"an" as identifier
                let is_article = self.current().clone();
                self.advance();
                self.skip_noise();
                
                // If followed by a type keyword, treat as article and parse the type expression
                if matches!(self.current(), Token::Number | Token::Text | Token::Boolean | Token::List) {
                    self.parse_primary()
                } else {
                    // Otherwise, treat "a" or "an" as an identifier
                    let name = if matches!(is_article, Token::A) { "a" } else { "an" };
                    Ok(Expr::Identifier(name.to_string()))
                }
            }
            _ => Err(self.err_expected("a statement", self.current())),
        }
    }
    
    // ========================================================================
    // Time and Timer parsing
    // ========================================================================
    
    fn parse_wait(&mut self) -> Result<Statement, CompileError> {
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
    
    fn parse_timer_start(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume Start/Begin
        self.skip_noise();
        
        // Optional "the"
        self.expect(&Token::The);
        self.skip_noise();
        
        // Timer name (string literal or identifier)
        let name = match self.current().clone() {
            Token::StringLiteral(n) => { self.advance(); n }
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected timer name after 'start'")),
        };
        
        Ok(Statement::TimerStart { name })
    }
    
    fn parse_timer_stop(&mut self) -> Result<Statement, CompileError> {
        self.advance(); // consume Stop/Finish
        self.skip_noise();
        
        // Optional "the"
        self.expect(&Token::The);
        self.skip_noise();
        
        // Timer name (string literal or identifier)
        let name = match self.current().clone() {
            Token::StringLiteral(n) => { self.advance(); n }
            Token::Identifier(n) => { self.advance(); n }
            _ => return Err(self.err("Expected timer name after 'stop'")),
        };
        
        Ok(Statement::TimerStop { name })
    }
    
    fn parse_get(&mut self) -> Result<Statement, CompileError> {
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
                        Token::StringLiteral(n) => { self.advance(); n }
                        Token::Identifier(n) => { self.advance(); n }
                        _ => return Err(self.err("Expected variable name after 'into'")),
                    };
                    
                    return Ok(Statement::GetTime { into: name });
                }
            }
        }
        
        Err(self.err("Expected 'current time into <name>' after 'get'"))
    }
}

// ========================================================================
// Unit Tests for Buffer Declarations
// ========================================================================

#[cfg(test)]
mod buffer_declaration_tests {
    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, CompileError> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    #[test]
    fn test_buffer_with_string_initializer() {
        let input = r#"a buffer called "byte_buf" is "Hello"."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::VarDecl { name, var_type, value } => {
                assert_eq!(name, "byte_buf");
                assert_eq!(var_type, &Some(Type::Buffer));
                assert!(matches!(value, Some(Expr::StringLit(_))));
            }
            _ => panic!("Expected VarDecl for buffer with initializer"),
        }
    }

    #[test]
    fn test_buffer_with_size_clause() {
        let input = r#"a buffer called "log" is 2048 bytes."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "log");
                assert!(matches!(size, Expr::IntegerLit(2048)));
            }
            _ => panic!("Expected BufferDecl for buffer with size"),
        }
    }

    #[test]
    fn test_buffer_with_size_in_size_suffix() {
        let input = r#"a buffer called "buf" is 1024 bytes in size."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "buf");
                assert!(matches!(size, Expr::IntegerLit(1024)));
            }
            _ => panic!("Expected BufferDecl for buffer with size in size"),
        }
    }

    #[test]
    fn test_buffer_non_numeric_size_error() {
        let input = r#"a buffer called "bad" is "Hello" bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("numeric literal"));
    }

    #[test]
    fn test_buffer_negative_size_error() {
        let input = r#"a buffer called "bad" is -100 bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("positive integer"));
    }

    #[test]
    fn test_buffer_zero_size_error() {
        let input = r#"a buffer called "bad" is 0 bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("positive integer"));
    }

    #[test]
    fn test_buffer_excessive_size_error() {
        let input = r#"a buffer called "huge" is 9999999999999 bytes."#;
        let result = parse_input(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_buffer_with_variable_size() {
        let input = r#"a buffer called "dynamic" is config_size bytes."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "dynamic");
                assert!(matches!(size, Expr::Identifier(_)));
            }
            _ => panic!("Expected BufferDecl for buffer with variable size"),
        }
    }

    #[test]
    fn test_buffer_with_numeric_initializer() {
        // Without "bytes" keyword, this should be an initializer, not a size
        let input = r#"a buffer called "data" is 42."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::VarDecl { name, var_type, value } => {
                assert_eq!(name, "data");
                assert_eq!(var_type, &Some(Type::Buffer));
                assert!(matches!(value, Some(Expr::IntegerLit(42))));
            }
            _ => panic!("Expected VarDecl for buffer with numeric initializer"),
        }
    }

    #[test]
    fn test_buffer_without_initializer_warning() {
        let input = r#"a buffer called "empty_buf"."#;
        let result = parse_input(input);
        assert!(result.is_ok());
        let program = result.unwrap();
        assert_eq!(program.statements.len(), 1);
        match &program.statements[0] {
            Statement::BufferDecl { name, size } => {
                assert_eq!(name, "empty_buf");
                assert!(matches!(size, Expr::IntegerLit(0)));
            }
            _ => panic!("Expected BufferDecl for uninitialized buffer"),
        }
        // Note: Warning should be emitted to stderr during parsing
    }
}
