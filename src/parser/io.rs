use super::*;

impl Parser {
    pub(crate) fn parse_parse_flags(&mut self) -> Result<Statement, Box<CompileError>> {
        self.advance(); // consume parse
        self.skip_noise();

        if matches!(self.current(), Token::Flag) {
            self.advance();
            Ok(Statement::ParseFlags)
        } else if let Token::Identifier(id) = self.current().clone() {
            if id.eq_ignore_ascii_case("flags") || id.eq_ignore_ascii_case("flag") {
                self.advance();
                Ok(Statement::ParseFlags)
            } else {
                Err(self.err("Expected 'flag' or 'flags' after 'parse'"))
            }
        } else {
            Err(self.err("Expected 'flag' or 'flags' after 'parse'"))
        }
    }

    pub(crate) fn parse_flag_schema_decl(&mut self) -> Result<Statement, Box<CompileError>> {
        self.expect(&Token::Flag);
        self.skip_noise();

        self.expect(&Token::Called);
        self.skip_noise();

        let name = self.parse_name()?;

        self.skip_noise();
        self.expect(&Token::Is);
        self.skip_noise();

        // Flag aliases are string literals (plan 270 §9): `-n`/`--number`
        // are data, not names. The flag *name* above is an identifier.
        let short = match self.current().clone() {
            Token::StringLiteral(v) => {
                self.advance();
                v
            }
            _ => return Err(self.err("Expected short flag alias string like '-n'")),
        };

        self.skip_noise();
        self.expect(&Token::Or);
        self.skip_noise();

        let long = match self.current().clone() {
            Token::StringLiteral(v) => {
                self.advance();
                v
            }
            _ => return Err(self.err("Expected long flag alias string like '--number'")),
        };

        self.skip_noise();
        self.expect(&Token::Comma);
        self.skip_noise();

        // optional "it"
        if let Token::Identifier(id) = self.current().clone() {
            if id.eq_ignore_ascii_case("it") {
                self.advance();
                self.skip_noise();
            }
        }

        self.expect(&Token::Is);
        self.skip_noise();

        // optional article before type
        if matches!(self.current(), Token::A | Token::An | Token::The) {
            self.advance();
            self.skip_noise();
        }

        let value_type = match self.current() {
            Token::Boolean => {
                self.advance();
                FlagValueType::Boolean
            }
            Token::Number | Token::Int => {
                self.advance();
                FlagValueType::Number
            }
            Token::Text => {
                self.advance();
                FlagValueType::Text
            }
            _ => return Err(self.err("Expected flag value type: boolean, number, or text")),
        };

        let mut required = false;
        let mut default = None;

        loop {
            self.skip_noise();
            match self.current() {
                Token::And => {
                    self.advance();
                    self.skip_noise();
                    if self.expect(&Token::Is) {
                        self.skip_noise();
                    }

                    if self.expect(&Token::Required) {
                        required = true;
                    } else {
                        return Err(self.err("Expected 'required' after 'and is' in flag schema"));
                    }
                }
                Token::With => {
                    self.advance();
                    self.skip_noise();
                    if !self.expect(&Token::Default) {
                        return Err(self.err("Expected 'default' after 'with' in flag schema"));
                    }
                    self.skip_noise();
                    default = Some(self.parse_expression()?);
                }
                _ => break,
            }
        }

        Ok(Statement::FlagSchemaDecl {
            name,
            short,
            long,
            value_type,
            required,
            default,
        })
    }

    pub(crate) fn parse_file_open(&mut self) -> Result<Statement, Box<CompileError>> {
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
        let mut path_info: Option<PathInfo> = None;
        
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
                        Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
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
                    if let Some((variable, collection, treating)) = self.try_parse_each_from(false)? {
                        // `open` takes one path, so a grid of two or more
                        // `each` clauses is an arity error (plan 320 rule 12).
                        self.skip_noise();
                        if *self.current() == Token::And {
                            return Err(self.one_slot_arity_error("open"));
                        }
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

    pub(crate) fn parse_file_read(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Read from <source> into <buffer>"
        // "Read line from <source> into <buffer>"
        self.advance(); // consume 'read'
        self.skip_noise();

        // Optional line mode: "read line from ..."
        let mut line_mode = false;
        if let Token::Identifier(s) = self.current().clone() {
            if s.eq_ignore_ascii_case("line") {
                line_mode = true;
                self.advance();
                self.skip_noise();
            }
        }
        
        // Expect "from"
        if !self.expect(&Token::From) {
            let expected = if line_mode {
                "'from' after 'read line'"
            } else {
                "'from' after 'read'"
            };
            return Err(self.err_expected(expected, self.current()));
        }
        self.skip_noise();

        // Optional article before source handle/path: "from the source"
        if matches!(self.current(), Token::The | Token::A | Token::An) {
            self.advance();
            self.skip_noise();
        }
        
        // Parse source: "standard input" or file name
        let source = if *self.current() == Token::Standard {
            self.advance();
            self.skip_noise();
            self.expect(&Token::Input);
            "stdin".to_string()
        } else {
            match self.current().clone() {
                Token::StringLiteral(s) => return Err(self.err_string_as_name(&s)),
                Token::Identifier(n) => { self.advance(); n }
                Token::Input => { self.advance(); "input".to_string() }
                _ => return Err(self.err_expected("file name or 'standard input' after 'from'", self.current())),
            }
        };

        self.skip_noise();

        // Expect "into"
        if !self.expect(&Token::Into) {
            return Err(self.err_expected("'into' after read source", self.current()));
        }
        self.skip_noise();

        // Optional article before destination buffer: "into the content"
        if matches!(self.current(), Token::The | Token::A | Token::An) {
            self.advance();
            self.skip_noise();
        }

        // Get buffer name
        let buffer = self.parse_name()?;
        
        if line_mode {
            Ok(Statement::FileReadLine { source, buffer })
        } else {
            Ok(Statement::FileRead { source, buffer })
        }
    }

    pub(crate) fn parse_file_seek(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Seek <file> to line <expr>"
        // "Seek <file> to byte <expr>"
        self.advance(); // consume 'seek'
        self.skip_noise();

        let file = self.parse_name().or_else(|e| {
            if matches!(self.current(), Token::StringLiteral(_)) {
                Err(e)
            } else {
                Err(self.err_expected("file name after 'seek'", self.current()))
            }
        })?;

        self.skip_noise();
        if !self.expect(&Token::To) {
            return Err(self.err_expected("'to' after file name in seek", self.current()));
        }
        self.skip_noise();

        let mode = match self.current().clone() {
            Token::Identifier(s) => {
                let lower = s.to_lowercase();
                if lower == "line" || lower == "lines" {
                    self.advance();
                    "line"
                } else if lower == "byte" || lower == "bytes" {
                    self.advance();
                    "byte"
                } else {
                    return Err(self.err(
                        "Expected 'line' or 'byte' after 'seek <file> to'\n  \
                         Syntax: Seek source to line 1.\n  \
                         Also valid: Seek source to byte 1."
                    ));
                }
            }
            Token::Byte | Token::Bytes => {
                self.advance();
                "byte"
            }
            _ => {
                return Err(self.err(
                    "Expected 'line' or 'byte' after 'seek <file> to'\n  \
                     Syntax: Seek source to line 1."
                ))
            }
        };

        self.skip_noise();
        let position = self.parse_expression()?;

        if mode == "line" {
            Ok(Statement::FileSeekLine {
                file,
                line: position,
            })
        } else {
            Ok(Statement::FileSeekByte {
                file,
                byte: position,
            })
        }
    }

    pub(crate) fn parse_file_write(&mut self) -> Result<Statement, Box<CompileError>> {
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
                        Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
                        Token::File => { self.advance(); "File".to_string() }
                        _ => return Err(self.err("Expected file name after 'to'")),
                    };

                    return Ok(Statement::FileWriteNewline { file });
                }
            }
        }
        
        // Parse value to write (string literal or identifier)
        let mut value = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
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
                Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
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
                Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
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
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            Token::File => { self.advance(); "File".to_string() }
            _ => return Err(self.err_expected("file name after 'to'", self.current())),
        };

        Ok(Statement::FileWrite { file, value })
    }

    pub(crate) fn parse_file_close(&mut self) -> Result<Statement, Box<CompileError>> {
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
            Token::StringLiteral(n) => return Err(self.err_string_as_name(&n)),
            Token::File => { self.advance(); "File".to_string() }
            Token::Input => { self.advance(); "input".to_string() }
            _ => return Err(self.err_expected("file name after 'close'", self.current())),
        };
        
        Ok(Statement::FileClose { file })
    }

    pub(crate) fn parse_file_delete(&mut self) -> Result<Statement, Box<CompileError>> {
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

    pub(crate) fn parse_rmdir(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Delete/Remove the directory <path>"
        self.advance(); // consume 'delete'/'remove'
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        // Expect "directory"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("directory") {
                return Err(self.err(&format!("Expected 'directory' after 'the', got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'directory' after 'the'"));
        }
        self.skip_noise();

        // Skip optional "called"
        if matches!(self.current(), Token::Called) {
            self.advance();
            self.skip_noise();
        }

        // Get path
        let path = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            _ => return Err(self.err("Expected a path (string or variable) after 'directory'")),
        };

        Ok(Statement::Rmdir { path })
    }

    pub(crate) fn parse_mount(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Mount <source> at <target> with type <fstype> [with options <options>]"
        self.advance(); // consume 'mount'
        self.skip_noise();

        let source = self.parse_path_like_expr("after 'mount'")?;
        self.skip_noise();

        // Expect "at" (lexes as Token::On - 'at'/'on' are synonyms)
        if !matches!(self.current(), Token::On) {
            return Err(self.err(&format!("Expected 'at' after mount source, got {:?}", self.current())));
        }
        self.advance();
        self.skip_noise();

        let target = self.parse_path_like_expr("after 'at'")?;
        self.skip_noise();

        // Expect "with"
        if !matches!(self.current(), Token::With) {
            return Err(self.err("Expected 'with type' after mount target"));
        }
        self.advance();
        self.skip_noise();

        // Expect "type"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("type") {
                return Err(self.err(&format!("Expected 'type' after 'with', got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'type' after 'with'"));
        }
        self.skip_noise();

        let fstype = self.parse_path_like_expr("after 'type'")?;
        self.skip_noise();

        // Optional "with options <options>"
        let mut options = None;
        if matches!(self.current(), Token::With) {
            self.advance();
            self.skip_noise();

            if let Token::Identifier(ref id) = self.current() {
                if !id.eq_ignore_ascii_case("options") {
                    return Err(self.err(&format!("Expected 'options' after 'with', got '{}'", id)));
                }
                self.advance();
            } else {
                return Err(self.err("Expected 'options' after 'with'"));
            }
            self.skip_noise();

            options = Some(self.parse_path_like_expr("after 'options'")?);
        }

        Ok(Statement::Mount { source, target, fstype, options })
    }

    pub(crate) fn parse_unmount(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Unmount <target> [lazily]"
        self.advance(); // consume 'unmount'/'umount'
        self.skip_noise();

        // Skip optional "the"
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }

        let target = self.parse_path_like_expr("after 'unmount'")?;
        self.skip_noise();

        // Optional "lazily" - MNT_DETACH, succeeds even while the mount is busy
        let mut lazy = false;
        if let Token::Identifier(ref id) = self.current() {
            if id.eq_ignore_ascii_case("lazily") {
                lazy = true;
                self.advance();
                self.skip_noise();
            }
        }

        Ok(Statement::Unmount { target, lazy })
    }

    pub(crate) fn parse_pivot_root(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Pivot root to <new_root> with old root <put_old>"
        self.advance(); // consume 'pivot'
        self.skip_noise();

        // Expect "root"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("root") {
                return Err(self.err(&format!("Expected 'root' after 'pivot', got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'root' after 'pivot'"));
        }
        self.skip_noise();

        // Expect "to"
        if !matches!(self.current(), Token::To) {
            return Err(self.err("Expected 'to' after 'pivot root'"));
        }
        self.advance();
        self.skip_noise();

        let new_root = self.parse_path_like_expr("after 'pivot root to'")?;
        self.skip_noise();

        // Expect "with"
        if !matches!(self.current(), Token::With) {
            return Err(self.err("Expected 'with old root' after pivot root target"));
        }
        self.advance();
        self.skip_noise();

        // Expect "old"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("old") {
                return Err(self.err(&format!("Expected 'old' after 'with', got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'old' after 'with'"));
        }
        self.skip_noise();

        // Expect "root"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("root") {
                return Err(self.err(&format!("Expected 'root' after 'old', got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'root' after 'old'"));
        }
        self.skip_noise();

        let put_old = self.parse_path_like_expr("after 'with old root'")?;

        Ok(Statement::PivotRoot { new_root, put_old })
    }

    pub(crate) fn parse_execute(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Execute <path> with arguments [<list>]"
        self.advance(); // consume 'execute'
        self.skip_noise();

        let path = self.parse_path_like_expr("after 'execute'")?;
        self.skip_noise();

        // "with arguments <list>" is optional: a bare `Execute "/bin/sh".`
        // gets argv = [path, NULL] (argc = 1), which is what the kernel
        // expects for an argumentless program.
        if !matches!(self.current(), Token::With) {
            return Ok(Statement::Execute {
                path,
                args: Expr::ListLit { elements: vec![] },
            });
        }
        self.advance();
        self.skip_noise();

        // Expect "arguments" (already a dedicated keyword: Token::Arguments)
        if !matches!(self.current(), Token::Arguments) {
            return Err(self.err("Expected 'arguments' after 'with'"));
        }
        self.advance();
        self.skip_noise();

        // The arguments are either a bracketed list literal (argv is built
        // at compile time) or a list variable (argv is built at runtime by
        // _list_to_argv from the list's length - see codegen).
        let args = if matches!(self.current(), Token::OpenBracket) {
            // parse_primary() handles '[' natively with no ambiguity
            // concerns (unlike the string-literal case elsewhere here).
            self.parse_primary()?
        } else {
            self.parse_path_like_expr("after 'arguments'")?
        };

        Ok(Statement::Execute { path, args })
    }

    // Shared helper: parse a simple path-like expression - a string literal,
    // a bare identifier, or "the <identifier>". Deliberately does NOT go
    // through parse_primary(), which has function-call lookahead rules
    // (e.g. "string" followed by 'to') that can swallow trailing keywords
    // like 'at'/'to'/'with' that these filesystem statements rely on.
    pub(crate) fn parse_path_like_expr(&mut self, context: &str) -> Result<Expr, Box<CompileError>> {
        if *self.current() == Token::The {
            self.advance();
            self.skip_noise();
        }
        match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); Ok(self.string_value_expr(s)) }
            Token::Identifier(n) => { self.advance(); Ok(Expr::Identifier(n)) }
            _ => Err(self.err(&format!("Expected a path (string or variable) {}", context))),
        }
    }

    pub(crate) fn parse_mkdir(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Create a directory called <path>"
        self.advance(); // consume 'create'
        self.skip_noise();

        // Skip optional "a"
        if *self.current() == Token::A {
            self.advance();
            self.skip_noise();
        }

        // Expect "directory"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("directory") {
                return Err(self.err(&format!(
                    "Expected 'directory' after 'create a', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'directory' after 'create a'"));
        }
        self.skip_noise();

        // Expect "called"
        if !matches!(self.current(), Token::Called) {
            return Err(self.err("Expected 'called' after directory"));
        }
        self.advance();
        self.skip_noise();

        // Get path
        let path = self.parse_primary()?;

        Ok(Statement::Mkdir { path })
    }

    pub(crate) fn parse_send_signal(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Send signal <N-expr> to process <pid-expr>."
        //   - `child` is accepted as an alias for `process`, mirroring
        //     `reap process/child`.
        self.advance(); // consume 'send'
        self.skip_noise();

        // Expect "signal"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("signal") {
                return Err(self.err(&format!(
                    "Expected 'signal' after 'send', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'signal' after 'send'"));
        }
        self.skip_noise();

        let signal = self.parse_primary()?;
        self.skip_noise();

        // Expect "to"
        if !matches!(self.current(), Token::To) {
            return Err(self.err(&format!(
                "Expected 'to' after the signal value, got {:?}",
                self.current()
            )));
        }
        self.advance();
        self.skip_noise();

        // Optional "process" / "child" qualifier (either accepted).
        if let Token::Identifier(ref id) = self.current() {
            if id.eq_ignore_ascii_case("process") || id.eq_ignore_ascii_case("child") {
                self.advance();
                self.skip_noise();
            }
        }

        let pid = self.parse_primary()?;

        Ok(Statement::SendSignal { signal, pid })
    }

    pub(crate) fn parse_chdir(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Change directory to <path>"
        self.advance(); // consume 'change'
        self.skip_noise();

        // Expect "directory"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("directory") {
                return Err(self.err(&format!(
                    "Expected 'directory' after 'change', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'directory' after 'change'"));
        }
        self.skip_noise();

        // Expect "to"
        if !matches!(self.current(), Token::To) {
            return Err(self.err("Expected 'to' after directory"));
        }
        self.advance();
        self.skip_noise();

        // Get path
        let path = self.parse_primary()?;

        Ok(Statement::Chdir { path })
    }

    pub(crate) fn parse_symlink(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Create symbolic link from <target> to <linkpath>"
        self.advance(); // consume 'create'
        self.skip_noise();

        // Skip optional "a"
        if *self.current() == Token::A {
            self.advance();
            self.skip_noise();
        }

        // Expect "symbolic"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("symbolic") {
                return Err(self.err(&format!(
                    "Expected 'symbolic' after 'create a', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'symbolic' after 'create a'"));
        }
        self.skip_noise();

        // Expect "link"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("link") {
                return Err(self.err(&format!(
                    "Expected 'link' after 'symbolic', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'link' after 'symbolic'"));
        }
        self.skip_noise();

        // Expect "from"
        if !matches!(self.current(), Token::From) {
            return Err(self.err("Expected 'from' after link"));
        }
        self.advance();
        self.skip_noise();

        // Get target as a simple path (string literal or identifier).
        // NOTE: we deliberately don't call parse_primary() here - it treats
        // "string" followed by 'to' as a function-call expression, which
        // would swallow our 'to' keyword and the linkpath.
        let target = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            _ => return Err(self.err("Expected a path (string or variable) after 'from'")),
        };
        self.skip_noise();

        // Expect "to"
        if !matches!(self.current(), Token::To) {
            return Err(self.err("Expected 'to' after target path"));
        }
        self.advance();
        self.skip_noise();

        // Get linkpath
        let linkpath = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            _ => return Err(self.err("Expected a path (string or variable) after 'to'")),
        };

        Ok(Statement::Symlink { target, linkpath })
    }

    pub(crate) fn parse_mknod(&mut self) -> Result<Statement, Box<CompileError>> {
        // "Create a device node called <path> with type <"c"|"b"> major <n> minor <n>"
        self.advance(); // consume 'create'
        self.skip_noise();

        // Skip optional "a"
        if *self.current() == Token::A {
            self.advance();
            self.skip_noise();
        }

        // Expect "device"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("device") {
                return Err(self.err(&format!(
                    "Expected 'device' after 'create a', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'device' after 'create a'"));
        }
        self.skip_noise();

        // Expect "node"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("node") {
                return Err(self.err(&format!(
                    "Expected 'node' after 'device', got '{}'",
                    id
                )));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'node' after 'device'"));
        }
        self.skip_noise();

        // Expect "called"
        if !matches!(self.current(), Token::Called) {
            return Err(self.err("Expected 'called' after 'device node'"));
        }
        self.advance();
        self.skip_noise();

        // Get path
        let path = match self.current().clone() {
            Token::StringLiteral(s) => { self.advance(); self.string_value_expr(s) }
            Token::Identifier(n) => { self.advance(); Expr::Identifier(n) }
            _ => return Err(self.err("Expected a path (string or variable) after 'called'")),
        };
        self.skip_noise();

        // Expect "with"
        if !matches!(self.current(), Token::With) {
            return Err(self.err("Expected 'with' after device node path"));
        }
        self.advance();
        self.skip_noise();

        // Expect "type"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("type") {
                return Err(self.err(&format!("Expected 'type' after 'with', got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'type' after 'with'"));
        }
        self.skip_noise();

        // Get device type: "c" or "b"
        let node_type = match self.current().clone() {
            Token::StringLiteral(s) => {
                self.advance();
                match s.as_str() {
                    "c" => DeviceNodeType::Character,
                    "b" => DeviceNodeType::Block,
                    "p" => DeviceNodeType::Fifo,
                    _ => return Err(self.err(&format!(
                        "Invalid device type '{}' - expected \"c\" (character), \"b\" (block), or \"p\" (FIFO)",
                        s
                    ))),
                }
            }
            _ => return Err(self.err("Expected device type \"c\", \"b\", or \"p\" after 'type'")),
        };
        self.skip_noise();

        // Expect "major"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("major") {
                return Err(self.err(&format!("Expected 'major' after device type, got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'major' after device type"));
        }
        self.skip_noise();

        let major = self.parse_primary()?;
        self.skip_noise();

        // Expect "minor"
        if let Token::Identifier(ref id) = self.current() {
            if !id.eq_ignore_ascii_case("minor") {
                return Err(self.err(&format!("Expected 'minor' after major number, got '{}'", id)));
            }
            self.advance();
        } else {
            return Err(self.err("Expected 'minor' after major number"));
        }
        self.skip_noise();

        let minor = self.parse_primary()?;

        Ok(Statement::Mknod { path, node_type, major, minor })
    }

}
