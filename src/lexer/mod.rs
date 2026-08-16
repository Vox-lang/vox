use std::iter::Peekable;
use std::str::Chars;

mod tokens;
pub use tokens::Token;

/// Whether a character may continue a bare identifier (`[A-Za-z0-9_]`).
/// Used by the possessive rule (plan §5) to decide what counts as a
/// "non-identifier character" following the `s` of `'s`. Note this is the
/// lexical identifier class from the plan (`[A-Za-z_][A-Za-z0-9_]*`), which
/// intentionally excludes `-` even though `read_word` admits `-` as a word
/// character for keywords like `bit-and`.
fn is_ident_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}


#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: Token,
    pub line: usize,
    pub column: usize,
}

pub struct Lexer<'a> {
    input: Peekable<Chars<'a>>,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer {
            input: input.chars().peekable(),
            line: 1,
            column: 1,
        }
    }
    
    fn advance(&mut self) -> Option<char> {
        let ch = self.input.next();
        if let Some(c) = ch {
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
        ch
    }
    
    fn peek(&mut self) -> Option<&char> {
        self.input.peek()
    }
    
    fn skip_whitespace(&mut self) {
        while let Some(&ch) = self.peek() {
            if ch == ' ' || ch == '\t' || ch == '\r' {
                self.advance();
            } else {
                break;
            }
        }
    }
    
    /// Skip a comment (content inside parentheses), handling nested parens
    fn skip_comment(&mut self) {
        let mut depth = 1;
        while depth > 0 {
            match self.advance() {
                Some('(') => depth += 1,
                Some(')') => depth -= 1,
                None => break, // EOF, stop
                _ => {} // Skip all other characters
            }
        }
    }
    
    fn read_string(&mut self) -> String {
        let mut result = String::new();
        while let Some(&ch) = self.peek() {
            if ch == '"' {
                self.advance();
                break;
            } else if ch == '\\' {
                self.advance();
                if let Some(&escaped) = self.peek() {
                    match escaped {
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        'r' => result.push('\r'),
                        '\\' => result.push('\\'),
                        '"' => result.push('"'),
                        _ => result.push(escaped),
                    }
                    self.advance();
                }
            } else {
                result.push(ch);
                self.advance();
            }
        }
        result
    }
    
    fn read_single_quoted_string(&mut self) -> String {
        let mut result = String::new();
        while let Some(&ch) = self.peek() {
            if ch == '\'' {
                self.advance();
                break;
            } else if ch == '\\' {
                self.advance();
                if let Some(&escaped) = self.peek() {
                    match escaped {
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        'r' => result.push('\r'),
                        '\\' => result.push('\\'),
                        '\'' => result.push('\''),
                        _ => result.push(escaped),
                    }
                    self.advance();
                }
            } else {
                result.push(ch);
                self.advance();
            }
        }
        result
    }
    
    fn is_char_literal(&self) -> bool {
        // Check if this is a character literal: 'X' (single char followed by closing quote)
        let mut input = self.input.clone();
        
        // Check for escape sequence or single character
        if let Some(&first) = input.peek() {
            input.next();
            if first == '\\' {
                // Escape sequence: need one more char then closing quote
                input.next(); // skip escaped char
                if let Some(&close) = input.peek() {
                    return close == '\'';
                }
            } else {
                // Single character: next should be closing quote
                if let Some(&close) = input.peek() {
                    return close == '\'';
                }
            }
        }
        false
    }
    
    fn is_single_quoted_identifier(&self) -> bool {
        // Check if the content after ' looks like a single-quoted identifier.
        // NOT a standalone possessive `'s` (an apostrophe followed by `s` and
        // a non-identifier char) — that is the bare-identifier possessive form
        // (`name's`) and must lex as Apostrophe + Identifier("s"), not as a
        // quoted identifier whose content happens to start with `s`.
        //
        // This lookahead is the bare-`'s` path. It is NOT subsumed by
        // `peek_is_possessive_s_after_quote` (plan §5), which handles the
        // *quoted*-identifier possessive `'my nums's` where the `'` is the
        // closing quote fused with `s`. Both rules are required; tests pin
        // each.
        let mut input = self.input.clone();

        // Check for possessive pattern: 's followed by non-letter
        if let Some(&first) = input.peek() {
            if first == 's' || first == 'S' {
                input.next();
                if let Some(&second) = input.peek() {
                    // If 's is followed by whitespace, punctuation, or end - it's possessive
                    if second.is_whitespace() || second == '.' || second == ',' || second == '\'' {
                        return false; // This is possessive 's, not a single-quoted identifier
                    }
                } else {
                    return false; // End of input after 's
                }
            }
        }

        // Reset and check for proper single-quoted identifier
        let mut input = self.input.clone();
        let mut count = 0;
        while let Some(&ch) = input.peek() {
            if ch == '\'' {
                // Found closing quote - it's a single-quoted identifier if we have content
                return count > 0;
            } else if ch == '\n' {
                return false; // Newline before closing quote
            }
            input.next();
            count += 1;
        }
        false
    }
    
    /// After a single-quoted identifier's closing quote has been consumed,
    /// detect the possessive marker of plan §5: an `s`/`S` *immediately*
    /// following the closing quote (no space) and itself followed by a
    /// non-identifier character. When this holds, the closing quote and the
    /// `s` together form the possessive; we emit an `Apostrophe` token here
    /// and let the main loop lex the `s` as `Identifier("s")`, producing the
    /// same token stream as the doubled-apostrophe form (`'name''s`).
    fn peek_is_possessive_s_after_quote(&mut self) -> bool {
        let mut input = self.input.clone();
        if let Some(&s) = input.peek() {
            if s == 's' || s == 'S' {
                input.next();
                return match input.peek() {
                    None => true, // EOF after 's
                    Some(&after) => !is_ident_continue(after),
                };
            }
        }
        false
    }

    fn read_number(&mut self, first: char) -> Token {
        // Check for hex (0x) or binary (0b) prefix
        if first == '0' {
            if let Some(&next) = self.peek() {
                if next == 'x' || next == 'X' {
                    self.advance(); // consume 'x'
                    return self.read_hex_number();
                } else if next == 'b' || next == 'B' {
                    self.advance(); // consume 'b'
                    return self.read_binary_number();
                }
            }
        }
        
        let mut num = String::from(first);
        let mut is_float = false;
        
        while let Some(&ch) = self.peek() {
            if ch.is_ascii_digit() {
                num.push(ch);
                self.advance();
            } else if ch == '.' && !is_float {
                // Check if next char after '.' is a digit (to distinguish from period)
                let mut chars = self.input.clone();
                chars.next(); // skip the '.'
                if let Some(&next) = chars.peek() {
                    if next.is_ascii_digit() {
                        is_float = true;
                        num.push(ch);
                        self.advance();
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        if is_float {
            Token::FloatLiteral(num.parse().unwrap_or(0.0))
        } else {
            Token::IntegerLiteral(num.parse().unwrap_or(0))
        }
    }
    
    fn read_hex_number(&mut self) -> Token {
        let mut num = String::new();
        while let Some(&ch) = self.peek() {
            if ch.is_ascii_hexdigit() {
                num.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        if num.is_empty() {
            Token::IntegerLiteral(0)
        } else {
            Token::IntegerLiteral(i64::from_str_radix(&num, 16).unwrap_or(0))
        }
    }
    
    fn read_binary_number(&mut self) -> Token {
        let mut num = String::new();
        while let Some(&ch) = self.peek() {
            if ch == '0' || ch == '1' {
                num.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        if num.is_empty() {
            Token::IntegerLiteral(0)
        } else {
            Token::IntegerLiteral(i64::from_str_radix(&num, 2).unwrap_or(0))
        }
    }
    
    fn read_char_literal(&mut self) -> Token {
        // Read a single character inside single quotes: 'A'
        let ch = match self.advance() {
            Some('\\') => {
                // Handle escape sequences
                match self.advance() {
                    Some('n') => '\n',
                    Some('t') => '\t',
                    Some('r') => '\r',
                    Some('\\') => '\\',
                    Some('\'') => '\'',
                    Some('0') => '\0',
                    Some(c) => c,
                    None => '\0',
                }
            }
            Some(c) => c,
            None => '\0',
        };
        
        // Consume closing quote
        if let Some(&'\'') = self.peek() {
            self.advance();
        }
        
        Token::IntegerLiteral(ch as i64)
    }
    
    fn read_word(&mut self, first: char) -> Token {
        let mut word = String::from(first);
        while let Some(&ch) = self.peek() {
            if ch.is_alphanumeric() || ch == '_' || ch == '-' {
                word.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        match word.to_lowercase().as_str() {
            "print" | "prints" | "display" | "show" => Token::Print,
            "set" | "store" | "assign" => Token::Set,
            "create" | "make" | "define" => Token::Create,
            "add" | "plus" => Token::Add,
            "subtract" | "minus" => Token::Subtract,
            "multiply" => Token::Multiply,
            "divide" => Token::Divide,
            "increment" => Token::Increment,
            "decrement" => Token::Decrement,
            "allocate" => Token::Allocate,
            "free" | "release" | "deallocate" => Token::Free,
            "append" | "push" => Token::Append,
            "copy" => Token::Copy,
            "clear" => Token::Clear,
            "if" => Token::If,
            "when" => Token::When,
            "then" => Token::Then,
            "else" => Token::Else,
            "but" => Token::But,
            "otherwise" => Token::Otherwise,
            "while" => Token::While,
            "for" => Token::For,
            "each" => Token::Each,
            "repeat" => Token::Repeat,
            "times" => Token::Times,
            "break" => Token::Break,
            "exit" | "quit" | "terminate" => Token::Exit,
            "continue" | "skip" => Token::Continue,
            "return" | "returns" | "give" => Token::Return,
            "to" => Token::To,
            "with" => Token::With,
            "called" | "named" => Token::Called,
            "modulo" | "mod" | "remainder" => Token::Modulo,
            "parse" => Token::Parse,
            "flag" => Token::Flag,
            "flags" => Token::Identifier("flags".to_string()),
            "required" => Token::Required,
            "default" => Token::Default,
            "is" | "it's" => Token::Is,
            "it" => Token::Identifier("it".to_string()),
            "are" | "they're" => Token::Are,
            "equals" | "equal" => Token::Equals,
            "greater" | "more" | "bigger" | "larger" => Token::Greater,
            "less" | "fewer" | "smaller" => Token::Less,
            "than" => Token::Than,
            "not" | "isn't" | "aren't" | "doesn't" | "don't" => Token::Not,
            "and" => Token::And,
            "or" => Token::Or,
            "from" | "starting" => Token::From,
            "up" => Token::To,
            "between" => Token::Between,
            "in" | "inside" | "within" => Token::In,
            "of" => Token::Of,
            "on" | "at" => Token::On,
            "the" => Token::The,
            "a" => Token::A,
            "an" => Token::An,
            "all" => Token::All,
            "number" | "numbers" => Token::Number,
            "float" | "decimal" | "real" => Token::Float,
            "int" | "integer" => Token::Int,
            "text" | "string" | "message" => Token::Text,
            "boolean" | "bool" => Token::Boolean,
            "list" | "array" | "collection" => Token::List,
            "map" | "dictionary" => Token::Map,
            "true" | "yes" => Token::True,
            "false" | "no" => Token::False,
            "even" => Token::Even,
            "odd" => Token::Odd,
            "positive" => Token::Positive,
            "negative" => Token::Negative,
            "zero" => Token::Zero,
            "empty" => Token::Empty,
            "nothing" | "null" | "nil" => Token::Nothing,
            // File I/O keywords
            "open" | "opened" => Token::Open,
            "read" => Token::Read,
            "write" => Token::Write,
            "close" | "closed" => Token::Close,
            "delete" | "remove" => Token::Delete,
            "exists" | "exist" => Token::Exists,
            "resize" | "reallocate" | "grow" | "shrink" => Token::Resize,
            "seek" => Token::Seek,
            "buffer" => Token::Buffer,
            "file" => Token::File,
            "bytes" => Token::Bytes,
            "size" | "length" => Token::Size,
            "capacity" => Token::Capacity,
            "into" => Token::Into,
            "reading" => Token::Reading,
            "writing" => Token::Writing,
            "appending" => Token::Appending,
            "standard" => Token::Standard,
            "input" => Token::Input,
            "error" => Token::Error,
            "auto" | "automatic" => Token::Auto,
            "enable" | "enabled" => Token::Enable,
            "disable" | "disabled" => Token::Disable,
            "descriptor" | "fd" => Token::Descriptor,
            "modified" => Token::Modified,
            "accessed" => Token::Accessed,
            "permissions" | "perms" => Token::Permissions,
            "readable" => Token::Readable,
            "writable" => Token::Writable,
            "full" => Token::Full,
            "first" => Token::First,
            "last" => Token::Last,
            "keys" => Token::Keys,
            "values" => Token::Values,
            "absolute" | "abs" => Token::Absolute,
            "sign" => Token::Sign,
            // Library system
            "see" | "import" | "include" | "require" => Token::See,
            "library" | "lib" => Token::Library,
            "version" | "ver" => Token::Version,
            // Arguments and environment
            "argument" | "arg" | "param" | "parameter" => Token::Argument,
            "arguments" | "args" | "params" | "parameters" => Token::Arguments,
            "environment" | "env" => Token::Environment,
            "variable" | "var" => Token::Variable,
            "count" => Token::Count,
            "raw" => Token::Raw,
            "treating" | "treat" => Token::Treating,
            // Time and Timers
            "wait" | "pause" => Token::Wait,
            "sleep" | "delay" => Token::Sleep,
            "timer" | "stopwatch" => Token::Timer,
            // start/begin/stop/finish are contextual, not reserved: the
            // parser claims them for a timer statement only when a name
            // operand follows; everywhere else they are ordinary
            // identifiers, normalized to lowercase like `start` always was.
            "start" => Token::Identifier("start".to_string()),
            "begin" => Token::Identifier("begin".to_string()),
            "stop" => Token::Identifier("stop".to_string()),
            "finish" => Token::Identifier("finish".to_string()),
            "get" | "fetch" | "retrieve" => Token::Get,
            "current" => Token::Current,
            "time" => Token::Time,
            "second" => Token::Second,
            "seconds" => Token::Seconds,
            "millisecond" => Token::Millisecond,
            "milliseconds" | "ms" => Token::Milliseconds,
            "duration" => Token::Duration,
            "elapsed" => Token::Elapsed,
            "hour" | "hours" => Token::Hour,
            "minute" | "minutes" => Token::Minute,
            "day" | "days" => Token::Day,
            "month" | "months" => Token::Month,
            "year" | "years" => Token::Year,
            "unix" | "unixtime" | "timestamp" => Token::Unix,
            "running" => Token::Running,
            "as" => Token::As,
            // Bitwise operations (only bit-* forms)
            "bit-and" => Token::BitAnd,
            "bit-or" => Token::BitOr,
            "bit-xor" => Token::BitXor,
            "bit-not" => Token::BitNot,
            "bit-shift-left" => Token::BitShiftLeft,
            "bit-shift-right" => Token::BitShiftRight,
            // Buffer/List access
            "byte" => Token::Byte,
            "element" => Token::Element,
            "without" => Token::Without,
            _ => Token::Identifier(word),
        }
    }
    
    pub fn tokenize(&mut self) -> Vec<TokenInfo> {
        let mut tokens = Vec::new();
        
        loop {
            self.skip_whitespace();
            let line = self.line;
            let column = self.column;
            
            let token = match self.advance() {
                None => Token::EOF,
                Some(ch) => match ch {
                    '\n' => {
                        // Check for paragraph break (double newline)
                        let mut newline_count = 1;
                        while let Some(&next) = self.peek() {
                            if next == '\n' {
                                self.advance();
                                newline_count += 1;
                            } else if next == ' ' || next == '\t' || next == '\r' {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                        if newline_count >= 2 {
                            Token::ParagraphBreak
                        } else {
                            Token::Newline
                        }
                    }
                    '.' => Token::Period,
                    ',' => Token::Comma,
                    ':' => Token::Colon,
                    '(' => {
                        // Parentheses are comments - skip until matching close paren
                        self.skip_comment();
                        continue;
                    }
                    ')' => continue, // Stray close paren, ignore
                    '[' => Token::OpenBracket,
                    ']' => Token::CloseBracket,
                    '{' => Token::OpenBrace,
                    '}' => Token::CloseBrace,
                    '-' => Token::Minus,
                    '\'' => {
                        // Check if this is a character literal ('A'),
                        // a single-quoted identifier, or an apostrophe
                        // (the bare-`'s` possessive marker).
                        if self.is_char_literal() {
                            self.read_char_literal()
                        } else if self.is_single_quoted_identifier() {
                            let content = self.read_single_quoted_string();
                            tokens.push(TokenInfo {
                                token: Token::Identifier(content),
                                line,
                                column,
                            });
                            // Plan §5: a closing identifier quote fused
                            // with a trailing `s` + non-identifier char is
                            // the possessive marker. Emit an Apostrophe;
                            // the `s` is lexed next as Identifier("s"),
                            // matching the `'name''s` doubled-apostrophe
                            // stream so the parser needs no new path.
                            if self.peek_is_possessive_s_after_quote() {
                                tokens.push(TokenInfo {
                                    token: Token::Apostrophe,
                                    line: self.line,
                                    column: self.column,
                                });
                            }
                            continue;
                        } else {
                            Token::Apostrophe
                        }
                    }
                    '"' => Token::StringLiteral(self.read_string()),
                    c if c.is_ascii_digit() => self.read_number(c),
                    c if c.is_alphabetic() || c == '_' => self.read_word(c),
                    _ => continue,
                }
            };
            
            let is_eof = token == Token::EOF;
            tokens.push(TokenInfo { token, line, column });
            
            if is_eof {
                break;
            }
        }

        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens_of(input: &str) -> Vec<Token> {
        let mut lexer = Lexer::new(input);
        lexer
            .tokenize()
            .into_iter()
            .map(|t| t.token)
            .filter(|t| *t != Token::EOF)
            .collect()
    }

    #[test]
    fn single_char_between_single_quotes_is_a_character_literal() {
        // Plan 270 §"The rule" item 3: exactly one character between single
        // quotes is a character literal, not a one-character identifier —
        // this is why single-character quoted identifiers do not exist.
        assert_eq!(tokens_of("'A'"), vec![Token::IntegerLiteral(65)]);
    }

    #[test]
    fn possessive_single_apostrophe_form_lexes_identifier_then_s() {
        // Plan 270 §5: `'name's` reads as the quoted identifier plus the
        // possessive marker, not `Unknown function: s`. `length` is the
        // reserved size/length property keyword (`Token::Size`), matching
        // the plan's own canonical example (`'total items's length`).
        assert_eq!(
            tokens_of("'my nums's length"),
            vec![
                Token::Identifier("my nums".to_string()),
                Token::Apostrophe,
                Token::Identifier("s".to_string()),
                Token::Size,
            ]
        );
    }

    #[test]
    fn possessive_doubled_apostrophe_form_lexes_identically() {
        // Plan 270 §5: `'name''s` is the pre-existing doubled-apostrophe
        // path and must produce the exact same token stream as the new
        // single-apostrophe possessive form, so the parser needs no new path.
        assert_eq!(
            tokens_of("'my nums''s length"),
            tokens_of("'my nums's length")
        );
    }

    #[test]
    fn underscore_prefix_is_preserved_in_identifier() {
        // Regression 1: `_str_eq` must lex as a single identifier with the
        // leading underscore intact, not as the bare name `str_eq`.
        assert_eq!(
            tokens_of("_str_eq"),
            vec![Token::Identifier("_str_eq".to_string())]
        );
        // Mid-word underscores continue to work.
        assert_eq!(
            tokens_of("my_helper"),
            vec![Token::Identifier("my_helper".to_string())]
        );
    }
}
