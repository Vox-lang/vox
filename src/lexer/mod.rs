use std::iter::Peekable;
use std::str::Chars;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Actions
    Print, Set, Create, Add, Subtract, Multiply, Divide, Increment, Decrement,
    Call, Allocate, Free, Append,
    
    // File I/O Actions
    Open, Read, Write, Close, Delete, Exists, Resize,
    
    // Control Flow
    If, When, Then, Else, But, Otherwise, While, Until, For, Each, Every,
    Loop, Repeat, Times, Break, Continue, Return, Exit,
    
    // Functions
    With, Called, Modulo,
    
    // Comparisons
    Is, Are, Equals, Equal, Greater, Less, Than, Not, And, Or,
    
    // Range/Collection
    From, To, Between, Through, In, Of, On, The, A, An, All, By, Treating,
    
    // Types
    Number, Float, Int, Text, Boolean, List, True, False,
    
    // File I/O Types and Keywords
    Buffer, File, Bytes, Size, Into, Reading, Writing, Appending, Standard, Input,
    
    // Properties
    Even, Odd, Positive, Negative, Zero, Empty,
    
    // Property Access
    Apostrophe, Capacity, Descriptor, Modified, Accessed, Permissions,
    Readable, Writable, Full, First, Last, Absolute, Sign,
    
    // Error Handling
    Error, Stderr, Auto, Catching, Enable, Disable,
    
    // Library System
    See, Library, Version,
    
    // Arguments and Environment
    Argument, Arguments, Environment, Variable, Count,
    
    // Time and Timers
    Wait, Sleep, Timer, Stop, Begin, Finish,
    Get, Current, Time, Second, Seconds, Millisecond, Milliseconds,
    Duration, Elapsed, Hour, Minute, Day, Month, Year, Unix,
    Running, As,
    
    // Bitwise Operations (only bit-* forms, no standalone keywords)
    BitAnd, BitOr, BitXor, BitNot, BitShiftLeft, BitShiftRight,
    
    // Buffer/List Access
    Byte, Element, Without,
    
    // Literals
    IntegerLiteral(i64),
    FloatLiteral(f64),
    StringLiteral(String),
    
    // Identifiers
    Identifier(String),
    
    // Punctuation
    Period, Comma, Colon, OpenBracket, CloseBracket, Minus,
    
    // Special
    Newline, ParagraphBreak, EOF,
}

impl Token {
    /// Check if a string matches any reserved keyword.
    /// Returns the canonical keyword name if it matches.
    pub fn string_is_keyword(s: &str) -> Option<&'static str> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            // Actions
            "print" | "say" | "display" | "output" | "show" => Some("print"),
            "set" | "assign" | "let" | "make" | "put" => Some("set"),
            "create" | "declare" | "define" => Some("create"),
            "add" | "plus" => Some("add"),
            "subtract" | "minus" => Some("subtract"),
            "multiply" | "times" => Some("multiply"),
            "divide" | "over" => Some("divide"),
            "increment" | "increase" => Some("increment"),
            "decrement" | "decrease" => Some("decrement"),
            "call" | "invoke" | "run" | "execute" => Some("call"),
            "allocate" => Some("allocate"),
            "free" | "deallocate" | "release" => Some("free"),
            "modulo" | "mod" | "remainder" => Some("modulo"),
            // Control flow
            "if" => Some("if"),
            "when" => Some("when"),
            "then" => Some("then"),
            "else" => Some("else"),
            "but" => Some("but"),
            "otherwise" => Some("otherwise"),
            "while" => Some("while"),
            "until" => Some("until"),
            "for" => Some("for"),
            "each" => Some("each"),
            "every" => Some("every"),
            "loop" | "repeat" => Some("loop"),
            "break" => Some("break"),
            "stop" => Some("stop"),
            "continue" | "skip" => Some("continue"),
            "return" | "give" | "respond" | "reply" => Some("return"),
            "exit" | "quit" | "terminate" | "end" | "halt" | "abort" => Some("exit"),
            // Functions
            "with" | "using" | "given" | "taking" => Some("with"),
            "called" | "named" => Some("called"),
            // Comparisons
            "is" | "equals" | "equal" | "==" => Some("is"),
            "are" => Some("are"),
            "greater" | "more" | "larger" | "bigger" | "higher" | "above" => Some("greater"),
            "less" | "smaller" | "lower" | "below" | "fewer" => Some("less"),
            "than" => Some("than"),
            "not" | "!" => Some("not"),
            "and" | "&&" => Some("and"),
            "or" | "||" => Some("or"),
            // Range/Collection
            "from" | "starting" => Some("from"),
            "to" | "up" => Some("to"),
            "between" => Some("between"),
            "through" => Some("through"),
            "in" | "inside" | "within" => Some("in"),
            "of" => Some("of"),
            "on" | "at" => Some("on"),
            "the" => Some("the"),
            "a" => Some("a"),
            "an" => Some("an"),
            "all" => Some("all"),
            "by" => Some("by"),
            "treating" | "treat" => Some("treating"),
            // Types
            "number" | "numbers" => Some("number"),
            "float" | "decimal" | "real" => Some("float"),
            "int" | "integer" => Some("int"),
            "text" | "string" | "message" => Some("text"),
            "boolean" | "bool" | "flag" => Some("boolean"),
            "list" | "array" | "collection" => Some("list"),
            "true" | "yes" => Some("true"),
            "false" | "no" => Some("false"),
            // File I/O
            "buffer" => Some("buffer"),
            "file" => Some("file"),
            "bytes" => Some("bytes"),
            "byte" => Some("byte"),
            "size" | "length" => Some("size"),
            "into" => Some("into"),
            "reading" => Some("reading"),
            "writing" => Some("writing"),
            "appending" => Some("appending"),
            "standard" => Some("standard"),
            "input" => Some("input"),
            "open" | "opened" => Some("open"),
            "read" => Some("read"),
            "write" => Some("write"),
            "close" | "closed" => Some("close"),
            "delete" | "remove" => Some("delete"),
            "exists" | "exist" => Some("exists"),
            "resize" | "reallocate" | "grow" | "shrink" => Some("resize"),
            // Properties
            "even" => Some("even"),
            "odd" => Some("odd"),
            "positive" => Some("positive"),
            "negative" => Some("negative"),
            "zero" => Some("zero"),
            "empty" | "nothing" | "null" | "nil" => Some("empty"),
            "capacity" => Some("capacity"),
            "descriptor" | "fd" => Some("descriptor"),
            "modified" => Some("modified"),
            "accessed" => Some("accessed"),
            "permissions" | "perms" => Some("permissions"),
            "readable" => Some("readable"),
            "writable" => Some("writable"),
            "full" => Some("full"),
            "first" => Some("first"),
            "last" => Some("last"),
            "absolute" | "abs" => Some("absolute"),
            "sign" => Some("sign"),
            // Error handling
            "error" => Some("error"),
            "stderr" => Some("stderr"),
            "auto" | "automatic" => Some("auto"),
            "catching" => Some("catching"),
            "enable" | "enabled" => Some("enable"),
            "disable" | "disabled" => Some("disable"),
            // Library
            "see" | "import" | "include" | "require" => Some("see"),
            "library" | "lib" => Some("library"),
            "version" | "ver" => Some("version"),
            // Arguments/Environment
            "argument" | "arg" | "param" | "parameter" => Some("argument"),
            "arguments" | "args" | "params" | "parameters" => Some("arguments"),
            "environment" | "env" => Some("environment"),
            "variable" | "var" => Some("variable"),
            "count" => Some("count"),
            // Time and timers
            "wait" | "pause" => Some("wait"),
            "sleep" | "delay" => Some("sleep"),
            "timer" | "stopwatch" => Some("timer"),
            "begin" => Some("begin"),
            "finish" => Some("stop"),
            "get" | "fetch" | "retrieve" => Some("get"),
            "current" => Some("current"),
            "time" => Some("time"),
            "second" => Some("second"),
            "seconds" => Some("seconds"),
            "millisecond" => Some("millisecond"),
            "milliseconds" | "ms" => Some("milliseconds"),
            "duration" => Some("duration"),
            "elapsed" => Some("elapsed"),
            "hour" | "hours" => Some("hour"),
            "minute" | "minutes" => Some("minute"),
            "day" | "days" => Some("day"),
            "month" | "months" => Some("month"),
            "year" | "years" => Some("year"),
            "unix" | "unixtime" | "timestamp" => Some("unix"),
            "running" => Some("running"),
            "as" => Some("as"),
            _ => None,
        }
    }
    
    /// Returns the keyword name if this token is a reserved keyword.
    /// Returns None for identifiers, literals, punctuation, and special tokens.
    pub fn as_keyword(&self) -> Option<&'static str> {
        match self {
            // Actions
            Token::Print => Some("print"),
            Token::Set => Some("set"),
            Token::Create => Some("create"),
            Token::Add => Some("add"),
            Token::Subtract => Some("subtract"),
            Token::Multiply => Some("multiply"),
            Token::Divide => Some("divide"),
            Token::Increment => Some("increment"),
            Token::Decrement => Some("decrement"),
            Token::Call => Some("call"),
            Token::Allocate => Some("allocate"),
            Token::Free => Some("free"),
            Token::Append => Some("append"),
            // File I/O Actions
            Token::Open => Some("open"),
            Token::Read => Some("read"),
            Token::Write => Some("write"),
            Token::Close => Some("close"),
            Token::Delete => Some("delete"),
            Token::Exists => Some("exists"),
            Token::Resize => Some("resize"),
            // Control Flow
            Token::If => Some("if"),
            Token::When => Some("when"),
            Token::Then => Some("then"),
            Token::Else => Some("else"),
            Token::But => Some("but"),
            Token::Otherwise => Some("otherwise"),
            Token::While => Some("while"),
            Token::Until => Some("until"),
            Token::For => Some("for"),
            Token::Each => Some("each"),
            Token::Every => Some("every"),
            Token::Loop => Some("loop"),
            Token::Repeat => Some("repeat"),
            Token::Times => Some("times"),
            Token::Break => Some("break"),
            Token::Continue => Some("continue"),
            Token::Return => Some("return"),
            Token::Exit => Some("exit"),
            // Functions
            Token::With => Some("with"),
            Token::Called => Some("called"),
            Token::Modulo => Some("modulo"),
            // Comparisons
            Token::Is => Some("is"),
            Token::Are => Some("are"),
            Token::Equals => Some("equals"),
            Token::Equal => Some("equal"),
            Token::Greater => Some("greater"),
            Token::Less => Some("less"),
            Token::Than => Some("than"),
            Token::Not => Some("not"),
            Token::And => Some("and"),
            Token::Or => Some("or"),
            // Range/Collection
            Token::From => Some("from"),
            Token::To => Some("to"),
            Token::Between => Some("between"),
            Token::Through => Some("through"),
            Token::In => Some("in"),
            Token::Of => Some("of"),
            Token::On => Some("on"),
            Token::The => Some("the"),
            Token::A => Some("a"),
            Token::An => Some("an"),
            Token::All => Some("all"),
            Token::By => Some("by"),
            Token::Treating => Some("treating"),
            // Types
            Token::Number => Some("number"),
            Token::Float => Some("float"),
            Token::Int => Some("int"),
            Token::Text => Some("text"),
            Token::Boolean => Some("boolean"),
            Token::List => Some("list"),
            Token::True => Some("true"),
            Token::False => Some("false"),
            // File I/O Types and Keywords
            Token::Buffer => Some("buffer"),
            Token::File => Some("file"),
            Token::Bytes => Some("bytes"),
            Token::Size => Some("size"),
            Token::Into => Some("into"),
            Token::Reading => Some("reading"),
            Token::Writing => Some("writing"),
            Token::Appending => Some("appending"),
            Token::Standard => Some("standard"),
            Token::Input => Some("input"),
            // Properties
            Token::Even => Some("even"),
            Token::Odd => Some("odd"),
            Token::Positive => Some("positive"),
            Token::Negative => Some("negative"),
            Token::Zero => Some("zero"),
            Token::Empty => Some("empty"),
            // Property Access
            Token::Apostrophe => None, // punctuation
            Token::Capacity => Some("capacity"),
            Token::Descriptor => Some("descriptor"),
            Token::Modified => Some("modified"),
            Token::Accessed => Some("accessed"),
            Token::Permissions => Some("permissions"),
            Token::Readable => Some("readable"),
            Token::Writable => Some("writable"),
            Token::Full => Some("full"),
            Token::First => Some("first"),
            Token::Last => Some("last"),
            Token::Absolute => Some("absolute"),
            Token::Sign => Some("sign"),
            // Error Handling
            Token::Error => Some("error"),
            Token::Stderr => Some("stderr"),
            Token::Auto => Some("auto"),
            Token::Catching => Some("catching"),
            Token::Enable => Some("enable"),
            Token::Disable => Some("disable"),
            // Library System
            Token::See => Some("see"),
            Token::Library => Some("library"),
            Token::Version => Some("version"),
            // Arguments and Environment
            Token::Argument => Some("argument"),
            Token::Arguments => Some("arguments"),
            Token::Environment => Some("environment"),
            Token::Variable => Some("variable"),
            Token::Count => Some("count"),
            // Time and Timers
            Token::Wait => Some("wait"),
            Token::Sleep => Some("sleep"),
            Token::Timer => Some("timer"),
            Token::Stop => Some("stop"),
            Token::Begin => Some("begin"),
            Token::Finish => Some("finish"),
            Token::Get => Some("get"),
            Token::Current => Some("current"),
            Token::Time => Some("time"),
            Token::Second => Some("second"),
            Token::Seconds => Some("seconds"),
            Token::Millisecond => Some("millisecond"),
            Token::Milliseconds => Some("milliseconds"),
            Token::Duration => Some("duration"),
            Token::Elapsed => Some("elapsed"),
            Token::Hour => Some("hour"),
            Token::Minute => Some("minute"),
            Token::Day => Some("day"),
            Token::Month => Some("month"),
            Token::Year => Some("year"),
            Token::Unix => Some("unix"),
            Token::Running => Some("running"),
            Token::As => Some("as"),
            // Bitwise operations
            Token::BitAnd => Some("bit-and"),
            Token::BitOr => Some("bit-or"),
            Token::BitXor => Some("bit-xor"),
            Token::BitNot => Some("bit-not"),
            Token::BitShiftLeft => Some("bit-shift-left"),
            Token::BitShiftRight => Some("bit-shift-right"),
            // Buffer/List access
            Token::Byte => Some("byte"),
            Token::Element => Some("element"),
            Token::Without => Some("without"),
            // Not keywords - these are identifiers, literals, punctuation, or special
            Token::IntegerLiteral(_) => None,
            Token::FloatLiteral(_) => None,
            Token::StringLiteral(_) => None,
            Token::Identifier(_) => None,
            Token::Period => None,
            Token::Comma => None,
            Token::Colon => None,
            Token::OpenBracket => None,
            Token::CloseBracket => None,
            Token::Minus => None,
            Token::Newline => None,
            Token::ParagraphBreak => None,
            Token::EOF => None,
        }
    }
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
        // Check if the content after ' looks like a single-quoted identifier
        // NOT possessive 's (which is just apostrophe followed by 's' and whitespace)
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
            "call" | "invoke" | "run" => Token::Call,
            "allocate" => Token::Allocate,
            "free" | "release" | "deallocate" => Token::Free,
            "append" | "push" => Token::Append,
            "if" => Token::If,
            "when" => Token::When,
            "then" => Token::Then,
            "else" => Token::Else,
            "but" => Token::But,
            "otherwise" => Token::Otherwise,
            "while" => Token::While,
            "until" => Token::Until,
            "for" => Token::For,
            "each" => Token::Each,
            "every" => Token::Every,
            "loop" => Token::Loop,
            "repeat" => Token::Repeat,
            "times" => Token::Times,
            "break" => Token::Break,
            "stop" => Token::Stop,
            "exit" | "quit" | "terminate" => Token::Exit,
            "continue" | "skip" => Token::Continue,
            "return" | "returns" | "give" => Token::Return,
            "to" => Token::To,
            "with" => Token::With,
            "called" | "named" => Token::Called,
            "modulo" | "mod" | "remainder" => Token::Modulo,
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
            "through" => Token::Through,
            "in" | "inside" | "within" => Token::In,
            "of" => Token::Of,
            "on" | "at" => Token::On,
            "the" => Token::The,
            "a" => Token::A,
            "an" => Token::An,
            "all" => Token::All,
            "by" => Token::By,
            "number" | "numbers" => Token::Number,
            "float" | "decimal" | "real" => Token::Float,
            "int" | "integer" => Token::Int,
            "text" | "string" | "message" => Token::Text,
            "boolean" | "bool" | "flag" => Token::Boolean,
            "list" | "array" | "collection" => Token::List,
            "true" | "yes" => Token::True,
            "false" | "no" => Token::False,
            "even" => Token::Even,
            "odd" => Token::Odd,
            "positive" => Token::Positive,
            "negative" => Token::Negative,
            "zero" => Token::Zero,
            "empty" | "nothing" | "null" | "nil" => Token::Empty,
            // File I/O keywords
            "open" | "opened" => Token::Open,
            "read" => Token::Read,
            "write" => Token::Write,
            "close" | "closed" => Token::Close,
            "delete" | "remove" => Token::Delete,
            "exists" | "exist" => Token::Exists,
            "resize" | "reallocate" | "grow" | "shrink" => Token::Resize,
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
            "stderr" => Token::Stderr,
            "auto" | "automatic" => Token::Auto,
            "catching" => Token::Catching,
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
            "treating" | "treat" => Token::Treating,
            // Time and Timers
            "wait" | "pause" => Token::Wait,
            "sleep" | "delay" => Token::Sleep,
            "timer" | "stopwatch" => Token::Timer,
            "start" => Token::Identifier("start".to_string()),
            "begin" => Token::Begin,
            "finish" => Token::Finish,
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
                    '-' => Token::Minus,
                    '\'' => {
                        // Check if this is a character literal ('A'), single-quoted identifier, or apostrophe
                        if self.is_char_literal() {
                            self.read_char_literal()
                        } else if self.is_single_quoted_identifier() {
                            Token::Identifier(self.read_single_quoted_string())
                        } else {
                            Token::Apostrophe
                        }
                    }
                    '"' => Token::StringLiteral(self.read_string()),
                    c if c.is_ascii_digit() => self.read_number(c),
                    c if c.is_alphabetic() => self.read_word(c),
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
