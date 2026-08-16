#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Actions
    Print, Set, Create, Add, Subtract, Multiply, Divide, Increment, Decrement,
    Allocate, Free, Append, Copy, Clear,

    // File I/O Actions
    Open, Read, Write, Close, Delete, Exists, Resize, Seek,

    // Control Flow
    If, When, Then, Else, But, Otherwise, While, For, Each,
    Repeat, Times, Break, Continue, Return, Exit,
    
    // Functions
    With, Called, Modulo,

    // Flag schema
    Flag, Parse, Required, Default,
    
    // Comparisons
    Is, Are, Equals, Equal, Greater, Less, Than, Not, And, Or,
    
    // Range/Collection
    From, To, Between, In, Of, On, The, A, An, All, Treating,
    
    // Types
    Number, Float, Int, Text, Boolean, List, Map, True, False,
    
    // File I/O Types and Keywords
    Buffer, File, Bytes, Size, Into, Reading, Writing, Appending, Standard, Input,
    
    // Properties
    Even, Odd, Positive, Negative, Zero, Empty,
    // The nothing/null literal (stage 1e3, tag 6). Distinct from the
    // `empty` *property* predicate: `nothing`/`null`/`nil` are value
    // literals, `empty` tests a collection's size.
    Nothing,
    
    // Property Access
    Apostrophe, Capacity, Descriptor, Modified, Accessed, Permissions,
    Readable, Writable, Full, First, Last, Keys, Values, Absolute, Sign,
    
    // Error Handling
    Error, Auto, Enable, Disable,
    
    // Library System
    See, Library, Version,
    
    // Arguments and Environment
    Argument, Arguments, Environment, Variable, Count, Raw,
    
    // Time and Timers
    Wait, Sleep, Timer,
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
    Period, Comma, Colon, OpenBracket, CloseBracket, OpenBrace, CloseBrace, Minus,
    
    // Special
    Newline, ParagraphBreak, EOF,
}

impl Token {
    /// Check if a string matches any reserved keyword.
    /// Returns the canonical keyword name if it matches.
    ///
    /// After plan 270 a string literal is never a name, so the parser no
    /// longer consults this to reject `"flag"`-style names; it remains for
    /// tests and as a general lexical utility.
    #[allow(dead_code)]
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
            "execute" => Some("execute"),
            "allocate" => Some("allocate"),
            "free" | "deallocate" | "release" => Some("free"),
            "clear" => Some("clear"),
            "modulo" | "mod" | "remainder" => Some("modulo"),
            // Control flow
            "if" => Some("if"),
            "when" => Some("when"),
            "then" => Some("then"),
            "else" => Some("else"),
            "but" => Some("but"),
            "otherwise" => Some("otherwise"),
            "while" => Some("while"),
            "for" => Some("for"),
            "each" => Some("each"),
            "repeat" => Some("repeat"),
            "break" => Some("break"),
            "continue" | "skip" => Some("continue"),
            "return" | "give" | "respond" | "reply" => Some("return"),
            "exit" | "quit" | "terminate" | "end" | "halt" | "abort" => Some("exit"),
            // Functions
            "with" | "using" | "given" | "taking" => Some("with"),
            "called" | "named" => Some("called"),
            "parse" => Some("parse"),
            "flag" => Some("flag"),
            "required" => Some("required"),
            "default" => Some("default"),
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
            "in" | "inside" | "within" => Some("in"),
            "of" => Some("of"),
            "on" | "at" => Some("on"),
            "the" => Some("the"),
            "a" => Some("a"),
            "an" => Some("an"),
            "all" => Some("all"),
            "treating" | "treat" => Some("treating"),
            // Types
            "number" | "numbers" => Some("number"),
            "float" | "decimal" | "real" => Some("float"),
            "int" | "integer" => Some("int"),
            "text" | "string" | "message" => Some("text"),
            "boolean" | "bool" => Some("boolean"),
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
            "seek" => Some("seek"),
            // Properties
            "even" => Some("even"),
            "odd" => Some("odd"),
            "positive" => Some("positive"),
            "negative" => Some("negative"),
            "zero" => Some("zero"),
            "empty" => Some("empty"),
            "nothing" | "null" | "nil" => Some("nothing"),
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
            "auto" | "automatic" => Some("auto"),
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
            "raw" => Some("raw"),
            // Time and timers
            "wait" | "pause" => Some("wait"),
            "sleep" | "delay" => Some("sleep"),
            "timer" | "stopwatch" => Some("timer"),
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
            Token::Allocate => Some("allocate"),
            Token::Free => Some("free"),
            Token::Append => Some("append"),
            Token::Copy => Some("copy"),
            Token::Clear => Some("clear"),
            // File I/O Actions
            Token::Open => Some("open"),
            Token::Read => Some("read"),
            Token::Write => Some("write"),
            Token::Close => Some("close"),
            Token::Delete => Some("delete"),
            Token::Exists => Some("exists"),
            Token::Resize => Some("resize"),
            Token::Seek => Some("seek"),
            // Control Flow
            Token::If => Some("if"),
            Token::When => Some("when"),
            Token::Then => Some("then"),
            Token::Else => Some("else"),
            Token::But => Some("but"),
            Token::Otherwise => Some("otherwise"),
            Token::While => Some("while"),
            Token::For => Some("for"),
            Token::Each => Some("each"),
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
            Token::Parse => Some("parse"),
            Token::Flag => Some("flag"),
            Token::Required => Some("required"),
            Token::Default => Some("default"),
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
            Token::In => Some("in"),
            Token::Of => Some("of"),
            Token::On => Some("on"),
            Token::The => Some("the"),
            Token::A => Some("a"),
            Token::An => Some("an"),
            Token::All => Some("all"),
            Token::Treating => Some("treating"),
            // Types
            Token::Number => Some("number"),
            Token::Float => Some("float"),
            Token::Int => Some("int"),
            Token::Text => Some("text"),
            Token::Boolean => Some("boolean"),
            Token::List => Some("list"),
            Token::Map => Some("map"),
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
            Token::Nothing => Some("nothing"),
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
            Token::Keys => Some("keys"),
            Token::Values => Some("values"),
            Token::Absolute => Some("absolute"),
            Token::Sign => Some("sign"),
            // Error Handling
            Token::Error => Some("error"),
            Token::Auto => Some("auto"),
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
            Token::Raw => Some("raw"),
            // Time and Timers
            Token::Wait => Some("wait"),
            Token::Sleep => Some("sleep"),
            Token::Timer => Some("timer"),
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
            Token::OpenBrace => None,
            Token::CloseBrace => None,
            Token::Minus => None,
            Token::Newline => None,
            Token::ParagraphBreak => None,
            Token::EOF => None,
        }
    }
}
