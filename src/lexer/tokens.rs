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
    From, To, Between, In, Of, On, The, A, An, Treating,
    
    // Types
    Number, Float, Int, Text, Boolean, List, Map, True, False,
    
    // File I/O Types and Keywords
    Buffer, File, Bytes, Into, Reading, Writing, Appending, Standard, Input,
    
    // Properties
    Even, Odd, Positive, Negative, Zero, Empty,
    // The nothing/null literal (stage 1e3, tag 6). Distinct from the
    // `empty` *property* predicate: `nothing`/`null`/`nil` are value
    // literals, `empty` tests a collection's size.
    Nothing,
    
    // Property Access
    Apostrophe, Descriptor, Modified, Accessed, Permissions,
    Readable, Writable, Full, Keys, Values, Absolute, Sign,
    
    // Error Handling
    Error,
    
    // Library System
    See, Library, Version,
    
    // Arguments and Environment
    Argument, Arguments, Environment, Variable,
    
    // Time and Timers
    Wait, Sleep, Timer,
    Get, Current, Time, Seconds, Millisecond, Milliseconds,
    Duration, Elapsed, Hour, Minute, Day, Month, Year, Unix,
    Running, As,
    
    // Bitwise Operations (only bit-* forms, no standalone keywords)
    BitAnd, BitOr, BitXor, BitNot, BitShiftLeft, BitShiftRight,
    
    // Buffer/List Access
    Byte, Element, Without,
    
    // Literals
    IntegerLiteral(i64),
    /// An integer literal whose text does not fit in a 64-bit signed
    /// integer (BUGS_FOUND #22). Carries the raw source text (with a
    /// `0x`/`0b` prefix for hex/binary literals) so the parser can name the
    /// offending literal in its diagnostic. Never silently coerced to 0.
    IntegerLiteralOverflow(String),
    FloatLiteral(f64),
    StringLiteral(String),
    
    // Identifiers
    Identifier(String),
    
    // Punctuation
    Period, Comma, Colon, OpenBracket, CloseBracket, OpenBrace, CloseBrace, Minus,
    
    // Special
    Newline, ParagraphBreak, EOF,
}

/// The complete alias -> canonical-keyword table, one row per spelling the
/// lexer's word fold (`Lexer::read_word` in `scan.rs`) reserves. This is the
/// single source of truth `string_is_keyword` reads from below, the source
/// `LANGUAGE.md`'s Reserved Aliases table is generated/checked against
/// (`codegen::tests::reserved_aliases_doc_matches_the_const`), and the set
/// every entry is checked against the *live* lexer for
/// (`codegen::tests::string_is_keyword_matches_the_live_lexer`).
///
/// A canonical keyword with only one spelling still gets a row mapping to
/// itself (`("if", "if")`), since `string_is_keyword` must answer for those
/// too; the docs generator filters those out when it lists "alternate
/// spellings" (a keyword aliasing itself isn't an alias).
///
/// This table does not include the contextual words `scan.rs` folds to
/// `Token::Identifier` (`flags`, `it`, `all`, `size`, `length`, `capacity`,
/// `first`, `last`, `version`, `count`, `raw`, `start`, `begin`, `stop`,
/// `finish`, `second`) - those are deliberately *not* reserved, so they
/// have no row here either. BUGS_FOUND #106: the live lexer wins every
/// disagreement; nothing here reserves a spelling `scan.rs` does not fold,
/// or omits one it does.
pub const RESERVED_ALIASES: &[(&str, &str)] = &[
    // Actions
    ("print", "print"), ("prints", "print"), ("display", "print"), ("show", "print"),
    ("set", "set"), ("store", "set"), ("assign", "set"),
    ("create", "create"), ("make", "create"), ("define", "create"),
    ("add", "add"), ("plus", "add"),
    ("subtract", "subtract"), ("minus", "subtract"),
    ("multiply", "multiply"),
    ("divide", "divide"),
    ("increment", "increment"),
    ("decrement", "decrement"),
    ("allocate", "allocate"),
    ("free", "free"), ("release", "free"), ("deallocate", "free"),
    ("append", "append"), ("push", "append"),
    ("copy", "copy"),
    ("clear", "clear"),
    ("modulo", "modulo"), ("mod", "modulo"), ("remainder", "modulo"),
    // Control flow
    ("if", "if"),
    ("when", "when"),
    ("then", "then"),
    ("else", "else"),
    ("but", "but"),
    ("otherwise", "otherwise"),
    ("while", "while"),
    ("for", "for"),
    ("each", "each"),
    ("repeat", "repeat"),
    ("times", "times"),
    ("break", "break"),
    ("continue", "continue"), ("skip", "continue"),
    ("return", "return"), ("returns", "return"), ("give", "return"),
    ("exit", "exit"), ("quit", "exit"), ("terminate", "exit"),
    // Functions
    ("with", "with"),
    ("called", "called"), ("named", "called"),
    ("parse", "parse"),
    ("flag", "flag"),
    ("required", "required"),
    ("default", "default"),
    // Comparisons
    ("is", "is"),
    ("are", "are"),
    ("equals", "equals"), ("equal", "equals"),
    ("greater", "greater"), ("more", "greater"), ("bigger", "greater"), ("larger", "greater"),
    ("less", "less"), ("fewer", "less"), ("smaller", "less"),
    ("than", "than"),
    ("not", "not"),
    ("and", "and"),
    ("or", "or"),
    // Range/Collection
    ("from", "from"), ("starting", "from"),
    ("to", "to"), ("up", "to"),
    ("between", "between"),
    ("in", "in"), ("inside", "in"), ("within", "in"),
    ("of", "of"),
    ("on", "on"), ("at", "on"),
    ("the", "the"),
    ("a", "a"),
    ("an", "an"),
    ("treating", "treating"), ("treat", "treating"),
    // Types
    ("number", "number"), ("numbers", "number"),
    ("float", "float"), ("decimal", "float"), ("real", "float"),
    ("int", "int"), ("integer", "int"),
    ("text", "text"), ("string", "text"), ("message", "text"),
    ("boolean", "boolean"), ("bool", "boolean"),
    ("list", "list"), ("array", "list"), ("collection", "list"),
    ("map", "map"), ("dictionary", "map"),
    ("true", "true"), ("yes", "true"),
    ("false", "false"), ("no", "false"),
    // File I/O
    ("buffer", "buffer"),
    ("file", "file"),
    ("bytes", "bytes"),
    ("byte", "byte"),
    ("into", "into"),
    ("reading", "reading"),
    ("writing", "writing"),
    ("appending", "appending"),
    ("standard", "standard"),
    ("input", "input"),
    ("open", "open"), ("opened", "open"),
    ("read", "read"),
    ("write", "write"),
    ("close", "close"), ("closed", "close"),
    ("delete", "delete"), ("remove", "delete"),
    ("exists", "exists"), ("exist", "exists"),
    ("resize", "resize"), ("reallocate", "resize"), ("grow", "resize"), ("shrink", "resize"),
    ("seek", "seek"),
    // Properties
    ("even", "even"),
    ("odd", "odd"),
    ("positive", "positive"),
    ("negative", "negative"),
    ("zero", "zero"),
    ("empty", "empty"),
    ("nothing", "nothing"), ("null", "nothing"), ("nil", "nothing"),
    ("descriptor", "descriptor"), ("fd", "descriptor"),
    ("modified", "modified"),
    ("accessed", "accessed"),
    ("permissions", "permissions"), ("perms", "permissions"),
    ("readable", "readable"),
    ("writable", "writable"),
    ("full", "full"),
    ("keys", "keys"),
    ("values", "values"),
    ("absolute", "absolute"), ("abs", "absolute"),
    ("sign", "sign"),
    ("element", "element"),
    ("without", "without"),
    // Error handling
    ("error", "error"),
    // Library
    ("see", "see"), ("import", "see"), ("include", "see"), ("require", "see"),
    ("library", "library"), ("lib", "library"),
    // `version` itself is contextual (a header-sentence word), not
    // reserved - only the `ver` alias is (Class C, deferred), and it keeps
    // its own `Token::Version` mapping, so it is the row here.
    ("ver", "version"),
    // Arguments/Environment
    ("argument", "argument"), ("arg", "argument"), ("param", "argument"), ("parameter", "argument"),
    ("arguments", "arguments"), ("args", "arguments"), ("params", "arguments"), ("parameters", "arguments"),
    ("environment", "environment"), ("env", "environment"),
    ("variable", "variable"), ("var", "variable"),
    // `count` and `raw` are contextual possessive properties, not reserved.
    // Time and timers
    ("wait", "wait"), ("pause", "wait"),
    ("sleep", "sleep"), ("delay", "sleep"),
    ("timer", "timer"), ("stopwatch", "timer"),
    ("get", "get"), ("fetch", "get"), ("retrieve", "get"),
    ("current", "current"),
    ("time", "time"),
    ("seconds", "seconds"),
    ("millisecond", "millisecond"),
    ("milliseconds", "milliseconds"), ("ms", "milliseconds"),
    ("duration", "duration"),
    ("elapsed", "elapsed"),
    ("hour", "hour"), ("hours", "hour"),
    ("minute", "minute"), ("minutes", "minute"),
    ("day", "day"), ("days", "day"),
    ("month", "month"), ("months", "month"),
    ("year", "year"), ("years", "year"),
    ("unix", "unix"), ("unixtime", "unix"), ("timestamp", "unix"),
    ("running", "running"),
    ("as", "as"),
    // Bitwise operations (only bit-* forms, no standalone keywords)
    ("bit-and", "bit-and"),
    ("bit-or", "bit-or"),
    ("bit-xor", "bit-xor"),
    ("bit-not", "bit-not"),
    ("bit-shift-left", "bit-shift-left"),
    ("bit-shift-right", "bit-shift-right"),
];

impl Token {
    /// Check if a string matches any reserved keyword.
    /// Returns the canonical keyword name if it matches.
    ///
    /// After plan 270 a string literal is never a name, so the parser no
    /// longer consults this to reject `"flag"`-style names; it remains for
    /// tests and as a general lexical utility.
    ///
    /// Answers strictly from [`RESERVED_ALIASES`] (BUGS_FOUND #106): there
    /// is no separate hand-maintained keyword list here to drift from the
    /// lexer's own fold.
    #[allow(dead_code)]
    pub fn string_is_keyword(s: &str) -> Option<&'static str> {
        let lower = s.to_lowercase();
        RESERVED_ALIASES
            .iter()
            .find(|(spelling, _)| *spelling == lower)
            .map(|(_, canonical)| *canonical)
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
            Token::Descriptor => Some("descriptor"),
            Token::Modified => Some("modified"),
            Token::Accessed => Some("accessed"),
            Token::Permissions => Some("permissions"),
            Token::Readable => Some("readable"),
            Token::Writable => Some("writable"),
            Token::Full => Some("full"),
            Token::Keys => Some("keys"),
            Token::Values => Some("values"),
            Token::Absolute => Some("absolute"),
            Token::Sign => Some("sign"),
            // Error Handling
            Token::Error => Some("error"),
            // Library System
            Token::See => Some("see"),
            Token::Library => Some("library"),
            Token::Version => Some("version"),
            // Arguments and Environment
            Token::Argument => Some("argument"),
            Token::Arguments => Some("arguments"),
            Token::Environment => Some("environment"),
            Token::Variable => Some("variable"),
            // Time and Timers
            Token::Wait => Some("wait"),
            Token::Sleep => Some("sleep"),
            Token::Timer => Some("timer"),
            Token::Get => Some("get"),
            Token::Current => Some("current"),
            Token::Time => Some("time"),
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
            Token::IntegerLiteralOverflow(_) => None,
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
