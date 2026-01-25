#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Integer,
    Float,
    String,
    Boolean,
    List(Box<Type>),
    Buffer,
    File,
    Time,
    Timer,
    Void,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FileMode {
    Reading,
    Writing,
    Appending,
}

#[derive(Debug, Clone)]
pub enum Expr {
    IntegerLit(i64),
    FloatLit(f64),
    StringLit(String),
    BoolLit(bool),
    Identifier(String),
    
    BinaryOp {
        left: Box<Expr>,
        op: BinaryOperator,
        right: Box<Expr>,
    },
    
    UnaryOp {
        op: UnaryOperator,
        operand: Box<Expr>,
    },
    
    Range {
        start: Box<Expr>,
        end: Box<Expr>,
        inclusive: bool,
    },
    
    PropertyCheck {
        value: Box<Expr>,
        property: Property,
    },
    
    FunctionCall {
        name: String,
        args: Vec<Expr>,
    },
    
    ListLit {
        elements: Vec<Expr>,
    },
    
    #[allow(dead_code)]
    ListAccess {
        list: Box<Expr>,
        index: Box<Expr>,
    },
    
    // Property access: buffer's size, buffer's capacity
    PropertyAccess {
        object: String,
        property: ObjectProperty,
    },
    
    // The last error value
    #[allow(dead_code)]
    LastError,
    
    // Command-line arguments
    ArgumentCount,
    ArgumentAt {
        index: Box<Expr>,
    },
    ArgumentName,       // argv[0] - program name
    ArgumentFirst,      // argv[1] - first user arg
    ArgumentSecond,     // argv[2] - second user arg
    ArgumentLast,       // last user argument (or program name if no args)
    ArgumentEmpty,      // true if argc <= 1 (no user args)
    ArgumentAll,        // all user arguments as a list (argv[1..])
    
    // Inline substitution: expr treating "X" as "Y"
    TreatingAs {
        value: Box<Expr>,
        match_value: Box<Expr>,
        replacement: Box<Expr>,
    },
    
    // Environment variables
    EnvironmentVariable {
        name: Box<Expr>,
    },
    EnvironmentVariableCount,
    EnvironmentVariableAt {
        index: Box<Expr>,
    },
    EnvironmentVariableExists {
        name: Box<Expr>,
    },
    EnvironmentVariableFirst,   // first env var
    EnvironmentVariableLast,    // last env var
    EnvironmentVariableEmpty,   // true if no env vars
    
    // Time expressions
    CurrentTime,                // current time value
    
    // Type casting
    Cast {
        value: Box<Expr>,
        target_type: Type,
    },
    
    // Duration cast (timer's duration in seconds)
    DurationCast {
        value: Box<Expr>,
        unit: TimeUnit,
    },
    
    // Byte access: byte N of buffer
    ByteAccess {
        buffer: Box<Expr>,
        index: Box<Expr>,
    },
    
    // Element access: element N of list
    ElementAccess {
        list: Box<Expr>,
        index: Box<Expr>,
    },
    
    // Format string: "Hello {name}, you are {age} years old"
    FormatString {
        parts: Vec<FormatPart>,
    },
}

#[derive(Debug, Clone)]
pub enum FormatPart {
    Literal(String),
    Variable { name: String, format: Option<String> },
    Expression { expr: Box<Expr>, format: Option<String> },
}

#[derive(Debug, Clone)]
pub enum TimeUnit {
    Seconds,
    Milliseconds,
}

#[derive(Debug, Clone)]
pub enum BinaryOperator {
    Add, Subtract, Multiply, Divide, Modulo,
    Equal, NotEqual, Greater, Less, GreaterEqual, LessEqual,
    And, Or,
    // Bitwise operators
    BitAnd, BitOr, BitXor, ShiftLeft, ShiftRight,
}

#[derive(Debug, Clone)]
pub enum UnaryOperator {
    Negate,
    Not,
}

#[derive(Debug, Clone)]
pub enum Property {
    Even,
    Odd,
    Positive,
    Negative,
    Zero,
    Empty,
}

#[derive(Debug, Clone)]
pub enum ObjectProperty {
    // Buffer properties
    Size,      // buffer's size (current length)
    Capacity,  // buffer's capacity (max size)
    Empty,     // buffer's empty (size == 0)
    Full,      // buffer's full (size == capacity)
    
    // File properties
    Descriptor,  // file's descriptor (fd number)
    Modified,    // file's modified (mtime)
    Accessed,    // file's accessed (atime)
    Permissions, // file's permissions (mode bits)
    Readable,    // file's readable
    Writable,    // file's writable
    
    // List properties
    First,     // list's first item
    Last,      // list's last item
    
    // Number properties
    Absolute,  // number's absolute value
    Sign,      // number's sign (-1, 0, 1)
    Even,      // number's even
    Odd,       // number's odd
    Positive,  // number's positive
    Negative,  // number's negative
    Zero,      // number's zero
    
    // Time properties
    Hour,      // time's hour (0-23)
    Minute,    // time's minute (0-59)
    Second,    // time's second (0-59)
    Day,       // time's day (1-31)
    Month,     // time's month (1-12)
    Year,      // time's year
    Unix,      // time's unix timestamp
    
    // Timer properties
    Duration,   // timer's duration
    Elapsed,    // timer's elapsed time
    StartTime,  // timer's start time
    EndTime,    // timer's end time
    Running,    // timer's running status
}

#[derive(Debug, Clone)]
pub enum Statement {
    Print {
        value: Expr,
        without_newline: bool,
    },
    
    VarDecl {
        name: String,
        var_type: Option<Type>,
        value: Option<Expr>,
    },
    
    Assignment {
        name: String,
        value: Expr,
    },
    
    If {
        condition: Expr,
        then_block: Vec<Statement>,
        else_if_blocks: Vec<(Expr, Vec<Statement>)>,
        else_block: Option<Vec<Statement>>,
    },
    
    While {
        condition: Expr,
        body: Vec<Statement>,
    },
    
    ForRange {
        variable: String,
        range: Expr,
        body: Vec<Statement>,
    },
    
    ForEach {
        variable: String,
        collection: Expr,
        body: Vec<Statement>,
    },
    
    Repeat {
        count: Expr,
        body: Vec<Statement>,
    },
    
    Break,
    Continue,
    
    Exit {
        code: Expr,
    },
    
    Return {
        value: Option<Expr>,
    },
    
    FunctionDef {
        name: String,
        params: Vec<(String, Type)>,
        #[allow(dead_code)]
        return_type: Type,
        body: Vec<Statement>,
    },
    
    FunctionCall {
        name: String,
        args: Vec<Expr>,
    },
    
    Allocate {
        name: String,
        size: Expr,
    },
    
    Free {
        name: String,
    },
    
    Increment {
        name: String,
    },
    
    Decrement {
        name: String,
    },
    
    // File I/O statements
    BufferDecl {
        name: String,
        size: Expr,
    },
    
    // Set byte N of buffer to value (1-indexed)
    ByteSet {
        buffer: String,
        index: Expr,
        value: Expr,
    },
    
    // Set element N of list to value (1-indexed)
    ElementSet {
        list: String,
        index: Expr,
        value: Expr,
    },
    
    // Append value to list
    ListAppend {
        list: String,
        value: Expr,
    },
    
    FileOpen {
        name: String,
        path: Expr,
        mode: FileMode,
    },
    
    FileRead {
        source: String,      // file name or "stdin"
        buffer: String,
    },
    
    FileWrite {
        file: String,
        value: Expr,
    },
    
    FileWriteNewline {
        file: String,
    },
    
    FileClose {
        file: String,
    },
    
    FileDelete {
        path: Expr,
    },
    
    // Error handling - actions are comma-separated within the sentence
    OnError {
        actions: Vec<Statement>,
    },
    
    // Buffer resize
    BufferResize {
        name: String,
        new_size: Expr,
    },
    
    // Library declaration (for library authors)
    LibraryDecl {
        name: String,
        version: String,
    },
    
    // See/import statement (for library users)
    See {
        path: String,
        lib_name: Option<String>,
        lib_version: Option<String>,
    },
    
    // Time and Timer statements
    TimerDecl {
        name: String,
    },
    
    TimerStart {
        name: String,
    },
    
    TimerStop {
        name: String,
    },
    
    Wait {
        duration: Expr,
        unit: TimeUnit,
    },
    
    GetTime {
        into: String,
    },
}

#[derive(Debug, Clone)]
pub struct Program {
    pub statements: Vec<Statement>,
    pub uses_heap: bool,
    pub uses_strings: bool,
    pub uses_io: bool,
    pub uses_args: bool,
}

impl Program {
    pub fn new(statements: Vec<Statement>) -> Self {
        Program {
            statements,
            uses_heap: false,
            uses_strings: false,
            uses_io: false,
            uses_args: false,
        }
    }
}
