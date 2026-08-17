use crate::errors::SourceLocation;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    Integer,
    Float,
    String,
    Boolean,
    List(Box<Type>),
    Map(Box<Type>), // key/value collection (tag 5); inner type is the value type, keys are always text
    Buffer,
    File,
    Time,
    Timer,
    Value,
    Void,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FlagValueType {
    Boolean,
    Number,
    Text,
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
    // The nothing/null literal (stage 1e3, tag 6). Unit variant: the
    // payload is always 0 and the tag is always TAG_NOTHING (6), so it
    // carries no data. Spelled `nothing`, `null`, or `nil` in source.
    NothingLit,
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

    // Runtime type predicate: `item is a text` / `is a number` / etc.
    // `type_noun` is constrained by the parser to Integer/Float/String/Boolean.
    // Negation (`is not a text`) wraps this in `UnaryOp { Not, .. }`.
    TypeCheck {
        value: Box<Expr>,
        type_noun: Type,
    },

    FunctionCall {
        name: String,
        args: Vec<Expr>,
    },
    
    ListLit {
        elements: Vec<Expr>,
    },

    // Map literal: {"key": value, ...}. Each pair is (key_expr, value_expr);
    // keys must be text. JSON-object syntax (stage 1e2, tag 5).
    MapLit {
        pairs: Vec<(Expr, Expr)>,
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

    // Map key access: person's "name". `map` is the variable name (like
    // PropertyAccess.object); `key` is an expression that evaluates to a
    // text value (usually a StringLit). Tag of the found value travels in
    // r11 at codegen, mirroring ElementAccess. (stage 1e2, tag 5)
    MapAccess {
        map: String,
        key: Box<Expr>,
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
    ArgumentRaw,        // raw user arguments as a list (argv[1..], unfiltered)
    ArgumentHas {
        value: Box<Expr>,
    },
    
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
    Fork,                       // fork() - 0 in child, child pid in parent, negative on error
    ReapChild {                 // wait4() - reap a child process, returns its pid (or -1 on error)
        pid: Option<Box<Expr>>, // None = any child (pid -1); Some(expr) = a specific pid
        no_hang: bool,          // plan 311: true = WNOHANG (non-blocking); false = blocking
    },
    // plan 311: the raw wait4 status word from the most recent successful reap.
    // -1 sentinel before any reap. Decoding lives in lib/process.vox, not here.
    ReapedStatus,
    
    // Type casting
    Cast {
        value: Box<Expr>,
        target_type: Type,
        radix: u32, // base for string->integer casts (2, 8, 10, or 16); ignored otherwise
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

    // File availability check: path is available
    FileAvailable {
        path: Box<Expr>,
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

    // Map properties (stage 1e2)
    Keys,      // map's keys   -> a list of key texts (insertion order)
    Values,    // map's values -> a list of values with their tags (insertion order)
    
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

    // Universal property: every variable reports its type as text.
    Type,       // x's type -> "Number (static)" / "Text (dynamic)" etc.
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

    FlagSchemaDecl {
        name: String,
        short: String,
        long: String,
        value_type: FlagValueType,
        required: bool,
        default: Option<Expr>,
    },

    ParseFlags,
    
    Assignment {
        name: String,
        value: Expr,
    },

    // In-place cast/retype of a `value` variable: `<name> is a <type>.`.
    // Statement position only; the same phrase in condition position is a
    // TypeCheck predicate.
    ValueRetype {
        name: String,
        target_type: Type,
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
        // The type written in `Return a <type>, ...`, when present. Carried
        // on the statement itself (rather than only being consulted where
        // the statement is parsed) so that whichever code assembles the
        // enclosing function's `FunctionDef.return_type` can read it back
        // regardless of where in the body this Return sits.
        declared_type: Option<Type>,
    },
    
    FunctionDef {
        name: String,
        params: Vec<(String, Type)>,
        #[allow(dead_code)]
        return_type: Type,
        body: Vec<Statement>,
        // Set when a blank line (paragraph break) force-closed this
        // function's body early, per the "blank line closes all open
        // clauses" rule. Consulted by the analyzer to explain otherwise
        // confusing errors in the top-level statements that follow.
        body_ended_early: Option<SourceLocation>,
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

    // Set map's "<key>" to value: insert or replace. The map may reallocate
    // on growth; codegen stores the returned pointer back into the variable
    // (mirroring ListAppend). (stage 1e2, tag 5)
    MapSet {
        map: String,
        key: Expr,
        value: Expr,
    },
    
    // Append value to list
    ListAppend {
        list: String,
        value: Expr,
    },

    // Copy buffer contents into another buffer (clobber destination)
    BufferCopy {
        source: Expr,
        destination: String,
    },

    // Clear buffer contents (set length to zero, preserve capacity)
    BufferClear {
        name: String,
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

    FileReadLine {
        source: String,      // file name or "stdin"
        buffer: String,
    },

    FileSeekLine {
        file: String,
        line: Expr,          // 1-indexed line number
    },

    FileSeekByte {
        file: String,
        byte: Expr,          // 1-indexed byte position
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

    Rmdir {
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

    // Filesystem operations
    Mkdir {
        path: Expr,
    },

    Chdir {
        path: Expr,
    },

    Symlink {
        target: Expr,
        linkpath: Expr,
    },

    // Create device node: mknod(path, mode, dev)
    Mknod {
        path: Expr,
        node_type: DeviceNodeType,
        major: Expr,
        minor: Expr,
    },

    Mount {
        source: Expr,
        target: Expr,
        fstype: Expr,
        options: Option<Expr>,
    },

    Unmount {
        target: Expr,
        /// true = MNT_DETACH (lazy unmount, succeeds even while busy)
        lazy: bool,
    },

    /// reboot(2) with LINUX_REBOOT_CMD_POWER_OFF (syncs filesystems first)
    Shutdown,

    /// reboot(2) with LINUX_REBOOT_CMD_RESTART (syncs filesystems first)
    Reboot,

    /// reboot(2) with LINUX_REBOOT_CMD_HALT (syncs filesystems first)
    Halt,

    PivotRoot {
        new_root: Expr,
        put_old: Expr,
    },

    // execve(path, argv, envp) - argv is built as [path, args..., NULL]
    // envp is always the process's own inherited environment (_envp)
    Execute {
        path: Expr,
        args: Expr, // expected to be an Expr::ListLit
    },

    // kill(2): "Send signal <N> to process <pid>." / "... to child <pid>."
    // rdi = pid, rsi = signal. Sets _last_error on failure, clears on success.
    SendSignal {
        signal: Expr,
        pid: Expr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceNodeType {
    Character, // 'c' - requires CAP_MKNOD/root on real hardware
    Block,     // 'b' - requires CAP_MKNOD/root on real hardware
    Fifo,      // 'p' - named pipe, no special privilege required
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

/// What kind of definitely-declared name this is, so consumers can route
/// it into their type-specific tracking (buffer/list/file sets).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DefiniteDeclKind {
    Plain,
    Buffer,
    List,
    Map,
    File,
}

/// Names that are DEFINITELY declared by the time this statement sequence
/// finishes, regardless of which control-flow path ran: unconditional
/// declarations, plus - for if/otherwise chains that have an else branch -
/// the intersection of what every branch declares. A name declared in only
/// some branches is not definite (the analyzer's guard tracking owns those),
/// and loop bodies never count (they may run zero times). Function bodies
/// are their own scope and are never entered.
///
/// Shared by the analyzer (function-visible globals) and codegen (bss
/// mirror labels) so the two can never disagree about which main-line
/// declarations behave as globals.
pub fn collect_definite_decls(stmts: &[Statement]) -> std::collections::HashMap<String, DefiniteDeclKind> {
    let mut out = std::collections::HashMap::new();
    // A name whose recognised occurrences disagree on kind (e.g. `a text
    // called src is "hello".` followed later by `open ... called src`,
    // which this function would otherwise see as `Plain` then `File`) is
    // poisoned: removed from `out` and never re-added, rather than letting
    // whichever occurrence is scanned last silently win. That "last write
    // wins" used to pre-register the *later* kind (into
    // buffer_variables/list_variables/map_variables/file_variables) before
    // the analyzer's own per-statement, declaration-order-respecting
    // type-immutability check ever ran - masking the real conflict instead
    // of surfacing it (plan 294 finding 3). A poisoned name is simply
    // absent from the definite-decl map; the analyzer's linear walk still
    // sees and rejects the conflict when it reaches the second occurrence,
    // it just does so without this pre-pass having pre-judged the type.
    let mut poisoned: std::collections::HashSet<String> = std::collections::HashSet::new();

    fn record(
        out: &mut std::collections::HashMap<String, DefiniteDeclKind>,
        poisoned: &mut std::collections::HashSet<String>,
        name: &str,
        kind: DefiniteDeclKind,
    ) {
        if poisoned.contains(name) {
            return;
        }
        match out.get(name) {
            Some(existing) if *existing != kind => {
                out.remove(name);
                poisoned.insert(name.to_string());
            }
            _ => {
                out.insert(name.to_string(), kind);
            }
        }
    }

    for stmt in stmts {
        match stmt {
            Statement::VarDecl { name, var_type, .. } => {
                let kind = match var_type {
                    Some(Type::Buffer) => DefiniteDeclKind::Buffer,
                    Some(Type::List(_)) => DefiniteDeclKind::List,
                    Some(Type::Map(_)) => DefiniteDeclKind::Map,
                    _ => DefiniteDeclKind::Plain,
                };
                record(&mut out, &mut poisoned, name, kind);
            }
            Statement::BufferDecl { name, .. } => {
                record(&mut out, &mut poisoned, name, DefiniteDeclKind::Buffer);
            }
            Statement::Allocate { name, .. } | Statement::TimerDecl { name } => {
                record(&mut out, &mut poisoned, name, DefiniteDeclKind::Plain);
            }
            Statement::FileOpen { name, .. } => {
                record(&mut out, &mut poisoned, name, DefiniteDeclKind::File);
            }
            Statement::GetTime { into } => {
                record(&mut out, &mut poisoned, into, DefiniteDeclKind::Plain);
            }
            Statement::If { then_block, else_if_blocks, else_block: Some(else_block), .. } => {
                let mut definite = collect_definite_decls(then_block);
                for (_, block) in else_if_blocks {
                    let branch = collect_definite_decls(block);
                    definite.retain(|name, kind| branch.get(name) == Some(kind));
                }
                let branch = collect_definite_decls(else_block);
                definite.retain(|name, kind| branch.get(name) == Some(kind));
                for (name, kind) in definite {
                    record(&mut out, &mut poisoned, &name, kind);
                }
            }
            _ => {}
        }
    }
    out
}
