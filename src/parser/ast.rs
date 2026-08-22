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
    // A user-defined thing (plan 310): the payload is the thing's name as
    // written in `A thing called <name> has ...`. Layout, size, and field
    // offsets are resolved from the `ThingDef` registry at compile time;
    // the type itself carries only the name.
    Thing(String),
    Void,
    Unknown,
}

/// One user-defined composite type, as written in a definition construct
/// (plan 310 §1). Built by the parser and carried on the `Program` so the
/// analyzer and codegen can compute layout without re-parsing.
///
/// Function members take no storage - they are the type's declared
/// callable API (the manifest, plan 310 §4), so `fields` and `members` are
/// deliberately separate lists: everything sensitive to layout (size,
/// offsets, copying, printing, equality) reads `fields` alone.
///
/// `allow(dead_code)`: definition parsing lands ahead of the declaration,
/// field-access, and codegen work that reads the registry, so these fields
/// are written but not yet read. Same treatment as `Type` and the other
/// ahead-of-consumer shapes in this file.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ThingDef {
    pub name: String,
    /// Data fields only, in definition order (which is layout order).
    pub fields: Vec<FieldDef>,
    /// Manifest function-member names, in definition order.
    pub members: Vec<String>,
    /// 1-based source line of the `A thing called <name> has` opener, so a
    /// later duplicate definition can point back at this one.
    pub line: usize,
}

/// One data field of a `ThingDef`. `allow(dead_code)` for the same reason
/// as `ThingDef`: written by the parser, read once layout work lands.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    /// A builtin type noun, or `Type::Thing(name)` for a nested thing.
    pub field_type: Type,
    /// The literal written after `is`, when the field declares a default.
    /// `None` means the field takes its type's zero/empty value.
    pub default: Option<Expr>,
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

    // A field of a user-defined thing (plan 310 §3): `origin's x`, and
    // through nesting to any depth, `route's leg's start's x`. `base` is the
    // thing variable's name; `path` is the field names in order, outermost
    // first. Every step is a compile-time offset, so the whole chain folds
    // into one `base_address + constant` - there is no pointer chase and no
    // runtime failure path (unlike list element access).
    ThingField {
        base: String,
        path: Vec<String>,
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

    // A user-defined thing definition (plan 310 §1). Declares a type, not a
    // variable: it allocates nothing and emits no code. It stays in the
    // statement stream so a definition keeps its source position relative to
    // the uses that must follow it.
    ThingDecl(ThingDef),

    // Write to a field of a user-defined thing (plan 310 §3): `Set origin's x
    // to 3.`, the bare `origin's x is 3.`, and `increment origin's x.` (which
    // the parser desugars into this statement with a `+ 1` value, since the
    // target is an offset, not a name). The read counterpart is
    // `Expr::ThingField`, and `base`/`path` mean exactly the same there.
    SetThingField {
        base: String,
        path: Vec<String>,
        value: Expr,
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
        // Set to the location of a body-level `Return` (one that isn't the
        // function's first statement - "Gate B") when IT closed the body,
        // rather than a blank line. Statements written after it in source
        // are silently promoted to top-level entry code (plan 318 §2) - if
        // one of them is itself a `Return`, the analyzer's "Return is only
        // valid inside a function" error consults this to explain why.
        body_ended_via_return: Option<SourceLocation>,
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
    /// Every thing defined in this program, in definition order. The parser
    /// fills this from its own registry after a successful parse; consumers
    /// look layout up here rather than walking the statement list.
    pub things: Vec<ThingDef>,
}

impl Program {
    pub fn new(statements: Vec<Statement>) -> Self {
        // `things` is DERIVED here, not filled in by the caller, so every
        // construction path populates it. The `--shared` driver builds a
        // Program directly from the combined statements of several inputs
        // (src/main.rs), bypassing the parser's own post-parse derivation -
        // which left `things` empty for a multi-input build, so every
        // consumer of the registry (layout, offsets, cycle checks) silently
        // saw no things at all.
        let things = statements
            .iter()
            .filter_map(|s| match s {
                Statement::ThingDecl(def) => Some(def.clone()),
                _ => None,
            })
            .collect();
        Program {
            statements,
            uses_heap: false,
            uses_strings: false,
            uses_io: false,
            uses_args: false,
            things,
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

/// Every typed declaration reachable in this statement sequence, at ANY
/// nesting depth, regardless of whether the path that reaches it is
/// guaranteed to run - the complement of `collect_definite_decls`.
///
/// `On error`, `While`, `for each` (both `ForRange` and `ForEach`), and
/// `Repeat` bodies are not scoped (LANGUAGE.md:526: no block scoping) -
/// a name declared in one of them is accepted everywhere after, exactly
/// like a top-level declaration, but the analyzer never proves the body
/// ran. `collect_definite_decls` correctly refuses to call such a
/// declaration definite; this function is the other half - it finds
/// EVERY declaration so codegen can tell "definitely declared" apart
/// from "declared on some path, might be skipped" and emit the type's
/// default for the latter at frame setup (docs/BUGS_FOUND.md #25,
/// plan 318 §1). `If` bodies are included too, for the same reason
/// `collect_definite_decls` recurses into them: a some-branches name
/// still needs its type known here even though its own use-after is
/// separately rejected by the analyzer's branch tracking.
///
/// Function bodies are their own scope and are never entered - same
/// rule as `collect_definite_decls`.
pub fn collect_all_typed_decls(stmts: &[Statement]) -> std::collections::HashMap<String, Type> {
    let mut out = std::collections::HashMap::new();
    let mut poisoned: std::collections::HashSet<String> = std::collections::HashSet::new();

    fn record(
        out: &mut std::collections::HashMap<String, Type>,
        poisoned: &mut std::collections::HashSet<String>,
        name: &str,
        ty: Type,
    ) {
        if poisoned.contains(name) {
            return;
        }
        match out.get(name) {
            Some(existing) if *existing != ty => {
                out.remove(name);
                poisoned.insert(name.to_string());
            }
            _ => {
                out.insert(name.to_string(), ty);
            }
        }
    }

    fn walk(
        stmts: &[Statement],
        out: &mut std::collections::HashMap<String, Type>,
        poisoned: &mut std::collections::HashSet<String>,
    ) {
        for stmt in stmts {
            match stmt {
                Statement::VarDecl { name, var_type: Some(t), .. } => {
                    record(out, poisoned, name, t.clone());
                }
                Statement::BufferDecl { name, .. } => {
                    record(out, poisoned, name, Type::Buffer);
                }
                Statement::If { then_block, else_if_blocks, else_block, .. } => {
                    walk(then_block, out, poisoned);
                    for (_, block) in else_if_blocks {
                        walk(block, out, poisoned);
                    }
                    if let Some(block) = else_block {
                        walk(block, out, poisoned);
                    }
                }
                Statement::While { body, .. }
                | Statement::ForRange { body, .. }
                | Statement::ForEach { body, .. }
                | Statement::Repeat { body, .. } => {
                    walk(body, out, poisoned);
                }
                Statement::OnError { actions } => {
                    walk(actions, out, poisoned);
                }
                Statement::FunctionDef { .. } => {}
                _ => {}
            }
        }
    }

    walk(stmts, &mut out, &mut poisoned);
    out
}

/// Every list name whose element types this file cannot pin down from its
/// declaration alone — because something in the program can still change,
/// replace, or share the elements after that declaration (bug #54).
///
/// The analyzer proves a list's element type from a homogeneous literal
/// initializer (`a list called counts is [1, 2].`) and refuses a read of
/// an element into a variable of a different type. That proof is only
/// sound while nothing widens the list afterwards, so every name reachable
/// by a widening or aliasing move is collected here and the proof is
/// simply not offered for it:
///
/// - `Append <value> to <list>` and `Set element N of <list> to <value>`
///   write an element directly, of any type.
/// - `<list> is <value>.` replaces the whole list.
/// - a name used as a call argument escapes into a body that can append
///   to it (lists are heap objects passed by reference).
/// - a name copied into or out of another variable (`a list called other
///   is counts.`) makes two names for one heap object, so an append
///   through either widens both — both ends of the copy are collected.
///
/// Deliberately name-keyed and whole-program, with no scoping and no
/// type-awareness: a widening move anywhere disables the proof
/// everywhere, including for an unrelated local of the same name. That is
/// the safe direction — the cost is a missed diagnostic, never a false
/// one — and it makes the answer independent of statement order, which a
/// proof consulted mid-walk would otherwise depend on.
///
/// Unlike `collect_definite_decls`/`collect_all_typed_decls`, this DOES
/// descend into function bodies: a list appended to inside a function is
/// widened by that append no matter whose name reached it.
pub fn collect_widened_lists(stmts: &[Statement]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    walk_widened_lists(stmts, &mut out);
    out
}

/// True if any function in the program widens a list it was HANDED - it
/// appends to, or element-sets, one of its own parameters.
///
/// This is the one widening move `collect_widened_lists` cannot attribute
/// to a name: the append is written against the parameter, and the call
/// that passes the caller's list may sit in an expression position the
/// scan does not reach. A function that appends to a list by its own
/// global name is a different case and IS attributed, since that append
/// names the list directly.
///
/// The analyzer's answer to this is blunt on purpose: while it is true, no
/// list anywhere gets an element-type proof. Losing a diagnostic in a
/// program that has such a helper costs nothing; offering a proof that a
/// call could have invalidated would cost a false rejection.
pub fn any_function_widens_a_parameter(stmts: &[Statement]) -> bool {
    fn body_widens(body: &[Statement], params: &std::collections::HashSet<&str>) -> bool {
        body.iter().any(|stmt| match stmt {
            Statement::ListAppend { list, .. } | Statement::ElementSet { list, .. } => {
                params.contains(list.as_str())
            }
            Statement::If { then_block, else_if_blocks, else_block, .. } => {
                body_widens(then_block, params)
                    || else_if_blocks.iter().any(|(_, b)| body_widens(b, params))
                    || else_block.as_ref().is_some_and(|b| body_widens(b, params))
            }
            Statement::While { body, .. }
            | Statement::ForRange { body, .. }
            | Statement::ForEach { body, .. }
            | Statement::Repeat { body, .. } => body_widens(body, params),
            Statement::OnError { actions } => body_widens(actions, params),
            _ => false,
        })
    }

    stmts.iter().any(|stmt| match stmt {
        Statement::FunctionDef { params, body, .. } => {
            let names: std::collections::HashSet<&str> =
                params.iter().map(|(n, _)| n.as_str()).collect();
            body_widens(body, &names)
        }
        _ => false,
    })
}

fn walk_widened_lists(stmts: &[Statement], out: &mut std::collections::HashSet<String>) {
    fn note_alias(expr: &Expr, out: &mut std::collections::HashSet<String>) {
        if let Expr::Identifier(n) = expr {
            out.insert(n.clone());
        }
    }

    fn note_call_args(expr: &Expr, out: &mut std::collections::HashSet<String>) {
        // Only a call's own arguments matter here: an identifier anywhere
        // else in an expression is a read, and a read cannot widen. The
        // walk still has to reach nested calls, so it recurses through the
        // expression shapes that can contain one.
        match expr {
            Expr::FunctionCall { args, .. } => {
                for arg in args {
                    note_alias(arg, out);
                    note_call_args(arg, out);
                }
            }
            Expr::BinaryOp { left, right, .. } => {
                note_call_args(left, out);
                note_call_args(right, out);
            }
            Expr::UnaryOp { operand, .. } => note_call_args(operand, out),
            Expr::Cast { value, .. } | Expr::TreatingAs { value, .. } => note_call_args(value, out),
            Expr::ListLit { elements } => {
                for e in elements {
                    note_call_args(e, out);
                }
            }
            Expr::MapLit { pairs } => {
                for (k, v) in pairs {
                    note_call_args(k, out);
                    note_call_args(v, out);
                }
            }
            Expr::ElementAccess { list, index } | Expr::ListAccess { list, index } => {
                note_call_args(list, out);
                note_call_args(index, out);
            }
            Expr::FormatString { parts } => {
                for part in parts {
                    if let FormatPart::Expression { expr, .. } = part {
                        note_call_args(expr, out);
                    }
                }
            }
            _ => {}
        }
    }

    for stmt in stmts {
        match stmt {
            Statement::ListAppend { list, value } => {
                out.insert(list.clone());
                note_call_args(value, out);
            }
            Statement::ElementSet { list, index, value } => {
                out.insert(list.clone());
                note_call_args(index, out);
                note_call_args(value, out);
            }
            Statement::Assignment { name, value } => {
                out.insert(name.clone());
                note_alias(value, out);
                note_call_args(value, out);
            }
            Statement::VarDecl { value: Some(value), .. } => {
                note_alias(value, out);
                note_call_args(value, out);
            }
            Statement::Return { value: Some(value), .. } => {
                // A returned list leaves with the callee's name and comes
                // back under the caller's; the copy is an alias like any
                // other.
                note_alias(value, out);
                note_call_args(value, out);
            }
            Statement::FunctionCall { args, .. } => {
                for arg in args {
                    note_alias(arg, out);
                    note_call_args(arg, out);
                }
            }
            Statement::If { condition, then_block, else_if_blocks, else_block } => {
                note_call_args(condition, out);
                walk_widened_lists(then_block, out);
                for (cond, block) in else_if_blocks {
                    note_call_args(cond, out);
                    walk_widened_lists(block, out);
                }
                if let Some(block) = else_block {
                    walk_widened_lists(block, out);
                }
            }
            Statement::While { body, .. }
            | Statement::ForRange { body, .. }
            | Statement::ForEach { body, .. }
            | Statement::Repeat { body, .. }
            | Statement::FunctionDef { body, .. } => {
                walk_widened_lists(body, out);
            }
            Statement::OnError { actions } => {
                walk_widened_lists(actions, out);
            }
            Statement::Print { value, .. } => {
                note_call_args(value, out);
            }
            _ => {}
        }
    }
}
