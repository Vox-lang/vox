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
    collect_definite_decls_inner(stmts).kinds
}

/// One statement sequence's definite declarations, plus the two facts the
/// merge of an if/otherwise chain needs in order to stay faithful: which
/// names were poisoned, and which are held only by a write that named no
/// type.
struct DefiniteDecls {
    kinds: std::collections::HashMap<String, DefiniteDeclKind>,
    // A name whose recognised declarations disagree on kind (e.g. `a text
    // called src is "hello".` followed later by `open ... called src`,
    // which this walk would otherwise see as `Plain` then `File`) is
    // poisoned: removed from `kinds` and never re-added, rather than letting
    // whichever declaration is scanned last silently win. That "last write
    // wins" used to pre-register the *later* kind (into
    // buffer_variables/list_variables/map_variables/file_variables) before
    // the analyzer's own per-statement, declaration-order-respecting
    // type-immutability check ever ran - masking the real conflict instead
    // of surfacing it (plan 294 finding 3). A poisoned name is simply
    // absent from the definite-decl map; the analyzer's linear walk still
    // sees and rejects the conflict when it reaches the second occurrence,
    // it just does so without this pre-pass having pre-judged the type.
    poisoned: std::collections::HashSet<String>,
    // Names in `kinds` that only ever arrived through a write naming no
    // type. Such a write claims no kind, so a real declaration of the same
    // name always overrides it and never collides with it.
    untyped: std::collections::HashSet<String>,
}

impl DefiniteDecls {
    fn new() -> Self {
        DefiniteDecls {
            kinds: std::collections::HashMap::new(),
            poisoned: std::collections::HashSet::new(),
            untyped: std::collections::HashSet::new(),
        }
    }

    /// Record a declaration that names its type.
    fn record(&mut self, name: &str, kind: DefiniteDeclKind) {
        if self.poisoned.contains(name) {
            return;
        }
        match self.kinds.get(name) {
            Some(existing) if *existing != kind => {
                // A name an untyped write put here was never a claim about
                // its kind, so the declaration simply takes it over. Two
                // declarations that disagree are the real conflict.
                if self.untyped.remove(name) {
                    self.kinds.insert(name.to_string(), kind);
                } else {
                    self.kinds.remove(name);
                    self.poisoned.insert(name.to_string());
                }
            }
            _ => {
                self.untyped.remove(name);
                self.kinds.insert(name.to_string(), kind);
            }
        }
    }

    /// Record a write that names no type - `Set xs to ["a"].` at top level.
    /// `xs is <value>.`, `the xs is <value>.` and `Set xs to <value>.` are
    /// three spellings of one write, checked the same way (LANGUAGE.md,
    /// "Type Immutability"); the first two parse as an assignment and never
    /// reach this walk, so the third must not be read as a competing
    /// declaration either. Reading it as one used to collide with the
    /// `List`/`Map`/`Buffer` the real declaration recorded and poison the
    /// name, which stopped a global collection from being a global at all
    /// (docs/BUGS_FOUND.md #92).
    ///
    /// It still registers a name nothing else declares, because `Set count
    /// to 5.` on a fresh name brings `count` into being.
    fn record_untyped_write(&mut self, name: &str) {
        if self.poisoned.contains(name) || self.kinds.contains_key(name) {
            return;
        }
        self.kinds.insert(name.to_string(), DefiniteDeclKind::Plain);
        self.untyped.insert(name.to_string());
    }

    /// Keep only what this sequence and `other` both declare, under the same
    /// kind - the intersection an if/otherwise chain's branches make. A name
    /// stays untyped only while every branch left it untyped.
    fn intersect_with(&mut self, other: &DefiniteDecls) {
        self.kinds
            .retain(|name, kind| other.kinds.get(name) == Some(kind));
        let still_untyped: std::collections::HashSet<String> = self
            .untyped
            .iter()
            .filter(|name| {
                self.kinds.contains_key(name.as_str()) && other.untyped.contains(name.as_str())
            })
            .cloned()
            .collect();
        self.untyped = still_untyped;
    }
}

fn collect_definite_decls_inner(stmts: &[Statement]) -> DefiniteDecls {
    let mut decls = DefiniteDecls::new();

    for stmt in stmts {
        match stmt {
            Statement::VarDecl { name, var_type, .. } => match var_type {
                Some(Type::Buffer) => decls.record(name, DefiniteDeclKind::Buffer),
                Some(Type::List(_)) => decls.record(name, DefiniteDeclKind::List),
                Some(Type::Map(_)) => decls.record(name, DefiniteDeclKind::Map),
                Some(_) => decls.record(name, DefiniteDeclKind::Plain),
                None => decls.record_untyped_write(name),
            },
            Statement::BufferDecl { name, .. } => {
                decls.record(name, DefiniteDeclKind::Buffer);
            }
            Statement::Allocate { name, .. } | Statement::TimerDecl { name } => {
                decls.record(name, DefiniteDeclKind::Plain);
            }
            Statement::FileOpen { name, .. } => {
                decls.record(name, DefiniteDeclKind::File);
            }
            Statement::GetTime { into } => {
                decls.record(into, DefiniteDeclKind::Plain);
            }
            Statement::If { then_block, else_if_blocks, else_block: Some(else_block), .. } => {
                let mut definite = collect_definite_decls_inner(then_block);
                for (_, block) in else_if_blocks {
                    definite.intersect_with(&collect_definite_decls_inner(block));
                }
                definite.intersect_with(&collect_definite_decls_inner(else_block));
                for (name, kind) in &definite.kinds {
                    if definite.untyped.contains(name) {
                        decls.record_untyped_write(name);
                    } else {
                        decls.record(name, *kind);
                    }
                }
            }
            _ => {}
        }
    }

    decls
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

/// Every function definition hidden inside `stmt`'s own block bodies, at any
/// depth, in source order. `stmt` itself is never included - the caller has
/// already seen it.
///
/// A `To` written while a clause is still open is parsed into that clause's
/// body: the termination rule (LANGUAGE.md, "The termination rule") names a
/// period and a blank line as the closers, and a definition is a statement
/// like any other. Codegen then compiles that definition perfectly well - a
/// `FunctionDef` is emitted into `functions_section` wherever the walk meets
/// it - but every pre-pass that answers "what is this function's signature?"
/// scanned the top-level list flat and so never saw it. A call was compiled
/// against an empty signature, which spells "every parameter is one word":
/// a `value` parameter's tag word was never pushed and the callee read its
/// tag from a register the caller never wrote (bug #73).
///
/// Paired with a scan of the top-level list, this is the ONE answer to
/// "which statements define a function". A new pre-pass that needs that
/// answer should use both halves rather than growing a fourth flat scan.
pub fn nested_function_defs(stmt: &Statement) -> Vec<&Statement> {
    let mut out = Vec::new();
    walk_nested_function_defs(stmt, &mut out);
    out
}

fn walk_nested_function_defs<'a>(stmt: &'a Statement, out: &mut Vec<&'a Statement>) {
    fn walk<'a>(stmts: &'a [Statement], out: &mut Vec<&'a Statement>) {
        for stmt in stmts {
            if matches!(stmt, Statement::FunctionDef { .. }) {
                out.push(stmt);
            }
            // A definition can be nested inside another definition's body,
            // so the descent continues through a `FunctionDef` too.
            walk_nested_function_defs(stmt, out);
        }
    }
    match stmt {
        Statement::If { then_block, else_if_blocks, else_block, .. } => {
            walk(then_block, out);
            for (_, block) in else_if_blocks {
                walk(block, out);
            }
            if let Some(block) = else_block {
                walk(block, out);
            }
        }
        Statement::While { body, .. }
        | Statement::ForRange { body, .. }
        | Statement::ForEach { body, .. }
        | Statement::Repeat { body, .. }
        | Statement::FunctionDef { body, .. } => walk(body, out),
        Statement::OnError { actions } => walk(actions, out),
        _ => {}
    }
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

/// Every map name some statement in the program can insert a key INTO -
/// `Set m's "k" to <value>.`, which is `Statement::MapSet`.
///
/// Bug #72 needs to know whether a map's key set is still the one its
/// declaration literal wrote, because an absent key is what makes a read
/// yield the number 0 (LANGUAGE.md:2429) rather than a value of the map's
/// type. One `Set` anywhere can put the very key a read asks for into the
/// map, so a name in this set gets no key-set proof at all.
///
/// Aliasing is deliberately NOT collected here.
/// `collect_widened_lists` above already collects every name copied into
/// or out of another variable, returned, or handed to a call - that walk
/// is name-keyed and type-blind, so it catches an aliased map too - and
/// the analyzer requires a name to be absent from BOTH sets before it
/// offers the proof.
///
/// Name-keyed and whole-program in exactly the sense
/// `collect_widened_lists` is, and for the same reason: a read early in
/// the file must get the same answer as one written after the `Set`.
pub fn collect_map_key_writers(stmts: &[Statement]) -> std::collections::HashSet<String> {
    fn walk(stmts: &[Statement], out: &mut std::collections::HashSet<String>) {
        for stmt in stmts {
            match stmt {
                Statement::MapSet { map, .. } => {
                    out.insert(map.clone());
                }
                Statement::If { then_block, else_if_blocks, else_block, .. } => {
                    walk(then_block, out);
                    for (_, block) in else_if_blocks {
                        walk(block, out);
                    }
                    if let Some(block) = else_block {
                        walk(block, out);
                    }
                }
                Statement::While { body, .. }
                | Statement::ForRange { body, .. }
                | Statement::ForEach { body, .. }
                | Statement::Repeat { body, .. }
                | Statement::FunctionDef { body, .. } => walk(body, out),
                Statement::OnError { actions } => walk(actions, out),
                _ => {}
            }
        }
    }

    let mut out = std::collections::HashSet::new();
    walk(stmts, &mut out);
    out
}

/// True if any function in the program inserts a key into a map it was
/// HANDED - `Set <one of my own parameters>'s "k" to <value>.`
///
/// The map half of `any_function_widens_a_parameter`, blunt for the same
/// reason: the `Set` names the parameter, and the call that passed the
/// caller's map may sit in an expression position no scan reaches. While
/// this is true, no map anywhere gets a key-set proof. The cost is a
/// diagnostic in a program that has such a helper; the alternative is a
/// proof a call could have invalidated (bug #72).
/// Bug #72: the shape every literal collection declaration writes - a map
/// literal's key set, a list literal's length - for the names where that
/// shape is unambiguous.
///
/// A name is offered ONLY if the whole program declares it exactly once.
/// Two declarations mean two shapes, and which one is live at a read
/// depends on control flow this walk does not follow: a function defined
/// above a second declaration of the same global reads whichever map the
/// call site left in the slot, not the one textually above it. Taking the
/// most recent declaration's word for it turns the absence proof from a
/// missed diagnostic into a WRONG one - it would accept a text read into a
/// number and print an address. So the proof is withheld instead, the same
/// "can't prove it, allow it" policy as the rest of this family.
///
/// Filled once, BEFORE the analyzer's walk, for the reason
/// `collect_widened_lists` is filled before it: a read must get the same
/// answer wherever in the file it sits.
///
/// A map literal whose keys are not all string literals answers no key set
/// at all - a `"{k}"` key is dynamic, so the set would be incomplete and no
/// key could be proven absent from it. A list literal always answers its
/// length, mixed elements included: a length is provable whether or not the
/// elements share a type.
pub fn collect_literal_collection_shapes(
    stmts: &[Statement],
) -> (
    std::collections::HashMap<String, std::collections::HashSet<String>>,
    std::collections::HashMap<String, usize>,
) {
    use std::collections::{HashMap, HashSet};

    fn walk(
        stmts: &[Statement],
        counts: &mut HashMap<String, usize>,
        keys: &mut HashMap<String, HashSet<String>>,
        lens: &mut HashMap<String, usize>,
    ) {
        for stmt in stmts {
            match stmt {
                Statement::VarDecl { name, value, .. } => {
                    *counts.entry(name.clone()).or_insert(0) += 1;
                    match value {
                        Some(Expr::MapLit { pairs }) => {
                            let mut set = HashSet::new();
                            let every_key_is_literal = pairs.iter().all(|(k, _)| match k {
                                Expr::StringLit(key) => {
                                    set.insert(key.clone());
                                    true
                                }
                                _ => false,
                            });
                            if every_key_is_literal {
                                keys.insert(name.clone(), set);
                            }
                        }
                        Some(Expr::ListLit { elements }) => {
                            lens.insert(name.clone(), elements.len());
                        }
                        _ => {}
                    }
                }
                Statement::If { then_block, else_if_blocks, else_block, .. } => {
                    walk(then_block, counts, keys, lens);
                    for (_, block) in else_if_blocks {
                        walk(block, counts, keys, lens);
                    }
                    if let Some(block) = else_block {
                        walk(block, counts, keys, lens);
                    }
                }
                Statement::While { body, .. }
                | Statement::ForRange { body, .. }
                | Statement::ForEach { body, .. }
                | Statement::Repeat { body, .. }
                | Statement::FunctionDef { body, .. } => walk(body, counts, keys, lens),
                Statement::OnError { actions } => walk(actions, counts, keys, lens),
                _ => {}
            }
        }
    }

    let mut counts = HashMap::new();
    let mut keys = HashMap::new();
    let mut lens = HashMap::new();
    walk(stmts, &mut counts, &mut keys, &mut lens);
    keys.retain(|name, _| counts.get(name) == Some(&1));
    lens.retain(|name, _| counts.get(name) == Some(&1));
    (keys, lens)
}

pub fn any_function_writes_a_map_parameter(stmts: &[Statement]) -> bool {
    fn body_writes(body: &[Statement], params: &std::collections::HashSet<&str>) -> bool {
        body.iter().any(|stmt| match stmt {
            Statement::MapSet { map, .. } => params.contains(map.as_str()),
            Statement::If { then_block, else_if_blocks, else_block, .. } => {
                body_writes(then_block, params)
                    || else_if_blocks.iter().any(|(_, b)| body_writes(b, params))
                    || else_block.as_ref().is_some_and(|b| body_writes(b, params))
            }
            Statement::While { body, .. }
            | Statement::ForRange { body, .. }
            | Statement::ForEach { body, .. }
            | Statement::Repeat { body, .. } => body_writes(body, params),
            Statement::OnError { actions } => body_writes(actions, params),
            _ => false,
        })
    }

    stmts.iter().any(|stmt| match stmt {
        Statement::FunctionDef { params, body, .. } => {
            let names: std::collections::HashSet<&str> =
                params.iter().map(|(n, _)| n.as_str()).collect();
            body_writes(body, &names)
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

/// Every text variable name whose `Set`/declaration codegen may free the
/// string it replaces (docs/BUGS_FOUND.md #108): declared ONLY EVER as `a
/// text called <name> is ...` anywhere in the program (never a buffer, a
/// `value`, a function parameter, or a for-each/for-range loop variable -
/// each of those poisons the name out, the same idea `collect_all_typed_decls`
/// uses for a redeclared type), and never read anywhere in a position that
/// could keep the string alive past this variable's next `Set` - the RHS of
/// another variable's declaration or assignment, a function argument,
/// `Return`, an append to a LIST (a buffer append merely copies bytes and is
/// not collected), a map key or value, or a list/map literal element.
///
/// Deliberately name-keyed, whole-program, and flow-insensitive, in exactly
/// `collect_widened_lists`'s sense and for the same reason: one retaining
/// read anywhere disables freeing for that name EVERYWHERE, including at a
/// `Set` that executes before the retaining read ever runs. The cost is a
/// missed free; offering one anyway would risk a use-after-free, which is
/// worse than the leak this fix exists to close (master's ruling,
/// docs/BUGS_FOUND.md #108).
///
/// A read inside a format string's `{name}` interpolation is NOT collected -
/// that read copies bytes into the format's own fresh buffer and never keeps
/// `name`'s pointer beyond the interpolation, matching LANGUAGE.md's "each
/// evaluation allocates a new string". A retaining construct found INSIDE an
/// interpolated *expression* (`{expr}`) still counts, because whatever THAT
/// sub-expression passes on can retain independently of the interpolation
/// around it - see `find_nested_retains`'s `FormatString` arm.
pub fn collect_freeable_texts(stmts: &[Statement]) -> std::collections::HashSet<String> {
    use std::collections::HashSet;

    fn poison(candidates: &mut HashSet<String>, poisoned: &mut HashSet<String>, name: &str) {
        candidates.remove(name);
        poisoned.insert(name.to_string());
    }

    fn note_candidate(candidates: &mut HashSet<String>, poisoned: &mut HashSet<String>, name: &str) {
        if !poisoned.contains(name) {
            candidates.insert(name.to_string());
        }
    }

    // A bare identifier read in a retaining slot stays retaining for good,
    // whatever it turns out to name - a non-candidate name costs nothing
    // extra in the final set difference. Also walks the expression for any
    // retaining construct nested deeper inside it.
    fn mark_retaining(expr: &Expr, retaining: &mut HashSet<String>) {
        if let Expr::Identifier(n) = expr {
            retaining.insert(n.clone());
        }
        find_nested_retains(expr, retaining);
    }

    // Recurse for a retaining use buried inside an otherwise consuming
    // position - e.g. `Print 'keep' with a.` calls `'keep'` with `a` as
    // its own (retaining) argument, even though `Print`'s own operand
    // position is safe. `FormatString`'s `Variable` parts (plain `{name}`
    // interpolation) are deliberately not visited at all: that read has no
    // nested expression and never retains.
    fn find_nested_retains(expr: &Expr, retaining: &mut HashSet<String>) {
        match expr {
            Expr::FunctionCall { args, .. } => {
                for a in args {
                    mark_retaining(a, retaining);
                }
            }
            Expr::ListLit { elements } => {
                for e in elements {
                    mark_retaining(e, retaining);
                }
            }
            Expr::MapLit { pairs } => {
                for (k, v) in pairs {
                    mark_retaining(k, retaining);
                    mark_retaining(v, retaining);
                }
            }
            Expr::BinaryOp { left, right, .. } => {
                find_nested_retains(left, retaining);
                find_nested_retains(right, retaining);
            }
            Expr::UnaryOp { operand, .. } => find_nested_retains(operand, retaining),
            Expr::Range { start, end, .. } => {
                find_nested_retains(start, retaining);
                find_nested_retains(end, retaining);
            }
            Expr::PropertyCheck { value, .. }
            | Expr::TypeCheck { value, .. }
            | Expr::DurationCast { value, .. }
            | Expr::ArgumentHas { value }
            | Expr::EnvironmentVariable { name: value }
            | Expr::EnvironmentVariableAt { index: value }
            | Expr::EnvironmentVariableExists { name: value }
            | Expr::FileAvailable { path: value }
            | Expr::ArgumentAt { index: value } => find_nested_retains(value, retaining),
            // `<value> as text` on an ALREADY-text `value` is a bare pointer
            // pass-through in codegen (`generate_expr`'s Cast/String branch
            // leaves a text source untouched - see `text_write_is_owned`'s
            // doc comment) - so the result can be `value`'s own pointer,
            // unmodified, handed to whatever this Cast sits inside. Marking
            // a non-text (number/float/boolean/buffer) operand costs
            // nothing: those are never `freeable_texts` candidates, and a
            // buffer source really does get copied fresh by
            // `emit_buffer_to_text_copy`, so over-marking it is only ever
            // conservative, never a missed catch. Found the hard way
            // (docs/BUGS_FOUND.md #108's own review): a bare
            // `find_nested_retains(value, ...)` here recursed but never
            // inserted the bare-`Identifier` case into `retaining`, so
            // `a text called u is src as text.` left `src` freeable and its
            // next `Set` freed the string `u` still pointed at.
            Expr::Cast { value, .. } => mark_retaining(value, retaining),
            Expr::TreatingAs { value, match_value, replacement } => {
                // `codegen/expr.rs`'s `Expr::TreatingAs` arm: the "no match"
                // path pops and keeps `value`'s own computed pointer
                // unchanged, and the "match" path evaluates and keeps
                // `replacement`'s own pointer unchanged - neither is ever a
                // fresh copy. `match_value` is only ever compared
                // (`_str_eq`/`_mem_eq`/a register `cmp`) and never becomes
                // part of the result, so it stays a consuming read.
                mark_retaining(value, retaining);
                find_nested_retains(match_value, retaining);
                mark_retaining(replacement, retaining);
            }
            Expr::ByteAccess { buffer, index } => {
                find_nested_retains(buffer, retaining);
                find_nested_retains(index, retaining);
            }
            // `list` is type-constrained to a List, never a `freeable_texts`
            // candidate itself, so `mark_retaining` over `find_nested_retains`
            // costs nothing here either - defensive, in case that constraint
            // is ever looser than assumed.
            Expr::ElementAccess { list, index } | Expr::ListAccess { list, index } => {
                mark_retaining(list, retaining);
                find_nested_retains(index, retaining);
            }
            Expr::MapAccess { key, .. } => find_nested_retains(key, retaining),
            Expr::ReapChild { pid: Some(pid), .. } => find_nested_retains(pid, retaining),
            Expr::FormatString { parts } => {
                for part in parts {
                    if let FormatPart::Expression { expr, .. } = part {
                        find_nested_retains(expr, retaining);
                    }
                }
            }
            _ => {}
        }
    }

    // Any name ever declared or bound as a Buffer, whole-program - the one
    // piece of type information this otherwise type-blind scan needs, to
    // tell a byte-consuming `append <it> to <buffer>` from a retaining
    // `append <it> to <list>` (both parse to the same `ListAppend`).
    fn buffer_names(stmts: &[Statement], out: &mut HashSet<String>) {
        for stmt in stmts {
            match stmt {
                Statement::VarDecl { name, var_type: Some(Type::Buffer), .. } => {
                    out.insert(name.clone());
                }
                Statement::BufferDecl { name, .. } => {
                    out.insert(name.clone());
                }
                Statement::FunctionDef { params, body, .. } => {
                    for (p, t) in params {
                        if matches!(t, Type::Buffer) {
                            out.insert(p.clone());
                        }
                    }
                    buffer_names(body, out);
                }
                Statement::If { then_block, else_if_blocks, else_block, .. } => {
                    buffer_names(then_block, out);
                    for (_, b) in else_if_blocks {
                        buffer_names(b, out);
                    }
                    if let Some(b) = else_block {
                        buffer_names(b, out);
                    }
                }
                Statement::While { body, .. }
                | Statement::ForRange { body, .. }
                | Statement::ForEach { body, .. }
                | Statement::Repeat { body, .. } => buffer_names(body, out),
                Statement::OnError { actions } => buffer_names(actions, out),
                _ => {}
            }
        }
    }

    fn walk(
        stmts: &[Statement],
        candidates: &mut HashSet<String>,
        poisoned: &mut HashSet<String>,
        retaining: &mut HashSet<String>,
        buffers: &HashSet<String>,
    ) {
        for stmt in stmts {
            match stmt {
                Statement::VarDecl { name, var_type, value } => {
                    match var_type {
                        Some(Type::String) => note_candidate(candidates, poisoned, name),
                        Some(_) => poison(candidates, poisoned, name),
                        // An untyped `Set`/`the ... is` landing here (no
                        // local, no global mirror yet): its type was fixed
                        // by whichever declaration brought it into being,
                        // which this scan visits separately.
                        None => {}
                    }
                    if let Some(v) = value {
                        mark_retaining(v, retaining);
                    }
                }
                Statement::BufferDecl { name, .. } => {
                    poison(candidates, poisoned, name);
                }
                Statement::Assignment { value, .. } => {
                    mark_retaining(value, retaining);
                }
                Statement::SetThingField { value, .. } => {
                    mark_retaining(value, retaining);
                }
                Statement::ValueRetype { name, .. } => {
                    poison(candidates, poisoned, name);
                }
                Statement::Return { value: Some(v), .. } => {
                    mark_retaining(v, retaining);
                }
                Statement::FunctionCall { args, .. } => {
                    for a in args {
                        mark_retaining(a, retaining);
                    }
                }
                Statement::ListAppend { list, value } => {
                    if buffers.contains(list) {
                        find_nested_retains(value, retaining);
                    } else {
                        mark_retaining(value, retaining);
                    }
                }
                Statement::ElementSet { index, value, .. } => {
                    find_nested_retains(index, retaining);
                    mark_retaining(value, retaining);
                }
                Statement::MapSet { key, value, .. } => {
                    mark_retaining(key, retaining);
                    mark_retaining(value, retaining);
                }
                Statement::Allocate { name, size } => {
                    poison(candidates, poisoned, name);
                    find_nested_retains(size, retaining);
                }
                Statement::Free { name } => {
                    poison(candidates, poisoned, name);
                }
                Statement::FlagSchemaDecl { name, default, .. } => {
                    poison(candidates, poisoned, name);
                    if let Some(d) = default {
                        find_nested_retains(d, retaining);
                    }
                }
                Statement::FunctionDef { params, body, .. } => {
                    for (p, _) in params {
                        poison(candidates, poisoned, p);
                    }
                    walk(body, candidates, poisoned, retaining, buffers);
                }
                Statement::ForRange { variable, range, body } => {
                    poison(candidates, poisoned, variable);
                    find_nested_retains(range, retaining);
                    walk(body, candidates, poisoned, retaining, buffers);
                }
                Statement::ForEach { variable, collection, body } => {
                    poison(candidates, poisoned, variable);
                    find_nested_retains(collection, retaining);
                    walk(body, candidates, poisoned, retaining, buffers);
                }
                Statement::If { condition, then_block, else_if_blocks, else_block } => {
                    find_nested_retains(condition, retaining);
                    walk(then_block, candidates, poisoned, retaining, buffers);
                    for (c, b) in else_if_blocks {
                        find_nested_retains(c, retaining);
                        walk(b, candidates, poisoned, retaining, buffers);
                    }
                    if let Some(b) = else_block {
                        walk(b, candidates, poisoned, retaining, buffers);
                    }
                }
                Statement::While { condition, body } => {
                    find_nested_retains(condition, retaining);
                    walk(body, candidates, poisoned, retaining, buffers);
                }
                Statement::Repeat { count, body } => {
                    find_nested_retains(count, retaining);
                    walk(body, candidates, poisoned, retaining, buffers);
                }
                Statement::OnError { actions } => {
                    walk(actions, candidates, poisoned, retaining, buffers);
                }
                Statement::Print { value, .. } => {
                    find_nested_retains(value, retaining);
                }
                Statement::FileWrite { value, .. } => {
                    find_nested_retains(value, retaining);
                }
                Statement::Execute { path, args } => {
                    find_nested_retains(path, retaining);
                    mark_retaining(args, retaining);
                }
                Statement::Exit { code } => find_nested_retains(code, retaining),
                Statement::ByteSet { index, value, .. } => {
                    find_nested_retains(index, retaining);
                    find_nested_retains(value, retaining);
                }
                Statement::BufferCopy { source, .. } => find_nested_retains(source, retaining),
                Statement::FileOpen { path, .. } => find_nested_retains(path, retaining),
                Statement::FileSeekLine { line, .. } => find_nested_retains(line, retaining),
                Statement::FileSeekByte { byte, .. } => find_nested_retains(byte, retaining),
                Statement::FileDelete { path }
                | Statement::Rmdir { path }
                | Statement::Mkdir { path }
                | Statement::Chdir { path } => find_nested_retains(path, retaining),
                Statement::BufferResize { new_size, .. } => find_nested_retains(new_size, retaining),
                Statement::Wait { duration, .. } => find_nested_retains(duration, retaining),
                Statement::Symlink { target, linkpath } => {
                    find_nested_retains(target, retaining);
                    find_nested_retains(linkpath, retaining);
                }
                Statement::Mknod { path, major, minor, .. } => {
                    find_nested_retains(path, retaining);
                    find_nested_retains(major, retaining);
                    find_nested_retains(minor, retaining);
                }
                Statement::Mount { source, target, fstype, options } => {
                    find_nested_retains(source, retaining);
                    find_nested_retains(target, retaining);
                    find_nested_retains(fstype, retaining);
                    if let Some(o) = options {
                        find_nested_retains(o, retaining);
                    }
                }
                Statement::Unmount { target, .. } => find_nested_retains(target, retaining),
                Statement::PivotRoot { new_root, put_old } => {
                    find_nested_retains(new_root, retaining);
                    find_nested_retains(put_old, retaining);
                }
                Statement::SendSignal { signal, pid } => {
                    find_nested_retains(signal, retaining);
                    find_nested_retains(pid, retaining);
                }
                _ => {}
            }
        }
    }

    let mut candidates = HashSet::new();
    let mut poisoned = HashSet::new();
    let mut retaining = HashSet::new();
    let mut buffers = HashSet::new();
    buffer_names(stmts, &mut buffers);
    walk(stmts, &mut candidates, &mut poisoned, &mut retaining, &buffers);

    candidates.into_iter().filter(|n| !retaining.contains(n)).collect()
}

/// The bound a fixed buffer's size must satisfy: at least one byte, at most
/// 1 GiB (LANGUAGE.md, "Fixed-Size Buffers").
///
/// It is a memory-safety rule rather than a formatting one, so the two
/// numbers live here, once, where every site that can decide a size reads
/// the same pair: the parser for a literal it can see, the analyzer for a
/// named size it can prove, and codegen for the runtime guard on a size
/// nobody can prove (docs/BUGS_FOUND.md #78). Before #78 the bound existed
/// only in the parser's `Expr::IntegerLit` arm, so naming the size in a
/// variable walked straight past it.
pub const MIN_BUFFER_SIZE: i64 = 1;
pub const MAX_BUFFER_SIZE: i64 = 1024 * 1024 * 1024;

/// The integer this expression evaluates to, when the whole expression is
/// decidable without running the program - a literal, a negation, or the
/// three arithmetic operators whose answer on two integers is another
/// integer.
///
/// `None` means "not provable here", never "not an integer": `divide` and
/// `modulo` are deliberately absent (their answer on two integers is not
/// always one, LANGUAGE.md's Arithmetic section), and every operation is
/// checked, so an overflow answers `None` rather than a wrapped number
/// nobody wrote. Callers must treat `None` as "allow it" - the same
/// can't-prove-it-so-allow-it policy the analyzer's type checks use.
pub fn constant_integer(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::IntegerLit(n) => Some(*n),
        Expr::UnaryOp { op: UnaryOperator::Negate, operand } => {
            constant_integer(operand)?.checked_neg()
        }
        Expr::BinaryOp { left, op, right } => {
            let left = constant_integer(left)?;
            let right = constant_integer(right)?;
            match op {
                BinaryOperator::Add => left.checked_add(right),
                BinaryOperator::Subtract => left.checked_sub(right),
                BinaryOperator::Multiply => left.checked_mul(right),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Every name that holds one fixed integer for the whole program: declared
/// exactly once with an initializer `constant_integer` can evaluate, and
/// never written again anywhere in the file.
///
/// A single write - an assignment, an increment, a second declaration, a
/// loop variable, a parameter of that name - drops the name from the
/// answer entirely, whatever the write would have stored. That is the safe
/// direction, and it is why this is a whole-program pre-pass rather than
/// something tracked as the walk proceeds: a value tracked mid-walk would
/// be whatever the last branch happened to write, and a size proved from a
/// branch nobody may take would refuse a program that is legal on the
/// other path. Losing the proof costs a diagnostic; a wrong proof costs a
/// correct program (docs/BUGS_FOUND.md #78).
///
/// Like `collect_widened_lists`, this descends into function bodies: a
/// write is a write no matter whose name reached it.
pub fn collect_constant_numbers(stmts: &[Statement]) -> std::collections::HashMap<String, i64> {
    let mut declared: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
    walk_constant_numbers(stmts, &mut declared, &mut written);
    declared.retain(|name, _| !written.contains(name));
    declared
}

fn walk_constant_numbers(
    stmts: &[Statement],
    declared: &mut std::collections::HashMap<String, i64>,
    written: &mut std::collections::HashSet<String>,
) {
    for stmt in stmts {
        match stmt {
            Statement::VarDecl { name, var_type, value } => {
                // A second declaration of the same name is itself a write:
                // the two initializers can differ, and nothing here decides
                // which one a later read sees.
                if declared.contains_key(name) {
                    written.insert(name.clone());
                }
                match (var_type, value.as_ref().and_then(constant_integer)) {
                    (None | Some(Type::Integer), Some(n)) => {
                        declared.insert(name.clone(), n);
                    }
                    _ => {
                        written.insert(name.clone());
                    }
                }
            }
            Statement::Assignment { name, .. }
            | Statement::ValueRetype { name, .. }
            | Statement::Increment { name }
            | Statement::Decrement { name }
            | Statement::Allocate { name, .. }
            | Statement::BufferDecl { name, .. }
            | Statement::TimerDecl { name }
            | Statement::FileOpen { name, .. } => {
                written.insert(name.clone());
            }
            Statement::GetTime { into } => {
                written.insert(into.clone());
            }
            Statement::FlagSchemaDecl { name, .. } => {
                // A flag's value arrives from the command line at run time.
                written.insert(name.clone());
            }
            Statement::If { then_block, else_if_blocks, else_block, .. } => {
                walk_constant_numbers(then_block, declared, written);
                for (_, block) in else_if_blocks {
                    walk_constant_numbers(block, declared, written);
                }
                if let Some(block) = else_block {
                    walk_constant_numbers(block, declared, written);
                }
            }
            Statement::ForRange { variable, body, .. } => {
                written.insert(variable.clone());
                walk_constant_numbers(body, declared, written);
            }
            Statement::ForEach { variable, body, .. } => {
                written.insert(variable.clone());
                walk_constant_numbers(body, declared, written);
            }
            Statement::While { body, .. } | Statement::Repeat { body, .. } => {
                walk_constant_numbers(body, declared, written);
            }
            Statement::FunctionDef { params, body, .. } => {
                for (param, _) in params {
                    written.insert(param.clone());
                }
                walk_constant_numbers(body, declared, written);
            }
            Statement::OnError { actions } => {
                walk_constant_numbers(actions, declared, written);
            }
            _ => {}
        }
    }
}
