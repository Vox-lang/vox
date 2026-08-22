use super::*;

impl CodeGenerator {
    /// Pre-scan pass: walk the whole program and decide, before any code is
    /// emitted, which lists are heterogeneous ("mixed"). A list is mixed
    /// when its homogeneity cannot be *proven* — i.e. some write is of an
    /// `Unknowable` type, or two writes provably differ in type (a mixed
    /// list literal, or an append/element-set whose value's tag conflicts
    /// with the list's established element type).
    ///
    /// Stage 1b flipped the default: a value whose type can't be proven
    /// (e.g. a function result without a declared return type) widens the
    /// list to `Mixed` so elements are never silently reinterpreted. Lists
    /// whose every write is provably one type keep the untagged fast path.
    /// Aliasing a mixed list (`a list called b is the a.`) propagates
    /// mixedness.
    pub(crate) fn prescan_mixed_lists(&mut self, statements: &[Statement]) {
        // Iterate to a fixed point so aliases and later evidence propagate
        // regardless of declaration order. Termination: each pass only ever
        // *adds* to `mixed_lists`, which is bounded by the number of list
        // names, so the loop always converges.
        let mut env: HashMap<String, TagInfo> = HashMap::new();
        let mut list_seen_tags: HashMap<String, u8> = HashMap::new();
        loop {
            let before = self.mixed_lists.len();
            env.clear();
            list_seen_tags.clear();
            self.prescan_walk(statements, &mut env, &mut list_seen_tags);
            if self.mixed_lists.len() == before {
                // Converged. `env` now holds the final verdict per scalar;
                // carry the unprovable ones into codegen so emit-time tag
                // selection agrees with the pre-scan instead of trusting a
                // declared type that the initializer never established.
                self.unprovable_scalars = env
                    .iter()
                    .filter(|(_, info)| matches!(info, TagInfo::Unknowable))
                    .map(|(name, _)| name.clone())
                    .collect();
                break;
            }
        }
    }

    /// Join a write's `TagInfo` into a list's running element-type record.
    /// `Known(t)` conflicts with a different prior tag (or joins an
    /// established one); `Unknowable` widens the list straight to `Mixed`
    /// (the write's type can't be proven, so homogeneity can't be claimed).
    pub(crate) fn prescan_note_list_value(
        &mut self,
        list: &str,
        tag: TagInfo,
        list_seen_tags: &mut HashMap<String, u8>,
    ) {
        match tag {
            TagInfo::Known(t) => match list_seen_tags.get(list) {
                Some(prev) if *prev != t => {
                    self.mixed_lists.insert(list.to_string());
                }
                Some(_) => {}
                None => {
                    list_seen_tags.insert(list.to_string(), t);
                }
            },
            TagInfo::Unknowable => {
                self.mixed_lists.insert(list.to_string());
            }
        }
    }

    pub(crate) fn prescan_walk(
        &mut self,
        statements: &[Statement],
        env: &mut HashMap<String, TagInfo>,
        list_seen_tags: &mut HashMap<String, u8>,
    ) {
        for stmt in statements {
            match stmt {
                Statement::VarDecl { name, value, var_type, .. } => {
                    // A declared scalar type is a static proof of the slot tag
                    // and seeds `env` even when the initializer is opaque (e.g.
                    // `a buffer called b is 4 bytes in size.` — the size expr
                    // is unknowable, but the declared `buffer` type proves the
                    // tag is `TAG_STRING`, so appending it doesn't widen).
                    let declared_tag = var_type.as_ref().and_then(type_to_tag);
                    match value {
                        Some(Expr::ListLit { elements }) => {
                            let mut tags: Vec<u8> = Vec::new();
                            let mut unknowable = false;
                            for e in elements {
                                match self.prescan_expr_tag(e, env, list_seen_tags) {
                                    TagInfo::Known(t) => {
                                        if !tags.contains(&t) {
                                            tags.push(t);
                                        }
                                    }
                                    TagInfo::Unknowable => unknowable = true,
                                }
                            }
                            // A list holding `nothing` is treated as mixed even
                            // when every element is nothing: the fast path
                            // reads a slot without its tag, and a nothing slot
                            // read that way is indistinguishable from 0.
                            if unknowable || tags.len() > 1 || tags.contains(&TAG_NOTHING) {
                                self.mixed_lists.insert(name.clone());
                            } else if let Some(t) = tags.first() {
                                list_seen_tags.insert(name.clone(), *t);
                            }
                        }
                        // Alias: `a list called b is the a.` inherits
                        // mixedness (both names refer to the same block).
                        Some(Expr::Identifier(src)) | Some(Expr::StringLit(src)) => {
                            if self.mixed_lists.contains(src) {
                                self.mixed_lists.insert(name.clone());
                            } else if let Some(t) = list_seen_tags.get(src).copied() {
                                list_seen_tags.insert(name.clone(), t);
                            } else if let Some(t) = declared_tag {
                                env.insert(name.clone(), TagInfo::Known(t));
                            } else {
                                // Scalar alias with no declared scalar type:
                                // track its provability (Unknowable overwrites
                                // a prior Known, so a later reassignment taints).
                                let info = self.prescan_expr_tag(
                                    value.as_ref().unwrap(),
                                    env,
                                    list_seen_tags,
                                );
                                env.insert(name.clone(), info);
                            }
                        }
                        Some(other) => {
                            // The initializer decides, not the declaration: a
                            // declared type is the author's intent, while the
                            // tag must describe the bits that actually land in
                            // the slot. `a text called s is element 3 of m.`
                            // (m mixed) stores whatever element 3 holds, which
                            // may not be a string pointer - trusting `text`
                            // here would write TAG_STRING over an integer and
                            // make a tag-dispatching reader dereference it.
                            // (`a buffer called b is 4 bytes in size.` does
                            // not reach this arm; it parses to BufferDecl,
                            // handled below.)
                            let info = self.prescan_expr_tag(other, env, list_seen_tags);
                            env.insert(name.clone(), info);
                        }
                        None => {
                            // No initializer: nothing foreign has been stored,
                            // so the declared type does prove the slot's tag.
                            if let Some(t) = declared_tag {
                                env.insert(name.clone(), TagInfo::Known(t));
                            }
                        }
                    }
                }
                // A buffer (fixed-size `is N bytes in size` or `Create a
                // buffer`) appends as a string-tagged slot, so record it as
                // Known(TAG_STRING) — otherwise appending it would widen.
                Statement::BufferDecl { name, .. } => {
                    env.insert(name.clone(), TagInfo::Known(TAG_STRING));
                }
                Statement::Assignment { name, value } => {
                    if let Expr::ListLit { elements } = value {
                        let mut tags: Vec<u8> = Vec::new();
                        let mut unknowable = false;
                        for e in elements {
                            match self.prescan_expr_tag(e, env, list_seen_tags) {
                                TagInfo::Known(t) => {
                                    if !tags.contains(&t) {
                                        tags.push(t);
                                    }
                                }
                                TagInfo::Unknowable => unknowable = true,
                            }
                        }
                        if unknowable || tags.len() > 1 || tags.contains(&TAG_NOTHING) {
                            self.mixed_lists.insert(name.clone());
                        } else if let Some(t) = tags.first() {
                            self.prescan_note_list_value(
                                name,
                                TagInfo::Known(*t),
                                list_seen_tags,
                            );
                        }
                    } else {
                        let info = self.prescan_expr_tag(value, env, list_seen_tags);
                        env.insert(name.clone(), info);
                    }
                }
                // In-place `value` retyping does not change the prescan tag
                // facts: the variable stays `value`/Mixed at compile time.
                Statement::ValueRetype { .. } => {}
                Statement::ListAppend { list, value } => {
                    let tag = self.prescan_expr_tag(value, env, list_seen_tags);
                    self.prescan_note_list_value(list, tag, list_seen_tags);
                }
                Statement::ElementSet { list, value, .. } => {
                    let tag = self.prescan_expr_tag(value, env, list_seen_tags);
                    self.prescan_note_list_value(list, tag, list_seen_tags);
                }
                Statement::If { then_block, else_if_blocks, else_block, .. } => {
                    self.prescan_walk(then_block, env, list_seen_tags);
                    for (_, block) in else_if_blocks {
                        self.prescan_walk(block, env, list_seen_tags);
                    }
                    if let Some(block) = else_block {
                        self.prescan_walk(block, env, list_seen_tags);
                    }
                }
                Statement::ForEach { variable, collection, body } => {
                    // A provably-empty collection runs its body zero times, so
                    // skip it — otherwise `append each x from [] to L` would
                    // widen L even though nothing is appended.
                    if let Expr::ListLit { elements } = collection {
                        if elements.is_empty() {
                            continue;
                        }
                    }
                    // Seed the loop variable's proven tag from the collection
                    // so appends of it inside the body don't widen (e.g.
                    // `append each x from [10, 20, 30] to copied` keeps copied
                    // homogeneous). Save/restore so a shadowing outer variable
                    // isn't clobbered.
                    let elem_tag =
                        self.foreach_loop_var_tag(collection, env, list_seen_tags);
                    let saved = env.insert(variable.clone(), elem_tag);
                    self.prescan_walk(body, env, list_seen_tags);
                    match saved {
                        Some(prev) => {
                            env.insert(variable.clone(), prev);
                        }
                        None => {
                            env.remove(variable);
                        }
                    }
                }
                Statement::ForRange { variable, body, .. } => {
                    // Range elements are integers; seed the loop variable so
                    // `append each n from 1 to 5 to L` keeps L homogeneous.
                    // Save/restore so a shadowing outer variable isn't clobbered.
                    let saved = env.insert(variable.clone(), TagInfo::Known(TAG_INTEGER));
                    self.prescan_walk(body, env, list_seen_tags);
                    match saved {
                        Some(prev) => {
                            env.insert(variable.clone(), prev);
                        }
                        None => {
                            env.remove(variable);
                        }
                    }
                }
                Statement::While { body, .. }
                | Statement::Repeat { body, .. } => {
                    self.prescan_walk(body, env, list_seen_tags);
                }
                Statement::FunctionDef { name, params, body, .. } => {
                    // Walk the body on a SNAPSHOT of the global pre-scan state
                    // so this function's own locals never leak into the shared
                    // `env`/`mixed_lists` (and thence into other functions'
                    // analysis or the top-level `unprovable_scalars` set). Two
                    // functions can declare a same-named local with opposite
                    // verdicts — a proven map in one, an unprovable value in
                    // the other — and a flat global set cannot hold both, so
                    // each function's locals are partitioned out here and
                    // re-applied only during that function's own codegen.
                    let func_key = self.function_label(name);
                    let saved_env = env.clone();
                    let saved_list_seen_tags = list_seen_tags.clone();
                    let saved_mixed = self.mixed_lists.clone();
                    self.prescan_walk(body, env, list_seen_tags);
                    // The function's own locals: its parameters plus any names
                    // the body walk newly introduced into `env` (VarDecl
                    // locals; loop variables are save/restored by their arms
                    // and so do not persist as new keys here).
                    let mut fn_locals: std::collections::HashSet<String> =
                        params.iter().map(|(n, _)| n.clone()).collect();
                    for n in env.keys() {
                        if !saved_env.contains_key(n) {
                            fn_locals.insert(n.clone());
                        }
                    }
                    // Per-function unprovable scalars: locals the body left
                    // Unknowable. Globals keep the outer env's verdict.
                    let local_unprov: std::collections::HashSet<String> = env
                        .iter()
                        .filter(|(n, info)| {
                            matches!(info, TagInfo::Unknowable)
                                && fn_locals.contains(n.as_str())
                        })
                        .map(|(n, _)| n.clone())
                        .collect();
                    // Per-function mixed lists: locals the body marked
                    // heterogeneous (e.g. `append v to L` where `L` is a param).
                    let local_mixed: std::collections::HashSet<String> = self
                        .mixed_lists
                        .iter()
                        .filter(|n| {
                            !saved_mixed.contains(*n) && fn_locals.contains(n.as_str())
                        })
                        .cloned()
                        .collect();
                    // Globals the body marked mixed (e.g. `append v to g` on a
                    // top-level `g`) must stay in the shared set so the
                    // top-level sees `g` as mixed. Capture before restoring.
                    let added: Vec<String> = self
                        .mixed_lists
                        .difference(&saved_mixed)
                        .cloned()
                        .collect();
                    // Restore the global pre-scan state.
                    *env = saved_env;
                    *list_seen_tags = saved_list_seen_tags;
                    self.mixed_lists = saved_mixed;
                    for n in &added {
                        if !fn_locals.contains(n.as_str()) {
                            self.mixed_lists.insert(n.clone());
                        }
                    }
                    self.local_mixed_lists.insert(func_key.clone(), local_mixed);
                    self.local_unprovable_scalars.insert(func_key.clone(), local_unprov);
                    self.local_names.insert(func_key, fn_locals);
                }
                Statement::OnError { actions } => {
                    self.prescan_walk(actions, env, list_seen_tags);
                }
                // A `Library` declaration sets the identity for the function
                // definitions that follow it. The pre-scan classifies
                // FunctionCall results via `function_return_types`, keyed by
                // the mangled label, so `infer_expr_type` must see the SAME
                // library the call site sits in. The walk is in source order
                // and a `Library` precedes its functions, so setting the field
                // here (and again on each fixed-point pass) keeps it correct
                // as the walk enters each library's function bodies. This
                // mirrors the main generate walk's `LibraryDecl` arm.
                Statement::LibraryDecl { name, version } => {
                    self.current_library = Some((name.clone(), version.clone()));
                }
                _ => {}
            }
        }
    }

    /// Emit a print of the value in rdi dispatched on the runtime tag held
    /// in `tag_reg` (a full 64-bit register holding 0..=6).
    ///
    /// The spec-less form, for a `Print` with no format hole to carry one.
    pub(crate) fn emit_mixed_print_dispatch(&mut self, tag_reg: &str) {
        let plain = self.parse_format_spec(None);
        self.emit_mixed_print_dispatch_spec(tag_reg, plain);
    }

    /// The same dispatch, carrying the hole's format spec.
    ///
    /// `docs/BUGS_FOUND.md #81`, the composition half. #68 made a hole
    /// dispatch on the value's runtime tag, and its BUFFER twin
    /// (`emit_append_mixed_value_to_buffer_ptr`) already renders the integer
    /// branch through `emit_append_formatted_int_to_buffer(fmt)` - so
    /// `a text called t is "{element 1 of sizes:5}".` pads and always has.
    /// Print's twin took no spec at all and emitted a bare `PRINT_INT`, so
    /// the same hole printed straight to the terminal did not pad. That is
    /// the one sink LANGUAGE.md's "Format Strings Everywhere" promise was
    /// still missing, and #86's shape one type over.
    ///
    /// Only the INTEGER branch takes the spec, exactly as the buffer twin
    /// does: a tagged text has no width primitive and a tagged float has no
    /// float-padding primitive (#36's recorded residue), so both render by
    /// their tag and ignore the spec, and a list, a map and `nothing` render
    /// through their own routines.
    pub(crate) fn emit_mixed_print_dispatch_spec(&mut self, tag_reg: &str, fmt: FormatSpec) {
        let str_label = self.new_label("mixp_str");
        let flt_label = self.new_label("mixp_flt");
        let list_label = self.new_label("mixp_list");
        let map_label = self.new_label("mixp_map");
        let nothing_label = self.new_label("mixp_nothing");
        let done_label = self.new_label("mixp_done");
        self.emit_indent(&format!("cmp {}, {}  ; string tag?", tag_reg, TAG_STRING));
        self.emit_indent(&format!("je {}", str_label));
        self.emit_indent(&format!("cmp {}, {}  ; float tag?", tag_reg, TAG_FLOAT));
        self.emit_indent(&format!("je {}", flt_label));
        // A list element (tag 4): rdi already holds the child list pointer, so
        // recurse into `_list_print` (stage 1e1). The tag in `tag_reg` has
        // already been consumed by the comparisons above, so `_list_print`
        // clobbering r11/rax/etc. is safe.
        self.emit_indent(&format!("cmp {}, {}  ; list tag?", tag_reg, TAG_LIST));
        self.emit_indent(&format!("je {}", list_label));
        // A map element (tag 5, stage 1e2): rdi holds the child map pointer;
        // recurse into `_map_print`.
        self.emit_indent(&format!("cmp {}, {}  ; map tag?", tag_reg, TAG_MAP));
        self.emit_indent(&format!("je {}", map_label));
        // A nothing/null element (tag 6, stage 1e3): payload is 0 (unused),
        // so print the literal word `nothing` regardless of rdi.
        self.emit_indent(&format!("cmp {}, {}  ; nothing tag?", tag_reg, TAG_NOTHING));
        self.emit_indent(&format!("je {}", nothing_label));
        // Integer and boolean both print as numbers (matches homogeneous
        // boolean lists, which print 1/0 today) - through the formatter, so a
        // width or a radix written in the hole is honoured here exactly as it
        // is in the buffer twin (#81).
        self.emit_formatted_value(Some(VarType::Integer), fmt);
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", str_label));
        self.emit_indent("PRINT_CSTR rdi");
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", flt_label));
        self.emit_indent("movq xmm0, rdi");
        self.emit_indent("PRINT_FLOAT");
        self.uses_floats = true;
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", list_label));
        self.emit_indent("call _list_print  ; rdi = child list pointer");
        self.uses_lists = true;
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", map_label));
        self.emit_indent("call _map_print  ; rdi = child map pointer");
        self.uses_maps = true;
        self.emit_indent(&format!("jmp {}", done_label));
        self.emit(&format!("{}:", nothing_label));
        let nothing_str = self.add_string("nothing");
        self.emit_indent(&format!("PRINT_STR {}, {}_len", nothing_str, nothing_str));
        self.emit(&format!("{}:", done_label));
    }

    /// Whether a list-valued expression refers to a list whose elements are
    /// runtime-tagged (element reads must carry the runtime tag). A named
    /// mixed list is the base case; a read (element/first/last) from a mixed
    /// list yields a runtime-tagged value, so indexing it again is again a
    /// runtime-tagged read (chained access, stage 1e1); and a list literal is
    /// mixed iff its elements span more than one distinct tag (or any element
    /// is itself runtime-tagged).
    pub(crate) fn list_expr_is_mixed(&self, e: &Expr) -> bool {
        match e {
            Expr::Identifier(name) | Expr::StringLit(name) => {
                // A list whose element type the codegen cannot prove — a bare
                // `list` parameter, or any list with no recorded element type —
                // still stores a per-slot runtime tag for every element (both
                // `_list_append` and list-literal codegen always pass a tag, see
                // the `edx`/`mov byte` writes). Treat such a list as mixed for
                // reads so the tag is loaded into r11 instead of trusting a
                // static element type the slot never had. This is what lets a
                // `value` extracted from a list *parameter* carry the right tag.
                self.mixed_lists.contains(name)
                    || matches!(
                        self.list_element_types.get(name),
                        None | Some(&VarType::Mixed) | Some(&VarType::Unknown)
                    )
            }
            // Chained read: a read from a mixed list yields a runtime-tagged
            // value, so indexing that result is again a runtime-tagged read.
            // (PropertyAccess `first`/`last` takes a bare variable name, so
            // it cannot chain; it is handled by the name arm above.)
            Expr::ElementAccess { list, .. } => self.list_expr_is_mixed(list),
            // A list literal is mixed iff its elements span >1 distinct tag,
            // or any element is itself runtime-tagged (no static tag).
            Expr::ListLit { elements } => {
                let mut tags: Vec<u8> = Vec::new();
                for el in elements {
                    match self.emit_time_expr_tag(el) {
                        Some(t) => {
                            if !tags.contains(&t) {
                                tags.push(t);
                            }
                        }
                        None => return true,
                    }
                }
                tags.len() > 1
            }
            // `map's keys` and `map's values` both build fresh lists that store
            // a runtime type tag per slot (string for keys, the value's own tag
            // for values). Element access on the temporary must read that tag,
            // otherwise a chained read like `element 1 of m's values` treats the
            // loaded pointer as an untagged integer and prints garbage.
            Expr::PropertyAccess { property, .. }
                if matches!(property, ObjectProperty::Keys | ObjectProperty::Values) =>
            {
                true
            }
            _ => false,
        }
    }

    /// The type codegen statically believes a read out of `list` yields, or
    /// `None` when it cannot tell. `Some(VarType::Mixed)` means the elements
    /// are runtime-tagged and the tag in `r11` decides — every consumer of an
    /// element read (`generate_print`, and the miss paths in `generate_expr`)
    /// must agree on this answer, which is why it lives here rather than
    /// inline at each of them. (stage 1e1/1e2; extracted for #91.)
    pub(crate) fn static_list_element_type(&self, list: &Expr) -> Option<VarType> {
        if let Expr::Identifier(name) = list {
            // A list parameter (or any list with no proven element type)
            // stores a per-slot runtime tag, so the tag decides rather than a
            // static type the slot never had — see `list_expr_is_mixed`.
            match self.list_element_types.get(name) {
                None | Some(&VarType::Mixed) | Some(&VarType::Unknown) => Some(VarType::Mixed),
                Some(other) => Some(other.clone()),
            }
        } else if let Expr::ListLit { elements } = list {
            if self.list_expr_is_mixed(list) {
                Some(VarType::Mixed)
            } else if let Some(first) = elements.first() {
                match first {
                    Expr::IntegerLit(_) => Some(VarType::Integer),
                    Expr::FloatLit(_) => Some(VarType::Float),
                    Expr::StringLit(_) => Some(VarType::String),
                    // A format string always materializes text (bug #17);
                    // `element N of <literal>` on a list literal never
                    // carried that arm (bug #39).
                    Expr::FormatString { .. } => Some(VarType::String),
                    Expr::BoolLit(_) => Some(VarType::Boolean),
                    Expr::ListLit { .. } => Some(VarType::List),
                    Expr::MapLit { .. } => Some(VarType::Map),
                    _ => None,
                }
            } else {
                None
            }
        } else if self.list_expr_is_mixed(list) {
            Some(VarType::Mixed)
        } else {
            None
        }
    }

    /// Materialize a map key expression as a NUL-terminated text pointer in
    /// `rax`. A quoted key (`"name"`) is ALWAYS the literal text, even when a
    /// variable with that name exists — otherwise the key would silently
    /// become the variable's value (e.g. `{"inner": ...}` colliding with a
    /// later `a map called inner` stored the variable's pointer as the key
    /// and crashed `_map_print`'s C-string read). A non-literal key (a bare
    /// variable holding text) is evaluated normally. (stage 1e2)
    pub(crate) fn generate_text_key(&mut self, key: &Expr) {
        match key {
            Expr::StringLit(s) => {
                let label = self.add_string(s);
                self.emit_indent(&format!("lea rax, [rel {}]  ; literal map key", label));
            }
            _ => self.generate_expr(key),
        }
    }

}

/// `docs/BUGS_FOUND.md #91`: the type a **tagless** consumer will read a
/// fallible read's result as, when the compiler can name one.
///
/// A miss yields the number 0 at the read (LANGUAGE.md's "yields 0"), and a
/// destination with a declared type re-types it through
/// `emit_empty_value_if_missed`. A consumer with no declared destination -
/// `Print element 5 of names.`, a format hole holding the same read, an
/// `append` of it - has no slot to read the type from, so it reads the value
/// as the collection's own static element type. Where that type is a pointer,
/// this is what tells the consumer's guard which empty value to substitute.
///
/// `None` for a mixed or unprovable element type: there the runtime tag
/// travels with the value and every consumer dispatches on it, so the 0 is
/// read as the number it is.
impl CodeGenerator {
    pub(crate) fn tagless_read_type(&self, expr: &Expr) -> Option<VarType> {
        if !is_fallible_collection_read(expr) {
            return None;
        }
        let found = match expr {
            Expr::ElementAccess { list, .. } => self.static_list_element_type(list),
            Expr::PropertyAccess {
                object,
                property: ObjectProperty::First | ObjectProperty::Last,
                ..
            } => self.list_element_types.get(object).cloned(),
            _ => None,
        };
        match found {
            Some(VarType::String) | Some(VarType::List) | Some(VarType::Map) => found,
            _ => None,
        }
    }
}

/// `docs/BUGS_FOUND.md #91`: the reads that can MISS — an index outside the
/// list, a key the map does not hold, `first`/`last` of an empty list. Each
/// sets the error flag and yields the number 0 (LANGUAGE.md's "yields 0",
/// "returns 0"), so each is a read whose result must be re-typed before it
/// can enter a `text`/`list`/`map` destination.
pub(crate) fn is_fallible_collection_read(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::ElementAccess { .. }
            | Expr::ListAccess { .. }
            | Expr::MapAccess { .. }
            | Expr::PropertyAccess {
                property: ObjectProperty::First | ObjectProperty::Last,
                ..
            }
    )
}
