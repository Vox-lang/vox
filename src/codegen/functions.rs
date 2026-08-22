use super::*;

impl CodeGenerator {
    pub(crate) fn emit_function_call(&mut self, name: &str, args: &[Expr]) {
        let param_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

        // A `value` parameter occupies TWO argument words (payload, tag) in the
        // SysV stream; a scalar parameter occupies one. We push words
        // right-to-left so word 0 (param 0 payload) ends on top (first pop).
        // When the callee's signature is unknown (e.g. an extern/builtin),
        // assume every parameter is scalar — preserving the original ABI for
        // statically-typed calls (criterion 6). The signature tables are keyed
        // by the resolution target (a local `<lib>_<ver>_<func>` label in
        // shared mode, an import's mangled symbol, or `mangle_symbol(name)`),
        // so the lookup goes through `resolved_call_label` — the same target
        // the `call` below emits.
        let label = self.resolved_call_label(name);
        let param_types = self.function_param_types.get(&label).cloned().unwrap_or_default();
        // Plan 296: a `.lib` parameter declared `list of <type>` carries a
        // real element type (`Type::List(Box<non-Unknown>)`) rather than the
        // usual `Unknown`. When the argument is a plain local variable,
        // record that element type for it here — the same table
        // (`list_element_types`) a local `Append <literal> to x` already
        // populates, so every later read of that variable (a `for each`
        // print, in particular) sees a real type instead of defaulting to
        // "don't know." This is additive only: it fires exclusively for a
        // `.lib` import whose ToC entry spelled `list of <type>`; a bare
        // `list` parameter (every `.lib` ever emitted before this plan)
        // still resolves to `Type::List(Unknown)` here and changes nothing.
        for (i, arg) in args.iter().enumerate() {
            if let (Some(Type::List(inner)), Expr::Identifier(argname)) = (param_types.get(i), arg) {
                if !matches!(**inner, Type::Unknown) {
                    self.list_element_types
                        .insert(argname.clone(), list_element_vartype(inner));
                }
            }
        }
        let is_value_param = |i: usize| -> bool {
            param_types.get(i) == Some(&Type::Value)
        };
        // A `thing` parameter takes one word too, but the word is the ADDRESS
        // of the caller's thing: the callee copies the bytes into its own
        // frame on entry, which is what makes a parameter a copy (plan 310 §5)
        // without giving a thing an argument-word count that depends on its
        // size.
        let is_thing_param = |i: usize| -> bool {
            matches!(param_types.get(i), Some(Type::Thing(_)))
        };
        // A parameter declared `a text called ...` holds text, so a buffer
        // argument is converted on the way in rather than arriving as a
        // struct pointer the callee would read as a C string - the capacity
        // byte, historically (#51). A copy is also what makes the argument
        // behave like every other Vox argument: the callee's text does not
        // change when the caller refills or resizes the buffer afterwards.
        let is_text_param = |i: usize| -> bool {
            param_types.get(i) == Some(&Type::String)
        };
        // Number of argument words a given arg contributes.
        let word_count = |i: usize| if is_value_param(i) { 2 } else { 1 };

        // A call returning a whole thing writes it into storage the CALLER
        // owns: its address travels as a hidden first argument word and comes
        // back in rax (plan 310 §5). The slot belongs to this call site, so
        // two calls in one argument list cannot land on each other's result,
        // and a recursive call's slot lives in its own frame.
        let destination = self.thing_returned_by_call(name).map(|thing| {
            self.stack_offset += self.thing_storage_size(&thing) as i64;
            self.stack_offset
        });
        let hidden_words = if destination.is_some() { 1 } else { 0 };
        let total_words: usize = hidden_words + (0..args.len()).map(word_count).sum::<usize>();

        // Evaluate/push all arg words right-to-left. For a `value` param the
        // tag word is pushed BEFORE the payload word, so the payload lands on
        // top (lower word index) — matching how the callee reads them.
        for i in (0..args.len()).rev() {
            if is_thing_param(i) {
                self.emit_thing_address(&args[i]); // rax = where the thing is
            } else {
                if is_text_param(i) {
                    self.generate_expr_as_text(&args[i]); // rax = text payload
                } else {
                    self.generate_expr(&args[i]); // rax = payload
                }
                if is_value_param(i) {
                    self.emit_load_value_tag(&args[i]); // r11 = tag (rax preserved)
                    self.emit_indent("push r11  ; value param tag word");
                }
            }
            self.emit_indent("push rax");
        }
        // Pushed last so it lands on top: the hidden destination is word 0.
        if let Some(slot) = destination {
            self.emit_indent(&format!(
                "lea rax, [rbp-{}]  ; where '{}' writes its result",
                slot, name
            ));
            self.emit_indent("push rax  ; hidden destination word");
        }

        // Pop the first 6 argument WORDS into registers (word 0 -> rdi, ...).
        let reg_words = total_words.min(param_regs.len());
        for reg in param_regs.iter().take(reg_words) {
            self.emit_indent(&format!("pop {}", reg));
        }

        // Remaining words (7th+) stay on the stack.
        let stack_words = total_words.saturating_sub(param_regs.len());
        let stack_word_bytes = stack_words * 8;

        // Align stack before call (SysV: 16B-aligned at call instruction).
        let needs_pad = stack_words % 2 != 0;
        if needs_pad {
            self.emit_indent("sub rsp, 8  ; align stack before call");
        }

        // In shared library mode a call to a function DEFINED in this
        // library must target the same `<lib>_<ver>_<func>` label the
        // definition emitted — otherwise the .so defines
        // `mathkit_1_0_greet` while the call site branches to the bare
        // `greet`, which the version script does not export. The signature
        // tables are keyed by that mangled label, so `contains_key(&label)`
        // is true exactly for a function defined in the CURRENT library
        // (whose identity `function_label` reads). A call to a function in
        // a DIFFERENT library of the same .so never reaches here: the
        // analyzer scopes its own `functions` set per library, so a
        // cross-library name is the existing "Unknown function" error
        // before codegen runs. An (A4) extern or a runtime helper is not in
        // the table, so it falls through to the plain mangled name. Non-
        // shared builds take the plain path unconditionally (`label` is
        // already `mangle_symbol(name)` there), so their output is byte-
        // identical to today.
        //
        // A4: `label` was computed by `resolved_call_label`, which prefers
        // the local definition (present in the tables), then an import's
        // mangled extern symbol, then the plain mangled fallback. The call
        // and the signature lookup above therefore always agree, for local,
        // imported, and runtime-helper targets alike.
        self.emit_indent(&format!("call {}", label));

        // Clean up stack words + pad (caller cleanup in SysV). The return tag
        // for a `value`-returning function rides in r11; `add rsp` does not
        // clobber it, so a caller that consumes the result sees r11=tag.
        let cleanup = stack_word_bytes + if needs_pad { 8 } else { 0 };
        if cleanup > 0 {
            self.emit_indent(&format!("add rsp, {}", cleanup));
        }
    }

    pub fn set_shared_lib_mode(&mut self, enabled: bool) {
        self.shared_lib_mode = enabled;
    }

    /// Stage A4: register the resolved, .dynsym-verified imports from the
    /// program's `see ... from "*.lib"` statements. Stored pre-`generate`;
    /// `collect_function_signatures` merges their signatures into the tables
    /// (which it clears), keyed by each import's mangled label, and `generate`
    /// emits one `extern <label>` per imported symbol.
    pub fn set_imports(&mut self, imports: Vec<crate::lib_file::ImportedFunction>) {
        self.import_labels.clear();
        self.imported_symbols.clear();
        for imp in &imports {
            // Ambiguity is an analyzer error: at most one claimant per
            // authored name can reach here. `or_insert` keeps that guarantee
            // locally rather than re-deriving it.
            self.import_labels
                .entry(imp.name.clone())
                .or_insert_with(|| imp.mangled.clone());
            if !self.imported_symbols.contains(&imp.mangled) {
                self.imported_symbols.push(imp.mangled.clone());
            }
        }
        self.imports = imports;
    }

    /// The label a call to `name` actually targets. A locally defined function
    /// wins (its label is in the signature tables — the same test the shared-
    /// mode call path already uses), then an import's mangled `<lib>_<ver>_`
    /// `<func>` symbol, then the historical plain `mangle_symbol` fallback for
    /// runtime helpers and other tables-missing calls. Keying everything off
    /// the signature tables keeps this ONE rule for both call emission and
    /// return-type inference.
    pub(crate) fn resolved_call_label(&self, name: &str) -> String {
        let local = self.function_label(name);
        if self.function_return_types.contains_key(&local) {
            return local;
        }
        if let Some(mangled) = self.import_labels.get(name) {
            return mangled.clone();
        }
        mangle_symbol(name)
    }

    /// Resolve the assembly label for a function DEFINED in this compilation.
    /// In shared library mode with a library identity set, the label is
    /// `<lib>_<ver>_<func>` (each component through `mangle_symbol`); this is
    /// what makes two libraries in one .so both defining `greet` emit two
    /// distinct labels. In every other case it is the plain `mangle_symbol`
    /// of the name, so non-shared builds are byte-identical to today.
    pub(crate) fn function_label(&self, name: &str) -> String {
        make_function_label(self.shared_lib_mode, self.current_library.as_ref(), name)
    }

    /// Pre-pass: find the `Library` declaration that names this compilation's
    /// identity and stash it in `current_library` before any function is
    /// generated. Running this up front (rather than only when the statement
    /// is reached during `generate`) means the order of `Library` vs `To` in
    /// the source is irrelevant — a forward call to a function defined above
    /// the declaration still mangles correctly. The analyzer has already
    /// rejected `--shared` with no `Library` line, so in shared mode exactly
    /// one is expected; the first wins and a second is left for A2 to reject.
    pub(crate) fn collect_library_identity(&mut self, program: &Program) {
        for stmt in &program.statements {
            if let Statement::LibraryDecl { name, version } = stmt {
                self.current_library = Some((name.clone(), version.clone()));
                return;
            }
        }
    }

    /// Plan 270 G4: a bare or quoted identifier in *expression* position
    /// that names a zero-argument function is a call, not a variable lookup.
    /// Returns the function's return type iff `name` resolves (locally or via
    /// an import) to a function declaring zero parameters. A name that is a
    /// variable in scope is handled by the caller *before* consulting this —
    /// a variable shadows a same-named zero-arg function, matching the
    /// analyzer's "variable first" resolution. `resolved_call_label` returns
    /// `mangle_symbol(name)` for an unknown name, which is absent from the
    /// signature tables, so this never false-positives on an unknown.
    pub(crate) fn zero_arg_func_return_type(&self, name: &str) -> Option<VarType> {
        let label = self.resolved_call_label(name);
        match self.function_param_types.get(&label) {
            Some(params) if params.is_empty() => self.function_return_types.get(&label).cloned(),
            _ => None,
        }
    }

    /// The resolved call-target label for `val`, if it is a function call —
    /// either the unambiguous `Expr::FunctionCall` shape (an explicit
    /// `of`/`with`/`to` argument list), or a bare/quoted identifier in
    /// expression position that names a zero-argument function rather than
    /// a variable. The second shape is the one plan 296's first cut of
    /// list-return element typing missed: `a list called got is 'tokens'.`
    /// has no connector, so the parser can't tell it's a call — it produces
    /// `Expr::Identifier("tokens")`, indistinguishable at the AST level
    /// from a variable reference. `generate_expr`'s own Identifier arm
    /// resolves the exact same ambiguity (plan 270 G4: try a variable load
    /// first, fall back to `zero_arg_func_return_type`); this mirrors that
    /// resolution order so a variable always wins over a same-named
    /// zero-arg function, here too.
    pub(crate) fn call_label_for_list_return(&self, val: &Expr) -> Option<String> {
        match val {
            Expr::FunctionCall { name, .. } => Some(self.resolved_call_label(name)),
            Expr::Identifier(name)
                if self.get_var(name).is_none() && self.global_var_label(name).is_none() =>
            {
                self.zero_arg_func_return_type(name)
                    .map(|_| self.resolved_call_label(name))
            }
            _ => None,
        }
    }

    /// The mangled labels of functions exported by a `--shared` compile, in
    /// emission order. Populated during `generate`; the linker's version
    /// script names exactly these as the library's public symbols.
    pub fn exported_functions(&self) -> &[String] {
        &self.exported_functions
    }

    /// The per-library exported signatures for the Stage A3 `.lib` interface
    /// file: one `LibBlock` per <library, version> identity, in first-seen
    /// order, each carrying its functions in source order. Empty for non-shared
    /// builds. `main.rs` renders this beside the `.so` after a successful link.
    pub fn library_blocks(&self) -> &[LibBlock] {
        &self.library_blocks
    }

    pub fn set_target_arch(&mut self, arch: &str) {
        self.target_arch = arch.to_string();
    }

    // Record each function's declared return type so infer_expr_type() can
    // resolve Expr::FunctionCall correctly instead of falling through to
    // its generic "Integer for anything unrecognized" default. Without
    // this, reassigning an EXISTING variable from a function call (`the x
    // is "some func" of y.`) silently corrupted the variable's tracked
    // type to Integer - a fresh `a text called x is ...` declaration
    // happened to read the correct type from a different code path and
    // was unaffected, which is what made this easy to miss.
    pub(crate) fn collect_function_signatures(&mut self, program: &Program) {
        let lib_fn_return_types = collect_lib_function_return_types(program);
        self.function_return_types.clear();
        self.function_param_types.clear();
        self.function_return_full_types.clear();
        // Track the library identity as we walk so each function is keyed by
        // its OWN `<lib>_<ver>_<func>` label, not the authored name. This is
        // what scopes the signature tables: two libraries in one .so each
        // defining `greet` get distinct keys, so the second no longer silently
        // overwrites the first's return/parameter types (the wrong-code bug A1
        // found). A local, not `self.current_library`, so this pre-pass does
        // not disturb the identity the main generate walk manages.
        let mut current_lib: Option<(String, String)> = None;
        // Stage A3: collect per-library exported signatures for the `.lib`
        // interface file, in the same single walk. Shared mode only — a
        // non-shared build has no `Library` blocks and writes no `.lib`. The
        // block list is keyed by <lib, version> (first-seen order), so two
        // versions of one library become two blocks, each carrying its own
        // functions in source order. A function with no current_lib in shared
        // mode is a malformed input the analyzer has already rejected, so it
        // is skipped here rather than crash the collector.
        let mut lib_blocks: Vec<LibBlock> = Vec::new();
        let mut block_idx: HashMap<(String, String), usize> = HashMap::new();
        for stmt in &program.statements {
            match stmt {
                Statement::LibraryDecl { name, version } => {
                    current_lib = Some((name.clone(), version.clone()));
                }
                Statement::FunctionDef { name, params, return_type, body, .. } => {
                    let key = make_function_label(
                        self.shared_lib_mode,
                        current_lib.as_ref(),
                        name,
                    );
                    let vt = match return_type {
                        Type::Integer => VarType::Integer,
                        Type::Float => VarType::Float,
                        Type::String => VarType::String,
                        Type::Boolean => VarType::Boolean,
                        Type::Buffer => VarType::Buffer,
                        Type::List(_) => VarType::List,
                        // A `value` return is dynamic: the runtime tag travels
                        // back in r11 alongside the payload in rax, so the
                        // result is a Mixed-typed value (no static tag).
                        Type::Value => VarType::Mixed,
                        _ => VarType::Unknown,
                    };
                    self.function_return_types.insert(key.clone(), vt);
                    self.function_return_full_types.insert(key.clone(), return_type.clone());
                    self.function_param_types
                        .insert(key, params.iter().map(|(_, t)| t.clone()).collect());

                    if self.shared_lib_mode {
                        if let Some((lib, ver)) = current_lib.as_ref() {
                            let id = (lib.clone(), ver.clone());
                            let idx = match block_idx.get(&id) {
                                Some(&i) => i,
                                None => {
                                    let i = lib_blocks.len();
                                    block_idx.insert(id, i);
                                    lib_blocks.push(LibBlock {
                                        lib: lib.clone(),
                                        version: ver.clone(),
                                        funcs: Vec::new(),
                                    });
                                    i
                                }
                            };
                            // The `.lib` records a real list element type when
                            // one can be inferred from this function's OWN
                            // body (plan 296, widened by plan 303 phase 2 to
                            // also credit a local's declared type and a
                            // same-library call's declared return type) — the
                            // exported interface only; `function_param_types`/
                            // `function_return_types` above (this compilation
                            // unit's own codegen) keep the plain declared type
                            // unchanged.
                            let param_env: HashMap<String, Type> =
                                params.iter().cloned().collect();
                            let empty_fn_returns: HashMap<String, Type> = HashMap::new();
                            let fn_return_env = lib_fn_return_types
                                .get(&(lib.clone(), ver.clone()))
                                .unwrap_or(&empty_fn_returns);
                            let lib_params: Vec<(String, Type)> = params
                                .iter()
                                .map(|(pname, ptype)| match ptype {
                                    Type::List(inner) if matches!(**inner, Type::Unknown) => (
                                        pname.clone(),
                                        Type::List(Box::new(infer_list_element_type(
                                            pname, &param_env, fn_return_env, body,
                                        ))),
                                    ),
                                    _ => (pname.clone(), ptype.clone()),
                                })
                                .collect();
                            let lib_return_type = match return_type {
                                Type::List(inner) if matches!(**inner, Type::Unknown) => {
                                    Type::List(Box::new(infer_return_list_element_type(
                                        &param_env, fn_return_env, body,
                                    )))
                                }
                                other => other.clone(),
                            };
                            lib_blocks[idx].funcs.push(LibFunction {
                                name: name.clone(),
                                params: lib_params,
                                return_type: lib_return_type,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // Stage A4: imported signatures, keyed by each import's own
        // `<lib>_<ver>_<func>` symbol (never the plain authored name, so a
        // shadowing LOCAL definition — a different key — still wins at the
        // call site). `resolved_call_label` consults these tables, so the
        // call, the return type, and the value-parameter word count all read
        // this same entry. A `value` return is Mixed for the same reason a
        // local one is (the tag rides home in r11).
        for imp in &self.imports {
            let vt = match imp.return_type {
                Type::Integer => VarType::Integer,
                Type::Float => VarType::Float,
                Type::String => VarType::String,
                Type::Boolean => VarType::Boolean,
                Type::Buffer => VarType::Buffer,
                Type::List(_) => VarType::List,
                Type::Value => VarType::Mixed,
                _ => VarType::Unknown,
            };
            self.function_return_types.insert(imp.mangled.clone(), vt);
            self.function_return_full_types
                .insert(imp.mangled.clone(), imp.return_type.clone());
            self.function_param_types.insert(
                imp.mangled.clone(),
                imp.params.iter().map(|(_, t)| t.clone()).collect(),
            );
        }

        self.library_blocks = lib_blocks;
    }

}
