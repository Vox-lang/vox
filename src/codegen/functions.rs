use super::*;

/// What a call site has to repair after a call that took a `buffer` argument,
/// so the buffer's (possibly new) pointer reaches every holder of it and none
/// is left pointing at the block `_reallocate_buffer` freed
/// (docs/BUGS_FOUND.md #90).
enum BufferArgFixup {
    /// The cell handed to the callee was the name's BSS mirror; carry the new
    /// pointer back into the frame slot the top level reads.
    MirrorToSlot { label: String, offset: i64 },
    /// The argument was itself a `buffer` parameter of this frame, so what the
    /// callee was handed is the cell this frame's OWN cell points at - the
    /// buffer's owner, however many frames up. Refresh this frame's copy of
    /// the pointer from it now that the call has returned.
    OuterCellToSlot { cell: i64, offset: i64 },
}

impl CodeGenerator {
    /// Leave in rax the ADDRESS of the cell where the caller keeps its buffer
    /// pointer, which is what a `buffer` parameter's argument word carries
    /// (docs/BUGS_FOUND.md #90).
    ///
    /// A top-level name has two holders - the frame slot the top level reads
    /// and the BSS mirror functions read - and the mirror is the one handed
    /// over, because a function the callee calls can reach the same buffer
    /// through the mirror while the call is still in flight; that read must
    /// not land in a freed block either. The frame slot, which nothing can
    /// read until the call returns, is refreshed from the mirror afterwards.
    ///
    /// Handing over the mirror is safe in the other direction too: at the top
    /// level the mirror is never the staler of the two. Every top-level write
    /// stores the slot and mirrors it in the same breath, and a function that
    /// grows the same buffer by name can only reach the mirror - so copying
    /// the slot into the mirror first would be the one way to LOSE a pointer.
    fn emit_buffer_arg_cell_address(&mut self, arg: &Expr) -> Option<BufferArgFixup> {
        if let Expr::Identifier(name) = arg {
            if !self.in_function_codegen {
                if let (Some(offset), Some(label)) =
                    (self.get_var(name), self.global_var_label(name).cloned())
                {
                    self.emit_indent(&format!(
                        "lea rax, [rel {}]  ; the cell holding {}",
                        label, name
                    ));
                    return Some(BufferArgFixup::MirrorToSlot { label, offset });
                }
            }
            if let Some(offset) = self.get_var(name) {
                // When this name is itself a `buffer` parameter of THIS frame,
                // the holder that has to stay live while the callee runs is
                // not this frame's slot but the one this frame's own cell
                // points at - the buffer's owner, however many frames up. Hand
                // the callee that, so a reallocation two or thirty calls deep
                // reaches the owner AT the reallocation and not one return at
                // a time; this frame's own copy is refreshed from it when the
                // call comes back (docs/BUGS_FOUND.md #90).
                if let Some(cell) = self.buffer_param_cells.get(&offset).copied() {
                    self.emit_indent(&format!(
                        "mov rax, [rbp-{}]  ; where {}'s owner keeps it",
                        cell, name
                    ));
                    return Some(BufferArgFixup::OuterCellToSlot { cell, offset });
                }
                self.emit_indent(&format!("lea rax, [rbp-{}]  ; the cell holding {}", offset, name));
                return None;
            }
            if let Some(label) = self.global_var_label(name).cloned() {
                self.emit_indent(&format!("lea rax, [rel {}]  ; the cell holding {}", label, name));
                return None;
            }
        }
        // An argument with no variable of its own - a literal, an element
        // read, a call's result - gets a cell of its own. The callee is
        // correct for the length of the call, and the growth dies with the
        // temporary because there is no caller variable for it to reach.
        self.generate_expr(arg);
        self.stack_offset += 8;
        let tmp = self.stack_offset;
        self.emit_indent(&format!(
            "mov [rbp-{}], rax  ; a cell for a buffer argument with no name",
            tmp
        ));
        self.emit_indent(&format!("lea rax, [rbp-{}]", tmp));
        None
    }

    fn emit_buffer_arg_fixups(&mut self, fixups: Vec<BufferArgFixup>) {
        // rcx and rdx only: a call's result is still live in rax, and a
        // `value` result's tag in r11.
        for fixup in fixups {
            match fixup {
                BufferArgFixup::MirrorToSlot { label, offset } => {
                    self.emit_indent(&format!("mov rcx, [rel {}]  ; the buffer may have moved", label));
                    self.emit_indent(&format!(
                        "mov [rbp-{}], rcx  ; the top level's copy follows it",
                        offset
                    ));
                }
                BufferArgFixup::OuterCellToSlot { cell, offset } => {
                    self.emit_indent(&format!("mov rcx, [rbp-{}]  ; where this buffer's owner keeps it", cell));
                    self.emit_indent("mov rcx, [rcx]  ; the buffer may have moved");
                    self.emit_indent(&format!(
                        "mov [rbp-{}], rcx  ; this frame's copy follows it",
                        offset
                    ));
                }
            }
        }
    }

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
        // A `value` parameter given a buffer wants the same copy (#87): the
        // tag word pushed with it is TAG_STRING, so the payload word beside
        // it has to be text.
        let is_text_param = |i: usize| -> bool {
            param_types.get(i) == Some(&Type::String)
        };
        // A `buffer` parameter takes one word too, but the word is the ADDRESS
        // of the cell holding the caller's buffer pointer, not the pointer:
        // growing a buffer inside the callee FREES the block it grew out of,
        // so the caller has to be told where the buffer went before it reads
        // it again (docs/BUGS_FOUND.md #90).
        let is_buffer_param = |i: usize| -> bool {
            param_types.get(i) == Some(&Type::Buffer)
        };
        // BUGS_FOUND #75. A `list` or `map` parameter takes one word too, and
        // like a `thing` parameter's (above) that word is an ADDRESS - here the
        // address of the caller's own storage for the argument. The callee
        // reads the pointer out of it on entry, so every read inside the body
        // is unchanged; what the address buys is the way back, so a realloc
        // inside the callee can store the new pointer into the caller's
        // variable instead of only into the parameter's slot. Without it the
        // caller kept pointing at the block the collection outgrew, and every
        // append past the literal's capacity was silently dropped.
        let is_collection_param = |i: usize| -> bool {
            matches!(param_types.get(i), Some(Type::List(_)) | Some(Type::Map(_)))
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
        let mut buffer_fixups: Vec<BufferArgFixup> = Vec::new();
        // Named collections whose slot the callee may have written through:
        // whatever else holds that same pointer is re-synced after the call.
        let mut collections_to_resync: Vec<(String, i64)> = Vec::new();
        for i in (0..args.len()).rev() {
            if is_thing_param(i) {
                self.emit_thing_address(&args[i]); // rax = where the thing is
            } else if is_buffer_param(i) {
                // rax = where the caller keeps its buffer pointer
                if let Some(fixup) = self.emit_buffer_arg_cell_address(&args[i]) {
                    buffer_fixups.push(fixup);
                }
            } else if is_collection_param(i) {
                if let Some(sync) = self.emit_collection_argument_address(&args[i]) {
                    collections_to_resync.push(sync);
                }
            } else {
                if is_text_param(i) || is_value_param(i) {
                    self.generate_expr_as_text(&args[i]); // rax = text payload
                } else {
                    self.generate_expr(&args[i]); // rax = payload
                }
                // #114, before #91: a parameter slot is a destination like
                // any other - a present dynamic map value argument is cast
                // to the declared parameter type. Resolved separately from
                // `param_slot` below, which only names #91's pointer types
                // (String/List/Map) - the cast also covers a scalar
                // Integer/Float/Boolean parameter.
                let cast_param_slot = param_types.get(i).map(vartype_of_declared_type);
                self.emit_map_value_cast_if_needed(&args[i], cast_param_slot.clone());
                self.emit_map_value_collection_guard(&args[i], cast_param_slot);
                let param_slot = param_types.get(i).and_then(declared_slot_vartype);
                // #91: a parameter slot is a destination like any other -
                // a text/list/map parameter must not receive a missed read's 0.
                self.emit_empty_value_if_missed(&args[i], param_slot);
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
        // A buffer has more than one holder, so the new pointer follows it to
        // all of them (#90). `add rsp` leaves rcx/rdx alone, so this reads the
        // same registers either way.
        self.emit_buffer_arg_fixups(buffer_fixups);

        // A collection the callee may have grown can live in more than this
        // frame's slot: a top-level name also has the global mirror a function
        // body reads it by, and a name that is ITSELF a collection parameter
        // has our own caller's storage behind it. The callee wrote the slot;
        // carry that on to the rest, or growth would stop one call short of
        // home whenever a function passes its own collection parameter along.
        for (name, offset) in collections_to_resync {
            self.emit_resync_collection_after_call(&name, offset);
        }
    }

    /// BUGS_FOUND #75. Propagate a collection's (possibly reallocated) pointer
    /// out of this frame's slot to everything else that holds it - our own
    /// caller's storage, when the name is a collection parameter, and the
    /// global mirror, when it is a top-level name.
    ///
    /// Emitted immediately after a call, so it must leave the call's result
    /// alone: `rax` carries the return value and `r11` a `value` return's tag.
    /// It works in `rbx`/`rcx`, both restored, and touches neither.
    fn emit_resync_collection_after_call(&mut self, name: &str, offset: i64) {
        let backing = self.collection_backing_slots.get(name).copied();
        let mirror = if self.in_function_codegen {
            None
        } else {
            self.global_var_label(name).cloned()
        };
        if backing.is_none() && mirror.is_none() {
            return;
        }
        self.emit_indent("push rbx");
        self.emit_indent(&format!("mov rbx, [rbp-{}]  ; {} as the call left it", offset, name));
        if let Some(back_slot) = backing {
            self.emit_indent("push rcx");
            self.emit_indent(&format!(
                "mov rcx, [rbp-{}]  ; where our caller keeps {}",
                back_slot, name
            ));
            self.emit_indent("mov [rcx], rbx  ; the caller grows too");
            self.emit_indent("pop rcx");
        }
        if let Some(label) = mirror {
            self.emit_indent(&format!("mov [rel {}], rbx  ; global mirror of {}", label, name));
        }
        self.emit_indent("pop rbx");
    }

    /// BUGS_FOUND #75. Leave in `rax` the address of storage holding this
    /// collection argument's pointer, for a `list`/`map` parameter.
    ///
    /// A named variable hands over its own slot, so a realloc inside the
    /// callee lands in the caller's variable. Anything else - a literal, a
    /// call's result, an element read - has no variable to update, so its
    /// value is parked in a slot this call site owns and the address of that
    /// is passed instead: the callee's store-back is then a harmless write to
    /// a temporary, and the argument still arrives correctly.
    ///
    /// Returns the `(name, offset)` of a top-level stack slot whose global
    /// mirror the caller must re-sync after the call, if any.
    pub(crate) fn emit_collection_argument_address(
        &mut self,
        arg: &Expr,
    ) -> Option<(String, i64)> {
        if let Expr::Identifier(name) = arg {
            if let Some(offset) = self.get_var(name) {
                self.emit_indent(&format!("lea rax, [rbp-{}]  ; the caller's {}", offset, name));
                return Some((name.clone(), offset));
            }
            if let Some(label) = self.global_var_label(name).cloned() {
                self.emit_indent(&format!("lea rax, [rel {}]  ; the caller's {}", label, name));
                return None;
            }
        }
        // No variable behind this argument: park its value in a slot of our own.
        self.generate_expr(arg);
        self.stack_offset += 8;
        let slot = self.stack_offset;
        self.emit_indent(&format!("mov [rbp-{}], rax  ; collection argument", slot));
        self.emit_indent(&format!("lea rax, [rbp-{}]", slot));
        None
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

    /// File one definition's signature under `key`: the return type, twice
    /// (once reduced to a `VarType`, once whole), and the parameter types the
    /// call site counts argument words from.
    ///
    /// Shared by the scan of the top-level list and the sweep of definitions
    /// nested inside an open clause, so the two can never disagree about what
    /// a function's ABI is (bug #73).
    fn record_function_signature(
        &mut self,
        key: String,
        params: &[(String, Type)],
        return_type: &Type,
    ) {
        let vt = vartype_of_declared_type(return_type);
        self.function_return_types.insert(key.clone(), vt);
        self.function_return_full_types.insert(key.clone(), return_type.clone());
        self.function_param_types
            .insert(key, params.iter().map(|(_, t)| t.clone()).collect());
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
                    self.record_function_signature(key, params, return_type);

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

            // A definition the parser drew into an open clause's body is a
            // definition like any other: the walk that generates code emits
            // it into `functions_section`, so every call to it must be
            // compiled against its real signature. Without this the lookup in
            // `emit_function_call` missed and `unwrap_or_default()` invented
            // an all-scalar signature, so a `value` parameter's tag word was
            // never pushed (bug #73). The library identity used is the one in
            // force at the enclosing top-level statement, which is where the
            // definition textually sits.
            //
            // Exports are deliberately NOT extended: a `.lib` interface lists
            // what a library offers, and a definition swallowed into a block
            // is not something the author wrote at a library's top level.
            for def in nested_function_defs(stmt) {
                if let Statement::FunctionDef { name, params, return_type, .. } = def {
                    let key = make_function_label(
                        self.shared_lib_mode,
                        current_lib.as_ref(),
                        name,
                    );
                    self.record_function_signature(key, params, return_type);
                }
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
            let vt = vartype_of_declared_type(&imp.return_type);
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
