    //! Codegen routing tests for whole-list printing (plan 000). These lock
    //! the routing in at the compiler level - independent of the runtime -
    //! so a regression in `generate_print` is caught without assembling.
    use crate::analyzer::Analyzer;
    use crate::lexer::Lexer;
    use crate::parser::ast::Type;
    use crate::parser::Parser;
    use super::{CodeGenerator, LibBlock};

    /// Parse, analyze, and generate asm for a source snippet. Panics with a
    /// clear message if parsing or analysis fails, so test failures point at
    /// the snippet rather than at silently-empty output.
    fn compile_to_asm(source: &str) -> String {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("unit_test.vox", source);
        let mut program = parser
            .parse()
            .expect("test snippet should parse cleanly");
        let mut analyzer = Analyzer::new().with_source("unit_test.vox", source);
        analyzer.analyze(&mut program);
        assert!(
            analyzer.errors.is_empty(),
            "test snippet should analyze cleanly, got: {:?}",
            analyzer.errors
        );
        let mut gen = CodeGenerator::new();
        gen.generate(&program)
    }

    /// Like `compile_to_asm`, but in `--shared` mode: the analyzer enforces the
    /// library top-level rules (a `Library` declaration, only function defs)
    /// and the codegen mangles labels by library and version. Used to test the
    /// shared-library path without shelling out to nasm/ld.
    fn compile_to_asm_shared(source: &str) -> String {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("lib_test.vox", source);
        let mut program = parser
            .parse()
            .expect("shared test snippet should parse cleanly");
        let mut analyzer = Analyzer::new()
            .with_source("lib_test.vox", source)
            .with_shared_mode(true);
        analyzer.analyze(&mut program);
        assert!(
            analyzer.errors.is_empty(),
            "shared test snippet should analyze cleanly, got: {:?}",
            analyzer.errors
        );
        let mut gen = CodeGenerator::new();
        gen.set_shared_lib_mode(true);
        gen.generate(&program)
    }

    #[test]
    fn quoted_zero_arg_identifier_in_expression_position_calls_not_reads() {
        // Plan 270 G4 / defect Q1: `is 'get five'` must emit a call to the
        // zero-argument function, not a variable lookup (which used to
        // silently print the function's pointer value instead).
        let asm = compile_to_asm(
            "To 'get five', Return a number, 5.\n\
             a number called x is 'get five'.\n\
             print x.\n",
        );
        assert!(
            asm.contains("call get_five"),
            "a bare zero-arg identifier in expression position must call the function: {}",
            asm
        );
    }

    #[test]
    fn whole_list_print_routes_to_list_print() {
        let asm = compile_to_asm("a list called xs is [1, 2, 3].\nprint xs.\n");
        assert!(
            asm.contains("call _list_print"),
            "a whole-list print must route to _list_print, not PRINT_INT"
        );
        // Exactly one whole-list print in the source -> exactly one call.
        assert_eq!(
            asm.matches("call _list_print").count(),
            1,
            "expected exactly one `call _list_print`"
        );
    }

    #[test]
    fn list_format_interpolation_routes_to_list_print() {
        let asm = compile_to_asm("a list called xs is [1, 2, 3].\nprint \"xs: {xs}\".\n");
        assert!(
            asm.contains("call _list_print"),
            "a {{list}} interpolation must route to _list_print"
        );
        assert_eq!(asm.matches("call _list_print").count(), 1);
    }

    #[test]
    fn mixed_list_whole_print_routes_to_list_print() {
        // A mixed list variable has variable_types == List (its element type
        // is tracked separately in list_element_types), so the whole-list
        // print must still take the _list_print branch - not the per-element
        // Mixed dispatch, which would print a single pointer.
        let asm = compile_to_asm("a list called m is [1, \"two\", 3.5].\nprint m.\n");
        assert!(asm.contains("call _list_print"));
        assert_eq!(asm.matches("call _list_print").count(), 1);
    }

    #[test]
    fn non_list_print_does_not_route_to_list_print() {
        let asm = compile_to_asm("a number called n is 5.\nprint n.\n");
        assert!(
            !asm.contains("call _list_print"),
            "a non-list print must not route to _list_print"
        );
    }

    #[test]
    fn multiple_list_prints_each_route_to_list_print() {
        // Two whole-list prints (one direct, one interpolated) -> two calls.
        let asm = compile_to_asm(
            "a list called xs is [1, 2, 3].\nprint xs.\nprint \"xs: {xs}\".\n",
        );
        assert_eq!(asm.matches("call _list_print").count(), 2);
    }

    // ---- Stage 1b: inference soundness flip (plan 010) ----
    //
    // These lock in the three-state pre-scan: a list whose every write is
    // provable keeps the untagged fast path; an unprovable write widens to
    // Mixed so reads dispatch on runtime tags.

    #[test]
    fn homogeneous_int_list_keeps_fast_path() {
        // Acceptance criterion 1: a list built only from integer literals
        // emits no tag writes and no runtime-tag dispatch.
        let asm =
            compile_to_asm("a list called xs is [1, 2, 3].\nprint element 1 of xs.\n");
        assert!(
            !asm.contains("mixp_"),
            "a homogeneous int list must not emit mixed-dispatch labels"
        );
        assert!(
            !asm.contains("movzx r11, byte"),
            "a homogeneous int list read must not load a runtime tag into r11"
        );
    }

    #[test]
    fn mixed_list_emits_dispatch() {
        // Contrast: a genuinely mixed list DOES dispatch on tags.
        let asm =
            compile_to_asm("a list called m is [1, \"two\"].\nprint element 1 of m.\n");
        assert!(
            asm.contains("mixp_"),
            "a mixed list read must emit mixed-dispatch labels"
        );
    }

    #[test]
    fn declared_text_function_append_tagged_string() {
        // Acceptance criterion 2: a function result of declared text type
        // appended alongside an integer is tagged STRING (not the old
        // TAG_INTEGER guess), and the list widens to Mixed.
        let asm = compile_to_asm(
            "To greet with a number called x.\n  Return a text, \"hi\".\n\
             a list called items is [].\n\
             append 1 to items.\n\
             append greet of 0 to items.\n\
             print element 1 of items.\n\
             print element 2 of items.\n",
        );
        assert!(
            asm.contains("mov edx, 1  ; element type tag"),
            "the text-returning function result must be written with TAG_STRING (1)"
        );
        assert!(
            asm.contains("mixp_"),
            "the list widened to Mixed (int + text function result)"
        );
    }

    #[test]
    fn read_of_widened_list_does_not_prove_a_type() {
        // `list_seen_tags` records the FIRST tag proven for a list and is
        // never retracted, so a list that starts homogeneous and is later
        // appended a different type still has its original tag recorded.
        // Reading an element out of it must consult `mixed_lists` and yield
        // Unknowable - otherwise the destination stays on the fast path while
        // holding a value of the wrong type.
        let asm = compile_to_asm(
            "a list called m is [1, 2].\n\
             append \"hi\" to m.\n\
             a list called out is [0, 0].\n\
             set element 1 of out to element 3 of m.\n\
             print element 1 of out.\n",
        );
        assert!(
            asm.contains("mixp_"),
            "reading an element of a widened list must widen the destination"
        );
    }

    #[test]
    fn declared_type_does_not_forge_a_string_tag() {
        // A declared type is the author's intent, not a proof about the bits
        // that land in the slot. Tagging an unprovable value TAG_STRING makes
        // the tag-dispatching printer dereference whatever integer is there.
        let asm = compile_to_asm(
            "a list called m is [\"a\", \"b\"].\n\
             append 42 to m.\n\
             a text called s is element 3 of m.\n\
             a list called out is [].\n\
             append s to out.\n",
        );
        assert!(
            !asm.contains("mov edx, 1  ; element type tag"),
            "an unprovable value must not be written with TAG_STRING"
        );
    }

    #[test]
    fn declared_type_still_tags_a_provable_string() {
        // Contrast with the above: when the initializer IS provable, the
        // string tag must still be written, or homogeneous text lists would
        // print pointers.
        let asm = compile_to_asm(
            "a text called s is \"hello\".\n\
             a list called out is [].\n\
             append s to out.\n",
        );
        assert!(
            asm.contains("mov edx, 1  ; element type tag"),
            "a provably-text value must still be written with TAG_STRING"
        );
    }

    #[test]
    fn format_string_append_tags_string() {
        // BUGS_FOUND #17: a format string can only ever produce text, so
        // appending one directly must write TAG_STRING (1), not the old
        // TAG_INTEGER guess that corrupted the element.
        let asm = compile_to_asm(
            "a list called out is [].\n\
             a number called k is 7.\n\
             append \"n {k}\" to out.\n",
        );
        assert!(
            asm.contains("mov edx, 1  ; element type tag"),
            "a format-string append must be written with TAG_STRING"
        );
    }

    #[test]
    fn format_string_append_does_not_spuriously_widen_list() {
        // Before the fix, `prescan_expr_tag` reported a format string as
        // Unknowable, which `prescan_note_list_value` treats as proof of
        // heterogeneity - permanently widening the list to Mixed even though
        // every element is actually text. A later plain-string append to the
        // same list must still get the untagged fast path.
        let asm = compile_to_asm(
            "a list called out is [].\n\
             a number called k is 7.\n\
             append \"n {k}\" to out.\n\
             append \"literal\" to out.\n\
             print element 1 of out.\n",
        );
        assert!(
            !asm.contains("mixp_"),
            "a format-string append must not widen the list to Mixed"
        );
    }

    #[test]
    fn format_string_local_appended_by_name_tags_string() {
        // BUGS_FOUND #17: a text local initialized from a format string,
        // then appended by name, must also prove TAG_STRING - the pre-scan's
        // `env` entry for the local must not be tainted Unknowable by the
        // format string's (previously missing) tag.
        let asm = compile_to_asm(
            "a text called greeting is \"hi\".\n\
             a text called tok is \"fmt {greeting}\".\n\
             a list called out is [].\n\
             append tok to out.\n",
        );
        assert!(
            asm.contains("mov edx, 1  ; element type tag"),
            "a name-forwarded format-string value must be written with TAG_STRING"
        );
    }

    #[test]
    fn undeclared_return_function_append_widens() {
        // Acceptance criterion 3: a function with an undeclared return type
        // (`Return x add 1.` — no `a number,` prefix) is genuinely opaque to
        // the compiler, so appending its result widens the list to Mixed and
        // reads dispatch on tags (the flip from 1a's optimistic default).
        let asm = compile_to_asm(
            "To five with a number called x.\n  Return x add 1.\n\
             a list called items is [].\n\
             append \"hello\" to items.\n\
             append five of 4 to items.\n\
             print element 1 of items.\n\
             print element 2 of items.\n",
        );
        assert!(
            asm.contains("mixp_"),
            "an unknowable (undeclared-return) append must widen the list to Mixed"
        );
    }

    // ---- Stage 1c: runtime type predicates (plan 020) ----
    //
    // Lock in the two codegen paths: a mixed operand emits a runtime tag
    // compare against r11; a statically-typed operand folds to a constant
    // with no runtime compare.

    #[test]
    fn type_predicate_mixed_emits_runtime_compare() {
        // A for-each over a mixed list binds a Mixed loop variable, whose
        // tag lives in its shadow slot. `item is a text` must load that tag
        // and compare it against TAG_STRING (1) at runtime.
        let asm = compile_to_asm(
            "a list called m is [1, \"x\"].\n\
             For each item in m, if item is a text, print item.\n",
        );
        assert!(
            asm.contains("cmp r11, 1"),
            "a mixed-element type predicate must compare the runtime tag against TAG_STRING"
        );
        assert!(
            asm.contains("movzx r11, byte [rbp-"),
            "the for-each variable's tag must be loaded from its shadow slot"
        );
    }

    #[test]
    fn mangle_symbol_produces_c_identifiers() {
        use super::mangle_symbol;
        // Spaces, the existing case.
        assert_eq!(mangle_symbol("greet user"), "greet_user");
        // Dots - the case that matters, because library versions contain one.
        assert_eq!(mangle_symbol("my.helper"), "my_helper");
        assert_eq!(mangle_symbol("flags_0.1_hasflag"), "flags_0_1_hasflag");
        // Anything else outside [A-Za-z0-9_].
        assert_eq!(mangle_symbol("parse-line"), "parse_line");
        assert_eq!(mangle_symbol("add%"), "add_");
        // A leading digit is not a legal identifier start in C.
        assert_eq!(mangle_symbol("2fast"), "_2fast");
        // Already-valid names are untouched.
        assert_eq!(mangle_symbol("already_fine"), "already_fine");
    }

    #[test]
    fn mangle_library_symbol_joins_three_components() {
        use super::mangle_library_symbol;
        // The plan 230 example: mathkit + 1.0 + "add two numbers".
        assert_eq!(
            mangle_library_symbol("mathkit", "1.0", "add two numbers"),
            "mathkit_1_0_add_two_numbers"
        );
        // Each component is mangled independently, then joined with `_`.
        // A version with a dot folds to `_` only inside that component.
        assert_eq!(
            mangle_library_symbol("my.lib", "2.0", "greet"),
            "my_lib_2_0_greet"
        );
        // A leading-digit version component is prefixed per mangle_symbol.
        assert_eq!(
            mangle_library_symbol("lib", "1", "greet"),
            "lib_1_greet"
        );
    }

    // ---- Stage A1: mangle exported symbols by library and version ----
    //
    // The label itself must change, not just the export list. These lock in
    // both halves: the definition emits `<lib>_<ver>_<func>`, and a call
    // site inside the library targets the same mangled label (never the bare
    // name the version script does not export).

    #[test]
    fn shared_lib_mangles_exported_labels_by_library_and_version() {
        // The tests/shared/libmath.vox corpus, in source form: a Library
        // declaration plus the three exports. In --shared mode every defined
        // label becomes <lib>_<ver>_<func>.
        let src = "\
Library mathkit version \"1.0\".\n\
To 'add two numbers' with a number called n.\n  Return n add 2.\n\
To greet.\n  Print \"hello from libmath\".\n\
To makebuf.\n  Create a buffer called b.\n  Append \"hello\" to b.\n  Return b's size.\n";
        let asm = compile_to_asm_shared(src);
        // The three definitions emit the mangled labels...
        assert!(
            asm.contains("mathkit_1_0_add_two_numbers:"),
            "the 'add two numbers' definition must emit the mangled label"
        );
        assert!(
            asm.contains("mathkit_1_0_greet:"),
            "the 'greet' definition must emit the mangled label"
        );
        assert!(
            asm.contains("mathkit_1_0_makebuf:"),
            "the 'makebuf' definition must emit the mangled label"
        );
        // ...and each is exported as a STT_FUNC dynamic symbol.
        assert!(
            asm.contains("global mathkit_1_0_add_two_numbers:function"),
            "the mangled label must be the exported symbol, not the bare name"
        );
        assert!(
            asm.contains("global mathkit_1_0_greet:function"),
            "greet must be exported under its mangled name"
        );
        assert!(
            asm.contains("global mathkit_1_0_makebuf:function"),
            "makebuf must be exported under its mangled name"
        );
        // The bare labels must NOT appear as definitions or exports — that is
        // the half-right failure mode the plan warns about.
        assert!(
            !asm.contains("\nadd_two_numbers:"),
            "the bare label must not be defined alongside the mangled one"
        );
        assert!(
            !asm.contains("global greet:function"),
            "the bare 'greet' must not be exported"
        );
    }

    #[test]
    fn shared_lib_call_site_targets_mangled_label() {
        // A function that calls a sibling in the same library must `call` the
        // mangled label, not the bare name — otherwise the .so defines
        // mathkit_1_0_greet while the call branches to greet, which the
        // version script does not export.
        let src = "\
Library mathkit version \"1.0\".\n\
To double with a number called n.\n  Return n add n.\n\
To run.\n  Print double of 21.\n";
        let asm = compile_to_asm_shared(src);
        assert!(
            asm.contains("call mathkit_1_0_double"),
            "an intra-library call must target the mangled label, not the bare name"
        );
        assert!(
            !asm.contains("call double\n") && !asm.contains("call double "),
            "the bare name must not be the call target in shared mode"
        );
    }

    // Acceptance item 2 — two source files each defining `greet` in one .so
    // — was deferred from A1. A1 mangled the labels but could not demonstrate
    // coexistence: the per-compilation symbol tables were keyed by the
    // AUTHORED name, so two `greet`s collided in `function_return_types` /
    // `function_param_types` (and the analyzer's `functions` /
    // `mangled_functions` / `function_param_counts`) even with distinct labels.
    // A2 scopes those tables by `<lib,version>` (keyed on the mangled label),
    // so the case is now provable. The unit test below mirrors it at the
    // codegen level; the end-to-end proof is `run_two_version_library_test` in
    // test.sh, which builds a real two-version .so through the CLI and calls
    // both versions from an assembly driver.

    #[test]
    fn two_versions_of_one_library_coexist_in_one_unit() {
        // The A1 finding, now resolved. Two VERSIONS of `flags` in one
        // compilation unit (exactly what the CLI concatenates from two inputs),
        // both defining `hasflag`, no longer collide: the signature tables are
        // keyed by the `<lib>_<ver>_<func>` label, so each definition emits and
        // exports its own mangled symbol. A call inside each library would
        // resolve to its own body; here we assert the definitions survive
        // side by side rather than the second overwriting the first.
        let src = "\
Library flags version \"0.1\".\n\
To hasflag with a number called n.\n  Return n add 1.\n\
Library flags version \"1.0\".\n\
To hasflag with a number called n.\n  Return n add 100.\n";
        let asm = compile_to_asm_shared(src);
        assert!(
            asm.contains("flags_0_1_hasflag:"),
            "version 0.1 must emit its own mangled label"
        );
        assert!(
            asm.contains("flags_1_0_hasflag:"),
            "version 1.0 must emit its own mangled label"
        );
        assert!(
            asm.contains("global flags_0_1_hasflag:function"),
            "version 0.1 must be exported under its mangled name"
        );
        assert!(
            asm.contains("global flags_1_0_hasflag:function"),
            "version 1.0 must be exported under its mangled name"
        );
        // The collision A1 found would let the second definition's signature
        // overwrite the first's; both labels must still be defined exactly
        // once (no silent merge, no duplicate-label NASM error pending). The
        // `\n` prefix counts the label DEFINITION line, not the
        // `global <label>:function` export line, which also ends in `:`.
        assert_eq!(
            asm.matches("\nflags_0_1_hasflag:").count(),
            1,
            "version 0.1 label defined exactly once"
        );
        assert_eq!(
            asm.matches("\nflags_1_0_hasflag:").count(),
            1,
            "version 1.0 label defined exactly once"
        );
    }

    #[test]
    fn two_version_call_resolves_within_its_own_library() {
        // A call to `hasflag` inside version 0.1's body must target
        // flags_0_1_hasflag, and a call inside 1.0's body must target
        // flags_1_0_hasflag — the same-library resolution that the scoped
        // tables make work. This is the wrong-code bug A1 warned about: with
        // name-keyed tables both calls would resolve against one signature.
        let src = "\
Library flags version \"0.1\".\n\
To hasflag with a number called n.\n  Return n add 1.\n\
To call0.\n  Return hasflag of 5.\n\
Library flags version \"1.0\".\n\
To hasflag with a number called n.\n  Return n add 100.\n\
To call1.\n  Return hasflag of 5.\n";
        let asm = compile_to_asm_shared(src);
        // `call0` lives in the 0.1 library, so its `hasflag` call targets the
        // 0.1 mangled label; `call1` lives in 1.0, so its call targets 1.0.
        assert!(
            asm.contains("call flags_0_1_hasflag"),
            "a call in the 0.1 library must target flags_0_1_hasflag"
        );
        assert!(
            asm.contains("call flags_1_0_hasflag"),
            "a call in the 1.0 library must target flags_1_0_hasflag"
        );
    }

    // ---- Stage A2 (corpus fix): differing signatures prove table scoping ----
    //
    // The flags corpus above (`two_versions_of_one_library_coexist_in_one_unit`
    // and `two_version_call_resolves_within_its_own_library`) gives both
    // versions of `hasflag` the SAME signature — a number in, a number out.
    // That proves the mangled LABELS are distinct and intra-library calls
    // target the right label, but it is blind to the bug A2 exists to prevent:
    // a failure to scope the SIGNATURE tables (`function_return_types` /
    // `function_param_types`) by <lib,version>. With identical signatures, a
    // collapsed (name-keyed) table produces byte-identical codegen to a scoped
    // one — the second library's return type "wins" but is the same value, so
    // nothing observable changes. A test that passes for the wrong reason
    // reports safety it is not checking.
    //
    // This case gives the two `get`s DIFFERENT return types — number in 0.1,
    // text in 1.0 — and consumes each result with `print`. The print routing
    // (PRINT_INT for a number, PRINT_CSTR for text) is driven by
    // `infer_expr_type`, which reads `function_return_types[function_label(name)]`
    // — the scoped lookup. If the table were keyed by authored name, 1.0's
    // `text` return would win for 0.1's `useit` too, and a number would be
    // printed with PRINT_CSTR: wrong code, no diagnostic. The assertions below
    // fail in exactly that collapse, so the case is now sensitive to the
    // signature-table scoping the flags corpus cannot see.

    /// The first `PRINT_*` instruction occurring after `anchor` in `asm`, used
    /// to check that a function-call result is routed by its inferred (scoped)
    /// return type. `"PRINT_INT "` / `"PRINT_CSTR "` (with the trailing space)
    /// avoid matching `PRINT_INT_ZEROPAD` / `PRINT_INT_PADDED`, which embed the
    /// `PRINT_INT` prefix under an underscore.
    fn first_print_after(asm: &str, anchor: &str) -> &'static str {
        let i = asm
            .find(anchor)
            .unwrap_or_else(|| panic!("anchor {:?} not found in asm", anchor));
        let rest = &asm[i..];
        let int = rest.find("PRINT_INT ");
        let cstr = rest.find("PRINT_CSTR ");
        match (int, cstr) {
            (Some(a), Some(b)) => {
                if a < b {
                    "PRINT_INT"
                } else {
                    "PRINT_CSTR"
                }
            }
            (Some(_), None) => "PRINT_INT",
            (None, Some(_)) => "PRINT_CSTR",
            (None, None) => panic!("no PRINT_* found after anchor {:?}", anchor),
        }
    }

    #[test]
    fn two_versions_differing_signatures_resolve_per_library() {
        let src = "\
Library sig version \"0.1\".\n\
To 'get' with a number called n.\n  Return a number, n add 1.\n\
To useit with a number called n.\n  Print 'get' of n.\n\n\
Library sig version \"1.0\".\n\
To 'get' with a number called n.\n  Return a text, \"hello\".\n\
To useit2 with a number called n.\n  Print 'get' of n.\n";
        let asm = compile_to_asm_shared(src);
        // The call inside each library targets its own `get` (the property
        // A2 scoped; restated here because this is the case that also carries
        // the return-type value).
        assert!(
            asm.contains("call sig_0_1_get"),
            "a call in the 0.1 library must target sig_0_1_get"
        );
        assert!(
            asm.contains("call sig_1_0_get"),
            "a call in the 1.0 library must target sig_1_0_get"
        );
        // The return-type VALUE is scoped per library: 0.1's `get` returns a
        // number, so `useit` prints it with PRINT_INT; 1.0's `get` returns text,
        // so `useit2` prints it with PRINT_CSTR. A name-keyed table would let
        // 1.0's `text` win for 0.1's call, making `useit` print a number with
        // PRINT_CSTR — the wrong-code bug, caught here.
        assert_eq!(
            first_print_after(&asm, "call sig_0_1_get"),
            "PRINT_INT",
            "0.1's get returns a number, so its result must print as PRINT_INT"
        );
        assert_eq!(
            first_print_after(&asm, "call sig_1_0_get"),
            "PRINT_CSTR",
            "1.0's get returns text, so its result must print as PRINT_CSTR"
        );
    }

    // ---- Stage A3: emit the `.lib` interface file ----

    /// Compile `source` in `--shared` mode and return the collected per-library
    /// signature blocks plus the mangled export labels, so the `.lib` render
    /// and the ToC↔export round-trip can be tested without shelling out to
    /// nasm/ld. Mirrors `compile_to_asm_shared` but exposes the codegen state.
    fn compile_shared_with_libs(source: &str) -> (Vec<LibBlock>, Vec<String>) {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("lib_test.vox", source);
        let mut program = parser
            .parse()
            .expect("shared test snippet should parse cleanly");
        let mut analyzer = Analyzer::new()
            .with_source("lib_test.vox", source)
            .with_shared_mode(true);
        analyzer.analyze(&mut program);
        assert!(
            analyzer.errors.is_empty(),
            "shared test snippet should analyze cleanly, got: {:?}",
            analyzer.errors
        );
        let mut gen = CodeGenerator::new();
        gen.set_shared_lib_mode(true);
        gen.generate(&program);
        (gen.library_blocks().to_vec(), gen.exported_functions().to_vec())
    }

    #[test]
    fn lib_file_two_version_round_trip() {
        // The showcase case: two versions of `flags` in one .so, each with a
        // typed return (`Return a number, ...`), so the `.lib` carries a
        // return type. The emitted `.lib` is pasted in the A3 report; this test
        // pins it to the normative format so a formatting drift fails here.
        let src = "\
Library flags version \"0.1\".\n\
To hasflag with a number called n.\n  Return a number, n add 1.\n\
Library flags version \"1.0\".\n\
To hasflag with a number called n.\n  Return a number, n add 100.\n";
        let (blocks, exports) = compile_shared_with_libs(src);

        // Two Library blocks, one per version, in source order.
        assert_eq!(blocks.len(), 2, "two inputs -> two Library blocks in one .lib");
        assert_eq!(blocks[0].lib, "flags");
        assert_eq!(blocks[0].version, "0.1");
        assert_eq!(blocks[1].lib, "flags");
        assert_eq!(blocks[1].version, "1.0");

        // Round-trip invariant (the one thing to test): each ToC entry, mangled
        // by its block's <lib, version>, must equal the exported dynamic
        // symbol set one-for-one. A4 will re-parse this `.lib` and verify the
        // same against `.dynsym`; here we verify it against the codegen's own
        // export list, which becomes `.dynsym` via the version script.
        let toc_mangled: Vec<String> = blocks
            .iter()
            .flat_map(|b| {
                b.funcs
                    .iter()
                    .map(|f| super::mangle_library_symbol(&b.lib, &b.version, &f.name))
            })
            .collect();
        let mut got = toc_mangled.clone();
        got.sort();
        let mut exp = exports.clone();
        exp.sort();
        assert_eq!(
            got, exp,
            "ToC mangled names must match exported_functions one-for-one"
        );

        // The emitted `.lib` for libflags.so (the normative format; one entry
        // per line, never wrapped; `Location` relative to the `.lib`). Written
        // as one literal — Rust's `\` line continuation strips leading
        // whitespace, which would silently drop the 4-space indent the format
        // requires, so the entry lines are kept on their `\n` continuation
        // line instead of split across one.
        let lib = super::render_lib_file(&blocks, "libflags.so");
        let expected = "Library flags version \"0.1\".\nLocation \"./libflags.so\".\n\nTable of Contents:\n    To hasflag with a number called n, returning a number.\n\nLibrary flags version \"1.0\".\nLocation \"./libflags.so\".\n\nTable of Contents:\n    To hasflag with a number called n, returning a number.\n";
        assert_eq!(lib, expected, "emitted .lib must match the normative format");
    }

    #[test]
    fn lib_file_return_first_statement_still_carries_return_type() {
        // Gate A regression: `Return` as the function's literal first
        // statement is handled by a separate inline path in
        // `parse_function_def`, not `parse_return`. This pins its output
        // unchanged by the Gate B fix below.
        let src = "\
Library ga version \"1.0\".\n\
To ga with a number called x.\n  Return a number, x.\n";
        let (blocks, _exports) = compile_shared_with_libs(src);
        let lib = super::render_lib_file(&blocks, "libga.so");
        assert!(
            lib.contains("To ga with a number called x, returning a number."),
            "Return as the first statement must still record its return type; got:\n{}",
            lib
        );
    }

    #[test]
    fn lib_file_return_after_other_statement_carries_return_type() {
        // Gate B: `Return` follows a local declaration, so it's parsed by
        // `parse_return`, not the inline first-statement path above. Before
        // the fix, `parse_return` validated the type annotation but never
        // wrote it back to `FunctionDef.return_type`, which stayed
        // `Type::Void` — so the .lib ToC silently dropped the `, returning
        // a <type>` clause for any function with real logic before its
        // `Return`. Covers all three types Gate B accepts today.
        let src = "\
Library gb version \"1.0\".\n\
To gbnum with a number called x.\n  a number called y is x add x.\n  Return a number, y.\n\
To gbtext with a text called s.\n  a text called t is s.\n  Return a text, t.\n\
To gbbool with a number called x.\n  a boolean called ok is true.\n  Return a boolean, ok.\n";
        let (blocks, _exports) = compile_shared_with_libs(src);
        let lib = super::render_lib_file(&blocks, "libgb.so");
        assert!(
            lib.contains("To gbnum with a number called x, returning a number."),
            "a number return after a preceding statement must not evaporate to void; got:\n{}",
            lib
        );
        assert!(
            lib.contains("To gbtext with a text called s, returning a text."),
            "a text return after a preceding statement must not evaporate to void; got:\n{}",
            lib
        );
        assert!(
            lib.contains("To gbbool with a number called x, returning a boolean."),
            "a boolean return after a preceding statement must not evaporate to void; got:\n{}",
            lib
        );
    }

    #[test]
    fn lib_file_signatures_carry_params_names_types_and_return() {
        // A library whose export has multiple parameters and a `value` return:
        // the `.lib` must carry every parameter (name + type), joined with
        // ` and `, and the return type as `, returning a value` (the `value` ABI
        // is fixed, so the type name alone is complete — no extra fields).
        let src = "\
Library m version \"2.0\".\n\
To f with a number called aa and a text called s and a value called v.\n  Return a value, v.\n";
        let (blocks, _exports) = compile_shared_with_libs(src);
        assert_eq!(blocks.len(), 1);
        let lib = super::render_lib_file(&blocks, "libm.so");
        assert!(
            lib.contains("To f with a number called aa and a text called s and a value called v, returning a value."),
            "multi-param entry joined with ` and `, value param/return by type name only; got:\n{}",
            lib
        );
    }

    #[test]
    fn lib_file_parameterless_and_void_return_omits_clauses() {
        // `To greet.` — no params, void return — reads as a bare entry with
        // no `with` clause and no `, returning` clause. A parameterless function
        // with a return reads `To makebuf, returning a number.`. This is the
        // parameterless / value-parameter readability the steer asked to settle.
        let src = "\
Library m version \"1.0\".\n\
To greet.\n  Print \"hi\".\n\n\
To makebuf.\n  Return a number, 7.\n";
        let (blocks, _exports) = compile_shared_with_libs(src);
        let lib = super::render_lib_file(&blocks, "libm.so");
        assert!(
            lib.contains("To greet."),
            "a parameterless void-return function reads `To greet.`; got:\n{}",
            lib
        );
        assert!(
            lib.contains("To makebuf, returning a number."),
            "a parameterless function with a return reads `To makebuf, returning a number.`; got:\n{}",
            lib
        );
    }

    #[test]
    fn bodyless_function_does_not_absorb_successor() {
        // A3 round-trip regression: a bodyless function (`To greet.` with no
        // body and no separating blank line) used to absorb the following
        // `To c ...` as a *nested* FunctionDef. The nested function was still
        // emitted (so it appeared in `nm -D`) but was invisible to the top-level
        // walk that collects `.lib` signatures, so the ToC dropped it while the
        // `.so` still exported it — a silent `.lib`/`.so` mismatch and the one
        // property this stage exists for. The parser now terminates a body on
        // `To`/`Library`, keeping the successor top-level. This asserts the
        // successor is collected (not absorbed) and that the ToC count equals
        // the export count — the class-wide invariant, not a name check.
        let src = "\
Library toc version \"1.0\".\n\
To aa. Return a number, 1.\n\
To greet.\n\
To c. Return a number, 3.\n";
        let (blocks, exports) = compile_shared_with_libs(src);
        assert_eq!(blocks.len(), 1);
        let names: Vec<&str> = blocks[0].funcs.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names, vec!["aa", "greet", "c"],
            "a bodyless `greet` must not absorb `c` into its body"
        );
        // ToC count == export count: each ToC entry, mangled by its block's
        // <lib, version>, must equal the exported set one-for-one.
        let toc_mangled: Vec<String> = blocks[0]
            .funcs
            .iter()
            .map(|f| super::mangle_library_symbol(&blocks[0].lib, &blocks[0].version, &f.name))
            .collect();
        let mut got = toc_mangled.clone();
        got.sort();
        let mut exp = exports.clone();
        exp.sort();
        assert_eq!(got, exp, "ToC count must equal exported function count");
    }

    #[test]
    fn non_shared_builds_keep_plain_labels() {
        // Non-shared builds must be completely unaffected: same labels as
        // today. The same source without --shared emits the bare mangled
        // name, no library prefix, no `:function` export.
        let src = "\
To greet.\n  Print \"hi\".\n\
To double with a number called n.\n  Return n add n.\n\
To run.\n  Print double of 21.\n";
        let asm = compile_to_asm(src);
        assert!(
            asm.contains("greet:"),
            "non-shared builds keep the plain mangled label"
        );
        assert!(
            asm.contains("call double"),
            "non-shared call sites target the plain mangled name"
        );
        assert!(
            !asm.contains("_1_0_"),
            "no library/version mangling outside shared mode"
        );
        assert!(
            !asm.contains(":function"),
            "the :function export tag is shared-mode only"
        );
    }

    #[test]
    fn unprovable_guard_never_suppresses_a_list_tag() {
        // The unprovable-scalar guard must not reach list-typed names: a list
        // variable's slot always holds a list pointer, so TAG_LIST is always
        // truthful. Suppressing it would write the integer tag and print the
        // nested list as a pointer instead of its contents.
        let asm = compile_to_asm(
            "a list called one is [1, 2].\n\
             a list called two is [3].\n\
             set two to one.\n\
             a list called outer is [].\n\
             append two to outer.\n",
        );
        assert!(
            asm.contains("mov edx, 4  ; element type tag"),
            "appending a list must write TAG_LIST even when the pre-scan could \
             not prove the alias's contents"
        );
    }

    #[test]
    fn type_predicate_never_compares_an_unset_r11() {
        // r11 carries a runtime tag only straight out of a mixed-list read.
        // An opaque function result has no tag anywhere, and the `call` that
        // produced it has already clobbered r11 - comparing against it would
        // read garbage. The predicate must answer statically instead.
        let asm = compile_to_asm(
            "To opaque with a number called n.\n  Return n add 1.\n\
             if opaque of 4 is a text, print \"t\".\n",
        );
        assert!(
            !asm.contains("cmp r11,"),
            "a tagless operand must not be compared against r11"
        );
    }

    #[test]
    fn type_predicate_on_unprovable_scalar_uses_declared_type() {
        // `unprovable_scalars` stops a declared type from being written as a
        // slot tag (it would forge a pointer), but a predicate only reads a
        // tag. It must still fold on the declared type rather than fall
        // through to a runtime compare against an unset r11.
        let asm = compile_to_asm(
            "a list called m is [\"a\", \"b\"].\n\
             append 42 to m.\n\
             a text called s is element 3 of m.\n\
             print \"sep\".\n\
             if s is a text, print \"t\".\n",
        );
        assert!(
            !asm.contains("cmp r11,"),
            "an unprovable scalar predicate must fold, not compare a stale r11"
        );
    }

    #[test]
    fn type_predicate_static_folds() {
        // A declared `a number called x` is statically integer, so
        // `x is a number` folds to true (no runtime compare) and `x is a
        // text` folds to false (a static-false jump, no cmp r11).
        let asm_true = compile_to_asm(
            "a number called x is 5.\nif x is a number, print \"n\".\n",
        );
        assert!(
            !asm_true.contains("cmp r11,"),
            "a statically-true predicate must fold (no runtime tag compare)"
        );

        let asm_false = compile_to_asm(
            "a number called x is 5.\nif x is a text, print \"t\".\n",
        );
        assert!(
            !asm_false.contains("cmp r11,"),
            "a statically-false predicate must fold (no runtime tag compare)"
        );
        assert!(
            asm_false.contains("statically false"),
            "a statically-false predicate must emit a fold-time jump to the false label"
        );
    }

    #[test]
    fn type_predicate_result_appends_tagged_boolean() {
        // Appending a predicate result (`append item is a number to flags`)
        // must tag the slot TAG_BOOLEAN (3) — not TAG_INTEGER — so the list
        // is a homogeneous boolean list (no mixed widening) and a later
        // `is a boolean` recognises its elements. Covers the TypeCheck arms
        // of prescan_expr_tag / emit_time_expr_tag and the append
        // element-type classifier reached only via `append <value> is a ...`.
        let asm = compile_to_asm(
            "a list called m is [1, 2, 3].\n\
             a list called flags is [].\n\
             For each item in m, append item is a number to flags.\n\
             For each f in flags, if f is a boolean, print \"B\".\n",
        );
        // The append stores tag 3 (TAG_BOOLEAN), not 0 (TAG_INTEGER).
        assert!(
            asm.contains("mov edx, 3"),
            "an appended predicate result must be tagged TAG_BOOLEAN (edx=3)"
        );
        // The list of predicate results stays homogeneous (no mixed widening
        // from the predicate appends), so it must not use the mixed print
        // dispatch.
        assert!(
            !asm.contains("mixp_"),
            "a list of predicate results must not widen to mixed"
        );
        // `f is a boolean` on the boolean-typed for-each variable folds true
        // (no runtime tag compare for f).
    }

    // ---- Stage 1d: dynamic `value` type across function boundaries (plan 030)
    //
    // A `value` parameter/return carries its runtime type tag through the
    // calling convention. These lock the ABI in at the asm level, independent
    // of the runtime: inbound (2 words per value param), outbound (tag in r11,
    // no spill), the 7-word straddle (reg/stack pad), and the append tag
    // forwarding for a value-returning call.

    #[test]
    fn value_param_carries_tag_inbound() {
        // Acceptance 1: a value parameter gets a shadow tag slot in the callee,
        // and the caller pushes a 2nd (tag) word for it. Inside the callee, a
        // predicate classifies by comparing the loaded tag to TAG_INTEGER (0).
        let asm = compile_to_asm(
            "To describe with a value called v.\n\
             If v is a number, print \"N\". Otherwise print \"T\".\n\
             a list called m is [1, \"two\"].\n\
             For each item in m, describe of item.\n",
        );
        // Caller pushes the value param's tag word (payload pushed after, on top).
        assert!(
            asm.contains("value param tag word"),
            "a value param must push a 2nd (tag) word at the call site"
        );
        // Callee stores the inbound tag byte to the value's shadow slot.
        assert!(
            asm.contains("param value tag"),
            "the callee must store the inbound value tag byte to a shadow slot"
        );
        // The predicate inside the callee compares the loaded tag to TAG_INTEGER.
        assert!(
            asm.contains("cmp r11, 0"),
            "the `v is a number` predicate must compare the loaded tag to 0"
        );
    }

    #[test]
    fn value_return_leaves_tag_in_r11() {
        // Acceptance 2: a value-returning function loads its result's tag into
        // r11 on the return path, and — because FUNC_EPILOGUE (`leave; ret`)
        // and `_dec_call_depth` clobber neither r11 nor the saved words — no
        // r11 spill is needed across the return.
        let asm = compile_to_asm(
            "To id with a value called v. Return a value, v.\n\
             a list called m is [1, \"two\"].\n\
             a list called out is [].\n\
             For each item in m, append id of item to out.\n",
        );
        // The return path loads the tag from the shadow slot, then the existing
        // `push rax / call _dec_call_depth / pop rax` epilogue. (This sequence
        // is distinct from the call-site tag load, which is followed by
        // `push r11  ; value param tag word`.)
        assert!(
            asm.contains("value tag (shadow slot)\n    push rax  ; save return value"),
            "the return path must load the value tag into r11 before the epilogue"
        );
        // No r11 spill: r11 is never pushed/popped around the return. r11 is not
        // a param register, so it is never saved in the prologue either.
        assert!(
            !asm.contains("pop r11"),
            "the value return tag rides in r11 across leave;ret with no spill"
        );
    }

    #[test]
    fn value_param_two_words_in_call() {
        // Acceptance 3: a value param occupies 2 argument words (payload, tag).
        // With 5 scalar params + 1 value param = 7 words, 6 fill the registers
        // and the 7th spills to the stack; an odd stack-word count needs the
        // alignment pad (`sub rsp, 8`), cleaned up by `add rsp, 16` (1 word + pad).
        let asm = compile_to_asm(
            "To f with a number called aa and a number called b and \
             a number called c and a number called d and a number called \
             e and a value called v.\n\
             If v is a text, print \"T\". Otherwise print \"N\".\n\
             f of 1 and 2 and 3 and 4 and 5 and \"hi\".\n",
        );
        // The value arg pushes a tag word then its payload (2 words for 1 param).
        assert!(
            asm.contains("value param tag word"),
            "a value argument must push a tag word in addition to its payload"
        );
        // 7 words total: 6 register words (popped into rdi..r9) + 1 stack word.
        assert!(
            asm.contains("pop r9") && asm.contains("pop rdi"),
            "the 6 register words must be popped into rdi..r9"
        );
        // Odd stack-word count (1) needs an alignment pad before the call.
        assert!(
            asm.contains("align stack before call"),
            "a 7-word call (1 stack word) must pad the stack before the call"
        );
        // Cleanup releases the 1 stack word + the 8-byte pad = 16 bytes.
        assert!(
            asm.contains("add rsp, 16"),
            "cleanup must release the stack word plus the alignment pad"
        );
    }

    #[test]
    fn append_fresh_mixed_element_keeps_tag() {
        // Plan 3f regression: appending a freshly-produced mixed value (here a
        // value-returning function call, whose tag is left in r11 by the callee)
        // must forward that tag into the list slot, not zero it. Previously the
        // append None-branch did `xor edx, edx`, dropping the tag.
        let asm = compile_to_asm(
            "To id with a value called v. Return a value, v.\n\
             a list called m is [1, \"two\"].\n\
             a list called out is [].\n\
             For each item in m, append id of item to out.\n",
        );
        // The append forwards the runtime tag from r11 into the slot.
        assert!(
            asm.contains("mov edx, r11d"),
            "appending a value-returning call must forward its tag from r11"
        );
        // The append must not zero the tag for a value-returning source.
        assert!(
            !asm.contains("xor edx, edx"),
            "the value-append must not zero the tag (the 3f latent-bug fix)"
        );
    }

    /// A nested list literal element's slot carries tag 4 (LIST), and a read
    /// of that element from the mixed parent dispatches on the runtime tag
    /// with a tag-4 branch that recurses into `_list_print` (plan 040 §1/§5).
    #[test]
    fn nested_list_literal_tags_slot_4() {
        let asm = compile_to_asm(
            "a list called nested is [1, [2, 3], \"four\"].\n\
             print element 2 of nested.\n",
        );
        // The nested element is index 1 -> "slot 2"; its slot tag is 4.
        assert!(
            asm.contains("4  ; slot 2 type tag"),
            "a nested list literal element's slot must carry tag 4 (LIST)"
        );
        // Reading element 2 of a mixed list uses the runtime-tag dispatch.
        assert!(
            asm.contains("mixp_"),
            "a mixed-list element read must use the mixed print dispatch"
        );
        assert!(
            asm.contains("cmp r11, 4"),
            "the mixed dispatch must branch on tag 4 (LIST)"
        );
        assert!(
            asm.contains("call _list_print"),
            "the tag-4 branch must recurse into _list_print"
        );
    }

    /// A homogeneous list-of-lists literal `[[1,2],[3,4]]` does NOT widen to
    /// mixed (all elements are tag 4), and a for-each loop var over it is
    /// typed `List` and prints via `_list_print`, not `PRINT_INT` (plan 040 §3).
    #[test]
    fn homogeneous_list_of_lists_not_mixed() {
        let asm = compile_to_asm(
            "a list called lol is [[1, 2], [3, 4]].\n\
             for each row in lol, print row.\n",
        );
        assert!(
            !asm.contains("mixp_"),
            "a homogeneous list-of-lists must not widen to mixed"
        );
        assert!(
            asm.contains("call _list_print"),
            "a list-typed for-each loop var must print via _list_print"
        );
    }

    /// `is a list` compiles to a runtime `cmp r11, 4` on a mixed element,
    /// and folds statically on a statically-typed list variable (plan 040
    /// §1/§6). In condition context a statically-true predicate falls through
    /// and a statically-false one jumps to the else branch with a comment
    /// naming the folded tag, so the false case is the observable evidence.
    #[test]
    fn is_a_list_predicate_compiles_to_cmp_4() {
        // Runtime path: a mixed-list element read leaves its tag in r11.
        let asm = compile_to_asm(
            "a list called m is [1, [2, 3], \"x\"].\n\
             if element 2 of m is a list, print \"L\".\n",
        );
        assert!(
            asm.contains("cmp r11, 4"),
            "`is a list` on a mixed element must compare the runtime tag to 4"
        );

        // Static fold: a declared list variable provably carries tag 4, so
        // `is a number` (tag 0) is statically false and jumps to the else
        // branch with a comment naming the folded static tag.
        let asm = compile_to_asm(
            "a list called xs is [1, 2, 3].\n\
             if xs is a number\n\
               print \"yes\"\n\
             otherwise\n\
               print \"no\".\n",
        );
        assert!(
            asm.contains("is a number statically false (static tag 4)"),
            "a static list (tag 4) must fold `is a number` to false"
        );
        assert!(
            !asm.contains("cmp r11, 4"),
            "a static list must not emit a runtime tag compare"
        );
    }

    /// Appending a list-typed value forwards tag 4 into the slot, not the
    /// integer default (plan 040 §1).
    #[test]
    fn append_list_value_forwards_tag_4() {
        let asm = compile_to_asm(
            "a list called inner is [9, 8].\n\
             a list called outer is [].\n\
             append inner to outer.\n",
        );
        assert!(
            asm.contains("mov edx, 4  ; element type tag"),
            "appending a list value must forward tag 4 (LIST)"
        );
        assert!(
            !asm.contains("xor edx, edx"),
            "appending a list value must not fall back to the integer tag"
        );
    }

    /// The recursive `_list_print` runtime has a depth guard (limit 64) that
    /// sets `_last_error` instead of overflowing the stack on a cycle, and a
    /// tag-4 branch that recurses (plan 040 §7). This locks the runtime asm
    /// in at the source level (independent of assembling/linking).
    #[test]
    fn list_print_has_depth_guard() {
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        assert!(
            list_asm.contains("%define LIST_TAG_LIST           4"),
            "_list_print must define the LIST tag constant"
        );
        assert!(
            list_asm.contains("cmp qword [rel _print_depth], 64"),
            "_list_print must cap recursion at depth 64 (shared _print_depth, stage 1e2)"
        );
        assert!(
            list_asm.contains("mov qword [rel _last_error], 1"),
            "the depth-guard path must set the error flag"
        );
        assert!(
            list_asm.contains("je .lp_list") && list_asm.contains("call _list_print"),
            "_list_print must recurse on the LIST tag"
        );
    }

    // ---- Stage 1e2: maps (tag 5) ----
    // These lock the map codegen routing in at the compiler level so a
    // regression is caught without assembling/linking (plan 050).

    #[test]
    fn map_literal_emits_map_insert() {
        let asm = compile_to_asm("a map called m is {\"a\": 1, \"b\": 2}.\n");
        assert!(
            asm.contains("call _map_new"),
            "a map literal must allocate via _map_new"
        );
        // One insert per pair.
        assert_eq!(
            asm.matches("call _map_insert").count(),
            2,
            "expected one _map_insert per pair"
        );
        assert!(
            asm.contains("%include \"coreasm/x86_64/map.asm\""),
            "map usage must include map.asm"
        );
    }

    #[test]
    fn map_literal_empty_emits_map_new() {
        let asm = compile_to_asm("a map called m is {}.\nprint m.\n");
        assert!(
            asm.contains("call _map_new"),
            "an empty map literal must still allocate via _map_new"
        );
        // No pairs -> no inserts.
        assert_eq!(
            asm.matches("call _map_insert").count(),
            0,
            "an empty map literal must not insert anything"
        );
        assert!(
            asm.contains("call _map_print"),
            "printing a map must route to _map_print"
        );
    }

    #[test]
    fn is_a_map_compiles_to_cmp_5() {
        // Runtime predicate on a value holding a map: the element's tag
        // travels in r11, so `is a map` compiles to `cmp r11, 5`. Mirrors the
        // `is a list` test (170) - iterate a mixed list so each item is a
        // runtime-tagged value.
        let asm = compile_to_asm(
            "for each item in [{\"a\": 1}, 2]\n  if item is a map, print \"M\".\n",
        );
        assert!(
            asm.contains("cmp r11, 5"),
            "`is a map` on a runtime-tagged value must compare against tag 5"
        );
    }

    #[test]
    fn is_a_map_folds_on_static_map() {
        // A statically-typed map variable is known to be a map at compile
        // time, so `is a map` folds to constant true and emits NO runtime
        // `cmp r11, 5` - the taken-branch print runs unconditionally.
        let asm = compile_to_asm(
            "a map called m is {\"a\": 1}.\nif m is a map, print \"yes\".\n",
        );
        assert!(
            !asm.contains("cmp r11, 5"),
            "`is a map` on a static map variable must fold (no runtime cmp)"
        );
        assert!(
            asm.contains("PRINT_STR") || asm.contains("PRINT_CSTR"),
            "the folded-true branch's print must still be emitted"
        );
    }

    #[test]
    fn map_access_emits_map_lookup_and_sets_r11() {
        let asm = compile_to_asm("a map called m is {\"a\": 1}.\nprint m's \"a\".\n");
        assert!(
            asm.contains("call _map_lookup"),
            "map key access must call _map_lookup"
        );
        // The looked-up value's tag travels in r11 and is dispatched on.
        assert!(
            asm.contains("cmp r11, 1"),
            "map access print must dispatch on the r11 tag"
        );
    }

    #[test]
    fn map_missing_key_emits_last_error_path() {
        // _map_lookup sets _last_error on a miss; the codegen doesn't need a
        // special path (the runtime owns the flag), but the lookup must be
        // emitted and the error flag must be observable.
        let asm = compile_to_asm(
            "a map called m is {\"a\": 1}.\nprint m's \"nope\".\non error print \"miss\".\n",
        );
        assert!(asm.contains("call _map_lookup"));
        // The on-error handler reads _last_error.
        assert!(
            asm.contains("_last_error"),
            "the on-error handler must reference _last_error"
        );
    }

    #[test]
    fn map_print_dispatch_tag_5() {
        // Mixed dispatch (used when a map is read into a value slot and
        // printed) must branch on tag 5 to _map_print. A `value` parameter
        // carries the map with its tag in a shadow slot, and `print v`
        // dispatches on it.
        let asm = compile_to_asm(
            "To 'show' with a value called v.\n  print v.\n\na map called m is {\"a\": 1}.\n'show' of m.\n",
        );
        assert!(
            asm.contains("cmp r11, 5") && asm.contains("call _map_print"),
            "mixed print dispatch must branch on tag 5 to _map_print"
        );
    }

    #[test]
    fn map_asm_has_fnv_constants() {
        let map_asm = include_str!("../../coreasm/x86_64/map.asm");
        assert!(
            map_asm.contains("0xcbf29ce484222325"),
            "map.asm must define the FNV-1a 64-bit offset basis"
        );
        assert!(
            map_asm.contains("0x100000001b3"),
            "map.asm must define the FNV-1a 64-bit prime"
        );
    }

    #[test]
    fn map_print_depth_guard_shared() {
        // The recursion-depth counter was renamed from _list_print_depth to a
        // shared _print_depth so a mixed map/list tree is cycle-safe under
        // one 64-deep budget. Both printers must reference the shared name.
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        let map_asm = include_str!("../../coreasm/x86_64/map.asm");
        assert!(
            !list_asm.contains("_list_print_depth"),
            "list.asm must no longer reference the old _list_print_depth"
        );
        assert!(
            list_asm.contains("_print_depth"),
            "list.asm must reference the shared _print_depth"
        );
        assert!(
            map_asm.contains("_print_depth"),
            "map.asm must reference the shared _print_depth"
        );
    }

    #[test]
    fn homogeneous_map_values_dont_widen() {
        // A whole-map print routes straight to _map_print (which reads each
        // entry's stored tag); it must NOT emit the mixp_ dispatch for the
        // whole-map print itself.
        let asm = compile_to_asm("a map called m is {\"a\": 1, \"b\": 2}.\nprint m.\n");
        assert!(
            asm.contains("call _map_print"),
            "whole-map print must route to _map_print"
        );
        assert!(
            !asm.contains("mixp_"),
            "a homogeneous whole-map print must not emit mixp_ dispatch"
        );
    }

    #[test]
    fn keys_values_sets_uses_lists() {
        // `map's keys`/`values` build a fresh list, so both list.asm and
        // map.asm must be included.
        let asm = compile_to_asm("a map called m is {\"a\": 1}.\nprint m's keys.\n");
        assert!(
            asm.contains("%include \"coreasm/x86_64/map.asm\""),
            "keys/values must include map.asm"
        );
        assert!(
            asm.contains("%include \"coreasm/x86_64/list.asm\""),
            "keys/values must also include list.asm (they build a list)"
        );
        assert!(
            asm.contains("call _map_keys"),
            "map's keys must call _map_keys"
        );
    }

    // ---- Stage 1e3: nothing/null (tag 6) ----
    // These lock the null feature in at the compiler level, independent of
    // the runtime: the literal threads tag 6 through the tag oracles, the
    // `is nothing` equality routes to a tag-6 compare (NOT the numeric
    // payload compare, so `0 is nothing` is false), the mixed print
    // dispatch has a nothing arm, and the recursive printers carry a
    // nothing label. The `nothing`/`null`/`nil` spellings are reserved.

    #[test]
    fn nothing_lit_emits_tag_6() {
        // A nothing literal inside a mixed list literal threads tag 6 via
        // prescan_expr_tag / emit_time_expr_tag: the element payload is 0
        // (`xor rax, rax`) and its slot tag byte is written as 6.
        let asm = compile_to_asm("a list called xs is [1, nothing, 2].\n");
        assert!(
            asm.contains("xor rax, rax  ; nothing literal, payload 0"),
            "a nothing literal must emit payload 0 with the nothing-literal comment"
        );
        assert!(
            asm.contains(", 6  ; slot 2 type tag"),
            "the nothing list element's slot must carry tag 6 (TAG_NOTHING)"
        );
    }

    #[test]
    fn is_nothing_emits_tag_compare() {
        // `is nothing` is the equality route. On a runtime-tagged `value`
        // parameter it must compare the loaded tag against 6 — NOT fall
        // through to the numeric `cmp rax, rbx` payload compare (which
        // would make `0 is nothing` true, since a nothing payload is 0).
        let asm = compile_to_asm(
            "To check with a value called v.\n\
             If v is nothing, print \"y\".\n\
             check of nothing.\n",
        );
        assert!(
            asm.contains("cmp r11, 6"),
            "`is nothing` on a value must compare the runtime tag against 6"
        );
        assert!(
            !asm.contains("cmp rax, rbx"),
            "`is nothing` must NOT use the numeric payload compare (0 is nothing must be false)"
        );
        // The static fold: `0 is nothing` is statically false (tag 0) and
        // jumps to the else branch with a comment naming the folded tag.
        let asm_fold = compile_to_asm("a number called n is 0.\nif n is nothing, print \"bug\".\n");
        assert!(
            asm_fold.contains("is not nothing folded (static tag 0)"),
            "a static integer (tag 0) must fold `is nothing` to false"
        );
        assert!(
            !asm_fold.contains("cmp r11, 6"),
            "a statically-folded `is nothing` must not emit a runtime tag compare"
        );
    }

    #[test]
    fn print_dispatch_has_nothing_arm() {
        // Printing a `value` that holds nothing dispatches on the runtime
        // tag and must branch on tag 6 to a nothing arm that prints the
        // `nothing` rodata string (mirrors the map/list dispatch arms).
        let asm = compile_to_asm(
            "To 'show' with a value called v.\n  print v.\n\n\
             a map called m is {\"k\": nothing}.\n'show' of m's \"k\".\n",
        );
        assert!(
            asm.contains("cmp r11, 6") && asm.contains("mixp_nothing"),
            "mixed print dispatch must branch on tag 6 to a nothing arm"
        );
        // A bare `print nothing.` routes through the explicit NothingLit
        // print arm (a `nothing` rodata string + PRINT_STR), not PRINT_INT.
        let asm_lit = compile_to_asm("print nothing.\n");
        assert!(
            asm_lit.contains("db 'nothing'") || asm_lit.contains("db \"nothing\""),
            "`print nothing.` must materialize a `nothing` rodata string"
        );
        assert!(
            !asm_lit.contains("PRINT_INT"),
            "`print nothing.` must not fall through to PRINT_INT"
        );
    }

    #[test]
    fn list_and_map_print_have_nothing_arms() {
        // The recursive printers must carry a nothing dispatch arm + label
        // so a nothing slot inside a list or map prints as `nothing` (and
        // closes the pre-existing LIST_TAG_MAP gap in list.asm).
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        assert!(
            list_asm.contains("%define LIST_TAG_NOTHING        6"),
            "list.asm must define LIST_TAG_NOTHING (6)"
        );
        assert!(
            list_asm.contains("cmp r8, LIST_TAG_NOTHING") && list_asm.contains(".lp_nothing:"),
            "_list_print must dispatch the nothing tag to a .lp_nothing label"
        );
        assert!(
            list_asm.contains("%define LIST_TAG_MAP            5")
                && list_asm.contains(".lp_map:"),
            "_list_print must also carry the map (tag 5) arm closed in 1e3"
        );

        let map_asm = include_str!("../../coreasm/x86_64/map.asm");
        assert!(
            map_asm.contains("%define MAP_TAG_NOTHING        6"),
            "map.asm must define MAP_TAG_NOTHING (6)"
        );
        assert!(
            map_asm.contains("cmp r8, MAP_TAG_NOTHING") && map_asm.contains(".mp_nothing:"),
            "_map_print must dispatch the nothing tag to a .mp_nothing label"
        );
    }

    #[test]
    fn nothing_keyword_reserved() {
        // The three null spellings lex to Token::Nothing and reserve via
        // as_keyword / string_is_keyword; `empty` stays its own keyword
        // (the size-emptiness property), so the split is clean.
        use crate::lexer::{Lexer, Token};
        let toks: Vec<Token> = Lexer::new("nothing null nil empty")
            .tokenize()
            .into_iter()
            .map(|ti| ti.token)
            .filter(|t| !matches!(t, Token::EOF))
            .collect();
        assert_eq!(toks.len(), 4, "the four words must each produce one token");
        assert!(toks.iter().all(|t| matches!(t, Token::Nothing | Token::Empty)),
            "nothing/null/nil -> Token::Nothing; empty -> Token::Empty");
        assert_eq!(toks[0], Token::Nothing);
        assert_eq!(toks[1], Token::Nothing);
        assert_eq!(toks[2], Token::Nothing);
        assert_eq!(toks[3], Token::Empty);
        // as_keyword reserves the word (drives check_not_keyword).
        assert_eq!(Token::Nothing.as_keyword(), Some("nothing"));
        assert_eq!(Token::Empty.as_keyword(), Some("empty"));
        // string_is_keyword catches the quoted-name form too.
        assert_eq!(Token::string_is_keyword("nothing"), Some("nothing"));
        assert_eq!(Token::string_is_keyword("null"), Some("nothing"));
        assert_eq!(Token::string_is_keyword("nil"), Some("nothing"));
        assert_eq!(Token::string_is_keyword("empty"), Some("empty"));

        // Using `nothing` as a variable name: the BARE form is rejected
        // (reserved keyword). The QUOTED form `'nothing'` is a legal — if
        // non-canonical — single-word quoted identifier (plan 270 §point 4),
        // and the S4 codemod relies on this: it rewrites `called "nothing"` to
        // `'nothing'`, so rejecting the quoted form would make the codemod
        // emit invalid code. Only the bare keyword is reserved; quoting escapes
        // it. (A keyword-named function `To 'show'` works the same way.)
        use crate::parser::Parser;
        fn parse_snippet(src: &str) -> Result<(), String> {
            let toks = Lexer::new(src).tokenize();
            match Parser::new(toks).parse() {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        let bare = parse_snippet("a number called nothing is 1.");
        assert!(bare.is_err(), "bare `nothing` as a name must be rejected");
        assert!(
            bare.unwrap_err().to_lowercase().contains("reserved"),
            "the error must call `nothing` a reserved keyword"
        );
        let quoted = parse_snippet("a number called 'nothing' is 1.");
        assert!(quoted.is_ok(), "quoted 'nothing' is a legal non-canonical name; only the bare form is reserved");
    }

    // -----------------------------------------------------------------
    // Plan 296 — full type-vocabulary parity, both `.lib` positions
    // -----------------------------------------------------------------
    //
    // Regression matrix: every one of the 11 expressible types (`Type::Void`
    // and `Type::Unknown` excluded by design — see
    // docs/plans/296_lib_collection_types.md) must parse and emit
    // identically as a `.lib` PARAMETER and a RETURN type. Each case goes
    // through the real pipeline — source -> `collect_function_signatures`
    // -> `render_lib_file` -> `parse_lib_text` — so a vocabulary drift
    // between the emitter (`type_noun`) and the parser (`take_type`) fails
    // here, not just a spot check of one side.
    #[test]
    fn plan_296_full_type_vocabulary_round_trips_both_positions() {
        let cases: &[(&str, Type)] = &[
            ("number", Type::Integer),
            ("float", Type::Float),
            ("text", Type::String),
            ("boolean", Type::Boolean),
            ("list", Type::List(Box::new(Type::Unknown))),
            ("map", Type::Map(Box::new(Type::Unknown))),
            ("buffer", Type::Buffer),
            ("file", Type::File),
            ("time", Type::Time),
            ("timer", Type::Timer),
            ("value", Type::Value),
        ];
        for (noun, expected) in cases {
            let src = format!(
                "Library matrix version \"1.0\".\nTo f with a {} called x.\n  Return a {}, x.\n",
                noun, noun
            );
            let (blocks, _exports) = compile_shared_with_libs(&src);
            assert_eq!(blocks.len(), 1, "case {}: one Library block", noun);
            assert_eq!(blocks[0].funcs.len(), 1, "case {}: one function", noun);
            let f = &blocks[0].funcs[0];
            assert_eq!(f.params[0].1, *expected, "case {}: emitted parameter type", noun);
            assert_eq!(f.return_type, *expected, "case {}: emitted return type", noun);

            let emitted = super::render_lib_file(&blocks, "libmatrix.so");
            let reparsed = crate::lib_file::parse_lib_text(&emitted).unwrap_or_else(|e| {
                panic!("case {}: emitted .lib failed to reparse: {}\n{}", noun, e, emitted)
            });
            let rf = &reparsed[0].funcs[0];
            assert_eq!(rf.params[0].1, *expected, "case {}: round-tripped parameter type; emitted:\n{}", noun, emitted);
            assert_eq!(rf.return_type, *expected, "case {}: round-tripped return type; emitted:\n{}", noun, emitted);
        }
    }

    // List element typing (plan 296, "Element typing crosses the .lib
    // boundary"): every scalar noun `take_list_type` accepts as a list
    // element must be correctly INFERRED from a single `Append <expr> to
    // <param>` site where `<expr>` references a same-named-type parameter
    // (the plan's own verified repro appends a parameter: `Append s to
    // out.`), emitted as `list of <noun>`, and round-trip back through the
    // parser to the same `Type`.
    #[test]
    fn plan_296_list_element_type_matrix_parameter() {
        let cases: &[(&str, Type)] = &[
            ("number", Type::Integer),
            ("float", Type::Float),
            ("text", Type::String),
            ("boolean", Type::Boolean),
            ("file", Type::File),
            ("buffer", Type::Buffer),
            ("time", Type::Time),
            ("timer", Type::Timer),
            ("value", Type::Value),
        ];
        for (noun, expected) in cases {
            let src = format!(
                "Library elemkit version \"1.0\".\nTo f with a {} called s and a list called out.\n  Append s to out.\n",
                noun
            );
            let (blocks, _exports) = compile_shared_with_libs(&src);
            let f = &blocks[0].funcs[0];
            let want = Type::List(Box::new(expected.clone()));
            assert_eq!(
                f.params[1].1, want,
                "case {}: inferred parameter element type; got params {:?}", noun, f.params
            );

            let emitted = super::render_lib_file(&blocks, "libelem.so");
            assert!(
                emitted.contains(&format!("a list of {} called out", noun)),
                "case {}: emitted .lib must render 'list of {}'; got:\n{}", noun, noun, emitted
            );
            let reparsed = crate::lib_file::parse_lib_text(&emitted).expect("reparse emitted .lib");
            assert_eq!(
                reparsed[0].funcs[0].params[1].1, want,
                "case {}: round-tripped parameter element type", noun
            );
        }
    }

    // Same matrix for a RETURNED list: the element type is inferred from a
    // local list variable built with `Append` inside the function and
    // returned with a declared `Return a list, <name>.` (bare, undeclared
    // `Return <name>.` records no return type at all — see
    // `lib_file_return_after_other_statement_carries_return_type` and
    // LANGUAGE.md's ".lib" section: an entry with no `returning` clause
    // means the function returns nothing, so a declared return type is the
    // precondition for the `.lib` to say anything about the return at all).
    #[test]
    fn plan_296_list_element_type_matrix_return() {
        let cases: &[(&str, Type)] = &[
            ("number", Type::Integer),
            ("float", Type::Float),
            ("text", Type::String),
            ("boolean", Type::Boolean),
            ("file", Type::File),
            ("buffer", Type::Buffer),
            ("time", Type::Time),
            ("timer", Type::Timer),
            ("value", Type::Value),
        ];
        for (noun, expected) in cases {
            let src = format!(
                "Library elemretkit version \"1.0\".\nTo f with a {} called s.\n  a list called out is [].\n  Append s to out.\n  Return a list, out.\n",
                noun
            );
            let (blocks, _exports) = compile_shared_with_libs(&src);
            let f = &blocks[0].funcs[0];
            let want = Type::List(Box::new(expected.clone()));
            assert_eq!(
                f.return_type, want,
                "case {}: inferred return element type; got {:?}", noun, f.return_type
            );

            let emitted = super::render_lib_file(&blocks, "libelemret.so");
            assert!(
                emitted.contains(&format!(", returning a list of {}", noun)),
                "case {}: emitted .lib must render 'returning a list of {}'; got:\n{}", noun, noun, emitted
            );
            let reparsed = crate::lib_file::parse_lib_text(&emitted).expect("reparse emitted .lib");
            assert_eq!(
                reparsed[0].funcs[0].return_type, want,
                "case {}: round-tripped return element type", noun
            );
        }
    }

    // A list that disagrees on element type (or has none at all) must stay
    // untyped, exactly as before this plan — a wrong guess would be worse
    // than no annotation.
    #[test]
    fn plan_296_list_element_type_stays_unknown_on_disagreement_or_no_evidence() {
        let disagreeing = "\
Library mixedkit version \"1.0\".\n\
To f with a text called s and a number called n and a list called out.\n  \
Append s to out.\n  Append n to out.\n";
        let (blocks, _) = compile_shared_with_libs(disagreeing);
        assert_eq!(blocks[0].funcs[0].params[2].1, Type::List(Box::new(Type::Unknown)));

        let no_evidence = "\
Library emptykit version \"1.0\".\n\
To f with a list called out.\n  Print \"noop\".\n";
        let (blocks, _) = compile_shared_with_libs(no_evidence);
        assert_eq!(blocks[0].funcs[0].params[0].1, Type::List(Box::new(Type::Unknown)));
    }

    // ---- Plan 303 phase 2 — BUGS_FOUND #18: the four shapes the plan 296
    // scan under-credited, plus the newly-sound format-string shape (BUGS_FOUND
    // #17), each checked in both a list PARAMETER and a list RETURN position. ----

    #[test]
    fn plan_303_local_declared_type_credits_element_parameter() {
        // "text local from literal, appended by name" (BUGS_FOUND #18 row 3):
        // a local's declared scalar type is authoritative for its reads, the
        // same way a parameter's declared type already was.
        let src = "\
Library elemkit version \"1.0\".\n\
To f with a list called out.\n  \
a text called s is \"literal\".\n  \
Append s to out.\n";
        let (blocks, _) = compile_shared_with_libs(src);
        assert_eq!(
            blocks[0].funcs[0].params[0].1,
            Type::List(Box::new(Type::String)),
            "a local's declared text type must be credited"
        );
    }

    #[test]
    fn plan_303_call_declared_return_type_credits_element_parameter() {
        // "call to a function with a declared text return" (BUGS_FOUND #18
        // row 6): the callee's declared return type is authoritative for the
        // call expression's type, the same way it already is for
        // `infer_expr_type`'s Expr::FunctionCall arm in ordinary codegen.
        let src = "\
Library elemkit version \"1.0\".\n\
To helper with a number called n.\n  Return a text, \"hi\".\n\
To f with a list called out.\n  \
Append helper of 1 to out.\n";
        let (blocks, _) = compile_shared_with_libs(src);
        assert_eq!(
            blocks[0].funcs[1].params[0].1,
            Type::List(Box::new(Type::String)),
            "a same-library call's declared text return must be credited"
        );
    }

    #[test]
    fn plan_303_format_string_credits_element_parameter() {
        // "format-string appends" (BUGS_FOUND #18 row 5): sound once phase 1
        // (BUGS_FOUND #17) made the appended element itself a real text
        // pointer rather than a mistagged one.
        let src = "\
Library elemkit version \"1.0\".\n\
To f with a list called out.\n  \
a number called n is 7.\n  \
Append \"n {n}\" to out.\n";
        let (blocks, _) = compile_shared_with_libs(src);
        assert_eq!(
            blocks[0].funcs[0].params[0].1,
            Type::List(Box::new(Type::String)),
            "a format-string append must be credited as text"
        );
    }

    #[test]
    fn plan_303_newly_credited_shapes_in_return_position() {
        // The same three shapes, but for a RETURNED list built and appended
        // to inside the function body rather than an appended-to parameter.
        let local_literal = "\
Library elemkit version \"1.0\".\n\
To f.\n  a list called out is [].\n  \
a text called s is \"literal\".\n  Append s to out.\n  \
Return a list, out.\n";
        let (blocks, _) = compile_shared_with_libs(local_literal);
        assert_eq!(
            blocks[0].funcs[0].return_type,
            Type::List(Box::new(Type::String)),
            "a local's declared text type must be credited in return position"
        );

        let call_return = "\
Library elemkit version \"1.0\".\n\
To helper with a number called n.\n  Return a text, \"hi\".\n\
To f.\n  a list called out is [].\n  Append helper of 1 to out.\n  \
Return a list, out.\n";
        let (blocks, _) = compile_shared_with_libs(call_return);
        assert_eq!(
            blocks[0].funcs[1].return_type,
            Type::List(Box::new(Type::String)),
            "a same-library call's declared return must be credited in return position"
        );

        let format_string = "\
Library elemkit version \"1.0\".\n\
To f.\n  a list called out is [].\n  a number called n is 7.\n  \
Append \"n {n}\" to out.\n  Return a list, out.\n";
        let (blocks, _) = compile_shared_with_libs(format_string);
        assert_eq!(
            blocks[0].funcs[0].return_type,
            Type::List(Box::new(Type::String)),
            "a format-string append must be credited as text in return position"
        );
    }

    #[test]
    fn plan_303_function_call_return_type_scoped_per_library() {
        // Two libraries in one file each define `helper` with a DIFFERING
        // declared return type. `collect_lib_function_return_types` must scope
        // by (library, version) so libb's `g` doesn't credit liba's `helper`
        // (or vice versa) — a flat name-keyed map would let whichever library
        // is collected last win for both, silently mis-annotating one.
        let src = "\
Library liba version \"1.0\".\n\
To helper with a number called n.\n  Return a number, n.\n\
To f with a list called out.\n  Append helper of 1 to out.\n\n\
Library libb version \"1.0\".\n\
To helper with a number called n.\n  Return a text, \"hi\".\n\
To g with a list called out.\n  Append helper of 1 to out.\n";
        let (blocks, _) = compile_shared_with_libs(src);
        assert_eq!(blocks.len(), 2, "two Library blocks");
        assert_eq!(
            blocks[0].funcs[1].params[0].1,
            Type::List(Box::new(Type::Integer)),
            "liba's f must credit liba's own number-returning helper"
        );
        assert_eq!(
            blocks[1].funcs[1].params[0].1,
            Type::List(Box::new(Type::String)),
            "libb's g must credit libb's own text-returning helper, not liba's"
        );
    }

    #[test]
    fn plan_303_local_declared_type_conflict_stays_unknown() {
        // A local declared with two disagreeing scalar types (once per `if`
        // branch, each appending its own `s` immediately - a bare
        // post-branch read of a branch-only local is a separate analyzer
        // error, unrelated to this scan) must not be guessed either way —
        // this scan is non-flow-sensitive and can't tell which declaration a
        // given append sees, so the conservative behaviour (same as plan
        // 296's own disagreement guard) is to drop it as evidence entirely.
        let src = "\
Library elemkit version \"1.0\".\n\
To f with a boolean called cond and a list called out.\n  \
If cond, a text called s is \"a\", append s to out. \
Otherwise, a number called s is 1, append s to out.\n";
        let (blocks, _) = compile_shared_with_libs(src);
        assert_eq!(
            blocks[0].funcs[0].params[1].1,
            Type::List(Box::new(Type::Unknown)),
            "a local declared with conflicting types across branches must not be credited"
        );
    }

    // ---- Plan 305 — BUGS_FOUND #20: stringy-vs-non-stringy equality must
    // never dereference the non-stringy operand. Pinned at the codegen
    // level (no _str_eq/_mem_eq/_buffer_length call emitted) in addition to
    // the tests/bugs_found_20_*.vox end-to-end coverage, since a refactor
    // that kept an exit-0 answer by accident (e.g. a coincidentally-valid
    // read) wouldn't be caught by output alone. ----

    #[test]
    fn stringy_vs_non_stringy_condition_never_dereferences() {
        // generate_condition's Equal/NotEqual arm (BUGS_FOUND #20 site 1).
        let asm = compile_to_asm(
            "If \"abc\" is equal to 3.5 then, print \"a\". Otherwise, print \"b\".\n",
        );
        assert!(
            !asm.contains("call _str_eq") && !asm.contains("call _mem_eq"),
            "a stringy-vs-float mismatch must not reach the byte-comparison path"
        );
    }

    #[test]
    fn stringy_vs_non_stringy_expression_never_dereferences() {
        // generate_expr's structurally identical Equal/NotEqual arm
        // (BUGS_FOUND #20 site 2). `Return a boolean, <comparison>.` is real
        // surface syntax that reaches it (confirmed against the pre-fix
        // binary: SIGSEGV; the red team's own search hadn't found this one).
        let asm = compile_to_asm(
            "To f.\n  Return a boolean, \"abc\" is equal to 3.\n",
        );
        assert!(
            !asm.contains("call _str_eq") && !asm.contains("call _mem_eq"),
            "a stringy-vs-integer mismatch in expression position must not \
             reach the byte-comparison path"
        );
    }

    #[test]
    fn both_stringy_equality_still_dereferences_correctly() {
        // Contrast with the above: two genuinely stringy operands must still
        // take the real content-comparison path - the fix narrows the guard,
        // it must not disable it.
        let asm = compile_to_asm(
            "a text called t is \"hi\".\nIf t is equal to \"hi\" then, print \"a\". Otherwise, print \"b\".\n",
        );
        assert!(
            asm.contains("call _str_eq"),
            "a text-vs-literal equality must still use byte comparison"
        );
    }

    /// Track B4 regression guard: the consuming one-byte exact-fill probe
    /// (read 1 byte into a stack slot + lseek(-1, SEEK_CUR) to put it back)
    /// must stay removed from the runtime. It lost a byte on unseekable fds
    /// (issue #8). Asserted at the source level because the probe is gone from
    /// the assembled object iff it is gone from resource.asm.
    #[test]
    fn b4_exact_fill_probe_is_removed_from_runtime() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("coreasm").join("x86_64").join("resource.asm");
        let asm = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        assert!(!asm.contains("Probe for additional data using a scratch byte"),
            "the consuming one-byte probe comment must be removed from resource.asm");
        assert!(!asm.contains("mov rsi, -1"),
            "the probe's lseek(fd, -1, SEEK_CUR) put-back must be removed from resource.asm");
        assert!(!asm.contains(".no_more_data"),
            "the old probe's .no_more_data branch must be removed from resource.asm");
        assert!(asm.contains("fd_mode_table"), "fd_mode_table cache must be present");
        assert!(asm.contains("fd_size_table"), "fd_size_table cache must be present");
        assert!(asm.contains("S_IFREG"), "regular-file type check must be present");
        assert!(asm.contains("SYS_FSTAT"), "fstat syscall constant must be present");
        assert!(asm.contains(".exact_fit_success"),
            "the seekability-aware exact-fit decision must be present");
    }

    /// Static lint: every runtime helper that can set _last_error on failure
    /// must also clear it to 0 on its success path. This locks the lifecycle
    /// rule in at the asm source level so a regression is caught without
    /// assembling/linking.
    #[test]
    fn last_error_runtime_helpers_clear_on_success() {
        let int_asm = include_str!("../../coreasm/x86_64/int.asm");
        let float_asm = include_str!("../../coreasm/x86_64/float.asm");
        let list_asm = include_str!("../../coreasm/x86_64/list.asm");
        let map_asm = include_str!("../../coreasm/x86_64/map.asm");

        fn function_body_has_clear(asm: &str, name: &str) -> bool {
            let label = format!("{}:", name);
            let start = asm
                .find(&label)
                .unwrap_or_else(|| panic!("{} label not found", name));
            let rest = &asm[start..];
            let lines: Vec<&str> = rest.lines().collect();
            let end = lines
                .iter()
                .position(|l| l.trim() == "ret")
                .unwrap_or_else(|| panic!("{} has no ret", name));
            lines[..end].join("\n").contains("mov qword [rel _last_error], 0")
        }

        fn macro_body_has_clear(asm: &str, name: &str) -> bool {
            let open = format!("%macro {} 0", name);
            let start = asm
                .find(&open)
                .unwrap_or_else(|| panic!("%macro {} not found", name));
            let rest = &asm[start..];
            let lines: Vec<&str> = rest.lines().collect();
            let end = lines
                .iter()
                .position(|l| l.trim() == "%endmacro")
                .unwrap_or_else(|| panic!("%endmacro for {} not found", name));
            lines[..end].join("\n").contains("mov qword [rel _last_error], 0")
        }

        assert!(
            function_body_has_clear(int_asm, "_parse_i64"),
            "_parse_i64 must clear _last_error on success"
        );
        assert!(
            function_body_has_clear(int_asm, "_parse_int_radix"),
            "_parse_int_radix must clear _last_error on success"
        );
        assert!(
            function_body_has_clear(int_asm, "_parse_i64_bounded"),
            "_parse_i64_bounded must clear _last_error on success"
        );
        assert!(
            function_body_has_clear(int_asm, "_parse_int_radix_bounded"),
            "_parse_int_radix_bounded must clear _last_error on success"
        );
        assert!(
            macro_body_has_clear(int_asm, "INT_DIV"),
            "INT_DIV must clear _last_error on its non-zero-divisor path"
        );
        assert!(
            macro_body_has_clear(int_asm, "INT_MOD"),
            "INT_MOD must clear _last_error on its non-zero-divisor path"
        );

        assert!(
            function_body_has_clear(float_asm, "_parse_f64"),
            "_parse_f64 must clear _last_error on success"
        );
        assert!(
            function_body_has_clear(float_asm, "_parse_f64_bounded"),
            "_parse_f64_bounded must clear _last_error on success"
        );

        assert!(
            function_body_has_clear(list_asm, "_list_print"),
            "_list_print must clear _last_error on its normal return path"
        );

        assert!(
            function_body_has_clear(map_asm, "_map_lookup"),
            "_map_lookup must clear _last_error on a hit"
        );
        assert!(
            function_body_has_clear(map_asm, "_map_print"),
            "_map_print must clear _last_error on its normal return path"
        );
    }
