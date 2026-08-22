    use super::*;
    use crate::lexer::Lexer;
    use crate::parser::Parser;

    fn analyze_input(input: &str) -> Analyzer {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        let mut program = parser.parse().expect("input should parse");
        let mut analyzer = Analyzer::new().with_source("test.en", input);
        analyzer.analyze(&mut program);
        analyzer
    }

    #[test]
    fn append_requires_buffer_source_when_destination_is_buffer() {
        let input = r#"
            a buffer called dst is "hello".
            a number called n is 7.
            append n to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Buffer append requires")),
            "expected buffer-append type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn quoted_condition_unknown_variable_inside_function_is_reported() {
        let input = r#"
            To mutate,
                if 'missing' then,
                    Print "ok".

            'mutate'.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Unknown variable: missing")),
            "expected unknown-variable error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn quoted_condition_top_level_global_inside_function_is_allowed() {
        let input = r#"
            a boolean called counter is true.

            To bump,
                if 'counter' then,
                    Print "ok".

            'bump'.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: counter")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn copy_requires_buffers_for_both_operands() {
        let input = r#"
            a buffer called dst is "hello".
            a number called n is 7.
            copy n to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Copy source must be a buffer")),
            "expected copy-source type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn clear_requires_buffer_operand() {
        let input = r#"
            a number called n is 7.
            clear n.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Clear target must be a buffer")),
            "expected clear-target type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn append_allows_format_string_when_destination_is_buffer() {
        let input = r#"
            a number called n is 7.
            a buffer called dst is "".
            append "N={n:04}" to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Buffer append requires")),
            "unexpected buffer-append error(s): {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn copy_allows_format_string_source() {
        let input = r#"
            a number called n is 7.
            a buffer called dst is "".
            copy "N={n:04}" to dst.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Copy source must be a buffer") && !e.message.contains("Copy source must be a buffer or format/literal text")),
            "unexpected copy-source error(s): {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_rejects_float_path_literal() {
        let input = r#"
            open a file for reading called source at 1.5.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Open path must be either a text path")),
            "expected open-path type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_rejects_boolean_path_literal() {
        let input = r#"
            open a file for reading called source at true.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Open path must be either a text path")),
            "expected open-path type error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_rejects_fd_literal_out_of_range() {
        let input = r#"
            open a file for reading called source at -1.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("File descriptor out of range")),
            "expected fd-range error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn file_open_accepts_string_path_and_fd_literal() {
        let input = r#"
            open a file for reading called source at "./data.txt".
            open a file for writing called output at 1.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Open path must be either a text path") && !e.message.contains("File descriptor out of range")),
            "unexpected open-path errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_rejects_mismatched_match_and_replacement_types() {
        let input = r#"
            print each filename from arguments's all treating "-" as 0.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Treating match and replacement must be the same type")),
            "expected treating type mismatch error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_allows_same_type_substitution() {
        let input = r#"
            print each filename from arguments's all treating "-" as "/dev/stdin".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Treating match and replacement must be the same type")),
            "unexpected treating type mismatch error(s): {:?}",
            analyzer.errors
        );
    }

    /// Bug #55. The two checks above only ever compared the clause's own
    /// operands to each other. The SUBJECT - the loop variable, holding an
    /// element of the collection being walked - was invisible to them,
    /// because `infer_simple_expr_type` answers None for a plain name. So a
    /// match of the wrong type for that collection compiled clean and the
    /// emitted `_str_eq` dereferenced it.
    ///
    /// Note both `arguments's all` cases above still pass: an argument
    /// list has no provable element type, so nothing new fires there.
    #[test]
    fn treating_rejects_a_match_mistyped_for_a_list_literal() {
        let input = r#"
            print each item from ["a"] treating 98 as 31.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Treating value and match must be the same type (got text vs number)")),
            "expected the subject/match mismatch to be rejected, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_rejects_a_match_mistyped_for_a_named_list() {
        let input = r#"
            a list called words is ["a", "b"].
            print each item from words treating 98 as 31.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Treating value and match must be the same type (got text vs number)")),
            "expected the subject/match mismatch to be rejected, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_rejects_a_text_match_over_a_range() {
        let input = r#"
            print each step from 1 to 3 treating "a" as "b".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Treating value and match must be the same type (got number vs text)")),
            "expected the range loop variable's type to be checked, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn treating_accepts_a_match_of_the_collection_element_type() {
        let input = r#"
            a list called sources is ["-", "report.txt"].
            print each source from sources treating "-" as "/dev/stdin".
            print each count from [1, 2] treating 1 as 9.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Treating value and match must be the same type")),
            "unexpected treating type mismatch error(s): {:?}",
            analyzer.errors
        );
    }

    /// Over a list proven MIXED the loop variable genuinely holds a
    /// different type each iteration, so there is no static answer to give
    /// and the clause is left alone - the same policy `value`-typed names
    /// get everywhere else.
    #[test]
    fn treating_leaves_a_mixed_list_to_the_runtime() {
        let input = r#"
            print each item from [1, "a"] treating 98 as 31.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Treating value and match must be the same type")),
            "a mixed list has no provable element type to check against: {:?}",
            analyzer.errors
        );
    }
