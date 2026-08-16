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
