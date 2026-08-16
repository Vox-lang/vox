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
    fn variable_declared_under_same_guard_is_available_under_same_guard_later() {
        let input = r#"
            if "number lines" then,
                a number called 'line number' is 1.

            if "number lines" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn variable_declared_under_different_guard_is_not_available() {
        let input = r#"
            if "number lines" then,
                a number called 'line number' is 1.

            if "verbose" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Unknown variable: line number")),
            "expected unknown-variable error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn guarded_variable_is_available_in_nested_while_for_repeat_blocks() {
        let input = r#"
            if "number lines" then,
                a number called 'line number' is 1.

            if "number lines" then,
                while true,
                    for each item in arguments's all,
                        repeat 1 times,
                            Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn variable_declared_under_same_and_condition_is_available() {
        let input = r#"
            if "number lines" and "verbose" then,
                a number called 'line number' is 1.

            if "number lines" and "verbose" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn variable_declared_under_same_not_condition_is_available() {
        let input = r#"
            if not "number lines" then,
                a number called 'line number' is 1.

            if not "number lines" then,
                Print "{line number:6}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: line number")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn unknown_variable_inside_function_is_reported() {
        let input = r#"
            To 'show',
                Print "{missing}".

            'show'.
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
    fn top_level_global_variable_is_available_inside_function() {
        let input = r#"
            A text called 'Program Version' is "0.1.3".

            To 'show',
                Print "{Program Version}".

            'show'.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown variable: Program Version")),
            "unexpected unknown-variable errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn function_local_variable_is_not_available_at_top_level() {
        let input = r#"
            To 'make',
                a number called temp is 1.

            Print "{temp}".
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Unknown variable: temp") || e.message.contains("Unknown identifier 'temp'")),
            "expected unknown-variable error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn branch_local_identifier_named_like_keyword_is_not_false_positive() {
        let input = r#"
            If arguments's count is greater than 1 then,
                a text called arg1 is arguments's first,
                Print the arg1.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .all(|e| !e.message.contains("Unknown identifier 'arg1'") && !e.message.contains("Unknown variable: arg1")),
            "unexpected arg1 errors: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn flag_schema_after_non_schema_code_is_allowed() {
        let input = r#"
            Print "hello".
            a flag called verbose is "-v" or "--verbose", it is a boolean.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer.errors.is_empty(),
            "expected no errors for schema after non-schema code, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn flag_schema_after_explicit_parse_is_rejected() {
        let input = r#"
            a flag called verbose is "-v" or "--verbose", it is a boolean.
            parse flags.
            a flag called debug is "-d" or "--debug", it is a boolean.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Cannot declare new flags after 'parse flags.'")),
            "expected post-parse schema error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn duplicate_parse_flags_statement_is_rejected() {
        let input = r#"
            a flag called verbose is "-v" or "--verbose", it is a boolean.
            parse flags.
            parse flags.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Duplicate 'parse flags.' statement")),
            "expected duplicate-parse error, got: {:?}",
            analyzer.errors
        );
    }

    #[test]
    fn flag_usage_before_explicit_parse_is_rejected() {
        let input = r#"
            a flag called verbose is "-v" or "--verbose", it is a boolean.
            Print "{verbose}".
            parse flags.
        "#;

        let analyzer = analyze_input(input);
        assert!(
            analyzer
                .errors
                .iter()
                .any(|e| e.message.contains("Flag variable 'verbose' is used before flags are parsed")),
            "expected pre-parse usage error, got: {:?}",
            analyzer.errors
        );
    }
