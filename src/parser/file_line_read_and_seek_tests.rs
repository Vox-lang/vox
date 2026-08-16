    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    #[test]
    fn test_parse_read_line_statement() {
        let input = r#"Read line from source into linebuf."#;
        let result = parse_input(input).expect("read line should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FileReadLine { source, buffer } => {
                assert_eq!(source, "source");
                assert_eq!(buffer, "linebuf");
            }
            other => panic!("Expected FileReadLine, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_read_line_statement_with_optional_article_before_buffer() {
        let input = r#"Read line from source into the linebuf."#;
        let result = parse_input(input).expect("read line with optional article before buffer should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FileReadLine { source, buffer } => {
                assert_eq!(source, "source");
                assert_eq!(buffer, "linebuf");
            }
            other => panic!("Expected FileReadLine, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_read_line_statement_with_optional_article_before_source() {
        let input = r#"Read line from the source into linebuf."#;
        let result = parse_input(input).expect("read line with optional article should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FileReadLine { source, buffer } => {
                assert_eq!(source, "source");
                assert_eq!(buffer, "linebuf");
            }
            other => panic!("Expected FileReadLine, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_seek_line_statement() {
        let input = r#"Seek source to line 1."#;
        let result = parse_input(input).expect("seek line should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FileSeekLine { file, line } => {
                assert_eq!(file, "source");
                assert!(matches!(line, Expr::IntegerLit(1)));
            }
            other => panic!("Expected FileSeekLine, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_seek_byte_statement() {
        let input = r#"Seek source to byte 1."#;
        let result = parse_input(input).expect("seek byte should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FileSeekByte { file, byte } => {
                assert_eq!(file, "source");
                assert!(matches!(byte, Expr::IntegerLit(1)));
            }
            other => panic!("Expected FileSeekByte, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_read_line_requires_from_keyword() {
        let input = r#"Read line source into linebuf."#;
        let err = parse_input(input).expect_err("missing 'from' should fail");
        assert!(err.to_string().contains("'from' after 'read line'"));
    }

    #[test]
    fn test_parse_seek_requires_mode() {
        let input = r#"Seek source to 1."#;
        let err = parse_input(input).expect_err("seek mode should be required");
        assert!(err.to_string().contains("Expected 'line' or 'byte'"));
    }

    #[test]
    fn test_nested_if_period_does_not_end_while_body() {
        let input = r#"
            While true,
                if false then,
                    Print "X".
                Print "Y",
                Print "Z".
        "#;

        let result = parse_input(input).expect("nested if in while should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::While { body, .. } => {
                assert_eq!(body.len(), 3, "while body should include statements after inner if");
                match &body[0] {
                    Statement::If { then_block, .. } => {
                        assert_eq!(then_block.len(), 1, "inner if should only own its print statement");
                    }
                    other => panic!("Expected first while body statement to be If, got {:?}", other),
                }
            }
            other => panic!("Expected While, got {:?}", other),
        }
    }

    #[test]
    fn test_on_error_sentence_can_return_to_parent_if_block() {
        let input = r#"
            If arguments's empty then,
                Open a file for reading called source at "/dev/stdin",
                On error print "cat: /dev/stdin: No such file or directory", exit 1.
                Read line from source into content,
                While content is not empty,
                    Read line from source into content.
        "#;

        let result = parse_input(input).expect("if block should continue after on error sentence");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::If { then_block, .. } => {
                assert_eq!(then_block.len(), 4, "then block should include statements after on error");
                assert!(matches!(then_block[0], Statement::FileOpen { .. }));
                assert!(matches!(then_block[1], Statement::OnError { .. }));
                assert!(matches!(then_block[2], Statement::FileReadLine { .. }));
                assert!(matches!(then_block[3], Statement::While { .. }));
            }
            other => panic!("Expected If, got {:?}", other),
        }
    }

    #[test]
    fn test_function_call_expression_curly_grouping_parses() {
        let input = r#"
            To fib with a number called n.
                Return a number, {fibonacci of n subtract 1} add {fibonacci of n subtract 2}.
        "#;

        let result = parse_input(input).expect("function-call expression with curly grouping should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FunctionDef { body, .. } => {
                assert_eq!(body.len(), 1);
                match &body[0] {
                    Statement::Return { value: Some(Expr::BinaryOp { op, .. }), .. } => {
                        assert!(matches!(op, BinaryOperator::Add));
                    }
                    other => panic!("Expected Return(BinaryOp Add), got {:?}", other),
                }
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }
    }

    #[test]
    fn test_function_call_expression_comma_add_is_rejected() {
        let input = r#"
            To fib with a number called n.
                Return a number, fibonacci of n subtract 1, add fibonacci of n subtract 2.
        "#;

        let err = parse_input(input).expect_err("comma-delimited arithmetic should be rejected");
        assert!(
            err.to_string().contains("Expected a statement, got Add"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_curly_grouping_changes_arithmetic_shape() {
        let input = r#"
            To math with a number called n.
                Return a number, {n add 1} multiply {n subtract 1}.
        "#;

        let result = parse_input(input).expect("curly grouped arithmetic should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FunctionDef { body, .. } => {
                assert_eq!(body.len(), 1);
                match &body[0] {
                    Statement::Return {
                        value:
                            Some(Expr::BinaryOp {
                                op: BinaryOperator::Multiply,
                                left,
                                right,
                            }),
                        ..
                    } => {
                        assert!(matches!(&**left, Expr::BinaryOp { op: BinaryOperator::Add, .. }));
                        assert!(matches!(&**right, Expr::BinaryOp { op: BinaryOperator::Subtract, .. }));
                    }
                    other => panic!("Expected grouped multiply return, got {:?}", other),
                }
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }
    }

    #[test]
    fn test_function_call_in_comma_separated_if_block() {
        let input = r#"
            If arguments's empty then,
                Open a file for reading called source at 0,
                On error print "cat: /dev/stdin: Could not open pipe", exit 1.
                a buffer called staged_output is 'read the file' with source,
                Write staged_output to output,
                Clear staged_output,
                Exit 0.
        "#;

        let result = parse_input(input).expect("if block should continue after function call expression statement");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::If { then_block, .. } => {
                assert_eq!(then_block.len(), 6, "then block should include statements after function call expression var decl");
                assert!(matches!(then_block[0], Statement::FileOpen { .. }));
                assert!(matches!(then_block[1], Statement::OnError { .. }));
                assert!(matches!(then_block[2], Statement::VarDecl { .. }));
                assert!(matches!(then_block[3], Statement::FileWrite { .. }));
                assert!(matches!(then_block[4], Statement::BufferClear { .. }));
                assert!(matches!(then_block[5], Statement::Exit { .. }));
            }
            other => panic!("Expected If, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_zero_param_function_def_with_comma_signature() {
        let input = r#"
            To 'show version',
                Exit 0.
        "#;

        let result = parse_input(input).expect("zero-parameter function definition should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FunctionDef { name, params, body, .. } => {
                assert_eq!(name, "show version");
                assert!(params.is_empty(), "expected no parameters");
                assert_eq!(body.len(), 1, "expected single statement function body");
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_function_def_with_buffer_parameter_type() {
        let input = r#"
            To 'handle content' with a buffer called content,
                Clear content.
        "#;

        let result = parse_input(input).expect("function definition with buffer parameter should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FunctionDef { name, params, body, .. } => {
                assert_eq!(name, "handle content");
                assert_eq!(params.len(), 1);
                assert_eq!(params[0].0, "content");
                assert_eq!(params[0].1, Type::Buffer);
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Statement::BufferClear { .. }));
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_function_def_with_file_and_buffer_parameters() {
        let input = r#"
            To 'copy line' with a file called source and a buffer called destination,
                Read line from source into destination.
        "#;

        let result = parse_input(input).expect("function definition with file and buffer parameters should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FunctionDef { name, params, body, .. } => {
                assert_eq!(name, "copy line");
                assert_eq!(params.len(), 2);
                assert_eq!(params[0], ("source".to_string(), Type::File));
                assert_eq!(params[1], ("destination".to_string(), Type::Buffer));
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Statement::FileReadLine { .. }));
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_zero_param_function_call_statement() {
        let input = r#"
            To 'show version',
                Exit 0.

            'show version'.
        "#;

        let result = parse_input(input).expect("zero-parameter function definition and call should parse");
        assert_eq!(result.statements.len(), 2);

        match &result.statements[1] {
            Statement::FunctionCall { name, args } => {
                assert_eq!(name, "show version");
                assert!(args.is_empty(), "expected no call arguments");
            }
            other => panic!("Expected FunctionCall, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_function_def_with_file_parameter_type() {
        let input = r#"
            To 'handle file' with a file called source,
                Read line from source into content.
        "#;

        let result = parse_input(input).expect("function definition with file parameter should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FunctionDef { name, params, body, .. } => {
                assert_eq!(name, "handle file");
                assert_eq!(params.len(), 1);
                assert_eq!(params[0].0, "source");
                assert_eq!(params[0].1, Type::File);
                assert_eq!(body.len(), 1);
                assert!(matches!(body[0], Statement::FileReadLine { .. }));
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }
    }

    #[test]
    fn test_set_assignment_supports_quoted_variable_name() {
        let input = r#"
            A boolean called 'failed to open a file' is false.
            Set 'failed to open a file' to true.
        "#;

        let result = parse_input(input).expect("quoted variable assignment with set should parse");
        assert_eq!(result.statements.len(), 2);

        match &result.statements[1] {
            Statement::VarDecl { name, value, .. } => {
                assert_eq!(name, "failed to open a file");
                assert!(matches!(value, Some(Expr::BoolLit(true))));
            }
            other => panic!("Expected Set to parse as VarDecl assignment-style statement, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_flag_schema_boolean_required() {
        let input = r#"a flag called numbering is "-n" or "--number", it is a boolean and is required."#;
        let result = parse_input(input).expect("flag schema should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FlagSchemaDecl { name, short, long, value_type, required, default } => {
                assert_eq!(name, "numbering");
                assert_eq!(short, "-n");
                assert_eq!(long, "--number");
                assert!(matches!(value_type, FlagValueType::Boolean));
                assert!(*required);
                assert!(default.is_none());
            }
            other => panic!("Expected FlagSchemaDecl, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_flag_schema_text_with_default() {
        let input = r#"a flag called 'output' is "-o" or "--output", it is a text with default "out.txt"."#;
        let result = parse_input(input).expect("flag schema with default should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::FlagSchemaDecl { name, value_type, required, default, .. } => {
                assert_eq!(name, "output");
                assert!(matches!(value_type, FlagValueType::Text));
                assert!(!required);
                assert!(matches!(default, Some(Expr::StringLit(s)) if s == "out.txt"));
            }
            other => panic!("Expected FlagSchemaDecl, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_parse_flags_statement() {
        let input = r#"
            a flag called verbose is "-v" or "--verbose", it is a boolean.
            parse flags.
        "#;
        let result = parse_input(input).expect("parse flags statement should parse");
        assert_eq!(result.statements.len(), 2);
        assert!(matches!(result.statements[1], Statement::ParseFlags));
    }

    #[test]
    fn test_parse_arguments_raw_property() {
        let input = r#"Print arguments's raw."#;
        let result = parse_input(input).expect("arguments's raw should parse");
        assert_eq!(result.statements.len(), 1);

        match &result.statements[0] {
            Statement::Print { value, .. } => {
                assert!(matches!(value, Expr::ArgumentRaw));
            }
            other => panic!("Expected Print statement, got {:?}", other),
        }
    }
