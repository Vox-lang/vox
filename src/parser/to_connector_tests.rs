    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    /// Regression 2: `to` as a call connector must not break `Set X to Y`.
    #[test]
    fn set_assignment_keeps_to_as_separator() {
        let input = r#"Set start to 1."#;
        let result = parse_input(input).expect("Set assignment should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::VarDecl { name, value, .. } => {
                assert_eq!(name, "start");
                assert!(matches!(value, Some(Expr::IntegerLit(1))));
            }
            other => panic!("Expected VarDecl, got {:?}", other),
        }
    }

    /// Regression 2: `For each number from A to B` range keeps `to` as a
    /// range-bound keyword, not a call connector.
    #[test]
    fn for_each_range_keeps_to_as_bound() {
        let input = r#"For each number from 1 to 3, print the number."#;
        let result = parse_input(input).expect("for-each range should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::ForRange {
                variable: _,
                range: Expr::Range { start, end, inclusive },
                body,
            } => {
                assert!(matches!(start.as_ref(), Expr::IntegerLit(1)));
                assert!(matches!(end.as_ref(), Expr::IntegerLit(3)));
                assert!(matches!(inclusive, true));
                assert_eq!(body.len(), 1);
            }
            other => panic!("Expected ForRange, got {:?}", other),
        }
    }

    /// Regression 2: `to` as a universal call connector in expression calls.
    #[test]
    fn function_call_with_to_connector_parses() {
        let input = r#"To greet with a text called name. Return a text, name."#;
        let result = parse_input(input).expect("function definition should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::FunctionDef { name, params, .. } => {
                assert_eq!(name, "greet");
                assert_eq!(params.len(), 1);
                assert_eq!(params[0].0, "name");
            }
            other => panic!("Expected FunctionDef, got {:?}", other),
        }

        // The call itself: a bare identifier callee followed by `to` and an argument.
        let call_input = r#"greet to "world"."#;
        let call_result = parse_input(call_input).expect("call with 'to' should parse");
        match &call_result.statements[0] {
            Statement::FunctionCall { name, args } => {
                assert_eq!(name, "greet");
                assert_eq!(args.len(), 1);
                assert!(matches!(
                    &args[0],
                    Expr::StringLit(s) if s == "world"
                ));
            }
            other => panic!("Expected FunctionCall, got {:?}", other),
        }
    }

    /// Regression 2: `Set X to (calc to 3)` — `to` must serve both the
    /// assignment separator and the nested call connector in one sentence.
    #[test]
    fn set_value_to_nested_call_with_to_connector() {
        let input = r#"Set x to calc to 3."#;
        let result = parse_input(input).expect("Set with nested 'to' call should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::VarDecl { name, value, .. } => {
                assert_eq!(name, "x");
                assert!(matches!(
                    value,
                    Some(Expr::FunctionCall { name: callee, args })
                    if callee == "calc" && args.len() == 1 && matches!(&args[0], Expr::IntegerLit(3)
                )));
            }
            other => panic!("Expected VarDecl with nested FunctionCall value, got {:?}", other),
        }
    }

    /// Regression 2 round 2: `Set start to 1.` alone is not sufficient
    /// coverage - the bug only appears once `start`/`end` are also used as
    /// range bounds later in the same file. `parse_primary()`'s generic
    /// call-tail lookahead ate the `to end` in `from start to end` as a
    /// call `start(end)`, leaving no `to` for the range check, so the whole
    /// range collapsed into a bogus `ForEach` calling `start` as a function.
    #[test]
    fn identifier_range_bounds_do_not_become_calls() {
        let input = "Set start to 1.\nSet end to 3.\nFor each number from start to end, print the number.\n";
        let result = parse_input(input).expect("identifier range bounds should parse");
        assert_eq!(result.statements.len(), 3);
        match &result.statements[2] {
            Statement::ForRange {
                range: Expr::Range { start, end, .. },
                ..
            } => {
                assert!(matches!(start.as_ref(), Expr::Identifier(s) if s == "start"));
                assert!(matches!(end.as_ref(), Expr::Identifier(s) if s == "end"));
            }
            other => panic!("Expected ForRange with identifier bounds, got {:?}", other),
        }
    }

    /// Same root cause, `append each ... from <source> to <dest>` shape:
    /// the collection-source identifier must not eat the append's own `to`.
    #[test]
    fn append_each_from_identifier_source_keeps_to_separator() {
        let input = "append each x from source to dest.";
        let result = parse_input(input).expect("append each from identifier source should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::ForEach { collection, .. } => {
                assert!(matches!(collection, Expr::Identifier(s) if s == "source"));
            }
            other => panic!("Expected ForEach wrapping the append, got {:?}", other),
        }
    }

    /// Same root cause, `element N of <list>` shape (statement and
    /// expression forms) with an identifier index: the index must not eat
    /// the statement's own `of`.
    #[test]
    fn element_index_identifier_keeps_of_separator() {
        let input = "a number called item is element j of items.";
        let result = parse_input(input).expect("element N of with identifier index should parse");
        assert_eq!(result.statements.len(), 1);
        match &result.statements[0] {
            Statement::VarDecl {
                value: Some(Expr::ElementAccess { list, index }),
                ..
            } => {
                assert!(matches!(index.as_ref(), Expr::Identifier(s) if s == "j"));
                assert!(matches!(list.as_ref(), Expr::Identifier(s) if s == "items"));
            }
            other => panic!("Expected VarDecl with ElementAccess value, got {:?}", other),
        }
    }

    /// Same shape for `Set element N of list to value` and
    /// `Set byte N of buffer to value`, which parse the index the same way.
    #[test]
    fn set_element_and_byte_identifier_index_keeps_of_separator() {
        let result = parse_input("Set element j of items to 5.")
            .expect("Set element N of with identifier index should parse");
        match &result.statements[0] {
            Statement::ElementSet { list, index, .. } => {
                assert!(matches!(index, Expr::Identifier(s) if s == "j"));
                assert_eq!(list, "items");
            }
            other => panic!("Expected ElementSet, got {:?}", other),
        }

        let result = parse_input("Set byte i of buf to 5.")
            .expect("Set byte N of with identifier index should parse");
        match &result.statements[0] {
            Statement::ByteSet { buffer, index, .. } => {
                assert!(matches!(index, Expr::Identifier(s) if s == "i"));
                assert_eq!(buffer, "buf");
            }
            other => panic!("Expected ByteSet, got {:?}", other),
        }
    }

    /// The combined regression test: every construct that legitimately uses
    /// `to`/`of`/`with` as a call connector must still work *alongside* a
    /// `Set`, a range, an `append`, and an `element N of` in the same
    /// program - this is the shape that would have caught the incomplete
    /// first fix, which only tested each construct in isolation.
    #[test]
    fn connectors_and_reserved_words_coexist_in_one_program() {
        let input = r#"
To greet with a text called name. Return a text, name.
Set start to 1.
Set end to 3.
For each number from start to end, print the number.
append each x from source to dest.
a number called item is element j of items.
Set element k of items to 9.
Set byte b of buf to 9.
greet to "world".
"#;
        let result = parse_input(input).expect("connectors and reserved words should coexist");
        assert_eq!(result.statements.len(), 9);

        assert!(matches!(result.statements[0], Statement::FunctionDef { .. }));
        assert!(matches!(result.statements[1], Statement::VarDecl { .. }));
        assert!(matches!(result.statements[2], Statement::VarDecl { .. }));
        assert!(matches!(
            &result.statements[3],
            Statement::ForRange { range: Expr::Range { start, end, .. }, .. }
            if matches!(start.as_ref(), Expr::Identifier(s) if s == "start")
                && matches!(end.as_ref(), Expr::Identifier(s) if s == "end")
        ));
        assert!(matches!(
            &result.statements[4],
            Statement::ForEach { collection, .. }
            if matches!(collection, Expr::Identifier(s) if s == "source")
        ));
        assert!(matches!(
            &result.statements[5],
            Statement::VarDecl { value: Some(Expr::ElementAccess { .. }), .. }
        ));
        assert!(matches!(result.statements[6], Statement::ElementSet { .. }));
        assert!(matches!(result.statements[7], Statement::ByteSet { .. }));
        assert!(matches!(
            &result.statements[8],
            Statement::FunctionCall { name, args }
            if name == "greet" && args.len() == 1
        ));
    }

    /// Plan 281: a braced group is fully self-delimiting, so a function
    /// call inside it must use its own `of` connector even though `byte`'s
    /// index position reserves `of` for itself via `parse_primary_reserving`
    /// - before the fix, the outer reservation leaked into the group and
    /// `ci of 1 and 2` failed with "Expected a statement, got And".
    #[test]
    fn braced_multi_arg_call_as_byte_index_uses_own_of_connector() {
        let input = "a number called v is byte {ci of 1 and 2} of buf.";
        let result = parse_input(input).expect("braced call as byte index should parse");
        match &result.statements[0] {
            Statement::VarDecl { value: Some(Expr::ByteAccess { buffer, index }), .. } => {
                assert!(matches!(buffer.as_ref(), Expr::Identifier(s) if s == "buf"));
                assert!(matches!(
                    index.as_ref(),
                    Expr::FunctionCall { name, args }
                    if name == "ci" && args.len() == 2
                ));
            }
            other => panic!("Expected VarDecl with ByteAccess value, got {:?}", other),
        }
    }

    /// Same bug, single-argument call whose `of` sits right against the
    /// closing brace - before the fix this failed differently ("Expected a
    /// statement, got CloseBrace") because the suppressed `of` couldn't even
    /// start a call tail, leaving the brace unconsumed.
    #[test]
    fn braced_single_arg_call_as_byte_index_uses_own_of_connector() {
        let input = "a number called v is byte {id of 3} of buf.";
        let result = parse_input(input).expect("braced single-arg call as byte index should parse");
        match &result.statements[0] {
            Statement::VarDecl { value: Some(Expr::ByteAccess { index, .. }), .. } => {
                assert!(matches!(
                    index.as_ref(),
                    Expr::FunctionCall { name, args }
                    if name == "id" && args.len() == 1
                ));
            }
            other => panic!("Expected VarDecl with ByteAccess value, got {:?}", other),
        }
    }

    /// Same bug, `element N of list` shape instead of `byte N of buffer`.
    #[test]
    fn braced_call_as_element_index_uses_own_of_connector() {
        let input = "a number called v is element {idfn of 2} of lst.";
        let result = parse_input(input).expect("braced call as element index should parse");
        match &result.statements[0] {
            Statement::VarDecl { value: Some(Expr::ElementAccess { list, index }), .. } => {
                assert!(matches!(list.as_ref(), Expr::Identifier(s) if s == "lst"));
                assert!(matches!(
                    index.as_ref(),
                    Expr::FunctionCall { name, args }
                    if name == "idfn" && args.len() == 1
                ));
            }
            other => panic!("Expected VarDecl with ElementAccess value, got {:?}", other),
        }
    }

    /// Same fix, `to` side rather than `of`: a range's start bound reserves
    /// `to` for the range itself, so a braced call there must still be free
    /// to use its own `to`.
    #[test]
    fn braced_call_uses_own_to_connector_in_range_start_bound() {
        let input = "For each number from {calc to 3} to 10, print the number.";
        let result = parse_input(input).expect("braced call in range start bound should parse");
        match &result.statements[0] {
            Statement::ForRange { range: Expr::Range { start, end, .. }, .. } => {
                assert!(matches!(
                    start.as_ref(),
                    Expr::FunctionCall { name, args }
                    if name == "calc" && args.len() == 1
                ));
                assert!(matches!(end.as_ref(), Expr::IntegerLit(10)));
            }
            other => panic!("Expected ForRange, got {:?}", other),
        }
    }

    /// Plan 281 item 4: the `Token::OpenBrace` handler reaches
    /// `parse_expression()` on both the grouping path and the map-literal
    /// key/value path before it can tell which one it's in, so a map value
    /// nested inside a suppressed context shares the exact same exposure -
    /// even though no live program has hit it yet.
    #[test]
    fn map_literal_value_inside_suppressed_of_context_uses_own_of_connector() {
        let input = "a number called v is byte {\"k\": ci of 1 and 2} of buf.";
        let result = parse_input(input).expect("map literal as byte index should parse");
        match &result.statements[0] {
            Statement::VarDecl { value: Some(Expr::ByteAccess { index, .. }), .. } => {
                match index.as_ref() {
                    Expr::MapLit { pairs } => {
                        assert_eq!(pairs.len(), 1);
                        assert!(matches!(&pairs[0].0, Expr::StringLit(s) if s == "k"));
                        assert!(matches!(
                            &pairs[0].1,
                            Expr::FunctionCall { name, args }
                            if name == "ci" && args.len() == 2
                        ));
                    }
                    other => panic!("Expected MapLit index, got {:?}", other),
                }
            }
            other => panic!("Expected VarDecl with ByteAccess value, got {:?}", other),
        }
    }

    /// Combined regression: every bare (non-braced) construct that the
    /// original plan 270 fix protects must keep working exactly as before,
    /// *alongside* a braced sub-expression that now legitimately uses its
    /// own connector - proving the plan 281 fix doesn't loosen suppression
    /// for anything outside an explicit `{...}` group.
    #[test]
    fn braced_group_coexists_with_reserved_connectors_in_one_program() {
        let input = r#"
Set start to 1.
Set end to 3.
For each number from start to end, print the number.
append each x from source to dest.
a number called item is element j of items.
Set element k of items to 9.
Set byte b of buf to 9.
a number called computed is byte {ci of 1 and 2} of buf.
"#;
        let result = parse_input(input).expect("braced group should coexist with reserved words");
        assert_eq!(result.statements.len(), 8);

        assert!(matches!(
            &result.statements[2],
            Statement::ForRange { range: Expr::Range { start, end, .. }, .. }
            if matches!(start.as_ref(), Expr::Identifier(s) if s == "start")
                && matches!(end.as_ref(), Expr::Identifier(s) if s == "end")
        ));
        assert!(matches!(
            &result.statements[3],
            Statement::ForEach { collection, .. }
            if matches!(collection, Expr::Identifier(s) if s == "source")
        ));
        assert!(matches!(
            &result.statements[4],
            Statement::VarDecl { value: Some(Expr::ElementAccess { index, .. }), .. }
            if matches!(index.as_ref(), Expr::Identifier(s) if s == "j")
        ));
        assert!(matches!(result.statements[5], Statement::ElementSet { .. }));
        assert!(matches!(result.statements[6], Statement::ByteSet { .. }));
        assert!(matches!(
            &result.statements[7],
            Statement::VarDecl { value: Some(Expr::ByteAccess { index, .. }), .. }
            if matches!(
                index.as_ref(),
                Expr::FunctionCall { name, args }
                if name == "ci" && args.len() == 2
            )
        ));
    }
