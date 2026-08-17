    //! Unit coverage for the thing registry and the shapes a declaration and
    //! a field chain parse into (plan 310 §1, §3).
    //!
    //! An integration test can only observe a program's output, so the AST
    //! later tasks depend on - field order, field types, defaults, the
    //! manifest split, `Program.things`, and how a possessive chain and each
    //! write spelling land - is pinned here instead.

    use super::*;
    use crate::lexer::Lexer;

    fn parse_input(input: &str) -> Result<Program, Box<CompileError>> {
        let mut lexer = Lexer::new(input);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    fn parse_err(input: &str) -> String {
        parse_input(input)
            .err()
            .unwrap_or_else(|| panic!("expected {:?} to be rejected", input))
            .to_string()
    }

    fn only_thing(program: &Program) -> &ThingDef {
        assert_eq!(
            program.things.len(),
            1,
            "expected exactly one thing, got {:?}",
            program.things
        );
        &program.things[0]
    }

    /// Data fields land in definition order (which is layout order), with
    /// their declared type and their literal default.
    #[test]
    fn fields_keep_definition_order_types_and_defaults() {
        let program = parse_input(
            "A thing called point has\n  a number called x is 0,\n  a float called y.\n",
        )
        .expect("a definition should parse");

        let def = only_thing(&program);
        assert_eq!(def.name, "point");
        assert_eq!(def.line, 1);
        assert!(def.members.is_empty());

        let names: Vec<&str> = def.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["x", "y"]);
        assert_eq!(def.fields[0].field_type, Type::Integer);
        assert!(matches!(def.fields[0].default, Some(Expr::IntegerLit(0))));
        assert_eq!(def.fields[1].field_type, Type::Float);
        // No `is` clause: the field takes its type's zero value, which is
        // the layout's business, not a default expression.
        assert!(def.fields[1].default.is_none());
    }

    /// A manifest entry declares callable API, not storage: it must never
    /// reach `fields`, or every offset after it would be wrong.
    #[test]
    fn function_members_are_declared_without_taking_storage() {
        let program = parse_input(
            "A thing called point has\n  \
             a function called 'from polar',\n  \
             a number called x is 0.\n",
        )
        .expect("a manifest entry should parse");

        let def = only_thing(&program);
        assert_eq!(def.members, vec!["from polar".to_string()]);
        assert_eq!(def.fields.len(), 1);
        assert_eq!(def.fields[0].name, "x");
    }

    /// A field may name a thing defined earlier, to any depth (plan 310 §6).
    #[test]
    fn a_field_may_name_an_earlier_thing() {
        let program = parse_input(
            "A thing called point has\n  a number called x is 0.\n\n\
             A thing called segment has\n  a point called start,\n  a point called end.\n",
        )
        .expect("a nested thing field should parse");

        assert_eq!(program.things.len(), 2);
        let segment = &program.things[1];
        assert_eq!(segment.name, "segment");
        assert_eq!(
            segment.fields[0].field_type,
            Type::Thing("point".to_string())
        );
        assert_eq!(
            segment.fields[1].field_type,
            Type::Thing("point".to_string())
        );
    }

    /// Definitions precede use, so a field naming a *later* thing is an
    /// unknown type rather than a forward reference the single pass would
    /// have to resolve.
    #[test]
    fn a_field_may_not_name_a_later_thing() {
        let err = parse_err(
            "A thing called segment has\n  a point called start.\n\n\
             A thing called point has\n  a number called x is 0.\n",
        );
        assert!(
            err.contains("Unknown field type 'point'"),
            "unexpected error: {}",
            err
        );
    }

    /// Both the thing's name and a field's name go through `parse_name`, so
    /// both accept a quoted multi-word identifier.
    #[test]
    fn names_may_be_quoted_and_multi_word() {
        let program = parse_input(
            "A thing called 'bounding box' has\n  a number called 'top left x' is 1.\n",
        )
        .expect("quoted multi-word names should parse");

        let def = only_thing(&program);
        assert_eq!(def.name, "bounding box");
        assert_eq!(def.fields[0].name, "top left x");
    }

    /// A definition declares a type and nothing else - it must not also
    /// introduce a variable, or the one identifier space would already be
    /// occupied by its own definition.
    #[test]
    fn a_definition_emits_only_a_thing_decl() {
        let program = parse_input("A thing called point has\n  a number called x is 0.\n")
            .expect("a definition should parse");
        assert_eq!(program.statements.len(), 1);
        assert!(matches!(program.statements[0], Statement::ThingDecl(_)));
    }

    /// `thing` is contextual, not reserved: outside `a thing called X has`
    /// it is an ordinary identifier, in every position a name can appear.
    #[test]
    fn thing_stays_an_ordinary_identifier() {
        let program = parse_input("a number called thing is 42.\nPrint thing.\nthing is 7.\n")
            .expect("`thing` should still be usable as a variable name");
        assert!(program.things.is_empty());
        assert!(matches!(
            &program.statements[0],
            Statement::VarDecl { name, .. } if name == "thing"
        ));
        assert!(matches!(
            &program.statements[2],
            Statement::Assignment { name, .. } if name == "thing"
        ));
    }

    /// The lookahead keys on `called`, not on the whole `... has` shape, so
    /// the reserved near-misses reach their own diagnostics.
    #[test]
    fn reserved_wrong_shapes_get_targeted_diagnostics() {
        assert!(parse_err("Create a thing called point.\n")
            .contains("A thing is defined, not created as a variable"));
        assert!(parse_err("A thing called point is 5.\n")
            .contains("'is' declares a variable; a thing definition uses 'has'"));
        assert!(parse_err("A thing called point has.\n").contains("at least one field"));
        assert!(parse_err("A thing called point.\n").contains("at least one field"));
    }

    // ---------------------------------------------------------------------
    // Declaration position and field access (plan 310 §3, §6, §10)
    // ---------------------------------------------------------------------

    const POINT: &str = "A thing called point has\n  a number called x is 0,\n  a number called y is 0.\n\n";
    const ROUTE: &str = "A thing called segment has\n  a point called start,\n  a point called end.\n\n\
                         A thing called route has\n  a segment called leg,\n  a number called id.\n\n";

    /// A thing name is a type noun in declaration position, and the
    /// declaration carries no value: every field takes its own default.
    #[test]
    fn a_declaration_names_the_thing_as_its_type() {
        let program = parse_input(&format!("{}a point called origin.\n", POINT))
            .expect("a thing declaration should parse");
        assert!(matches!(
            &program.statements[1],
            Statement::VarDecl { name, var_type: Some(Type::Thing(thing)), value: None }
                if name == "origin" && thing == "point"
        ));
    }

    /// One identifier space, first-come-first-serve (plan 310 §10): the
    /// definition claimed the name, so a variable cannot reuse it.
    #[test]
    fn a_declaration_may_not_reuse_the_things_own_name() {
        let err = parse_err(&format!("{}a point called point.\n", POINT));
        assert!(
            err.contains("'point' is already defined as a thing"),
            "unexpected error: {}",
            err
        );
    }

    /// A declaration's initialiser is carried on the VarDecl, so the copy
    /// (plan 310 §5) has a source to read - dropping it would silently
    /// declare the defaults instead.
    #[test]
    fn a_declaration_carries_its_initialiser() {
        let program = parse_input(&format!(
            "{}a point called origin.\na point called mirror is origin.\n",
            POINT
        ))
        .expect("a declaration with an initialiser should parse");
        match program.statements.last() {
            Some(Statement::VarDecl {
                name,
                var_type: Some(Type::Thing(thing)),
                value: Some(Expr::Identifier(source)),
            }) => {
                assert_eq!(name, "mirror");
                assert_eq!(thing, "point");
                assert_eq!(source, "origin");
            }
            other => panic!("expected a point declaration copying origin, got {:?}", other),
        }
    }

    /// `The <name> is <call>.` declares its target from what the call
    /// returns (plan 310 §2), so the parse already knows the name holds a
    /// point - which is what lets `after's x` read as a field chain.
    #[test]
    fn a_call_returning_a_thing_declares_the_name_it_is_assigned_to() {
        let program = parse_input(&format!(
            "{}To nudged with a point called start.\n  Return a point, start.\n\n\
             a point called before.\nThe after is nudged of before.\nPrint after's x.\n",
            POINT
        ))
        .expect("declaration by inference should parse");
        let declared = program.statements.iter().find_map(|stmt| match stmt {
            Statement::VarDecl {
                name,
                var_type: Some(Type::Thing(thing)),
                value: Some(Expr::FunctionCall { name: callee, .. }),
            } if name == "after" => Some((thing.clone(), callee.clone())),
            _ => None,
        });
        assert_eq!(
            declared,
            Some(("point".to_string(), "nudged".to_string())),
            "`The after is nudged of before.` should declare a point"
        );
        assert!(
            program.statements.iter().any(|stmt| matches!(
                stmt,
                Statement::Print {
                    value: Expr::ThingField { base, .. },
                    ..
                } if base == "after"
            )),
            "after's x should read as a field chain"
        );
    }

    /// A thing parameter is a thing inside the body, so its fields read
    /// through a possessive exactly like a local declaration's.
    #[test]
    fn a_thing_parameter_takes_the_things_type() {
        let program = parse_input(&format!(
            "{}To nudged with a point called start.\n  Return a point, start.\n\n",
            POINT
        ))
        .expect("a thing parameter should parse");
        let definition = program
            .statements
            .iter()
            .find(|stmt| matches!(stmt, Statement::FunctionDef { .. }));
        match definition {
            Some(Statement::FunctionDef {
                params,
                return_type,
                ..
            }) => {
                assert_eq!(
                    params.as_slice(),
                    &[("start".to_string(), Type::Thing("point".to_string()))]
                );
                assert_eq!(return_type, &Type::Thing("point".to_string()));
            }
            other => panic!("expected a function definition, got {:?}", other),
        }
    }

    /// A possessive on a thing variable reads a field, at any depth, and the
    /// path is the field names in order.
    #[test]
    fn a_possessive_chain_reads_fields_in_order() {
        let program = parse_input(&format!(
            "{}{}a route called commute.\nPrint commute's leg's start's x.\n",
            POINT, ROUTE
        ))
        .expect("a chained possessive should parse");
        let last = program.statements.last().expect("a Print statement");
        match last {
            Statement::Print { value: Expr::ThingField { base, path }, .. } => {
                assert_eq!(base, "commute");
                assert_eq!(path, &["leg", "start", "x"]);
            }
            other => panic!("expected a Print of a ThingField, got {:?}", other),
        }
    }

    /// Every write spelling lands on one statement, because the target is an
    /// offset rather than a name: `Set ... to`, the bare `is`, and the
    /// increment/decrement steps.
    #[test]
    fn every_write_spelling_becomes_one_field_write() {
        let program = parse_input(&format!(
            "{}a point called origin.\n\
             Set origin's x to 3.\n\
             origin's y is 4.\n\
             increment origin's x.\n\
             decrement origin's y.\n",
            POINT
        ))
        .expect("every write spelling should parse");

        assert!(matches!(
            &program.statements[2],
            Statement::SetThingField { base, path, value: Expr::IntegerLit(3) }
                if base == "origin" && path == &["x"]
        ));
        assert!(matches!(
            &program.statements[3],
            Statement::SetThingField { base, path, value: Expr::IntegerLit(4) }
                if base == "origin" && path == &["y"]
        ));
        // A step reads the field, adds one, and writes it back.
        match &program.statements[4] {
            Statement::SetThingField { base, path, value: Expr::BinaryOp { left, op, right } } => {
                assert_eq!(base, "origin");
                assert_eq!(path, &["x"]);
                assert!(matches!(op, BinaryOperator::Add));
                assert!(matches!(left.as_ref(), Expr::ThingField { path, .. } if path == &["x"]));
                assert!(matches!(right.as_ref(), Expr::IntegerLit(1)));
            }
            other => panic!("expected increment to become a field write, got {:?}", other),
        }
        assert!(matches!(
            &program.statements[5],
            Statement::SetThingField { value: Expr::BinaryOp { op: BinaryOperator::Subtract, .. }, .. }
        ));
    }

    /// The step literal follows the field's own type, so a float field stays
    /// a float instead of taking an integer 1 through the float path.
    #[test]
    fn a_step_on_a_float_field_steps_by_a_float() {
        let program = parse_input(
            "A thing called 'water tank' has\n  a float called 'depth in metres' is 1.5.\n\n\
             a 'water tank' called cistern.\n\
             increment cistern's 'depth in metres'.\n",
        )
        .expect("a step on a float field should parse");
        assert!(matches!(
            &program.statements[2],
            Statement::SetThingField { value: Expr::BinaryOp { right, .. }, .. }
                if matches!(right.as_ref(), Expr::FloatLit(_))
        ));
    }

    /// §3 lists interpolation among the places a field must work. A `{...}`
    /// placeholder is parsed by its own sub-parser, so this is the test that
    /// the sub-parser knows the program's things.
    #[test]
    fn a_field_interpolates_into_a_format_string() {
        let program = parse_input(&format!(
            "{}a point called origin.\nPrint \"origin sits at {{origin's x}}\".\n",
            POINT
        ))
        .expect("a field in a format string should parse");
        let last = program.statements.last().expect("a Print statement");
        match last {
            Statement::Print { value: Expr::FormatString { parts }, .. } => {
                assert!(
                    parts.iter().any(|part| matches!(
                        part,
                        FormatPart::Expression { expr, .. }
                            if matches!(expr.as_ref(), Expr::ThingField { path, .. } if path == &["x"])
                    )),
                    "expected an interpolated ThingField, got {:?}",
                    parts
                );
            }
            other => panic!("expected a Print of a FormatString, got {:?}", other),
        }
    }

    /// A chain may end on a nested thing: that names the whole thing, which
    /// is a copy source (plan 310 §5). Whether the position it sits in
    /// accepts one is the analyzer's call, so the parse keeps the chain -
    /// see `tests/compile_fail/thing_chain_ends_on_a_nested_thing.vox` for
    /// the rejection a print of one still gets (§7).
    #[test]
    fn a_chain_may_end_on_a_nested_thing() {
        let program = parse_input(&format!(
            "{}{}a route called commute.\na segment called span is commute's leg.\n",
            POINT, ROUTE
        ))
        .expect("a chain ending on a nested thing should parse");
        match program.statements.last() {
            Some(Statement::VarDecl {
                var_type: Some(Type::Thing(thing)),
                value: Some(Expr::ThingField { base, path }),
                ..
            }) => {
                assert_eq!(thing, "segment");
                assert_eq!(base, "commute");
                assert_eq!(path.as_slice(), &["leg".to_string()]);
            }
            other => panic!("expected a segment copied out of commute, got {:?}", other),
        }
    }

    /// An unknown field names the thing and lists what it does have.
    #[test]
    fn an_unknown_field_lists_the_things_fields() {
        let err = parse_err(&format!("{}a point called origin.\nPrint origin's z.\n", POINT));
        assert!(
            err.contains("Thing 'point' has no field 'z'") && err.contains("x, y"),
            "unexpected error: {}",
            err
        );
    }

    /// A thing name is only a type noun before `called`, so it stays an
    /// ordinary identifier everywhere else - the same guard `value` has.
    #[test]
    fn a_thing_name_is_only_a_type_noun_before_called() {
        let program = parse_input(&format!("{}a number called point is 42.\nPrint point.\n", POINT))
            .expect("a thing's name should still be usable as a variable name");
        assert!(matches!(
            &program.statements[1],
            Statement::VarDecl { name, var_type: Some(Type::Integer), .. } if name == "point"
        ));
    }
