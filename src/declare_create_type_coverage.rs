// Regression test for the declaration-form unification: every `Type`
// variant must be classified, by construction, as either wired into
// `Create a T called N.`'s shared type resolver (`try_parse_type_noun` in
// src/parser/mod.rs) or deliberately excluded from it (`file`/`time`,
// which require an initializer; `Void`/`Unknown`, which are not spellable
// in Vox source at all).
//
// This lives in-crate rather than under tests/ because the crate ships no
// `[lib]` target (see Cargo.toml — only a `[[bin]] name = "vox"`), so an
// integration test under tests/ cannot see `parser::ast::Type` and can
// only black-box the compiled binary (as tests/p296_full_type_vocabulary.rs
// does, and as tests/declare_create_type_vocabulary.rs added alongside this
// file does for end-to-end coverage). Only an in-crate `#[cfg(test)]`
// module - the same pattern src/compile_fail_tests.rs already uses - can
// hold a real exhaustive match against the enum itself.

#[cfg(test)]
mod tests {
    use crate::lexer::Lexer;
    use crate::parser::ast::{Statement, Type};
    use crate::parser::Parser;

    fn parse_one_statement(source: &str) -> Result<Statement, String> {
        let mut lexer = Lexer::new(source);
        let tokens = lexer.tokenize();
        let mut parser = Parser::new(tokens).with_source("probe", source);
        let program = parser.parse().map_err(|e| e.to_string())?;
        program
            .statements
            .into_iter()
            .next()
            .ok_or_else(|| "parser produced no statements".to_string())
    }

    /// `Create a <keyword> called probe.` must parse into a declaration
    /// whose `Statement` variant/type matches, with no explicit value -
    /// the whole point of this stage was to route these through one type
    /// resolver instead of a hand-picked subset.
    fn assert_default_create_wires_up(keyword: &str, expect: &Type) {
        let source = format!("Create a {} called probe.\n\nPrint \"ok\".\n", keyword);
        match parse_one_statement(&source) {
            Ok(Statement::VarDecl { var_type, value, .. }) => {
                assert_eq!(
                    var_type.as_ref(),
                    Some(expect),
                    "Create a {} called probe. parsed with var_type {:?}, expected {:?}",
                    keyword, var_type, expect
                );
                assert!(
                    value.is_none(),
                    "Create a {} called probe. should have no explicit value (default-initialized), got {:?}",
                    keyword, value
                );
            }
            // buffer and timer are their own Statement variants (BufferDecl /
            // TimerDecl), not VarDecl - still "resolved through the shared
            // resolver" since try_parse_type_noun is what recognized the
            // keyword before routing to the specific statement kind.
            Ok(Statement::BufferDecl { size, .. }) if *expect == Type::Buffer => {
                assert!(
                    matches!(size, crate::parser::ast::Expr::IntegerLit(0)),
                    "Create a buffer called probe. should be a zero-size dynamic buffer, got {:?}",
                    size
                );
            }
            Ok(Statement::TimerDecl { .. }) if *expect == Type::Timer => {}
            Ok(other) => panic!(
                "Create a {} called probe. parsed as an unexpected statement: {:?}",
                keyword, other
            ),
            Err(e) => panic!(
                "Create a {} called probe. should parse (this type is supposed to default-initialize), but got: {}",
                keyword, e
            ),
        }
    }

    /// `Create a <keyword> called probe.` must be REJECTED with a message
    /// naming the requirement - a zero value would be meaningless for
    /// these types.
    fn assert_default_create_requires_initializer(keyword: &str, message_fragment: &str) {
        let source = format!("Create a {} called probe.\n\nPrint \"ok\".\n", keyword);
        match parse_one_statement(&source) {
            Ok(stmt) => panic!(
                "Create a {} called probe. should be rejected (needs an initializer), but parsed: {:?}",
                keyword, stmt
            ),
            Err(e) => assert!(
                e.contains(message_fragment),
                "Create a {} called probe. error {:?} does not contain {:?}",
                keyword, e, message_fragment
            ),
        }
    }

    #[test]
    fn every_type_variant_is_wired_into_create_or_deliberately_excluded() {
        // The dispatch match below is exhaustive over `Type` - no `_`
        // wildcard arm. If `parser::ast::Type` gains a new variant, this
        // stops compiling until someone adds a case for it here, which
        // means `cargo test` fails at the build step rather than a
        // forgotten fixture quietly reporting green.
        fn dispatch(ty: Type) {
            match ty {
                Type::Integer => assert_default_create_wires_up("number", &Type::Integer),
                Type::Float => assert_default_create_wires_up("float", &Type::Float),
                Type::String => {
                    // KNOWN BUG, not covered here: `Create a text called
                    // probe.` PARSES fine (var_type = Some(Type::String),
                    // value = None) so it is included in the exhaustive
                    // dispatch below like every other default-initializing
                    // type. But the codegen default-init fallback for
                    // Type::String (src/codegen/mod.rs, the `_ => { xor
                    // rax, rax; ... }` arm reached because Type::String has
                    // no dedicated case, unlike the Buffer/List/Map/Float/
                    // Value arms right above it) stores a null pointer
                    // instead of a valid empty-string pointer. Printing (or
                    // otherwise reading) that default text variable
                    // segfaults at runtime. That is a codegen problem, not
                    // a parser/resolver problem, so it is out of scope for
                    // this parse-level exhaustiveness test - see the master
                    // report for the repro. Only the parse-level assertion
                    // runs here; deliberately not asserted against a
                    // runtime .vox/.expected fixture (tests/declare_create_
                    // text.vox does NOT exercise the bare-Create default -
                    // see its header comment).
                    assert_default_create_wires_up("text", &Type::String)
                }
                Type::Boolean => assert_default_create_wires_up("boolean", &Type::Boolean),
                Type::List(_) => assert_default_create_wires_up(
                    "list",
                    &Type::List(Box::new(Type::Unknown)),
                ),
                Type::Map(_) => assert_default_create_wires_up(
                    "map",
                    &Type::Map(Box::new(Type::Unknown)),
                ),
                Type::Buffer => assert_default_create_wires_up("buffer", &Type::Buffer),
                Type::Value => assert_default_create_wires_up("value", &Type::Value),
                Type::Timer => assert_default_create_wires_up("timer", &Type::Timer),
                Type::File => assert_default_create_requires_initializer(
                    "file",
                    "A file variable must be initialized with a path",
                ),
                Type::Time => assert_default_create_requires_initializer(
                    "time",
                    "A time variable must be initialized",
                ),
                // Not spellable in Vox source - there is no keyword that
                // lexes to these, so there is no `Create` syntax to probe.
                // Deliberately excluded, mirroring the same judgment call
                // tests/p296_full_type_vocabulary.rs already makes for
                // Return/parameter types.
                Type::Void | Type::Unknown => {}
            }
        }

        for ty in [
            Type::Integer,
            Type::Float,
            Type::String,
            Type::Boolean,
            Type::List(Box::new(Type::Unknown)),
            Type::Map(Box::new(Type::Unknown)),
            Type::Buffer,
            Type::Value,
            Type::Timer,
            Type::File,
            Type::Time,
            Type::Void,
            Type::Unknown,
        ] {
            dispatch(ty);
        }
    }
}
