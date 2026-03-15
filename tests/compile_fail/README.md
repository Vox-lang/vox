# compile_fail corpus

Each `*.vox` file in this directory is expected to fail compilation.

- Matching `*.err` files must contain a stable substring expected in the compiler/analyzer error output.
- The Rust test harness in `src/compile_fail_tests.rs` enforces this during `cargo test`.

This suite is for safety regression testing: malformed or unsafe programs must be rejected without panics or segfaults.
