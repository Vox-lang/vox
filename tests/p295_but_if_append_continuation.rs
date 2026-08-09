// Plan 295 finding 1 — a `but if` append branch that repeats the base
// statement's own `to <name>` (e.g. `Append "." to line, but if v is equal
// to 1 append "#" to line.`) left the `to line` text unconsumed. The parser
// then returned control with the token stream desynced: the top-level loop
// silently discards the boolean result of `expect(&Token::Period)`
// (src/parser/mod.rs `parse()`), so the stray `to` was picked up by
// `parse_statement` as the start of a NEW top-level construct - `Token::To`
// always dispatches to `parse_function_def`, which happily consumed
// `line. print "AFTER". print "SECOND AFTER".` as a bogus, never-called
// function body named `line`. Net effect: silent, total loss of the rest of
// the program, with a clean compile (0.3.3 regression - v0.3.2 rejected the
// same source with a parse error instead of discarding it).
//
// The fix (src/parser/mod.rs `parse_conditional_branch`, `ListAppend` arm)
// makes the branch grammar consume an optional trailing `to <name>`,
// requiring it to name the same list/buffer as the base statement - matching
// what a user naturally writes by mirroring the base statement's own
// grammar, and erroring cleanly (never silently discarding) if it names a
// different target.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-p295-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

fn compile(work: &std::path::Path, source: &str) -> Result<std::path::PathBuf, String> {
    fs::write(work.join("prog.vox"), source).expect("write prog.vox");
    let vox = env!("CARGO_BIN_EXE_vox");
    let bin = work.join("prog");
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("-o")
        .arg(&bin)
        .current_dir(work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");
    if output.status.success() {
        Ok(bin)
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn run(bin: &std::path::Path) -> String {
    let output = Command::new(bin)
        .stdin(Stdio::null())
        .output()
        .expect("run compiled binary");
    assert!(output.status.success(), "program should exit cleanly");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// The exact plan 295 finding 1 repro: the base append's `to line` is
// mirrored on the `but if` branch. Must fully consume the branch (not
// desync into a bogus function def) and produce every statement after it.
#[test]
fn finding1_repro_v_true_branch_runs_and_rest_of_program_survives() {
    let work = work_dir("f1-true");
    let bin = compile(
        &work,
        r##"a buffer called line is 64 bytes in size.
a number called v is 1.
print "BEFORE".
Append "." to line, but if v is equal to 1 append "#" to line.
print "AFTER".
print "SECOND AFTER".
print line.
"##,
    )
    .expect("compile should succeed");
    assert_eq!(run(&bin), "BEFORE\nAFTER\nSECOND AFTER\n#\n");
    let _ = fs::remove_dir_all(&work);
}

// The condition's other branch: same source shape, `v` set so the
// condition is false, so the base (not the `but if` branch) value should
// land in the buffer, and the rest of the program must still survive.
#[test]
fn finding1_repro_v_false_branch_runs_and_rest_of_program_survives() {
    let work = work_dir("f1-false");
    let bin = compile(
        &work,
        r##"a buffer called line is 64 bytes in size.
a number called v is 2.
print "BEFORE".
Append "." to line, but if v is equal to 1 append "#" to line.
print "AFTER".
print "SECOND AFTER".
print line.
"##,
    )
    .expect("compile should succeed");
    assert_eq!(run(&bin), "BEFORE\nAFTER\nSECOND AFTER\n.\n");
    let _ = fs::remove_dir_all(&work);
}

// Neighbouring shape: the plan 291 canonical form, which omits `to <name>`
// on the branch entirely, must keep working unchanged (this is what
// tests/220_conditional_append.vox already exercises end to end; asserted
// again here as the direct counterpart of the two tests above).
#[test]
fn but_if_append_branch_without_to_clause_still_works() {
    let work = work_dir("f1-no-to");
    let bin = compile(
        &work,
        r##"a buffer called line is 64 bytes in size.
a number called v is 1.
Append "." to line, but if v is equal to 1 append "#".
print line.
"##,
    )
    .expect("compile should succeed");
    assert_eq!(run(&bin), "#\n");
    let _ = fs::remove_dir_all(&work);
}

// Neighbouring shape: a multi-branch chain (3+ conditions, mirroring
// tests/222_conditional_append_multibranch.vox) where every branch repeats
// `to <name>` must fully consume every branch, not just the first.
#[test]
fn but_if_append_multibranch_with_to_clause_on_every_branch() {
    let work = work_dir("f1-multibranch");
    let bin = compile(
        &work,
        r##"a buffer called out is 64 bytes in size.
a number called n is 15.
Append "x" to out, but if n modulo 15 is equal to 0 append "fizzbuzz" to out, but if n modulo 3 is equal to 0 append "fizz" to out, but if n modulo 5 is equal to 0 append "buzz" to out.
print "AFTER".
print out.
"##,
    )
    .expect("compile should succeed");
    assert_eq!(run(&bin), "AFTER\nfizzbuzz\n");
    let _ = fs::remove_dir_all(&work);
}

// Neighbouring shape: `otherwise` with a `to <name>` clause on the final
// branch must also be fully consumed.
#[test]
fn but_if_append_otherwise_with_to_clause() {
    let work = work_dir("f1-otherwise");
    let bin = compile(
        &work,
        r##"a buffer called line is 64 bytes in size.
a number called v is 9.
Append "." to line, but if v is equal to 1 append "#" to line, otherwise append "@" to line.
print "AFTER".
print line.
"##,
    )
    .expect("compile should succeed");
    assert_eq!(run(&bin), "AFTER\n@\n");
    let _ = fs::remove_dir_all(&work);
}

// A `but if` append branch naming a *different* list/buffer than the base
// statement is not supported (plan 291's own non-goal). This must be a
// clean compile error - never a silent desync into misparsed code, which is
// the exact failure class finding 1 is about.
#[test]
fn but_if_append_branch_retargeting_different_list_is_a_clean_error() {
    let work = work_dir("f1-mismatch");
    let err = compile(
        &work,
        r##"a buffer called line is 64 bytes in size.
a buffer called other is 64 bytes in size.
a number called v is 1.
Append "." to line, but if v is equal to 1 append "#" to other.
print "AFTER".
"##,
    )
    .expect_err("retargeting to a different buffer must fail to compile");
    assert!(
        err.contains("cannot retarget") || err.contains("other"),
        "expected a clear retargeting error, got:\n{}",
        err
    );
    let _ = fs::remove_dir_all(&work);
}

// Neighbouring shape: plain `print`'s own `but if` sugar (unrelated base
// statement kind) must be unaffected by the `ListAppend` branch change.
#[test]
fn but_if_print_unaffected() {
    let work = work_dir("f1-print");
    let bin = compile(
        &work,
        r##"a number called v is 1.
print "plain", but if v is equal to 1 print "override".
"##,
    )
    .expect("compile should succeed");
    assert_eq!(run(&bin), "override\n");
    let _ = fs::remove_dir_all(&work);
}
