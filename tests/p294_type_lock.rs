// Plan 294 — a variable's type is fixed at its declaration and never
// changes; a type-differing write is a compile error with an explicit-cast
// suggestion, instead of the compiler's tracked type silently drifting from
// the variable's actual runtime type (which is what the whole "wrong number
// printed" / "segfault" bug family came from - see
// docs/plans/294_retype_audit.md for the full audit and finding list).
//
// The negative cases (a type-differing write IS a compile error) are
// covered by tests/compile_fail/073-080_*. This file covers the positive
// cases: constructs that must keep compiling and behaving exactly as
// before, so a narrowing of the rule's scope shows up as a test failure
// here rather than only as a silent behavior change.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-p294-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

fn compile(work: &std::path::Path, source: &str) -> std::path::PathBuf {
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
    assert!(
        output.status.success(),
        "compile failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    bin
}

fn run_and_expect(bin: &std::path::Path, expected_stdout: &str) {
    let output = Command::new(bin)
        .stdin(Stdio::null())
        .output()
        .expect("run compiled binary");
    assert!(
        output.status.success(),
        "program should exit cleanly, got status {:?}; stderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        expected_stdout,
        "stdout mismatch"
    );
}

/// The plan 293 headline segfault (finding 6) is now a compile error, not
/// a runtime crash. See tests/compile_fail/073_* for the message itself;
/// this asserts the OLD behavior (compiling and segfaulting) is gone.
#[test]
fn plan_293_headline_segfault_is_now_a_compile_error() {
    let work = work_dir("p293-headline");
    let vox = env!("CARGO_BIN_EXE_vox");
    fs::write(
        work.join("prog.vox"),
        r#"a number called n is 5.
a number called g is 0.
If g is equal to 1,
  n is "abc".
Print "{n}".
"#,
    )
    .unwrap();
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("-o")
        .arg(work.join("prog"))
        .current_dir(&work)
        .output()
        .expect("spawn vox");
    assert!(
        !output.status.success(),
        "expected a compile error, but it compiled successfully"
    );
    assert!(
        !work.join("prog").exists(),
        "no binary should have been produced"
    );
}

/// All three retype spellings agree once an explicit cast is used - the
/// sanctioned escape hatch the whole rule depends on, both directions.
#[test]
fn explicit_cast_works_both_directions_all_three_spellings() {
    let work = work_dir("explicit-cast");

    let bin = compile(&work, "a number called n is 5.\nn is \"abc\" as a number.\nPrint \"{n}\".\n");
    run_and_expect(&bin, "0\n");

    let bin = compile(&work, "a number called n is 5.\nthe n is \"42\" as a number.\nPrint \"{n}\".\n");
    run_and_expect(&bin, "42\n");

    let bin = compile(&work, "a text called s is \"hello\".\nSet s to 42 as text.\nPrint \"{s}\".\n");
    run_and_expect(&bin, "42\n");
}

/// A fresh `Set x to <value>` naming a brand-new variable is a genuine
/// declaration, not a locked rebind - it must keep working exactly as
/// before this track (only an already-declared name's type is locked).
///
/// Uses an integer literal deliberately, not a text one: a fresh `Set n to
/// "abc".` (n never declared before) is a SEPARATE, pre-existing codegen
/// bug independent of this track - codegen's `VarDecl` arm only tracks
/// `variable_types` for a `var_type: None` declaration when the value is
/// one of a few specific expression shapes (list literal, float literal,
/// an inherited-from-variable source, ...); a bare string literal matches
/// none of them, so the fresh slot's type is never recorded and `Print`
/// reads it as an untyped raw integer instead of following it as a string
/// pointer. Confirmed present on unmodified `main` (`git diff 409bd2c --
/// src/codegen/mod.rs` is empty - this file is untouched by plan 294) and
/// out of scope for this track, which is about REJECTING a conflicting
/// REBIND, not about a first declaration's value never being tracked at
/// all. Reported separately rather than fixed here.
#[test]
fn set_still_declares_a_new_variable() {
    let work = work_dir("fresh-decl");
    let bin = compile(&work, "Set n to 42.\nPrint \"{n}\".\n");
    run_and_expect(&bin, "42\n");
}

/// Buffers are exempt from the lock: writing into one is a content/format
/// operation (copy the value's text into the buffer), not a retype, for
/// every spelling that writes to one.
#[test]
fn buffer_targets_are_exempt_from_the_lock() {
    let work = work_dir("buffer-exempt");

    let bin = compile(
        &work,
        "a buffer called b is 64 bytes in size.\nb is 7.\nb is 123.\nPrint b.\n",
    );
    run_and_expect(&bin, "123\n");

    let bin = compile(
        &work,
        "a buffer called out is \"\".\nset out to \"N={1 add 1}\".\nprint out.\n",
    );
    run_and_expect(&bin, "N=2\n");
}

/// `value`-typed variables keep accepting any type across reassignment -
/// that mechanism is the sanctioned dynamic escape hatch and is
/// unaffected by the lock (plan 294 decision 4).
#[test]
fn value_typed_variable_keeps_accepting_varying_types() {
    let work = work_dir("value-dynamic");
    let bin = compile(
        &work,
        r#"a value called v is 5.
Print "{v}".
v is "abc".
Print "{v}".
"#,
    );
    run_and_expect(&bin, "5\nabc\n");
}

/// Incrementing a `value` holding a number must keep working - a
/// regression a review caught mid-track (commit f3ff0be rejected this
/// before it was reverted). Only Increment/Decrement on TEXT is rejected
/// (findings 5, 15; see tests/compile_fail/077-078_*).
#[test]
fn increment_on_value_typed_number_still_works() {
    let work = work_dir("value-increment");
    let bin = compile(&work, "a value called v is 5.\nIncrement v.\nPrint \"{v}\".\n");
    run_and_expect(&bin, "6\n");
}

/// A for-range loop variable, freshly introduced, still just works - the
/// lock (finding 2) only rejects REUSING an already-declared, incompatibly
/// typed name.
#[test]
fn for_range_fresh_loop_variable_still_works() {
    let work = work_dir("forrange-fresh");
    let bin = compile(
        &work,
        "For each i from 1 to 3,\n  Print \"{i}\".\n",
    );
    run_and_expect(&bin, "1\n2\n3\n");
}

/// Arithmetic on a for-each loop variable over a HOMOGENEOUS list must
/// keep working without any cast/check - only a list PROVEN heterogeneous
/// (finding 18; tests/compile_fail/080_*) requires one.
#[test]
fn for_each_over_homogeneous_list_arithmetic_still_works() {
    let work = work_dir("foreach-homogeneous");
    let bin = compile(
        &work,
        r#"a list called nums is [1, 2, 3].
For each item in nums,
  a number called doubled is item multiply 2,
  Print "{doubled}".
"#,
    );
    run_and_expect(&bin, "2\n4\n6\n");
}
