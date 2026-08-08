// Plan 282 — `while` did not honor a `ParagraphBreak` (blank line) as a
// body terminator, unlike `for`/`repeat`, which already did. See
// `docs/plans/282_while_ignores_paragraph_break.md` for the full
// root-cause writeup and the language's own termination rule, now also
// documented in `LANGUAGE.md`.
//
// The fix is two lines in `parse_while`'s separator-decision chain: a
// `ParagraphBreak` now ends the body (matching `for`/`repeat`) instead of
// being skipped as noise. These are end-to-end tests: compile the exact
// repro and actually run the produced binary, since the bug was only
// externally observable through real program behavior (a runaway infinite
// print), not a parse error.
//
// An earlier attempt at this fix (withdrawn, preserved at
// `rescue/p282-wrong-model`) used a speculative-comma-lookahead heuristic
// instead of implementing the language's own documented rule directly.
// This file replaces `tests/p282_loop_body_swallow.rs` from that attempt
// (same rescue ref), adapted to the final semantics: bugs originally
// reported as 2 and 3 are reclassified as malformed source (see the plan
// doc), not compiler defects, so their fixed-output assertions from the
// withdrawn version are gone — asserting a "fix" for source the language
// doesn't consider valid would be asserting the wrong thing.

use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-p282-{}-{}", tag, std::process::id()));
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

fn run(bin: &std::path::Path) -> String {
    let output = Command::new(bin)
        .stdin(Stdio::null())
        .output()
        .expect("run compiled binary");
    assert!(output.status.success(), "program should exit cleanly");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Assert the compiled binary hangs (does not exit) and produces exactly
/// `expected_stdout` within the timeout — never more. Used for every case
/// in this file where the body correctly ended before a mutator the loop
/// condition depends on, so the loop must never terminate; the *symptom*
/// this whole plan exists to fix was a runaway re-print of whatever got
/// wrongly pulled into the body, so asserting exact, non-growing output is
/// the actual regression check, not just "it doesn't exit".
fn assert_hangs_with_exact_output(bin: &std::path::Path, expected_stdout: &str) {
    let mut child = Command::new(bin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn compiled binary");
    let mut stdout = child.stdout.take().expect("child stdout");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    std::thread::sleep(Duration::from_millis(1500));

    match child.try_wait() {
        Ok(Some(status)) => panic!(
            "expected the loop to genuinely hang, but the process exited with {:?}",
            status
        ),
        Ok(None) => {} // still running - correct, this loop must never terminate
        Err(e) => panic!("try_wait failed: {}", e),
    }

    child.kill().expect("kill hung child");
    let _ = child.wait();

    let buf = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("reader thread should finish once the child's stdout pipe closes");
    let output = String::from_utf8_lossy(&buf);
    assert_eq!(
        output, expected_stdout,
        "hung binary produced unexpected output - either a runaway re-print (wrong \
         statement pulled into the loop body) or a mutator was included that shouldn't \
         have been (loop would have to terminate)"
    );
}

// Bug 1's original repro, with the blank line the reclassified rule
// requires: `if j is equal to 1 then, the j is j add 1.` is the while's
// only body statement (self-terminates its own period), then a blank line,
// then an independently-valid trailing `Print`. `j` only ever increments
// behind a condition that's never true, so this loop must never terminate,
// and the trailing `Print` - correctly separated by the blank line - must
// never run. Pre-fix (even with the blank line present) this printed
// `start` once and then looped forever RE-PRINTING the trailing line, a
// runaway print, because `parse_while` treated the blank line as
// skippable noise instead of a terminator.
#[test]
fn bug1_while_if_then_hangs_without_swallowing_trailing_print() {
    let work = work_dir("bug1");
    let bin = compile(
        &work,
        r#"Print "start".
a number called j is 0.
While j is less than 3,
    if j is equal to 1 then, the j is j add 1.

Print "this should never print if the loop is genuinely stuck".
"#,
    );
    assert_hangs_with_exact_output(&bin, "start\n");
    let _ = fs::remove_dir_all(&work);
}

// The pi.vox shape: a blank line right after a comma-continued line is
// pure visual spacing within a still-open sentence and must not end the
// body - this is `while`-specific (its comma branch explicitly skips a
// following `ParagraphBreak`), not shared by `for`/`repeat`, whose
// grammars don't have an equivalent "protected" case (see the two tests
// below, which confirm `for`'s pre-existing, different, unconditional
// behavior instead).
#[test]
fn while_blank_line_after_comma_does_not_end_body() {
    let work = work_dir("while-comma-safe");
    let bin = compile(
        &work,
        r#"a number called j is 0.
While j is less than 3,
    print j,

    the j is j add 1.
Print "after".
"#,
    );
    assert_eq!(run(&bin), "0\n1\n2\nafter\n");
    let _ = fs::remove_dir_all(&work);
}

// The mirror of the case above, and the actual fix: a blank line right
// after a statement that already consumed its own trailing period
// (`if`/`on error` owning their own period, per `parse_if`) is a genuine
// paragraph break and must end the body - `while` now matches
// `for`/`repeat`'s pre-existing behavior here instead of treating the
// blank line as noise and continuing to swallow the next statement.
#[test]
fn while_blank_line_after_if_then_ends_body() {
    let work = work_dir("while-if-closes");
    let bin = compile(
        &work,
        r#"a number called j is 0.
While j is less than 3,
    if j is equal to 5 then, print "never".

Print "after".
"#,
    );
    // The if's condition is never true and nothing else in the body
    // mutates j, so if the blank line correctly ended the body, this
    // loop must hang - never print "after", never exit.
    assert_hangs_with_exact_output(&bin, "");
    let _ = fs::remove_dir_all(&work);
}

// `for each ... from X to Y` already had this behavior before this fix
// (parse_for's body loop already breaks unconditionally on a
// ParagraphBreak) - confirmed unaffected, proving `while` now matches an
// existing sibling rather than diverging from it.
#[test]
fn for_range_blank_line_after_if_then_ends_body_unaffected() {
    let work = work_dir("for-range-if-closes");
    let bin = compile(
        &work,
        r#"For each n from 1 to 3,
    if n is equal to 99 then, print "never".

Print "after".
"#,
    );
    assert_eq!(run(&bin), "after\n");
    let _ = fs::remove_dir_all(&work);
}

// Same as above, for the `for each ... in <collection>` form.
#[test]
fn for_each_in_collection_blank_line_after_if_then_ends_body_unaffected() {
    let work = work_dir("for-each-if-closes");
    let bin = compile(
        &work,
        r#"a list called nums is [1, 2, 3].
For each n in nums,
    if n is equal to 99 then, print "never".

Print "after".
"#,
    );
    assert_eq!(run(&bin), "after\n");
    let _ = fs::remove_dir_all(&work);
}

// `repeat` already had this behavior before this fix too (its own
// period-then-ParagraphBreak-or-Return-or-EOF check, unrelated to this
// change) - confirmed unaffected. `repeat`'s body is period-separated
// statements, not comma-joined, so there is no comma-protected case to
// mirror here the way there is for `while`.
#[test]
fn repeat_blank_line_after_if_then_ends_body_unaffected() {
    let work = work_dir("repeat-if-closes");
    let bin = compile(
        &work,
        r#"a number called n is 0.
Repeat 3 times,
    the n is n add 1.
    if n is equal to 99 then, print "never".

Print "after n={n}".
"#,
    );
    assert_eq!(run(&bin), "after n=3\n");
    let _ = fs::remove_dir_all(&work);
}
