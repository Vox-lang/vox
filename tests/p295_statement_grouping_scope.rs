// Plan 295 findings 2 and 3 — investigated together, per the plan's own
// instruction to root-cause them before patching either.
//
// CONCLUSION: neither is a compiler defect. Both repros are the
// "malformed source" pattern plan 282 already investigated, red-teamed, and
// got an explicit owner ruling on for structurally identical programs (see
// docs/plans/282_while_ignores_paragraph_break.md, "Reclassified: bugs
// originally reported as 2 and 3 are malformed source"). Plan 295's own
// framing of "the rule" - stated in prose as "is the following text
// independently valid as its own top-level sentence?" - is the exact
// speculative-comma-lookahead heuristic plan 282's withdrawn first attempt
// built and then discarded after a red team found six independent
// correctness bugs and an O(N^2) parse-time/stack-overflow DoS in it (see
// plan 282's "History" section). That heuristic was never the real rule and
// was never implemented; LANGUAGE.md's actual, current, already-correctly-
// implemented rule is different:
//
//   1. A period closes the most recently opened clause - the innermost one
//      currently open (if/on error/for/while/repeat/function), and only
//      that one.
//   2. A blank line (paragraph break) force-closes every open clause at
//      once, including an enclosing function definition.
//
// Applying rule 1 by hand to both repros (verified empirically below, not
// just reasoned about) produces exactly the CURRENT compiler output - not
// plan 295's EXPECTED.md, which assumes the discarded heuristic instead.
// Both repros are simply missing a comma at the exact point where the
// author needed to keep a clause open (a nested `if`'s own self-terminating
// period closes only the `if`; whatever follows needs a comma to stay
// inside the enclosing while/function, or it becomes the enclosing
// construct's own closing statement instead). Adding exactly that comma
// (see the `_conforming` variant of each test) reproduces the author's
// intended semantics using the existing, already-correct rule - proving the
// rule itself is sufficient and the repros are the thing that's wrong, not
// the parser.
//
// This is now the third time this exact shape of confusion has produced a
// bug report (plan 282's original bugs 2/3, and now plan 295's findings 2/3)
// against real, working code - both times pointing at the same production
// file (voxos's sh.vox, outside this repo). That is a real, repeated
// ergonomics problem worth addressing with a diagnostic (a warning on the
// ambiguous shape) or documentation, but it is not a parser bug, and
// plan 282's own history is direct evidence that trying to make the parser
// "smarter" about this ambiguity - rather than diagnosing it - is exactly
// how new, worse bugs get introduced here. No parser change is made for
// findings 2/3; these tests lock in the current, correct behavior so a
// future well-intentioned "fix" doesn't reintroduce plan 282's discarded
// heuristic.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-p295-scope-{}-{}", tag, std::process::id()));
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

// Finding 2's exact repro. Per rule 1, `print "inner".`'s period closes the
// `if` (the innermost open clause) - the if's own body is exactly the one
// comma-joined sentence it was given, which is just that one action.
// `Return.` is therefore NOT nested inside the if; it is the function
// body's own next direct statement, and a `Return` parsed as a function's
// own direct body statement ends the body early (a separate, deliberate
// convenience documented at src/parser/mod.rs:4319-4337, unrelated to rule
// 1/2, so a function whose body ends in `Return.` doesn't need a trailing
// blank line to avoid swallowing following top-level code). `Return.` was
// never the *last* statement here as the author apparently intended, so
// `print "ESCAPED".` is left over as a top-level statement, unconditional
// and independent of whether `'do thing'` is ever called - which is exactly
// what runs.
#[test]
fn finding2_repro_matches_the_documented_termination_rule() {
    let work = work_dir("f2-asis");
    let bin = compile(
        &work,
        r#"To 'do thing' with a number called n.
    if n is 1 then,
        print "inner".
        Return.
    print "ESCAPED".

print "MAIN".
"#,
    );
    assert_eq!(run(&bin), "ESCAPED\nMAIN\n");
    let _ = fs::remove_dir_all(&work);
}

// The author's evident intent - `Return.` nested inside the `if`, `print
// "ESCAPED".` unconditional but still part of the function body -
// expressed the way rule 1 actually requires: a comma keeps `Return.`
// inside the `if`'s own sentence instead of letting the `if`'s period close
// it early. With that one comma, `'do thing'` is never called, so nothing
// from its body may run, and only `MAIN` prints - the plan's own
// EXPECTED.md outcome, achieved with the existing rule and no parser
// change.
#[test]
fn finding2_conforming_rewrite_achieves_the_intended_semantics() {
    let work = work_dir("f2-conforming");
    let bin = compile(
        &work,
        r#"To 'do thing' with a number called n.
    if n is 1 then,
        print "inner",
        Return.
    print "ESCAPED".

print "MAIN".
"#,
    );
    assert_eq!(run(&bin), "MAIN\n");
    let _ = fs::remove_dir_all(&work);
}

// Calling the function makes the current (correct-per-rule-1) parse
// explicit: `Return.` is a direct, unconditional body statement (a sibling
// of the `if`, not nested in it), so every call returns immediately
// regardless of `n` - `"inner"` prints only when the `if`'s own condition
// is true, but the function always returns right after, and `"ESCAPED"`
// (parsed as top-level, per the test above) never runs as part of either
// call - it runs once, unconditionally, as soon as the program reaches
// that point in top-level execution order, which is *before* either call
// (it was parsed as the statement immediately following the function
// definition, ahead of both `'do thing' with ...` calls below it).
#[test]
fn finding2_repro_called_returns_unconditionally_regardless_of_n() {
    let work = work_dir("f2-called");
    let bin = compile(
        &work,
        r#"To 'do thing' with a number called n.
    if n is 1 then,
        print "inner".
        Return.
    print "ESCAPED".

'do thing' with 1.
'do thing' with 2.
print "MAIN".
"#,
    );
    assert_eq!(run(&bin), "ESCAPED\ninner\nMAIN\n");
    let _ = fs::remove_dir_all(&work);
}

// Finding 3's exact repro. Trace: `increment k,` explicitly continues the
// while's sentence. `if p is 9 then, print "never".` is a nested clause;
// its own period closes only it (rule 1), and the while - still open -
// keeps going without needing a comma (this fallthrough is deliberate and
// unchanged since plan 282, see src/parser/mod.rs `parse_while`). But
// `print "EXTRA k={k}".` is a *bare* action: nothing is nested open when
// its period is reached, so per rule 1 that period closes the innermost
// open clause, which at that point is the `while` itself. Everything after
// - the second `if` and `print "TAIL k={k}".` - is therefore top-level,
// executed exactly once, after the loop has already run to completion
// (k=2), which is why the second `if`'s condition (`k is 1`) is false by
// the time it runs and `BRANCH` never prints.
#[test]
fn finding3_repro_matches_the_documented_termination_rule() {
    let work = work_dir("f3-asis");
    let bin = compile(
        &work,
        r#"a number called k is 0.
a number called p is 0.
While k is less than 2,
    increment k,
    if p is 9 then, print "never".
    print "EXTRA k={k}".
    if p is 0 and k is 1 then,
        print "BRANCH k={k}".
    print "TAIL k={k}".
"#,
    );
    assert_eq!(run(&bin), "EXTRA k=1\nEXTRA k=2\nTAIL k=2\n");
    let _ = fs::remove_dir_all(&work);
}

// The author's evident intent - all four actions running every iteration -
// expressed with the comma rule 1 actually requires: a comma after `print
// "EXTRA k={k}"` keeps the while's sentence open past it. The second `if`
// is moved ahead of `print "EXTRA k={k}"` rather than comma-joined directly
// after it, because `print X, if Y ...` (no `but`) is itself valid `but if`
// conditional-sugar grammar (`src/parser/mod.rs` `maybe_parse_conditional_
// suffix` treats a bare `if` after the comma the same as `but if` - see
// plan 291) - an unrelated, pre-existing ambiguity, not something this
// investigation needed to resolve. With that reordering, every action runs
// every iteration, and `print "TAIL k={k}"` (now the last action, still a
// bare statement) correctly closes the while with its own un-stolen
// period - the plan's own EXPECTED.md outcome (modulo the BRANCH/EXTRA
// print order, which is a direct consequence of the reordering forced by
// the sugar ambiguity above, not a semantic difference), achieved with the
// existing rule and no parser change.
#[test]
fn finding3_conforming_rewrite_achieves_the_intended_semantics() {
    let work = work_dir("f3-conforming");
    let bin = compile(
        &work,
        r#"a number called k is 0.
a number called p is 0.
While k is less than 2,
    increment k,
    if p is 9 then, print "never".
    if p is 0 and k is 1 then, print "BRANCH k={k}".
    print "EXTRA k={k}",
    print "TAIL k={k}".
"#,
    );
    assert_eq!(run(&bin), "BRANCH k=1\nEXTRA k=1\nTAIL k=1\nEXTRA k=2\nTAIL k=2\n");
    let _ = fs::remove_dir_all(&work);
}
