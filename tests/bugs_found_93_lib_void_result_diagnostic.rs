// BUGS_FOUND #93 (part A) — the diagnostic for reading the result of a
// `.lib` entry that has no `, returning` clause used to cite LANGUAGE.md by
// line number: `(LANGUAGE.md:4963-4965)` and `(LANGUAGE.md:4990)`. Both
// numbers had drifted onto unrelated text (the Contextual Keywords list and
// the Things section) by the time this was found. The fix cites the two
// sections by NAME instead, matching the house style already used next door
// in `untyped_returns.rs` (`LANGUAGE.md "Functions"`).
//
// This diagnostic can only be triggered through the real `.lib` import path
// (`lib_file::resolve_program_imports`, wired up in `main.rs`), which the
// analyzer-only `compile_fail` corpus (`src/compile_fail_tests.rs`) never
// exercises — it builds an `Analyzer` directly and never calls
// `.with_imports(..)`. So, like `p296_lib_element_type_runtime.rs`, this
// test builds a real `.so`/`.lib` pair and compiles a separate consumer
// against it.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-bugs93-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

#[test]
fn reading_a_returning_less_lib_entrys_result_cites_sections_by_name() {
    let work = work_dir("void-lib-entry");

    // Build the library: one entry, no `, returning` clause.
    let lib_src = work.join("libgreetlib.vox");
    fs::write(&lib_src, "Library greetlib version \"1.0\".\n\nTo greet.\n  Print \"hi\".\n")
        .expect("write libgreetlib.vox");
    let so = work.join("liblibrary.so");
    let build = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&lib_src)
        .arg("--shared")
        .arg("-o")
        .arg(&so)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox --shared");
    assert!(
        build.status.success(),
        "library build failed; stderr:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(
        work.join("liblibrary.lib").exists(),
        "expected liblibrary.lib to be emitted beside liblibrary.so"
    );

    // The consumer reads 'greet's result as a value — the entry has no
    // declared return type, so this is refused.
    let consumer_src = work.join("consumer.vox");
    fs::write(
        &consumer_src,
        "see greetlib version \"1.0\" from \"./liblibrary.lib\".\n\n\
         a number called n is greet.\n\
         Print n.\n",
    )
    .expect("write consumer.vox");
    let bin = work.join("consumer");
    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&consumer_src)
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        !compile.status.success(),
        "reading a void .lib entry's result as a value must be refused"
    );
    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains("has no declared return type in its .lib entry"),
        "expected the void-lib-entry diagnostic; got:\n{}",
        stderr
    );

    // The two citations now name their sections, not stale line numbers.
    assert!(
        stderr.contains("LANGUAGE.md \"The `.lib` file\""),
        "expected a citation naming \"The `.lib` file\" section; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("LANGUAGE.md \"Consuming a library\""),
        "expected a citation naming the \"Consuming a library\" section; got:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("LANGUAGE.md:4963") && !stderr.contains("LANGUAGE.md:4990"),
        "stale line-number citations must be gone; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}
