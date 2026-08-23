// BUGS_FOUND #93 (part B) — the compiler warning for a dynamic buffer
// declared with no size or initializer used to say "This creates a
// zero-capacity buffer which may not be useful", which is wrong: the
// runtime gives every fresh dynamic buffer 4096 bytes of capacity up
// front (`INITIAL_BUF_CAP`, coreasm/x86_64/resource.asm:25). The warning
// still usefully suggests a sized declaration when the size is known
// ahead of time, so it is kept, but corrected to say what actually
// happens. No test previously asserted this warning's text at all.

use std::fs;
use std::process::{Command, Stdio};

fn work_dir(tag: &str) -> std::path::PathBuf {
    let work = std::env::temp_dir().join(format!("vox-bugs93-warn-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");
    work
}

#[test]
fn uninitialized_dynamic_buffer_warning_states_the_true_default_capacity() {
    let work = work_dir("warn");
    let src_path = work.join("prog.vox");
    fs::write(&src_path, "a buffer called b.\nPrint \"ok\".\n").expect("write prog.vox");
    let bin = work.join("prog");

    let compile = Command::new(env!("CARGO_BIN_EXE_vox"))
        .arg(&src_path)
        .arg("-o")
        .arg(&bin)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        compile.status.success(),
        "an uninitialized dynamic buffer must still compile (warning, not error); stderr:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        stderr.contains("Warning: Buffer \"b\" declared without size or initializer"),
        "expected the uninitialized-buffer warning; got:\n{}",
        stderr
    );
    assert!(
        stderr.contains("4096 bytes of capacity"),
        "warning must state the true default capacity (4096); got:\n{}",
        stderr
    );
    assert!(
        !stderr.to_lowercase().contains("zero-capacity") && !stderr.to_lowercase().contains("zero capacity"),
        "warning must no longer claim zero capacity; got:\n{}",
        stderr
    );
    // The sized-declaration suggestion is still useful advice; keep it.
    assert!(
        stderr.contains("a buffer called 'b' is 1024 bytes"),
        "warning should still suggest a sized declaration; got:\n{}",
        stderr
    );

    fs::remove_dir_all(&work).ok();
}
