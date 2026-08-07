// Plan 260 (F2) — a failed build must not leave `<stem>.asm` behind.
//
// `<stem>.asm` is an intermediate written to the working directory before
// nasm/ld run. On success it is cleaned up (unless --keep-asm); until F2 the
// failure paths (nasm-fail, ld-fail, the lib-exists guard, the version-script
// write) exited without removing it, leaking a temp file the user never asked
// to see. Every failure exit after the asm is written now removes it, honouring
// the same `--keep-asm` flag as the success path. `--emit-asm` returns before
// any of those exits, so its assembly is untouched.
//
// These drive the built `vox` binary so they share the toolchain the rest of
// the suite already requires; a missing toolchain fails the build loudly.

use std::fs;
use std::process::{Command, Stdio};

// A failed build (ld cannot open its output) leaves no `<stem>.asm` behind.
#[test]
fn failed_build_leaves_no_asm() {
    let work = std::env::temp_dir().join(format!("vox-p260-asmfail-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    fs::write(
        work.join("prog.vox"),
        "To greet with a number called n.\n  Return a number, n add 1.\n",
    )
    .expect("write prog.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    // An output path whose parent directory does not exist makes ld fail to
    // open its output — a genuine post-asm-write, post-nasm failure that used
    // to leak `prog.asm`.
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("-o")
        .arg(work.join("no_such_dir").join("prog"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        !output.status.success(),
        "expected the build to fail; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Linking failed"),
        "expected an ld failure; stderr:\n{}",
        stderr
    );

    assert!(
        !work.join("prog.asm").exists(),
        "a failed build leaked prog.asm into the working directory"
    );

    let _ = fs::remove_dir_all(&work);
}

// `--emit-asm` exists to keep the assembly, so it must still produce the file.
#[test]
fn emit_asm_still_writes_asm() {
    let work = std::env::temp_dir().join(format!("vox-p260-emitasm-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    fs::write(
        work.join("prog.vox"),
        "To greet with a number called n.\n  Return a number, n add 1.\n",
    )
    .expect("write prog.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("--emit-asm")
        .arg("-o")
        .arg(work.join("prog"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        output.status.success(),
        "--emit-asm failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        work.join("prog.asm").exists(),
        "--emit-asm did not produce prog.asm"
    );

    let _ = fs::remove_dir_all(&work);
}

// `--keep-asm` is honoured even on a failure: the user asked to keep the
// assembly, so a failed build that ran far enough to write it must not delete
// it. (Confirms the cleanup guard checks the flag, not just `--emit-asm`.)
#[test]
fn keep_asm_preserves_asm_on_failure() {
    let work = std::env::temp_dir().join(format!("vox-p260-keepasm-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    fs::write(
        work.join("prog.vox"),
        "To greet with a number called n.\n  Return a number, n add 1.\n",
    )
    .expect("write prog.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    let output = Command::new(vox)
        .arg(work.join("prog.vox"))
        .arg("--keep-asm")
        .arg("-o")
        .arg(work.join("no_such_dir").join("prog"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(!output.status.success(), "expected the build to fail");
    assert!(
        work.join("prog.asm").exists(),
        "--keep-asm did not preserve prog.asm on the failed build"
    );

    let _ = fs::remove_dir_all(&work);
}