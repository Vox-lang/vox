// Plan 210 P1 — `--shared` must not destroy a pre-existing `<source>.map`.
//
// The version script the linker needs is a pure implementation detail with no
// value to the user, so it must never land in their working directory: a `.map`
// next to a source file is plausible (linker scripts and source maps both use
// the extension), and the old code wrote `<base_name>.map` there and then
// deleted it — destroying whatever the user had. This drives the real
// compiler binary on a real `--shared` compile and asserts a pre-existing
// `<name>.map` survives with its original contents.
//
// It invokes the built `vox` binary, which shells out to nasm + ld, so it
// shares the toolchain the rest of the suite already requires (test.sh builds
// every program the same way). It never skips — a missing toolchain fails the
// build loudly, the way the project wants.

use std::fs;
use std::process::{Command, Stdio};

#[test]
fn shared_does_not_clobber_preexisting_map() {
    let work = std::env::temp_dir().join(format!("vox-p210-map-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).expect("create temp work dir");

    // A precious, user-owned linker script beside the source.
    let precious = "MY IMPORTANT LINKER SCRIPT\n";
    fs::write(work.join("victim.map"), precious).expect("write victim.map");

    // A one-export library — the smallest thing `--shared` accepts.
    fs::write(
        work.join("victim.vox"),
        "To \"greet\".\n  Print \"hi\".\n",
    )
    .expect("write victim.vox");

    let vox = env!("CARGO_BIN_EXE_vox");
    let output = Command::new(vox)
        .arg(work.join("victim.vox"))
        .arg("--shared")
        .arg("-o")
        .arg(work.join("victim.so"))
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    assert!(
        output.status.success(),
        "vox --shared failed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The user's file must still exist, untouched.
    let after = fs::read_to_string(work.join("victim.map"))
        .expect("victim.map must still exist after --shared");
    assert_eq!(
        after, precious,
        "victim.map was overwritten or deleted by the --shared compile"
    );

    let _ = fs::remove_dir_all(&work);
}