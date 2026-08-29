// #113 — a `coreasm/` tree in the working directory takes precedence over
// `VOX_CORE_PATH` at assembly time, BY DESIGN.
//
// Owner ruling (2026-08-29): this is not a defect. nasm resolves a relative
// `%include` against its own current working directory before it ever
// consults `-I`, and vox deliberately leaves that in place — a checkout
// under test (a unit test suite building against its own bleeding-edge
// `coreasm/`) must assemble its OWN tree's macros, not a `VOX_CORE_PATH`
// pointed elsewhere, or CI and integration testing would silently exercise
// the wrong runtime. `VOX_CORE_PATH` and the rest of the resolution order
// (`find_coreasm_path`) only decide when the invoking directory has no
// `coreasm/x86_64/` of its own.
//
// This test pins that precedence rather than fighting it: it plants a
// one-byte, macro-free decoy at `coreasm/x86_64/list.asm` in a temp working
// directory, points `VOX_CORE_PATH` at this tree's real (working) coreasm,
// and asserts the compile FAILS with nasm's "instruction expected" error —
// proof that the cwd copy, not the `VOX_CORE_PATH` tree, was the one
// assembled. An EMPTY `coreasm/x86_64/` would not prove this (nasm only
// wins on a file that exists at the relative path), which is why the decoy
// is one real byte.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn cwd_coreasm_takes_precedence_by_design() {
    let vox = env!("CARGO_BIN_EXE_vox");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let real_coreasm = root.join("coreasm");

    let work = std::env::temp_dir().join(format!("vox-p113-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    let decoy_arch_dir = work.join("coreasm").join("x86_64");
    fs::create_dir_all(&decoy_arch_dir).expect("create decoy coreasm/x86_64");

    // One byte, no macros — nasm chokes on it as soon as it is `%include`d,
    // so a compile failure here proves this decoy (not the real tree) is
    // what got assembled.
    fs::write(decoy_arch_dir.join("list.asm"), b"x").expect("write decoy list.asm");

    let src = work.join("prog.vox");
    fs::write(
        &src,
        "a list called items is [1, 2, 3].\nPrint items.\n",
    )
    .expect("write prog.vox");

    let bin = work.join("prog");
    let compile = Command::new(vox)
        .env("VOX_CORE_PATH", &real_coreasm)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        // The cwd holds the decoy; VOX_CORE_PATH points at the real tree.
        // By design, the decoy wins.
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn vox");

    let stderr = String::from_utf8_lossy(&compile.stderr);
    assert!(
        !compile.status.success(),
        "compile was expected to fail against the cwd decoy at {}/coreasm/x86_64/list.asm \
         despite VOX_CORE_PATH={} — the cwd tree no longer took precedence, which contradicts \
         the owner's ruling that this is by design:\n{}",
        work.display(),
        real_coreasm.display(),
        stderr
    );
    assert!(
        stderr.contains("instruction expected"),
        "compile failed, but not with the decoy's expected nasm parse error — got:\n{}",
        stderr
    );

    let _ = fs::remove_dir_all(&work);
}
