# 312 — `cargo install vox` produces a working compiler

**Status:** approved by TheJostler (2026-08-18) — build for 0.4.2.

**Dependencies:** none. Touches `Cargo.toml`, a new `build.rs`, and the
coreasm resolution chain in `src/main.rs`.

## The defect

`cargo install vox` installs the binary to `~/.cargo/bin/vox` and
nothing else. The coreasm resolution chain
(`src/main.rs`, `find_core_path`) then tries, in order:

1. `VOX_CORE_PATH` / `EC_CORE_PATH`
2. the XDG config file
3. `/usr/local/share/vox/coreasm`, `/usr/share/vox/coreasm`,
   `/opt/vox/coreasm`

On a machine with no RPM installed, all of these miss and **the
compiler cannot compile anything**. Verified: `find_core_path` has no
final fallback.

## The material fact that shapes the fix

**The crate already ships coreasm.** `cargo package --list` shows all
**21** `.asm` files under `coreasm/` in the published artifact — they are
inside the crates.io tarball, covered by its checksum, and unpacked on
every machine that installs. Nothing needs downloading.

This rules out the obvious-looking alternative of fetching coreasm from
GitHub at install or first run. That would place the code that ends up
inside **every binary Vox emits** outside crates.io's integrity model,
break offline and air-gapped installs and docs.rs builds, and add a
network dependency to a compiler that otherwise has none. Cargo
discourages network access in build scripts for these reasons, and
rustup — the closest precedent — distributes *signed, versioned*
toolchain bundles rather than fetching from a git host.

## Design

Add a `build.rs`. During `cargo install`, cargo unpacks the crate to a
temporary build directory and runs the build script there with
`CARGO_MANIFEST_DIR` pointing at the unpacked sources, so `coreasm/` is
readable at build time by construction.

**Fallback shape: embed, and let disk win.** `build.rs` generates a Rust
source into `OUT_DIR` containing every coreasm file's path and contents;
`main.rs` includes it. `find_core_path` gains a final step: if no
on-disk coreasm was found, materialise the embedded copy into a
per-user cache directory (`$XDG_CACHE_HOME/vox/coreasm-<version>`,
defaulting to `~/.cache`) and use that. The directory is versioned by
the compiler's own `CARGO_PKG_VERSION`, so two installed versions never
share a cache and a stale cache cannot outlive its compiler.

Materialising to disk rather than feeding nasm from memory is
deliberate: nasm resolves `%include` between coreasm files by path, so
they must exist as files. Writing them once per version, on first use,
keeps that working with no change to codegen.

**Precedence is unchanged for existing users.** The embedded copy is
consulted *last*, so `VOX_CORE_PATH`, the XDG config, and the system
paths all continue to win. An RPM install behaves exactly as it does
today; a development tree with `VOX_CORE_PATH` set behaves exactly as it
does today. The only behaviour that changes is the case that currently
fails outright.

**Why embed rather than have `build.rs` install to a system path:**
a build script must not write outside `OUT_DIR` (it may run unprivileged,
sandboxed, or during `cargo package` verification), and `cargo install`
does not run as root. Embedding keeps the compiler and its runtime
inseparable, which also closes the shadowing class of bug this project
has hit repeatedly (see `docs/INSTALL.md`).

**Growth:** coreasm is 240KB of text today (21 files, all
architectures). If it grows large enough that embedding hurts, the same
fallback function can switch to a sysroot located relative to the
executable — the approach rustc, zig, and go use — without changing the
resolution order or any user-visible behaviour. That is the documented
escape hatch, not this plan's work.

## Acceptance criteria

1. `cargo install --path .` into a clean prefix, with `VOX_CORE_PATH`
   unset and **no** `/usr/share/vox/coreasm` present, compiles and runs
   a hello-world `.vox`. This is the whole point and must be tested
   with the system coreasm genuinely out of the way, not merely
   unreferenced.
2. `VOX_CORE_PATH` still wins over the embedded copy — prove it by
   pointing it at a coreasm containing a detectable marker and finding
   that marker in `--emit-asm` output.
3. A system coreasm still wins over the embedded copy.
4. Second and subsequent runs reuse the materialised cache rather than
   rewriting it; a run with the cache deleted re-materialises it.
5. `cargo package` still succeeds and still lists all 21 `.asm` files.
6. `./test.sh` and `cargo test` unchanged and green; zero build
   warnings.
7. The embedded set is generated from `coreasm/` at build time — never
   a hand-maintained file list, which would silently rot when a
   `.asm` file is added.

## Documentation

`docs/INSTALL.md` gains `cargo install vox` as a supported path with a
note that the compiler carries its own coreasm and materialises it on
first use; the existing shadowing warning stays and gains a line saying
the embedded copy is last in precedence. `README.md`'s install section
mentions cargo alongside Copr. CHANGELOG entry under a new `[0.4.2]`.
