# Installing `vox` system-wide

> **Status:** Current install guide — paths and the coreasm resolution order
> verified against `src/main.rs` (B5 audit; B9 update for plan 250 D5/D6).
> `VOX_CORE_PATH` is the documented environment variable and
> `~/.config/vox/config` the documented config path; the older `EC_CORE_PATH`
> and `~/.config/ec/config` names still work as deprecated aliases
> (`src/main.rs:74-86`, `:149-172`). The `vox` name wins when both are set, and a
> one-line deprecation note is printed when only the old name is found.
> _(assessed 2026-08, vox v0.2.0)_

This document describes how to install `vox` and its runtime assembly macros (`coreasm`) so it works from *any* directory.

## Prerequisites

- `cargo` (Rust toolchain >= 1.71, to build the compiler)
- `nasm`
- `ld` (binutils)

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y nasm binutils cargo
```

## Recommended system-wide install (Linux)

### 1) Build a release binary

From the repo root:

```bash
cargo build --release
```

### 2) Install the binary

```bash
sudo install -m 0755 target/release/vox /usr/local/bin/vox
```

### 3) Install the `coreasm` runtime library

`vox` needs access to the `coreasm/` directory at compile time (it passes an `-I` include path to NASM).

Install it to the standard shared-data location:

```bash
sudo mkdir -p /usr/local/share/vox
sudo rm -rf /usr/local/share/vox/coreasm
sudo cp -r coreasm /usr/local/share/vox/coreasm
```

At this point you should be able to run:

```bash
vox /path/to/program.vox --run
```

## Libraries (optional)

Vox has no standard library, and the compiler never needs one — it builds and
runs with `/usr/include/vox/` empty. Libraries are separate, and ship from the
same Copr repository, so no extra setup is needed:

```sh
sudo dnf install vox-libs
```

That installs each library's `.lib` interface into `/usr/include/vox/` and its
`.so` into `/usr/lib64/` — the same split a C library uses between its header
and its shared object. See
[Vox-lang/vox-libs](https://github.com/Vox-lang/vox-libs).

The compiler's RPM carries `Suggests: vox-libs`, which records that they exist
without dnf installing them: a plain `dnf install vox` gets the compiler alone,
exactly as before.

## How `vox` finds `coreasm`

At assembly time, nasm resolves each `%include` first against the directory
`vox` was invoked from — before it consults anything else. This is
deliberate: a checkout under test (a unit test suite, an integration run,
CI building a bleeding-edge `coreasm/`) must assemble its OWN tree's macros
even when `VOX_CORE_PATH` or another setting points somewhere else, or the
suite would silently exercise the wrong runtime instead of the one it is
meant to be testing. If the invoking directory has no matching
`coreasm/<arch>/*.asm` file for what a program needs, resolution falls
through to the directory chosen by the order below, which the compiler
passes to nasm as an `-I` search path:

1. `VOX_CORE_PATH` environment variable (`EC_CORE_PATH` is read as a deprecated alias; `VOX_CORE_PATH` wins when both are set)
2. XDG config file: `~/.config/vox/config` (`core_path=...`; `~/.config/ec/config` is read as a deprecated alias, with the `vox` file winning when both exist)
3. System paths:
   - `/usr/local/share/vox/coreasm`
   - `/usr/share/vox/coreasm`
   - `/opt/vox/coreasm`
4. Executable-relative search (portable installs)
5. Current working directory fallback (`./coreasm`)
6. The copy embedded in the binary itself, written to
   `~/.cache/vox/<version>/coreasm` on first use

Step 6 exists because `cargo install` copies only the binary, leaving the
crate's `coreasm/` behind in the registry cache — without it, a
cargo-installed `vox` cannot compile anything. The compiler therefore
carries its own copy and writes it out the first time it needs it, keyed
by version so two installed compilers never share one tree. It is
consulted **last**, so every path above still wins: an RPM install, a
development tree, and `VOX_CORE_PATH` all behave exactly as they did
before it existed.

Installing with cargo needs nothing else:

```sh
cargo install vox-lang     # the crate is vox-lang; the binary is vox
```

### Working on the compiler with a system install present

Note step 3 if you develop on this repo *and* have `vox` installed
system-wide: with `VOX_CORE_PATH` unset, an installed
`/usr/share/vox/coreasm` wins over the repo's own `coreasm`, even when you
run `./target/release/vox` from inside the tree. Edits to
`coreasm/*/*.asm` then appear to do nothing — a new macro is assembled as
an orphan label (`warning: label 'X' alone on a line without a colon`) and
the feature silently no-ops, because the compiler is using the packaged
runtime rather than the one you are editing.

Set the variable whenever you test a coreasm change by hand:

```bash
export VOX_CORE_PATH="$PWD/coreasm"
```

`./test.sh` already exports it, so the suite is unaffected — only manual
`vox` invocations hit this.

## Option A: Configure via environment variable (per-shell / CI)

If you keep `coreasm` somewhere non-standard:

```bash
export VOX_CORE_PATH=/path/to/vox
# or: export VOX_CORE_PATH=/path/to/vox/coreasm
```

`EC_CORE_PATH` still works as a deprecated alias — `VOX_CORE_PATH` wins when
both are set. If only `EC_CORE_PATH` is found, the compiler prints a one-line
note pointing you at `VOX_CORE_PATH` (once, at the start of the build). Existing
shell profiles and CI that set the old name keep working; migrate when
convenient.

## Option B: Configure via XDG config file (per-user)

Create:

`~/.config/vox/config`

With contents:

```text
# vox config
core_path=/path/to/vox
```

(`core_path` may point at the repo root or at the `coreasm` directory directly.)

`~/.config/ec/config` is still read as a deprecated alias — the `vox` file wins
when both exist. If only the `ec` file is found, the compiler prints a one-line
note pointing you at `~/.config/vox/config` (once, at the start of the build).
Existing per-user configs under the old name keep working; migrate when
convenient.

## Uninstall

```bash
sudo rm -f /usr/local/bin/vox
sudo rm -rf /usr/local/share/vox
```

If you set up user configuration:

```bash
rm -rf ~/.config/vox
```