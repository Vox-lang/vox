# Installing `vox` system-wide

This document describes how to install `vox` and its runtime assembly macros (`coreasm`) so it works from *any* directory.

## Prerequisites

- `cargo` (Rust toolchain, to build the compiler)
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

## How `vox` finds `coreasm`

The compiler searches for `coreasm` using the following resolution order:

1. `EC_CORE_PATH` environment variable
2. XDG config file: `~/.config/vox/config` (`core_path=...`)
3. System paths:
   - `/usr/local/share/vox/coreasm`
   - `/usr/share/vox/coreasm`
   - `/opt/vox/coreasm`
4. Executable-relative search (portable installs)
5. Current working directory fallback (`./coreasm`)

## Option A: Configure via environment variable (per-shell / CI)

If you keep `coreasm` somewhere non-standard:

```bash
export EC_CORE_PATH=/path/to/vox
# or: export EC_CORE_PATH=/path/to/vox/coreasm
```

## Option B: Configure via XDG config file (per-user)

Create:

`~/.config/vox/config`

With contents:

```text
# vox config
core_path=/path/to/vox
```

(`core_path` may point at the repo root or at the `coreasm` directory directly.)

## Uninstall

```bash
sudo rm -f /usr/local/bin/vox
sudo rm -rf /usr/local/share/vox
```

If you set up user configuration:

```bash
rm -rf ~/.config/vox
```