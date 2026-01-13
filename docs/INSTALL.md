# Installing `ec` system-wide

This document describes how to install `ec` and its runtime assembly macros (`coreasm`) so it works from *any* directory.

## Prerequisites

- `nasm`
- `ld` (binutils)

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y nasm binutils
```

## Recommended system-wide install (Linux)

### 1) Build a release binary

From the repo root:

```bash
cargo build --release
```

### 2) Install the binary

```bash
sudo install -m 0755 target/release/ec /usr/local/bin/ec
```

### 3) Install the `coreasm` runtime library

`ec` needs access to the `coreasm/` directory at compile time (it passes an `-I` include path to NASM).

Install it to the standard shared-data location:

```bash
sudo mkdir -p /usr/local/share/ec
sudo rm -rf /usr/local/share/ec/coreasm
sudo cp -r coreasm /usr/local/share/ec/coreasm
```

At this point you should be able to run:

```bash
ec /path/to/program.en --run
```

## How `ec` finds `coreasm`

The compiler searches for `coreasm` using the following resolution order:

1. `EC_CORE_PATH` environment variable
2. XDG config file: `~/.config/ec/config` (`core_path=...`)
3. System paths:
   - `/usr/local/share/ec/coreasm`
   - `/usr/share/ec/coreasm`
   - `/opt/ec/coreasm`
4. Executable-relative search (portable installs)
5. Current working directory fallback (`./coreasm`)

## Option A: Configure via environment variable (per-shell / CI)

If you keep `coreasm` somewhere non-standard:

```bash
export EC_CORE_PATH=/path/to/ec
# or: export EC_CORE_PATH=/path/to/ec/coreasm
```

## Option B: Configure via XDG config file (per-user)

Create:

`~/.config/ec/config`

With contents:

```text
# ec config
core_path=/path/to/ec
```

(`core_path` may point at the repo root or at the `coreasm` directory directly.)

## Uninstall

```bash
sudo rm -f /usr/local/bin/ec
sudo rm -rf /usr/local/share/ec
```

If you set up user configuration:

```bash
rm -rf ~/.config/ec
```
