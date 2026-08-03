#!/usr/bin/env bash
# Build and test the migrate-identifiers codemod.
# The tool is a standalone package (the repo root is NOT a Cargo workspace),
# so cargo must run from this directory, not the repo root.
set -euo pipefail
cd "$(dirname "$0")"   # -> tools/migrate-identifiers
cargo test
cargo build --release