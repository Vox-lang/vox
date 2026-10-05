#!/bin/bash
#
# Vox has no dependencies beyond the Rust standard library, so Cargo.lock lists
# only vox-lang itself and vox.spec declares no bundled crates. If a crate is
# ever added, a binary that statically links it must declare it with
# `Provides: bundled(crate(<name>)) = <version>`: "all bundled crate
# dependencies MUST be declared with virtual Provides in the format
# Provides: bundled(crate($crate)) = $version in the subpackage that contains
# the Rust component"
# (https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/).
# Adding a crate also means giving vox.spec a vendor tarball and a `cargo
# build --offline` source replacement again (see git history of vox.spec and
# .copr/Makefile before the zero-dependency change).
#
# The spec has to be static -- Copr builds ONE source RPM and feeds it to
# every chroot, so nothing may rewrite the spec at SRPM time -- which means
# that list is hand-written and can drift the moment a dependency is added,
# removed, or bumped. This script is what stops that: it derives the list
# from Cargo.lock and fails if the spec disagrees. ./test.sh runs it.
#
# Usage: scripts/check-spec-bundled.sh [Cargo.lock] [vox.spec]

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="${1:-$root/Cargo.lock}"
spec="${2:-$root/vox.spec}"

for f in "$lock" "$spec"; do
    if [[ ! -f "$f" ]]; then
        echo "check-spec-bundled: $f not found" >&2
        exit 2
    fi
done

# The crate this repo IS, taken from the [package] name of the Cargo.toml
# beside the lockfile, is not a bundled dependency of itself -- everything
# else in Cargo.lock is.
manifest="$(dirname "$lock")/Cargo.toml"
if [[ ! -f "$manifest" ]]; then
    echo "check-spec-bundled: $manifest not found" >&2
    exit 2
fi
self="$(sed -n 's/^name = "\(.*\)"/\1/p' "$manifest" | head -1)"

# Every package in Cargo.lock except the crate this repo is.
from_lock="$(awk -v self="$self" '
    /^\[\[package\]\]/ { name = ""; version = ""; next }
    /^name = / { gsub(/^name = "|"$/, ""); name = $0; next }
    /^version = "/ { gsub(/^version = "|"$/, ""); version = $0
                     if (name != "" && name != self) print name " " version
                     next }
' "$lock" | sort)"

# An empty list is the expected state, but only if the lockfile still parses:
# it must contain this crate itself, or the format moved under us and an
# empty list would be a vacuous pass.
if ! grep -q "^name = \"$self\"\$" "$lock"; then
    echo "check-spec-bundled: $self not found in $lock -- has the" >&2
    echo "  Cargo.lock format changed? Refusing to report a vacuous pass." >&2
    exit 2
fi

# Read the Provides lines as written.
from_spec="$(sed -n 's/^Provides:[[:space:]]*bundled(crate(\([^)]*\)))[[:space:]]*=[[:space:]]*\(.*\)$/\1 \2/p' \
    "$spec" | sed 's/[[:space:]]*$//' | grep . | sort)"

if [[ "$from_lock" == "$from_spec" ]]; then
    count=$(printf '%s\n' "$from_lock" | grep -c . || true)
    echo "check-spec-bundled: OK - $count bundled crate(s) match Cargo.lock"
    exit 0
fi

echo "check-spec-bundled: vox.spec's bundled() list disagrees with Cargo.lock" >&2
echo "  in Cargo.lock but not in vox.spec:" >&2
comm -23 <(printf '%s\n' "$from_lock") <(printf '%s\n' "$from_spec") | sed 's/^/    /' >&2
echo "  in vox.spec but not in Cargo.lock:" >&2
comm -13 <(printf '%s\n' "$from_lock") <(printf '%s\n' "$from_spec") | sed 's/^/    /' >&2
if [[ -z "$from_lock" ]]; then
    echo "  Fix: remove the 'Provides: bundled(crate(...))' lines from vox.spec." >&2
else
    echo "  Fix: make the 'Provides: bundled(crate(...)) = ...' lines in vox.spec" >&2
    echo "  read exactly:" >&2
    printf '%s\n' "$from_lock" | awk '{ printf "    Provides:       bundled(crate(%s)) = %s\n", $1, $2 }' >&2
fi
exit 1
