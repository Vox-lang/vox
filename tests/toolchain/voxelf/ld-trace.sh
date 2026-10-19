# Sourced by the tests that link with voxelf, after they set $work, their
# scratch directory. Nothing on voxelf's side, vox-elf or nasm-image.sh,
# calls ld; this measures it rather than assuming it.
#
# guarded COMMAND... runs voxelf's side of a link under strace, which records
# every program it starts, wherever it lives, so a call by an absolute path,
# such as /usr/bin/ld, is seen as well as one found on PATH. A stand-in for
# ld first on PATH also fails any call found there, so ld cannot quietly do
# the link. ld_pass_throughs counts the programs started whose name is ld or
# starts with "ld.", such as ld.bfd and ld.gold.
if ! command -v strace > /dev/null; then
    echo "$0: strace is not installed; the test counts voxelf's calls to ld with it" >&2
    exit 1
fi
mkdir -p "$work/guard"
printf '#!/bin/sh\nexit 1\n' > "$work/guard/ld"
chmod +x "$work/guard/ld"
: > "$work/execs.log"
guarded() { PATH="$work/guard:$PATH" strace -f -qq -z -e trace=execve -e signal=none -A -o "$work/execs.log" "$@"; }
ld_execs() { grep -E 'execve\("([^"]*/)?ld(\.[^"/]*)?"' "$work/execs.log"; }
ld_pass_throughs() { ld_execs | wc -l; }
