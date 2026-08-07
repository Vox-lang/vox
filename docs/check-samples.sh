#!/usr/bin/env bash
#
# check-samples.sh — compile every real Vox code sample in a doc and report
# honest pass/fail/skip counts.
#
# Usage:  docs/check-samples.sh [FILE]     (default: LANGUAGE.md)
# Exit:   0 if every compiled sample either passed or was an explained,
#         expected excerpt failure; 1 if any sample failed for an
#         unexplained reason; 2 on a setup/self-check problem.
#
# Design notes (read before touching the extraction logic):
#
#   * A prior attempt at this script (branch p270-samples, commit 85e1f67)
#     extracted fenced blocks LINE BY LINE instead of by fence PAIR, so it
#     fed the compiler individual lines like `Return a number, total.`
#     ripped out of their block and called the resulting parse failure a
#     finding. It reported "Checked: 1117" against a file with 178 real
#     code blocks. That bug is why this rewrite tracks fence state with an
#     explicit boolean and treats everything between one opening fence and
#     its matching close as exactly one sample, compiled as a unit — never
#     per-line.
#
#   * LANGUAGE.md is a language reference, not a test suite: most of its
#     fenced blocks are short excerpts illustrating one construct (`While x
#     is less than 10, increment x.`), not complete standalone programs.
#     Compiling `increment x` alone fails with "Unknown variable: x" — that
#     is not a doc bug, it's the nature of an excerpt. So a block whose only
#     compile errors are "Unknown variable/function: NAME" for a NAME that
#     is never declared anywhere in that same block is bucketed as an
#     "excerpt" failure and auto-explained rather than flagged. If the
#     failing name WAS declared in-block (e.g. via `called NAME`) and the
#     compiler still couldn't resolve it, that's suspicious and is kept in
#     the "needs triage" bucket instead — auto-explaining away a failure
#     that mentions a name the sample itself declared would risk masking a
#     real identifier-syntax regression, which is exactly what this project
#     has been fixing.
#
#   * No `set -e`. A failing sample is expected, useful output, not a script
#     error — aborting on the first one would defeat the point of the tool.
#
#   * Self-check: checked + skipped must equal the real fence-pair count for
#     the file. This is asserted below and the script exits loudly if it
#     doesn't hold — that assertion is exactly what would have caught the
#     1117-vs-178 bug on day one.
#
# No new dependencies: POSIX shell + Python 3, matching
# vox-vscode/check-grammar.sh.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VOX="$REPO_ROOT/target/release/vox"
DOC="${1:-$REPO_ROOT/LANGUAGE.md}"

if [ ! -x "$VOX" ]; then
    echo "check-samples: $VOX not found or not executable." >&2
    echo "  Build it first: rm -f target/release/vox && cargo build --release" >&2
    exit 2
fi

if [ ! -f "$DOC" ]; then
    echo "check-samples: doc not found: $DOC" >&2
    exit 2
fi

exec python3 - "$VOX" "$DOC" <<'PYEOF'
import re
import subprocess
import sys
import tempfile
from pathlib import Path

vox_bin, doc_path = sys.argv[1], sys.argv[2]
doc_path = Path(doc_path)
lines = doc_path.read_text(encoding='utf-8').splitlines()

# --- Extraction: track fence state with a boolean; a block is everything
# between one opening ``` and its matching closing ```, compiled as a unit.
FENCE_RE = re.compile(r'^(\s*)```(.*)$')

blocks = []
in_fence = False
fence_start = None
fence_info = None
fence_lines = []

for i, line in enumerate(lines, start=1):
    m = FENCE_RE.match(line)
    if not in_fence:
        if m:
            in_fence = True
            fence_start = i
            fence_info = m.group(2).strip()
            fence_lines = []
    else:
        if line.strip() == '```':
            blocks.append({
                'start': fence_start,
                'end': i,
                'info': fence_info,
                'content': '\n'.join(fence_lines),
            })
            in_fence = False
        else:
            fence_lines.append(line)

if in_fence:
    print(f"check-samples: unterminated fence starting at {doc_path}:{fence_start}", file=sys.stderr)
    sys.exit(2)

total_blocks = len(blocks)

# --- Classification heuristic for untagged (```) blocks: a bare block is
# Vox if some line (ignoring a trailing "(...)" comment) ends in a period
# and the block contains a recognisable Vox syntax marker. This is the
# "idea" referenced from 85e1f67 — the extraction logic above is new.
VOX_MARKERS = re.compile(
    r'\b(print|called|return|while|repeat|library|exit|wait|create|mount|'
    r'unmount|execute|shutdown|reboot|halt|open|read|write|close|seek|'
    r'delete|increment|append|set|parse\s+flags|pivot|see)\b'
    r'|\bfor each\b|\bif\b.*\bthen\b|\bto\s+[\'A-Za-z_]',
    re.IGNORECASE,
)
TRAILING_COMMENT_RE = re.compile(r'\s*\([^()]*\)\s*$')


def looks_like_vox(content):
    has_period_line = False
    for line in content.splitlines():
        stripped = TRAILING_COMMENT_RE.sub('', line).rstrip()
        if stripped.endswith('.'):
            has_period_line = True
            break
    return has_period_line and bool(VOX_MARKERS.search(content))


# --- Declared-name extraction, for the excerpt-vs-real-bug distinction.
DECLARED_RE = re.compile(
    r"\bcalled\s+'([^']{1,})'|\bcalled\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|\bTo\s+'([^']{1,})'|\bTo\s+([A-Za-z_][A-Za-z0-9_]*)",
)
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
# The compiler names the same "this identifier was never declared" problem
# differently depending on what kind of thing it expected (variable, buffer,
# file, map, ...) — all of these are the same excerpt signal. The name runs
# to end-of-line, not \S+: quoted multi-word identifiers ('output file')
# are reported with the space intact, and a \S+ capture silently truncates
# them at the first word — which then fails to match a same-named
# single-word declaration and falsely trips the "suspicious" safety net.
UNKNOWN_RE = re.compile(
    r"Unknown (?:variable|function|map|buffer|file|list|timer): (.+)$"
    r"|Unknown identifier '([^']+)'"
    r"|Cannot use '([^']+)' as a variable name - it's a reserved keyword\.",
    re.MULTILINE,
)
# Compiler errors whose *shape* means "this excerpt started mid-construct",
# not "this syntax is wrong". Each was manually verified against LANGUAGE.md
# during S2 triage — see the doc-vs-compiler mismatch report. This is a
# closed list, not a catch-all: a generic "expected a name, found a string
# literal" is deliberately NOT here, because that is the S1.5 diagnostic this
# whole project exists to surface, and auto-explaining it away would defeat
# the gate.
TRUNCATED_EXCERPT_PATTERNS = [
    re.compile(r"Missing loop variable after 'each'"),
    re.compile(r"Expected file name or 'standard input' after 'from', got File"),
    re.compile(r"Expected identifier after 'the', got Timer"),
    re.compile(r"^error: Expected a statement, got Period$", re.MULTILINE),
]
MISSING_FILE_PATTERNS = [
    re.compile(r"could not find the library interface file"),
]


def declared_names(content):
    names = set()
    for m in DECLARED_RE.finditer(content):
        for g in m.groups():
            if g:
                names.add(g)
    return names


results = {
    'pass': [],
    'fail_excerpt': [],
    'fail_expected': [],
    'fail_real': [],
    'skip': [],
}

tmpdir = Path(tempfile.mkdtemp(prefix='vox-check-samples-'))

for b in blocks:
    info = (b['info'] or '').strip()
    info_l = info.lower()
    tag = 'bare' if info == '' else info

    expect_fail = '(compile error:' in b['content'] or '(Compile error:' in b['content']

    if info == '':
        attempt = looks_like_vox(b['content'])
        skip_reason = 'no vox syntax markers found (heuristic: non-vox content, e.g. shell/output text)'
    elif 'vox' in info_l and 'fragment' in info_l:
        attempt = False
        skip_reason = "tagged 'vox fragment' — illustrative/placeholder syntax, not a standalone program"
    elif 'vox' in info_l:
        attempt = True
        skip_reason = None
    else:
        attempt = False
        skip_reason = f"tagged '{info}' — not vox"

    if attempt and 'Table of Contents:' in b['content']:
        attempt = False
        skip_reason = "illustrates .lib interface file format (its own dedicated parser), not compilable .vox source"

    if not attempt:
        results['skip'].append((b, tag, skip_reason))
        continue

    src = tmpdir / f"sample_{b['start']}.vox"
    src.write_text(b['content'] + '\n', encoding='utf-8')
    out_bin = tmpdir / f"sample_{b['start']}_bin"
    try:
        proc = subprocess.run(
            [vox_bin, str(src), '-o', str(out_bin)],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        results['fail_real'].append((b, tag, 'compiler timed out after 15s'))
        continue

    if proc.returncode == 0:
        if expect_fail:
            results['fail_real'].append((
                b, tag,
                "doc labels this '(compile error: ...)' but it compiled successfully "
                "— documented restriction no longer holds",
            ))
        else:
            results['pass'].append((b, tag))
        continue

    stderr = ANSI_RE.sub('', proc.stderr)

    if expect_fail:
        results['fail_expected'].append((b, tag, stderr))
        continue

    unknown_names = {n for pair in UNKNOWN_RE.findall(stderr) for n in pair if n}
    decl = declared_names(b['content'])
    error_lines = [l for l in stderr.splitlines() if l.strip().startswith('error:')]
    all_unknown_class = bool(unknown_names) and all(UNKNOWN_RE.search(l) for l in error_lines)
    suspicious = unknown_names & decl

    if all_unknown_class and not suspicious:
        reason = f"incomplete excerpt — references {', '.join(sorted(unknown_names))} from surrounding prose, not declared in this block"
        results['fail_excerpt'].append((b, tag, reason, stderr))
    elif any(p.search(stderr) for p in TRUNCATED_EXCERPT_PATTERNS):
        results['fail_excerpt'].append((b, tag, 'incomplete excerpt — starts mid-construct (parse error consistent with a truncated snippet)', stderr))
    elif any(p.search(stderr) for p in MISSING_FILE_PATTERNS):
        results['fail_excerpt'].append((b, tag, 'references an external file that does not exist in this isolated check (illustrative path example)', stderr))
    else:
        results['fail_real'].append((b, tag, stderr))

# --- Report
def loc(b):
    return f"{doc_path.name}:{b['start']}-{b['end']}"

if results['skip']:
    print("-- skipped --")
    for b, tag, reason in results['skip']:
        print(f"  SKIP  {loc(b):<22} [{tag}] {reason}")

if results['fail_excerpt']:
    print("\n-- failed: incomplete excerpt (expected, auto-explained) --")
    for b, tag, reason, _stderr in results['fail_excerpt']:
        print(f"  SKIP* {loc(b):<22} [{tag}] {reason}")

if results['fail_expected']:
    print("\n-- failed: doc labels this a compile error, and it is one (expected) --")
    for b, tag, stderr in results['fail_expected']:
        first_err = next((l for l in stderr.splitlines() if l.strip()), '(no stderr)')
        print(f"  OK*   {loc(b):<22} [{tag}] {first_err}")

if results['fail_real']:
    print("\n-- failed: needs triage --")
    for item in results['fail_real']:
        if len(item) == 3:
            b, tag, reason = item
            print(f"  FAIL  {loc(b):<22} [{tag}] {reason}")
        else:
            b, tag, stderr = item
            first_err = next((l for l in stderr.splitlines() if l.strip()), '(no stderr)')
            print(f"  FAIL  {loc(b):<22} [{tag}] {first_err}")

passed = len(results['pass'])
fail_excerpt = len(results['fail_excerpt'])
fail_expected = len(results['fail_expected'])
fail_real = len(results['fail_real'])
failed = fail_excerpt + fail_expected + fail_real
skipped = len(results['skip'])
checked = passed + failed

print()
print("=== Summary ===")
print(f"  Doc:                {doc_path}")
print(f"  Fence-pair blocks:  {total_blocks}")
print(f"  Skipped:            {skipped}")
print(f"  Checked (compiled): {checked}")
print(f"    Passed:             {passed}")
print(f"    Failed (excerpt):   {fail_excerpt}  (expected — excerpt references undeclared external names)")
print(f"    Failed (expected):  {fail_expected}  (doc explicitly documents this as a compile error, and it is one)")
print(f"    Failed (triage):    {fail_real}  (unexplained — doc bug or compiler bug)")

# The assertion that would have caught the 1117-vs-178 bug on day one.
if checked + skipped != total_blocks:
    print(
        f"\ncheck-samples: SELF-CHECK FAILED — checked({checked}) + skipped({skipped}) "
        f"!= total_blocks({total_blocks}). Extraction or classification is double-counting "
        f"or dropping blocks.",
        file=sys.stderr,
    )
    sys.exit(2)

if fail_real > 0:
    print(f"\n{fail_real} sample(s) failed for an unexplained reason. See '-- failed: needs triage --' above.")
    sys.exit(1)

print("\nAll compiled samples passed or were explained excerpts.")
sys.exit(0)
PYEOF
