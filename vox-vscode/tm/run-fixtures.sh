#!/usr/bin/env bash
#
# run-fixtures.sh — tokenize every fixture under fixtures/ with the real
# TextMate engine and diff against the committed .expected.txt. Fails on
# drift, so a grammar change that silently changes highlighting is caught.
#
#   ./run-fixtures.sh            # check (diff against committed expected)
#   ./run-fixtures.sh --update    # overwrite the committed expected output
#
# node_modules must be installed first:  npm install   (in this directory)
set -euo pipefail

cd "$(dirname "$0")"
GRAMMAR="../syntaxes/vox.tmLanguage.json"
update=false
[ "${1:-}" = "--update" ] && update=true

if [ ! -d node_modules ]; then
  echo "run-fixtures: node_modules missing — run 'npm install' in $(pwd)" >&2
  exit 2
fi

status=0
for vox in fixtures/*.vox; do
  base="${vox%.vox}"
  expected="${base}.expected.txt"
  if $update; then
    node tokenize.js "$GRAMMAR" "$vox" > "$expected"
    echo "updated $expected"
    continue
  fi
  if [ ! -f "$expected" ]; then
    echo "run-fixtures: $expected missing — run with --update to create it" >&2
    status=1
    continue
  fi
  if diff -u "$expected" <(node tokenize.js "$GRAMMAR" "$vox"); then
    echo "ok: $vox"
  else
    echo "FAIL: $vox drifted from $expected" >&2
    status=1
  fi
done
exit $status