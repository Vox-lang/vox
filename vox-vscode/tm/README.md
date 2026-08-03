# vox-vscode/tm — real-engine grammar tokenizer

Verification, not simulation. `vscode-textmate` + `vscode-oniguruma` are exactly
what VS Code runs internally, so the scopes printed here are the scopes the
editor applies. This harness exists because `/tmp` has been wiped twice on this
machine and took the only copy with it.

## One-time setup

```sh
cd vox-vscode/tm
npm install
```

`node_modules/` is gitignored; install deps locally.

## Usage

```sh
# Tokenize one file, print every token and its scope:
node tokenize.js ../syntaxes/vox.tmLanguage.json path/to/file.vox

# Or a one-line summary (scopes applied + unscoped words):
node tokenize.js ../syntaxes/vox.tmLanguage.json path/to/file.vox --summary
```

## Drift check

```sh
./run-fixtures.sh            # diff each fixture against its committed .expected.txt
./run-fixtures.sh --update   # overwrite the committed expected output
```

`fixtures/*.vox` are canonical samples (the cases the grammar must get right);
`fixtures/*.expected.txt` is the real tokenizer's output, committed so a
grammar change that silently shifts highlighting is caught in review.