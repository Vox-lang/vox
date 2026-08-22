# Vox — VS Code Extension

> **Syntax highlighting for Vox (sentence-based code)**

[Vox](https://github.com/vox-lang/vox) is a systems-level programming language with a constrained, sentence-based English syntax. This extension provides syntax highlighting, bracket/comment configuration, and code folding for `.vox` files.

Website and full language reference: **[vox-lang.dev](https://vox-lang.dev)** — the browsable manual is at [vox-lang.dev/docs/](https://vox-lang.dev/docs/), generated from the compiler's `LANGUAGE.md`.

## Installation

The extension is published on the [Open VSX Marketplace](https://open-vsx.org/extension/vox-lang/vox) (VS Code, Windsurf, Cursor, and other compatible editors) and the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=vox-lang.vox-lang) (VS Code). Search for "Vox" in your editor's Extensions panel and click Install.

For manual installation during development, see [Manual Installation](#manual-installation) below.

## Features

- **Syntax highlighting** for Vox language constructs.
- **Comment support** — parenthetical comments `(like this)` with nesting.
- **Auto-closing pairs** for brackets, parentheses, and quotes.
- **Code folding** for function definitions and block constructs.
- **Format-string interpolation** — `{variable}` inside double-quoted strings gets distinct highlighting.
- **Distinct colors** for unique Vox constructs:
  - `each` (loop expansion)
  - `but` (conditional branching)

## Supported File Extensions

| Extension | Associated language |
|-----------|---------------------|
| `.vox`    | Vox                 |

The extension also registers the aliases `Vox`, `vox`, `VoxLang`, and `voxlang` for the language picker.

## Highlighted Elements

| Element                  | Example Vox syntax                                  | Scope token                              |
|--------------------------|-----------------------------------------------------|------------------------------------------|
| `each` keyword           | `Open ... at each filename from arguments's all`    | `entity.name.tag.each.vox`               |
| `but` keyword            | `but if x is greater than 10 then, ...`             | `support.type.vox`                       |
| Format interpolation     | `"Hello {name}!"`                                   | `variable.other.interpolation.vox`       |
| Control keywords         | `If`, `While`, `For`, `Return`, `Otherwise`, `then` | `keyword.control.vox`                    |
| Action keywords          | `Print`, `Set`, `Create`, `Append`, `Increment`     | `keyword.other.vox`                      |
| Import keywords          | `see`, `library`, `version`, `from`                 | `keyword.control.import.vox`             |
| I/O keywords             | `Open`, `Read`, `Write`, `Close`                    | `support.function.vox`                   |
| Types                    | `number`, `text`, `boolean`, `buffer`, `float`      | `storage.type.vox`                       |
| Strings                  | `"Hello, World!"`                                     | `string.quoted.double.vox`               |
| Numbers                  | `42`, `3.14`, `-5`, `0xFF`, `0b1010`                | `constant.numeric.*.vox`                 |
| Booleans                 | `true`, `false`                                     | `constant.language.boolean.vox`          |
| Null literal             | `nothing`                                           | `constant.language.null.vox`             |
| Comments                 | `(this is a comment)`                               | `comment.block.vox`                      |
| Function definitions     | `To 'add two numbers'`                                | `entity.name.function.definition.vox`    |
| Function calls           | `'add two numbers' of 3 and 4`                      | `entity.name.function.call.vox`          |
| Properties               | `buf's length`, `arguments's all`                   | `variable.other.property.vox`          |
| Articles / particles     | `a`, `an`, `the`, `called`, `of`, `from`            | `punctuation.definition.vox`             |

Colors are provided as defaults in `package.json` under `contributes.configurationDefaults.editor.tokenColorCustomizations`. Your theme may override them.

---

## Manual Installation

### Option 1: Symlink (Recommended for Development)

**Linux / macOS:**
```bash
# VS Code
ln -s /path/to/vox/vox-vscode ~/.vscode/extensions/vox

# Windsurf
ln -s /path/to/vox/vox-vscode ~/.windsurf/extensions/vox

# Cursor
ln -s /path/to/vox/vox-vscode ~/.cursor/extensions/vox
```

**Windows (PowerShell as Admin):**
```powershell
# VS Code
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.vscode\extensions\vox" -Target "C:\path\to\vox\vox-vscode"

# Windsurf
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.windsurf\extensions\vox" -Target "C:\path\to\vox\vox-vscode"
```

Then reload your editor (`Ctrl+Shift+P` → "Reload Window").

### Option 2: Copy the Folder

Copy the `vox-vscode` folder to your editor's extensions directory and rename it to `vox`:

| Editor           | Extensions directory                        |
|------------------|---------------------------------------------|
| VS Code (Linux)  | `~/.vscode/extensions/`                     |
| VS Code (macOS)  | `~/.vscode/extensions/`                     |
| VS Code (Windows)| `%USERPROFILE%\.vscode\extensions\`          |
| Windsurf         | `~/.windsurf/extensions/`                   |
| Cursor           | `~/.cursor/extensions/`                     |

### Option 3: Build and Install a VSIX Package

```bash
# Install vsce (VS Code Extension manager)
npm install -g @vscode/vsce

# Navigate to the extension directory
cd vox-vscode

# Package the extension
vsce package

# Install the generated .vsix file (replace <version> with the version shown in package.json)
code --install-extension vox-<version>.vsix
# Or for Windsurf:
windsurf --install-extension vox-<version>.vsix
```

---

## Verifying Installation

1. Open any `.vox` file.
2. Check the language mode in the bottom-right corner — it should say **Vox**.
3. If it says **Plain Text**, click it and select **Vox** from the list.

---

## Troubleshooting

**Highlighting not working?**
- Reload the editor window (`Ctrl+Shift+P` → "Reload Window").
- Check that the extension folder is named `vox` in the extensions directory.
- Verify the `.vox` file extension is associated with the **Vox** language.

**Colors look different than expected?**
- The extension provides default token colors in `package.json`.
- Your color theme may override these defaults.

---

## File Structure

```
vox-vscode/
├── check-grammar.sh             # Drift checker: lexer keywords vs. grammar
├── language-configuration.json  # Brackets, comments, folding rules
├── package.json                 # Extension manifest and default token colors
├── setup.sh                     # Auto-setup script for new developers
├── syntaxes/
│   └── vox.tmLanguage.json      # TextMate grammar (token rules)
├── tm/                          # Real-engine tokenizer test harness
│   ├── run-fixtures.sh          # Run fixture-based grammar regression tests
│   ├── tokenize.js              # Tokenize a .vox file with vscode-textmate
│   └── fixtures/                # Canonical .vox samples and expected scopes
├── images/
│   └── icon.png                 # Extension icon
├── LICENSE                      # MIT
└── README.md                    # This file
```

---

## Contributing

- The grammar is defined in `syntaxes/vox.tmLanguage.json` using TextMate patterns.
- Default token colors live in `package.json` under `contributes.configurationDefaults.editor.tokenColorCustomizations`.
- The `tm/` harness uses the same `vscode-textmate` / `vscode-oniguruma` engines as VS Code itself, so the fixtures show the exact scopes the editor will apply.

To run the grammar fixtures:

```bash
cd vox-vscode/tm
npm install
./run-fixtures.sh
```

To update expected fixture output after an intentional grammar change:

```bash
./run-fixtures.sh --update
```

## License

MIT
