# Vox - VSCode Extension

> **Syntax highlighting for Vox (sentence based code)**

Vox is a systems-level programming language with natural language syntax. This extension provides rich syntax highlighting for `.vx`, `.vox`, `.en` and `.eng` files.
## Installation

This extension is available on the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=vox.vox). Simply search for "Vox" in the Extensions panel and click Install.

Or see [Manual Installation](#installation-before-marketplace-release) below.

## Features

- **Full syntax highlighting** for all Vox language constructs
- **Comment support** — parenthetical comments `(like this)` with nesting
- **Auto-closing pairs** for brackets, parentheses, and quotes
- **Code folding** for function definitions
- **Format string interpolation** — `{variable}` inside strings gets distinct highlighting
- **Special highlighting** for unique Vox constructs:
  - `each` (loop expansion) — teal + bold
  - `but` (conditional branching) — pink + bold

## Highlighted Elements

| Element | Example | Color |
|---------|---------|-------|
| `each` keyword | `print each number from 1 to 10` | **Teal + Bold** |
| `but` keyword | `but if x is true` | **Pink + Bold** |
| Format interpolation | `"Hello {name}!"` → `name` | **Yellow + Bold** |
| Control keywords | `If`, `While`, `For`, `Return` | Purple |
| Action keywords | `Print`, `Set`, `Create`, `treating`, `as` | Purple |
| Types | `number`, `text`, `boolean`, `buffer`, `float`, `list` | Teal |
| Strings | `"Hello, World!"` | Green |
| Numbers | `42`, `3.14`, `-5` | Orange |
| Booleans | `true`, `false` | Blue |
| Comments | `(this is a comment)` | Gray/Italic |
| Function definitions | `To "function name"` | Yellow + Bold |
| Function calls | `"function" of x` | Yellow |
| I/O keywords | `Open`, `Read`, `Write`, `Close` | Light Green |
| Properties | `x's absolute`, `buf's size` | Light Blue |
| Articles | `a`, `an`, `the`, `called` | Gray (dimmed) |

---

## Installation (Before Marketplace Release)

### Option 1: Symlink (Recommended for Development)

**Linux/macOS:**
```bash
# For VSCode
ln -s /path/to/vox/vox-vscode ~/.vscode/extensions/vox

# For Windsurf
ln -s /path/to/vox/vox-vscode ~/.windsurf/extensions/vox

# For Cursor
ln -s /path/to/vox/vox-vscode ~/.cursor/extensions/vox
```

**Windows (PowerShell as Admin):**
```powershell
# For VSCode
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.vscode\extensions\vox" -Target "C:\path\to\vox\vox-vscode"

# For Windsurf
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.windsurf\extensions\vox" -Target "C:\path\to\vox\vox-vscode"
```

Then **reload your editor** (`Ctrl+Shift+P` → "Reload Window").

### Option 2: Copy the Folder

Simply copy the `vox-vscode` folder to your extensions directory:

| Editor | Extensions Directory |
|--------|---------------------|
| VSCode (Linux) | `~/.vscode/extensions/` |
| VSCode (macOS) | `~/.vscode/extensions/` |
| VSCode (Windows) | `%USERPROFILE%\.vscode\extensions\` |
| Windsurf | `~/.windsurf/extensions/` |
| Cursor | `~/.cursor/extensions/` |

Rename the copied folder to `vox`.

### Option 3: Build and Install VSIX Package

```bash
# Install vsce (VS Code Extension manager)
npm install -g @vscode/vsce

# Navigate to extension directory
cd vox-vscode

# Package the extension
vsce package

# Install the generated .vsix file
code --install-extension vox-0.1.0.vsix
# Or for Windsurf:
windsurf --install-extension vox-0.1.0.vsix
```

---

## Verifying Installation

1. Open any `.vox` file
2. Check the language mode in the bottom-right corner of the editor - it should say "Vox"
3. If it says "Plain Text", click it and select "Vox" from the list

---

## Troubleshooting

**Highlighting not working?**
- Reload the editor window (`Ctrl+Shift+P` → "Reload Window")
- Check that the extension folder is named correctly in the extensions directory
- Verify the `.vox` file extension is associated with the "Vox" language

**Colors look different than expected?**
- The extension provides default colors, but your theme may override them
- Colors are defined in `package.json` under `configurationDefaults`

---

## File Structure

```
vox-vscode/
├── setup.sh                     # Auto-setup script for new developers
├── package.json                 # Extension manifest + color customizations
├── language-configuration.json  # Brackets, comments, folding
├── syntaxes/
│   └── english.tmLanguage.json  # TextMate grammar (token rules)
└── README.md                    # This file
```

---

## Usage

Once installed, simply open any `.vox` or `.en` file and syntax highlighting will be applied automatically.

The language will appear as **"Vox"** in the language picker.

## Contributing

The grammar is defined in `syntaxes/english.tmLanguage.json` using TextMate patterns.
Color customizations are in `package.json` under `configurationDefaults.editor.tokenColorCustomizations`.

## License

MIT
