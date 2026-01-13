# English Compiler - VSCode Extension

Syntax highlighting for the English programming language (`.en` files).

## Features

- **Syntax highlighting** for all English language constructs
- **Comment support** - parenthetical comments `(like this)`
- **Auto-closing pairs** for brackets, parentheses, and quotes
- **Code folding** for function definitions
- **Creative highlighting** for unique English constructs like `each` (loop expansion) and `but` (conditional branching)

## Highlighted Elements

| Element | Example | Color |
|---------|---------|-------|
| `each` keyword | `print each number from 1 to 10` | **Teal + Bold** |
| `but` keyword | `but if x is true` | **Pink + Bold** |
| Control keywords | `If`, `While`, `For`, `Return` | Purple |
| Action keywords | `Print`, `Set`, `Create` | Purple |
| Types | `number`, `text`, `boolean`, `buffer` | Teal |
| Strings | `"Hello, World!"` | Green |
| Numbers | `42`, `3.14` | Orange |
| Booleans | `true`, `false` | Blue |
| Comments | `(this is a comment)` | Gray/Italic |
| Function definitions | `To "function name"` | Yellow + Bold |
| Function calls | `"function" of x` | Yellow |
| I/O keywords | `Open`, `Read`, `Write`, `Close` | Yellow |
| Properties | `x's absolute`, `buf's size` | Light Blue |
| Articles | `a`, `an`, `the`, `called` | Gray (dimmed) |

---

## Installation (Before Marketplace Release)

### Option 1: Symlink (Recommended for Development)

**Linux/macOS:**
```bash
# For VSCode
ln -s /path/to/ec/ec-vscode ~/.vscode/extensions/ec-english

# For Windsurf
ln -s /path/to/ec/ec-vscode ~/.windsurf/extensions/ec-english

# For Cursor
ln -s /path/to/ec/ec-vscode ~/.cursor/extensions/ec-english
```

**Windows (PowerShell as Admin):**
```powershell
# For VSCode
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.vscode\extensions\ec-english" -Target "C:\path\to\ec\ec-vscode"

# For Windsurf
New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.windsurf\extensions\ec-english" -Target "C:\path\to\ec\ec-vscode"
```

Then **reload your editor** (`Ctrl+Shift+P` → "Reload Window").

### Option 2: Copy the Folder

Simply copy the `ec-vscode` folder to your extensions directory:

| Editor | Extensions Directory |
|--------|---------------------|
| VSCode (Linux) | `~/.vscode/extensions/` |
| VSCode (macOS) | `~/.vscode/extensions/` |
| VSCode (Windows) | `%USERPROFILE%\.vscode\extensions\` |
| Windsurf | `~/.windsurf/extensions/` |
| Cursor | `~/.cursor/extensions/` |

Rename the copied folder to `ec-english`.

### Option 3: Build and Install VSIX Package

```bash
# Install vsce (VS Code Extension manager)
npm install -g @vscode/vsce

# Navigate to extension directory
cd ec-vscode

# Package the extension
vsce package

# Install the generated .vsix file
code --install-extension ec-english-0.1.0.vsix
# Or for Windsurf:
windsurf --install-extension ec-english-0.1.0.vsix
```

---

## Verifying Installation

1. Open any `.en` file
2. Check the language mode in the bottom-right corner of the editor - it should say "English"
3. If it says "Plain Text", click it and select "English" from the list

---

## Troubleshooting

**Highlighting not working?**
- Reload the editor window (`Ctrl+Shift+P` → "Reload Window")
- Check that the extension folder is named correctly in the extensions directory
- Verify the `.en` file extension is associated with the "English" language

**Colors look different than expected?**
- The extension provides default colors, but your theme may override them
- Colors are defined in `package.json` under `configurationDefaults`

---

## File Structure

```
ec-vscode/
├── package.json                 # Extension manifest + color customizations
├── language-configuration.json  # Brackets, comments, folding
├── syntaxes/
│   └── english.tmLanguage.json  # TextMate grammar (token rules)
└── README.md                    # This file
```

---

## Usage

Once installed, simply open any `.en` file and syntax highlighting will be applied automatically.

## License

MIT
