// Tokenize a .vox file with the real VS Code TextMate engine.
//
// vscode-textmate + vscode-oniguruma are exactly what VS Code uses internally,
// so the scopes printed here are the scopes the editor would apply. This is
// verification, not simulation.
//
//   node tokenize.js <grammar.json> <file.vox> [--summary]
//
// The grammar is committed at ../syntaxes/vox.tmLanguage.json. Run from this
// directory, or pass an explicit grammar path. The oniguruma WASM is loaded
// from ./node_modules/vscode-oniguruma/release/onig.wasm.
const fs = require('fs');
const path = require('path');
const vsctm = require('vscode-textmate');
const oniguruma = require('vscode-oniguruma');

const [, , grammarPath, filePath, ...flags] = process.argv;
const summary = flags.includes('--summary');

if (!grammarPath || !filePath) {
  console.error('usage: node tokenize.js <grammar.json> <file.vox> [--summary]');
  process.exit(2);
}

const wasmBin = fs.readFileSync(
  path.join(__dirname, 'node_modules/vscode-oniguruma/release/onig.wasm')
).buffer;

const vscodeOnigurumaLib = oniguruma.loadWASM(wasmBin).then(() => ({
  createOnigScanner: (s) => new oniguruma.OnigScanner(s),
  createOnigString: (s) => new oniguruma.OnigString(s),
}));

const registry = new vsctm.Registry({
  onigLib: vscodeOnigurumaLib,
  loadGrammar: () =>
    Promise.resolve(
      vsctm.parseRawGrammar(fs.readFileSync(grammarPath, 'utf8'), grammarPath)
    ),
});

(async () => {
  const grammar = await registry.loadGrammar('source.vox');
  if (!grammar) {
    console.error('FAILED to load grammar — invalid, or scopeName is not source.vox');
    process.exit(2);
  }
  const text = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  let ruleStack = vsctm.INITIAL;
  const unscoped = new Set();
  const scoped = new Map();

  for (let i = 0; i < text.length; i++) {
    const line = text[i];
    const r = grammar.tokenizeLine(line, ruleStack);
    for (const tok of r.tokens) {
      const frag = line.substring(tok.startIndex, tok.endIndex);
      if (!frag.trim()) continue;
      // scopes[0] is always the root source.vox; anything more is real highlighting
      const specific = tok.scopes.filter((s) => s !== 'source.vox');
      if (specific.length === 0) {
        if (/[A-Za-z]/.test(frag)) unscoped.add(frag.trim());
      } else {
        const key = specific[specific.length - 1];
        if (!scoped.has(key)) scoped.set(key, new Set());
        scoped.get(key).add(frag.trim());
      }
      if (!summary) {
        console.log(
          `${String(i + 1).padStart(3)}: ${JSON.stringify(frag)}  ->  ${
            specific.join(' ') || '(none)'
          }`
        );
      }
    }
    ruleStack = r.ruleStack;
  }

  if (summary) {
    console.log(`\n=== scopes applied in ${path.basename(filePath)} ===`);
    for (const [k, v] of [...scoped].sort()) {
      console.log(`  ${k.padEnd(42)} ${[...v].slice(0, 8).join(', ')}`);
    }
    console.log(`\n=== words with NO scope (${unscoped.size}) ===`);
    console.log('  ' + [...unscoped].sort().join(' '));
  }
})();