mod lexer;
mod parser;
mod analyzer;
mod codegen;
mod errors;
#[cfg(test)]
mod compile_fail_tests;

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

use lexer::Lexer;
use parser::Parser;
use parser::ast::{Program, Statement};
use analyzer::Analyzer;
use codegen::CodeGenerator;

/// Find the coreasm library directory using industry-standard resolution order:
/// 1. EC_CORE_PATH environment variable (user override)
/// 2. XDG config file (~/.config/vox/config)
/// 3. System paths (/usr/local/share/vox, /usr/share/vox)
/// 4. Executable-relative paths (for portable installs)
/// 5. Current working directory fallback (for development)
fn find_coreasm_path() -> Option<PathBuf> {
    // 1. Environment variable - highest priority
    if let Ok(core_path) = env::var("EC_CORE_PATH") {
        let path = PathBuf::from(&core_path);
        if path.exists() {
            return Some(path);
        }
        // Also check for coreasm subdirectory
        let coreasm = path.join("coreasm");
        if coreasm.exists() {
            return Some(coreasm);
        }
    }
    
    // 2. XDG config file (~/.config/vox/config)
    if let Some(config_path) = get_config_lib_path() {
        if config_path.exists() {
            return Some(config_path);
        }
    }
    
    // 3. System paths (Unix standard locations)
    let system_paths = [
        "/usr/local/share/vox/coreasm",
        "/usr/share/vox/coreasm",
        "/opt/vox/coreasm",
    ];
    for path in &system_paths {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }
    
    // 4. Executable-relative (walk up from exe to find coreasm/)
    if let Ok(exe) = env::current_exe() {
        let mut dir = exe.parent();
        while let Some(d) = dir {
            let candidate = d.join("coreasm");
            if candidate.exists() {
                return Some(candidate);
            }
            dir = d.parent();
        }
    }
    
    // 5. Current working directory fallback
    let cwd_coreasm = PathBuf::from("coreasm");
    if cwd_coreasm.exists() {
        return Some(cwd_coreasm);
    }
    
    None
}

/// Read lib_path from XDG config file
fn get_config_lib_path() -> Option<PathBuf> {
    // XDG Base Directory: ~/.config/vox/config
    let config_dir = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            env::var("HOME")
                .map(|h| PathBuf::from(h).join(".config"))
                .unwrap_or_default()
        });
    
    let config_file = config_dir.join("ec").join("config");
    
    if let Ok(file) = fs::File::open(&config_file) {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(value) = line.strip_prefix("core_path=") {
                let path = PathBuf::from(value.trim());
                let coreasm = if path.ends_with("coreasm") {
                    path
                } else {
                    path.join("coreasm")
                };
                return Some(coreasm);
            }
        }
    }
    
    None
}

/// Track included files to prevent circular dependencies
fn process_includes(
    program: &mut parser::ast::Program,
    base_path: &Path,
    included: &mut HashSet<PathBuf>,
    verbose: bool,
) {
    let mut new_statements = Vec::new();
    
    for stmt in program.statements.drain(..) {
        if let Statement::See { ref path, .. } = stmt {
            // Resolve path relative to current file
            let include_path = if path.starts_with("./") || path.starts_with("../") {
                base_path.parent().unwrap_or(Path::new(".")).join(path)
            } else if path.starts_with('/') {
                PathBuf::from(path)
            } else {
                // Check system library path first
                let system_path = PathBuf::from("/usr/share/vox/lib").join(path);
                if system_path.exists() {
                    system_path
                } else {
                    base_path.parent().unwrap_or(Path::new(".")).join(path)
                }
            };
            
            let canonical = include_path.canonicalize().unwrap_or(include_path.clone());
            
            // Skip if already included (prevents circular dependencies)
            if included.contains(&canonical) {
                if verbose {
                    println!("Skipping already included: {}", path);
                }
                new_statements.push(stmt);
                continue;
            }
            
            // Only inline Vox source (not .so libraries). A `see` of a source
            // file splices its statements in here, before compilation.
            if path.ends_with(".vox") {
                if let Ok(source) = fs::read_to_string(&include_path) {
                    if verbose {
                        println!("Including: {}", include_path.display());
                    }
                    
                    included.insert(canonical);
                    
                    let mut lexer = Lexer::new(&source);
                    let tokens = lexer.tokenize();
                    let mut parser = Parser::new(tokens);
                    
                    if let Ok(mut included_program) = parser.parse() {
                        // Recursively process includes in the included file
                        process_includes(&mut included_program, &include_path, included, verbose);
                        
                        // Add included statements (replaces the see statement)
                        new_statements.extend(included_program.statements);
                    } else if verbose {
                        eprintln!("Warning: Failed to parse {}", include_path.display());
                    }
                } else if verbose {
                    eprintln!("Warning: Could not read file: {}", include_path.display());
                }
                // Don't keep the see statement for source files - content is inlined
            } else {
                // Keep the see statement for .so files as a marker
                new_statements.push(stmt);
            }
        } else {
            new_statements.push(stmt);
        }
    }
    
    program.statements = new_statements;
}

fn show_version() {
    eprintln!("vox v{} By Josjuar Lister 2026", env!("CARGO_PKG_VERSION"));
}

fn show_help() {
    eprintln!("Usage: vox <source.vox> [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --emit-asm       Output assembly only (don't assemble/link)");
    eprintln!("  --keep-asm       Keep assembly file after linking");
    eprintln!("  --run            Compile and run the program");
    eprintln!("  --shared         Build a shared library (.so) instead of executable");
    eprintln!("  --link <libs>    Link against shared libraries (comma-separated)");
    eprintln!("  --lib-path <paths>  Additional library search paths (comma-separated)");
    eprintln!("  --target <arch>   Target architecture (default: x86_64)");
    eprintln!("  -o <file>        Output file name");
    eprintln!("  -v | --verbose   Verbose output");
    eprintln!("  -h | --help           Show help");
    eprintln!("  -V | --version        Show version");
    eprintln!();
    show_version();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        show_help();
        std::process::exit(1);
    }

    // Check for help/version flags before treating first arg as source file
    if args.len() == 2 {
        match args[1].as_str() {
            "--help" | "-h" => {
                show_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                show_version();
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let mut source_paths: Vec<String> = Vec::new();
    let mut emit_asm_only = false;
    let mut keep_asm = false;
    let mut run_after = false;
    let mut build_shared = false;
    let mut output_name = None;
    let mut verbose = false;
    let mut link_libs: Vec<String> = Vec::new();
    let mut lib_paths: Vec<String> = Vec::new();
    let mut target_arch = option_env!("TARGET_ARCH").unwrap_or("x86_64").to_string();

    // Any positional argument that is not a recognised flag (and not the value
    // consumed by -o/--link/--lib-path/--target) is a source file. This accepts
    // one or several: `vox a.vox --shared -o lib.so` (single, as today) and
    // `vox a.vox b.vox --shared -o lib.so` (plan 230 stage A2: several libraries
    // linked into one .so in a single link step).
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                show_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                show_version();
                std::process::exit(0);
            }
            "--emit-asm" => emit_asm_only = true,
            "--keep-asm" => keep_asm = true,
            "--run" => run_after = true,
            "--shared" => build_shared = true,
            "--verbose" | "-v" => verbose = true,
            "-o" => {
                i += 1;
                if i < args.len() {
                    output_name = Some(args[i].clone());
                }
            }
            "--link" => {
                i += 1;
                if i < args.len() {
                    link_libs.extend(args[i].split(',').map(|s| s.trim().to_string()));
                }
            }
            "--lib-path" => {
                i += 1;
                if i < args.len() {
                    lib_paths.extend(args[i].split(',').map(|s| s.trim().to_string()));
                }
            }
            "--target" => {
                i += 1;
                if i < args.len() {
                    target_arch = args[i].clone();
                }
            }
            _ => {
                // A positional argument: a source file. The old loop started at
                // index 2 and silently dropped any extra positional args (the
                // `_ => {}` arm), so `vox a.vox b.vox --shared` quietly lost
                // `b.vox`. Collecting them here is what makes multi-input work.
                source_paths.push(args[i].clone());
            }
        }
        i += 1;
    }

    if source_paths.is_empty() {
        show_help();
        std::process::exit(1);
    }

    // Multi-input is --shared only. Two `main`-equivalents in one executable
    // has no meaning, and silently picking one would be the worst outcome; a
    // shared build is the one place several sources combine into one output.
    if source_paths.len() > 1 && !build_shared {
        eprintln!(
            "Multiple source files ({}) are only valid with --shared, which links \
             them into one library in a single link step. An executable build takes \
             a single source — pass --shared, or compile each source separately.",
            source_paths.join(", ")
        );
        std::process::exit(1);
    }

    let first_source = source_paths[0].clone();

    // Parse each source independently, then concatenate the statements into
    // ONE compilation unit so the coreasm runtime is emitted once and shared by
    // every library in the .so (plan 230 stage A2's design: one resource table,
    // one .fini_array, one idempotent _cleanup_all — never a runtime per input).
    // Each input is lexed/parsed on its own so a parse error names its own file
    // and a `see` of a .vox resolves relative to that file's directory.
    let mut combined_statements: Vec<Statement> = Vec::new();
    // (library, version, filename) per input, to reject duplicate identities.
    let mut identities: Vec<(String, String, String)> = Vec::new();
    for source_path in &source_paths {
        let source = match fs::read_to_string(source_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading file '{}': {}", source_path, e);
                std::process::exit(1);
            }
        };

        if verbose {
            println!("Compiling {}...", source_path);
        }

        let mut lexer = Lexer::new(&source);
        let tokens = lexer.tokenize();

        let mut parser = Parser::new(tokens).with_source(source_path, &source);
        let mut program = match parser.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        };

        // Process includes (see statements) with circular dependency tracking,
        // relative to this input's directory.
        let source_path_buf = PathBuf::from(source_path);
        let mut included_files = HashSet::new();
        included_files.insert(
            source_path_buf
                .canonicalize()
                .unwrap_or(source_path_buf.clone()),
        );
        process_includes(&mut program, &source_path_buf, &mut included_files, verbose);

        // Multi-input --shared: every input must carry its own `Library`
        // declaration (its symbols are mangled by it), and no two inputs may
        // claim the same <library, version> — the second would silently
        // overwrite the first's signatures, the wrong-code bug A1 found. This
        // is a property of the inputs, not the program, so it is checked here
        // in the driver where both filenames are in hand (the analyzer sees one
        // concatenated unit and has no filenames).
        if build_shared && source_paths.len() > 1 {
            let identity = program.statements.iter().find_map(|s| {
                if let Statement::LibraryDecl { name, version } = s {
                    Some((name.clone(), version.clone()))
                } else {
                    None
                }
            });
            match identity {
                Some((lib, ver)) => {
                    if let Some((_, prev_file)) = identities.iter().find_map(|(l, v, f)| {
                        if l == &lib && v == &ver {
                            Some(((), f.clone()))
                        } else {
                            None
                        }
                    }) {
                        eprintln!(
                            "Duplicate library identity: '{}' and '{}' both declare \
                             Library \"{}\" version \"{}\". Two sources linked into one .so \
                             must each name a distinct library and version, or the second's \
                             signatures silently overwrite the first's. Rename one.",
                            prev_file, source_path, lib, ver
                        );
                        std::process::exit(1);
                    }
                    identities.push((lib, ver, source_path.clone()));
                }
                None => {
                    eprintln!(
                        "'{}' has no `Library` declaration. A source linked into a shared \
                         library alongside others must declare its identity — \
                         `Library \"name\" version \"x.y\".` — so its symbols are mangled \
                         apart from the other libraries' and a `.lib` can be written for it. \
                         Add one before the function definitions.",
                        source_path
                    );
                    std::process::exit(1);
                }
            }
        }

        combined_statements.extend(program.statements);
    }

    // One Program for the whole .so. `Program::new` defaults every uses_* flag
    // to false; the single analyze pass below sets them from the combined
    // statement list, so the runtime include block reflects what every library
    // in the .so actually needs (and is emitted once).
    let mut program = Program::new(combined_statements);

    // The analyzer locates errors by text search in one source file (plan 210
    // P3 — the Statement AST carries no span). For a multi-input build that is
    // the first file; a symbol in a later library may mislocate, but a
    // spanned AST is the separate work that fixes it. Single-input builds are
    // unchanged: the same source, the same content, as today.
    let first_source_content = fs::read_to_string(&first_source).unwrap_or_default();
    let mut analyzer = Analyzer::new()
        .with_source(&first_source, &first_source_content)
        .with_shared_mode(build_shared);
    analyzer.analyze(&mut program);

    if !analyzer.errors.is_empty() {
        for err in &analyzer.errors {
            eprintln!("{}", err);
        }
        std::process::exit(1);
    }

    let mut codegen = CodeGenerator::new();
    codegen.set_shared_lib_mode(build_shared);
    codegen.set_target_arch(&target_arch);
    let assembly = codegen.generate(&program);
    
    let base_name = Path::new(&first_source)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    
    let asm_path = format!("{}.asm", base_name);
    let obj_path = format!("{}.o", base_name);
    let output_path = output_name.unwrap_or_else(|| {
        if build_shared {
            format!("lib{}.so", base_name)
        } else {
            base_name.to_string()
        }
    });
    
    if let Err(e) = fs::write(&asm_path, &assembly) {
        eprintln!("Error writing assembly: {}", e);
        std::process::exit(1);
    }
    if verbose {
        println!("Generated {}", asm_path);
    }
    
    if emit_asm_only {
        return;
    }
    
    // Find coreasm library using standard resolution order
    // The ASM uses %include "coreasm/core.asm", so we need the parent directory
    let coreasm_include = match find_coreasm_path() {
        Some(path) => {
            // Get parent directory since ASM includes "coreasm/..." paths
            if let Some(parent) = path.parent() {
                format!("-I{}/", parent.display())
            } else {
                format!("-I{}/", path.display())
            }
        }
        None => {
            eprintln!("Warning: coreasm library not found. Set EC_CORE_PATH or install to /usr/local/share/vox/");
            "-I./".to_string()
        }
    };
    
    if verbose {
        println!("Assembling...");
    }
    
    // For shared libraries, we need position-independent code
    let nasm_args = if build_shared {
        vec!["-f", "elf64", "-DPIC", &coreasm_include, "-o", &obj_path, &asm_path]
    } else {
        vec!["-f", "elf64", &coreasm_include, "-o", &obj_path, &asm_path]
    };
    
    let nasm_result = Command::new("nasm")
        .args(&nasm_args)
        .status();
    
    match nasm_result {
        Ok(status) if status.success() => {}
        Ok(_) => {
            eprintln!("NASM assembly failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to run NASM: {}", e);
            eprintln!("Make sure NASM is installed: sudo apt install nasm");
            std::process::exit(1);
        }
    }
    
    if verbose {
        println!("Linking...");
    }
    
    // The version script is a pure implementation detail the user never asked
    // to see, so it must never touch their working directory — a `.map` next to
    // a source file is entirely plausible (linker scripts and source maps both
    // use that extension), and writing then deleting `<base_name>.map` there
    // would destroy a pre-existing file (plan 210 P1). Put it in the system temp
    // dir under a name unique to this process. The single `map_path` is the
    // only place this path exists, so the cleanup below cannot drift from the
    // write (plan 210 P7 — the two used to be recomputed independently).
    let map_path = if build_shared {
        Some(env::temp_dir().join(format!("vox-{}-{}.map", base_name, std::process::id())))
    } else {
        None
    };

    let ld_result = if build_shared {
        // An anonymous version script restricts the dynamic symbol table to
        // exactly the library's exported functions. coreasm declares ~54 of
        // its runtime symbols `global`; without this script every one would
        // leak into .dynsym, colliding on generic names like `_str_len` when
        // two Vox .so files are loaded together. The fix is link-time (zero
        // coreasm edits) for the same reason the %define mangling is: coreasm
        // is ported per architecture. The anonymous form (no version tag)
        // keeps `nm -D` reporting the plain symbol names.
        let map_path = map_path.as_ref().unwrap();
        let mut script = String::from("{ global:");
        for func in codegen.exported_functions() {
            script.push_str(&format!(" {};", func));
        }
        script.push_str(" local:*; };\n");
        if let Err(e) = fs::write(&map_path, &script) {
            eprintln!("Error writing version script: {}", e);
            std::process::exit(1);
        }

        let mut all_args: Vec<String> = vec![
            "-shared".to_string(),
            format!("--version-script={}", map_path.display()),
            "-o".to_string(),
            output_path.clone(),
            obj_path.clone(),
        ];
        for p in lib_paths.iter().map(|p| format!("-L{}", p)) {
            all_args.push(p);
        }
        for l in link_libs.iter().map(|l| format!("-l{}", l)) {
            all_args.push(l);
        }

        let arg_refs: Vec<&str> = all_args.iter().map(|s| s.as_str()).collect();
        Command::new("ld")
            .args(&arg_refs)
            .status()
    } else {
        // Build executable
        let ld_args = vec!["-o", &output_path, &obj_path];

        // Add library search paths
        let lib_path_args: Vec<String> = lib_paths.iter()
            .map(|p| format!("-L{}", p))
            .collect();

        // Add linked libraries
        let link_args: Vec<String> = link_libs.iter()
            .map(|l| format!("-l{}", l))
            .collect();

        // A static executable has no PT_INTERP and no runtime dependencies, so
        // it execs directly. But an executable linked against a shared library
        // needs the dynamic loader to map the .so in at runtime, and an rpath so
        // the loader finds it. Add both ONLY when there are link libs, so plain
        // static builds are untouched — the default Vox output stays a flat
        // static binary with no loader dependency.
        let mut dynamic_args: Vec<String> = Vec::new();
        if !link_libs.is_empty() {
            // FIXME(x86-64, M6): this loader path is hard-coded for x86-64.
            // `target_arch` is in scope here (it is threaded down from the
            // --arch flag / TARGET_ARCH at line ~249), so M6's port can derive
            // the path from it per architecture instead of fixing this string
            // by hand. Left as-is for now because the other architectures do
            // not exist yet and guessing their loader paths would be worse
            // than a grep-findable marker. See plan 210 P6.
            dynamic_args.push("-dynamic-linker".to_string());
            dynamic_args.push("/lib64/ld-linux-x86-64.so.2".to_string());
            for p in lib_paths.iter() {
                dynamic_args.push("-rpath".to_string());
                dynamic_args.push(p.clone());
            }
        }

        let mut all_args: Vec<&str> = ld_args;
        for a in &dynamic_args {
            all_args.push(a);
        }
        for p in &lib_path_args {
            all_args.push(p);
        }
        for l in &link_args {
            all_args.push(l);
        }

        Command::new("ld")
            .args(&all_args)
            .status()
    };
    
    // Remove the version script regardless of whether `ld` succeeded. The
    // cleanup used to live after the success check, so a failed link left
    // `<name>.map` in the user's working directory — a file they never asked
    // to see, named for a script they have no reason to know exists. Removing
    // it here covers both the success and the two failure exits below. The
    // temp path lives in `map_path`, the same value written above.
    if let Some(ref p) = map_path {
        let _ = fs::remove_file(p);
    }

    match ld_result {
        Ok(status) if status.success() => {}
        Ok(_) => {
            eprintln!("Linking failed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to run ld: {}", e);
            std::process::exit(1);
        }
    }

    let _ = fs::remove_file(&obj_path);

    if verbose {
        if build_shared {
            println!("Created shared library: {}", output_path);
        } else {
            println!("Created executable: {}", output_path);
        }
    }

    if keep_asm {
        if verbose {
            println!("Kept assembly file: {}", asm_path);
        }
    } else {
        if verbose {
            println!("Removed assembly file: {}", asm_path);
        }
        let _ = fs::remove_file(&asm_path);
    }
    
    if run_after {
        if build_shared {
            eprintln!("Cannot run a shared library directly");
            std::process::exit(1);
        }
        if verbose {
            println!("\nRunning {}...\n", output_path);
        }
        let run_result = Command::new(format!("./{}", output_path))
            .status();
        
        if let Ok(status) = run_result {
            std::process::exit(status.code().unwrap_or(0));
        }
    }
}
