mod lexer;
mod parser;
mod analyzer;
mod codegen;
mod errors;

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

use lexer::Lexer;
use parser::Parser;
use parser::ast::Statement;
use analyzer::Analyzer;
use codegen::CodeGenerator;
use errors::CompileError;

/// Find the coreasm library directory using industry-standard resolution order:
/// 1. EC_CORE_PATH environment variable (user override)
/// 2. XDG config file (~/.config/ec/config)
/// 3. System paths (/usr/local/share/ec, /usr/share/ec)
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
    
    // 2. XDG config file (~/.config/ec/config)
    if let Some(config_path) = get_config_lib_path() {
        if config_path.exists() {
            return Some(config_path);
        }
    }
    
    // 3. System paths (Unix standard locations)
    let system_paths = [
        "/usr/local/share/ec/coreasm",
        "/usr/share/ec/coreasm",
        "/opt/ec/coreasm",
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
    // XDG Base Directory: ~/.config/ec/config
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
                let system_path = PathBuf::from("/usr/share/ec/lib").join(path);
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
            
            // Only process .en source files (not .so libraries)
            if path.ends_with(".en") {
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
                // Don't keep the see statement for .en files - content is inlined
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

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("ec v0.1.0");
        eprintln!("Usage: ec <source.en> [options]");
        eprintln!("By Josjuar Lister 2026");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --emit-asm       Output assembly only (don't assemble/link)");
        eprintln!("  --run            Compile and run the program");
        eprintln!("  --shared         Build a shared library (.so) instead of executable");
        eprintln!("  --link <libs>    Link against shared libraries (comma-separated)");
        eprintln!("  --lib-path <paths>  Additional library search paths (comma-separated)");
        eprintln!("  --target <arch>   Target architecture (default: x86_64)");
        eprintln!("  -o <file>        Output file name");
        eprintln!("  -v | --verbose   Verbose output");
        std::process::exit(1);
    }
    
    let source_path = &args[1];
    let mut emit_asm_only = false;
    let mut run_after = false;
    let mut build_shared = false;
    let mut output_name = None;
    let mut verbose = false;
    let mut link_libs: Vec<String> = Vec::new();
    let mut lib_paths: Vec<String> = Vec::new();
    let mut target_arch = option_env!("TARGET_ARCH").unwrap_or("x86_64").to_string();
    
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--emit-asm" => emit_asm_only = true,
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
            _ => {}
        }
        i += 1;
    }
    
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
    
    // Process includes (see statements) with circular dependency tracking
    let source_path_buf = PathBuf::from(source_path);
    let mut included_files = HashSet::new();
    included_files.insert(source_path_buf.canonicalize().unwrap_or(source_path_buf.clone()));
    process_includes(&mut program, &source_path_buf, &mut included_files, verbose);
    
    let mut analyzer = Analyzer::new();
    analyzer.analyze(&mut program);
    
    if !analyzer.errors.is_empty() {
        for err in &analyzer.errors {
            eprintln!("{}", CompileError::new(err));
        }
        std::process::exit(1);
    }
    
    let mut codegen = CodeGenerator::new();
    codegen.set_shared_lib_mode(build_shared);
    codegen.set_target_arch(&target_arch);
    let assembly = codegen.generate(&program);
    
    let base_name = Path::new(source_path)
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
            eprintln!("Warning: coreasm library not found. Set EC_CORE_PATH or install to /usr/local/share/ec/");
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
    
    let ld_result = if build_shared {
        // Build shared library with -shared flag
        let ld_args = vec!["-shared", "-o", &output_path, &obj_path];
        
        // Add library search paths
        let lib_path_args: Vec<String> = lib_paths.iter()
            .map(|p| format!("-L{}", p))
            .collect();
        
        // Add linked libraries
        let link_args: Vec<String> = link_libs.iter()
            .map(|l| format!("-l{}", l))
            .collect();
        
        let mut all_args: Vec<&str> = ld_args;
        for p in &lib_path_args {
            all_args.push(p);
        }
        for l in &link_args {
            all_args.push(l);
        }
        
        Command::new("ld")
            .args(&all_args)
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
        
        let mut all_args: Vec<&str> = ld_args;
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
