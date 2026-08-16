use super::*;

/// Turn an author-written name into an assembly symbol, per the project
/// standard in `docs/SYMBOL_MANGLING.md`.
///
/// Every character outside `[A-Za-z0-9_]` becomes `_`, and a leading digit is
/// prefixed with `_`. The target is a valid **C** identifier, not merely a
/// valid NASM one: NASM happily assembles `my.helper` and `flags_0.1_hasflag`,
/// so a dot survives all the way to the symbol table and only fails when a C
/// or Rust consumer tries to name the function — which is the entire point of
/// a standalone `.so`. Catching it here keeps that failure impossible.
///
/// Used for function labels today and for the `<lib>_<version>_<name>` library
/// mangling when shared libraries land, so both go through one rule.
pub(crate) fn mangle_symbol(name: &str) -> String {
    let mut out = sanitize_symbol(name);
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// The per-character sanitizer that is the core of `mangle_symbol`: every
/// character outside `[A-Za-z0-9_]` becomes `_`. This is the ONE sanitizer —
/// `mangle_symbol` layers the leading-digit prefix on top, and the library
/// mangling applies it per component (prefixing only the first, since a digit
/// may start an interior component without making the whole joined symbol an
/// invalid C identifier). Factoring it out keeps a second sanitizer from
/// being written, per plan 230.
fn sanitize_symbol(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 1);
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

/// The library mangling: `<lib>_<version>_<func>`, built by applying the
/// shared `sanitize_symbol` to each of the three components and joining with
/// `_`. The library component goes through the full `mangle_symbol` (with the
/// leading-digit prefix) because it STARTS the symbol — a digit there would
/// make the whole result an invalid C identifier. The version and function
/// components are interior (joined with `_`), so a leading digit there is
/// fine and the prefix would only insert a spurious double underscore:
/// `1.0` sanitizes to `1_0`, giving `mathkit_1_0_greet` as the plan specifies
/// — not `mathkit__1_0_greet`, which a literal `mangle_symbol("1.0")` (whose
/// leading-digit rule turns `1.0` into `_1_0`) would produce. This is the
/// only place the three-component form is built — both the definition label
/// and the call site resolve through it, so a .so that defines
/// `mathkit_1_0_greet` also calls `mathkit_1_0_greet`, never the bare `greet`
/// it would otherwise emit.
pub(crate) fn mangle_library_symbol(lib: &str, version: &str, func: &str) -> String {
    format!(
        "{}_{}_{}",
        mangle_symbol(lib),
        sanitize_symbol(version),
        sanitize_symbol(func)
    )
}

/// The assembly label a function DEFINED in this compilation emits, independent
/// of any `CodeGenerator` state. This is the ONE rule both the codegen and the
/// analyzer use to key their per-function symbol tables, so the tables are
/// scoped by `<library, version>` rather than by the authored name: two
/// libraries in one .so each defining `greet` produce two distinct keys
/// (`alpha_1_0_greet`, `beta_2_0_greet`) instead of colliding on the bare
/// `greet`. In shared mode with an identity set, the key is the
/// `<lib>_<ver>_<func>` mangled label; otherwise (non-shared, or shared before
/// a `Library` declaration is seen) it is the plain `mangle_symbol(name)`,
/// preserving today's single-library and executable behaviour exactly. The
/// `current_lib` is passed in rather than read from a field so the pre-passes
/// that walk statements in order can track the identity in a local without
/// disturbing `self.current_library` (which the main generate walk owns).
pub(crate) fn make_function_label(
    shared: bool,
    current_lib: Option<&(String, String)>,
    name: &str,
) -> String {
    if shared {
        if let Some((lib, ver)) = current_lib {
            return mangle_library_symbol(lib, ver, name);
        }
    }
    mangle_symbol(name)
}

/// Render a name as its canonical identifier form (plan 270): a bare word when
/// it is bare-legal (`[A-Za-z_][A-Za-z0-9_]*`) and not a reserved keyword, else
/// a `'single-quoted'` identifier. The compiler only ever registers names that
/// are already legal, so the keyword check is defensive against a future
/// hand-edited `LibBlock`; the writer and reader agree on exactly this form —
/// no dual parsing, no backwards compatibility.
pub(crate) fn format_lib_name(name: &str) -> String {
    fn is_bare_legal(s: &str) -> bool {
        let mut chars = s.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            && crate::lexer::Token::string_is_keyword(s).is_none()
    }
    if is_bare_legal(name) {
        name.to_string()
    } else {
        format!("'{}'", name)
    }
}

