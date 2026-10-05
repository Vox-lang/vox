//! Numbers the kernel reads narrower than a Vox number: a signal, a pid or
//! process group, an exit status. Each has a range the statement promises
//! (LANGUAGE.md "Send a signal" and "Program Termination"); a value the
//! compiler can prove is outside it is refused here, and codegen guards
//! every value it cannot prove at run time (docs/BUGS_FOUND.md #135, #136).

use super::*;

impl Analyzer {
    /// The value `expr` holds for the whole program, if the compiler can
    /// prove it, and the spelling the author wrote for it, for the caret.
    fn provable_kernel_number(&self, expr: &Expr) -> Option<(i64, String)> {
        if let Expr::Identifier(name) = expr {
            return self.number_constants.get(name).map(|&value| (value, name.clone()));
        }
        constant_integer(expr).map(|value| (value, value.to_string()))
    }

    fn push_kernel_range_error(
        &mut self,
        message: String,
        written: &str,
        patterns: &[String],
        value: i64,
        note: &str,
        help: Option<&str>,
    ) {
        let mut err = CompileError::new(&message);
        let occurrence = *self.symbol_error_counts.get(written).unwrap_or(&0);
        if let Some(loc) = self.find_pattern_location(written, patterns, occurrence, None, false, false) {
            let underline = if written == value.to_string() {
                "written here".to_string()
            } else {
                format!("'{}' is {} here", written, value)
            };
            err = err.with_underline_note(written.len().max(1), &underline);
            err = err.with_location(loc);
        }
        self.symbol_error_counts.insert(written.to_string(), occurrence + 1);
        err = err.with_note_line(note);
        if let Some(help) = help {
            err = err.with_help_line(help);
        }
        self.errors.push(err);
    }

    /// `Send signal N ...`: N is 0 (the existence check) to 64 (SIGRTMAX).
    pub(crate) fn check_signal_number(&mut self, signal: &Expr) {
        let Some((value, written)) = self.provable_kernel_number(signal) else {
            return;
        };
        if (0..=MAX_SIGNAL_NUMBER).contains(&value) {
            return;
        }
        let patterns = [format!("signal {}", written), written.clone()];
        self.push_kernel_range_error(
            format!("cannot send signal {}: there is no such signal", value),
            &written,
            &patterns,
            value,
            &format!("a signal number is between 0 and {}", MAX_SIGNAL_NUMBER),
            None,
        );
    }

    /// `to process <pid>` names exactly one process, and `to process group
    /// <g>` exactly one group: both are numbered 1 to 2147483647. A 0 or a
    /// negative pid is refused in favour of the forms that say what the
    /// kernel would do with it.
    pub(crate) fn check_signal_process(&mut self, pid: &Expr, group: bool) {
        let Some((value, written)) = self.provable_kernel_number(pid) else {
            return;
        };
        if (1..=MAX_PROCESS_ID).contains(&value) {
            return;
        }
        let (what, patterns) = if group {
            ("process group", vec![format!("group {}", written), written.clone()])
        } else {
            (
                "process",
                vec![
                    format!("process {}", written),
                    format!("child {}", written),
                    format!("to {}", written),
                    written.clone(),
                ],
            )
        };
        let help = (!group && value <= 0).then_some(
            "to reach more than one process, say which: 'to process group <g>', 'to my process group' or 'to every process'",
        );
        self.push_kernel_range_error(
            format!("cannot send a signal to {} {}", what, value),
            &written,
            &patterns,
            value,
            &format!("a {} is numbered from 1 to {}", what, MAX_PROCESS_ID),
            help,
        );
    }

    /// `Exit N.`: the kernel passes on only the low 8 bits, so N is 0 to 255.
    pub(crate) fn check_exit_code(&mut self, code: &Expr) {
        let Some((value, written)) = self.provable_kernel_number(code) else {
            return;
        };
        if (0..=MAX_EXIT_CODE).contains(&value) {
            return;
        }
        let patterns = [
            format!("Exit {}", written),
            format!("exit {}", written),
            format!("with {}", written),
            format!("Quit {}", written),
            format!("quit {}", written),
            format!("Terminate {}", written),
            format!("terminate {}", written),
            written.clone(),
        ];
        self.push_kernel_range_error(
            format!("cannot exit with code {}", value),
            &written,
            &patterns,
            value,
            &format!("an exit code is between 0 and {}", MAX_EXIT_CODE),
            None,
        );
    }
}
