use super::*;

impl CodeGenerator {
    /// Evaluate a sequence of syscall argument expressions safely.
    ///
    /// Each expression's result (in rax) is parked on the stack before the
    /// next expression is generated, then everything is popped into the
    /// target registers in reverse order. Loading argument registers
    /// directly between generate_expr calls is unsound: a later expression
    /// containing a function call, format string, or buffer operation can
    /// clobber any register already loaded (user functions only preserve
    /// rbp, and syscalls clobber rcx/r11).
    pub(crate) fn emit_syscall_args(&mut self, args: &[(&Expr, &'static str)]) {
        for (expr, _) in args {
            self.generate_cstr_expr(expr);
            self.emit_indent("push rax  ; park syscall arg");
        }
        for (_, reg) in args.iter().rev() {
            self.emit_indent(&format!("pop {}", reg));
        }
    }

    /// Evaluate an expression that will be handed to the kernel as a
    /// C-string (path, mount option, execve argument). Buffer variables
    /// evaluate to their struct pointer (capacity/length/flags header
    /// first), so adjust to the data area - the runtime maintains a
    /// trailing NUL at data[length], making buffer contents directly
    /// usable as a C string. Text variables and string literals already
    /// point at NUL-terminated bytes.
    pub(crate) fn generate_cstr_expr(&mut self, expr: &Expr) {
        self.generate_expr(expr);
        if self.infer_expr_type(expr) == Some(VarType::Buffer) {
            self.emit_indent(&format!(
                "add rax, {}  ; buffer data area (header is {} bytes, data is NUL-terminated)",
                BUF_DATA_OFFSET, BUF_DATA_OFFSET
            ));
        }
    }

    pub(crate) fn is_fd_path_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::IntegerLit(_) => true,
            Expr::Identifier(name) => matches!(
                self.variable_types.get(name),
                Some(VarType::Integer)
            ),
            Expr::BinaryOp { .. }
            | Expr::UnaryOp { .. }
            | Expr::PropertyAccess { .. }
            | Expr::ByteAccess { .. }
            | Expr::ElementAccess { .. }
            | Expr::DurationCast { .. }
            | Expr::LastError
            | Expr::TreatingAs { .. } => self.infer_expr_type(expr) == Some(VarType::Integer),
            Expr::Cast { target_type, .. } => *target_type == Type::Integer,
            _ => false,
        }
    }

}
