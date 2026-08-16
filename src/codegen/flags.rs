use super::*;

#[derive(Clone)]
pub(crate) struct FlagSchemaRuntime {
    name: String,
    short: String,
    long: String,
    value_type: FlagValueType,
    required: bool,
}

impl CodeGenerator {
    pub(crate) fn collect_flag_schemas(&mut self, program: &Program) {
        self.flag_schemas.clear();
        for stmt in &program.statements {
            if let Statement::FlagSchemaDecl {
                name,
                short,
                long,
                value_type,
                required,
                ..
            } = stmt
            {
                self.flag_schemas.push(FlagSchemaRuntime {
                    name: name.clone(),
                    short: short.clone(),
                    long: long.clone(),
                    value_type: value_type.clone(),
                    required: *required,
                });
            }
        }
    }

    pub(crate) fn emit_flag_parse_routine(&mut self) {
        if self.flag_schemas.is_empty() {
            return;
        }

        // The routine calls _str_eq to match argument tokens against flag
        // aliases, so string.asm must be included even when the program
        // itself uses no other strings. Without this, a program that
        // declares and parses flags but never prints/compares text failed
        // to assemble with "symbol `_str_eq' not defined".
        self.uses_strings = true;

        self.emit_indent("; Runtime flag schema parsing");
        self.emit_indent("call _reset_parsed_args");

        let schemas = self.flag_schemas.clone();
        let mut seen_entries: Vec<(FlagSchemaRuntime, i64, i64)> = Vec::new();
        for schema in &schemas {
            let flag_offset = if let Some(off) = self.get_var(&schema.name) {
                off
            } else {
                self.alloc_var(&schema.name)
            };
            let seen_offset = self.alloc_var(&format!("__flag_seen_{}", schema.name.replace(' ', "_")));
            self.emit_indent(&format!("mov qword [rbp-{}], 0", seen_offset));
            seen_entries.push((schema.clone(), seen_offset, flag_offset));
        }

        let argc_off = self.alloc_var("__flag_parse_argc");
        let idx_off = self.alloc_var("__flag_parse_idx");
        let cur_off = self.alloc_var("__flag_parse_cur");
        let stop_off = self.alloc_var("__flag_parse_stop");

        self.emit_indent("call _get_raw_argc");
        self.emit_indent(&format!("mov [rbp-{}], rax", argc_off));
        self.emit_indent(&format!("mov qword [rbp-{}], 0", idx_off));
        self.emit_indent(&format!("mov qword [rbp-{}], 0", stop_off));

        let loop_label = self.new_label("flag_parse_loop");
        let done_label = self.new_label("flag_parse_done");
        let append_pos_label = self.new_label("flag_parse_append_positional");
        let continue_label = self.new_label("flag_parse_continue");

        let stop_token = self.add_string("--");
        self.emit(&format!("{}:", loop_label));
        self.emit_indent(&format!("mov rax, [rbp-{}]", idx_off));
        self.emit_indent(&format!("cmp rax, [rbp-{}]", argc_off));
        self.emit_indent(&format!("jge {}", done_label));

        self.emit_indent("mov rdi, rax");
        self.emit_indent("call _get_raw_arg");
        self.emit_indent(&format!("mov [rbp-{}], rax", cur_off));

        self.emit_indent(&format!("cmp qword [rbp-{}], 0", stop_off));
        self.emit_indent(&format!("jne {}", append_pos_label));

        let not_stop_label = self.new_label("flag_parse_not_stop");
        self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
        self.emit_indent(&format!("lea rsi, [rel {}]", stop_token));
        self.emit_indent("call _str_eq");
        self.emit_indent("test rax, rax");
        self.emit_indent(&format!("jz {}", not_stop_label));
        self.emit_indent(&format!("mov qword [rbp-{}], 1", stop_off));
        self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
        self.emit_indent(&format!("jmp {}", continue_label));
        self.emit(&format!("{}:", not_stop_label));

        let mut next_check_label = append_pos_label.clone();
        for (schema, seen_off, flag_off) in &seen_entries {
            let no_match_label = self.new_label("flag_no_match");
            let matched_label = self.new_label("flag_matched");

            let short_label = self.add_string(&schema.short);
            self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
            self.emit_indent(&format!("lea rsi, [rel {}]", short_label));
            self.emit_indent("call _str_eq");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jnz {}", matched_label));

            let long_label = self.add_string(&schema.long);
            self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
            self.emit_indent(&format!("lea rsi, [rel {}]", long_label));
            self.emit_indent("call _str_eq");
            self.emit_indent("test rax, rax");
            self.emit_indent(&format!("jz {}", no_match_label));

            self.emit(&format!("{}:", matched_label));
            match schema.value_type {
                FlagValueType::Boolean => {
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", flag_off));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", seen_off));
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
                FlagValueType::Text | FlagValueType::Number => {
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("mov rax, [rbp-{}]", idx_off));
                    self.emit_indent(&format!("cmp rax, [rbp-{}]", argc_off));
                    self.emit_indent(&format!("jge {}", done_label));
                    self.emit_indent("mov rdi, rax");
                    self.emit_indent("call _get_raw_arg");
                    if matches!(schema.value_type, FlagValueType::Number) {
                        self.uses_ints = true;
                        self.emit_indent("mov rdi, rax");
                        self.emit_indent("call _parse_i64");
                    }
                    self.emit_indent(&format!("mov [rbp-{}], rax", flag_off));
                    self.emit_indent(&format!("mov qword [rbp-{}], 1", seen_off));
                    self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
                    self.emit_indent(&format!("jmp {}", continue_label));
                }
            }

            self.emit(&format!("{}:", no_match_label));
            next_check_label = no_match_label;
        }

        // Fall through from last no-match to positional append
        self.emit_indent(&format!("jmp {}", append_pos_label));

        self.emit(&format!("{}:", append_pos_label));
        self.emit_indent(&format!("mov rdi, [rbp-{}]", cur_off));
        self.emit_indent("call _append_parsed_arg");
        self.emit_indent(&format!("inc qword [rbp-{}]", idx_off));
        self.emit_indent(&format!("jmp {}", continue_label));

        self.emit(&format!("{}:", continue_label));
        self.emit_indent(&format!("jmp {}", loop_label));

        self.emit(&format!("{}:", done_label));
        for (schema, seen_off, _) in &seen_entries {
            if schema.required {
                let ok_label = self.new_label("flag_required_ok");
                self.emit_indent(&format!("cmp qword [rbp-{}], 1", seen_off));
                self.emit_indent(&format!("je {}", ok_label));
                self.emit_indent("EXIT 1");
                self.emit(&format!("{}:", ok_label));
            }
        }
        for (schema, _, flag_off) in &seen_entries {
            if let Some(label) = self.global_var_label(&schema.name).cloned() {
                self.emit_indent(&format!("mov rax, [rbp-{}]", flag_off));
                self.emit_indent(&format!("mov [rel {}], rax", label));
            }
        }
        let _ = next_check_label;
    }

    pub(crate) fn argument_view_uses_parsed(&self) -> bool {
        self.parsed_args_active
    }

}
