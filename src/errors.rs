use std::fmt;

#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub line_content: String,
}

impl SourceLocation {
    pub fn new(file: &str, line: usize, column: usize, line_content: &str) -> Self {
        SourceLocation {
            file: file.to_string(),
            line,
            column,
            line_content: line_content.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    pub location: Option<SourceLocation>,
    pub hint: Option<String>,
    pub hint_location: Option<(usize, usize)>,  // (column, length) for visual connector
    pub suggestion: Option<String>,
    pub error_code: Option<String>,
}

impl CompileError {
    pub fn new(message: &str) -> Self {
        CompileError {
            message: message.to_string(),
            location: None,
            hint: None,
            hint_location: None,
            suggestion: None,
            error_code: None,
        }
    }

    pub fn with_location(mut self, loc: SourceLocation) -> Self {
        self.location = Some(loc);
        self
    }

    #[allow(dead_code)]
    pub fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.to_string());
        self
    }
    
    #[allow(dead_code)]
    pub fn with_hint_location(mut self, column: usize, length: usize) -> Self {
        self.hint_location = Some((column, length));
        self
    }

    pub fn with_suggestion(mut self, suggestion: &str) -> Self {
        self.suggestion = Some(suggestion.to_string());
        self
    }

    #[allow(dead_code)]
    pub fn with_code(mut self, code: &str) -> Self {
        self.error_code = Some(code.to_string());
        self
    }
}

impl From<String> for CompileError {
    fn from(s: String) -> Self {
        CompileError::new(&s)
    }
}

impl From<&str> for CompileError {
    fn from(s: &str) -> Self {
        CompileError::new(s)
    }
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // ANSI color codes
        const RED: &str = "\x1b[1;31m";
        const BLUE: &str = "\x1b[1;34m";
        const CYAN: &str = "\x1b[1;36m";
        const YELLOW: &str = "\x1b[1;33m";
        const GREEN: &str = "\x1b[1;32m";
        const RESET: &str = "\x1b[0m";
        const BOLD: &str = "\x1b[1m";

        // Error header
        if let Some(ref code) = self.error_code {
            write!(f, "{}error[{}]{}: {}{}\n", RED, code, RESET, BOLD, self.message)?;
        } else {
            write!(f, "{}error{}: {}{}\n", RED, RESET, BOLD, self.message)?;
        }
        write!(f, "{}", RESET)?;

        // Location info
        if let Some(ref loc) = self.location {
            write!(f, "  {}-->{} {}:{}:{}\n", BLUE, RESET, loc.file, loc.line, loc.column)?;
            
            // Line number gutter width
            let line_num_width = loc.line.to_string().len();
            
            // Empty line before source
            write!(f, "  {:width$} {}{}\n", "", BLUE, "|", width = line_num_width)?;
            
            // Source line
            write!(f, "  {}{}{} {} {}{}\n", 
                BLUE, loc.line, RESET, 
                format!("{}|{}", BLUE, RESET),
                loc.line_content.trim_end(),
                RESET)?;
            
            // Pointer line
            let pointer_offset = if loc.column > 0 { loc.column - 1 } else { 0 };
            let spaces = " ".repeat(pointer_offset);
            write!(f, "  {:width$} {}{} {}{}^--- here{}\n", 
                "", BLUE, "|", spaces, RED, RESET, width = line_num_width)?;
            
            // Draw connector to hint if we have a hint_location
            if let (Some(ref hint), Some((hint_col, hint_len))) = (&self.hint, self.hint_location) {
                let hint_offset = if hint_col > 0 { hint_col - 1 } else { 0 };
                
                // Draw vertical connector line
                write!(f, "  {:width$} {}{} ", "", BLUE, "|", width = line_num_width)?;
                write!(f, "{}{}|{}\n", " ".repeat(hint_offset), BLUE, RESET)?;
                
                // Draw the underline pointing to the typo word
                write!(f, "  {:width$} {}{} ", "", BLUE, "|", width = line_num_width)?;
                let underline = "─".repeat(hint_len);
                write!(f, "{}{}┴{}─── {}hint{}: {}\n", 
                    " ".repeat(hint_offset), BLUE, underline, CYAN, RESET, hint)?;
                
                return Ok(());  // Skip normal hint display
            }
        }

        // Hint (fallback if no hint_location)
        if let Some(ref hint) = self.hint {
            write!(f, "\n  {}hint{}: {}\n", CYAN, RESET, hint)?;
        }

        // Suggestion (did you mean?)
        if let Some(ref suggestion) = self.suggestion {
            write!(f, "  {}help{}: did you mean `{}{}{}`?\n", GREEN, RESET, YELLOW, suggestion, RESET)?;
        }

        Ok(())
    }
}

pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();
    let a_chars: Vec<char> = a_lower.chars().collect();
    let b_chars: Vec<char> = b_lower.chars().collect();
    
    let m = a_chars.len();
    let n = b_chars.len();
    
    if m == 0 { return n; }
    if n == 0 { return m; }
    
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i-1] == b_chars[j-1] { 0 } else { 1 };
            dp[i][j] = (dp[i-1][j] + 1)
                .min(dp[i][j-1] + 1)
                .min(dp[i-1][j-1] + cost);
        }
    }
    
    dp[m][n]
}

pub fn find_similar_keyword(word: &str, keywords: &[&str]) -> Option<String> {
    let word_lower = word.to_lowercase();
    let mut best_match: Option<(String, usize)> = None;
    
    // Don't suggest corrections for very short identifiers (1-2 chars)
    // These are common intentional variable names like x, y, i, n, etc.
    if word.len() <= 2 {
        return None;
    }
    
    for &keyword in keywords {
        // Skip if lengths are too different (avoid "source" -> "is" nonsense)
        let len_diff = (word.len() as isize - keyword.len() as isize).abs() as usize;
        if len_diff > 2 {
            continue;
        }
        
        let distance = levenshtein_distance(&word_lower, keyword);
        
        // Skip exact matches - no point suggesting what they already have
        if distance == 0 {
            return None;
        }
        
        // Only suggest if the distance is reasonable (up to 2 chars off for words 4+)
        let max_distance = if word.len() >= 4 { 2 } else { 1 };
        
        if distance <= max_distance {
            if let Some((_, best_dist)) = &best_match {
                if distance < *best_dist {
                    best_match = Some((keyword.to_string(), distance));
                }
            } else {
                best_match = Some((keyword.to_string(), distance));
            }
        }
    }
    
    best_match.map(|(s, _)| s)
}

pub const ENGLISH_KEYWORDS: &[&str] = &[
    "print", "set", "create", "add", "subtract", "multiply", "divide",
    "increment", "decrement", "call", "allocate", "free",
    "open", "read", "write", "close", "delete", "exists", "resize", "seek",
    "if", "when", "then", "else", "but", "otherwise", "while", "until",
    "for", "each", "every", "loop", "repeat", "times", "break", "continue",
    "return", "exit", "with", "called", "modulo",
    "is", "are", "equals", "equal", "greater", "less", "than", "not", "and", "or",
    "from", "to", "between", "through", "in", "of", "on", "the", "a", "an", "all", "by",
    "treating", "as",
    "number", "text", "boolean", "list", "true", "false",
    "buffer", "file", "bytes", "size", "into", "reading", "writing", "appending",
    "standard", "input", "output",
    "even", "odd", "positive", "negative", "zero", "empty",
    "capacity", "length", "first", "last", "count",
    "error", "stderr", "auto", "catching", "enable", "disable",
    "see", "library", "version",
    "argument", "arguments", "environment", "variable",
    "define", "function", "end", "returning", "taking",
];

pub struct SourceFile {
    pub filename: String,
    #[allow(dead_code)]
    pub content: String,
    lines: Vec<String>,
}

impl SourceFile {
    pub fn new(filename: &str, content: &str) -> Self {
        let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        SourceFile {
            filename: filename.to_string(),
            content: content.to_string(),
            lines,
        }
    }

    pub fn get_line(&self, line_num: usize) -> Option<&str> {
        if line_num > 0 && line_num <= self.lines.len() {
            Some(&self.lines[line_num - 1])
        } else {
            None
        }
    }

    pub fn make_location(&self, line: usize, column: usize) -> SourceLocation {
        let line_content = self.get_line(line).unwrap_or("").to_string();
        SourceLocation::new(&self.filename, line, column, &line_content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein_distance("print", "print"), 0);
        assert_eq!(levenshtein_distance("print", "pront"), 1);
        assert_eq!(levenshtein_distance("print", "prnt"), 1);
        assert_eq!(levenshtein_distance("create", "crate"), 1);
    }

    #[test]
    fn test_find_similar() {
        assert_eq!(find_similar_keyword("pirnt", ENGLISH_KEYWORDS), Some("print".to_string()));
        assert_eq!(find_similar_keyword("crate", ENGLISH_KEYWORDS), Some("create".to_string()));
        assert_eq!(find_similar_keyword("bufer", ENGLISH_KEYWORDS), Some("buffer".to_string()));
    }
}
