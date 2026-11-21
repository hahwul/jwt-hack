pub const COMMANDS: &[&str] = &[
    "set", "decode", "encode", "verify", "crack", "payload", "scan", "show", "clear", "help",
    "exit", "quit",
];

pub const SET_KEYS: &[&str] = &["token", "secret", "algorithm", "private_key", "wordlist"];

pub const ALGORITHMS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384",
    "PS512", "EdDSA", "none",
];

/// Represents the tab-completion state
pub struct CompletionState {
    pub candidates: Vec<String>,
    pub selected_index: usize,
    // Keep the text around the original word while cycling through replacements.
    before: String,
    after: String,
}

impl CompletionState {
    /// Apply the currently selected candidate to the input, returning (new_input, new_cursor_pos)
    pub fn apply(&self) -> (String, usize) {
        let replacement = &self.candidates[self.selected_index];
        let suffix = if self.after.is_empty() {
            " "
        } else {
            &self.after
        };
        let new_input = format!("{}{replacement}{suffix}", self.before);
        let separator_len = suffix.chars().next().map_or(0, char::len_utf8);
        let new_cursor = self.before.len() + replacement.len() + separator_len;
        (new_input, new_cursor)
    }

    /// Move selection to the next candidate
    pub fn next(&mut self) {
        if !self.candidates.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.candidates.len();
        }
    }

    /// Move selection to the previous candidate
    pub fn prev(&mut self) {
        if !self.candidates.is_empty() {
            self.selected_index = if self.selected_index == 0 {
                self.candidates.len() - 1
            } else {
                self.selected_index - 1
            };
        }
    }
}

/// Compute completions for the given input at the given cursor position.
/// Returns None if no completions are available.
pub fn compute_completions(input: &str, cursor_pos: usize) -> Option<CompletionState> {
    // Clamp the cursor down to a valid char boundary so neither the slice below nor
    // the `end - prefix.len()` offsets can land inside a multi-byte character.
    let mut end = cursor_pos.min(input.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let line_up_to_cursor = &input[..end];
    let parts: Vec<&str> = line_up_to_cursor.split_whitespace().collect();
    // `split_whitespace` splits on ALL Unicode whitespace, so the word-boundary test
    // must use the same predicate. Checking only for an ASCII ' ' let an input ending
    // in e.g. a non-breaking space (U+00A0) or ideographic space (U+3000) take the
    // "still typing a word" branch, where `end - prefix.len()` then pointed inside
    // that multi-byte whitespace char and `apply()` panicked slicing there.
    let at_word_boundary = line_up_to_cursor.ends_with(char::is_whitespace);

    let (prefix_start, candidates) = match parts.len() {
        0 => {
            // Empty line — suggest all commands
            let candidates: Vec<String> = COMMANDS.iter().map(|c| c.to_string()).collect();
            (end, candidates)
        }
        1 if !at_word_boundary => {
            // Typing first word — match commands
            let prefix = parts[0];
            let candidates: Vec<String> = COMMANDS
                .iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| c.to_string())
                .collect();
            (end - prefix.len(), candidates)
        }
        1 if at_word_boundary && parts[0] == "set" => {
            // After "set " — suggest keys
            let candidates: Vec<String> = SET_KEYS.iter().map(|k| k.to_string()).collect();
            (end, candidates)
        }
        2 if !at_word_boundary && parts[0] == "set" => {
            // Typing set key — match keys
            let prefix = parts[1];
            let candidates: Vec<String> = SET_KEYS
                .iter()
                .filter(|k| k.starts_with(prefix))
                .map(|k| k.to_string())
                .collect();
            (end - prefix.len(), candidates)
        }
        2 if at_word_boundary && parts[0] == "set" && parts[1] == "algorithm" => {
            // After "set algorithm " — suggest algorithms
            let candidates: Vec<String> = ALGORITHMS.iter().map(|a| a.to_string()).collect();
            (end, candidates)
        }
        3 if !at_word_boundary && parts[0] == "set" && parts[1] == "algorithm" => {
            // Typing algorithm name
            let prefix = parts[2];
            let candidates: Vec<String> = ALGORITHMS
                .iter()
                .filter(|a| a.starts_with(prefix))
                .map(|a| a.to_string())
                .collect();
            (end - prefix.len(), candidates)
        }
        _ => return None,
    };

    if candidates.is_empty() {
        return None;
    }

    // Include the part of the current word after the cursor in the replacement.
    let suffix_start = end
        + input[end..]
            .find(char::is_whitespace)
            .unwrap_or(input.len() - end);
    Some(CompletionState {
        candidates,
        selected_index: 0,
        before: input[..prefix_start].to_string(),
        after: input[suffix_start..].to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input_shows_all_commands() {
        let state = compute_completions("", 0).unwrap();
        assert_eq!(state.candidates.len(), COMMANDS.len());
        assert_eq!(state.before, "");
    }

    #[test]
    fn test_partial_command() {
        let state = compute_completions("dec", 3).unwrap();
        assert_eq!(state.candidates, vec!["decode"]);
        assert_eq!(state.before, "");
    }

    #[test]
    fn test_set_suggests_keys() {
        let state = compute_completions("set ", 4).unwrap();
        assert_eq!(state.candidates.len(), SET_KEYS.len());
    }

    #[test]
    fn test_set_partial_key() {
        let state = compute_completions("set to", 6).unwrap();
        assert_eq!(state.candidates, vec!["token"]);
        assert_eq!(state.before, "set ");
    }

    #[test]
    fn test_set_algorithm_suggests_algorithms() {
        let state = compute_completions("set algorithm ", 14).unwrap();
        assert_eq!(state.candidates.len(), ALGORITHMS.len());
    }

    #[test]
    fn test_set_algorithm_partial() {
        let state = compute_completions("set algorithm HS", 16).unwrap();
        assert_eq!(state.candidates, vec!["HS256", "HS384", "HS512"]);
    }

    #[test]
    fn test_no_completions() {
        let result = compute_completions("decode some_token", 17);
        assert!(result.is_none());
    }

    #[test]
    fn test_apply_completion() {
        let state = compute_completions("dec", 3).unwrap();
        let (new_input, new_cursor) = state.apply();
        assert_eq!(new_input, "decode ");
        assert_eq!(new_cursor, 7);
    }

    #[test]
    fn test_multibyte_whitespace_does_not_panic() {
        for ws in ["\u{3000}", "\u{a0}", "\u{2003}"] {
            let input = format!("set{ws}");
            let (new_input, new_cursor) = compute_completions(&input, input.len()).unwrap().apply();
            assert_eq!(new_input, format!("set{ws}token "));
            assert_eq!(new_cursor, new_input.len());
        }
    }

    #[test]
    fn test_multibyte_word_completion_boundary_safe() {
        let input = "set \u{3000}";
        let (new_input, new_cursor) = compute_completions(input, 5).unwrap().apply();
        assert_eq!(new_input, "set token\u{3000}");
        assert_eq!(new_cursor, new_input.len());
    }

    #[test]
    fn test_next_prev() {
        let mut state = CompletionState {
            candidates: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            selected_index: 0,
            before: String::new(),
            after: String::new(),
        };
        state.next();
        assert_eq!(state.selected_index, 1);
        state.next();
        assert_eq!(state.selected_index, 2);
        state.next();
        assert_eq!(state.selected_index, 0); // wraps around
        state.prev();
        assert_eq!(state.selected_index, 2); // wraps back
    }
}
