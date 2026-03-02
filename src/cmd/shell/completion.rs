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
    /// The position in the input where the completed word starts
    pub prefix_start: usize,
}

impl CompletionState {
    /// Apply the currently selected candidate to the input, returning (new_input, new_cursor_pos)
    pub fn apply(&self, input: &str) -> (String, usize) {
        let replacement = &self.candidates[self.selected_index];
        let before = &input[..self.prefix_start];
        let new_input = format!("{before}{replacement} ");
        let new_cursor = new_input.len();
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
    let line_up_to_cursor = &input[..cursor_pos.min(input.len())];
    let parts: Vec<&str> = line_up_to_cursor.split_whitespace().collect();
    let at_word_boundary = line_up_to_cursor.ends_with(' ');

    let (prefix_start, candidates) = match parts.len() {
        0 => {
            // Empty line — suggest all commands
            let candidates: Vec<String> = COMMANDS.iter().map(|c| c.to_string()).collect();
            (0, candidates)
        }
        1 if !at_word_boundary => {
            // Typing first word — match commands
            let prefix = parts[0];
            let candidates: Vec<String> = COMMANDS
                .iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| c.to_string())
                .collect();
            (cursor_pos - prefix.len(), candidates)
        }
        1 if at_word_boundary && parts[0] == "set" => {
            // After "set " — suggest keys
            let candidates: Vec<String> = SET_KEYS.iter().map(|k| k.to_string()).collect();
            (cursor_pos, candidates)
        }
        2 if !at_word_boundary && parts[0] == "set" => {
            // Typing set key — match keys
            let prefix = parts[1];
            let candidates: Vec<String> = SET_KEYS
                .iter()
                .filter(|k| k.starts_with(prefix))
                .map(|k| k.to_string())
                .collect();
            (cursor_pos - prefix.len(), candidates)
        }
        2 if at_word_boundary && parts[0] == "set" && parts[1] == "algorithm" => {
            // After "set algorithm " — suggest algorithms
            let candidates: Vec<String> = ALGORITHMS.iter().map(|a| a.to_string()).collect();
            (cursor_pos, candidates)
        }
        3 if !at_word_boundary && parts[0] == "set" && parts[1] == "algorithm" => {
            // Typing algorithm name
            let prefix = parts[2];
            let candidates: Vec<String> = ALGORITHMS
                .iter()
                .filter(|a| a.starts_with(prefix))
                .map(|a| a.to_string())
                .collect();
            (cursor_pos - prefix.len(), candidates)
        }
        _ => return None,
    };

    if candidates.is_empty() {
        return None;
    }

    Some(CompletionState {
        candidates,
        selected_index: 0,
        prefix_start,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input_shows_all_commands() {
        let state = compute_completions("", 0).unwrap();
        assert_eq!(state.candidates.len(), COMMANDS.len());
        assert_eq!(state.prefix_start, 0);
    }

    #[test]
    fn test_partial_command() {
        let state = compute_completions("dec", 3).unwrap();
        assert_eq!(state.candidates, vec!["decode"]);
        assert_eq!(state.prefix_start, 0);
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
        assert_eq!(state.prefix_start, 4);
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
        let state = CompletionState {
            candidates: vec!["decode".to_string(), "decode".to_string()],
            selected_index: 0,
            prefix_start: 0,
        };
        let (new_input, new_cursor) = state.apply("dec");
        assert_eq!(new_input, "decode ");
        assert_eq!(new_cursor, 7);
    }

    #[test]
    fn test_next_prev() {
        let mut state = CompletionState {
            candidates: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            selected_index: 0,
            prefix_start: 0,
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
