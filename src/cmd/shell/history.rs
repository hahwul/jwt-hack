use std::fs;
use std::path::PathBuf;

use crate::config::Config;

/// File-based command history for the shell
pub struct History {
    entries: Vec<String>,
    max_entries: usize,
    file_path: Option<PathBuf>,
    /// Current navigation index (None = not navigating)
    nav_index: Option<usize>,
}

impl History {
    pub fn new(max_entries: usize) -> Self {
        let file_path = Config::default_config_dir().map(|dir| dir.join("shell_history"));
        let mut history = Self {
            entries: Vec::new(),
            max_entries,
            file_path,
            nav_index: None,
        };
        history.load();
        history
    }

    fn load(&mut self) {
        if let Some(ref path) = self.file_path {
            if let Ok(content) = fs::read_to_string(path) {
                self.entries = content
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect();
                // Trim to max
                if self.entries.len() > self.max_entries {
                    let start = self.entries.len() - self.max_entries;
                    self.entries = self.entries[start..].to_vec();
                }
            }
        }
    }

    pub fn save(&self) {
        if let Some(ref path) = self.file_path {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let content = self.entries.join("\n");
            let _ = fs::write(path, content);
        }
    }

    pub fn add(&mut self, entry: &str) {
        let entry = entry.trim().to_string();
        if entry.is_empty() {
            return;
        }
        // Remove duplicate if it exists at the end
        if self.entries.last().map(|e| e.as_str()) == Some(&entry) {
            // skip duplicate
        } else {
            self.entries.push(entry);
        }
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
        self.nav_index = None;
    }

    /// Navigate up (older entries). Returns the entry if available.
    pub fn navigate_up(&mut self) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let idx = match self.nav_index {
            Some(0) => 0,
            Some(i) => i - 1,
            None => self.entries.len() - 1,
        };
        self.nav_index = Some(idx);
        Some(&self.entries[idx])
    }

    /// Navigate down (newer entries). Returns the entry or None if past the end.
    pub fn navigate_down(&mut self) -> Option<&str> {
        match self.nav_index {
            Some(i) => {
                if i + 1 < self.entries.len() {
                    self.nav_index = Some(i + 1);
                    Some(&self.entries[i + 1])
                } else {
                    self.nav_index = None;
                    None
                }
            }
            None => None,
        }
    }

    /// Reset navigation position
    pub fn reset_navigation(&mut self) {
        self.nav_index = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_history() -> History {
        History {
            entries: Vec::new(),
            max_entries: 100,
            file_path: None,
            nav_index: None,
        }
    }

    #[test]
    fn test_add_entry() {
        let mut h = test_history();
        h.add("set token abc");
        assert_eq!(h.entries.len(), 1);
        assert_eq!(h.entries[0], "set token abc");
    }

    #[test]
    fn test_add_skips_empty() {
        let mut h = test_history();
        h.add("");
        h.add("  ");
        assert!(h.entries.is_empty());
    }

    #[test]
    fn test_add_dedup_consecutive() {
        let mut h = test_history();
        h.add("decode");
        h.add("decode");
        assert_eq!(h.entries.len(), 1);
    }

    #[test]
    fn test_max_entries() {
        let mut h = History {
            entries: Vec::new(),
            max_entries: 3,
            file_path: None,
            nav_index: None,
        };
        h.add("a");
        h.add("b");
        h.add("c");
        h.add("d");
        assert_eq!(h.entries.len(), 3);
        assert_eq!(h.entries[0], "b");
    }

    #[test]
    fn test_navigate_up_down() {
        let mut h = test_history();
        h.add("first");
        h.add("second");
        h.add("third");

        assert_eq!(h.navigate_up(), Some("third"));
        assert_eq!(h.navigate_up(), Some("second"));
        assert_eq!(h.navigate_up(), Some("first"));
        assert_eq!(h.navigate_up(), Some("first")); // stays at top

        assert_eq!(h.navigate_down(), Some("second"));
        assert_eq!(h.navigate_down(), Some("third"));
        assert_eq!(h.navigate_down(), None); // past end
    }

    #[test]
    fn test_navigate_empty() {
        let mut h = test_history();
        assert_eq!(h.navigate_up(), None);
        assert_eq!(h.navigate_down(), None);
    }

    #[test]
    fn test_reset_navigation() {
        let mut h = test_history();
        h.add("first");
        h.navigate_up();
        h.reset_navigation();
        // After reset, navigate_up should go to the last entry again
        assert_eq!(h.navigate_up(), Some("first"));
    }
}
