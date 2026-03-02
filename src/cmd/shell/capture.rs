use std::io::Read;

use ansi_to_tui::IntoText;
use ratatui::text::Text;

/// Result of capturing stdout/stderr from a command
#[allow(dead_code)]
pub struct CapturedOutput {
    pub text: Text<'static>,
    pub raw: String,
}

/// Execute a closure while capturing stdout and stderr.
/// Returns the captured output converted to ratatui `Text` (preserving ANSI colors).
pub fn capture_command_output<F>(f: F) -> CapturedOutput
where
    F: FnOnce(),
{
    let mut stdout_capture = match gag::BufferRedirect::stdout() {
        Ok(c) => c,
        Err(_) => {
            // If capture fails, just run the function and return empty
            f();
            return CapturedOutput {
                text: Text::raw(""),
                raw: String::new(),
            };
        }
    };

    let mut stderr_capture = match gag::BufferRedirect::stderr() {
        Ok(c) => c,
        Err(_) => {
            drop(stdout_capture);
            f();
            return CapturedOutput {
                text: Text::raw(""),
                raw: String::new(),
            };
        }
    };

    f();

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();
    let _ = stdout_capture.read_to_string(&mut stdout_buf);
    let _ = stderr_capture.read_to_string(&mut stderr_buf);

    // Drop captures to restore stdout/stderr before any further output
    drop(stdout_capture);
    drop(stderr_capture);

    let combined = if stderr_buf.is_empty() {
        stdout_buf
    } else if stdout_buf.is_empty() {
        stderr_buf
    } else {
        format!("{stdout_buf}{stderr_buf}")
    };

    let cleaned = strip_non_sgr_sequences(&combined);

    let text = cleaned
        .as_bytes()
        .into_text()
        .unwrap_or_else(|_| Text::raw(cleaned.clone()));

    CapturedOutput { text, raw: cleaned }
}

/// Strip non-SGR ANSI escape sequences (cursor movement, erase, etc.)
/// but keep SGR color/style sequences (ESC[...m).
fn strip_non_sgr_sequences(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Start of an escape sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                let mut seq = String::new();
                // Read until we find a letter (the final byte of the CSI sequence)
                loop {
                    match chars.next() {
                        Some(c) if c.is_ascii_alphabetic() || c == 'J' || c == 'K' || c == 'H' => {
                            if c == 'm' {
                                // SGR sequence — keep it
                                result.push('\x1b');
                                result.push('[');
                                result.push_str(&seq);
                                result.push('m');
                            }
                            // else: non-SGR sequence — discard
                            break;
                        }
                        Some(c) => {
                            seq.push(c);
                        }
                        None => break,
                    }
                }
            }
            // else: not a CSI sequence, skip
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_keeps_sgr() {
        let input = "\x1b[32mgreen\x1b[0m";
        let result = strip_non_sgr_sequences(input);
        assert_eq!(result, "\x1b[32mgreen\x1b[0m");
    }

    #[test]
    fn test_strip_removes_cursor_movement() {
        let input = "\x1b[2J\x1b[1;1Hhello";
        let result = strip_non_sgr_sequences(input);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_strip_mixed() {
        let input = "\x1b[2J\x1b[31mred\x1b[0m\x1b[1;1H";
        let result = strip_non_sgr_sequences(input);
        assert_eq!(result, "\x1b[31mred\x1b[0m");
    }

    #[test]
    fn test_plain_text_unchanged() {
        let input = "hello world";
        let result = strip_non_sgr_sequences(input);
        assert_eq!(result, "hello world");
    }
}
