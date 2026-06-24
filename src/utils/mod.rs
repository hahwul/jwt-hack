use colored::{Color, Colorize};
use std::fmt::Display;

use crate::printing::theme;

pub mod compression;

/// Displays a success message with a green checkmark prefix
pub fn log_success<T: Display>(message: T) {
    eprintln!("{}", theme::status_line(theme::G_OK, Color::Green, message));
}

/// Displays an information message with a cyan arrow prefix
pub fn log_info<T: Display>(message: T) {
    eprintln!(
        "{}",
        theme::status_line(theme::G_INFO, Color::Cyan, message)
    );
}

/// Displays a warning message with a yellow warning symbol prefix
pub fn log_warning<T: Display>(message: T) {
    eprintln!(
        "{}",
        theme::status_line(theme::G_WARN, Color::Yellow, message)
    );
}

/// Displays an error message with a red cross prefix
pub fn log_error<T: Display>(message: T) {
    eprintln!("{}", theme::status_line(theme::G_ERR, Color::Red, message));
}

/// Displays a debug message with a dimmed dot prefix for development purposes
#[allow(dead_code)]
pub fn log_debug<T: Display>(message: T) {
    eprintln!("{} {}", theme::G_DEBUG.dimmed(), message);
}

/// Returns a value formatted with color based on success status (green for success, red for failure)
#[allow(dead_code)]
pub fn format_value<T: Display>(value: T, is_success: bool) -> colored::ColoredString {
    if is_success {
        format!("{value}").green()
    } else {
        format!("{value}").red()
    }
}

/// Colorizes JWT token components for better visual distinction (header=cyan, payload=default, signature=yellow)
pub fn format_jwt_token(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() < 2 {
        return token.to_string();
    }

    if parts.len() == 2 {
        // Header and payload only
        return format!("{}.{}", parts[0].cyan(), parts[1]);
    }

    // Full JWT with signature
    format!("{}.{}.{}", parts[0].cyan(), parts[1], parts[2].yellow())
}

/// Creates an animated spinner with a custom color to indicate ongoing operations
///
/// Retained for API compatibility; the color argument is accepted but the shared
/// theme spinner uses the unified cyan accent so spinners look identical
/// everywhere.
pub fn start_progress_with_color(message: &str, _color: &str) -> indicatif::ProgressBar {
    theme::spinner(message)
}

/// Creates an animated spinner to indicate ongoing operations with the specified message
pub fn start_progress(message: &str) -> indicatif::ProgressBar {
    theme::spinner(message)
}

/// Converts a duration into human-readable format (hours, minutes, seconds)
#[allow(dead_code)]
pub fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();

    if seconds < 60 {
        return format!("{seconds}s");
    }

    let minutes = seconds / 60;
    let remain_seconds = seconds % 60;

    if minutes < 60 {
        return format!("{minutes}m {remain_seconds}s");
    }

    let hours = minutes / 60;
    let remain_minutes = minutes % 60;

    format!("{hours}h {remain_minutes}m {remain_seconds}s")
}

/// Compares two byte slices in constant time relative to their content.
///
/// Returns `false` immediately on a length mismatch (lengths are not secret), but
/// for equal-length inputs the comparison does not short-circuit on the first
/// differing byte, avoiding a timing side channel. Used for HMAC signature and
/// API-key comparisons.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Abbreviates a string to its first `head` and last `tail` characters joined by an
/// ellipsis. Operates on characters, never raw byte offsets, so multibyte input
/// (e.g. a pasted token containing non-ASCII bytes) cannot trigger a
/// non-char-boundary slice panic. Strings short enough to show in full are returned
/// unchanged.
pub fn abbreviate_middle(s: &str, head: usize, tail: usize) -> String {
    if s.chars().count() <= head + tail {
        return s.to_string();
    }
    let prefix: String = s.chars().take(head).collect();
    let suffix: String = {
        let mut t: Vec<char> = s.chars().rev().take(tail).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("{prefix}...{suffix}")
}

/// Formats a base64 encoded string for display with preview (shows first/last chars with length)
///
/// Operates on characters rather than raw byte offsets so that JWE/JWK components,
/// which are not guaranteed to be ASCII (they come unvalidated from attacker-controlled
/// tokens and remote JWKS endpoints), never trigger a non-char-boundary slice panic.
pub fn format_base64_preview(base64_str: &str) -> String {
    const PREVIEW_LEN: usize = 8;

    let char_count = base64_str.chars().count();
    if char_count <= PREVIEW_LEN * 2 {
        return base64_str.to_string();
    }

    let start: String = base64_str.chars().take(PREVIEW_LEN).collect();
    let end: String = {
        let mut tail: Vec<char> = base64_str.chars().rev().take(PREVIEW_LEN).collect();
        tail.reverse();
        tail.into_iter().collect()
    };

    format!("{}...{} ({} chars)", start, end, char_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::Colorize;
    use std::time::Duration;

    #[test]
    fn test_format_jwt_token_full() {
        let token = "header.payload.signature";
        let expected = format!("{}.{}.{}", "header".cyan(), "payload", "signature".yellow());
        assert_eq!(format_jwt_token(token), expected);
    }

    #[test]
    fn test_format_jwt_token_no_signature() {
        let token = "header.payload";
        let expected = format!("{}.{}", "header".cyan(), "payload");
        assert_eq!(format_jwt_token(token), expected);
    }

    #[test]
    fn test_format_jwt_token_invalid_format() {
        let token = "invalidtoken";
        assert_eq!(format_jwt_token(token), "invalidtoken");
    }

    #[test]
    fn test_format_jwt_token_empty_string() {
        let token = "";
        assert_eq!(format_jwt_token(token), "");
    }

    #[test]
    fn test_format_duration_util_seconds() {
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
    }

    #[test]
    fn test_format_duration_util_minutes_seconds() {
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 5s");
    }

    #[test]
    fn test_format_duration_util_hours_minutes_seconds() {
        assert_eq!(format_duration(Duration::from_secs(3723)), "1h 2m 3s");
    }

    #[test]
    fn test_format_duration_util_exact_minute() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
    }

    #[test]
    fn test_format_duration_util_exact_hour() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
    }

    #[test]
    fn test_format_duration_util_zero() {
        assert_eq!(format_duration(Duration::ZERO), "0s");
    }

    #[test]
    fn test_format_value_success() {
        let expected = "success_text".green();
        assert_eq!(format_value("success_text", true), expected);
    }

    #[test]
    fn test_format_value_failure() {
        let expected = "failure_text".red();
        assert_eq!(format_value("failure_text", false), expected);
    }

    #[test]
    fn test_format_value_integer() {
        let expected = "123".green(); // is_success = true
        assert_eq!(format_value(123, true), expected);

        let expected_fail = "456".red(); // is_success = false
        assert_eq!(format_value(456, false), expected_fail);
    }

    #[test]
    fn test_format_base64_preview_empty() {
        assert_eq!(format_base64_preview(""), "");
    }

    #[test]
    fn test_format_base64_preview_short() {
        let input = "SGVsbG8=";
        assert_eq!(format_base64_preview(input), input);
    }

    #[test]
    fn test_format_base64_preview_threshold() {
        let input = "1234567812345678";
        assert_eq!(format_base64_preview(input), input);
    }

    #[test]
    fn test_format_base64_preview_long() {
        let input = "1234567890abcdefg";
        let expected = "12345678...0abcdefg (17 chars)";
        assert_eq!(format_base64_preview(input), expected);
    }

    #[test]
    fn test_format_base64_preview_very_long() {
        let input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let expected = "ABCDEFGH...456789+/ (64 chars)";
        assert_eq!(format_base64_preview(input), expected);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secres"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_format_base64_preview_multibyte_no_panic() {
        // Non-ASCII input must not panic on a non-char-boundary byte slice.
        let input = "abcdefgé".repeat(4); // multibyte chars straddle the 8-byte preview offsets
        let preview = format_base64_preview(&input);
        assert!(preview.contains("..."));
        assert!(preview.contains("chars)"));
    }
}
