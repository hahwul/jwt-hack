use colored::Colorize;
use std::fmt::Display;

pub mod compression;

/// Displays a success message with a green plus icon prefix
pub fn log_success<T: Display>(message: T) {
    println!("{} {}", "[+]".bright_green(), message);
}

/// Displays an information message with a blue asterisk icon prefix
pub fn log_info<T: Display>(message: T) {
    println!("{} {}", "[*]".bright_blue(), message);
}

/// Displays a warning message with a yellow exclamation mark prefix
pub fn log_warning<T: Display>(message: T) {
    println!("{} {}", "[!]".yellow(), message);
}

/// Displays an error message with a red minus icon prefix
pub fn log_error<T: Display>(message: T) {
    println!("{} {}", "[-]".bright_red(), message);
}

/// Displays a debug message with a cyan question mark prefix for development purposes
#[allow(dead_code)]
pub fn log_debug<T: Display>(message: T) {
    println!("{} {}", "[?]".cyan(), message);
}

/// Returns a value formatted with color based on success status (green for success, red for failure)
#[allow(dead_code)]
pub fn format_value<T: Display>(value: T, is_success: bool) -> colored::ColoredString {
    if is_success {
        format!("{value}").bright_green()
    } else {
        format!("{value}").bright_red()
    }
}

/// Colorizes JWT token components for better visual distinction (header=blue, payload=magenta, signature=yellow)
pub fn format_jwt_token(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() < 2 {
        return token.to_string();
    }

    if parts.len() == 2 {
        // Header and payload only
        return format!("{}.{}", parts[0].bright_blue(), parts[1].bright_magenta());
    }

    // Full JWT with signature
    format!(
        "{}.{}.{}",
        parts[0].bright_blue(),
        parts[1].bright_magenta(),
        parts[2].bright_yellow()
    )
}

/// Creates an animated spinner to indicate ongoing operations with the specified message
pub fn start_progress(message: &str) -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_style(
        indicatif::ProgressStyle::default_spinner()
            .template("{spinner:.blue} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
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

/// Formats a base64 encoded string for display with preview (shows first/last chars with length)
pub fn format_base64_preview(base64_str: &str) -> String {
    const PREVIEW_LEN: usize = 8;

    if base64_str.len() <= PREVIEW_LEN * 2 {
        return base64_str.to_string();
    }

    let start = &base64_str[..PREVIEW_LEN];
    let end = &base64_str[base64_str.len() - PREVIEW_LEN..];
    let length = base64_str.len();

    format!("{}...{} ({} chars)", start, end, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use colored::Colorize;
    use std::time::Duration;

    #[test]
    fn test_format_jwt_token_full() {
        let token = "header.payload.signature";
        let expected = format!(
            "{}.{}.{}",
            "header".bright_blue(),
            "payload".bright_magenta(),
            "signature".bright_yellow()
        );
        assert_eq!(format_jwt_token(token), expected);
    }

    #[test]
    fn test_format_jwt_token_no_signature() {
        let token = "header.payload";
        let expected = format!("{}.{}", "header".bright_blue(), "payload".bright_magenta());
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
        let expected = "success_text".bright_green();
        assert_eq!(format_value("success_text", true), expected);
    }

    #[test]
    fn test_format_value_failure() {
        let expected = "failure_text".bright_red();
        assert_eq!(format_value("failure_text", false), expected);
    }

    #[test]
    fn test_format_value_integer() {
        let expected = "123".bright_green(); // is_success = true
        assert_eq!(format_value(123, true), expected);

        let expected_fail = "456".bright_red(); // is_success = false
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
}
