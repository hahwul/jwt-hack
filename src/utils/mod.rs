use colored::Colorize;
use std::fmt::Display;

/// Log a success message with a green plus icon
pub fn log_success<T: Display>(message: T) {
    println!("{} {}", "[+]".bright_green(), message);
}

/// Log an info message with a blue asterisk icon
pub fn log_info<T: Display>(message: T) {
    println!("{} {}", "[*]".bright_blue(), message);
}

/// Log a warning message with a yellow warning icon
pub fn log_warning<T: Display>(message: T) {
    println!("{} {}", "[!]".yellow(), message);
}

/// Log an error message with a red minus icon
pub fn log_error<T: Display>(message: T) {
    println!("{} {}", "[-]".bright_red(), message);
}

/// Log a debug message with a cyan question mark icon
#[allow(dead_code)]
pub fn log_debug<T: Display>(message: T) {
    println!("{} {}", "[?]".cyan(), message);
}

/// Format a value with specified color
#[allow(dead_code)]
pub fn format_value<T: Display>(value: T, is_success: bool) -> colored::ColoredString {
    if is_success {
        format!("{}", value).bright_green()
    } else {
        format!("{}", value).bright_red()
    }
}

/// Format a JWT token with colored segments
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

/// Show progress spinner for operations
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

/// Format a duration in a human-readable way
#[allow(dead_code)]
pub fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();

    if seconds < 60 {
        return format!("{}s", seconds);
    }

    let minutes = seconds / 60;
    let remain_seconds = seconds % 60;

    if minutes < 60 {
        return format!("{}m {}s", minutes, remain_seconds);
    }

    let hours = minutes / 60;
    let remain_minutes = minutes % 60;

    format!("{}h {}m {}s", hours, remain_minutes, remain_seconds)
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
}
