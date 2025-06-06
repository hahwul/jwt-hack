pub mod brute;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Generate bruteforce payloads based on a character set and maximum length
#[allow(dead_code)]
pub fn generate_bruteforce_payloads(chars: &str, max_length: usize) -> Vec<String> {
    // Use the optimized implementation from brute module
    let progress = Arc::new(Mutex::new(0.0));
    brute::generate_bruteforce_payloads(chars, max_length, Some(progress))
}

/// Generate bruteforce payloads with progress reporting
pub fn generate_bruteforce_payloads_with_progress<F>(
    chars: &str,
    max_length: usize,
    progress_callback: F,
) -> Vec<String>
where
    F: Fn(f64, Duration) + Send + Sync + Clone + 'static,
{
    let progress = Arc::new(Mutex::new(0.0));
    let start_time = Instant::now();

    // Spawn a thread to monitor progress
    let progress_clone = Arc::clone(&progress);
    let callback = progress_callback.clone();
    let monitor_handle = std::thread::spawn(move || {
        let mut last_progress = 0.0;
        while last_progress < 100.0 {
            std::thread::sleep(Duration::from_millis(100));
            let current_progress = *progress_clone.lock().unwrap();
            let progress_diff = if current_progress > last_progress {
                current_progress - last_progress
            } else {
                last_progress - current_progress
            };

            if progress_diff > 0.1 {
                // Only call back when progress changes meaningfully
                callback(current_progress, start_time.elapsed());
                last_progress = current_progress;
            }
        }
    });

    // Generate the payloads
    let result =
        brute::generate_bruteforce_payloads(chars, max_length, Some(Arc::clone(&progress)));

    // Ensure 100% progress is reported
    *progress.lock().unwrap() = 100.0;
    progress_callback(100.0, start_time.elapsed());

    // Wait for monitor thread to finish
    let _ = monitor_handle.join();

    result
}

/// Chunked generation of combinations for memory efficiency
#[allow(dead_code)]
fn generate_combinations(chars: &str, length: usize) -> Vec<String> {
    if length == 0 {
        return vec![String::new()];
    } else if length == 1 {
        // Optimization for single-character case
        return chars.chars().map(|c| c.to_string()).collect();
    }

    // For longer combinations, use the optimized parallel approach
    let chunk_size = 10000;
    let mut result = Vec::new();

    for chunk in brute::generate_combinations_chunked(chars, length, chunk_size) {
        result.extend(chunk);
    }

    result
}

/// Read lines from a file or return the string as a single item if it's not a file
#[allow(dead_code)]
pub fn read_lines_or_literal(data: &str) -> Vec<String> {
    match std::fs::read_to_string(data) {
        Ok(content) => content.lines().map(|s| s.to_string()).collect(),
        Err(_) => vec![data.to_string()],
    }
}

/// Remove duplicate values from a vector
#[allow(dead_code)]
pub fn unique(vec: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(vec.len());

    for item in vec {
        if seen.insert(item.clone()) {
            result.push(item);
        }
    }

    result
}

/// Format a duration into a human-readable string
#[allow(dead_code)]
pub fn format_duration(duration: Duration) -> String {
    brute::format_time(duration.as_secs_f64())
}

/// Estimate time remaining based on progress percentage and elapsed time
#[allow(dead_code)]
pub fn estimate_remaining_time(progress_percent: f64, elapsed: Duration) -> String {
    let remaining_secs = brute::estimate_time_remaining(progress_percent, elapsed.as_secs_f64());
    brute::format_time(remaining_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    // Removed std::fs::File as it's unused
    use std::time::Duration;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_bruteforce_payloads_simple() {
        let chars = "a";
        let max_length = 2;
        let mut result = generate_bruteforce_payloads(chars, max_length);
        result.sort(); // Sort for consistent comparison
        let mut expected = vec!["a".to_string(), "aa".to_string()];
        expected.sort();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_generate_bruteforce_payloads_empty_chars() {
        let chars = "";
        let max_length = 3;
        let result = generate_bruteforce_payloads(chars, max_length);
        assert!(
            result.is_empty(),
            "Expected empty vector for empty charset, got {:?}",
            result
        );
    }

    #[test]
    fn test_generate_bruteforce_payloads_zero_max_length() {
        let chars = "ab";
        let max_length = 0;
        let result = generate_bruteforce_payloads(chars, max_length);
        assert!(
            result.is_empty(),
            "Expected empty vector for max_length 0, got {:?}",
            result
        );
    }

    #[test]
    fn test_read_lines_or_literal_literal() {
        let result = read_lines_or_literal("test_string");
        assert_eq!(result, vec!["test_string".to_string()]);
    }

    #[test]
    fn test_read_lines_or_literal_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "line1").unwrap();
        writeln!(temp_file, "line2").unwrap();

        let result = read_lines_or_literal(temp_file.path().to_str().unwrap());
        assert_eq!(result, vec!["line1".to_string(), "line2".to_string()]);
    }

    #[test]
    fn test_read_lines_or_literal_file_not_exists() {
        let result = read_lines_or_literal("non_existent_file_for_sure.txt");
        assert_eq!(result, vec!["non_existent_file_for_sure.txt".to_string()]);
    }

    #[test]
    fn test_unique_empty() {
        let input: Vec<String> = Vec::new();
        let result = unique(input);
        assert!(result.is_empty(), "Expected empty vector for empty input");
    }

    #[test]
    fn test_unique_no_duplicates() {
        let input = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let result = unique(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_unique_with_duplicates() {
        let input = vec![
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
            "c".to_string(),
            "b".to_string(),
            "a".to_string(),
        ];
        let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let result = unique(input);
        assert_eq!(
            result, expected,
            "Duplicates were not removed correctly or order changed"
        );
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(5)), "00:00:05");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(125)), "00:02:05"); // 2 minutes and 5 seconds
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3661)), "01:01:01"); // 1 hour, 1 minute, 1 second
    }

    // It seems format_duration(Duration::from_secs(0)) was not explicitly requested,
    // but it's good practice. The underlying brute::format_time(0.0) is tested, which covers this.
    // Adding one for Duration::ZERO for completeness of `format_duration` specific tests.
    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(Duration::ZERO), "00:00:00");
    }
}
