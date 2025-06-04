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
