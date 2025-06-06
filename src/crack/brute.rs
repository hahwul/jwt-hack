use rayon::prelude::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

/// Generate all possible combinations for brute force in chunks for parallel processing
pub fn generate_combinations_chunked(
    chars: &str,
    length: usize,
    chunk_size: usize,
) -> impl Iterator<Item = Vec<String>> {
    let char_vec: Vec<char> = chars.chars().collect();
    let charset_size = char_vec.len();
    let total = charset_size.pow(length as u32);

    // Use a struct that implements Iterator to hold the state
    struct CombinationIter {
        char_vec: Vec<char>,
        length: usize,
        charset_size: usize,
        total: usize,
        chunk_size: usize,
        current_pos: usize,
    }

    impl Iterator for CombinationIter {
        type Item = Vec<String>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.current_pos >= self.total {
                return None;
            }

            let chunk_start = self.current_pos;
            let mut result = Vec::with_capacity(self.chunk_size.min(self.total - chunk_start));
            let mut indices = vec![0; self.length];

            // Calculate initial state for this chunk
            let mut pos = chunk_start;
            for i in (0..self.length).rev() {
                indices[i] = pos % self.charset_size;
                pos /= self.charset_size;
            }

            // Generate combinations for this chunk
            for _ in 0..self.chunk_size {
                if self.current_pos >= self.total {
                    break;
                }

                // Create string from current indices
                let combination: String = indices.iter().map(|&idx| self.char_vec[idx]).collect();

                result.push(combination);
                self.current_pos += 1;

                // Increment indices (like counting in base charset_size)
                for i in (0..self.length).rev() {
                    indices[i] += 1;
                    if indices[i] < self.charset_size {
                        break;
                    }
                    indices[i] = 0;
                    // Continue to next digit if we wrapped around
                }
            }

            if result.is_empty() {
                None
            } else {
                Some(result)
            }
        }
    }

    CombinationIter {
        char_vec,
        length,
        charset_size,
        total,
        chunk_size,
        current_pos: 0,
    }
}

/// Generate brute force payloads efficiently using parallel processing
pub fn generate_bruteforce_payloads(
    chars: &str,
    max_length: usize,
    progress: Option<Arc<Mutex<f64>>>,
) -> Vec<String> {
    const CHUNK_SIZE: usize = 10000; // Adjust based on experimentation
    let result = Arc::new(Mutex::new(Vec::new()));

    // Calculate total combinations for progress tracking
    let total_combinations: usize = (1..=max_length)
        .map(|len| chars.len().pow(len as u32))
        .sum();

    let completed = Arc::new(AtomicUsize::new(0));

    // Process each length in parallel
    (1..=max_length).into_par_iter().for_each(|length| {
        let local_completed = Arc::clone(&completed);
        let local_progress = progress.clone();
        let local_result = Arc::clone(&result);
        let mut combinations = Vec::new();

        // Process chunks of combinations for this length
        for chunk in generate_combinations_chunked(chars, length, CHUNK_SIZE) {
            combinations.extend(chunk.clone());

            // Update progress if tracking is enabled
            if let Some(ref progress_tracker) = local_progress {
                let chunk_size = chunk.len();
                let prev = local_completed.fetch_add(chunk_size, Ordering::Relaxed);

                // Don't update too frequently to avoid lock contention
                if prev % 50000 < chunk_size {
                    let percentage = (prev + chunk_size) as f64 / total_combinations as f64 * 100.0;
                    *progress_tracker.lock().unwrap() = percentage;
                }
            }
        }

        // Critical section: append to main result
        let mut main_result = local_result.lock().unwrap();
        main_result.extend(combinations);
    });

    Arc::try_unwrap(result).unwrap().into_inner().unwrap()
}

/// Estimate the total number of combinations for a given charset and max length
pub fn estimate_combinations(charset_len: usize, max_len: usize) -> u64 {
    let mut total: u64 = 0;

    for length in 1..=max_len {
        // For each length, we have charset_len^length combinations
        let combinations = (charset_len as u64).pow(length as u32);
        total += combinations;
    }

    total
}

/// Calculate an estimated time remaining based on progress and elapsed time
#[allow(dead_code)]
pub fn estimate_time_remaining(progress_percent: f64, elapsed_seconds: f64) -> f64 {
    if progress_percent <= 0.0 {
        return 0.0;
    }

    let remaining_percent = 100.0 - progress_percent;
    let time_per_percent = elapsed_seconds / progress_percent;

    remaining_percent * time_per_percent
}

/// Format seconds into a human-readable time string (HH:MM:SS)
#[allow(dead_code)]
pub fn format_time(seconds: f64) -> String {
    let hours = (seconds / 3600.0).floor();
    let minutes = ((seconds % 3600.0) / 60.0).floor();
    let secs = (seconds % 60.0).floor();

    format!(
        "{:02}:{:02}:{:02}",
        hours as u64, minutes as u64, secs as u64
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_combinations_chunked_simple() {
        let chars = "ab";
        let length = 2;
        let chunk_size = 1;
        let mut all_combinations = Vec::new();

        for chunk in generate_combinations_chunked(chars, length, chunk_size) {
            all_combinations.extend(chunk);
        }

        all_combinations.sort(); // Sort for consistent comparison

        let expected = ["aa", "ab", "ba", "bb"];
        assert_eq!(all_combinations.len(), 4);
        assert_eq!(
            all_combinations,
            expected
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn test_generate_combinations_chunked_larger_chunks() {
        let chars = "a";
        let length = 3;
        let chunk_size = 10; // Larger than total combinations
        let mut all_combinations = Vec::new();

        for chunk in generate_combinations_chunked(chars, length, chunk_size) {
            all_combinations.extend(chunk);
        }

        let expected = ["aaa"];
        assert_eq!(all_combinations.len(), 1);
        assert_eq!(
            all_combinations,
            expected
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn test_estimate_combinations_simple() {
        assert_eq!(estimate_combinations(2, 2), 6); // 2^1 + 2^2 = 2 + 4 = 6
    }

    #[test]
    fn test_estimate_combinations_single_char() {
        assert_eq!(estimate_combinations(1, 3), 3); // 1^1 + 1^2 + 1^3 = 1 + 1 + 1 = 3
    }

    #[test]
    fn test_estimate_combinations_zero_length() {
        assert_eq!(estimate_combinations(3, 0), 0);
    }

    #[test]
    fn test_estimate_time_remaining_half_done() {
        let result = estimate_time_remaining(50.0, 10.0);
        let expected = 10.0;
        assert!(
            (result - expected).abs() < 1e-9,
            "Expected approx 10.0, got {}",
            result
        );
    }

    #[test]
    fn test_estimate_time_remaining_zero_progress() {
        assert_eq!(estimate_time_remaining(0.0, 10.0), 0.0);
    }

    #[test]
    fn test_estimate_time_remaining_full_progress() {
        assert_eq!(estimate_time_remaining(100.0, 10.0), 0.0);
    }

    #[test]
    fn test_format_time_seconds() {
        assert_eq!(format_time(30.0), "00:00:30");
    }

    #[test]
    fn test_format_time_minutes_seconds() {
        assert_eq!(format_time(90.0), "00:01:30");
    }

    #[test]
    fn test_format_time_hours_minutes_seconds() {
        assert_eq!(format_time(3661.0), "01:01:01");
    }

    #[test]
    fn test_format_time_zero() {
        assert_eq!(format_time(0.0), "00:00:00");
    }
}
