use rayon::prelude::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

/// Generates combinations of characters efficiently in chunks to support parallel processing
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

/// Creates all possible brute force combinations using parallel processing for better performance
pub fn generate_bruteforce_payloads(
    chars: &str,
    max_length: usize,
    progress: Option<Arc<Mutex<f64>>>,
) -> Vec<String> {
    const CHUNK_SIZE: usize = 10000; // Chunk size optimized for memory usage and parallelism
    let result = Arc::new(Mutex::new(Vec::new()));

    // Calculate total number of combinations for accurate progress reporting
    let total_combinations: usize = (1..=max_length)
        .map(|len| chars.len().pow(len as u32))
        .sum();

    let completed = Arc::new(AtomicUsize::new(0));

    // Process combinations of each length in parallel for better performance
    (1..=max_length).into_par_iter().for_each(|length| {
        let local_completed = Arc::clone(&completed);
        let local_progress = progress.clone();
        let local_result = Arc::clone(&result);
        let mut combinations = Vec::new();

        // Generate and process combinations in manageable chunks
        for chunk in generate_combinations_chunked(chars, length, CHUNK_SIZE) {
            combinations.extend(chunk.clone());

            // Update progress tracker with current completion percentage
            if let Some(ref progress_tracker) = local_progress {
                let chunk_size = chunk.len();
                let prev = local_completed.fetch_add(chunk_size, Ordering::Relaxed);

                // Update periodically rather than every chunk to reduce lock contention
                if prev % 50000 < chunk_size {
                    let percentage = (prev + chunk_size) as f64 / total_combinations as f64 * 100.0;
                    *progress_tracker.lock().unwrap_or_else(|e| e.into_inner()) = percentage;
                }
            }
        }

        // Thread-safe update of the shared result collection
        let mut main_result = local_result.lock().unwrap_or_else(|e| e.into_inner());
        main_result.extend(combinations);
    });

    Arc::try_unwrap(result)
        .unwrap_or_else(|arc| {
            // If other references exist, clone the inner data
            let guard = arc.lock().unwrap_or_else(|e| e.into_inner());
            std::sync::Mutex::new(guard.clone())
        })
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
}

/// Convert a charset string into a vector of per-character UTF-8 byte slices.
///
/// Used by the index-based brute force path so each candidate can be assembled
/// directly into a reusable byte buffer without allocating a fresh String.
pub fn charset_bytes(chars: &str) -> Vec<Vec<u8>> {
    chars
        .chars()
        .map(|c| {
            let mut buf = [0u8; 4];
            c.encode_utf8(&mut buf).as_bytes().to_vec()
        })
        .collect()
}

/// Maximum candidate length supported by [`write_candidate_bytes`].
/// Brute-forcing past this is computationally infeasible anyway.
pub const MAX_BRUTE_LENGTH: usize = 64;

/// Write the `idx`-th combination of `length` characters from `char_bytes`
/// into `out`. `out` is cleared first; no allocation occurs once `out` has
/// sufficient capacity. Iteration order matches the original
/// [`generate_combinations_chunked`] (lexicographic over charset indices).
pub fn write_candidate_bytes(idx: u64, char_bytes: &[Vec<u8>], length: usize, out: &mut Vec<u8>) {
    debug_assert!(length <= MAX_BRUTE_LENGTH);
    out.clear();
    let charset_size = char_bytes.len() as u64;
    let mut indices = [0u32; MAX_BRUTE_LENGTH];
    let mut n = idx;
    for i in (0..length).rev() {
        indices[i] = (n % charset_size) as u32;
        n /= charset_size;
    }
    for &i in indices.iter().take(length) {
        out.extend_from_slice(&char_bytes[i as usize]);
    }
}

/// Calculates the total number of possible combinations based on charset length
/// and a length range `min_len..=max_len`.
pub fn estimate_combinations(charset_len: usize, min_len: usize, max_len: usize) -> u64 {
    let mut total: u64 = 0;

    for length in min_len..=max_len {
        // Sum up number of combinations for each length (charset_len^length)
        let combinations = (charset_len as u64).pow(length as u32);
        total += combinations;
    }

    total
}

/// Calculates estimated completion time based on current progress and elapsed time
#[allow(dead_code)]
pub fn estimate_time_remaining(progress_percent: f64, elapsed_seconds: f64) -> f64 {
    if progress_percent <= 0.0 {
        return 0.0;
    }

    let remaining_percent = 100.0 - progress_percent;
    let time_per_percent = elapsed_seconds / progress_percent;

    remaining_percent * time_per_percent
}

/// Converts seconds into human-readable time format (HH:MM:SS)
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
    fn test_write_candidate_bytes_matches_chunked() {
        // Reference output from the legacy chunked iterator.
        let chars = "abc";
        let length = 3;
        let mut reference: Vec<String> = Vec::new();
        for chunk in generate_combinations_chunked(chars, length, 1) {
            reference.extend(chunk);
        }

        // New byte-based path must produce identical candidates in the same order.
        let char_bytes = charset_bytes(chars);
        let total = (char_bytes.len() as u64).pow(length as u32);
        let mut buf = Vec::with_capacity(length * 4);
        let mut produced: Vec<String> = Vec::new();
        for idx in 0..total {
            write_candidate_bytes(idx, &char_bytes, length, &mut buf);
            produced.push(std::str::from_utf8(&buf).unwrap().to_string());
        }
        assert_eq!(reference, produced);
    }

    #[test]
    fn test_write_candidate_bytes_multibyte() {
        let chars = "한글";
        let char_bytes = charset_bytes(chars);
        let mut buf = Vec::new();
        write_candidate_bytes(0, &char_bytes, 1, &mut buf);
        assert_eq!(buf.as_slice(), "한".as_bytes());
        write_candidate_bytes(1, &char_bytes, 1, &mut buf);
        assert_eq!(buf.as_slice(), "글".as_bytes());
        write_candidate_bytes(3, &char_bytes, 2, &mut buf);
        // idx 3 = 11 in base-2 → "글글"
        assert_eq!(buf.as_slice(), "글글".as_bytes());
    }

    #[test]
    fn test_estimate_combinations_simple() {
        assert_eq!(estimate_combinations(2, 1, 2), 6); // 2^1 + 2^2 = 2 + 4 = 6
    }

    #[test]
    fn test_estimate_combinations_single_char() {
        assert_eq!(estimate_combinations(1, 1, 3), 3); // 1^1 + 1^2 + 1^3 = 1 + 1 + 1 = 3
    }

    #[test]
    fn test_estimate_combinations_min_length() {
        // Only length 3: 2^3 = 8
        assert_eq!(estimate_combinations(2, 3, 3), 8);
        // Lengths 2..=3: 2^2 + 2^3 = 4 + 8 = 12
        assert_eq!(estimate_combinations(2, 2, 3), 12);
    }

    #[test]
    fn test_estimate_combinations_zero_length() {
        assert_eq!(estimate_combinations(3, 1, 0), 0);
    }

    #[test]
    fn test_estimate_time_remaining_half_done() {
        let result = estimate_time_remaining(50.0, 10.0);
        let expected = 10.0;
        assert!(
            (result - expected).abs() < 1e-9,
            "Expected approx 10.0, got {result}"
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
