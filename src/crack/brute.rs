use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// Generate all possible combinations for brute force
pub fn generate_combinations(chars: &str, length: usize) -> Vec<String> {
    let char_vec: Vec<char> = chars.chars().collect();
    let mut result = Vec::new();

    // Start with empty string and build up
    let mut queue = VecDeque::new();
    queue.push_back(String::new());

    while let Some(current) = queue.pop_front() {
        if current.len() == length {
            result.push(current);
            continue;
        }

        // Add each possible character
        for &c in &char_vec {
            let mut new_str = current.clone();
            new_str.push(c);
            queue.push_back(new_str);
        }
    }

    result
}

/// Generate brute force payloads efficiently
pub fn generate_bruteforce_payloads(chars: &str, max_length: usize, progress: Option<Arc<Mutex<f64>>>) -> Vec<String> {
    let mut result = Vec::new();
    
    // Calculate total combinations for progress tracking
    let total_combinations: usize = (1..=max_length)
        .map(|len| chars.len().pow(len as u32))
        .sum();
    
    let mut completed = 0;
    
    // For each length, generate all combinations
    for length in 1..=max_length {
        let combinations = generate_combinations(chars, length);
        
        // Update progress if tracking is enabled
        if let Some(progress_tracker) = &progress {
            completed += combinations.len();
            let percentage = (completed as f64 / total_combinations as f64) * 100.0;
            *progress_tracker.lock().unwrap() = percentage;
        }
        
        result.extend(combinations);
    }
    
    result
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