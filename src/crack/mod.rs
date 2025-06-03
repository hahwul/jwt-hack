pub mod brute;

/// Generate bruteforce payloads based on a character set and maximum length
pub fn generate_bruteforce_payloads(chars: &str, max_length: usize) -> Vec<String> {
    // Initialize result with single character payloads
    let mut result: Vec<String> = chars.chars().map(|c| c.to_string()).collect();
    
    // Generate combinations of increasing length
    for length in 2..=max_length {
        let current_length_payloads = generate_combinations(chars, length);
        result.extend(current_length_payloads);
    }
    
    result
}

/// Generate all possible combinations of a specific length
fn generate_combinations(chars: &str, length: usize) -> Vec<String> {
    if length == 0 {
        return vec![String::new()];
    }
    
    let mut result = Vec::new();
    let substrings = generate_combinations(chars, length - 1);
    
    for c in chars.chars() {
        for substring in &substrings {
            let mut new_string = substring.clone();
            new_string.push(c);
            result.push(new_string);
        }
    }
    
    result
}

/// Read lines from a file or return the string as a single item if it's not a file
pub fn read_lines_or_literal(data: &str) -> Vec<String> {
    match std::fs::read_to_string(data) {
        Ok(content) => content.lines().map(|s| s.to_string()).collect(),
        Err(_) => vec![data.to_string()],
    }
}

/// Remove duplicate values from a vector
pub fn unique(vec: Vec<String>) -> Vec<String> {
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();
    
    for item in vec {
        if !seen.contains(&item) {
            seen.insert(item.clone());
            result.push(item);
        }
    }
    
    result
}