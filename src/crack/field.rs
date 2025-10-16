use base64::Engine;
use rayon::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

/// Types of JWT fields that can be targeted for brute forcing
#[derive(Debug, Clone, PartialEq)]
pub enum FieldTarget {
    /// Header field (e.g., "kid", "jku", "x5u")
    Header(String),
    /// Payload/claims field (e.g., "jti", "sub", "user_id")
    Payload(String),
}

/// Options for field-specific brute forcing
pub struct FieldCrackOptions<'a> {
    pub token: &'a str,
    pub field_target: FieldTarget,
    pub charset: &'a str,
    pub max_length: usize,
    pub expected_pattern: Option<&'a str>,
}

/// Result of a successful field crack
#[derive(Debug, Clone)]
pub struct FieldCrackResult {
    pub field_name: String,
    pub field_location: String, // "header" or "payload"
    pub original_value: String,
    pub cracked_value: String,
    pub attempts: usize,
}

/// Generates candidate values for a specific field based on patterns
pub fn generate_field_candidates(
    charset: &str,
    max_length: usize,
    pattern: Option<&str>,
) -> Vec<String> {
    let mut candidates = Vec::new();

    // If pattern is provided, generate variations based on it
    if let Some(pattern_str) = pattern {
        // Generate variations: original, uppercase, lowercase
        candidates.push(pattern_str.to_string());
        candidates.push(pattern_str.to_uppercase());
        candidates.push(pattern_str.to_lowercase());

        // Add numbered variations (e.g., "user1", "user2", etc.)
        for i in 0..100 {
            candidates.push(format!("{}{}", pattern_str, i));
            candidates.push(format!("{}{}", pattern_str.to_uppercase(), i));
        }
    }

    // Generate brute force combinations
    let brute_force_payloads =
        super::brute::generate_bruteforce_payloads(charset, max_length, None);
    candidates.extend(brute_force_payloads);

    candidates
}

/// Attempt to crack a specific field in the JWT by trying different values
pub fn crack_field(
    options: &FieldCrackOptions,
    progress_callback: Option<Arc<dyn Fn(usize, usize) + Send + Sync>>,
) -> Result<Option<FieldCrackResult>, anyhow::Error> {
    // Parse the original token
    let parts: Vec<&str> = options.token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid JWT format"));
    }

    // Decode the header and payload
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow::anyhow!("Invalid header encoding"))?;
    let header_str = String::from_utf8(header_bytes)?;
    let mut header: HashMap<String, Value> = serde_json::from_str(&header_str)?;

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| anyhow::anyhow!("Invalid payload encoding"))?;
    let payload_str = String::from_utf8(payload_bytes)?;
    let mut payload: HashMap<String, Value> = serde_json::from_str(&payload_str)?;

    // Get the original field value
    let (field_map, field_location) = match &options.field_target {
        FieldTarget::Header(_name) => (&mut header, "header"),
        FieldTarget::Payload(_name) => (&mut payload, "payload"),
    };

    let field_name = match &options.field_target {
        FieldTarget::Header(name) | FieldTarget::Payload(name) => name.clone(),
    };

    let original_value = field_map
        .get(&field_name)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Generate candidate values
    let candidates = generate_field_candidates(
        options.charset,
        options.max_length,
        options.expected_pattern,
    );

    // Track progress
    let attempts = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(Mutex::new(None::<String>));
    let found_flag = Arc::new(AtomicBool::new(false));

    // Calculate optimal chunk size
    let num_threads = rayon::current_num_threads();
    let chunk_size = super::brute::calculate_optimal_chunk_size(candidates.len(), num_threads);

    // Try each candidate value in parallel
    candidates.par_chunks(chunk_size).for_each(|chunk| {
        // Early exit if already found
        if found_flag.load(Ordering::Relaxed) {
            return;
        }

        for candidate in chunk {
            if found_flag.load(Ordering::Relaxed) {
                break;
            }

            // Update the field with the candidate value
            let mut test_map = match &options.field_target {
                FieldTarget::Header(_) => header.clone(),
                FieldTarget::Payload(_) => payload.clone(),
            };
            test_map.insert(field_name.clone(), Value::String(candidate.clone()));

            // Rebuild the token with the new field value
            // Note: This is a simplified check - in real scenarios, you might want to
            // validate against specific patterns or external systems
            let is_valid = validate_field_value(candidate, &original_value);

            if is_valid {
                found_flag.store(true, Ordering::Relaxed);
                *found.lock().unwrap() = Some(candidate.clone());
                break;
            }
        }

        // Update progress
        let chunk_len = chunk.len();
        let current_attempts = attempts.fetch_add(chunk_len, Ordering::Relaxed) + chunk_len;

        if let Some(ref callback) = progress_callback {
            callback(current_attempts, candidates.len());
        }
    });

    // Return result if found
    let total_attempts = attempts.load(Ordering::Relaxed);
    let cracked_value = found.lock().unwrap().clone();
    
    if let Some(cracked) = cracked_value {
        Ok(Some(FieldCrackResult {
            field_name,
            field_location: field_location.to_string(),
            original_value,
            cracked_value: cracked,
            attempts: total_attempts,
        }))
    } else {
        Ok(None)
    }
}

/// Validate if a candidate field value matches expected criteria
/// This is a placeholder - real validation would depend on the application context
fn validate_field_value(candidate: &str, _original: &str) -> bool {
    // Simple validation: check if candidate is alphanumeric and within length limits
    // In a real scenario, this might involve API calls, database checks, etc.
    candidate.len() > 0 && candidate.len() <= 100 && candidate.chars().all(|c| c.is_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_field_candidates_with_pattern() {
        let candidates = generate_field_candidates("ab", 2, Some("user"));
        
        // Should include pattern variations
        assert!(candidates.contains(&"user".to_string()));
        assert!(candidates.contains(&"USER".to_string()));
        assert!(candidates.contains(&"user0".to_string()));
        assert!(candidates.contains(&"user1".to_string()));
        
        // Should also include brute force combinations
        assert!(candidates.contains(&"a".to_string()));
        assert!(candidates.contains(&"b".to_string()));
        assert!(candidates.contains(&"aa".to_string()));
    }

    #[test]
    fn test_generate_field_candidates_no_pattern() {
        let candidates = generate_field_candidates("abc", 2, None);
        
        // Should only include brute force combinations up to length 2
        assert!(candidates.contains(&"a".to_string()));
        assert!(candidates.contains(&"ab".to_string()));
        assert!(candidates.contains(&"ba".to_string()));
        
        // Total should be: 3 (length 1) + 9 (length 2) = 12
        assert_eq!(candidates.len(), 12);
    }

    #[test]
    fn test_validate_field_value() {
        assert!(validate_field_value("abc123", "original"));
        assert!(validate_field_value("user", "test"));
        assert!(!validate_field_value("", "test"));
        
        // Very long string should fail
        let long_string = "a".repeat(101);
        assert!(!validate_field_value(&long_string, "test"));
    }

    #[test]
    fn test_field_target_types() {
        let header_target = FieldTarget::Header("kid".to_string());
        let payload_target = FieldTarget::Payload("jti".to_string());
        
        assert_eq!(header_target, FieldTarget::Header("kid".to_string()));
        assert_eq!(payload_target, FieldTarget::Payload("jti".to_string()));
        assert_ne!(header_target, payload_target);
    }

    #[test]
    fn test_crack_field_invalid_token() {
        let options = FieldCrackOptions {
            token: "invalid.token",
            field_target: FieldTarget::Header("kid".to_string()),
            charset: "abc",
            max_length: 2,
            expected_pattern: None,
        };
        
        let result = crack_field(&options, None);
        assert!(result.is_err());
    }
}
