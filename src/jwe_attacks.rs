/// Module for JWE-specific attack capabilities
use anyhow::{anyhow, Result};
use base64::Engine;
use colored::Colorize;

/// Detect potential padding oracle vulnerabilities in JWE implementations
///
/// This function analyzes a JWE token to detect characteristics that may indicate
/// susceptibility to padding oracle attacks, particularly with CBC mode encryption.
pub fn detect_padding_oracle_vulnerability(token: &str) -> Result<Vec<String>> {
    use crate::jwt;

    let decoded = jwt::decode_jwe(token)?;
    let mut warnings = Vec::new();

    // Check if using CBC mode (vulnerable to padding oracle attacks)
    match decoded.encryption.as_str() {
        "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" => {
            warnings.push(format!(
                "⚠️  CRITICAL: {} uses CBC mode - potentially vulnerable to padding oracle attacks",
                decoded.encryption.red().bold()
            ));
            warnings.push(
                "   Attack: Send modified ciphertext and observe error responses".to_string(),
            );
            warnings.push("   If server returns different errors for padding vs MAC failures, it may be exploitable".to_string());
        }
        "A128GCM" | "A256GCM" => {
            warnings.push(format!(
                "✓ {} uses GCM mode - not vulnerable to classic padding oracle attacks",
                decoded.encryption.green()
            ));
        }
        _ => {
            warnings.push(format!(
                "⚠️  Unknown encryption algorithm: {}",
                decoded.encryption
            ));
        }
    }

    // Check for potential timing attack vectors
    if decoded.algorithm == "RSA-OAEP" || decoded.algorithm == "RSA-OAEP-256" {
        warnings.push("⚠️  RSA key wrapping - may be vulnerable to timing attacks".to_string());
    }

    // Check authentication tag length
    if !decoded.tag.is_empty() {
        if let Ok(tag_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&decoded.tag)
        {
            if tag_bytes.len() < 16 {
                warnings.push(
                    "⚠️  Short authentication tag - may indicate weak implementation".to_string(),
                );
            }
        }
    }

    Ok(warnings)
}

/// Generate test payloads for padding oracle attacks
///
/// Creates modified JWE tokens to test server responses for padding oracle vulnerabilities
pub fn generate_padding_oracle_payloads(token: &str) -> Result<Vec<String>> {
    use crate::jwt;

    let decoded = jwt::decode_jwe(token)?;
    let mut payloads = Vec::new();

    // Only generate payloads for CBC mode
    if !decoded.encryption.contains("CBC") {
        return Err(anyhow!(
            "Padding oracle attacks only apply to CBC mode encryption"
        ));
    }

    // Original token for baseline
    payloads.push(token.to_string());

    // Preserve the original header part to avoid re-serialization issues
    let parts: Vec<&str> = token.split('.').collect();
    let original_header = parts[0];

    // Decode ciphertext and IV once for all mutations
    let ciphertext_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&decoded.ciphertext)?;
    let iv_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&decoded.iv)?;

    // Helper to reassemble a JWE token from parts
    let reassemble = |header: &str, ek: &str, iv: &str, ct: &str, tag: &str| -> String {
        format!("{header}.{ek}.{iv}.{ct}.{tag}")
    };

    // Modify last byte of ciphertext (affects padding)
    if !ciphertext_bytes.is_empty() {
        let mut modified = ciphertext_bytes.clone();
        if let Some(last) = modified.last_mut() {
            *last ^= 0x01;
        }
        let ct = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modified);
        payloads.push(reassemble(
            original_header,
            &decoded.encrypted_key,
            &decoded.iv,
            &ct,
            &decoded.tag,
        ));
    }

    // Truncate ciphertext to test padding validation
    if ciphertext_bytes.len() > 16 {
        let mut modified = ciphertext_bytes.clone();
        modified.truncate(modified.len() - 8);
        let ct = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modified);
        payloads.push(reassemble(
            original_header,
            &decoded.encrypted_key,
            &decoded.iv,
            &ct,
            &decoded.tag,
        ));
    }

    // Flip first byte of ciphertext (affects first block)
    if !ciphertext_bytes.is_empty() {
        let mut modified = ciphertext_bytes.clone();
        modified[0] ^= 0xFF;
        let ct = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modified);
        payloads.push(reassemble(
            original_header,
            &decoded.encrypted_key,
            &decoded.iv,
            &ct,
            &decoded.tag,
        ));
    }

    // Replace entire last block with zeros (16-byte block boundary)
    if ciphertext_bytes.len() >= 16 {
        let mut modified = ciphertext_bytes.clone();
        let start = modified.len() - 16;
        modified[start..].fill(0x00);
        let ct = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modified);
        payloads.push(reassemble(
            original_header,
            &decoded.encrypted_key,
            &decoded.iv,
            &ct,
            &decoded.tag,
        ));
    }

    // Modify IV to test CBC chaining (affects first plaintext block)
    if !iv_bytes.is_empty() {
        let mut modified = iv_bytes.clone();
        modified[0] ^= 0x01;
        let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modified);
        payloads.push(reassemble(
            original_header,
            &decoded.encrypted_key,
            &iv,
            &decoded.ciphertext,
            &decoded.tag,
        ));
    }

    Ok(payloads)
}

/// Analyze server response patterns for padding oracle indicators
///
/// This function helps identify if a server may be vulnerable to padding oracle attacks
/// by analyzing response characteristics
pub fn analyze_response_for_oracle(
    response_time_ms: u64,
    status_code: u16,
    error_message: Option<&str>,
) -> Vec<String> {
    analyze_response_for_oracle_with_baseline(response_time_ms, status_code, error_message, None)
}

/// Analyze server response patterns with optional baseline timing data.
///
/// When `baseline_times_ms` is provided, uses statistical comparison (mean + 2*stddev)
/// to detect timing anomalies. Otherwise falls back to a fixed 100ms threshold.
pub fn analyze_response_for_oracle_with_baseline(
    response_time_ms: u64,
    status_code: u16,
    error_message: Option<&str>,
    baseline_times_ms: Option<&[u64]>,
) -> Vec<String> {
    let mut indicators = Vec::new();

    // Check for timing differences (potential timing side-channel)
    match baseline_times_ms {
        Some(baselines) if baselines.len() >= 2 => {
            let n = baselines.len() as f64;
            let mean = baselines.iter().sum::<u64>() as f64 / n;
            let variance = baselines
                .iter()
                .map(|&t| {
                    let diff = t as f64 - mean;
                    diff * diff
                })
                .sum::<f64>()
                / n;
            let stddev = variance.sqrt();
            let threshold = mean + 2.0 * stddev.max(5.0); // min stddev of 5ms to avoid false positives

            if (response_time_ms as f64) > threshold {
                indicators.push(format!(
                    "⚠️  Timing anomaly: {}ms (baseline: {:.1}ms ± {:.1}ms, threshold: {:.1}ms)",
                    response_time_ms, mean, stddev, threshold
                ));
            }
        }
        _ => {
            if response_time_ms > 100 {
                indicators.push(format!(
                    "⚠️  Slow response ({}ms) - may indicate server-side processing differences",
                    response_time_ms
                ));
            }
        }
    }

    // Check for detailed error messages that leak information
    if let Some(msg) = error_message {
        let msg_lower = msg.to_lowercase();
        if msg_lower.contains("padding") {
            indicators.push(
                "🚨 PADDING ERROR DETECTED - Strong oracle indicator!"
                    .red()
                    .bold()
                    .to_string(),
            );
        } else if msg_lower.contains("mac") || msg_lower.contains("authentication") {
            indicators
                .push("⚠️  MAC/Authentication error - Different from padding error".to_string());
        } else if msg_lower.contains("decrypt") {
            indicators.push("⚠️  Generic decryption error - May hide oracle".to_string());
        }
    }

    // Analyze status codes
    match status_code {
        400 => indicators.push("Status 400 - Bad Request (common for padding errors)".to_string()),
        401 => indicators.push("Status 401 - Unauthorized (may indicate MAC failure)".to_string()),
        500 => indicators.push("⚠️  Status 500 - Server error may leak information".to_string()),
        _ => {}
    }

    if indicators.is_empty() {
        indicators.push("No obvious oracle indicators detected".to_string());
    }

    indicators
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_padding_oracle_vulnerability() {
        let jwe_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..ZHVtbXlfaXZfMTIzNDU2.eyJzdWIiOiJ0ZXN0In0.ZHVtbXlfdGFn";
        let result = detect_padding_oracle_vulnerability(jwe_token);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(!warnings.is_empty(), "Should detect CBC mode vulnerability");
    }

    #[test]
    fn test_generate_padding_oracle_payloads() {
        let jwe_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..ZHVtbXlfaXZfMTIzNDU2.eyJzdWIiOiJ0ZXN0In0.ZHVtbXlfdGFn";
        let result = generate_padding_oracle_payloads(jwe_token);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert!(payloads.len() > 1, "Should generate multiple payloads");
    }

    #[test]
    fn test_analyze_response_for_oracle() {
        let indicators = analyze_response_for_oracle(50, 400, Some("Invalid padding"));
        assert!(!indicators.is_empty());
        assert!(indicators.iter().any(|i| i.contains("PADDING")));
    }

    #[test]
    fn test_analyze_response_timing() {
        let indicators = analyze_response_for_oracle(150, 200, None);
        assert!(indicators.iter().any(|i| i.contains("Slow response")));
    }

    #[test]
    fn test_detect_gcm_mode_not_vulnerable() {
        // GCM mode header: {"alg":"dir","enc":"A256GCM"}
        let jwe_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZHVtbXlfaXZfMTIzNDU2.eyJzdWIiOiJ0ZXN0In0.ZHVtbXlfdGFn";
        let result = detect_padding_oracle_vulnerability(jwe_token);
        assert!(result.is_ok());
        let warnings = result.unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("GCM") && w.contains("not vulnerable")),
            "GCM mode should be reported as not vulnerable"
        );
    }

    #[test]
    fn test_generate_padding_oracle_payloads_gcm_rejected() {
        // GCM mode should be rejected for padding oracle payloads
        let jwe_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZHVtbXlfaXZfMTIzNDU2.eyJzdWIiOiJ0ZXN0In0.ZHVtbXlfdGFn";
        let result = generate_padding_oracle_payloads(jwe_token);
        assert!(
            result.is_err(),
            "GCM mode should not generate padding oracle payloads"
        );
    }

    #[test]
    fn test_generate_padding_oracle_payloads_count() {
        // CBC token should generate: original + bit flip + truncate + first byte flip + zero block + IV modify = 6
        let jwe_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..ZHVtbXlfaXZfMTIzNDU2.eyJzdWIiOiJ0ZXN0In0.ZHVtbXlfdGFn";
        let result = generate_padding_oracle_payloads(jwe_token);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert!(
            payloads.len() >= 4,
            "Should generate at least 4 payloads (original + 3 modifications), got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_analyze_response_mac_error() {
        let indicators = analyze_response_for_oracle(50, 401, Some("MAC verification failed"));
        assert!(indicators.iter().any(|i| i.contains("MAC")));
    }

    #[test]
    fn test_analyze_response_decrypt_error() {
        let indicators = analyze_response_for_oracle(50, 500, Some("Decryption failed"));
        assert!(indicators.iter().any(|i| i.contains("decryption")));
        assert!(indicators.iter().any(|i| i.contains("500")));
    }

    #[test]
    fn test_analyze_response_no_indicators() {
        let indicators = analyze_response_for_oracle(50, 200, None);
        assert!(indicators.iter().any(|i| i.contains("No obvious oracle")));
    }

    #[test]
    fn test_analyze_response_with_baseline_normal() {
        let baselines = vec![50, 52, 48, 51, 49];
        let indicators = analyze_response_for_oracle_with_baseline(55, 200, None, Some(&baselines));
        // 55ms is within normal range of ~50ms baseline, should not trigger
        assert!(
            !indicators.iter().any(|i| i.contains("Timing anomaly")),
            "Normal response should not trigger timing anomaly"
        );
    }

    #[test]
    fn test_analyze_response_with_baseline_anomaly() {
        let baselines = vec![50, 52, 48, 51, 49];
        let indicators =
            analyze_response_for_oracle_with_baseline(200, 200, None, Some(&baselines));
        assert!(
            indicators.iter().any(|i| i.contains("Timing anomaly")),
            "200ms response against ~50ms baseline should trigger anomaly"
        );
    }
}
