/// Module for JWE-specific attack capabilities
use anyhow::{anyhow, Result};
use base64::Engine;
use colored::Colorize;
use serde_json;

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

    // Modify last byte of ciphertext (affects padding)
    if let Ok(mut ciphertext_bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&decoded.ciphertext)
    {
        if let Some(last_byte) = ciphertext_bytes.last_mut() {
            *last_byte ^= 0x01; // Flip last bit
            let modified_ciphertext =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext_bytes);
            let modified_token = format!(
                "{}.{}.{}.{}.{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_string(&decoded.header).unwrap()),
                decoded.encrypted_key,
                decoded.iv,
                modified_ciphertext,
                decoded.tag
            );
            payloads.push(modified_token);
        }
    }

    // Truncate ciphertext to test padding validation
    if let Ok(mut ciphertext_bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&decoded.ciphertext)
    {
        if ciphertext_bytes.len() > 16 {
            ciphertext_bytes.truncate(ciphertext_bytes.len() - 8);
            let truncated_ciphertext =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ciphertext_bytes);
            let truncated_token = format!(
                "{}.{}.{}.{}.{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_string(&decoded.header).unwrap()),
                decoded.encrypted_key,
                decoded.iv,
                truncated_ciphertext,
                decoded.tag
            );
            payloads.push(truncated_token);
        }
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
    let mut indicators = Vec::new();

    // Check for timing differences (potential timing side-channel)
    if response_time_ms > 100 {
        indicators.push(format!(
            "⚠️  Slow response ({}ms) - may indicate server-side processing differences",
            response_time_ms
        ));
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
}
