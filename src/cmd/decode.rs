use anyhow::Result;
use colored::Colorize;
use serde_json::Value;
use std::time::SystemTime;

use crate::jwt;
use crate::utils;

/// Helper function to format Unix timestamp to human-readable format
fn format_unix_timestamp(seconds: u64) -> String {
    let time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
    chrono::DateTime::<chrono::Utc>::from(time)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

/// Annotate issued-at claim with human-readable timestamp in the JSON output
fn process_issued_at_claim(claims: &Value, claims_map: &mut Value) {
    if let Some(iat) = claims.get("iat") {
        if let Some(iat_val) = iat.as_f64() {
            let iat_seconds = iat_val as u64;
            let formatted_time = format_unix_timestamp(iat_seconds);

            if let Some(obj) = claims_map.as_object_mut() {
                obj.insert("iat_time".to_string(), Value::String(formatted_time));
            }
        }
    }
}

/// Annotate expiration claim with human-readable timestamp and status in the JSON output
fn process_expiration_claim(claims: &Value, claims_map: &mut Value) {
    if let Some(exp) = claims.get("exp") {
        if let Some(exp_val) = exp.as_f64() {
            let exp_seconds = exp_val as u64;
            let exp_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp_seconds);
            let formatted_time = format_unix_timestamp(exp_seconds);

            let now = SystemTime::now();
            let is_expired = now > exp_time;

            if let Some(obj) = claims_map.as_object_mut() {
                obj.insert("exp_time".to_string(), Value::String(formatted_time));
                obj.insert(
                    "exp_status".to_string(),
                    Value::String(if is_expired { "EXPIRED" } else { "VALID" }.to_string()),
                );
            }
        }
    }
}

/// Decodes and displays JWT token components with formatted output
pub fn execute(token: &str) {
    if let Err(e) = decode_token(token) {
        utils::log_error(format!("JWT Decode Error: {e}"));
        utils::log_error("e.g jwt-hack decode {JWT_CODE}");
    }
}

fn decode_token(token: &str) -> Result<()> {
    // Detect token type first
    let token_type = jwt::detect_token_type(token);

    match token_type {
        jwt::TokenType::Jwt => decode_jwt_token(token),
        jwt::TokenType::Jwe => decode_jwe_token(token),
        jwt::TokenType::Unknown => {
            let parts: Vec<&str> = token.split('.').collect();
            Err(anyhow::anyhow!(
                "Unknown token format: expected 3 parts (JWT) or 5 parts (JWE), got {} parts",
                parts.len()
            ))
        }
    }
}

fn decode_jwt_token(token: &str) -> Result<()> {
    let decoded = jwt::decode(token)?;

    let alg_str = format!("{:?}", decoded.algorithm);
    let typ = decoded
        .header
        .get("typ")
        .and_then(|v| v.as_str())
        .unwrap_or("JWT");

    println!("  {:<14}{}", "Algorithm".bold(), alg_str.cyan());
    println!("  {:<14}{}", "Type".bold(), typ);

    println!("\n  {}", "Header".bold());
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("  {}", header_json.replace('\n', "\n  "));

    let mut claims_map: Value = decoded.claims.clone();
    process_issued_at_claim(&decoded.claims, &mut claims_map);
    process_expiration_claim(&decoded.claims, &mut claims_map);

    println!("\n  {}", "Payload".bold());
    let payload_json = serde_json::to_string_pretty(&claims_map)?;
    println!("  {}", payload_json.replace('\n', "\n  "));

    Ok(())
}

fn decode_jwe_token(token: &str) -> Result<()> {
    let decoded = jwt::decode_jwe(token)?;

    println!("  {:<14}{}", "Key Mgmt".bold(), decoded.algorithm.cyan());
    println!("  {:<14}{}", "Encryption".bold(), decoded.encryption.cyan());

    println!("\n  {}", "Header".bold());
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("  {}", header_json.replace('\n', "\n  "));

    println!("\n  {:<18}{}",
        "Encrypted Key".bold(),
        if decoded.encrypted_key.is_empty() {
            "(empty)".dimmed().to_string()
        } else {
            utils::format_base64_preview(&decoded.encrypted_key)
        }
    );
    println!("  {:<18}{}",
        "IV".bold(),
        if decoded.iv.is_empty() {
            "(empty)".dimmed().to_string()
        } else {
            utils::format_base64_preview(&decoded.iv)
        }
    );
    println!("  {:<18}{}",
        "Ciphertext".bold(),
        utils::format_base64_preview(&decoded.ciphertext)
    );
    println!("  {:<18}{}",
        "Auth Tag".bold(),
        if decoded.tag.is_empty() {
            "(empty)".dimmed().to_string()
        } else {
            utils::format_base64_preview(&decoded.tag)
        }
    );

    eprintln!("\n  {}", "JWE payload is encrypted and cannot be decoded without the appropriate key".dimmed());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_execute_valid_token() {
        // Create a valid token for testing
        let now = Utc::now();
        let claims = json!({
            "sub": "test_user",
            "name": "Test User",
            "iat": now.timestamp(),
            "exp": (now + chrono::Duration::days(1)).timestamp()
        });

        let token = jwt::encode(&claims, "", "HS256").expect("Failed to create test token");

        // Execute should not panic with a valid token
        let result = std::panic::catch_unwind(|| {
            execute(&token);
        });

        assert!(result.is_ok(), "execute() panicked with valid token");
    }

    #[test]
    fn test_execute_invalid_token() {
        // Create an invalid token for testing
        let invalid_token = "invalid.token.format";

        // Execute should handle the error and not panic
        let result = std::panic::catch_unwind(|| {
            execute(invalid_token);
        });

        assert!(result.is_ok(), "execute() panicked with invalid token");
    }

    #[test]
    fn test_decode_token_with_timestamps() {
        // Create a token with timestamp fields
        let now = SystemTime::now();
        let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
        let iat = since_epoch.as_secs() as i64;
        let exp = (since_epoch + Duration::from_secs(86400)).as_secs() as i64;

        let claims = json!({
            "sub": "test_user",
            "iat": iat,
            "exp": exp
        });

        let token = jwt::encode(&claims, "", "HS256").expect("Failed to create test token");

        // Test that decode_token processes timestamps correctly
        let result = decode_token(&token);
        assert!(
            result.is_ok(),
            "decode_token failed for valid token with timestamps"
        );
    }

    #[test]
    fn test_decode_token_without_timestamps() {
        // Create a token without timestamp fields
        let claims = json!({
            "sub": "test_user",
            "name": "Test User"
        });

        let token = jwt::encode(&claims, "", "HS256").expect("Failed to create test token");

        // Test that decode_token handles tokens without timestamps
        let result = decode_token(&token);
        assert!(
            result.is_ok(),
            "decode_token failed for valid token without timestamps"
        );
    }

    #[test]
    fn test_decode_jwe_token() {
        // Test JWE token decoding
        let jwe_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZHVtbXlfaXZfMTIzNDU2.eyJzdWIiOiJ0ZXN0In0.ZHVtbXlfdGFn";

        let result = decode_token(jwe_token);
        assert!(
            result.is_ok(),
            "decode_token should succeed for valid JWE token"
        );
    }

    #[test]
    fn test_decode_unknown_token_format() {
        // Test token with invalid number of parts
        let invalid_token = "invalid.token.with.too.many.parts.here";

        let result = decode_token(invalid_token);
        assert!(
            result.is_err(),
            "decode_token should fail for invalid token format"
        );
    }
}
