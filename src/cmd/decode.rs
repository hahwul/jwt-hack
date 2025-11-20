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

/// Process and display issued-at claim with formatted timestamp
fn process_issued_at_claim(claims: &Value, claims_map: &mut Value) {
    if let Some(iat) = claims.get("iat") {
        if let Some(iat_val) = iat.as_f64() {
            let iat_seconds = iat_val as u64;
            let formatted_time = format_unix_timestamp(iat_seconds);

            utils::log_info(format!(
                "Issued At (iat): {} ({})",
                iat_seconds.to_string().bright_yellow(),
                formatted_time.bright_cyan()
            ));

            // Add human-readable time format to the JSON output
            if let Some(obj) = claims_map.as_object_mut() {
                obj.insert("iat_time".to_string(), Value::String(formatted_time));
            }
        }
    }
}

/// Process and display expiration claim with status check
fn process_expiration_claim(claims: &Value, claims_map: &mut Value) {
    if let Some(exp) = claims.get("exp") {
        if let Some(exp_val) = exp.as_f64() {
            let exp_seconds = exp_val as u64;
            let exp_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp_seconds);
            let formatted_time = format_unix_timestamp(exp_seconds);

            // Check if token is expired
            let now = SystemTime::now();
            let is_expired = now > exp_time;
            let status = if is_expired {
                "EXPIRED".bright_red().bold()
            } else {
                "VALID".bright_green().bold()
            };

            utils::log_info(format!(
                "Expiration (exp): {} ({}) [{}]",
                exp_seconds.to_string().bright_yellow(),
                formatted_time.bright_cyan(),
                status
            ));

            // Add human-readable time and expiration status to the JSON output
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
    utils::log_info(format!(
        "Decoding JWT token: {}",
        utils::format_jwt_token(token)
    ));
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
    // Decode JWT token into its components
    let decoded = jwt::decode(token)?;
    utils::log_success("JWT token decoded successfully");

    // Display formatted header section
    println!("\n{}", "━━━ JWT Header ━━━".bright_cyan().bold());
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("{}", header_json.bright_blue());

    utils::log_info(format!(
        "Algorithm: {}",
        format!("{:?}", decoded.algorithm).bright_green()
    ));

    // Display payload section with human-readable timestamp formatting
    println!("\n{}", "━━━ JWT Payload ━━━".bright_magenta().bold());

    let mut claims_map: Value = decoded.claims.clone();

    // Convert Unix timestamps to human-readable dates
    process_issued_at_claim(&decoded.claims, &mut claims_map);
    process_expiration_claim(&decoded.claims, &mut claims_map);

    // Display claims as properly formatted JSON with added time information
    println!("\n{}", serde_json::to_string_pretty(&claims_map)?);

    Ok(())
}

fn decode_jwe_token(token: &str) -> Result<()> {
    // Decode JWE token structure
    let decoded = jwt::decode_jwe(token)?;
    utils::log_success("JWE token decoded successfully");

    // Display formatted header section
    println!("\n{}", "━━━ JWE Header ━━━".bright_cyan().bold());
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("{}", header_json.bright_blue());

    utils::log_info(format!(
        "Key Management Algorithm: {}",
        decoded.algorithm.bright_green()
    ));
    utils::log_info(format!(
        "Content Encryption Algorithm: {}",
        decoded.encryption.bright_green()
    ));

    // Display JWE structure
    println!("\n{}", "━━━ JWE Structure ━━━".bright_magenta().bold());

    println!("\n{}", "Encrypted Key:".bright_yellow());
    println!(
        "{}",
        if decoded.encrypted_key.is_empty() {
            "(empty)".dimmed()
        } else {
            utils::format_base64_preview(&decoded.encrypted_key).bright_blue()
        }
    );

    println!("\n{}", "Initialization Vector:".bright_yellow());
    println!(
        "{}",
        if decoded.iv.is_empty() {
            "(empty)".dimmed()
        } else {
            utils::format_base64_preview(&decoded.iv).bright_blue()
        }
    );

    println!("\n{}", "Ciphertext:".bright_yellow());
    println!(
        "{}",
        utils::format_base64_preview(&decoded.ciphertext).bright_blue()
    );

    println!("\n{}", "Authentication Tag:".bright_yellow());
    println!(
        "{}",
        if decoded.tag.is_empty() {
            "(empty)".dimmed()
        } else {
            utils::format_base64_preview(&decoded.tag).bright_blue()
        }
    );

    utils::log_info("JWE payload is encrypted and cannot be decoded without the appropriate key");

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
