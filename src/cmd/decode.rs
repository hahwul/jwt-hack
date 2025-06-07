use anyhow::Result;
use colored::Colorize;
use serde_json::Value;
use std::time::SystemTime;

use crate::jwt;
use crate::utils;

/// Decodes and displays JWT token components with formatted output
pub fn execute(token: &str) {
    utils::log_info(format!(
        "Decoding JWT token: {}",
        utils::format_jwt_token(token)
    ));
    if let Err(e) = decode_token(token) {
        utils::log_error(format!("JWT Decode Error: {}", e));
        utils::log_error("e.g jwt-hack decode {JWT_CODE}");
    }
}

fn decode_token(token: &str) -> Result<()> {
    // Decode JWT token into its components
    let decoded = jwt::decode(token)?;
    utils::log_success("Token decoded successfully");

    // Display formatted header section
    println!("\n{}", "━━━ Header ━━━".bright_cyan().bold());
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("{}", header_json.bright_blue());

    utils::log_info(format!(
        "Algorithm: {}",
        format!("{:?}", decoded.algorithm).bright_green()
    ));

    // Display payload section with human-readable timestamp formatting
    println!("\n{}", "━━━ Payload ━━━".bright_magenta().bold());

    let mut claims_map: Value = decoded.claims.clone();

    // Convert Unix timestamps to human-readable dates
    if let Some(iat) = decoded.claims.get("iat") {
        if let Some(iat_val) = iat.as_f64() {
            let iat_seconds = iat_val as u64;
            let iat_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(iat_seconds);
            let formatted_time = chrono::DateTime::<chrono::Utc>::from(iat_time)
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string();

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

    if let Some(exp) = decoded.claims.get("exp") {
        if let Some(exp_val) = exp.as_f64() {
            let exp_seconds = exp_val as u64;
            let exp_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp_seconds);
            let formatted_time = chrono::DateTime::<chrono::Utc>::from(exp_time)
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string();

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

    // Display claims as properly formatted JSON with added time information
    println!("\n{}", serde_json::to_string_pretty(&claims_map)?);

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
}
