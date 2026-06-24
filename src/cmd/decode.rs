use anyhow::Result;
use colored::Colorize;
use serde_json::Value;

use crate::jwt;
use crate::printing::theme;
use crate::utils;

/// Helper function to format a Unix timestamp to a human-readable string.
///
/// Returns `None` for values outside chrono's representable range instead of
/// panicking, so that attacker-controlled `exp`/`iat` claims cannot crash decode.
fn format_unix_timestamp(seconds: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Reads a NumericDate claim (`exp`/`iat`) as seconds. Accepts both integer and
/// float JSON numbers (RFC 7519 allows non-integer NumericDate). Float→int uses
/// Rust's saturating cast and non-finite values are rejected; out-of-range values
/// are later dropped by `format_unix_timestamp` rather than panicking.
fn claim_seconds(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
}

/// Annotate issued-at claim with human-readable timestamp in the JSON output
fn process_issued_at_claim(claims: &Value, claims_map: &mut Value) {
    if let Some(iat) = claims.get("iat") {
        if let Some(iat_seconds) = claim_seconds(iat) {
            if let Some(formatted_time) = format_unix_timestamp(iat_seconds) {
                if let Some(obj) = claims_map.as_object_mut() {
                    obj.insert("iat_time".to_string(), Value::String(formatted_time));
                }
            }
        }
    }
}

/// Annotate expiration claim with human-readable timestamp and status in the JSON output
fn process_expiration_claim(claims: &Value, claims_map: &mut Value) {
    if let Some(exp) = claims.get("exp") {
        if let Some(exp_seconds) = claim_seconds(exp) {
            if let Some(formatted_time) = format_unix_timestamp(exp_seconds) {
                let now = chrono::Utc::now().timestamp();
                let is_expired = now > exp_seconds;

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
}

/// Decodes and displays JWT token components with formatted output
pub fn execute(token: &str) {
    if let Err(e) = decode_token(token) {
        utils::log_error(format!("JWT Decode Error: {e}"));
        utils::log_error("e.g jwt-hack decode {JWT_CODE}");
    }
}

pub fn execute_json(token: &str) -> Result<Value> {
    decode_token_json(token)
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

fn decode_token_json(token: &str) -> Result<Value> {
    let token_type = jwt::detect_token_type(token);

    match token_type {
        jwt::TokenType::Jwt => decode_jwt_token_json(token),
        jwt::TokenType::Jwe => decode_jwe_token_json(token),
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

    println!("{}", theme::section_line("Decode"));
    println!();
    println!("{}", theme::kv("Algorithm", alg_str.cyan()));
    println!("{}", theme::kv("Type", typ));

    println!("\n{}", theme::subsection_line("Header"));
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("{}{}", theme::INDENT, header_json.replace('\n', "\n  "));

    let mut claims_map: Value = decoded.claims.clone();
    process_issued_at_claim(&decoded.claims, &mut claims_map);
    process_expiration_claim(&decoded.claims, &mut claims_map);

    println!("\n{}", theme::subsection_line("Payload"));
    let payload_json = serde_json::to_string_pretty(&claims_map)?;
    println!("{}{}", theme::INDENT, payload_json.replace('\n', "\n  "));

    Ok(())
}

fn decode_jwt_token_json(token: &str) -> Result<Value> {
    let decoded = jwt::decode(token)?;

    let alg_str = format!("{:?}", decoded.algorithm);
    let typ = decoded
        .header
        .get("typ")
        .and_then(|v| v.as_str())
        .unwrap_or("JWT");

    let mut claims_map: Value = decoded.claims.clone();
    process_issued_at_claim(&decoded.claims, &mut claims_map);
    process_expiration_claim(&decoded.claims, &mut claims_map);

    Ok(serde_json::json!({
        "success": true,
        "token_type": "jwt",
        "algorithm": alg_str,
        "typ": typ,
        "header": decoded.header,
        "payload": claims_map
    }))
}

fn decode_jwe_token(token: &str) -> Result<()> {
    let decoded = jwt::decode_jwe(token)?;

    println!("{}", theme::section_line("Decode · JWE"));
    println!();
    println!("{}", theme::kv("Key Mgmt", decoded.algorithm.cyan()));
    println!("{}", theme::kv("Encryption", decoded.encryption.cyan()));

    println!("\n{}", theme::subsection_line("Header"));
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("{}{}", theme::INDENT, header_json.replace('\n', "\n  "));

    println!("\n{}", theme::subsection_line("Components"));
    println!(
        "{}",
        theme::kv_line(
            "Encrypted Key",
            if decoded.encrypted_key.is_empty() {
                "(empty)".dimmed().to_string()
            } else {
                utils::format_base64_preview(&decoded.encrypted_key)
            },
            18
        )
    );
    println!(
        "{}",
        theme::kv_line(
            "IV",
            if decoded.iv.is_empty() {
                "(empty)".dimmed().to_string()
            } else {
                utils::format_base64_preview(&decoded.iv)
            },
            18
        )
    );
    println!(
        "{}",
        theme::kv_line(
            "Ciphertext",
            utils::format_base64_preview(&decoded.ciphertext),
            18
        )
    );
    println!(
        "{}",
        theme::kv_line(
            "Auth Tag",
            if decoded.tag.is_empty() {
                "(empty)".dimmed().to_string()
            } else {
                utils::format_base64_preview(&decoded.tag)
            },
            18
        )
    );

    eprintln!(
        "\n{}{}",
        theme::INDENT,
        "JWE payload is encrypted and cannot be decoded without the appropriate key".dimmed()
    );

    // Check for misconfigurations
    let misconfigs = jwt::detect_jwe_misconfigurations(&decoded);
    if !misconfigs.is_empty() {
        eprintln!("\n{}", theme::subsection_line("Security Issues"));
        for issue in misconfigs {
            eprintln!("{}{}", theme::INDENT, issue.yellow());
        }
    }

    Ok(())
}

fn decode_jwe_token_json(token: &str) -> Result<Value> {
    let decoded = jwt::decode_jwe(token)?;

    let misconfigs = jwt::detect_jwe_misconfigurations(&decoded);

    Ok(serde_json::json!({
        "success": true,
        "token_type": "jwe",
        "key_mgmt": decoded.algorithm,
        "encryption": decoded.encryption,
        "header": decoded.header,
        "encrypted_key": decoded.encrypted_key,
        "iv": decoded.iv,
        "ciphertext": decoded.ciphertext,
        "auth_tag": decoded.tag,
        "security_issues": misconfigs,
        "note": "JWE payload is encrypted and cannot be decoded without the appropriate key"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    #[test]
    fn test_decode_token_with_overflowing_exp_does_not_panic() {
        // Attacker-controlled out-of-range exp/iat claims must not crash decode.
        for value in [
            json!(8_300_000_000_000_000i64), // out of chrono range
            json!(i64::MAX),
            json!(1e30),  // saturates a naive float->u64 cast
            json!(-1i64), // negative timestamp
        ] {
            let claims = json!({ "sub": "u", "exp": value, "iat": value });
            let token = jwt::encode(&claims, "", "HS256").expect("token");
            let result = std::panic::catch_unwind(|| {
                let _ = execute_json(&token);
            });
            assert!(result.is_ok(), "decode panicked on exp/iat = {value}");
        }
    }

    #[test]
    fn test_decode_token_with_float_timestamp_is_annotated() {
        // RFC 7519 NumericDate allows non-integer values; a float exp/iat must still
        // be annotated (not silently dropped) and must not panic.
        let claims = json!({ "sub": "u", "exp": 1_700_000_000.0_f64, "iat": 1_600_000_000.0_f64 });
        let token = jwt::encode(&claims, "", "HS256").expect("token");
        let value = execute_json(&token).expect("decode");
        let payload = value.get("payload").expect("payload");
        assert!(
            payload.get("exp_time").is_some(),
            "float exp should be annotated with exp_time"
        );
        assert!(
            payload.get("iat_time").is_some(),
            "float iat should be annotated with iat_time"
        );
    }

    #[test]
    fn test_execute_json_success() {
        let claims = json!({ "sub": "u", "iat": 0, "exp": 1 });
        let token = jwt::encode(&claims, "", "HS256").expect("token");
        let value = execute_json(&token).expect("json decode");
        assert_eq!(value.get("success").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            value.get("token_type").and_then(|v| v.as_str()),
            Some("jwt")
        );
        assert!(value.get("payload").is_some());
    }
}
