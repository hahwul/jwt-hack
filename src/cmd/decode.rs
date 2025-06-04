use anyhow::Result;
use log::{error, info};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::jwt;

/// Execute the decode command
pub fn execute(token: &str) {
    if let Err(e) = decode_token(token) {
        error!("JWT Decode Error: {}", e);
        error!("e.g jwt-hack decode {{JWT_CODE}}");
    }
}

fn decode_token(token: &str) -> Result<()> {
    // Decode the JWT token
    let decoded = jwt::decode(token)?;

    // Log header and method info
    let header_json = serde_json::to_string(&decoded.header)?;
    info!(
        "Decoded data(claims) header=\"{}\" method=\"{:?}\"",
        header_json, decoded.algorithm
    );

    // Check for special time fields
    if let Some(iat) = decoded.claims.get("iat") {
        if let Some(iat_val) = iat.as_f64() {
            let iat_seconds = iat_val as u64;
            let iat_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(iat_seconds);

            info!(
                "Issued At Time IAT=\"{}\" TIME=\"{:?}\"",
                iat_seconds,
                iat_time.duration_since(UNIX_EPOCH).unwrap()
            );
        }
    }

    if let Some(exp) = decoded.claims.get("exp") {
        if let Some(exp_val) = exp.as_f64() {
            let exp_seconds = exp_val as u64;
            let exp_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(exp_seconds);

            info!(
                "Expiration Time EXP=\"{}\" TIME=\"{:?}\"",
                exp_seconds,
                exp_time.duration_since(UNIX_EPOCH).unwrap()
            );
        }
    }

    // Print claims as formatted JSON
    println!("{}", serde_json::to_string_pretty(&decoded.claims)?);

    Ok(())
}
