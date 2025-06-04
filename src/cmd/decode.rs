use anyhow::Result;
use std::time::SystemTime;
use colored::Colorize;
use serde_json::Value;

use crate::jwt;
use crate::utils;

/// Execute the decode command
pub fn execute(token: &str) {
    utils::log_info(format!("Decoding JWT token: {}", utils::format_jwt_token(token)));
    if let Err(e) = decode_token(token) {
        utils::log_error(format!("JWT Decode Error: {}", e));
        utils::log_error("e.g jwt-hack decode {JWT_CODE}");
    }
}

fn decode_token(token: &str) -> Result<()> {
    // Decode the JWT token
    let decoded = jwt::decode(token)?;
    utils::log_success("Token decoded successfully");

    // Display header section
    println!("\n{}", "━━━ Header ━━━".bright_cyan().bold());
    let header_json = serde_json::to_string_pretty(&decoded.header)?;
    println!("{}", header_json.bright_blue());
    
    utils::log_info(format!("Algorithm: {}", format!("{:?}", decoded.algorithm).bright_green()));

    // Display payload section with special handling for time fields
    println!("\n{}", "━━━ Payload ━━━".bright_magenta().bold());
    
    let mut claims_map: Value = decoded.claims.clone();
    
    // Process and format timestamp fields
    if let Some(iat) = decoded.claims.get("iat") {
        if let Some(iat_val) = iat.as_f64() {
            let iat_seconds = iat_val as u64;
            let iat_time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(iat_seconds);
            let formatted_time = chrono::DateTime::<chrono::Utc>::from(iat_time)
                .format("%Y-%m-%d %H:%M:%S UTC").to_string();
                
            utils::log_info(format!("Issued At (iat): {} ({})", 
                iat_seconds.to_string().bright_yellow(),
                formatted_time.bright_cyan()));
                
            // Add human-readable time to the claims for display
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
                .format("%Y-%m-%d %H:%M:%S UTC").to_string();
            
            // Check if token is expired
            let now = SystemTime::now();
            let is_expired = now > exp_time;
            let status = if is_expired { 
                "EXPIRED".bright_red().bold() 
            } else { 
                "VALID".bright_green().bold() 
            };
            
            utils::log_info(format!("Expiration (exp): {} ({}) [{}]", 
                exp_seconds.to_string().bright_yellow(),
                formatted_time.bright_cyan(),
                status));
                
            // Add human-readable time to the claims for display
            if let Some(obj) = claims_map.as_object_mut() {
                obj.insert("exp_time".to_string(), Value::String(formatted_time));
                obj.insert("exp_status".to_string(), Value::String(
                    if is_expired { "EXPIRED" } else { "VALID" }.to_string()));
            }
        }
    }

    // Print claims as formatted JSON
    println!("\n{}", serde_json::to_string_pretty(&claims_map)?);

    Ok(())
}
