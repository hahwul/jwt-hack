use anyhow::Result;
use log::{error, info};
use serde_json::Value;

use crate::jwt;

/// Execute the encode command
pub fn execute(json_str: &str, secret: Option<&str>, algorithm: &str) {
    if let Err(e) = encode_json(json_str, secret.unwrap_or(""), algorithm) {
        error!("JSON Encode Error: {}", e);
        error!("e.g jwt-hack encode {{JSON}} --secret={{YOUR_SECRET}}");
    }
}

fn encode_json(json_str: &str, secret: &str, algorithm: &str) -> Result<()> {
    // Parse the JSON string
    let claims: Value = serde_json::from_str(json_str)?;
    
    // Encode the JWT
    let token = jwt::encode(&claims, secret, algorithm)?;
    
    // Log and output
    info!("Encoded result algorithm={}", algorithm);
    println!("{}", token);
    
    Ok(())
}