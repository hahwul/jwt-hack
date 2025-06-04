use anyhow::Result;
use serde_json::Value;
use colored::Colorize;

use crate::jwt;
use crate::utils;

/// Execute the encode command
pub fn execute(json_str: &str, secret: Option<&str>, algorithm: &str) {
    utils::log_info(format!("Encoding JSON to JWT with algorithm: {}", algorithm.bright_green()));
    if let Err(e) = encode_json(json_str, secret.unwrap_or(""), algorithm) {
        utils::log_error(format!("JSON Encode Error: {}", e));
        utils::log_error("e.g jwt-hack encode {JSON} --secret={YOUR_SECRET}");
    }
}

fn encode_json(json_str: &str, secret: &str, algorithm: &str) -> Result<()> {
    // Parse the JSON string
    let claims: Value = serde_json::from_str(json_str)?;

    let progress = utils::start_progress("Encoding JWT token...");
    
    // Encode the JWT
    let token = jwt::encode(&claims, secret, algorithm)?;
    
    progress.finish_and_clear();
    
    // Display results with pretty formatting
    utils::log_success("JWT token created successfully");
    
    // Show algorithm and secret info
    println!("\n{}", "━━━ Encoding Details ━━━".bright_cyan().bold());
    utils::log_info(format!("Algorithm: {}", algorithm.bright_green()));
    utils::log_info(format!("Secret: {}", 
        if secret.is_empty() { "None (unsigned)".dimmed().to_string() } 
        else { "****".bright_yellow().to_string() }
    ));
    
    // Display token with colored segments
    println!("\n{}", "━━━ JWT Token ━━━".bright_magenta().bold());
    let formatted_token = utils::format_jwt_token(&token);
    println!("{}\n", formatted_token);

    Ok(())
}
