use anyhow::{anyhow, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::Value;
use base64::Engine;
use std::collections::HashMap;

/// JWT Decoded token data
#[derive(Debug, Clone)]
pub struct DecodedToken {
    pub header: HashMap<String, Value>,
    pub claims: Value,
    pub algorithm: Algorithm,
}

/// Encode JSON claims into a JWT token
pub fn encode(claims: &Value, secret: &str, alg_str: &str) -> Result<String> {
    // Parse algorithm
    let algorithm = match alg_str.to_uppercase().as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        _ => return Err(anyhow!("Unsupported algorithm: {}", alg_str)),
    };

    // Create header
    let header = Header::new(algorithm);

    // Create encoding key
    let encoding_key = match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            EncodingKey::from_secret(secret.as_bytes())
        }
        _ => return Err(anyhow!("Only HMAC algorithms are currently supported for encoding")),
    };

    // Encode JWT token
    let token = jsonwebtoken::encode(&header, claims, &encoding_key)?;
    Ok(token)
}

/// Decode a JWT token without verifying its signature
pub fn decode(token: &str) -> Result<DecodedToken> {
    // Split the token and handle potential errors
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid token format"));
    }

    // Extract header
    let header_b64 = parts[0];
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| anyhow!("Invalid header encoding"))?;
    let header_str = String::from_utf8(header_bytes)?;
    let header: HashMap<String, Value> = serde_json::from_str(&header_str)?;

    // Extract algorithm
    let alg_value = header.get("alg").ok_or_else(|| anyhow!("Missing 'alg' in header"))?;
    let alg_str = alg_value.as_str().ok_or_else(|| anyhow!("'alg' is not a string"))?;
    
    // Parse algorithm
let algorithm = match alg_str.to_uppercase().as_str() {
    "HS256" => Algorithm::HS256,
    "HS384" => Algorithm::HS384,
    "HS512" => Algorithm::HS512,
    "RS256" => Algorithm::RS256,
    "RS384" => Algorithm::RS384,
    "RS512" => Algorithm::RS512,
    "ES256" => Algorithm::ES256,
    "ES384" => Algorithm::ES384,
    "PS256" => Algorithm::PS256,
    "PS384" => Algorithm::PS384,
    "PS512" => Algorithm::PS512,
    "NONE" => Algorithm::HS256, // Treat 'none' as HS256 for parsing
    _ => return Err(anyhow!("Unsupported algorithm: {}", alg_str)),
};

    // Extract payload (claims)
    let payload_b64 = parts[1];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| anyhow!("Invalid payload encoding"))?;
    let payload_str = String::from_utf8(payload_bytes)?;
    let claims: Value = serde_json::from_str(&payload_str)?;

    Ok(DecodedToken {
        header,
        claims,
        algorithm,
    })
}

/// Verify a JWT token with a given secret
pub fn verify(token: &str, secret: &str) -> Result<bool> {
    // Create validation
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation(); // We'll validate manually
    validation.validate_exp = false;
    validation.validate_nbf = false;

    // Try to decode the token without validation
    let decoded_token = decode(token)?;
    
    // Split the token
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 3 {
        return Err(anyhow!("Invalid token format for verification"));
    }

    // Get message and signature parts
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature_b64 = parts[2];
    
    // Decode signature
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| anyhow!("Invalid signature encoding"))?;

    // Verify based on algorithm
    match decoded_token.algorithm {
        Algorithm::HS256 => {
            let key = hmac_sha256::HMAC::mac(message.as_bytes(), secret.as_bytes());
            Ok(signature == key.as_slice())
        },
        Algorithm::HS384 | Algorithm::HS512 => {
            // For HS384 and HS512, use jsonwebtoken directly
            let decoding_key = DecodingKey::from_secret(secret.as_bytes());
            let result = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation);
            Ok(result.is_ok())
        },
        _ => Err(anyhow!("Unsupported algorithm for verification: {:?}", decoded_token.algorithm)),
    }
}