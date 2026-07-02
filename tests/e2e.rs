//! End-to-end workflow tests exercising full jwt-hack lifecycles through the
//! public library API: encode -> crack -> verify, plus compression and JWE
//! round-trips. These use only `jwt_hack::*` so they mirror what a downstream
//! integrator (or the CLI) actually drives.

use jwt_hack::crack::brute;
use jwt_hack::jwt::{self, EncodeOptions, JweContentEncryption, JweKeyManagement, KeyData};
use serde_json::json;

/// Minimal dictionary crack over the public verifier, standing in for the
/// `crack` command's dictionary mode.
fn dictionary_crack(token: &str, wordlist: &[&str]) -> Option<String> {
    let verifier = jwt::prepare_hs256_verifier(token).ok()?;
    wordlist
        .iter()
        .find(|w| verifier.verify(w.as_bytes()))
        .map(|w| w.to_string())
}

/// Minimal brute-force crack using the same primitives as the crack hot path.
fn brute_crack(token: &str, chars: &str, max_len: usize) -> Option<String> {
    let verifier = jwt::prepare_hs256_verifier(token).ok()?;
    let char_bytes = brute::charset_bytes(chars);
    let mut buf = Vec::new();
    for length in 1..=max_len {
        let total = (char_bytes.len() as u64).pow(length as u32);
        for idx in 0..total {
            brute::write_candidate_bytes(idx, &char_bytes, length, &mut buf);
            if verifier.verify(&buf) {
                return Some(String::from_utf8(buf).unwrap());
            }
        }
    }
    None
}

/// Scenario 1: HS256 encode -> dictionary crack -> verify.
#[test]
fn e2e_hs256_encode_dictionary_crack_verify() {
    let secret = "letmein";
    let claims = json!({"sub": "1234567890", "name": "Alice", "role": "admin"});

    // Encode
    let token = jwt::encode(&claims, secret, "HS256").expect("encode");
    assert_eq!(jwt::detect_token_type(&token), jwt::TokenType::Jwt);

    // Crack (dictionary)
    let found = dictionary_crack(&token, &["nope", "wrong", secret, "other"]);
    assert_eq!(found.as_deref(), Some(secret));

    // Verify with the recovered secret succeeds, and a wrong one fails.
    assert!(jwt::verify(&token, secret).expect("verify ok"));
    assert!(!jwt::verify(&token, "not-the-secret").expect("verify wrong"));

    // Decode round-trips the claims.
    let decoded = jwt::decode(&token).expect("decode");
    assert_eq!(decoded.claims["name"], "Alice");
    assert_eq!(decoded.claims["role"], "admin");
}

/// Scenario 2: HS256 encode -> brute-force crack -> verify.
#[test]
fn e2e_hs256_encode_brute_crack_verify() {
    let secret = "cab";
    let token = jwt::encode(&json!({"sub": "x"}), secret, "HS256").expect("encode");

    let found = brute_crack(&token, "abc", 3);
    assert_eq!(found.as_deref(), Some(secret));

    assert!(jwt::verify(&token, secret).expect("verify"));
}

/// Scenario 3: compressed payload round-trip -> decode -> verify.
#[test]
fn e2e_compressed_payload_roundtrip() {
    let secret = "s3cr3t";
    let claims = json!({"sub": "1234", "data": "a".repeat(200)});

    let options = EncodeOptions {
        algorithm: "HS256",
        key_data: KeyData::Secret(secret),
        header_params: None,
        compress_payload: true,
    };
    let token = jwt::encode_with_options(&claims, &options).expect("encode compressed");

    // Header advertises DEFLATE compression.
    let decoded = jwt::decode(&token).expect("decode");
    assert_eq!(
        decoded.header.get("zip").and_then(|v| v.as_str()),
        Some("DEF")
    );

    // Claims survive the compress -> decode round-trip.
    assert_eq!(decoded.claims["sub"], "1234");
    assert_eq!(decoded.claims["data"], "a".repeat(200));

    // Signature still verifies against the original secret.
    assert!(jwt::verify(&token, secret).expect("verify compressed"));
}

/// Scenario 4: `none` algorithm token encode -> decode.
#[test]
fn e2e_none_algorithm_token() {
    let options = EncodeOptions {
        algorithm: "none",
        key_data: KeyData::None,
        header_params: None,
        compress_payload: false,
    };
    let token = jwt::encode_with_options(&json!({"sub": "admin"}), &options).expect("encode none");

    let decoded = jwt::decode(&token).expect("decode none");
    assert_eq!(
        decoded.header.get("alg").and_then(|v| v.as_str()),
        Some("none")
    );
    assert_eq!(decoded.claims["sub"], "admin");
    // The library `verify` accepts `alg:none` tokens regardless of the secret —
    // this is exactly the alg:none acceptance pitfall jwt-hack helps surface, so
    // we pin the behavior here rather than assume signature enforcement.
    assert!(jwt::verify(&token, "anything").expect("verify none"));
}

/// Scenario 5: JWE (direct symmetric key) encrypt -> detect -> decrypt.
#[test]
fn e2e_jwe_direct_roundtrip() {
    // A256GCM direct encryption needs a 32-byte key.
    let key = "0123456789abcdef0123456789abcdef";
    let payload = r#"{"sub":"1234","secret_data":"top secret"}"#;

    let token = jwt::encode_jwe(
        payload,
        JweKeyManagement::Direct(key),
        JweContentEncryption::A256GCM,
    )
    .expect("encode jwe");

    assert_eq!(jwt::detect_token_type(&token), jwt::TokenType::Jwe);

    let decrypted = jwt::decrypt_jwe(&token, key).expect("decrypt jwe");
    assert_eq!(decrypted, payload);

    // The wrong key must not decrypt.
    let wrong = "ffffffffffffffffffffffffffffffff";
    assert!(jwt::decrypt_jwe(&token, wrong).is_err());
}
