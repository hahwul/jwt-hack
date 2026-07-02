//! Cross-library interoperability tests.
//!
//! jwt-hack signs/verifies JWTs through `jsonwebtoken` internally. These tests
//! validate that tokens are interoperable with a *different* JWT/JWS
//! implementation — `josekit` — in both directions and across symmetric (HS256)
//! and asymmetric (RS256) algorithms.

use josekit::jws::{JwsHeader, HS256, RS256};
use jwt_hack::jwt::{self, EncodeOptions, KeyData};
use serde_json::{json, Value};

const RSA_PRIVATE_PEM: &str = include_str!("../src/jwt/test_rsa_2048_private.pem");
const RSA_PUBLIC_PEM: &str = include_str!("../src/jwt/test_rsa_2048_public.pem");

/// jwt-hack signs an HS256 token; josekit (a different library) must verify it
/// and read back the exact claims.
#[test]
fn interop_hs256_jwthack_encode_josekit_verify() {
    // josekit enforces the RFC 7518 minimum HMAC key size (>= 32 bytes for HS256).
    let secret = "0123456789abcdef0123456789abcdef";
    let claims = json!({"sub": "1234567890", "name": "Alice", "admin": true});

    let token = jwt::encode(&claims, secret, "HS256").expect("jwt-hack encode");

    let verifier = HS256
        .verifier_from_bytes(secret.as_bytes())
        .expect("josekit verifier");
    let (payload_bytes, header) =
        josekit::jws::deserialize_compact(&token, &verifier).expect("josekit verify");

    assert_eq!(header.algorithm(), Some("HS256"));
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
    assert_eq!(payload["name"], "Alice");
    assert_eq!(payload["admin"], true);

    // A wrong secret must be rejected by the other library too.
    let bad = HS256
        .verifier_from_bytes(b"ffffffffffffffffffffffffffffffff")
        .expect("verifier");
    assert!(josekit::jws::deserialize_compact(&token, &bad).is_err());
}

/// josekit signs an HS256 token; jwt-hack must verify and decode it.
#[test]
fn interop_hs256_josekit_encode_jwthack_verify() {
    // josekit enforces the RFC 7518 minimum HMAC key size (>= 32 bytes for HS256).
    let secret = "0123456789abcdef0123456789abcdef";

    let mut header = JwsHeader::new();
    header.set_algorithm("HS256");
    header.set_token_type("JWT");
    let payload = serde_json::to_vec(&json!({"sub": "42", "name": "Bob"})).unwrap();
    let signer = HS256
        .signer_from_bytes(secret.as_bytes())
        .expect("josekit signer");
    let token = josekit::jws::serialize_compact(&payload, &header, &signer).expect("josekit sign");

    // jwt-hack verifies the josekit-produced token.
    assert!(jwt::verify(&token, secret).expect("jwt-hack verify"));
    assert!(!jwt::verify(&token, "wrong").expect("jwt-hack verify wrong"));

    // jwt-hack decodes the josekit-produced claims.
    let decoded = jwt::decode(&token).expect("jwt-hack decode");
    assert_eq!(decoded.claims["name"], "Bob");
    assert_eq!(decoded.claims["sub"], "42");
}

/// jwt-hack signs an RS256 token with a private key; josekit must verify it with
/// the matching public key (asymmetric cross-library interop).
#[test]
fn interop_rs256_jwthack_encode_josekit_verify() {
    let claims = json!({"sub": "rsa-user", "scope": "read"});
    let options = EncodeOptions {
        algorithm: "RS256",
        key_data: KeyData::PrivateKeyPem(RSA_PRIVATE_PEM),
        header_params: None,
        compress_payload: false,
    };
    let token = jwt::encode_with_options(&claims, &options).expect("jwt-hack RS256 encode");

    let verifier = RS256
        .verifier_from_pem(RSA_PUBLIC_PEM.as_bytes())
        .expect("josekit RS256 verifier");
    let (payload_bytes, header) =
        josekit::jws::deserialize_compact(&token, &verifier).expect("josekit RS256 verify");

    assert_eq!(header.algorithm(), Some("RS256"));
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload json");
    assert_eq!(payload["sub"], "rsa-user");
    assert_eq!(payload["scope"], "read");
}

/// josekit signs an RS256 token; jwt-hack must verify it with the public key.
#[test]
fn interop_rs256_josekit_encode_jwthack_verify() {
    let mut header = JwsHeader::new();
    header.set_algorithm("RS256");
    header.set_token_type("JWT");
    let payload = serde_json::to_vec(&json!({"sub": "rsa-user-2"})).unwrap();
    let signer = RS256
        .signer_from_pem(RSA_PRIVATE_PEM.as_bytes())
        .expect("josekit RS256 signer");
    let token = josekit::jws::serialize_compact(&payload, &header, &signer).expect("josekit sign");

    let options = jwt::VerifyOptions {
        key_data: jwt::VerifyKeyData::PublicKeyPem(RSA_PUBLIC_PEM),
        validate_exp: false,
        validate_nbf: false,
        leeway: 0,
    };
    assert!(jwt::verify_with_options(&token, &options).expect("jwt-hack RS256 verify"));

    let decoded = jwt::decode(&token).expect("jwt-hack decode");
    assert_eq!(decoded.claims["sub"], "rsa-user-2");
}
