#![no_main]
//! Fuzz target focused on JWT header parsing. Treats the input as the first
//! (header) segment of an otherwise well-formed token, forcing `decode` through
//! the base64/JSON header parser with arbitrary bytes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header_segment) = std::str::from_utf8(data) {
        // Minimal payload "{}" -> "e30", empty signature.
        let token = format!("{header_segment}.e30.");
        let _ = jwt_hack::jwt::detect_token_type(&token);
        let _ = jwt_hack::jwt::decode(&token);
    }
});
