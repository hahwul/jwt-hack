#![no_main]
//! Fuzz target for JWE parsing/decryption. Exercises `decode_jwe` (structural
//! parsing of the 5-part JWE) and `decrypt_jwe` (the candidate-key path used by
//! cracking), asserting only that neither panics on malformed input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jwt_hack::jwt::decode_jwe(s);
        // A fixed 32-byte candidate key drives the direct-decryption path.
        let _ = jwt_hack::jwt::decrypt_jwe(s, "0123456789abcdef0123456789abcdef");
    }
});
