#![no_main]
//! Fuzz target for JWT decoding. Feeds arbitrary UTF-8 into `jwt::decode` and
//! `detect_token_type`, asserting only that they never panic on malformed input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = jwt_hack::jwt::detect_token_type(s);
        let _ = jwt_hack::jwt::decode(s);
    }
});
