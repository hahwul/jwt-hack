use anyhow::{Result, anyhow};
use std::fs;
use std::path::PathBuf;

use crate::jwt::{self, VerifyOptions, VerifyKeyData};
use crate::utils;

/// Execute the verify command
pub fn execute(token: &str, secret: Option<&str>, private_key_path: Option<&PathBuf>) {
    utils::log_info(format!("Verifying JWT token: {}", utils::format_jwt_token(token)));

    match verify_token(token, secret, private_key_path) {
        Ok(is_valid) => {
            if is_valid {
                utils::log_success("Token is valid.");
            } else {
                utils::log_error("Token is invalid.".to_string());
            }
        }
        Err(e) => {
            utils::log_error(format!("JWT Verification Error: {}", e));
            // Suggest common issues or next steps
            if e.to_string().contains("Invalid signature") {
                 utils::log_error("This could be due to an incorrect secret or key.".to_string());
            } else if e.to_string().contains("ExpiredSignature") {
                 utils::log_error("The token has expired. Check the 'exp' claim.".to_string());
            } else if e.to_string().contains("ImmatureSignature") {
                 utils::log_error("The token is not yet valid. Check the 'nbf' claim.".to_string());
            } else if e.to_string().contains("InvalidAlgorithm") || e.to_string().contains("AlgorithmMismatch") {
                 utils::log_error("The token's algorithm does not match the expected algorithm or the key provided.".to_string());
            }
             utils::log_error("e.g jwt-hack verify {JWT_CODE} --secret={YOUR_SECRET}".to_string());
             utils::log_error("or with RSA/ECDSA: jwt-hack verify {JWT_CODE} --private-key=key.pem".to_string());
        }
    }
}

fn verify_token(
    token: &str,
    secret: Option<&str>,
    private_key_path: Option<&PathBuf>,
) -> Result<bool> {
    // First, decode the token to get the algorithm without verification
    // This is important because jsonwebtoken::verify_with_options needs the algorithm
    // to be known if we are to construct the Validation struct with the correct Algorithm.
    // However, our jwt::verify_with_options already calls jwt::decode internally to get the algorithm.
    // So, we can directly proceed to prepare VerifyOptions.

    let key_data: VerifyKeyData;
    let validate_claims = false; // By default, we are only checking signature as per issue.
                                     // Flags for --validate-exp, --validate-nbf could be added later.

    let private_key_content: String; // Needs to live long enough

    if let Some(pk_path) = private_key_path {
        // Using a private key (implies asymmetric algorithm)
        private_key_content = fs::read_to_string(pk_path)
            .map_err(|e| anyhow!("Failed to read private key from {:?}: {}", pk_path, e))?;
        key_data = VerifyKeyData::PublicKeyPem(&private_key_content);
        // For asymmetric keys, claims validation (like exp, nbf) is often desired.
        // However, the issue doesn't specify flags for it, so keeping it simple.
        // The underlying jwt::verify_with_options uses jsonwebtoken::decode which can validate these
        // if options.validate_exp/nbf are true.
    } else if let Some(s) = secret {
        // Using a secret (implies HMAC algorithm)
        key_data = VerifyKeyData::Secret(s);
    } else {
        // No key/secret provided.
        // If the token is 'none' algorithm, it might be considered valid.
        // If it's another alg, it will fail validation.
        // We can try to decode and see if it's 'none' alg.
        let decoded_unverified = jwt::decode(token)?; //
        if decoded_unverified.header.get("alg").and_then(|v| v.as_str()) == Some("none") {
            // For "none" alg, verify_with_options should handle it.
            // We pass a dummy secret as it will be ignored for "none".
            key_data = VerifyKeyData::Secret("");
        } else {
            return Err(anyhow!("No secret or private key provided for a token that is not using 'none' algorithm. Please provide --secret or --private-key."));
        }
    }

    let options = VerifyOptions {
        key_data,
        validate_exp: validate_claims, // Set to true if --validate-exp flag is added
        validate_nbf: validate_claims, // Set to true if --validate-nbf flag is added
        leeway: 0, // Could be configurable too
    };

    jwt::verify_with_options(token, &options)
}
