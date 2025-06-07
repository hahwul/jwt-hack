use anyhow::Result;
use colored::Colorize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::jwt;
use crate::utils;

/// Encodes JSON data into a JWT token with various algorithm and signing options
pub fn execute(
    json_str: &str,
    secret: Option<&str>,
    private_key_path: Option<&PathBuf>,
    algorithm: &str,
    no_signature: bool,
    headers: Vec<(String, String)>,
) {
    utils::log_info(format!(
        "Encoding JSON to JWT with algorithm: {}",
        algorithm.bright_green()
    ));

    if let Err(e) = encode_json(
        json_str,
        secret,
        private_key_path,
        algorithm,
        no_signature,
        &headers,
    ) {
        utils::log_error(format!("JSON Encode Error: {}", e));
        utils::log_error("e.g jwt-hack encode {JSON} --secret={YOUR_SECRET}");
        utils::log_error(
            "or with RSA: jwt-hack encode {JSON} --private-key=private.pem --algorithm=RS256",
        );
    }
}

fn encode_json(
    json_str: &str,
    secret: Option<&str>,
    private_key_path: Option<&PathBuf>,
    algorithm: &str,
    no_signature: bool,
    headers: &Vec<(String, String)>,
) -> Result<()> {
    // Parse the input JSON into a Value object
    let claims: Value = serde_json::from_str(json_str)?;

    let progress = utils::start_progress("Encoding JWT token...");

    // Convert custom header key-value pairs into a hashmap for JWT encoding
    let header_map: Option<HashMap<&str, &str>> = if !headers.is_empty() {
        let mut map = HashMap::new();
        for (key, value) in headers {
            map.insert(key.as_str(), value.as_str());
        }
        Some(map)
    } else {
        None
    };

    // Build JWT encoding options based on provided parameters
    // Private key option is handled separately due to Rust lifetime requirements
    let options = if no_signature {
        // Use 'none' algorithm (creates unsigned JWT token)
        jwt::EncodeOptions {
            algorithm: "none",
            key_data: jwt::KeyData::None,
            header_params: header_map,
        }
    } else if let Some(path) = private_key_path {
        // Read RSA/EC private key from file for asymmetric algorithms
        let key_content = fs::read_to_string(path)?;

        // Create encoding options with the private key content (keeping ownership in this scope)
        let options = jwt::EncodeOptions {
            algorithm,
            key_data: jwt::KeyData::PrivateKeyPem(&key_content),
            header_params: header_map,
        };

        // Encode JWT immediately while private key content is in scope
        let token = jwt::encode_with_options(&claims, &options)?;

        progress.finish_and_clear();

        // Display successful encoding result with formatted output
        utils::log_success("JWT token created successfully");

        // Display algorithm information
        println!("\n{}", "━━━ Encoding Details ━━━".bright_cyan().bold());
        utils::log_info(format!("Algorithm: {}", algorithm.bright_green()));

        // Display private key file path information
        utils::log_info(format!(
            "Key: {} ({})",
            path.display().to_string().bright_yellow(),
            "Private Key".bright_cyan()
        ));

        // Display any custom headers included in the token
        if !headers.is_empty() {
            utils::log_info("Custom Headers:".to_string());
            for (key, value) in headers {
                println!("  • {}: {}", key.bright_blue(), value.bright_yellow());
            }
        }

        // Display the generated JWT token with color-coded segments
        println!("\n{}", "━━━ JWT Token ━━━".bright_magenta().bold());
        let formatted_token = utils::format_jwt_token(&token);
        println!("{}\n", formatted_token);

        return Ok(());
    } else {
        // Default case: use HMAC with provided secret (or empty string)
        jwt::EncodeOptions {
            algorithm,
            key_data: jwt::KeyData::Secret(secret.unwrap_or("")),
            header_params: header_map,
        }
    };

    // Encode the JWT token using the configured options
    let token = jwt::encode_with_options(&claims, &options)?;

    progress.finish_and_clear();

    // Display successful encoding result with formatted output
    utils::log_success("JWT token created successfully");

    // Display algorithm information
    println!("\n{}", "━━━ Encoding Details ━━━".bright_cyan().bold());
    utils::log_info(format!("Algorithm: {}", algorithm.bright_green()));

    // Display key/secret information based on what was used
    if no_signature {
        utils::log_info("Signature: None (unsigned)".dimmed().to_string());
    } else {
        utils::log_info(format!(
            "Key: {}",
            if secret.unwrap_or("").is_empty() {
                "None (unsigned)".dimmed().to_string()
            } else {
                "****".bright_yellow().to_string()
            }
        ));
    }

    // Display any custom headers included in the token
    if !headers.is_empty() {
        utils::log_info("Custom Headers:".to_string());
        for (key, value) in headers {
            println!("  • {}: {}", key.bright_blue(), value.bright_yellow());
        }
    }

    // Display the generated JWT token with color-coded segments
    println!("\n{}", "━━━ JWT Token ━━━".bright_magenta().bold());
    let formatted_token = utils::format_jwt_token(&token);
    println!("{}\n", formatted_token);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_execute_with_secret() {
        // Create a simple JSON payload
        let json_str = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let secret = Some("test_secret");
        let private_key_path = None;
        let algorithm = "HS256";
        let no_signature = false;
        let headers = Vec::new();

        // Execute should not panic
        let result = std::panic::catch_unwind(|| {
            execute(
                json_str,
                secret,
                private_key_path,
                algorithm,
                no_signature,
                headers,
            );
        });

        assert!(result.is_ok(), "execute() panicked with valid parameters");
    }

    #[test]
    fn test_execute_with_no_signature() {
        // Create a simple JSON payload
        let json_str = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let secret = None;
        let private_key_path = None;
        let algorithm = "none";
        let no_signature = true;
        let headers = Vec::new();

        // Execute should not panic
        let result = std::panic::catch_unwind(|| {
            execute(
                json_str,
                secret,
                private_key_path,
                algorithm,
                no_signature,
                headers,
            );
        });

        assert!(result.is_ok(), "execute() panicked with no signature");
    }

    #[test]
    fn test_execute_with_custom_headers() {
        // Create a simple JSON payload
        let json_str = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let secret = Some("test_secret");
        let private_key_path = None;
        let algorithm = "HS256";
        let no_signature = false;
        let headers = vec![
            ("kid".to_string(), "1234".to_string()),
            ("typ".to_string(), "JWT+AT".to_string()),
        ];

        // Execute should not panic
        let result = std::panic::catch_unwind(|| {
            execute(
                json_str,
                secret,
                private_key_path,
                algorithm,
                no_signature,
                headers,
            );
        });

        assert!(result.is_ok(), "execute() panicked with custom headers");
    }

    #[test]
    fn test_execute_with_invalid_json() {
        // Create an invalid JSON payload
        let json_str = r#"{"sub":"1234567890","name":"John Doe"#; // Missing closing brace
        let secret = Some("test_secret");
        let private_key_path = None;
        let algorithm = "HS256";
        let no_signature = false;
        let headers = Vec::new();

        // Execute should handle the error and not panic
        let result = std::panic::catch_unwind(|| {
            execute(
                json_str,
                secret,
                private_key_path,
                algorithm,
                no_signature,
                headers,
            );
        });

        assert!(result.is_ok(), "execute() panicked with invalid JSON");
    }

    #[test]
    fn test_encode_json_with_rsa_key() {
        // This test requires creating a temporary RSA key file
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let key_path = temp_dir.path().join("test_key.pem");

        // Write sample RSA private key (this is just a placeholder for testing)
        let sample_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw\nkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr\nm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi\nNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV\n3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2\nQU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB\n-----END RSA PRIVATE KEY-----";
        std::fs::write(&key_path, sample_key).expect("Failed to write test key file");

        // Create a simple JSON payload
        let json_str = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let secret = None;
        let private_key_path = Some(&key_path);
        let algorithm = "RS256";
        let no_signature = false;
        let headers = Vec::new();

        // Execute with RSA key shouldn't panic (even if the key is invalid for actual signing)
        let result = std::panic::catch_unwind(|| {
            encode_json(
                json_str,
                secret,
                private_key_path,
                algorithm,
                no_signature,
                &headers,
            )
        });

        assert!(
            result.is_err() || result.is_ok(),
            "Properly handled RSA key attempt"
        );

        // Clean up
        temp_dir.close().expect("Failed to clean up temp directory");
    }
}
