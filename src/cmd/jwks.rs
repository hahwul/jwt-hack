use colored::Colorize;
use std::path::PathBuf;

use jwt_hack::jwks;
use crate::utils;

/// Execute the JWKS fetch subcommand
pub fn execute_fetch(url: &str) {
    match jwks::fetch_jwks(url) {
        Ok(jwk_set) => {
            println!("\n  {}", "JWKS Endpoint".bold());
            println!("  {:<18}{}", "URL".dimmed(), url);
            println!("  {:<18}{}", "Keys Found".dimmed(), jwk_set.keys.len());

            for (i, key) in jwk_set.keys.iter().enumerate() {
                println!("\n  {} {}", "Key".bold(), format!("#{}", i + 1).bold());
                println!("  {:<18}{}", "Type (kty)".dimmed(), key.kty);

                if let Some(kid) = &key.kid {
                    println!("  {:<18}{}", "Key ID (kid)".dimmed(), kid);
                }
                if let Some(alg) = &key.alg {
                    println!("  {:<18}{}", "Algorithm".dimmed(), alg);
                }
                if let Some(use_) = &key.key_use {
                    println!("  {:<18}{}", "Use".dimmed(), use_);
                }

                match key.kty.as_str() {
                    "RSA" => {
                        if let Some(n) = &key.n {
                            let n_str: &str = n.as_str();
                            let n_display = if n_str.len() > 40 {
                                format!("{}...({} chars)", &n_str[..40], n_str.len())
                            } else {
                                n_str.to_string()
                            };
                            println!("  {:<18}{}", "Modulus (n)".dimmed(), n_display);
                        }
                        if let Some(e) = &key.e {
                            println!("  {:<18}{}", "Exponent (e)".dimmed(), e);
                        }

                        // Try to convert to PEM
                        match jwks::jwk_rsa_to_pem(key) {
                            Ok(pem) => {
                                println!("  {:<18}{}", "PEM".dimmed(), "OK (extractable)".green());
                                println!("\n{}", pem);
                            }
                            Err(e) => {
                                println!(
                                    "  {:<18}{}",
                                    "PEM".dimmed(),
                                    format!("Error: {}", e).red()
                                );
                            }
                        }
                    }
                    "EC" => {
                        if let Some(crv) = &key.crv {
                            println!("  {:<18}{}", "Curve".dimmed(), crv);
                        }
                        if let Some(x) = &key.x {
                            println!("  {:<18}{}", "X".dimmed(), x);
                        }
                        if let Some(y) = &key.y {
                            println!("  {:<18}{}", "Y".dimmed(), y);
                        }
                    }
                    "oct" => {
                        println!(
                            "  {:<18}{}",
                            "Key".dimmed(),
                            "(symmetric key present)".yellow()
                        );
                    }
                    _ => {
                        println!("  {:<18}(unknown key type)", "Details".dimmed());
                    }
                }
            }
        }
        Err(e) => {
            utils::log_error(format!("Failed to fetch JWKS: {}", e));
            utils::log_error(
                "e.g jwt-hack jwks fetch https://example.com/.well-known/jwks.json",
            );
        }
    }
}

/// Execute the JWKS spoof subcommand
pub fn execute_spoof(
    algorithm: &str,
    kid: Option<&str>,
    token: Option<&str>,
    attacker_url: Option<&str>,
    output: Option<&PathBuf>,
) {
    // If attacker URL is provided, generate full injection payloads
    if let Some(url) = attacker_url {
        let token_str = match token {
            Some(t) => t,
            None => {
                utils::log_error(
                    "Token is required when using --attacker-url. Provide a JWT token to inject."
                        .to_string(),
                );
                return;
            }
        };

        match jwks::generate_jwks_injection_payloads(token_str, url, algorithm) {
            Ok(result) => {
                println!("\n  {}", "JWKS Injection Attack".bold());
                println!("  {:<18}{}", "Algorithm".dimmed(), algorithm);
                println!("  {:<18}{}", "Attacker URL".dimmed(), url);

                // Save JWKS to file if output specified
                if let Some(output_path) = output {
                    match std::fs::write(output_path, &result.jwks_json) {
                        Ok(_) => {
                            utils::log_success(format!(
                                "JWKS saved to {}",
                                output_path.display()
                            ));
                        }
                        Err(e) => {
                            utils::log_error(format!(
                                "Failed to save JWKS to {}: {}",
                                output_path.display(),
                                e
                            ));
                        }
                    }
                }

                println!("\n  {}", "Spoofed JWKS".bold());
                println!("{}", result.jwks_json);

                println!("\n  {}", "Private Key".bold());
                println!("{}", result.private_key_pem);

                println!("\n  {}", "Injection Payloads".bold());
                for payload in &result.payloads {
                    println!(
                        "\n  {}",
                        format!("{} ({})", payload.header_type.to_uppercase(), payload.description)
                            .bold()
                    );
                    println!("  {}", payload.token);
                }

                println!(
                    "\n  {}",
                    "Host the JWKS JSON at the attacker URL and use the injection tokens."
                        .yellow()
                );
            }
            Err(e) => {
                utils::log_error(format!("Failed to generate injection payloads: {}", e));
            }
        }
        return;
    }

    // Simple spoof without injection
    match jwks::generate_spoofed_jwks(algorithm, kid, token) {
        Ok(spoofed) => {
            println!("\n  {}", "Spoofed JWKS".bold());
            println!("  {:<18}{}", "Algorithm".dimmed(), algorithm);

            // Save JWKS to file if output specified
            if let Some(output_path) = output {
                match std::fs::write(output_path, &spoofed.jwks_json) {
                    Ok(_) => {
                        utils::log_success(format!(
                            "JWKS saved to {}",
                            output_path.display()
                        ));
                    }
                    Err(e) => {
                        utils::log_error(format!(
                            "Failed to save JWKS to {}: {}",
                            output_path.display(),
                            e
                        ));
                    }
                }
            }

            println!("\n  {}", "JWKS (Public Key Set)".bold());
            println!("{}", spoofed.jwks_json);

            println!("\n  {}", "Private Key (PEM)".bold());
            println!("{}", spoofed.private_key_pem);

            if let Some(signed_token) = &spoofed.signed_token {
                println!("\n  {}", "Signed Token".bold());
                println!("  {}", signed_token);
            }
        }
        Err(e) => {
            utils::log_error(format!("Failed to generate spoofed JWKS: {}", e));
            utils::log_error(
                "e.g jwt-hack jwks spoof --algorithm RS256 --kid my-key-id",
            );
        }
    }
}

/// Execute the JWKS verify subcommand
pub fn execute_verify(token: &str, url: Option<&str>, jwks_file: Option<&PathBuf>) {
    let jwk_set = if let Some(url) = url {
        match jwks::fetch_jwks(url) {
            Ok(jwks) => jwks,
            Err(e) => {
                utils::log_error(format!("Failed to fetch JWKS: {}", e));
                return;
            }
        }
    } else if let Some(file) = jwks_file {
        match std::fs::read_to_string(file) {
            Ok(content) => match jwks::parse_jwks(&content) {
                Ok(jwks) => jwks,
                Err(e) => {
                    utils::log_error(format!("Failed to parse JWKS file: {}", e));
                    return;
                }
            },
            Err(e) => {
                utils::log_error(format!("Failed to read JWKS file: {}", e));
                return;
            }
        }
    } else {
        utils::log_error("Provide --url or --jwks-file for verification.".to_string());
        utils::log_error(
            "e.g jwt-hack jwks verify <TOKEN> --url https://example.com/.well-known/jwks.json",
        );
        return;
    };

    println!("\n  {}", "JWKS Verification".bold());
    println!("  {:<18}{}", "Keys".dimmed(), jwk_set.keys.len());

    match jwks::verify_with_jwks(token, &jwk_set) {
        Ok(results) => {
            let mut any_valid = false;

            for result in &results {
                let status = if result.valid {
                    any_valid = true;
                    "VALID".green().to_string()
                } else {
                    "INVALID".red().to_string()
                };

                let alg_str = result
                    .alg
                    .as_deref()
                    .unwrap_or("(unspecified)")
                    .to_string();

                println!(
                    "\n  {}  {:<12} {:<10} kid={:<20} alg={}",
                    status,
                    format!("Key #{}", result.key_index + 1),
                    result.kty,
                    result.kid,
                    alg_str
                );

                if let Some(error) = &result.error {
                    println!("       {}", error.as_str().dimmed());
                }
            }

            if any_valid {
                utils::log_success("Token verified successfully against JWKS.");
            } else {
                utils::log_error(
                    "Token could not be verified against any key in the JWKS.".to_string(),
                );
            }
        }
        Err(e) => {
            utils::log_error(format!("Verification failed: {}", e));
        }
    }
}

/// Execute the JWKS key rotation test subcommand
pub fn execute_rotate(token: &str, keys_dir: Option<&PathBuf>, key_files: &[PathBuf]) {
    let mut all_key_paths: Vec<PathBuf> = key_files.to_vec();

    // Collect key files from directory
    if let Some(dir) = keys_dir {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let ext = path
                            .extension()
                            .map(|e| e.to_string_lossy().to_lowercase())
                            .unwrap_or_default();
                        if matches!(ext.as_str(), "pem" | "key" | "pub" | "txt" | "") {
                            all_key_paths.push(path);
                        }
                    }
                }
            }
            Err(e) => {
                utils::log_error(format!(
                    "Failed to read keys directory {:?}: {}",
                    dir, e
                ));
                return;
            }
        }
    }

    if all_key_paths.is_empty() {
        utils::log_error("No key files provided. Use --keys-dir or --key to specify keys.".to_string());
        utils::log_error(
            "e.g jwt-hack jwks rotate <TOKEN> --keys-dir ./keys/ --key extra.pem",
        );
        return;
    }

    println!("\n  {}", "Key Rotation Test".bold());
    println!(
        "  {:<18}{}",
        "Keys to Test".dimmed(),
        all_key_paths.len()
    );

    match jwks::test_key_rotation(token, &all_key_paths) {
        Ok(results) => {
            let mut valid_count = 0;

            for result in &results {
                let status = if result.valid {
                    valid_count += 1;
                    "VALID".green().to_string()
                } else {
                    "INVALID".red().to_string()
                };

                println!("\n  {}  {}", status, result.key_file.bold());

                if let Some(error) = &result.error {
                    println!("       {}", error.as_str().dimmed());
                }
            }

            println!("\n  {}", "Summary".bold());
            println!(
                "  {} of {} keys verified the token",
                valid_count,
                results.len()
            );

            if valid_count > 1 {
                utils::log_warning(format!(
                    "Multiple keys ({}) can verify this token — possible key rotation overlap.",
                    valid_count
                ));
            } else if valid_count == 0 {
                utils::log_error(
                    "No keys could verify the token.".to_string(),
                );
            }
        }
        Err(e) => {
            utils::log_error(format!("Key rotation test failed: {}", e));
        }
    }
}
