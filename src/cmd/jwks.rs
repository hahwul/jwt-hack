use colored::Colorize;
use serde_json::Value;
use std::path::PathBuf;

use crate::printing::theme;
use crate::utils;
use jwt_hack::jwks;

pub fn execute_json(action: &super::JwksAction) -> anyhow::Result<Value> {
    match action {
        super::JwksAction::Fetch { url } => {
            let jwk_set = jwks::fetch_jwks(url)?;
            Ok(serde_json::json!({
                "success": true,
                "action": "fetch",
                "url": url,
                "keys": jwk_set.keys
            }))
        }
        super::JwksAction::Spoof {
            algorithm,
            kid,
            token,
            attacker_url,
            output,
        } => {
            if let Some(url) = attacker_url.as_deref() {
                let token_str = token.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("Token is required when using --attacker-url")
                })?;

                let result = jwks::generate_jwks_injection_payloads(token_str, url, algorithm)?;
                let payloads: Vec<Value> = result
                    .payloads
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "header_type": p.header_type,
                            "description": p.description,
                            "token": p.token
                        })
                    })
                    .collect();
                let write_result = if let Some(output_path) = output {
                    Some(std::fs::write(output_path, &result.jwks_json).map(|_| {
                        serde_json::json!({"path": output_path.display().to_string(), "written": true})
                    })?)
                } else {
                    None
                };

                Ok(serde_json::json!({
                    "success": true,
                    "action": "spoof",
                    "mode": "injection",
                    "algorithm": algorithm,
                    "attacker_url": url,
                    "jwks_json": result.jwks_json,
                    "private_key_pem": result.private_key_pem,
                    "payloads": payloads,
                    "output_file": write_result
                }))
            } else {
                let spoofed =
                    jwks::generate_spoofed_jwks(algorithm, kid.as_deref(), token.as_deref())?;
                let write_result = if let Some(output_path) = output {
                    Some(std::fs::write(output_path, &spoofed.jwks_json).map(|_| {
                        serde_json::json!({"path": output_path.display().to_string(), "written": true})
                    })?)
                } else {
                    None
                };

                Ok(serde_json::json!({
                    "success": true,
                    "action": "spoof",
                    "mode": "simple",
                    "algorithm": algorithm,
                    "kid": kid,
                    "jwks_json": spoofed.jwks_json,
                    "private_key_pem": spoofed.private_key_pem,
                    "signed_token": spoofed.signed_token,
                    "output_file": write_result
                }))
            }
        }
        super::JwksAction::Verify {
            token,
            url,
            jwks_file,
        } => {
            let jwk_set = if let Some(url) = url.as_deref() {
                jwks::fetch_jwks(url)?
            } else if let Some(file) = jwks_file {
                let content = std::fs::read_to_string(file)?;
                jwks::parse_jwks(&content)?
            } else {
                anyhow::bail!("Provide --url or --jwks-file for verification.");
            };

            let results = jwks::verify_with_jwks(token, &jwk_set)?;
            let any_valid = results.iter().any(|r| r.valid);
            let results_json: Vec<Value> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "key_index": r.key_index,
                        "kty": r.kty,
                        "kid": r.kid,
                        "alg": r.alg,
                        "valid": r.valid,
                        "error": r.error,
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "success": true,
                "action": "verify",
                "valid": any_valid,
                "keys_tested": jwk_set.keys.len(),
                "results": results_json
            }))
        }
        super::JwksAction::Rotate {
            token,
            keys_dir,
            key_files,
        } => {
            let mut all_key_paths: Vec<PathBuf> = key_files.to_vec();

            if let Some(dir) = keys_dir {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let ext = path
                        .extension()
                        .map(|e| e.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if matches!(ext.as_str(), "pem" | "key" | "pub" | "txt" | "") {
                        all_key_paths.push(path);
                    }
                }
            }

            if all_key_paths.is_empty() {
                anyhow::bail!("No key files provided. Use --keys-dir or --key to specify keys.");
            }

            let results = jwks::test_key_rotation(token, &all_key_paths)?;
            let valid_count = results.iter().filter(|r| r.valid).count();
            let results_json: Vec<Value> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "key_file": r.key_file,
                        "valid": r.valid,
                        "error": r.error,
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "success": true,
                "action": "rotate",
                "keys_tested": results.len(),
                "valid_keys": valid_count,
                "possible_rotation_overlap": valid_count > 1,
                "results": results_json
            }))
        }
    }
}

/// Execute the JWKS fetch subcommand
pub fn execute_fetch(url: &str) {
    match jwks::fetch_jwks(url) {
        Ok(jwk_set) => {
            println!("{}", theme::section_line("JWKS Endpoint"));
            println!();
            println!("{}", theme::kv_line("URL", url, 18));
            println!("{}", theme::kv_line("Keys Found", jwk_set.keys.len(), 18));

            for (i, key) in jwk_set.keys.iter().enumerate() {
                println!("\n{}", theme::subsection_line(&format!("Key #{}", i + 1)));
                println!("{}", theme::kv_line("Type (kty)", &key.kty, 18));

                if let Some(kid) = &key.kid {
                    println!("{}", theme::kv_line("Key ID (kid)", kid, 18));
                }
                if let Some(alg) = &key.alg {
                    println!("{}", theme::kv_line("Algorithm", alg, 18));
                }
                if let Some(use_) = &key.key_use {
                    println!("{}", theme::kv_line("Use", use_, 18));
                }

                match key.kty.as_str() {
                    "RSA" => {
                        if let Some(n) = &key.n {
                            let n_str: &str = n.as_str();
                            // The modulus comes verbatim from a remote/attacker-controlled
                            // JWKS and is not guaranteed to be ASCII; truncate by characters
                            // so a multibyte boundary at byte 40 cannot panic.
                            let char_count = n_str.chars().count();
                            let n_display = if char_count > 40 {
                                let head: String = n_str.chars().take(40).collect();
                                format!("{}...({} chars)", head, char_count)
                            } else {
                                n_str.to_string()
                            };
                            println!("{}", theme::kv_line("Modulus (n)", n_display, 18));
                        }
                        if let Some(e) = &key.e {
                            println!("{}", theme::kv_line("Exponent (e)", e, 18));
                        }

                        // Try to convert to PEM
                        match jwks::jwk_rsa_to_pem(key) {
                            Ok(pem) => {
                                println!(
                                    "{}",
                                    theme::kv_line("PEM", "OK (extractable)".green(), 18)
                                );
                                println!("\n{}", pem);
                            }
                            Err(e) => {
                                println!(
                                    "{}",
                                    theme::kv_line("PEM", format!("Error: {}", e).red(), 18)
                                );
                            }
                        }
                    }
                    "EC" => {
                        if let Some(crv) = &key.crv {
                            println!("{}", theme::kv_line("Curve", crv, 18));
                        }
                        if let Some(x) = &key.x {
                            println!("{}", theme::kv_line("X", x, 18));
                        }
                        if let Some(y) = &key.y {
                            println!("{}", theme::kv_line("Y", y, 18));
                        }
                    }
                    "oct" => {
                        println!(
                            "{}",
                            theme::kv_line("Key", "(symmetric key present)".yellow(), 18)
                        );
                    }
                    _ => {
                        println!("{}", theme::kv_line("Details", "(unknown key type)", 18));
                    }
                }
            }
        }
        Err(e) => {
            utils::log_error(format!("Failed to fetch JWKS: {}", e));
            utils::log_error("e.g jwt-hack jwks fetch https://example.com/.well-known/jwks.json");
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
                println!("{}", theme::section_line("JWKS Injection Attack"));
                println!();
                println!("{}", theme::kv_line("Algorithm", algorithm, 18));
                println!("{}", theme::kv_line("Attacker URL", url, 18));

                // Save JWKS to file if output specified
                if let Some(output_path) = output {
                    match std::fs::write(output_path, &result.jwks_json) {
                        Ok(_) => {
                            utils::log_success(format!("JWKS saved to {}", output_path.display()));
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

                println!("\n{}", theme::subsection_line("Spoofed JWKS"));
                println!("{}", result.jwks_json);

                println!("\n{}", theme::subsection_line("Private Key"));
                println!("{}", result.private_key_pem);

                println!("\n{}", theme::subsection_line("Injection Payloads"));
                for payload in &result.payloads {
                    println!(
                        "\n{}",
                        theme::subsection_line(&format!(
                            "{} ({})",
                            payload.header_type.to_uppercase(),
                            payload.description
                        ))
                    );
                    println!("  {}", payload.token);
                }

                println!(
                    "\n{}{}",
                    theme::INDENT,
                    "Host the JWKS JSON at the attacker URL and use the injection tokens.".yellow()
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
            println!("{}", theme::section_line("Spoofed JWKS"));
            println!();
            println!("{}", theme::kv_line("Algorithm", algorithm, 18));

            // Save JWKS to file if output specified
            if let Some(output_path) = output {
                match std::fs::write(output_path, &spoofed.jwks_json) {
                    Ok(_) => {
                        utils::log_success(format!("JWKS saved to {}", output_path.display()));
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

            println!("\n{}", theme::subsection_line("JWKS (Public Key Set)"));
            println!("{}", spoofed.jwks_json);

            println!("\n{}", theme::subsection_line("Private Key (PEM)"));
            println!("{}", spoofed.private_key_pem);

            if let Some(signed_token) = &spoofed.signed_token {
                println!("\n{}", theme::subsection_line("Signed Token"));
                println!("  {}", signed_token);
            }
        }
        Err(e) => {
            utils::log_error(format!("Failed to generate spoofed JWKS: {}", e));
            utils::log_error("e.g jwt-hack jwks spoof --algorithm RS256 --kid my-key-id");
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

    println!("{}", theme::section_line("JWKS Verification"));
    println!();
    println!("{}", theme::kv_line("Keys", jwk_set.keys.len(), 18));

    match jwks::verify_with_jwks(token, &jwk_set) {
        Ok(results) => {
            let mut any_valid = false;

            for result in &results {
                let status = if result.valid {
                    any_valid = true;
                    theme::badge_width(theme::G_OK, "VALID", colored::Color::Green, 7)
                } else {
                    theme::badge_width(theme::G_ERR, "INVALID", colored::Color::Red, 7)
                };

                let alg_str = result.alg.as_deref().unwrap_or("(unspecified)").to_string();

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
                utils::log_error(format!("Failed to read keys directory {:?}: {}", dir, e));
                return;
            }
        }
    }

    if all_key_paths.is_empty() {
        utils::log_error(
            "No key files provided. Use --keys-dir or --key to specify keys.".to_string(),
        );
        utils::log_error("e.g jwt-hack jwks rotate <TOKEN> --keys-dir ./keys/ --key extra.pem");
        return;
    }

    println!("{}", theme::section_line("Key Rotation Test"));
    println!();
    println!(
        "{}",
        theme::kv_line("Keys to Test", all_key_paths.len(), 18)
    );

    match jwks::test_key_rotation(token, &all_key_paths) {
        Ok(results) => {
            let mut valid_count = 0;

            for result in &results {
                let status = if result.valid {
                    valid_count += 1;
                    theme::badge_width(theme::G_OK, "VALID", colored::Color::Green, 7)
                } else {
                    theme::badge_width(theme::G_ERR, "INVALID", colored::Color::Red, 7)
                };

                println!("\n  {}  {}", status, result.key_file.bold());

                if let Some(error) = &result.error {
                    println!("       {}", error.as_str().dimmed());
                }
            }

            println!("\n{}", theme::section_line("Summary"));
            println!();
            println!(
                "{}{} of {} keys verified the token",
                theme::INDENT,
                valid_count,
                results.len()
            );

            if valid_count > 1 {
                utils::log_warning(format!(
                    "Multiple keys ({}) can verify this token — possible key rotation overlap.",
                    valid_count
                ));
            } else if valid_count == 0 {
                utils::log_error("No keys could verify the token.".to_string());
            }
        }
        Err(e) => {
            utils::log_error(format!("Key rotation test failed: {}", e));
        }
    }
}
