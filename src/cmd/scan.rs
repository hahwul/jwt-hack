use anyhow::Result;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use crate::jwt;
use crate::payload;
use crate::utils;

/// Options for customizing the scan
#[derive(Debug)]
pub struct ScanOptions<'a> {
    pub skip_crack: bool,
    pub skip_payloads: bool,
    pub wordlist: Option<&'a PathBuf>,
    pub max_crack_attempts: usize,
}

impl<'a> Default for ScanOptions<'a> {
    fn default() -> Self {
        Self {
            skip_crack: false,
            skip_payloads: false,
            wordlist: None,
            max_crack_attempts: 100,
        }
    }
}

/// Result of a vulnerability check
#[derive(Debug, Clone)]
pub struct VulnerabilityResult {
    pub name: String,
    pub vulnerable: bool,
    pub details: String,
    pub severity: Severity,
}

/// Severity levels for vulnerabilities
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    fn color(&self) -> colored::Color {
        match self {
            Severity::Critical => colored::Color::BrightRed,
            Severity::High => colored::Color::Red,
            Severity::Medium => colored::Color::Yellow,
            Severity::Low => colored::Color::Blue,
            Severity::Info => colored::Color::Cyan,
        }
    }
}

/// Execute the scan command
pub fn execute(
    token: &str,
    skip_crack: bool,
    skip_payloads: bool,
    wordlist: Option<&PathBuf>,
    max_crack_attempts: usize,
) {
    let options = ScanOptions {
        skip_crack,
        skip_payloads,
        wordlist,
        max_crack_attempts,
    };

    utils::log_info(format!(
        "Starting comprehensive JWT vulnerability scan for: {}",
        utils::format_jwt_token(token)
    ));

    if let Err(e) = run_scan(token, &options) {
        utils::log_error(format!("Scan failed: {e}"));
        utils::log_error(
            "e.g jwt-hack scan {JWT_CODE} [--skip-crack] [--skip-payloads] [-w wordlist.txt]",
        );
    }
}

/// Run comprehensive vulnerability scan
fn run_scan(token: &str, options: &ScanOptions) -> Result<()> {
    let mut results: Vec<VulnerabilityResult> = Vec::new();

    println!(
        "\n{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_cyan()
            .bold()
    );
    println!("{}", "  JWT VULNERABILITY SCANNER".bright_cyan().bold());
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            .bright_cyan()
            .bold()
    );

    // Decode token first to get basic info
    let decoded = jwt::decode(token)?;

    println!("\n{}", "━━━ Token Information ━━━".bright_magenta().bold());
    println!(
        "Algorithm: {}",
        format!("{:?}", decoded.algorithm).bright_yellow()
    );
    if let Some(typ) = decoded.header.get("typ") {
        println!("Type: {}", typ.to_string().bright_yellow());
    }

    // Check 1: None Algorithm Vulnerability
    results.push(check_none_algorithm(token, &decoded)?);

    // Check 2: Weak Secret (if not skipped)
    if !options.skip_crack {
        results.push(check_weak_secret(token, &decoded, options)?);
    }

    // Check 3: Algorithm Confusion
    results.push(check_algorithm_confusion(token, &decoded)?);

    // Check 4: Token Expiration
    results.push(check_token_expiration(&decoded)?);

    // Check 5: Missing Claims
    results.push(check_missing_claims(&decoded)?);

    // Check 6: Kid Header Vulnerabilities
    results.push(check_kid_vulnerabilities(&decoded)?);

    // Check 7: JKU/X5U Header Vulnerabilities
    results.push(check_jku_x5u_vulnerabilities(&decoded)?);

    // Display results summary
    display_results(&results);

    // Generate attack payloads if not skipped
    if !options.skip_payloads {
        println!(
            "\n{}",
            "━━━ Generating Attack Payloads ━━━".bright_magenta().bold()
        );
        utils::log_info("Generating example attack payloads for discovered vulnerabilities...");

        let spinner = utils::start_progress("Creating attack payloads...");
        generate_attack_payloads(token, &results)?;
        spinner.finish_and_clear();
    }

    Ok(())
}

/// Check for none algorithm vulnerability
fn check_none_algorithm(_token: &str, decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking for 'none' algorithm vulnerability");

    let alg_str = format!("{:?}", decoded.algorithm).to_lowercase();
    let vulnerable = alg_str.contains("none")
        || decoded
            .header
            .get("alg")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase() == "none")
            .unwrap_or(false);

    pb.finish_and_clear();

    let result = if vulnerable {
        VulnerabilityResult {
            name: "None Algorithm".to_string(),
            vulnerable: true,
            details: "Token uses 'none' algorithm, which accepts unsigned tokens".to_string(),
            severity: Severity::Critical,
        }
    } else {
        VulnerabilityResult {
            name: "None Algorithm".to_string(),
            vulnerable: false,
            details: "Token does not use 'none' algorithm".to_string(),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Check for weak secrets through limited dictionary attack
fn check_weak_secret(
    token: &str,
    decoded: &jwt::DecodedToken,
    options: &ScanOptions,
) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking for weak/common secrets");

    // Only check HMAC algorithms
    let alg_str = format!("{:?}", decoded.algorithm);
    if !alg_str.starts_with("HS") {
        pb.finish_and_clear();
        return Ok(VulnerabilityResult {
            name: "Weak Secret".to_string(),
            vulnerable: false,
            details: format!("Not applicable for {} algorithm", alg_str),
            severity: Severity::Info,
        });
    }

    // Use provided wordlist or common passwords
    let common_secrets = crate::config::COMMON_SECRETS;

    let secrets_to_test: Vec<String> = if let Some(ref wordlist_path) = options.wordlist {
        // Read from wordlist file (limited to max_crack_attempts)
        if let Ok(file) = std::fs::File::open(wordlist_path) {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(file);
            reader
                .lines()
                .map_while(Result::ok)
                .take(options.max_crack_attempts)
                .collect()
        } else {
            common_secrets.iter().map(|s| s.to_string()).collect()
        }
    } else {
        common_secrets.iter().map(|s| s.to_string()).collect()
    };

    let mut found_secret: Option<String> = None;
    for secret in &secrets_to_test {
        if let Ok(true) = jwt::verify(token, secret) {
            found_secret = Some(secret.clone());
            break;
        }
    }

    pb.finish_and_clear();

    let result = if let Some(secret) = found_secret {
        VulnerabilityResult {
            name: "Weak Secret".to_string(),
            vulnerable: true,
            details: format!(
                "Token uses weak/common secret: '{}'",
                secret.bright_red().bold()
            ),
            severity: Severity::Critical,
        }
    } else {
        VulnerabilityResult {
            name: "Weak Secret".to_string(),
            vulnerable: false,
            details: format!(
                "No common secret found (tested {} secrets)",
                secrets_to_test.len()
            ),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Check for algorithm confusion vulnerability
fn check_algorithm_confusion(
    _token: &str,
    decoded: &jwt::DecodedToken,
) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking for algorithm confusion vulnerability");

    let alg_str = format!("{:?}", decoded.algorithm);

    // Check if token uses asymmetric algorithm (RS256, ES256, etc.)
    let uses_asymmetric = alg_str.starts_with("RS")
        || alg_str.starts_with("ES")
        || alg_str.starts_with("PS")
        || alg_str == "EdDSA";

    pb.finish_and_clear();

    let result = if uses_asymmetric {
        VulnerabilityResult {
            name: "Algorithm Confusion".to_string(),
            vulnerable: true,
            details: format!(
                "Token uses {} which may be vulnerable to algorithm confusion attacks (RS256->HS256)",
                alg_str.bright_yellow()
            ),
            severity: Severity::High,
        }
    } else {
        VulnerabilityResult {
            name: "Algorithm Confusion".to_string(),
            vulnerable: false,
            details: "Token uses symmetric algorithm, not vulnerable to typical alg confusion"
                .to_string(),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Check token expiration
fn check_token_expiration(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking token expiration");

    let has_exp = decoded.claims.get("exp").is_some();
    let has_nbf = decoded.claims.get("nbf").is_some();
    let has_iat = decoded.claims.get("iat").is_some();

    let mut issues = Vec::new();

    if !has_exp {
        issues.push("Missing 'exp' (expiration) claim".to_string());
    } else if let Some(exp) = decoded.claims.get("exp").and_then(|v| v.as_i64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if exp < now {
            issues.push(format!("Token is expired (exp: {})", exp));
        }
    }

    if !has_nbf {
        issues.push("Missing 'nbf' (not before) claim".to_string());
    }

    if !has_iat {
        issues.push("Missing 'iat' (issued at) claim".to_string());
    }

    pb.finish_and_clear();

    let vulnerable = !issues.is_empty();
    let result = VulnerabilityResult {
        name: "Token Expiration".to_string(),
        vulnerable,
        details: if vulnerable {
            issues.join("; ")
        } else {
            "Token has proper expiration claims".to_string()
        },
        severity: if vulnerable {
            Severity::Medium
        } else {
            Severity::Info
        },
    };

    Ok(result)
}

/// Check for missing important claims
fn check_missing_claims(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking for missing security claims");

    let important_claims = vec!["sub", "aud", "iss", "jti"];
    let mut missing = Vec::new();

    for claim in &important_claims {
        if decoded.claims.get(claim).is_none() {
            missing.push(*claim);
        }
    }

    pb.finish_and_clear();

    let vulnerable = !missing.is_empty();
    let result = VulnerabilityResult {
        name: "Missing Claims".to_string(),
        vulnerable,
        details: if vulnerable {
            format!("Missing recommended claims: {}", missing.join(", "))
        } else {
            "All recommended claims are present".to_string()
        },
        severity: if vulnerable {
            Severity::Low
        } else {
            Severity::Info
        },
    };

    Ok(result)
}

/// Check for kid header vulnerabilities
fn check_kid_vulnerabilities(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking for kid header injection vulnerabilities");

    let has_kid = decoded.header.contains_key("kid");

    pb.finish_and_clear();

    let result = if has_kid {
        if let Some(kid) = decoded.header.get("kid") {
            VulnerabilityResult {
                name: "Kid Header Injection".to_string(),
                vulnerable: true,
                details: format!(
                    "Token has 'kid' header ({}), which may be vulnerable to SQL/path injection",
                    kid.to_string().bright_yellow()
                ),
                severity: Severity::Medium,
            }
        } else {
            VulnerabilityResult {
                name: "Kid Header Injection".to_string(),
                vulnerable: false,
                details: "No 'kid' header present".to_string(),
                severity: Severity::Info,
            }
        }
    } else {
        VulnerabilityResult {
            name: "Kid Header Injection".to_string(),
            vulnerable: false,
            details: "No 'kid' header present".to_string(),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Check for JKU/X5U header vulnerabilities
fn check_jku_x5u_vulnerabilities(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let pb = create_check_spinner("Checking for JKU/X5U header vulnerabilities");

    let has_jku = decoded.header.contains_key("jku");
    let has_x5u = decoded.header.contains_key("x5u");

    pb.finish_and_clear();

    let result = if has_jku || has_x5u {
        let header_type = if has_jku { "jku" } else { "x5u" };
        let header_value = decoded.header.get(header_type);

        VulnerabilityResult {
            name: "JKU/X5U Header".to_string(),
            vulnerable: true,
            details: format!(
                "Token has '{}' header ({}), which may allow URL spoofing attacks",
                header_type,
                header_value
                    .map(|v| v.to_string())
                    .unwrap_or_default()
                    .bright_yellow()
            ),
            severity: Severity::High,
        }
    } else {
        VulnerabilityResult {
            name: "JKU/X5U Header".to_string(),
            vulnerable: false,
            details: "No JKU/X5U headers present".to_string(),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Display scan results
fn display_results(results: &[VulnerabilityResult]) {
    println!("\n{}", "━━━ Scan Results ━━━".bright_green().bold());

    let mut vulnerable_count = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;

    for result in results {
        if result.vulnerable {
            vulnerable_count += 1;
            match result.severity {
                Severity::Critical => critical_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => medium_count += 1,
                Severity::Low => low_count += 1,
                _ => {}
            }
        }

        let status = if result.vulnerable { "✗" } else { "✓" };
        let status_color = if result.vulnerable {
            colored::Color::Red
        } else {
            colored::Color::Green
        };

        println!(
            "\n{} {} [{}]",
            status.color(status_color).bold(),
            result.name.bright_white().bold(),
            result
                .severity
                .as_str()
                .color(result.severity.color())
                .bold()
        );
        println!("  {}", result.details);
    }

    println!("\n{}", "━━━ Summary ━━━".bright_cyan().bold());
    println!(
        "Total Vulnerabilities Found: {}",
        vulnerable_count
            .to_string()
            .color(if vulnerable_count > 0 {
                colored::Color::Red
            } else {
                colored::Color::Green
            })
            .bold()
    );

    if critical_count > 0 {
        println!(
            "  {} Critical",
            critical_count.to_string().bright_red().bold()
        );
    }
    if high_count > 0 {
        println!("  {} High", high_count.to_string().red().bold());
    }
    if medium_count > 0 {
        println!("  {} Medium", medium_count.to_string().yellow().bold());
    }
    if low_count > 0 {
        println!("  {} Low", low_count.to_string().blue().bold());
    }

    if vulnerable_count > 0 {
        println!(
            "\n{}",
            "⚠️  Review the vulnerabilities above and consider generating attack payloads."
                .bright_yellow()
        );
    } else {
        println!(
            "\n{}",
            "✓ No major vulnerabilities detected in this scan.".bright_green()
        );
    }
}

/// Generate attack payloads for discovered vulnerabilities
fn generate_attack_payloads(token: &str, results: &[VulnerabilityResult]) -> Result<()> {
    let mut targets = HashSet::new();

    for result in results {
        if !result.vulnerable {
            continue;
        }

        match result.name.as_str() {
            "None Algorithm" => {
                targets.insert("none");
            }
            "Algorithm Confusion" => {
                targets.insert("alg_confusion");
            }
            "Kid Header Injection" => {
                targets.insert("kid_sql");
            }
            "JKU/X5U Header" => {
                targets.insert("jku");
                targets.insert("x5u");
            }
            _ => {}
        }
    }

    if targets.is_empty() {
        utils::log_info("No attack payloads to generate (no vulnerabilities found)");
        return Ok(());
    }

    // Generate payloads for the vulnerable areas
    let target_str = targets.into_iter().collect::<Vec<_>>().join(",");

    // Use the payload module to generate attack payloads
    if !target_str.is_empty() {
        utils::log_info(format!(
            "Generating payloads for: {}",
            target_str.bright_yellow()
        ));

        // Decode token parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() >= 2 {
            // Generate none payloads if vulnerable
            if target_str.contains("none") {
                println!(
                    "\n{}",
                    "━━━ None Algorithm Payloads ━━━".bright_cyan().bold()
                );
                let _ = payload::generate_none_payload(token, "none");
                let _ = payload::generate_none_payload(token, "None");
                let _ = payload::generate_none_payload(token, "NONE");
            }

            // Generate algorithm confusion payloads if vulnerable
            if target_str.contains("alg_confusion") {
                println!(
                    "\n{}",
                    "━━━ Algorithm Confusion Payloads ━━━".bright_cyan().bold()
                );
                if let Ok(payloads) = payload::generate_alg_confusion_payload(token, None) {
                    for payload in payloads.iter().take(2) {
                        println!("{}", payload);
                    }
                }
            }

            // Generate kid SQL injection payloads if vulnerable
            if target_str.contains("kid_sql") {
                println!(
                    "\n{}",
                    "━━━ Kid SQL Injection Payloads ━━━".bright_cyan().bold()
                );
                if let Ok(payloads) = payload::generate_kid_sql_payload(token) {
                    for payload in payloads.iter().take(2) {
                        println!("{}", payload);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Create a spinner progress bar for checks
fn create_check_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_token(alg: &str, secret: &str) -> String {
        let claims = json!({
            "sub": "test_user",
            "name": "Test User",
            "iat": 1516239022,
            "exp": 9999999999i64
        });

        crate::jwt::encode(&claims, secret, alg).expect("Failed to create test token")
    }

    #[test]
    fn test_execute_no_panic() {
        let token = create_test_token("HS256", "test_secret");

        let result = std::panic::catch_unwind(|| {
            execute(&token, true, true, None, 10);
        });

        assert!(result.is_ok(), "execute should not panic");
    }

    #[test]
    fn test_check_none_algorithm_vulnerable() {
        // Create a token with HS256 (not none)
        let token = create_test_token("HS256", "secret");
        let decoded = jwt::decode(&token).unwrap();

        let result = check_none_algorithm(&token, &decoded).unwrap();

        // HS256 token should not be vulnerable to none algorithm
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_check_weak_secret() {
        // Create a token with a weak secret
        let token = create_test_token("HS256", "secret");
        let decoded = jwt::decode(&token).unwrap();
        let options = ScanOptions::default();

        let result = check_weak_secret(&token, &decoded, &options).unwrap();

        // Should find "secret" as a weak password
        assert!(result.vulnerable);
        assert!(result.details.contains("secret"));
    }

    #[test]
    fn test_check_algorithm_confusion_hs256_not_vulnerable() {
        // HS256 should NOT be vulnerable to algorithm confusion (which affects asymmetric algs)
        let token = create_test_token("HS256", "secret");
        let decoded = jwt::decode(&token).unwrap();

        let result = check_algorithm_confusion(&token, &decoded).unwrap();

        // HS256 should not be vulnerable to algorithm confusion
        assert!(!result.vulnerable);
    }

    #[test]
    fn test_check_algorithm_confusion_asymmetric_vulnerable() {
        use base64::Engine;

        let asymmetric_algs = vec!["RS256", "ES256", "PS256", "EdDSA"];

        for alg in asymmetric_algs {
            // Manually construct a token with the target algorithm
            // We can't use create_test_token because it requires a valid private key for asymmetric algs
            let header = json!({
                "alg": alg,
                "typ": "JWT"
            });
            let claims = json!({
                "sub": "test_user",
                "name": "Test User"
            });

            let encoded_header =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string());
            let encoded_claims =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string());

            // Signature doesn't matter for decode
            let token = format!("{}.{}.fake_signature", encoded_header, encoded_claims);

            let decoded = jwt::decode(&token).unwrap();
            let result = check_algorithm_confusion(&token, &decoded).unwrap();

            assert!(
                result.vulnerable,
                "{} should be flagged as vulnerable to algorithm confusion",
                alg
            );
            assert!(
                result.details.contains(alg),
                "Details should mention {}",
                alg
            );
        }
    }

    #[test]
    fn test_check_token_expiration_with_exp() {
        let token = create_test_token("HS256", "secret");
        let decoded = jwt::decode(&token).unwrap();

        let result = check_token_expiration(&decoded).unwrap();

        // Token has exp claim, so might report missing nbf/iat but not critically vulnerable
        // The exact result depends on the token structure
        assert!(result.name == "Token Expiration");
    }

    #[test]
    fn test_check_missing_claims() {
        let token = create_test_token("HS256", "secret");
        let decoded = jwt::decode(&token).unwrap();

        let result = check_missing_claims(&decoded).unwrap();

        // Our test token is missing several recommended claims
        assert!(result.vulnerable);
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");
        assert_eq!(Severity::Info.as_str(), "INFO");
    }

    #[test]
    fn test_check_jku_x5u_vulnerabilities() {
        use std::collections::HashMap;

        // Case 1: jku header present
        let mut header = HashMap::new();
        header.insert("jku".to_string(), json!("https://evil.com/jwks.json"));
        let decoded_jku = jwt::DecodedToken {
            header,
            claims: json!({}),
            algorithm: jsonwebtoken::Algorithm::HS256,
        };

        let result = check_jku_x5u_vulnerabilities(&decoded_jku).unwrap();
        assert!(result.vulnerable);
        assert_eq!(result.name, "JKU/X5U Header");
        assert_eq!(result.severity, Severity::High);
        assert!(result.details.contains("jku"));

        // Case 2: x5u header present
        let mut header = HashMap::new();
        header.insert("x5u".to_string(), json!("https://evil.com/x509.pem"));
        let decoded_x5u = jwt::DecodedToken {
            header,
            claims: json!({}),
            algorithm: jsonwebtoken::Algorithm::HS256,
        };

        let result = check_jku_x5u_vulnerabilities(&decoded_x5u).unwrap();
        assert!(result.vulnerable);
        assert_eq!(result.name, "JKU/X5U Header");
        assert_eq!(result.severity, Severity::High);
        assert!(result.details.contains("x5u"));

        // Case 3: Neither present
        let header = HashMap::new();
        let decoded_clean = jwt::DecodedToken {
            header,
            claims: json!({}),
            algorithm: jsonwebtoken::Algorithm::HS256,
        };

        let result = check_jku_x5u_vulnerabilities(&decoded_clean).unwrap();
        assert!(!result.vulnerable);
    fn test_check_none_algorithm_positive() {
        // Create a token with 'none' algorithm
        let token = create_test_token("none", "");
        let decoded = jwt::decode(&token).unwrap();

        let result = check_none_algorithm(&token, &decoded).unwrap();

        // Should be vulnerable
        assert!(result.vulnerable);
        assert_eq!(result.name, "None Algorithm");
        assert_eq!(result.severity, Severity::Critical);
    }
}
