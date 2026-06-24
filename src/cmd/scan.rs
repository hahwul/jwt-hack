use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::jwt;
use crate::payload;
use crate::printing::theme;
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
#[derive(Debug, Clone, Serialize)]
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
            Severity::Critical => colored::Color::Red,
            Severity::High => colored::Color::Yellow,
            Severity::Medium => colored::Color::Yellow,
            Severity::Low => colored::Color::Blue,
            Severity::Info => colored::Color::Cyan,
        }
    }

    /// Render a colored status badge for terminal output. A non-vulnerable check
    /// shows a green `PASS`; a vulnerable one shows a severity-specific glyph and
    /// short label. This is presentation only — it never feeds the JSON/HTML
    /// report (those use `as_str()`), so the machine-readable contract is intact.
    fn badge(&self, vulnerable: bool) -> String {
        if !vulnerable {
            return theme::badge(theme::G_OK, "PASS", colored::Color::Green);
        }
        let (glyph, label) = match self {
            Severity::Critical => ("▲", "CRIT"),
            Severity::High => ("▲", "HIGH"),
            Severity::Medium => ("◆", "MED"),
            Severity::Low => ("■", "LOW"),
            Severity::Info => (theme::G_INFO, "INFO"),
        };
        theme::badge(glyph, label, self.color())
    }
}

impl Serialize for Severity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub success: bool,
    pub token_type: String,
    pub algorithm: String,
    pub typ: String,
    pub strict_decode_ok: bool,
    pub strict_decode_error: Option<String>,
    pub results: Vec<VulnerabilityResult>,
    pub summary: ScanSummary,
    pub attack_payloads: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub vulnerabilities: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Execute the scan command
pub fn execute(
    token: &str,
    report: Option<&PathBuf>,
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

    if let Err(e) = run_scan(token, &options, report) {
        utils::log_error(format!("Scan failed: {e}"));
        utils::log_error(
            "e.g jwt-hack scan {JWT_CODE} [--skip-crack] [--skip-payloads] [-w wordlist.txt]",
        );
    }
}

pub fn execute_json(
    token: &str,
    report: Option<&PathBuf>,
    skip_crack: bool,
    skip_payloads: bool,
    wordlist: Option<&PathBuf>,
    max_crack_attempts: usize,
) -> Result<Value> {
    let options = ScanOptions {
        skip_crack,
        skip_payloads,
        wordlist,
        max_crack_attempts,
    };

    let report_value = scan_token(token, &options, !skip_payloads)?;
    if let Some(path) = report {
        export_scan_report(&report_value, path)?;
    }
    Ok(serde_json::to_value(report_value)?)
}

/// Build a best-effort `DecodedToken` from the raw header bytes for tokens that
/// `jwt::decode` rejects. Claims are left null and `algorithm` is a sentinel —
/// only header-shape checks should consume the result.
fn parse_header_only(token: &str) -> Result<jwt::DecodedToken> {
    use base64::Engine;
    use std::collections::HashMap;
    let parts: Vec<&str> = token.split('.').collect();
    let header_b64 = parts.first().copied().unwrap_or("");
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| anyhow::anyhow!("token header is not base64url: {e}"))?;
    let header: HashMap<String, serde_json::Value> = serde_json::from_slice(&header_bytes)
        .map_err(|e| anyhow::anyhow!("token header is not JSON: {e}"))?;
    Ok(jwt::DecodedToken {
        header,
        claims: serde_json::Value::Null,
        algorithm: jsonwebtoken::Algorithm::HS256, // sentinel; do not trust
    })
}

/// Run comprehensive vulnerability scan
fn run_scan(token: &str, options: &ScanOptions, report_path: Option<&PathBuf>) -> Result<()> {
    let report = scan_token(token, options, !options.skip_payloads)?;

    println!("{}", theme::section_line("Scan"));
    println!();
    println!(
        "{}",
        theme::kv_line("Algorithm", report.algorithm.cyan(), 18)
    );
    println!("{}", theme::kv_line("Type", &report.typ, 18));
    if let Some(err) = &report.strict_decode_error {
        println!(
            "{}",
            theme::kv_line("Strict decode", format!("rejected: {err}").yellow(), 18)
        );
    }

    display_results(&report.results);

    if !options.skip_payloads {
        if let Some(payloads) = &report.attack_payloads {
            if !payloads.is_empty() {
                println!("\n{}", theme::section_line("Attack Payloads"));
                println!();
                for p in payloads {
                    println!("{}{}", theme::INDENT, p);
                }
            }
        }
    }

    if let Some(path) = report_path {
        export_scan_report(&report, path)?;
        utils::log_success(format!("Report saved to {}", path.display()));
    }

    Ok(())
}

fn scan_token(token: &str, options: &ScanOptions, include_payloads: bool) -> Result<ScanReport> {
    let token_type = jwt::detect_token_type(token);
    let token_type_str = match token_type {
        jwt::TokenType::Jwt => "jwt",
        jwt::TokenType::Jwe => "jwe",
        jwt::TokenType::Unknown => "unknown",
    }
    .to_string();

    let mut results: Vec<VulnerabilityResult> = Vec::new();

    let (decoded, strict_ok, decode_err) = match jwt::decode(token) {
        Ok(d) => (d, true, None),
        Err(e) => {
            let err_str = e.to_string();
            let fallback = parse_header_only(token)?;
            (fallback, false, Some(err_str))
        }
    };

    let header_alg_display = decoded
        .header
        .get("alg")
        .map(|v| v.as_str().map_or_else(|| v.to_string(), |s| s.to_string()))
        .unwrap_or_else(|| "<missing>".to_string());
    let typ = decoded
        .header
        .get("typ")
        .and_then(|v| v.as_str())
        .unwrap_or("JWT")
        .to_string();

    results.push(check_none_algorithm(token, &decoded)?);
    results.push(check_algorithm_confusion(token, &decoded)?);
    results.push(check_kid_vulnerabilities(&decoded)?);
    results.push(check_jku_x5u_vulnerabilities(&decoded)?);
    results.push(check_jwk_header(&decoded)?);
    results.push(check_crit_header(&decoded)?);
    results.push(check_b64_header(&decoded)?);
    results.push(check_signature_segment(token, &decoded)?);
    results.push(check_typ_confusion(&decoded)?);
    results.push(check_alg_edge(token, &decoded)?);
    results.push(check_psychic_signature(token, &decoded)?);
    results.push(check_zip_header(&decoded)?);

    if strict_ok {
        if !options.skip_crack {
            results.push(check_weak_secret(token, &decoded, options)?);
        }
        results.push(check_token_expiration(&decoded)?);
        results.push(check_missing_claims(&decoded)?);
        results.push(check_sensitive_claims(&decoded)?);
    }

    let summary = summarize_results(&results);
    let attack_payloads = if include_payloads {
        Some(collect_attack_payloads(token, &results)?)
    } else {
        None
    };

    Ok(ScanReport {
        success: true,
        token_type: token_type_str,
        algorithm: header_alg_display,
        typ,
        strict_decode_ok: strict_ok,
        strict_decode_error: decode_err,
        results,
        summary,
        attack_payloads,
    })
}

fn summarize_results(results: &[VulnerabilityResult]) -> ScanSummary {
    let mut vulnerable_count = 0;
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for result in results {
        if !result.vulnerable {
            continue;
        }
        vulnerable_count += 1;
        match result.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => {}
        }
    }

    ScanSummary {
        vulnerabilities: vulnerable_count,
        critical,
        high,
        medium,
        low,
    }
}

fn collect_attack_targets(results: &[VulnerabilityResult]) -> HashSet<&'static str> {
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
            "Kid Header" => {
                targets.insert("kid_sql");
                targets.insert("kid_traversal");
            }
            "JKU/X5U Header" => {
                targets.insert("jku");
                targets.insert("x5u");
            }
            "Embedded JWK" => {
                targets.insert("jwk_embed");
            }
            "crit Header" => {
                targets.insert("crit");
            }
            "b64 Header (RFC 7797)" => {
                targets.insert("b64");
            }
            "Signature Segment" => {
                targets.insert("empty_sig");
            }
            "typ Confusion" => {
                targets.insert("typ_confusion");
            }
            "alg Edge Value" => {
                targets.insert("alg_edge");
            }
            "Psychic Signature" => {
                targets.insert("psychic");
            }
            "zip Header" => {
                targets.insert("zip");
            }
            _ => {}
        }
    }

    targets
}

fn collect_attack_payloads(token: &str, results: &[VulnerabilityResult]) -> Result<Vec<String>> {
    let targets = collect_attack_targets(results);
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut payloads_out = Vec::new();

    if targets.contains("none") {
        if let Ok(p) = payload::generate_none_payload(token, "none") {
            payloads_out.push(p);
        }
        if let Ok(p) = payload::generate_none_payload(token, "None") {
            payloads_out.push(p);
        }
        if let Ok(p) = payload::generate_none_payload(token, "NONE") {
            payloads_out.push(p);
        }
    }

    if targets.contains("alg_confusion") {
        if let Ok(payloads) = payload::generate_alg_confusion_payload(token, None) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("kid_sql") {
        if let Ok(payloads) = payload::generate_kid_sql_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("kid_traversal") {
        if let Ok(payloads) = payload::generate_kid_traversal_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("jwk_embed") {
        if let Ok(p) = payload::generate_jwk_embed_payload(token) {
            payloads_out.push(p);
        }
    }

    if targets.contains("crit") {
        if let Ok(payloads) = payload::generate_crit_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("b64") {
        if let Ok(payloads) = payload::generate_b64_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("empty_sig") {
        if let Ok(payloads) = payload::generate_empty_sig_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("typ_confusion") {
        if let Ok(payloads) = payload::generate_typ_confusion_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("alg_edge") {
        if let Ok(payloads) = payload::generate_alg_edge_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("psychic") {
        if let Ok(payloads) = payload::generate_psychic_signature_payload(token) {
            payloads_out.extend(payloads.into_iter().take(2));
        }
    }

    if targets.contains("zip") {
        if let Ok(payloads) = payload::generate_zip_payload(token) {
            payloads_out.extend(payloads.into_iter().take(1));
        }
    }

    Ok(payloads_out)
}

/// Check for none algorithm vulnerability
fn check_none_algorithm(_token: &str, decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    // `decoded.algorithm` is a `jsonwebtoken::Algorithm`, which has no `none`
    // variant (the decoder maps `none` to an HS256 sentinel), so the only
    // reliable source is the raw header. Match a plain string `alg: "none"` as
    // well as the array form `alg: ["none", ...]`, a parser-confusion variant
    // some libraries resolve to the first element.
    let is_none_str =
        |v: &serde_json::Value| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("none"));
    let vulnerable = decoded.header.get("alg").is_some_and(|alg| match alg {
        serde_json::Value::Array(items) => items.iter().any(is_none_str),
        other => is_none_str(other),
    });

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
    // Only check HMAC algorithms
    let alg_str = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| format!("{:?}", decoded.algorithm));
    if !alg_str.starts_with("HS") {
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

    let result = if let Some(secret) = found_secret {
        VulnerabilityResult {
            name: "Weak Secret".to_string(),
            vulnerable: true,
            details: format!("Uses weak secret: '{}'", secret),
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
    // Pull alg from the raw header so this still works on tokens that fail
    // strict decode and only have a synthetic DecodedToken.
    let alg_str = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{:?}", decoded.algorithm));
    let alg_upper = alg_str.to_uppercase();

    let uses_asymmetric = alg_upper.starts_with("RS")
        || alg_upper.starts_with("ES")
        || alg_upper.starts_with("PS")
        || alg_upper == "EDDSA";

    let result = if uses_asymmetric {
        VulnerabilityResult {
            name: "Algorithm Confusion".to_string(),
            vulnerable: true,
            details: format!(
                "Uses {} — vulnerable to alg confusion (RS256->HS256)",
                alg_str
            ),
            severity: Severity::High,
        }
    } else {
        VulnerabilityResult {
            name: "Algorithm Confusion".to_string(),
            vulnerable: false,
            details: "Symmetric algorithm".to_string(),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Check token expiration
fn check_token_expiration(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let has_exp = decoded.claims.get("exp").is_some();
    let has_nbf = decoded.claims.get("nbf").is_some();
    let has_iat = decoded.claims.get("iat").is_some();

    let mut issues = Vec::new();

    if !has_exp {
        issues.push("Missing 'exp' (expiration) claim".to_string());
    } else if let Some(exp) = decoded.claims.get("exp").and_then(|v| v.as_i64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
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

    let vulnerable = !issues.is_empty();
    let missing_claims: Vec<&str> = [(!has_exp, "exp"), (!has_nbf, "nbf"), (!has_iat, "iat")]
        .iter()
        .filter(|(missing, _)| *missing)
        .map(|(_, name)| *name)
        .collect();
    let result = VulnerabilityResult {
        name: "Token Expiration".to_string(),
        vulnerable,
        details: if vulnerable {
            if missing_claims.is_empty() {
                issues.join("; ")
            } else {
                format!("Missing '{}'", missing_claims.join("', '"))
            }
        } else {
            "Proper expiration claims".to_string()
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
    let important_claims = vec!["sub", "aud", "iss", "jti"];
    let mut missing = Vec::new();

    for claim in &important_claims {
        if decoded.claims.get(claim).is_none() {
            missing.push(*claim);
        }
    }

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
    let result = match decoded.header.get("kid") {
        None => VulnerabilityResult {
            name: "Kid Header".to_string(),
            vulnerable: false,
            details: "No 'kid' header".to_string(),
            severity: Severity::Info,
        },
        Some(kid_value) => {
            let kid_str = kid_value.as_str().unwrap_or("").to_string();
            let lower = kid_str.to_lowercase();

            let looks_like_path = lower.contains("..")
                || lower.starts_with('/')
                || lower.starts_with("file:")
                || lower.contains('\\')
                || kid_str.contains('\0');
            let looks_like_sqli = kid_str.contains('\'')
                || lower.contains(" or ")
                || lower.contains(" union ")
                || lower.contains("--");

            let (severity, details) = if looks_like_path {
                (
                    Severity::High,
                    format!(
                        "'kid' value '{}' resembles a file path — possible path traversal / file load",
                        kid_str
                    ),
                )
            } else if looks_like_sqli {
                (
                    Severity::High,
                    format!(
                        "'kid' value '{}' contains SQL meta-characters — possible SQL injection",
                        kid_str
                    ),
                )
            } else {
                (
                    Severity::Medium,
                    format!(
                        "Has 'kid' header ('{}') — test for injection (SQLi, path traversal)",
                        kid_str
                    ),
                )
            };

            VulnerabilityResult {
                name: "Kid Header".to_string(),
                vulnerable: true,
                details,
                severity,
            }
        }
    };

    Ok(result)
}

/// Check for an embedded `jwk` header (attacker can substitute their key).
fn check_jwk_header(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let result = if decoded.header.contains_key("jwk") {
        VulnerabilityResult {
            name: "Embedded JWK".to_string(),
            vulnerable: true,
            details: "Header contains an embedded 'jwk' — verifiers that trust it accept attacker-supplied keys".to_string(),
            severity: Severity::Critical,
        }
    } else {
        VulnerabilityResult {
            name: "Embedded JWK".to_string(),
            vulnerable: false,
            details: "No embedded 'jwk' header".to_string(),
            severity: Severity::Info,
        }
    };
    Ok(result)
}

/// Check for `crit` header (RFC 7515 §4.1.11) misuse.
fn check_crit_header(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let result = if let Some(crit) = decoded.header.get("crit") {
        VulnerabilityResult {
            name: "crit Header".to_string(),
            vulnerable: true,
            details: format!(
                "Has 'crit' header ({}) — libraries that don't strictly enforce RFC 7515 §4.1.11 may skip validation",
                crit
            ),
            severity: Severity::High,
        }
    } else {
        VulnerabilityResult {
            name: "crit Header".to_string(),
            vulnerable: false,
            details: "No 'crit' header".to_string(),
            severity: Severity::Info,
        }
    };
    Ok(result)
}

/// Check for RFC 7797 `b64: false` (unencoded payload).
fn check_b64_header(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let name = "b64 Header (RFC 7797)".to_string();
    let result = match decoded.header.get("b64") {
        Some(v) if v.as_bool() == Some(false) => VulnerabilityResult {
            name,
            vulnerable: true,
            details:
                "Header sets 'b64' to false — implementations that mishandle this may accept unsigned/forged payloads"
                    .to_string(),
            severity: Severity::High,
        },
        Some(v) if v.as_bool() == Some(true) => VulnerabilityResult {
            // b64:true is the RFC default; explicit but harmless.
            name,
            vulnerable: false,
            details: "'b64' header is true (RFC default)".to_string(),
            severity: Severity::Info,
        },
        Some(v) => VulnerabilityResult {
            name,
            vulnerable: true,
            details: format!("Non-standard 'b64' header value: {}", v),
            severity: Severity::Medium,
        },
        None => VulnerabilityResult {
            name,
            vulnerable: false,
            details: "No 'b64' header".to_string(),
            severity: Severity::Info,
        },
    };
    Ok(result)
}

/// Check for an empty / suspiciously short signature segment.
fn check_signature_segment(
    token: &str,
    decoded: &jwt::DecodedToken,
) -> Result<VulnerabilityResult> {
    let parts: Vec<&str> = token.split('.').collect();
    let alg_str = format!("{:?}", decoded.algorithm).to_lowercase();
    let header_alg = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let is_none = alg_str.contains("none") || header_alg == "none";

    let sig = parts.get(2).copied().unwrap_or("");
    // The encoder writes `''` for the none-alg sentinel; treat that as empty too.
    let sig_trim = sig.trim_matches('\'');
    let is_empty = sig_trim.is_empty();

    let result = if is_empty && !is_none {
        VulnerabilityResult {
            name: "Signature Segment".to_string(),
            vulnerable: true,
            details: format!(
                "Signature is empty but 'alg' is '{}' — server may accept unsigned tokens",
                header_alg
            ),
            severity: Severity::Critical,
        }
    } else if parts.len() != 3 {
        VulnerabilityResult {
            name: "Signature Segment".to_string(),
            vulnerable: true,
            details: format!("Unexpected segment count: {}", parts.len()),
            severity: Severity::High,
        }
    } else {
        VulnerabilityResult {
            name: "Signature Segment".to_string(),
            vulnerable: false,
            details: "Signature segment present".to_string(),
            severity: Severity::Info,
        }
    };
    Ok(result)
}

/// Heuristically detect PII / sensitive data inside the claims.
fn check_sensitive_claims(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    fn looks_like_email(s: &str) -> bool {
        // Minimal email shape: x@y.z with no spaces.
        if s.len() < 5 || s.contains(' ') {
            return false;
        }
        let Some(at) = s.find('@') else {
            return false;
        };
        let (local, domain) = s.split_at(at);
        if local.is_empty() {
            return false;
        }
        let domain = &domain[1..];
        domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
    }

    fn looks_like_credit_card(s: &str) -> bool {
        // Reject strings that are mostly non-digit text — order IDs, JWT IDs,
        // hex hashes can otherwise sneak through Luhn by coincidence.
        let total = s.chars().count();
        if total == 0 {
            return false;
        }
        let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
        // Allow only digits, ASCII whitespace, and '-' separators in CC-shaped strings.
        let allowed = s
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_whitespace() || c == '-');
        if !allowed {
            return false;
        }
        if (digit_count as f64) / (total as f64) < 0.7 {
            return false;
        }
        let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
        if !(12..=19).contains(&digits.len()) {
            return false;
        }
        // Luhn check.
        let mut sum = 0u32;
        let mut alt = false;
        for d in digits.iter().rev() {
            let mut n = *d;
            if alt {
                n *= 2;
                if n > 9 {
                    n -= 9;
                }
            }
            sum += n;
            alt = !alt;
        }
        sum.is_multiple_of(10)
    }

    fn looks_like_ssn(s: &str) -> bool {
        // US SSN: 3-2-4 digits, hyphenated.
        let bytes = s.as_bytes();
        if bytes.len() != 11 {
            return false;
        }
        bytes[3] == b'-'
            && bytes[6] == b'-'
            && bytes
                .iter()
                .enumerate()
                .all(|(i, b)| matches!(i, 3 | 6) || b.is_ascii_digit())
    }

    fn walk(v: &serde_json::Value, findings: &mut Vec<String>, path: &str) {
        match v {
            serde_json::Value::String(s) => {
                if looks_like_email(s) {
                    findings.push(format!("email at '{}'", path));
                } else if looks_like_credit_card(s) {
                    findings.push(format!("credit-card-shaped value at '{}'", path));
                } else if looks_like_ssn(s) {
                    findings.push(format!("SSN-shaped value at '{}'", path));
                }
            }
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    let next = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", path, k)
                    };
                    walk(child, findings, &next);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, child) in arr.iter().enumerate() {
                    walk(child, findings, &format!("{}[{}]", path, i));
                }
            }
            _ => {}
        }
    }

    let mut findings = Vec::new();
    walk(&decoded.claims, &mut findings, "");

    let result = if findings.is_empty() {
        VulnerabilityResult {
            name: "Sensitive Claims".to_string(),
            vulnerable: false,
            details: "No obvious PII patterns in claims".to_string(),
            severity: Severity::Info,
        }
    } else {
        // De-duplicate and cap output.
        findings.sort();
        findings.dedup();
        let shown = findings
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if findings.len() > 5 {
            format!(" (+{} more)", findings.len() - 5)
        } else {
            String::new()
        };
        VulnerabilityResult {
            name: "Sensitive Claims".to_string(),
            vulnerable: true,
            details: format!("Found PII-like data: {}{}", shown, suffix),
            severity: Severity::Medium,
        }
    };
    Ok(result)
}

/// Check for JKU/X5U header vulnerabilities
fn check_jku_x5u_vulnerabilities(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let has_jku = decoded.header.contains_key("jku");
    let has_x5u = decoded.header.contains_key("x5u");

    let result = if has_jku || has_x5u {
        let header_type = if has_jku { "jku" } else { "x5u" };
        let header_value = decoded.header.get(header_type);

        VulnerabilityResult {
            name: "JKU/X5U Header".to_string(),
            vulnerable: true,
            details: format!(
                "Has '{}' header ({}), URL spoofing risk",
                header_type,
                header_value.map(|v| v.to_string()).unwrap_or_default()
            ),
            severity: Severity::High,
        }
    } else {
        VulnerabilityResult {
            name: "JKU/X5U Header".to_string(),
            vulnerable: false,
            details: "No JKU/X5U headers".to_string(),
            severity: Severity::Info,
        }
    };

    Ok(result)
}

/// Check for `typ` confusion (non-standard or omitted media types).
fn check_typ_confusion(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let name = "typ Confusion".to_string();
    let result = match decoded.header.get("typ").and_then(|v| v.as_str()) {
        Some("JWT") => VulnerabilityResult {
            name,
            vulnerable: false,
            details: "'typ' is JWT".to_string(),
            severity: Severity::Info,
        },
        Some(other) => {
            let suspicious = matches!(
                other,
                "at+jwt" | "JOSE" | "JOSE+JSON" | "application/jwt" | "jwt"
            ) || other.contains('\0');
            if suspicious {
                VulnerabilityResult {
                    name,
                    vulnerable: true,
                    details: format!(
                        "Non-canonical 'typ': '{}' — verify the server accepts only expected media types",
                        other
                    ),
                    severity: Severity::Medium,
                }
            } else {
                VulnerabilityResult {
                    name,
                    vulnerable: false,
                    details: format!("'typ' is '{}'", other),
                    severity: Severity::Info,
                }
            }
        }
        None => VulnerabilityResult {
            name,
            vulnerable: true,
            details:
                "'typ' header missing — some validators reject, others accept arbitrary tokens"
                    .to_string(),
            severity: Severity::Low,
        },
    };
    Ok(result)
}

/// Check for edge-shape `alg` values (empty, null, array, whitespace).
fn check_alg_edge(token: &str, _decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    use base64::Engine;
    let name = "alg Edge Value".to_string();
    let parts: Vec<&str> = token.split('.').collect();
    let header_b64 = parts.first().copied().unwrap_or("");
    let raw = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64) {
        Ok(b) => b,
        Err(_) => {
            return Ok(VulnerabilityResult {
                name,
                vulnerable: false,
                details: "Header not base64url".to_string(),
                severity: Severity::Info,
            });
        }
    };
    let val: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => {
            return Ok(VulnerabilityResult {
                name,
                vulnerable: false,
                details: "Header not JSON".to_string(),
                severity: Severity::Info,
            });
        }
    };
    let alg = val.get("alg");
    let result = match alg {
        None => VulnerabilityResult {
            name,
            vulnerable: true,
            details: "'alg' header is missing".to_string(),
            severity: Severity::High,
        },
        Some(serde_json::Value::Null) => VulnerabilityResult {
            name,
            vulnerable: true,
            details: "'alg' header is null".to_string(),
            severity: Severity::High,
        },
        Some(serde_json::Value::Array(_)) => VulnerabilityResult {
            name,
            vulnerable: true,
            details: "'alg' is an array — parsers disagree on which element to take".to_string(),
            severity: Severity::High,
        },
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if s.is_empty() {
                VulnerabilityResult {
                    name,
                    vulnerable: true,
                    details: "'alg' is an empty string".to_string(),
                    severity: Severity::High,
                }
            } else if trimmed != s {
                VulnerabilityResult {
                    name,
                    vulnerable: true,
                    details: format!("'alg' has surrounding whitespace: '{}'", s),
                    severity: Severity::Medium,
                }
            } else if s.contains('\0') {
                VulnerabilityResult {
                    name,
                    vulnerable: true,
                    details: "'alg' contains a NUL byte".to_string(),
                    severity: Severity::High,
                }
            } else {
                VulnerabilityResult {
                    name,
                    vulnerable: false,
                    details: "'alg' is a plain string".to_string(),
                    severity: Severity::Info,
                }
            }
        }
        Some(other) => VulnerabilityResult {
            name,
            vulnerable: true,
            details: format!("'alg' has unexpected JSON type: {}", other),
            severity: Severity::Medium,
        },
    };
    Ok(result)
}

/// Detect ECDSA psychic signatures (r=s=0, CVE-2022-21449).
fn check_psychic_signature(
    token: &str,
    decoded: &jwt::DecodedToken,
) -> Result<VulnerabilityResult> {
    use base64::Engine;
    let name = "Psychic Signature".to_string();
    // Read `alg` from the raw header so this still fires on tokens that fail
    // strict decode (where `decoded.algorithm` is only an HS256 sentinel) and on
    // curves jwt-hack's decoder doesn't model (e.g. ES512 / CVE-2022-21449 on P-521).
    let alg_str = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .map(str::to_uppercase)
        .unwrap_or_else(|| format!("{:?}", decoded.algorithm).to_uppercase());
    if !alg_str.starts_with("ES") {
        return Ok(VulnerabilityResult {
            name,
            vulnerable: false,
            details: format!("Not applicable for {}", alg_str),
            severity: Severity::Info,
        });
    }
    let parts: Vec<&str> = token.split('.').collect();
    let sig_b64 = parts.get(2).copied().unwrap_or("");
    let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64) {
        Ok(b) => b,
        Err(_) => {
            return Ok(VulnerabilityResult {
                name,
                vulnerable: false,
                details: "Signature is not base64url".to_string(),
                severity: Severity::Info,
            });
        }
    };
    let all_zero = !sig_bytes.is_empty() && sig_bytes.iter().all(|b| *b == 0);
    let result = if all_zero {
        VulnerabilityResult {
            name,
            vulnerable: true,
            details: format!(
                "{} signature is all-zero — accepted by vulnerable Java JDK (CVE-2022-21449)",
                alg_str
            ),
            severity: Severity::Critical,
        }
    } else {
        VulnerabilityResult {
            name,
            vulnerable: false,
            details: "ECDSA signature is non-zero".to_string(),
            severity: Severity::Info,
        }
    };
    Ok(result)
}

/// Check for non-standard `zip` (compression) values.
fn check_zip_header(decoded: &jwt::DecodedToken) -> Result<VulnerabilityResult> {
    let name = "zip Header".to_string();
    let result = match decoded.header.get("zip") {
        None => VulnerabilityResult {
            name,
            vulnerable: false,
            details: "No 'zip' header".to_string(),
            severity: Severity::Info,
        },
        Some(v) => match v.as_str() {
            // "DEF" is the only RFC 7516 §4.1.3 value.
            Some("DEF") => VulnerabilityResult {
                name,
                vulnerable: true,
                details: "Token uses DEFLATE compression — verify the decoder enforces a size cap"
                    .to_string(),
                severity: Severity::Low,
            },
            Some(other) => VulnerabilityResult {
                name,
                vulnerable: true,
                details: format!(
                    "Non-standard 'zip' value: '{}' — only 'DEF' is defined",
                    other
                ),
                severity: Severity::Medium,
            },
            None => VulnerabilityResult {
                name,
                vulnerable: true,
                details: format!("'zip' is not a string: {}", v),
                severity: Severity::Medium,
            },
        },
    };
    Ok(result)
}

/// Display scan results
fn display_results(results: &[VulnerabilityResult]) {
    println!("\n{}", theme::section_line("Results"));
    println!();

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

        // Badge carries both status and severity. Pad the plain name *before*
        // coloring so the columns line up under a real TTY.
        let name_padded = format!("{:<22}", result.name);
        println!(
            "{}{}  {} {}",
            theme::INDENT,
            result.severity.badge(result.vulnerable),
            name_padded.bold(),
            result.details
        );
    }

    // Summary
    println!("\n{}", theme::section_line("Summary"));
    println!();
    if vulnerable_count > 0 {
        let mut parts = Vec::new();
        if critical_count > 0 {
            parts.push(format!("{} critical", critical_count));
        }
        if high_count > 0 {
            parts.push(format!("{} high", high_count));
        }
        if medium_count > 0 {
            parts.push(format!("{} medium", medium_count));
        }
        if low_count > 0 {
            parts.push(format!("{} low", low_count));
        }
        println!(
            "{}{} vulnerabilities found: {}",
            theme::INDENT,
            vulnerable_count,
            parts.join(", ")
        );
    } else {
        println!(
            "{}{} No vulnerabilities detected",
            theme::INDENT,
            theme::G_OK.green()
        );
    }
}

fn export_scan_report(report: &ScanReport, path: &PathBuf) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "json".to_string());

    match ext.as_str() {
        "json" => {
            let content = serde_json::to_string_pretty(report)?;
            std::fs::write(path, content)?;
            Ok(())
        }
        "html" | "htm" => {
            let html = render_scan_report_html(report);
            std::fs::write(path, html)?;
            Ok(())
        }
        _ => anyhow::bail!("Unsupported report extension: .{}. Use .json or .html", ext),
    }
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_scan_report_html(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    out.push_str("<title>jwt-hack scan report</title>");
    out.push_str("<style>");
    out.push_str("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,Helvetica,Arial,sans-serif;margin:24px;color:#0f172a}");
    out.push_str(".meta,.summary{display:flex;gap:16px;flex-wrap:wrap}");
    out.push_str(
        ".card{border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px;background:#fff}",
    );
    out.push_str("table{border-collapse:collapse;width:100%;margin-top:12px}");
    out.push_str("th,td{border-bottom:1px solid #e2e8f0;text-align:left;padding:10px 8px;vertical-align:top}");
    out.push_str("th{background:#f8fafc;font-weight:600}");
    out.push_str(".sev{font-weight:700}");
    out.push_str(".sev-CRITICAL{color:#b91c1c}.sev-HIGH{color:#b45309}.sev-MEDIUM{color:#a16207}.sev-LOW{color:#1d4ed8}.sev-INFO{color:#0891b2}");
    out.push_str("pre{white-space:pre-wrap;word-break:break-all;background:#0b1220;color:#e2e8f0;padding:12px;border-radius:10px;overflow:auto}");
    out.push_str("</style></head><body>");

    out.push_str("<h1>jwt-hack scan report</h1>");
    out.push_str("<div class=\"meta\">");
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Algorithm</strong></div><div>{}</div></div>",
        html_escape(&report.algorithm)
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Type</strong></div><div>{}</div></div>",
        html_escape(&report.typ)
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Strict Decode</strong></div><div>{}</div></div>",
        if report.strict_decode_ok {
            "OK"
        } else {
            "REJECTED"
        }
    ));
    if let Some(err) = &report.strict_decode_error {
        out.push_str(&format!(
            "<div class=\"card\"><div><strong>Strict Decode Error</strong></div><div>{}</div></div>",
            html_escape(err)
        ));
    }
    out.push_str("</div>");

    out.push_str("<h2>Summary</h2>");
    out.push_str("<div class=\"summary\">");
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Vulnerabilities</strong></div><div>{}</div></div>",
        report.summary.vulnerabilities
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Critical</strong></div><div>{}</div></div>",
        report.summary.critical
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>High</strong></div><div>{}</div></div>",
        report.summary.high
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Medium</strong></div><div>{}</div></div>",
        report.summary.medium
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div><strong>Low</strong></div><div>{}</div></div>",
        report.summary.low
    ));
    out.push_str("</div>");

    out.push_str("<h2>Results</h2>");
    out.push_str("<table><thead><tr><th>Status</th><th>Check</th><th>Severity</th><th>Details</th></tr></thead><tbody>");
    for r in &report.results {
        let status = if r.vulnerable { "VULNERABLE" } else { "OK" };
        let severity = r.severity.as_str();
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"sev sev-{}\">{}</td><td>{}</td></tr>",
            status,
            html_escape(&r.name),
            html_escape(severity),
            html_escape(severity),
            html_escape(&r.details)
        ));
    }
    out.push_str("</tbody></table>");

    if let Some(payloads) = &report.attack_payloads {
        if !payloads.is_empty() {
            out.push_str("<h2>Attack Payloads</h2>");
            out.push_str("<pre>");
            for p in payloads {
                out.push_str(&html_escape(p));
                out.push('\n');
            }
            out.push_str("</pre>");
        }
    }

    out.push_str("</body></html>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

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
            execute(&token, None, true, true, None, 10);
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

    /// Build a synthetic token whose header carries the given extra fields and
    /// whose claims are the supplied JSON value. The signature is junk — these
    /// helpers feed checks that only look at parsed header/claims, never verify.
    fn synthetic_token(extra_header: serde_json::Value, claims: serde_json::Value) -> String {
        use base64::Engine;
        let mut header = json!({ "alg": "HS256", "typ": "JWT" });
        if let Some(map) = extra_header.as_object() {
            for (k, v) in map {
                header[k] = v.clone();
            }
        }
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&header).unwrap().as_bytes());
        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&claims).unwrap().as_bytes());
        format!("{header_b64}.{claims_b64}.fake")
    }

    /// Build a synthetic `DecodedToken` directly from a raw header JSON, with
    /// null claims and an HS256 sentinel algorithm. Use this for testing
    /// header-shape checks against headers that `jwt::decode` would reject.
    fn header_only_decoded(header_json: &str) -> jwt::DecodedToken {
        let header: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_str(header_json).unwrap();
        jwt::DecodedToken {
            header,
            claims: serde_json::Value::Null,
            algorithm: jsonwebtoken::Algorithm::HS256,
        }
    }

    #[test]
    fn test_check_b64_header_false_is_high() {
        let token = synthetic_token(json!({ "b64": false }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_b64_header(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn test_check_b64_header_true_is_info() {
        // b64:true is the RFC default — must not be reported as a vulnerability.
        let token = synthetic_token(json!({ "b64": true }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_b64_header(&decoded).unwrap();
        assert!(!r.vulnerable);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn test_check_b64_header_missing_is_info() {
        let token = synthetic_token(json!({}), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_b64_header(&decoded).unwrap();
        assert!(!r.vulnerable);
        assert_eq!(r.severity, Severity::Info);
    }

    #[test]
    fn test_check_jwk_header_detects_embedded_jwk() {
        let token = synthetic_token(
            json!({ "jwk": { "kty": "RSA", "n": "x", "e": "AQAB" } }),
            json!({}),
        );
        let decoded = jwt::decode(&token).unwrap();
        let r = check_jwk_header(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Critical);
    }

    #[test]
    fn test_check_crit_header_present() {
        let token = synthetic_token(json!({ "crit": ["b64"] }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_crit_header(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::High);
    }

    #[test]
    fn test_check_kid_header_classifies_path_traversal() {
        let token = synthetic_token(json!({ "kid": "../../../../dev/null" }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_kid_vulnerabilities(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::High);
        assert!(r.details.contains("path"));
    }

    #[test]
    fn test_check_kid_header_classifies_sqli() {
        let token = synthetic_token(json!({ "kid": "x' UNION SELECT 1 --" }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_kid_vulnerabilities(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::High);
        assert!(r.details.to_lowercase().contains("sql"));
    }

    #[test]
    fn test_check_kid_header_plain_value_is_medium() {
        let token = synthetic_token(json!({ "kid": "my-signing-key-2024" }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_kid_vulnerabilities(&decoded).unwrap();
        assert_eq!(r.severity, Severity::Medium);
    }

    #[test]
    fn test_check_signature_segment_empty_with_alg_is_critical() {
        // Build header.payload. (empty third segment) with alg=HS256.
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
        let claims_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#.as_bytes());
        let token = format!("{header_b64}.{claims_b64}.");
        let decoded = jwt::decode(&token).unwrap();
        let r = check_signature_segment(&token, &decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Critical);
    }

    #[test]
    fn test_check_sensitive_claims_finds_pii() {
        // Valid Luhn CC: 4539148803436467
        let claims = json!({
            "sub": "u1",
            "email": "alice@example.com",
            "cc": "4539148803436467",
            "ssn": "078-05-1120",
        });
        let token = synthetic_token(json!({}), claims);
        let decoded = jwt::decode(&token).unwrap();
        let r = check_sensitive_claims(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Medium);
        assert!(r.details.contains("email at 'email'"));
        assert!(r.details.contains("credit-card-shaped value at 'cc'"));
        assert!(r.details.contains("SSN-shaped value at 'ssn'"));
    }

    #[test]
    fn test_check_sensitive_claims_clean_token() {
        let claims = json!({ "sub": "u1", "role": "admin", "iat": 1700000000 });
        let token = synthetic_token(json!({}), claims);
        let decoded = jwt::decode(&token).unwrap();
        let r = check_sensitive_claims(&decoded).unwrap();
        assert!(!r.vulnerable);
    }

    #[test]
    fn test_check_sensitive_claims_rejects_alphanumeric_id() {
        // 16 digits embedded in an order ID — must NOT be Luhn-tested as a CC
        // because the string contains non-digit / non-separator characters.
        // (4539148803436467 is Luhn-valid; bracketed by letters it must be ignored.)
        let claims = json!({ "order": "ORD-4539148803436467-XYZ" });
        let token = synthetic_token(json!({}), claims);
        let decoded = jwt::decode(&token).unwrap();
        let r = check_sensitive_claims(&decoded).unwrap();
        assert!(
            !r.vulnerable,
            "alphanumeric IDs must not be classified as credit cards"
        );
    }

    #[test]
    fn test_check_typ_confusion_flags_at_jwt_and_missing() {
        let token1 = synthetic_token(json!({ "typ": "at+jwt" }), json!({}));
        let r1 = check_typ_confusion(&jwt::decode(&token1).unwrap()).unwrap();
        assert!(r1.vulnerable);
        assert_eq!(r1.severity, Severity::Medium);

        let token2 = synthetic_token(json!({}), json!({}));
        // Drop the typ field — easiest by building header manually.
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256"}"#.as_bytes());
        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}".as_ref());
        let no_typ = format!("{header_b64}.{claims_b64}.fake");
        let _ = token2; // silence
        let r2 = check_typ_confusion(&jwt::decode(&no_typ).unwrap()).unwrap();
        assert!(r2.vulnerable);
        assert_eq!(r2.severity, Severity::Low);

        let token3 = synthetic_token(json!({ "typ": "JWT" }), json!({}));
        let r3 = check_typ_confusion(&jwt::decode(&token3).unwrap()).unwrap();
        assert!(!r3.vulnerable);
    }

    #[test]
    fn test_check_alg_edge_array_value() {
        use base64::Engine;
        let raw_header = r#"{"alg":["none","HS256"],"typ":"JWT"}"#;
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_header.as_bytes());
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}".as_ref());
        let token = format!("{h}.{c}.fake");
        // jwt::decode rejects array alg, so use a synthetic header-only DecodedToken.
        let decoded = header_only_decoded(raw_header);
        let r = check_alg_edge(&token, &decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::High);
        assert!(r.details.contains("array"));
    }

    #[test]
    fn test_check_alg_edge_whitespace() {
        use base64::Engine;
        let raw_header = r#"{"alg":" HS256 ","typ":"JWT"}"#;
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_header.as_bytes());
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}".as_ref());
        let token = format!("{h}.{c}.fake");
        let decoded = header_only_decoded(raw_header);
        let r = check_alg_edge(&token, &decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Medium);
    }

    #[test]
    fn test_check_psychic_signature_detects_all_zero_es256() {
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES256","typ":"JWT"}"#.as_bytes());
        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}".as_ref());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
        let token = format!("{header_b64}.{claims_b64}.{sig_b64}");
        let decoded = jwt::decode(&token).unwrap();
        let r = check_psychic_signature(&token, &decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Critical);
    }

    #[test]
    fn test_check_psychic_signature_ignores_non_ecdsa() {
        let token = create_test_token("HS256", "secret");
        let decoded = jwt::decode(&token).unwrap();
        let r = check_psychic_signature(&token, &decoded).unwrap();
        assert!(!r.vulnerable);
    }

    #[test]
    fn test_check_psychic_signature_detects_es512_on_fallback_path() {
        // ES512 (P-521) tokens can fail strict decode, leaving only an HS256
        // sentinel in `decoded.algorithm`. The check must still read `alg` from
        // the header so CVE-2022-21449 is caught on the header-only fallback path.
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES512","typ":"JWT"}"#.as_bytes());
        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}".as_ref());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 132]);
        let token = format!("{header_b64}.{claims_b64}.{sig_b64}");
        // Synthetic decode with the HS256 sentinel, mirroring the fallback path.
        let decoded = header_only_decoded(r#"{"alg":"ES512","typ":"JWT"}"#);
        let r = check_psychic_signature(&token, &decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Critical);
    }

    #[test]
    fn test_check_none_algorithm_array_form() {
        // `alg: ["none", "HS256"]` is a parser-confusion variant; some libraries
        // resolve to the first element and accept an unsigned token. jwt::decode
        // rejects array alg, so use a header-only DecodedToken.
        let decoded = header_only_decoded(r#"{"alg":["none","HS256"],"typ":"JWT"}"#);
        let r = check_none_algorithm("token", &decoded).unwrap();
        assert!(r.vulnerable, "array containing 'none' should be flagged");
        assert_eq!(r.name, "None Algorithm");
        assert_eq!(r.severity, Severity::Critical);
    }

    #[test]
    fn test_check_none_algorithm_array_without_none_is_safe() {
        let decoded = header_only_decoded(r#"{"alg":["HS256","RS256"],"typ":"JWT"}"#);
        let r = check_none_algorithm("token", &decoded).unwrap();
        assert!(!r.vulnerable, "array without 'none' must not be flagged");
    }

    #[test]
    fn test_check_zip_header_def_is_low() {
        // zip:DEF requires a compressed claims segment for strict decode, so
        // call the check directly against a header-only DecodedToken.
        let decoded = header_only_decoded(r#"{"alg":"HS256","typ":"JWT","zip":"DEF"}"#);
        let r = check_zip_header(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Low);
    }

    #[test]
    fn test_check_zip_header_unknown_is_medium() {
        let token = synthetic_token(json!({ "zip": "GZIP" }), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_zip_header(&decoded).unwrap();
        assert!(r.vulnerable);
        assert_eq!(r.severity, Severity::Medium);
    }

    #[test]
    fn test_check_zip_header_missing_is_info() {
        let token = synthetic_token(json!({}), json!({}));
        let decoded = jwt::decode(&token).unwrap();
        let r = check_zip_header(&decoded).unwrap();
        assert!(!r.vulnerable);
    }

    #[test]
    fn test_parse_header_only_supports_array_alg() {
        // Tokens with array `alg` fail strict decode; parse_header_only must
        // still succeed so shape checks can run.
        use base64::Engine;
        let raw_header = r#"{"alg":["none","HS256"],"typ":"JWT"}"#;
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_header.as_bytes());
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}".as_ref());
        let token = format!("{h}.{c}.fake");
        assert!(
            jwt::decode(&token).is_err(),
            "strict decode must reject array alg"
        );
        let decoded = parse_header_only(&token).expect("header-only parse should succeed");
        assert!(decoded.header.get("alg").unwrap().is_array());
    }

    #[test]
    fn test_export_scan_report_json_and_html() {
        let token = create_test_token("HS256", "test_secret");
        let options = ScanOptions {
            skip_crack: true,
            skip_payloads: true,
            wordlist: None,
            max_crack_attempts: 10,
        };
        let report = scan_token(&token, &options, false).expect("scan report");

        let dir = tempdir().expect("tempdir");
        let json_path = dir.path().join("report.json");
        export_scan_report(&report, &json_path).expect("write json report");
        let json_str = std::fs::read_to_string(&json_path).expect("read json report");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid json");
        assert_eq!(parsed.get("success").and_then(|v| v.as_bool()), Some(true));

        let html_path = dir.path().join("report.html");
        export_scan_report(&report, &html_path).expect("write html report");
        let html = std::fs::read_to_string(&html_path).expect("read html report");
        assert!(html.contains("<!doctype html>"));
        assert!(html.contains("jwt-hack scan report"));
    }
}
