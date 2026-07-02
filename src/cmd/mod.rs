use clap::{Parser, Subcommand};
use log::error;
use std::path::PathBuf;

mod crack;
mod decode;
mod encode;
mod jwks;
mod mcp;
mod payload;
mod scan;
mod server;
mod shell;
mod verify;
mod version;

/// Parses command-line arguments in "key=value" format for custom header parameters
fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

/// Command-line interface for the jwt-hack tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to configuration file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Output JSON to stdout (pipeline-friendly)
    #[arg(long = "json", global = true)]
    output_json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decodes a JWT token and displays its header, payload, and validation info
    Decode {
        /// JWT token to decode
        token: String,
    },

    /// Encodes JSON data into a JWT token with specified algorithm and signing options
    Encode {
        /// JSON data to encode
        json: String,

        /// Secret key for HMAC algorithms (HS256, HS384, HS512)
        #[arg(long)]
        secret: Option<String>,

        /// RSA, ECDSA, or EdDSA private key in PEM format for asymmetric algorithms
        #[arg(long)]
        private_key: Option<PathBuf>,

        /// Algorithm to use (falls back to config `default_algorithm`, then HS256)
        #[arg(long)]
        algorithm: Option<String>,

        /// Use 'none' algorithm (no signature)
        #[arg(long)]
        no_signature: bool,

        /// Add custom header parameter (format: key=value)
        #[arg(long, value_parser = parse_key_value)]
        header: Vec<(String, String)>,

        /// Compress payload using DEFLATE compression (adds "zip":"DEF" header)
        #[arg(long)]
        compress: bool,

        /// Create JWE (JSON Web Encryption) token instead of JWT
        #[arg(long)]
        jwe: bool,
    },

    /// Verifies a JWT token's signature and optionally validates its expiration claim
    Verify {
        /// JWT token to verify
        token: String,

        /// Secret key for HMAC algorithms (HS256, HS384, HS512)
        #[arg(long)]
        secret: Option<String>,

        /// RSA, ECDSA, or EdDSA private key in PEM format for asymmetric algorithms
        #[arg(long)]
        private_key: Option<PathBuf>,

        /// Validate expiration claim (exp)
        #[arg(long)]
        validate_exp: bool,
    },

    /// Attempts to crack a JWT token using dictionary or bruteforce methods
    Crack {
        /// JWT token to crack
        token: String,

        /// Cracking mode, you can use 'dict' or 'brute'
        #[arg(short, long, default_value = "dict")]
        mode: String,

        /// Wordlist file (for dictionary attack)
        #[arg(short, long)]
        wordlist: Option<PathBuf>,

        /// Download & use a numbered preset wordlist for dictionary attacks
        /// (1=raft-medium-words, 2=raft-large-words, 3=jwt-secrets). Cached under
        /// the config dir; re-download is skipped when the cached copy matches.
        #[arg(short = 'p', long = "wordlist-preset")]
        wordlist_preset: Option<u32>,

        /// Character list (for bruteforce attack)
        #[arg(long, default_value = "abcdefghijklmnopqrstuvwxyz0123456789")]
        chars: String,

        /// Character set preset (for bruteforce attack): az, AZ, aZ, 19, aZ19, ascii
        #[arg(long)]
        preset: Option<String>,

        /// Concurrency level
        #[arg(short, long, default_value = "20")]
        concurrency: usize,

        /// Min length (for bruteforce attack, default: 1)
        #[arg(long, default_value = "1")]
        min: usize,

        /// Max length (for bruteforce attack)
        #[arg(long, default_value = "4")]
        max: usize,

        /// Use all CPU cores
        #[arg(long)]
        power: bool,

        /// Show testing log
        #[arg(long)]
        verbose: bool,

        /// Target a specific JWT field for brute-force (e.g., kid, jti)
        #[arg(long)]
        target_field: Option<String>,

        /// Pattern template for targeted field values (use {} as placeholder, e.g., "../../keys/{}")
        #[arg(long)]
        pattern: Option<String>,
    },

    /// Generates various JWT attack payloads for security testing
    Payload {
        /// JWT token to use for payload generation
        token: String,

        /// A trusted domain for jku&x5u (e.g google.com)
        #[arg(long)]
        jwk_trust: Option<String>,

        /// An attack payload domain for jku&x5u (e.g hahwul.com)
        #[arg(long)]
        jwk_attack: Option<String>,

        /// jku&x5u protocol (http/https)
        #[arg(long, default_value = "https")]
        jwk_protocol: String,

        /// Target payload types (comma-separated: all,none,jku,x5u,ssrf,alg_confusion,alg_edge,kid_sql,kid_traversal,kid_predictable,x5c,x5c_signed,cty,jwk_embed,crit,b64,empty_sig,psychic,typ_confusion,zip)
        #[arg(long, default_value = "all")]
        target: Option<String>,
    },

    /// Scans a JWT token for common vulnerabilities and security issues
    Scan {
        /// JWT token to scan
        token: String,

        /// Export scan report to a file (JSON/HTML based on file extension)
        #[arg(long)]
        report: Option<PathBuf>,

        /// Skip dictionary-based secret cracking
        #[arg(long)]
        skip_crack: bool,

        /// Skip generating attack payloads
        #[arg(long)]
        skip_payloads: bool,

        /// Wordlist file for checking weak secrets (default: common passwords)
        #[arg(short, long)]
        wordlist: Option<PathBuf>,

        /// Maximum number of secrets to test during weak secret check
        #[arg(long, default_value = "100")]
        max_crack_attempts: usize,
    },

    /// Manages JWKS (JSON Web Key Set) operations: fetch, spoof, verify, and key rotation testing
    Jwks {
        #[command(subcommand)]
        action: JwksAction,
    },

    /// Displays version information and project details
    Version,

    /// Runs jwt-hack as an MCP (Model Context Protocol) server
    Mcp,

    /// Starts an interactive shell for JWT operations
    Shell,

    /// Starts a REST API server for JWT operations
    Server {
        /// Host address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port number to listen on
        #[arg(long, default_value = "3000")]
        port: u16,

        /// API key to secure the REST API (validated against X-API-KEY header)
        #[arg(long)]
        api_key: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum JwksAction {
    /// Fetches and displays keys from a JWKS endpoint
    Fetch {
        /// JWKS endpoint URL (e.g. https://example.com/.well-known/jwks.json)
        url: String,
    },

    /// Generates a spoofed JWKS with attacker-controlled keys for jku/x5u attacks
    Spoof {
        /// Algorithm for the spoofed key (RS256, RS384, RS512, PS256, PS384, PS512)
        #[arg(long, default_value = "RS256")]
        algorithm: String,

        /// Key ID (kid) for the spoofed key
        #[arg(long)]
        kid: Option<String>,

        /// JWT token to re-sign with the spoofed key
        #[arg(long)]
        token: Option<String>,

        /// Attacker URL for jku/x5u header injection (generates full attack payloads)
        #[arg(long)]
        attacker_url: Option<String>,

        /// Output file path for the generated JWKS JSON
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verifies a JWT token against all keys in a JWKS endpoint or file
    Verify {
        /// JWT token to verify
        token: String,

        /// JWKS endpoint URL
        #[arg(long)]
        url: Option<String>,

        /// Path to a local JWKS JSON file
        #[arg(long)]
        jwks_file: Option<PathBuf>,
    },

    /// Tests a JWT token against multiple keys to detect key rotation vulnerabilities
    Rotate {
        /// JWT token to test
        token: String,

        /// Directory containing key files (.pem, .key, .pub, .txt)
        #[arg(long)]
        keys_dir: Option<PathBuf>,

        /// Individual key file paths (can be specified multiple times)
        #[arg(long = "key")]
        key_files: Vec<PathBuf>,
    },
}

/// Resolve the effective wordlist for a crack invocation.
///
/// Precedence: a `--wordlist-preset` wins (downloading/caching the preset on
/// demand), then an explicit `--wordlist`, then the configured default wordlist.
fn resolve_crack_wordlist(
    wordlist: &Option<PathBuf>,
    wordlist_preset: Option<u32>,
    config_default: &Option<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    if let Some(id) = wordlist_preset {
        return Ok(Some(crate::crack::wordlist_preset::ensure_wordlist(id)?));
    }
    if wordlist.is_some() {
        return Ok(wordlist.clone());
    }
    Ok(config_default.clone())
}

/// Parses command-line arguments and executes the appropriate command
pub fn execute() {
    let cli = Cli::parse();

    // Load configuration. Its `default_*` values are applied below as fallbacks when
    // the corresponding CLI flag is not provided (CLI flags always take precedence).
    let config = match crate::config::Config::load(cli.config.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    if cli.output_json {
        let result: anyhow::Result<serde_json::Value> = match &cli.command {
            Some(Commands::Decode { token }) => decode::execute_json(token),
            Some(Commands::Encode {
                json,
                secret,
                private_key,
                algorithm,
                no_signature,
                header,
                compress,
                jwe,
            }) => {
                let algorithm = algorithm
                    .as_deref()
                    .or(config.default_algorithm.as_deref())
                    .unwrap_or("HS256");
                encode::execute_json(
                    json,
                    secret.as_deref().or(config.default_secret.as_deref()),
                    private_key.as_ref().or(config.default_private_key.as_ref()),
                    algorithm,
                    *no_signature,
                    header,
                    *compress,
                    *jwe,
                )
            }
            Some(Commands::Verify {
                token,
                secret,
                private_key,
                validate_exp,
            }) => verify::execute_json(
                token,
                secret.as_deref().or(config.default_secret.as_deref()),
                private_key.as_ref().or(config.default_private_key.as_ref()),
                *validate_exp,
            ),
            Some(Commands::Crack {
                token,
                mode,
                wordlist,
                wordlist_preset,
                chars,
                preset,
                concurrency,
                min,
                max,
                power,
                verbose,
                target_field,
                pattern,
            }) => {
                match resolve_crack_wordlist(wordlist, *wordlist_preset, &config.default_wordlist) {
                    Ok(effective_wordlist) => crack::execute_json(
                        token,
                        mode,
                        &effective_wordlist,
                        chars,
                        preset,
                        *concurrency,
                        *min,
                        *max,
                        *power,
                        *verbose,
                        target_field,
                        pattern,
                    ),
                    Err(e) => Err(e),
                }
            }
            Some(Commands::Payload {
                token,
                jwk_trust,
                jwk_attack,
                jwk_protocol,
                target,
            }) => payload::execute_json(
                token,
                jwk_trust.as_deref(),
                jwk_attack.as_deref(),
                jwk_protocol,
                target.as_deref(),
            ),
            Some(Commands::Scan {
                token,
                report,
                skip_crack,
                skip_payloads,
                wordlist,
                max_crack_attempts,
            }) => scan::execute_json(
                token,
                report.as_ref(),
                *skip_crack,
                *skip_payloads,
                wordlist.as_ref().or(config.default_wordlist.as_ref()),
                *max_crack_attempts,
            ),
            Some(Commands::Jwks { action }) => jwks::execute_json(action),
            Some(Commands::Version) => version::execute_json(),
            Some(Commands::Mcp) => Err(anyhow::anyhow!(
                "--json is not supported with the mcp subcommand"
            )),
            Some(Commands::Shell) => Err(anyhow::anyhow!(
                "--json is not supported with the shell subcommand"
            )),
            Some(Commands::Server {
                host,
                port,
                api_key: _,
            }) => Ok(
                serde_json::json!({"success": true, "mode": "server", "host": host, "port": port}),
            ),
            None => Err(anyhow::anyhow!(
                "No command specified. Use --help for usage information."
            )),
        };

        match result {
            Ok(value) => {
                if let Err(e) = crate::output::print_json(&value) {
                    error!("Failed to print JSON output: {e}");
                    std::process::exit(1);
                }

                // Start long-running commands after emitting the startup JSON
                if let Some(Commands::Server {
                    host,
                    port,
                    api_key,
                }) = &cli.command
                {
                    let runtime = match tokio::runtime::Runtime::new() {
                        Ok(rt) => rt,
                        Err(e) => {
                            let err_value = crate::output::ErrorResponse::new(format!(
                                "Failed to create tokio runtime: {e}"
                            ));
                            let _ = crate::output::print_json(&err_value);
                            std::process::exit(1);
                        }
                    };
                    if let Some(key) = api_key.as_deref() {
                        runtime.block_on(server::execute_with_api_key(host, *port, key));
                    } else {
                        runtime.block_on(server::execute(host, *port));
                    }
                }

                // Note: Mcp/Shell are intentionally not launched here — they return an
                // error above because `--json` is unsupported for them, so control never
                // reaches this Ok arm for those subcommands.
            }
            Err(e) => {
                let err_value = crate::output::ErrorResponse::new(e.to_string());
                let _ = crate::output::print_json(&err_value);
                std::process::exit(1);
            }
        }

        return;
    }

    match &cli.command {
        Some(Commands::Decode { token }) => {
            decode::execute(token);
        }
        Some(Commands::Encode {
            json,
            secret,
            private_key,
            algorithm,
            no_signature,
            header,
            compress,
            jwe,
        }) => {
            let algorithm = algorithm
                .as_deref()
                .or(config.default_algorithm.as_deref())
                .unwrap_or("HS256");
            encode::execute(
                json,
                secret.as_deref().or(config.default_secret.as_deref()),
                private_key.as_ref().or(config.default_private_key.as_ref()),
                algorithm,
                *no_signature,
                header,
                *compress,
                *jwe,
            );
        }
        Some(Commands::Verify {
            token,
            secret,
            private_key,
            validate_exp,
        }) => {
            verify::execute(
                token,
                secret.as_deref().or(config.default_secret.as_deref()),
                private_key.as_ref().or(config.default_private_key.as_ref()),
                *validate_exp,
            );
        }
        Some(Commands::Crack {
            token,
            mode,
            wordlist,
            wordlist_preset,
            chars,
            preset,
            concurrency,
            min,
            max,
            power,
            verbose,
            target_field,
            pattern,
        }) => {
            let effective_wordlist = match resolve_crack_wordlist(
                wordlist,
                *wordlist_preset,
                &config.default_wordlist,
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to resolve wordlist preset: {e}");
                    std::process::exit(1);
                }
            };
            crack::execute(
                token,
                mode,
                &effective_wordlist,
                chars,
                preset,
                *concurrency,
                *min,
                *max,
                *power,
                *verbose,
                target_field,
                pattern,
            );
        }
        Some(Commands::Payload {
            token,
            jwk_trust,
            jwk_attack,
            jwk_protocol,
            target,
        }) => {
            payload::execute(
                token,
                jwk_trust.as_deref(),
                jwk_attack.as_deref(),
                jwk_protocol,
                target.as_deref(),
            );
        }
        Some(Commands::Scan {
            token,
            report,
            skip_crack,
            skip_payloads,
            wordlist,
            max_crack_attempts,
        }) => {
            scan::execute(
                token,
                report.as_ref(),
                *skip_crack,
                *skip_payloads,
                wordlist.as_ref().or(config.default_wordlist.as_ref()),
                *max_crack_attempts,
            );
        }
        Some(Commands::Jwks { action }) => match action {
            JwksAction::Fetch { url } => {
                jwks::execute_fetch(url);
            }
            JwksAction::Spoof {
                algorithm,
                kid,
                token,
                attacker_url,
                output,
            } => {
                jwks::execute_spoof(
                    algorithm,
                    kid.as_deref(),
                    token.as_deref(),
                    attacker_url.as_deref(),
                    output.as_ref(),
                );
            }
            JwksAction::Verify {
                token,
                url,
                jwks_file,
            } => {
                jwks::execute_verify(token, url.as_deref(), jwks_file.as_ref());
            }
            JwksAction::Rotate {
                token,
                keys_dir,
                key_files,
            } => {
                jwks::execute_rotate(token, keys_dir.as_ref(), key_files);
            }
        },
        Some(Commands::Version) => {
            version::execute();
        }
        Some(Commands::Mcp) => {
            mcp::execute();
        }
        Some(Commands::Shell) => {
            shell::execute();
        }
        Some(Commands::Server {
            host,
            port,
            api_key,
        }) => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    error!("Failed to create tokio runtime: {e}");
                    std::process::exit(1);
                }
            };
            if let Some(key) = api_key.as_deref() {
                runtime.block_on(server::execute_with_api_key(host, *port, key));
            } else {
                runtime.block_on(server::execute(host, *port));
            }
        }
        None => {
            error!("No command specified. Use --help for usage information.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_value_valid() {
        let result = parse_key_value("key=value");
        assert_eq!(result, Ok(("key".to_string(), "value".to_string())));
    }

    #[test]
    fn test_parse_key_value_with_multiple_equals() {
        let result = parse_key_value("key=value=more");
        assert_eq!(result, Ok(("key".to_string(), "value=more".to_string())));
    }

    #[test]
    fn test_parse_key_value_empty_key() {
        let result = parse_key_value("=value");
        assert_eq!(result, Ok(("".to_string(), "value".to_string())));
    }

    #[test]
    fn test_parse_key_value_empty_value() {
        let result = parse_key_value("key=");
        assert_eq!(result, Ok(("key".to_string(), "".to_string())));
    }

    #[test]
    fn test_parse_key_value_invalid_no_equals() {
        let result = parse_key_value("keyvalue");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "invalid KEY=value: no `=` found in `keyvalue`"
        );
    }

    #[test]
    fn test_parse_key_value_invalid_empty() {
        let result = parse_key_value("");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "invalid KEY=value: no `=` found in ``");
    }

    #[test]
    fn test_cli_parses_global_json_flag_before_subcommand() {
        let cli = Cli::try_parse_from(["jwt-hack", "--json", "decode", "a.b.c"]).expect("parse ok");
        assert!(cli.output_json);
        assert!(matches!(cli.command, Some(Commands::Decode { .. })));
    }

    #[test]
    fn test_cli_parses_global_json_flag_after_subcommand() {
        let cli = Cli::try_parse_from(["jwt-hack", "decode", "--json", "a.b.c"]).expect("parse ok");
        assert!(cli.output_json);
        assert!(matches!(cli.command, Some(Commands::Decode { .. })));
    }

    #[test]
    fn test_cli_parses_crack_wordlist_preset() {
        let cli = Cli::try_parse_from(["jwt-hack", "crack", "-p", "1", "a.b.c"]).expect("parse ok");
        assert!(matches!(
            cli.command,
            Some(Commands::Crack {
                wordlist_preset: Some(1),
                ..
            })
        ));

        let cli = Cli::try_parse_from(["jwt-hack", "crack", "--wordlist-preset", "2", "a.b.c"])
            .expect("parse ok");
        assert!(matches!(
            cli.command,
            Some(Commands::Crack {
                wordlist_preset: Some(2),
                ..
            })
        ));
    }

    #[test]
    fn test_resolve_crack_wordlist_precedence() {
        let explicit = Some(PathBuf::from("/tmp/explicit.txt"));
        let default = Some(PathBuf::from("/tmp/default.txt"));

        // Explicit wordlist is used when no preset is requested.
        let resolved = resolve_crack_wordlist(&explicit, None, &default).unwrap();
        assert_eq!(resolved, explicit);

        // Falls back to the configured default when neither is given.
        let resolved = resolve_crack_wordlist(&None, None, &default).unwrap();
        assert_eq!(resolved, default);

        // No wordlist at all resolves to None.
        let resolved = resolve_crack_wordlist(&None, None, &None).unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_cli_parses_scan_report_flag() {
        let cli = Cli::try_parse_from(["jwt-hack", "scan", "--report", "report.json", "a.b.c"])
            .expect("parse ok");
        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                report: Some(_),
                ..
            })
        ));
    }
}
