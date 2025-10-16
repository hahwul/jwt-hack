use clap::{Parser, Subcommand};
use log::error;
use std::path::PathBuf;

mod crack;
mod decode;
mod encode;
mod mcp;
mod payload;
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

        /// Algorithm to use
        #[arg(long, default_value = "HS256")]
        algorithm: String,

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

        /// Cracking mode, you can use 'dict', 'brute', or 'field'
        #[arg(short, long, default_value = "dict")]
        mode: String,

        /// Wordlist file (for dictionary attack)
        #[arg(short, long)]
        wordlist: Option<PathBuf>,

        /// Character list (for bruteforce attack)
        #[arg(long, default_value = "abcdefghijklmnopqrstuvwxyz0123456789")]
        chars: String,

        /// Character set preset (for bruteforce attack): az, AZ, aZ, 19, aZ19, ascii
        #[arg(long)]
        preset: Option<String>,

        /// Concurrency level
        #[arg(short, long, default_value = "20")]
        concurrency: usize,

        /// Max length (for bruteforce attack)
        #[arg(long, default_value = "4")]
        max: usize,

        /// Use all CPU cores
        #[arg(long)]
        power: bool,

        /// Show testing log
        #[arg(long)]
        verbose: bool,

        /// Target field for field-specific cracking (e.g., 'kid', 'jti', 'sub')
        #[arg(long)]
        field: Option<String>,

        /// Field location: 'header' or 'payload' (for field mode)
        #[arg(long, default_value = "header")]
        field_location: String,

        /// Expected pattern for field value (for field mode)
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

        /// Target payload types (comma-separated: all,none,jku,x5u,alg_confusion,kid_sql,x5c,cty)
        #[arg(long, default_value = "all")]
        target: Option<String>,
    },

    /// Displays version information and project details
    Version,

    /// Runs jwt-hack as an MCP (Model Context Protocol) server
    Mcp,
}

/// Parses command-line arguments and executes the appropriate command
pub fn execute() {
    let cli = Cli::parse();

    // Load configuration
    let _config = match crate::config::Config::load(cli.config.as_deref()) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

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
            encode::execute(
                json,
                secret.as_deref(),
                private_key.as_ref(),
                algorithm,
                *no_signature,
                header.clone(),
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
                secret.as_deref(),
                private_key.as_ref(),
                *validate_exp,
            );
        }
        Some(Commands::Crack {
            token,
            mode,
            wordlist,
            chars,
            preset,
            concurrency,
            max,
            power,
            verbose,
            field,
            field_location,
            pattern,
        }) => {
            crack::execute(
                token,
                mode,
                wordlist,
                chars,
                preset,
                *concurrency,
                *max,
                *power,
                *verbose,
                field.as_deref(),
                field_location,
                pattern.as_deref(),
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
        Some(Commands::Version) => {
            version::execute();
        }
        Some(Commands::Mcp) => {
            mcp::execute();
        }
        None => {
            error!("No command specified. Use --help for usage information.");
        }
    }
}
