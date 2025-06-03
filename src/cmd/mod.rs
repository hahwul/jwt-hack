use clap::{Parser, Subcommand};
use log::error;
use std::path::PathBuf;

mod crack;
mod decode;
mod encode;
mod payload;
mod version;

/// CLI for jwt-hack
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decode JWT to JSON
    Decode {
        /// JWT token to decode
        token: String,
    },
    
    /// Encode JSON to JWT
    Encode {
        /// JSON data to encode
        json: String,
        
        /// Secret key for JWT signature
        #[arg(long)]
        secret: Option<String>,
        
        /// Algorithm to use
        #[arg(long, default_value = "HS256")]
        algorithm: String,
    },
    
    /// Cracking JWT Token
    Crack {
        /// JWT token to crack
        token: String,

        /// Cracking mode, you can use 'dict' or 'brute'
        #[arg(short, long, default_value = "dict")]
        mode: String,
        
        /// Wordlist file (for dictionary attack)
        #[arg(short, long)]
        wordlist: Option<PathBuf>,
        
        /// Character list (for bruteforce attack)
        #[arg(long, default_value = "abcdefghijklmnopqrstuvwxyz0123456789")]
        chars: String,
        
        /// Concurrency level
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
        
        /// Max length (for bruteforce attack)
        #[arg(long, default_value = "6")]
        max: usize,
        
        /// Use all CPU cores
        #[arg(long)]
        power: bool,
        
        /// Show testing log
        #[arg(long)]
        verbose: bool,
    },
    
    /// Generate JWT Attack payloads
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
    },
    
    /// Show version
    Version,
}

/// Execute the CLI commands
pub fn execute() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Decode { token }) => {
            decode::execute(token);
        }
        Some(Commands::Encode { json, secret, algorithm }) => {
            encode::execute(json, secret.as_deref(), algorithm);
        }
        Some(Commands::Crack { token, mode, wordlist, chars, concurrency, max, power, verbose }) => {
            crack::execute(token, mode, wordlist, chars, *concurrency, *max, *power, *verbose);
        }
        Some(Commands::Payload { token, jwk_trust, jwk_attack, jwk_protocol }) => {
            payload::execute(token, jwk_trust.as_deref(), jwk_attack.as_deref(), jwk_protocol);
        }
        Some(Commands::Version) => {
            version::execute();
        }
        None => {
            error!("No command specified. Use --help for usage information.");
        }
    }
}