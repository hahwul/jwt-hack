use colored::Colorize;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};
use std::borrow::Cow;
use std::path::PathBuf;

use crate::config::Config;
use crate::utils;

/// Session state maintained across shell commands
struct Session {
    token: Option<String>,
    secret: Option<String>,
    algorithm: String,
    private_key: Option<PathBuf>,
    wordlist: Option<PathBuf>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            token: None,
            secret: None,
            algorithm: "HS256".to_string(),
            private_key: None,
            wordlist: None,
        }
    }
}

impl Session {
    fn prompt(&self) -> String {
        let token_indicator = if self.token.is_some() {
            "JWT"
        } else {
            "---"
        };
        format!("jwt-hack({})[{}]> ", self.algorithm, token_indicator)
    }
}

/// Tab-completion and highlighting helper for rustyline
struct ShellHelper;

impl Helper for ShellHelper {}
impl Validator for ShellHelper {}
impl Hinter for ShellHelper {
    type Hint = String;
    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Highlighter for ShellHelper {
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        Cow::Owned(prompt.bright_cyan().bold().to_string())
    }
}

const COMMANDS: &[&str] = &[
    "set", "decode", "encode", "verify", "crack", "payload", "scan", "show", "clear", "help",
    "exit", "quit",
];

const SET_KEYS: &[&str] = &["token", "secret", "algorithm", "private_key", "wordlist"];

const ALGORITHMS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384",
    "PS512", "EdDSA", "none",
];

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_up_to_cursor = &line[..pos];
        let parts: Vec<&str> = line_up_to_cursor.split_whitespace().collect();

        // Determine if we're at a word boundary (trailing space)
        let at_word_boundary = line_up_to_cursor.ends_with(' ');

        match parts.len() {
            0 => {
                // Empty line - suggest all commands
                let candidates: Vec<Pair> = COMMANDS
                    .iter()
                    .map(|c| Pair {
                        display: c.to_string(),
                        replacement: c.to_string(),
                    })
                    .collect();
                Ok((0, candidates))
            }
            1 if !at_word_boundary => {
                // Typing first word - match commands
                let prefix = parts[0];
                let candidates: Vec<Pair> = COMMANDS
                    .iter()
                    .filter(|c| c.starts_with(prefix))
                    .map(|c| Pair {
                        display: c.to_string(),
                        replacement: c.to_string(),
                    })
                    .collect();
                let start = pos - prefix.len();
                Ok((start, candidates))
            }
            1 if at_word_boundary && parts[0] == "set" => {
                // After "set " - suggest keys
                let candidates: Vec<Pair> = SET_KEYS
                    .iter()
                    .map(|k| Pair {
                        display: k.to_string(),
                        replacement: k.to_string(),
                    })
                    .collect();
                Ok((pos, candidates))
            }
            2 if !at_word_boundary && parts[0] == "set" => {
                // Typing set key - match keys
                let prefix = parts[1];
                let candidates: Vec<Pair> = SET_KEYS
                    .iter()
                    .filter(|k| k.starts_with(prefix))
                    .map(|k| Pair {
                        display: k.to_string(),
                        replacement: k.to_string(),
                    })
                    .collect();
                let start = pos - prefix.len();
                Ok((start, candidates))
            }
            2 if at_word_boundary && parts[0] == "set" && parts[1] == "algorithm" => {
                // After "set algorithm " - suggest algorithms
                let candidates: Vec<Pair> = ALGORITHMS
                    .iter()
                    .map(|a| Pair {
                        display: a.to_string(),
                        replacement: a.to_string(),
                    })
                    .collect();
                Ok((pos, candidates))
            }
            3 if !at_word_boundary && parts[0] == "set" && parts[1] == "algorithm" => {
                // Typing algorithm name
                let prefix = parts[2];
                let candidates: Vec<Pair> = ALGORITHMS
                    .iter()
                    .filter(|a| a.starts_with(prefix))
                    .map(|a| Pair {
                        display: a.to_string(),
                        replacement: a.to_string(),
                    })
                    .collect();
                let start = pos - prefix.len();
                Ok((start, candidates))
            }
            _ => Ok((pos, vec![])),
        }
    }
}

/// Get the history file path
fn history_path() -> Option<PathBuf> {
    Config::default_config_dir().map(|dir| dir.join("shell_history"))
}

/// Entry point for the interactive shell
pub fn execute() {
    let mut session = Session::default();

    let helper = ShellHelper;
    let mut rl = match Editor::new() {
        Ok(editor) => editor,
        Err(e) => {
            utils::log_error(format!("Failed to initialize shell: {e}"));
            return;
        }
    };
    rl.set_helper(Some(helper));

    // Load history
    if let Some(ref path) = history_path() {
        let _ = rl.load_history(path);
    }

    println!(
        "{}",
        "Welcome to jwt-hack interactive shell!".bright_green()
    );
    println!("Type {} for available commands.\n", "help".bright_yellow());

    loop {
        let prompt = session.prompt();
        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);
                if !handle_command(line, &mut session) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                break;
            }
            Err(e) => {
                utils::log_error(format!("Shell error: {e}"));
                break;
            }
        }
    }

    // Save history
    if let Some(ref path) = history_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = rl.save_history(path);
    }

    println!("{}", "Goodbye!".bright_green());
}

/// Handle a single command line. Returns false to exit the shell.
fn handle_command(line: &str, session: &mut Session) -> bool {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "exit" | "quit" => return false,
        "help" => print_help(),
        "show" => print_session(session),
        "clear" => clear_screen(),
        "set" => handle_set(&parts, session),
        "decode" => handle_decode(&parts, session),
        "encode" => handle_encode(&parts, session),
        "verify" => handle_verify(&parts, session),
        "crack" => handle_crack(&parts, session),
        "payload" => handle_payload(&parts, session),
        "scan" => handle_scan(&parts, session),
        _ => {
            utils::log_error(format!("Unknown command: {cmd}"));
            println!("Type {} for available commands.", "help".bright_yellow());
        }
    }

    true
}

fn print_help() {
    println!("\n{}", "━━━ Available Commands ━━━".bright_cyan().bold());
    println!(
        "  {} {}       Set a session variable",
        "set".bright_green(),
        "<key> <value>".dimmed()
    );
    println!(
        "  {} {}       Decode a JWT token",
        "decode".bright_green(),
        "[token]".dimmed()
    );
    println!(
        "  {} {}       Encode JSON to JWT",
        "encode".bright_green(),
        "<json>".dimmed()
    );
    println!(
        "  {} {}       Verify a JWT token",
        "verify".bright_green(),
        "[token]".dimmed()
    );
    println!(
        "  {} {}        Crack a JWT secret",
        "crack".bright_green(),
        "[token]".dimmed()
    );
    println!(
        "  {} {}      Generate attack payloads",
        "payload".bright_green(),
        "[token]".dimmed()
    );
    println!(
        "  {} {}         Scan for vulnerabilities",
        "scan".bright_green(),
        "[token]".dimmed()
    );
    println!(
        "  {}                  Show current session state",
        "show".bright_green()
    );
    println!(
        "  {}                 Clear the terminal",
        "clear".bright_green()
    );
    println!(
        "  {}                  Exit the shell",
        "exit".bright_green()
    );
    println!("\n{}", "━━━ Set Keys ━━━".bright_cyan().bold());
    println!("  token, secret, algorithm, private_key, wordlist");
    println!("\n{}", "━━━ Examples ━━━".bright_cyan().bold());
    println!("  set token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc");
    println!("  set secret my_secret_key");
    println!("  set algorithm RS256");
    println!("  decode");
    println!("  encode {{\"sub\":\"1234\"}}");
    println!();
}

fn print_session(session: &Session) {
    println!("\n{}", "━━━ Session State ━━━".bright_cyan().bold());
    println!(
        "  Algorithm:   {}",
        session.algorithm.bright_green()
    );
    println!(
        "  Token:       {}",
        session
            .token
            .as_deref()
            .map(|t| utils::format_jwt_token(t).to_string())
            .unwrap_or_else(|| "(not set)".dimmed().to_string())
    );
    println!(
        "  Secret:      {}",
        session
            .secret
            .as_deref()
            .map(|_| "****".bright_yellow().to_string())
            .unwrap_or_else(|| "(not set)".dimmed().to_string())
    );
    println!(
        "  Private Key: {}",
        session
            .private_key
            .as_ref()
            .map(|p| p.display().to_string().bright_yellow().to_string())
            .unwrap_or_else(|| "(not set)".dimmed().to_string())
    );
    println!(
        "  Wordlist:    {}",
        session
            .wordlist
            .as_ref()
            .map(|p| p.display().to_string().bright_yellow().to_string())
            .unwrap_or_else(|| "(not set)".dimmed().to_string())
    );
    println!();
}

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
}

fn handle_set(parts: &[&str], session: &mut Session) {
    if parts.len() < 3 {
        utils::log_error("Usage: set <key> <value>");
        println!(
            "Keys: {}",
            SET_KEYS
                .iter()
                .map(|k| k.bright_yellow().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return;
    }

    let key = parts[1];
    let value = parts[2];

    match key {
        "token" => {
            session.token = Some(value.to_string());
            utils::log_success(format!("Token set: {}", utils::format_jwt_token(value)));
        }
        "secret" => {
            session.secret = Some(value.to_string());
            utils::log_success("Secret set: ****");
        }
        "algorithm" => {
            session.algorithm = value.to_string();
            utils::log_success(format!("Algorithm set: {}", value.bright_green()));
        }
        "private_key" => {
            let path = PathBuf::from(value);
            if !path.exists() {
                utils::log_warning(format!(
                    "Warning: file '{}' does not exist",
                    path.display()
                ));
            }
            session.private_key = Some(path);
            utils::log_success(format!("Private key set: {}", value.bright_yellow()));
        }
        "wordlist" => {
            let path = PathBuf::from(value);
            if !path.exists() {
                utils::log_warning(format!(
                    "Warning: file '{}' does not exist",
                    path.display()
                ));
            }
            session.wordlist = Some(path);
            utils::log_success(format!("Wordlist set: {}", value.bright_yellow()));
        }
        _ => {
            utils::log_error(format!("Unknown key: {key}"));
            println!(
                "Valid keys: {}",
                SET_KEYS
                    .iter()
                    .map(|k| k.bright_yellow().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

/// Resolve the token to use: inline argument or session token
fn resolve_token<'a>(parts: &'a [&'a str], session: &'a Session) -> Option<&'a str> {
    if parts.len() > 1 {
        Some(parts[1])
    } else {
        session.token.as_deref()
    }
}

fn handle_decode(parts: &[&str], session: &Session) {
    let token = match resolve_token(parts, session) {
        Some(t) => t,
        None => {
            utils::log_error("No token provided. Use 'set token <jwt>' or 'decode <jwt>'");
            return;
        }
    };
    super::decode::execute(token);
}

fn handle_encode(parts: &[&str], session: &Session) {
    if parts.len() < 2 {
        utils::log_error("Usage: encode <json>");
        return;
    }

    // Everything after "encode " is the JSON
    let json_str = parts[1..].join(" ");

    super::encode::execute(
        &json_str,
        session.secret.as_deref(),
        session.private_key.as_ref(),
        &session.algorithm,
        session.algorithm.to_lowercase() == "none",
        &[],
        false,
        false,
    );
}

fn handle_verify(parts: &[&str], session: &Session) {
    let token = match resolve_token(parts, session) {
        Some(t) => t,
        None => {
            utils::log_error("No token provided. Use 'set token <jwt>' or 'verify <jwt>'");
            return;
        }
    };
    super::verify::execute(
        token,
        session.secret.as_deref(),
        session.private_key.as_ref(),
        false,
    );
}

fn handle_crack(parts: &[&str], session: &Session) {
    let token = match resolve_token(parts, session) {
        Some(t) => t,
        None => {
            utils::log_error("No token provided. Use 'set token <jwt>' or 'crack <jwt>'");
            return;
        }
    };
    super::crack::execute(
        token,
        "dict",
        &session.wordlist,
        "abcdefghijklmnopqrstuvwxyz0123456789",
        &None,
        20,
        4,
        false,
        false,
    );
}

fn handle_payload(parts: &[&str], session: &Session) {
    let token = match resolve_token(parts, session) {
        Some(t) => t,
        None => {
            utils::log_error("No token provided. Use 'set token <jwt>' or 'payload <jwt>'");
            return;
        }
    };
    super::payload::execute(token, None, None, "https", None);
}

fn handle_scan(parts: &[&str], session: &Session) {
    let token = match resolve_token(parts, session) {
        Some(t) => t,
        None => {
            utils::log_error("No token provided. Use 'set token <jwt>' or 'scan <jwt>'");
            return;
        }
    };
    super::scan::execute(
        token,
        false,
        false,
        session.wordlist.as_ref(),
        100,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_default() {
        let session = Session::default();
        assert_eq!(session.algorithm, "HS256");
        assert!(session.token.is_none());
        assert!(session.secret.is_none());
        assert!(session.private_key.is_none());
        assert!(session.wordlist.is_none());
    }

    #[test]
    fn test_session_prompt_no_token() {
        let session = Session::default();
        assert_eq!(session.prompt(), "jwt-hack(HS256)[---]> ");
    }

    #[test]
    fn test_session_prompt_with_token() {
        let mut session = Session::default();
        session.token = Some("eyJ...".to_string());
        assert_eq!(session.prompt(), "jwt-hack(HS256)[JWT]> ");
    }

    #[test]
    fn test_session_prompt_custom_algorithm() {
        let mut session = Session::default();
        session.algorithm = "RS256".to_string();
        assert_eq!(session.prompt(), "jwt-hack(RS256)[---]> ");
    }

    #[test]
    fn test_handle_command_exit() {
        let mut session = Session::default();
        assert!(!handle_command("exit", &mut session));
    }

    #[test]
    fn test_handle_command_quit() {
        let mut session = Session::default();
        assert!(!handle_command("quit", &mut session));
    }

    #[test]
    fn test_handle_command_unknown() {
        let mut session = Session::default();
        assert!(handle_command("unknown_cmd", &mut session));
    }

    #[test]
    fn test_handle_command_help() {
        let mut session = Session::default();
        assert!(handle_command("help", &mut session));
    }

    #[test]
    fn test_handle_command_show() {
        let mut session = Session::default();
        assert!(handle_command("show", &mut session));
    }

    #[test]
    fn test_handle_set_token() {
        let mut session = Session::default();
        handle_command("set token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc", &mut session);
        assert_eq!(
            session.token.as_deref(),
            Some("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc")
        );
    }

    #[test]
    fn test_handle_set_secret() {
        let mut session = Session::default();
        handle_command("set secret my_secret", &mut session);
        assert_eq!(session.secret.as_deref(), Some("my_secret"));
    }

    #[test]
    fn test_handle_set_algorithm() {
        let mut session = Session::default();
        handle_command("set algorithm RS256", &mut session);
        assert_eq!(session.algorithm, "RS256");
    }

    #[test]
    fn test_handle_set_private_key() {
        let mut session = Session::default();
        handle_command("set private_key /tmp/key.pem", &mut session);
        assert_eq!(session.private_key, Some(PathBuf::from("/tmp/key.pem")));
    }

    #[test]
    fn test_handle_set_wordlist() {
        let mut session = Session::default();
        handle_command("set wordlist /tmp/words.txt", &mut session);
        assert_eq!(session.wordlist, Some(PathBuf::from("/tmp/words.txt")));
    }

    #[test]
    fn test_handle_set_unknown_key() {
        let mut session = Session::default();
        // Should not panic
        handle_command("set unknown value", &mut session);
    }

    #[test]
    fn test_handle_set_missing_value() {
        let mut session = Session::default();
        // Should not panic
        handle_command("set token", &mut session);
    }

    #[test]
    fn test_handle_decode_with_inline_token() {
        let mut session = Session::default();
        // Should not panic even with an invalid token
        assert!(handle_command("decode invalid.token.here", &mut session));
    }

    #[test]
    fn test_handle_decode_no_token() {
        let mut session = Session::default();
        // Should print error but not panic
        assert!(handle_command("decode", &mut session));
    }

    #[test]
    fn test_resolve_token_inline() {
        let session = Session::default();
        let parts = vec!["decode", "inline_token"];
        assert_eq!(resolve_token(&parts, &session), Some("inline_token"));
    }

    #[test]
    fn test_resolve_token_from_session() {
        let mut session = Session::default();
        session.token = Some("session_token".to_string());
        let parts = vec!["decode"];
        assert_eq!(resolve_token(&parts, &session), Some("session_token"));
    }

    #[test]
    fn test_resolve_token_none() {
        let session = Session::default();
        let parts = vec!["decode"];
        assert_eq!(resolve_token(&parts, &session), None);
    }
}
