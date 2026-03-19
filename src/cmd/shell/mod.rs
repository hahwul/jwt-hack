use std::io;
use std::path::PathBuf;
use std::sync::mpsc;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, text::Text, Terminal};

use crate::utils;

mod capture;
pub mod completion;
mod history;
mod ui;

use completion::CompletionState;
use history::History;

/// Session state maintained across shell commands
pub struct Session {
    pub token: Option<String>,
    pub secret: Option<String>,
    pub algorithm: String,
    pub private_key: Option<PathBuf>,
    pub wordlist: Option<PathBuf>,
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

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            secret: self.secret.clone(),
            algorithm: self.algorithm.clone(),
            private_key: self.private_key.clone(),
            wordlist: self.wordlist.clone(),
        }
    }
}

impl Session {
    pub fn prompt(&self) -> String {
        let token_indicator = if self.token.is_some() { "JWT" } else { "---" };
        format!("jwt-hack({})[{}]> ", self.algorithm, token_indicator)
    }
}

/// App mode
pub enum AppMode {
    Normal,
    Completing(CompletionState),
}

/// Main application state
pub struct App {
    pub session: Session,
    pub input: String,
    pub cursor_position: usize,
    pub output_lines: Text<'static>,
    pub scroll_offset: usize,
    pub history: History,
    pub mode: AppMode,
    pub should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            session: Session::default(),
            input: String::new(),
            cursor_position: 0,
            output_lines: Text::default(),
            scroll_offset: 0,
            history: History::new(1000),
            mode: AppMode::Normal,
            should_quit: false,
        }
    }

    /// Add a styled Text block to the output area
    fn push_output(&mut self, text: Text<'static>) {
        for line in text.lines {
            self.output_lines.lines.push(line);
        }
        // Auto-scroll to bottom
        self.scroll_to_bottom();
    }

    /// Add a plain string line to output
    fn push_output_raw(&mut self, s: &str) {
        for line in s.lines() {
            self.output_lines
                .lines
                .push(ratatui::text::Line::raw(format!("  {line}")));
        }
        self.scroll_to_bottom();
    }

    /// Add a command echo line (shows what the user typed)
    fn push_command_echo(&mut self, cmd: &str) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};

        self.output_lines.lines.push(Line::from(vec![
            Span::styled("  > ", Style::default().fg(Color::DarkGray)),
            Span::styled(cmd.to_string(), Style::default().fg(Color::White)),
        ]));
    }

    /// Add a success message to output
    fn push_success(&mut self, msg: &str) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};

        self.output_lines.lines.push(Line::from(vec![
            Span::styled("  ✓ ", Style::default().fg(Color::Green)),
            Span::styled(msg.to_string(), Style::default().fg(Color::White)),
        ]));
        self.scroll_to_bottom();
    }

    /// Add an error message to output
    fn push_error(&mut self, msg: &str) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};

        self.output_lines.lines.push(Line::from(vec![
            Span::styled("  ✗ ", Style::default().fg(Color::Red)),
            Span::styled(msg.to_string(), Style::default().fg(Color::White)),
        ]));
        self.scroll_to_bottom();
    }

    /// Add a warning message to output
    fn push_warning(&mut self, msg: &str) {
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};

        self.output_lines.lines.push(Line::from(vec![
            Span::styled("  ⚠ ", Style::default().fg(Color::Yellow)),
            Span::styled(msg.to_string(), Style::default().fg(Color::White)),
        ]));
        self.scroll_to_bottom();
    }

    fn scroll_to_bottom(&mut self) {
        let total = self.output_lines.lines.len();
        // We'll let the UI renderer handle the actual scroll calculation
        // Setting to a large value means "auto-scroll to bottom"
        self.scroll_offset = total;
    }

    fn visible_height(&self) -> usize {
        // Approximate; actual value depends on terminal size.
        // The UI renderer will clamp this.
        20
    }
}

/// Entry point for the interactive shell
pub fn execute() {
    match run_tui() {
        Ok(()) => {}
        Err(e) => {
            // Make sure terminal is restored on error
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            utils::log_error(format!("Shell error: {e}"));
        }
    }
}

fn run_tui() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    // Channel for receiving async command output
    let (tx, rx) = mpsc::channel::<AsyncResult>();

    // Main event loop
    loop {
        terminal.draw(|frame| ui::render(frame, &app))?;

        // Check for async results (non-blocking)
        if let Ok(result) = rx.try_recv() {
            app.push_output(result.output);
            app.push_output_raw(""); // blank line
        }

        // Poll for events with a short timeout for responsive async updates
        if event::poll(std::time::Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                handle_key_event(key, &mut app, &tx);
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Save history
    app.history.save();

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

struct AsyncResult {
    output: Text<'static>,
}

fn handle_key_event(key: KeyEvent, app: &mut App, tx: &mpsc::Sender<AsyncResult>) {
    // Handle completion mode keys first
    if let AppMode::Completing(_) = &app.mode {
        match key.code {
            KeyCode::Tab => {
                // Cycle to next completion
                if let AppMode::Completing(ref mut state) = app.mode {
                    state.next();
                    let (new_input, new_cursor) = state.apply(&app.input);
                    app.input = new_input;
                    app.cursor_position = new_cursor;
                }
                return;
            }
            KeyCode::BackTab => {
                // Cycle to previous completion
                if let AppMode::Completing(ref mut state) = app.mode {
                    state.prev();
                    let (new_input, new_cursor) = state.apply(&app.input);
                    app.input = new_input;
                    app.cursor_position = new_cursor;
                }
                return;
            }
            KeyCode::Esc => {
                app.mode = AppMode::Normal;
                return;
            }
            KeyCode::Enter => {
                // Accept current completion and submit
                if let AppMode::Completing(ref state) = app.mode {
                    let (new_input, new_cursor) = state.apply(&app.input);
                    app.input = new_input;
                    app.cursor_position = new_cursor;
                }
                app.mode = AppMode::Normal;
                // Don't return — fall through to normal Enter handling below
                // Actually, let's just accept the completion and return to normal
                return;
            }
            _ => {
                // Any other key exits completion mode
                app.mode = AppMode::Normal;
                // Fall through to handle the key normally
            }
        }
    }

    match (key.modifiers, key.code) {
        // Ctrl+C — exit
        (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
            app.should_quit = true;
        }
        // Ctrl+A — move cursor to start
        (KeyModifiers::CONTROL, KeyCode::Char('a')) => {
            app.cursor_position = 0;
        }
        // Ctrl+E — move cursor to end
        (KeyModifiers::CONTROL, KeyCode::Char('e')) => {
            app.cursor_position = app.input.len();
        }
        // Ctrl+U — clear input
        (KeyModifiers::CONTROL, KeyCode::Char('u')) => {
            app.input.clear();
            app.cursor_position = 0;
        }
        // Ctrl+W — delete word backward
        (KeyModifiers::CONTROL, KeyCode::Char('w')) => {
            if app.cursor_position > 0 {
                let before = &app.input[..app.cursor_position];
                let trimmed = before.trim_end();
                let new_end = trimmed.rfind(' ').map(|i| i + 1).unwrap_or(0);
                let after = &app.input[app.cursor_position..];
                app.input = format!("{}{}", &app.input[..new_end], after);
                app.cursor_position = new_end;
            }
        }
        // Enter — execute command
        (_, KeyCode::Enter) => {
            let line = app.input.trim().to_string();
            if !line.is_empty() {
                app.push_command_echo(&line);
                app.history.add(&line);
                handle_command(&line, app, tx);
                app.input.clear();
                app.cursor_position = 0;
                app.history.reset_navigation();
            }
        }
        // Tab — trigger completion
        (_, KeyCode::Tab) => {
            if let Some(state) = completion::compute_completions(&app.input, app.cursor_position) {
                // Apply first completion immediately
                let (new_input, new_cursor) = state.apply(&app.input);
                app.input = new_input;
                app.cursor_position = new_cursor;
                if state.candidates.len() > 1 {
                    app.mode = AppMode::Completing(state);
                }
            }
        }
        // Up arrow — history navigate up
        (_, KeyCode::Up) => {
            if let Some(entry) = app.history.navigate_up() {
                app.input = entry.to_string();
                app.cursor_position = app.input.len();
            }
        }
        // Down arrow — history navigate down
        (_, KeyCode::Down) => match app.history.navigate_down() {
            Some(entry) => {
                app.input = entry.to_string();
                app.cursor_position = app.input.len();
            }
            None => {
                app.input.clear();
                app.cursor_position = 0;
            }
        },
        // Left arrow
        (_, KeyCode::Left) => {
            if app.cursor_position > 0 {
                app.cursor_position -= 1;
            }
        }
        // Right arrow
        (_, KeyCode::Right) => {
            if app.cursor_position < app.input.len() {
                app.cursor_position += 1;
            }
        }
        // Home
        (_, KeyCode::Home) => {
            app.cursor_position = 0;
        }
        // End
        (_, KeyCode::End) => {
            app.cursor_position = app.input.len();
        }
        // Page Up — scroll output up
        (_, KeyCode::PageUp) => {
            let scroll_amount = app.visible_height();
            app.scroll_offset = app.scroll_offset.saturating_sub(scroll_amount);
        }
        // Page Down — scroll output down
        (_, KeyCode::PageDown) => {
            app.scroll_offset += app.visible_height();
        }
        // Backspace
        (_, KeyCode::Backspace) => {
            if app.cursor_position > 0 {
                app.input.remove(app.cursor_position - 1);
                app.cursor_position -= 1;
            }
        }
        // Delete
        (_, KeyCode::Delete) => {
            if app.cursor_position < app.input.len() {
                app.input.remove(app.cursor_position);
            }
        }
        // Character input
        (_, KeyCode::Char(c)) => {
            app.input.insert(app.cursor_position, c);
            app.cursor_position += 1;
        }
        _ => {}
    }
}

// ---------- Command dispatch ----------

const SET_KEYS: &[&str] = &["token", "secret", "algorithm", "private_key", "wordlist"];

fn handle_command(line: &str, app: &mut App, tx: &mpsc::Sender<AsyncResult>) {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "exit" | "quit" => {
            app.should_quit = true;
        }
        "help" => render_help(app),
        "show" => render_show(app),
        "clear" => {
            app.output_lines = Text::default();
            app.scroll_offset = 0;
        }
        "set" => handle_set(&parts, app),
        "decode" => handle_decode(&parts, app),
        "encode" => handle_encode(&parts, app),
        "verify" => handle_verify(&parts, app),
        "crack" => handle_crack(&parts, app, tx),
        "payload" => handle_payload(&parts, app),
        "scan" => handle_scan(&parts, app, tx),
        _ => {
            app.push_error(&format!("Unknown command: {cmd}"));
            app.push_output_raw("  Type 'help' for available commands.");
        }
    }

    // blank line after command output
    app.push_output_raw("");
}

fn render_help(app: &mut App) {
    use ratatui::style::{Modifier, Style};
    use ratatui::text::{Line, Span};

    let bold_style = Style::default().add_modifier(Modifier::BOLD);
    let dim_style = Style::default().add_modifier(Modifier::DIM);

    app.output_lines.lines.push(Line::raw(""));
    app.output_lines
        .lines
        .push(Line::from(Span::styled("  Commands", bold_style)));

    let commands = [
        ("set", "<key> <value>", "Set a session variable"),
        ("decode", "[token]", "Decode a JWT token"),
        ("encode", "<json>", "Encode JSON to JWT"),
        ("verify", "[token]", "Verify a JWT token"),
        ("crack", "[token]", "Crack a JWT secret"),
        ("payload", "[token]", "Generate attack payloads"),
        ("scan", "[token]", "Scan for vulnerabilities"),
        ("show", "", "Show current session state"),
        ("clear", "", "Clear the output"),
        ("exit", "", "Exit the shell"),
    ];

    for (name, args, desc) in commands {
        let mut spans = vec![
            Span::raw("    "),
            Span::styled(format!("{name:<10}"), bold_style),
        ];
        if !args.is_empty() {
            spans.push(Span::styled(format!("{args:<16}"), dim_style));
        } else {
            spans.push(Span::raw("                "));
        }
        spans.push(Span::raw(desc));
        app.output_lines.lines.push(Line::from(spans));
    }

    app.output_lines.lines.push(Line::raw(""));
    app.output_lines
        .lines
        .push(Line::from(Span::styled("  Set Keys", bold_style)));
    app.output_lines.lines.push(Line::from(Span::styled(
        "    token, secret, algorithm, private_key, wordlist",
        dim_style,
    )));
    app.output_lines.lines.push(Line::raw(""));
    app.output_lines
        .lines
        .push(Line::from(Span::styled("  Examples", bold_style)));

    let examples = [
        "    set token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc",
        "    set secret my_secret_key",
        "    set algorithm RS256",
        "    decode",
        "    encode {\"sub\":\"1234\"}",
    ];
    for ex in examples {
        app.output_lines
            .lines
            .push(Line::from(Span::styled(ex, dim_style)));
    }

    app.scroll_to_bottom();
}

fn render_show(app: &mut App) {
    use ratatui::style::{Modifier, Style};
    use ratatui::text::{Line, Span};

    let bold_style = Style::default().add_modifier(Modifier::BOLD);
    let dim_style = Style::default().add_modifier(Modifier::DIM);
    let default_style = Style::default();

    app.output_lines.lines.push(Line::raw(""));
    app.output_lines
        .lines
        .push(Line::from(Span::styled("  Session", bold_style)));

    // Algorithm
    app.output_lines.lines.push(Line::from(vec![
        Span::styled("    Algorithm:   ", dim_style),
        Span::styled(app.session.algorithm.clone(), default_style),
    ]));

    // Token
    let token_display = app
        .session
        .token
        .as_deref()
        .map(|t| {
            if t.len() > 40 {
                format!("{}...{}", &t[..20], &t[t.len() - 10..])
            } else {
                t.to_string()
            }
        })
        .unwrap_or_else(|| "(not set)".to_string());
    let token_style = if app.session.token.is_some() {
        default_style
    } else {
        dim_style
    };
    app.output_lines.lines.push(Line::from(vec![
        Span::styled("    Token:       ", dim_style),
        Span::styled(token_display, token_style),
    ]));

    // Secret
    let (secret_display, s_style) = if app.session.secret.is_some() {
        ("****".to_string(), default_style)
    } else {
        ("(not set)".to_string(), dim_style)
    };
    app.output_lines.lines.push(Line::from(vec![
        Span::styled("    Secret:      ", dim_style),
        Span::styled(secret_display, s_style),
    ]));

    // Private key
    let (pk_display, pk_style) = app
        .session
        .private_key
        .as_ref()
        .map(|p| (p.display().to_string(), default_style))
        .unwrap_or_else(|| ("(not set)".to_string(), dim_style));
    app.output_lines.lines.push(Line::from(vec![
        Span::styled("    Private Key: ", dim_style),
        Span::styled(pk_display, pk_style),
    ]));

    // Wordlist
    let (wl_display, wl_style) = app
        .session
        .wordlist
        .as_ref()
        .map(|p| (p.display().to_string(), default_style))
        .unwrap_or_else(|| ("(not set)".to_string(), dim_style));
    app.output_lines.lines.push(Line::from(vec![
        Span::styled("    Wordlist:    ", dim_style),
        Span::styled(wl_display, wl_style),
    ]));

    app.scroll_to_bottom();
}

fn handle_set(parts: &[&str], app: &mut App) {
    if parts.len() < 3 {
        app.push_error("Usage: set <key> <value>");
        app.push_output_raw(&format!("  Keys: {}", SET_KEYS.join(", ")));
        return;
    }

    let key = parts[1];
    let value = parts[2];

    match key {
        "token" => {
            app.session.token = Some(value.to_string());
            let preview = if value.len() > 40 {
                format!("{}...{}", &value[..20], &value[value.len() - 10..])
            } else {
                value.to_string()
            };
            app.push_success(&format!("Token set: {preview}"));
        }
        "secret" => {
            app.session.secret = Some(value.to_string());
            app.push_success("Secret set: ****");
        }
        "algorithm" => {
            app.session.algorithm = value.to_string();
            app.push_success(&format!("Algorithm set: {value}"));
        }
        "private_key" => {
            let path = PathBuf::from(value);
            if !path.exists() {
                app.push_warning(&format!("Warning: file '{value}' does not exist"));
            }
            app.session.private_key = Some(path);
            app.push_success(&format!("Private key set: {value}"));
        }
        "wordlist" => {
            let path = PathBuf::from(value);
            if !path.exists() {
                app.push_warning(&format!("Warning: file '{value}' does not exist"));
            }
            app.session.wordlist = Some(path);
            app.push_success(&format!("Wordlist set: {value}"));
        }
        _ => {
            app.push_error(&format!("Unknown key: {key}"));
            app.push_output_raw(&format!("  Valid keys: {}", SET_KEYS.join(", ")));
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

fn handle_decode(parts: &[&str], app: &mut App) {
    let token = match resolve_token(parts, &app.session) {
        Some(t) => t.to_string(),
        None => {
            app.push_error("No token provided. Use 'set token <jwt>' or 'decode <jwt>'");
            return;
        }
    };
    let output = capture::capture_command_output(|| {
        super::decode::execute(&token);
    });
    app.push_output(output.text);
}

fn handle_encode(parts: &[&str], app: &mut App) {
    if parts.len() < 2 {
        app.push_error("Usage: encode <json>");
        return;
    }

    let json_str = parts[1..].join(" ");
    let session = app.session.clone();
    let output = capture::capture_command_output(|| {
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
    });
    app.push_output(output.text);
}

fn handle_verify(parts: &[&str], app: &mut App) {
    let token = match resolve_token(parts, &app.session) {
        Some(t) => t.to_string(),
        None => {
            app.push_error("No token provided. Use 'set token <jwt>' or 'verify <jwt>'");
            return;
        }
    };
    let session = app.session.clone();
    let output = capture::capture_command_output(|| {
        super::verify::execute(
            &token,
            session.secret.as_deref(),
            session.private_key.as_ref(),
            false,
        );
    });
    app.push_output(output.text);
}

fn handle_crack(parts: &[&str], app: &mut App, tx: &mpsc::Sender<AsyncResult>) {
    let token = match resolve_token(parts, &app.session) {
        Some(t) => t.to_string(),
        None => {
            app.push_error("No token provided. Use 'set token <jwt>' or 'crack <jwt>'");
            return;
        }
    };

    app.push_output_raw("  Cracking in background...");

    let session = app.session.clone();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let output = capture::capture_command_output(|| {
            super::crack::execute(
                &token,
                "dict",
                &session.wordlist,
                "abcdefghijklmnopqrstuvwxyz0123456789",
                &None,
                20,
                4,
                false,
                false,
                &None,
                &None,
            );
        });
        let _ = tx.send(AsyncResult {
            output: output.text,
        });
    });
}

fn handle_payload(parts: &[&str], app: &mut App) {
    let token = match resolve_token(parts, &app.session) {
        Some(t) => t.to_string(),
        None => {
            app.push_error("No token provided. Use 'set token <jwt>' or 'payload <jwt>'");
            return;
        }
    };
    let output = capture::capture_command_output(|| {
        super::payload::execute(&token, None, None, "https", None);
    });
    app.push_output(output.text);
}

fn handle_scan(parts: &[&str], app: &mut App, tx: &mpsc::Sender<AsyncResult>) {
    let token = match resolve_token(parts, &app.session) {
        Some(t) => t.to_string(),
        None => {
            app.push_error("No token provided. Use 'set token <jwt>' or 'scan <jwt>'");
            return;
        }
    };

    app.push_output_raw("  Scanning in background...");

    let session = app.session.clone();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let output = capture::capture_command_output(|| {
            super::scan::execute(&token, false, false, session.wordlist.as_ref(), 100);
        });
        let _ = tx.send(AsyncResult {
            output: output.text,
        });
    });
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
        let session = Session {
            token: Some("eyJ...".to_string()),
            ..Default::default()
        };
        assert_eq!(session.prompt(), "jwt-hack(HS256)[JWT]> ");
    }

    #[test]
    fn test_session_prompt_custom_algorithm() {
        let session = Session {
            algorithm: "RS256".to_string(),
            ..Default::default()
        };
        assert_eq!(session.prompt(), "jwt-hack(RS256)[---]> ");
    }

    #[test]
    fn test_handle_set_token() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command(
            "set token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc",
            &mut app,
            &tx,
        );
        assert_eq!(
            app.session.token.as_deref(),
            Some("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc")
        );
    }

    #[test]
    fn test_handle_set_secret() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("set secret my_secret", &mut app, &tx);
        assert_eq!(app.session.secret.as_deref(), Some("my_secret"));
    }

    #[test]
    fn test_handle_set_algorithm() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("set algorithm RS256", &mut app, &tx);
        assert_eq!(app.session.algorithm, "RS256");
    }

    #[test]
    fn test_handle_set_private_key() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("set private_key /tmp/key.pem", &mut app, &tx);
        assert_eq!(app.session.private_key, Some(PathBuf::from("/tmp/key.pem")));
    }

    #[test]
    fn test_handle_set_wordlist() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("set wordlist /tmp/words.txt", &mut app, &tx);
        assert_eq!(app.session.wordlist, Some(PathBuf::from("/tmp/words.txt")));
    }

    #[test]
    fn test_handle_set_unknown_key() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("set unknown value", &mut app, &tx);
        // Should not panic, error is in output
    }

    #[test]
    fn test_handle_set_missing_value() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("set token", &mut app, &tx);
        // Should not panic, error is in output
    }

    #[test]
    fn test_handle_command_exit() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("exit", &mut app, &tx);
        assert!(app.should_quit);
    }

    #[test]
    fn test_handle_command_quit() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("quit", &mut app, &tx);
        assert!(app.should_quit);
    }

    #[test]
    fn test_handle_command_unknown() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("unknown_cmd", &mut app, &tx);
        assert!(!app.should_quit);
        // Error should be in output
    }

    #[test]
    fn test_handle_command_help() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("help", &mut app, &tx);
        assert!(!app.should_quit);
        assert!(!app.output_lines.lines.is_empty());
    }

    #[test]
    fn test_handle_command_show() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("show", &mut app, &tx);
        assert!(!app.should_quit);
        assert!(!app.output_lines.lines.is_empty());
    }

    #[test]
    fn test_handle_command_clear() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        app.push_output_raw("some output");
        assert!(!app.output_lines.lines.is_empty());
        handle_command("clear", &mut app, &tx);
        // clear resets to empty Text; "".lines() yields nothing so output stays empty
        assert!(app.output_lines.lines.is_empty());
    }

    #[test]
    fn test_handle_decode_with_inline_token() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("decode invalid.token.here", &mut app, &tx);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_handle_decode_no_token() {
        let mut app = App::new();
        let (tx, _rx) = mpsc::channel();
        handle_command("decode", &mut app, &tx);
        // Should produce error output
        assert!(!app.output_lines.lines.is_empty());
    }

    #[test]
    fn test_resolve_token_inline() {
        let session = Session::default();
        let parts = vec!["decode", "inline_token"];
        assert_eq!(resolve_token(&parts, &session), Some("inline_token"));
    }

    #[test]
    fn test_resolve_token_from_session() {
        let session = Session {
            token: Some("session_token".to_string()),
            ..Default::default()
        };
        let parts = vec!["decode"];
        assert_eq!(resolve_token(&parts, &session), Some("session_token"));
    }

    #[test]
    fn test_resolve_token_none() {
        let session = Session::default();
        let parts = vec!["decode"];
        assert_eq!(resolve_token(&parts, &session), None);
    }

    #[test]
    fn test_app_push_output() {
        let mut app = App::new();
        app.push_output_raw("hello");
        assert!(!app.output_lines.lines.is_empty());
    }

    #[test]
    fn test_app_push_command_echo() {
        let mut app = App::new();
        app.push_command_echo("decode");
        assert_eq!(app.output_lines.lines.len(), 1);
    }

    #[test]
    fn test_app_push_success_error_warning() {
        let mut app = App::new();
        app.push_success("ok");
        app.push_error("fail");
        app.push_warning("warn");
        assert_eq!(app.output_lines.lines.len(), 3);
    }
}
