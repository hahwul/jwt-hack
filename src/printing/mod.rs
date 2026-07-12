pub mod theme;
pub mod version;

use colored::Colorize;
use log::{Level, LevelFilter, Metadata, Record};
use std::io::Write;

pub use version::VERSION;

// Custom logger structure
pub struct PrettyLogger;

impl log::Log for PrettyLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Dim, second-precision timestamp keeps the line scannable without the
            // noisy `[..] [..]` brackets of the old format.
            let timestamp = chrono::Local::now().format("%H:%M:%S");
            let glyph = match record.level() {
                Level::Error => theme::G_ERR.red(),
                Level::Warn => theme::G_WARN.yellow(),
                Level::Info => theme::G_INFO.cyan(),
                Level::Debug => theme::G_DEBUG.dimmed(),
                Level::Trace => theme::G_TRACE.dimmed(),
            };

            // Only escalated levels tint the message body; info/trace stay plain
            // so routine status output reads calmly.
            let message = match record.level() {
                Level::Error => record.args().to_string().red(),
                Level::Warn => record.args().to_string().yellow(),
                Level::Debug => record.args().to_string().dimmed(),
                Level::Info | Level::Trace => record.args().to_string().normal(),
            };

            let _ = writeln!(
                std::io::stderr(),
                "{}  {} {}",
                timestamp.to_string().dimmed(),
                glyph,
                message
            );
        }
    }

    fn flush(&self) {}
}

// Initialize the custom logger
pub fn setup_logger() -> Result<(), log::SetLoggerError> {
    log::set_logger(&PrettyLogger).map(|()| log::set_max_level(LevelFilter::Info))
}

// Print the banner with version information.
//
// The mark stacks two words — "JWT" over "HACK". The identity metadata (tagline,
// version/author, URL) is tucked into the whitespace to the right of the "JWT"
// rows so the name and description read as one unit with the art rather than a
// detached footer. Art is padded to a fixed column *before* coloring so the
// metadata stays aligned regardless of the (variable-length) version string.
pub fn banner() {
    // Top word ("JWT") — each row pairs with one identity line to its right.
    const JWT: [&str; 3] = [
        "    █ █  █  █ ████",
        "    █  █ █ █   ██",
        "   ██  ██ █    ██",
    ];
    // Bottom word ("HACK") — stands on its own beneath the paired rows.
    const HACK: [&str; 3] = [
        "  █ █   █   █   ███",
        "  █ █  ███  █   ██",
        "  █ █ █   █  ██ █ █",
    ];
    // Column the metadata starts at (art padded to this width + a 3-space gutter).
    const ART_COL: usize = 20;

    let meta = [
        "JSON Web Token Hack Toolkit".dimmed().to_string(),
        format!(
            "{}  {}  {}",
            VERSION.green().bold(),
            "·".dimmed(),
            "@hahwul".red().bold()
        ),
        "https://github.com/hahwul/jwt-hack".dimmed().to_string(),
    ];

    eprintln!();
    for (art, info) in JWT.iter().zip(meta.iter()) {
        // Pad the plain art first, then color — padding a ColoredString would
        // count ANSI escape bytes and misalign the metadata column.
        let padded = format!("{art:<ART_COL$}");
        eprintln!("{}   {}", padded.red().bold(), info);
    }
    eprintln!();
    for row in HACK {
        eprintln!("{}", row.red().bold());
    }
    eprintln!();
}
