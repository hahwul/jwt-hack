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

// Print the banner with version information
pub fn banner() {
    eprintln!(
        "{}",
        r#"
      ██ ██████ ██ █████ █  ██

      ██  ██   █  ██  ███████
      ██   ██ ██  ██     ██
      ██   ████████      ██
     ███    ███ ██       ██


   █   ██   ███    █████ ██ ██
   ██████   ████   ██    ████
   █   ██  █████   ██    █████
   █   ██  █   ██  ███   ██  ██

   █ █ █   █  █ █         ██
"#
        .red()
        .bold()
    );
    // Single, dot-separated identity line keeps the metadata compact and modern.
    eprintln!(
        "   {}  {}  {}  {}  {}",
        "JSON Web Token Hack Toolkit".dimmed(),
        "·".dimmed(),
        VERSION.green().bold(),
        "·".dimmed(),
        "@hahwul".red()
    );
    eprintln!("   {}\n", "https://github.com/hahwul/jwt-hack".dimmed());
}
