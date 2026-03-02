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
            let timestamp = chrono::Local::now().format("%H:%M:%S%.3f");
            let level_str = match record.level() {
                Level::Error => format!("{}", "✗".red()),
                Level::Warn => format!("{}", "⚠".yellow()),
                Level::Info => format!("{}", "▸".cyan()),
                Level::Debug => format!("{}", "●".dimmed()),
                Level::Trace => format!("{}", "○".dimmed()),
            };

            let message = match record.level() {
                Level::Error => format!("{}", record.args().to_string().red()),
                Level::Warn => format!("{}", record.args().to_string().yellow()),
                Level::Info => format!("{}", record.args()),
                Level::Debug => format!("{}", record.args().to_string().dimmed()),
                Level::Trace => format!("{}", record.args()),
            };

            let _ = writeln!(
                std::io::stderr(),
                "[{}] [{}] {}",
                timestamp.to_string().dimmed(),
                level_str,
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
      __     __     __     ______      __  __     ______     ______     __  __
     /\ \   /\ \  _ \ \   /\__  _\    /\ \_\ \   /\  __ \   /\  ___\   /\ \/ /
    _\_\ \  \ \ \/ ".\ \  \/_/\ \/    \ \  __ \  \ \  __ \  \ \ \____  \ \  _"-.
   /\_____\  \ \__/".~\_\    \ \_\     \ \_\ \_\  \ \_\ \_\  \ \_____\  \ \_\ \_\
   \/_____/   \/_/   \/_/     \/_/      \/_/\/_/   \/_/\/_/   \/_____/   \/_/\/_/
"#
        .cyan()
    );
    eprintln!(
        "{}{}{}",
        "                JSON Web Token Hack Toolkit - ".dimmed(),
        VERSION.green(),
        " by @hahwul".dimmed()
    );
    eprintln!(
        "{}\n",
        "                https://github.com/hahwul/jwt-hack".dimmed()
    );
}
