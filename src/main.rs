pub mod cmd;
pub mod config;
pub mod crack;
pub mod jwt;
pub mod payload;
pub mod printing;
pub mod utils;

fn main() {
    // Set up the logging system for the application
    if let Err(e) = printing::setup_logger() {
        eprintln!("Logger initialization error: {e}");
    }

    // Show banner only when help will be displayed (no args, -h, or --help)
    let args: Vec<String> = std::env::args().collect();
    let show_banner = args.len() <= 1
        || args.iter().any(|a| a == "-h" || a == "--help")
        || args.get(1).map(|a| a == "help").unwrap_or(false);
    if show_banner {
        printing::banner();
    }

    // Parse and execute command line arguments
    cmd::execute();
}
