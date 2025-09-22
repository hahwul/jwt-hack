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

    // Display the application banner
    printing::banner();

    // Parse and execute command line arguments
    cmd::execute();
}
