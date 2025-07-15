mod cmd;
mod crack;
mod jwt;
mod payload;
mod printing;
mod utils;

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
