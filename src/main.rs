mod cmd;
mod crack;
mod jwt;
mod payload;
mod printing;
mod utils;

fn main() {
    // Initialize custom logger
    if let Err(e) = printing::setup_logger() {
        eprintln!("Logger initialization error: {}", e);
    }

    // Print banner
    printing::banner();
    
    // Parse command line arguments
    cmd::execute();
}
