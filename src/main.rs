mod cmd;
mod jwt;
mod crack;
mod payload;
mod printing;

fn main() {
    // Initialize logger
    env_logger::init();
    
    // Print banner
    printing::banner();
    
    // Parse command line arguments
    cmd::execute();
}