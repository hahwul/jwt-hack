mod cmd;
mod crack;
mod jwt;
mod payload;
mod printing;

fn main() {
    // Initialize logger
    env_logger::init();

    // Parse command line arguments
    cmd::execute();
}
