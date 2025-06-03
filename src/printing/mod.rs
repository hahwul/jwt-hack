pub mod banner;
pub mod version;

use colored::Colorize;

pub use banner::banner;
pub use version::VERSION;

pub fn out(text: &str) {
    eprintln!("{}", text.cyan());
}