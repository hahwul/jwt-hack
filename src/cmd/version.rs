use crate::printing::VERSION;
use colored::Colorize;

/// Displays version information and other project details
pub fn execute() {
    println!(
        "  {:<14}{}",
        "Version".dimmed(),
        VERSION
    );
    println!(
        "  {:<14}{}",
        "Author".dimmed(),
        "@hahwul"
    );
    println!(
        "  {:<14}{}",
        "Repository".dimmed(),
        "https://github.com/hahwul/jwt-hack"
    );
    println!(
        "  {:<14}{}",
        "License".dimmed(),
        "MIT"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_no_panic() {
        // Simply test that execute() does not panic
        let result = std::panic::catch_unwind(|| {
            execute();
        });

        assert!(result.is_ok(), "execute() should not panic");
    }
}
