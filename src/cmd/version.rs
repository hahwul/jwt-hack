use crate::printing::VERSION;
use colored::Colorize;

/// Displays version information and other project details
pub fn execute() {
    println!("  {:<14}{}", "Version".dimmed(), VERSION);
    println!("  {:<14}@hahwul", "Author".dimmed());
    println!(
        "  {:<14}https://github.com/hahwul/jwt-hack",
        "Repository".dimmed()
    );
    println!("  {:<14}MIT", "License".dimmed());
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
