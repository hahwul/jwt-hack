use crate::printing::VERSION;
use colored::Colorize;

/// Show version command
pub fn execute() {
    println!("\n{}", "━━━ JWT-HACK ━━━".bright_green().bold());
    println!("{}: {}", "Version".bright_blue(), VERSION.bright_green());
    println!("{}: {}", "Author".bright_blue(), "@hahwul".bright_yellow());
    println!(
        "{}: {}",
        "Repository".bright_blue(),
        "https://github.com/hahwul/jwt-hack".bright_cyan()
    );
    println!("{}: {}", "License".bright_blue(), "MIT".bright_magenta());
    println!("\n{}", "Thank you for using JWT-Hack!".bright_green());
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
