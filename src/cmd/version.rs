use crate::printing::VERSION;
use colored::Colorize;
use serde_json::Value;

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

pub fn execute_json() -> anyhow::Result<Value> {
    Ok(serde_json::json!({
        "success": true,
        "version": VERSION,
        "author": "@hahwul",
        "repository": "https://github.com/hahwul/jwt-hack",
        "license": "MIT"
    }))
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

    #[test]
    fn test_execute_json() {
        let result = execute_json();
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value.get("success").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(value.get("version").and_then(|v| v.as_str()), Some(VERSION));
    }
}
