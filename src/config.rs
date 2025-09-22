use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration structure for jwt-hack
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Default secret key for HMAC algorithms
    pub default_secret: Option<String>,
    /// Default algorithm to use
    pub default_algorithm: Option<String>,
    /// Default wordlist path for cracking
    pub default_wordlist: Option<PathBuf>,
    /// Default private key path
    pub default_private_key: Option<PathBuf>,
}

impl Config {
    /// Load configuration from a specific file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;
        
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.as_ref().display()))
    }

    /// Get the default config directory path using XDG specification
    pub fn default_config_dir() -> Option<PathBuf> {
        // Check XDG_CONFIG_HOME environment variable first
        if let Ok(xdg_config_home) = std::env::var("XDG_CONFIG_HOME") {
            let path = PathBuf::from(xdg_config_home).join("jwt-hack");
            if !path.to_string_lossy().is_empty() {
                return Some(path);
            }
        }

        // Fall back to platform-specific config directory
        dirs::config_dir().map(|config_dir| config_dir.join("jwt-hack"))
    }

    /// Get the default config file path
    pub fn default_config_file() -> Option<PathBuf> {
        Self::default_config_dir().map(|dir| dir.join("config.toml"))
    }

    /// Load configuration with fallback logic
    /// 1. Use provided config file path if given
    /// 2. Try default config file location
    /// 3. Return default config if no file exists
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        if let Some(path) = config_path {
            // Use explicitly provided config file
            return Self::from_file(path);
        }

        // Try default config file location
        if let Some(default_path) = Self::default_config_file() {
            if default_path.exists() {
                return Self::from_file(default_path);
            }
        }

        // Return default config if no file exists
        Ok(Self::default())
    }

    /// Create default config directory if it doesn't exist
    pub fn ensure_config_dir() -> Result<Option<PathBuf>> {
        if let Some(config_dir) = Self::default_config_dir() {
            if !config_dir.exists() {
                fs::create_dir_all(&config_dir)
                    .with_context(|| format!("Failed to create config directory: {}", config_dir.display()))?;
            }
            Ok(Some(config_dir))
        } else {
            Ok(None)
        }
    }

    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config to TOML")?;

        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        fs::write(path.as_ref(), content)
            .with_context(|| format!("Failed to write config file: {}", path.as_ref().display()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.default_secret.is_none());
        assert!(config.default_algorithm.is_none());
        assert!(config.default_wordlist.is_none());
        assert!(config.default_private_key.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config {
            default_secret: Some("test_secret".to_string()),
            default_algorithm: Some("HS256".to_string()),
            default_wordlist: Some(PathBuf::from("/path/to/wordlist.txt")),
            default_private_key: Some(PathBuf::from("/path/to/key.pem")),
        };

        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.default_secret, deserialized.default_secret);
        assert_eq!(config.default_algorithm, deserialized.default_algorithm);
        assert_eq!(config.default_wordlist, deserialized.default_wordlist);
        assert_eq!(config.default_private_key, deserialized.default_private_key);
    }

    #[test]
    fn test_config_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("test_config.toml");

        let config_content = r#"
default_secret = "my_secret"
default_algorithm = "HS512"
default_wordlist = "/path/to/wordlist.txt"
default_private_key = "/path/to/private.pem"
"#;

        fs::write(&config_file, config_content).unwrap();

        let config = Config::from_file(&config_file).unwrap();
        assert_eq!(config.default_secret, Some("my_secret".to_string()));
        assert_eq!(config.default_algorithm, Some("HS512".to_string()));
        assert_eq!(config.default_wordlist, Some(PathBuf::from("/path/to/wordlist.txt")));
        assert_eq!(config.default_private_key, Some(PathBuf::from("/path/to/private.pem")));
    }

    #[test]
    fn test_config_load_with_fallback() {
        // Test loading with non-existent file should return default config
        let config = Config::load(None).unwrap();
        assert!(config.default_secret.is_none());
    }

    #[test]
    fn test_save_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("save_test.toml");

        let config = Config {
            default_secret: Some("saved_secret".to_string()),
            default_algorithm: Some("HS256".to_string()),
            default_wordlist: None,
            default_private_key: None,
        };

        config.save_to_file(&config_file).unwrap();

        let loaded_config = Config::from_file(&config_file).unwrap();
        assert_eq!(config.default_secret, loaded_config.default_secret);
        assert_eq!(config.default_algorithm, loaded_config.default_algorithm);
    }

    #[test]
    fn test_default_config_dir() {
        // This test just ensures the function doesn't panic
        // The actual path depends on the environment
        let _config_dir = Config::default_config_dir();
    }

    #[test]
    fn test_ensure_config_dir() {
        // This test just ensures the function doesn't panic
        let _result = Config::ensure_config_dir();
    }
}