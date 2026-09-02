use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Common secrets for dictionary attacks
pub const COMMON_SECRETS: &[&str] = &[
    "",
    "secret",
    "password",
    "1234",
    "123456",
    "admin",
    "test",
    "key",
    "jwt",
    "token",
    "your-256-bit-secret",
    "your-secret",
    "mysecret",
    "default",
    "changeme",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
    "monkey",
];

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
        Self::resolve_config_dir(std::env::var_os("XDG_CONFIG_HOME").as_deref())
    }

    /// Resolve the config directory from a supplied `XDG_CONFIG_HOME` value.
    ///
    /// Honors `XDG_CONFIG_HOME` only when it names an *absolute* path. The XDG Base
    /// Directory spec requires these variables to be absolute and says an empty
    /// value must be treated as unset (falling back to the platform default).
    /// Without this guard an empty `XDG_CONFIG_HOME=""` makes
    /// `PathBuf::from("").join("jwt-hack")` resolve to a CWD-relative `jwt-hack`
    /// directory, so config/history would be read from and written to whatever
    /// directory the tool happens to be launched in — and `Config::load` could
    /// silently pick up an attacker-planted `./jwt-hack/config.toml`.
    ///
    /// Split out from the env lookup so it is unit-testable without mutating the
    /// process-global environment (which would data-race parallel tests).
    fn resolve_config_dir(xdg_config_home: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
        if let Some(xdg_config_home) = xdg_config_home {
            let path = PathBuf::from(xdg_config_home);
            if path.is_absolute() {
                return Some(path.join("jwt-hack"));
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
                fs::create_dir_all(&config_dir).with_context(|| {
                    format!(
                        "Failed to create config directory: {}",
                        config_dir.display()
                    )
                })?;
            }
            Ok(Some(config_dir))
        } else {
            Ok(None)
        }
    }

    /// Save configuration to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize config to TOML")?;

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
    use std::ffi::OsStr;
    use tempfile::TempDir;

    #[test]
    fn test_xdg_config_home_absolute_is_honored() {
        let abs = if cfg!(windows) {
            "C:\\custom\\xdg"
        } else {
            "/custom/xdg"
        };
        let dir =
            Config::resolve_config_dir(Some(OsStr::new(abs))).expect("absolute XDG yields a dir");
        assert_eq!(dir, PathBuf::from(abs).join("jwt-hack"));
    }

    #[test]
    fn test_empty_xdg_config_home_falls_back_to_absolute_default() {
        // An empty XDG_CONFIG_HOME must NOT resolve to a CWD-relative `jwt-hack`
        // directory; it should be treated as unset and fall back to the platform
        // default (which is absolute).
        if let Some(dir) = Config::resolve_config_dir(Some(OsStr::new(""))) {
            assert!(
                dir.is_absolute(),
                "empty XDG_CONFIG_HOME must not produce a relative config dir, got {dir:?}"
            );
            assert_ne!(dir, PathBuf::from("jwt-hack"));
        }
    }

    #[test]
    fn test_relative_xdg_config_home_is_ignored() {
        // A relative XDG_CONFIG_HOME is invalid per the XDG spec and must be ignored
        // rather than producing a config dir relative to the current directory.
        if let Some(dir) = Config::resolve_config_dir(Some(OsStr::new("relative/path"))) {
            assert!(
                dir.is_absolute(),
                "relative XDG_CONFIG_HOME must be ignored, got {dir:?}"
            );
            assert!(!dir.starts_with("relative"));
        }
    }

    #[test]
    fn test_unset_xdg_config_home_uses_platform_default() {
        // With no XDG override, the resolver must produce an absolute platform
        // default (or None on an unusual host), never a relative path.
        if let Some(dir) = Config::resolve_config_dir(None) {
            assert!(
                dir.is_absolute(),
                "platform default must be absolute, got {dir:?}"
            );
            assert!(dir.ends_with("jwt-hack"));
        }
    }

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
        assert_eq!(
            config.default_wordlist,
            Some(PathBuf::from("/path/to/wordlist.txt"))
        );
        assert_eq!(
            config.default_private_key,
            Some(PathBuf::from("/path/to/private.pem"))
        );
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
