---
title: "Configuration"
weight: 1
---

JWT-HACK supports configuration through configuration files, environment variables, and command-line options.

## Configuration File

JWT-HACK uses TOML format for configuration files. The default configuration file location follows XDG Base Directory specification:

- **Linux/macOS**: `~/.config/jwt-hack/config.toml`
- **Windows**: `%APPDATA%\jwt-hack\config.toml`

### Configuration File Format

```toml
# Default secret key for HMAC algorithms
default_secret = "my-default-secret"

# Default algorithm to use when encoding
default_algorithm = "HS256"

# Default wordlist path for cracking
default_wordlist = "/usr/share/wordlists/rockyou.txt"

# Default private key path
default_private_key = "~/.ssh/jwt-private.pem"
```

### Custom Configuration File

Specify a custom configuration file path:

```bash
jwt-hack --config /path/to/custom/config.toml decode <TOKEN>
```

## Configuration Options

### Default Secret
Set a default secret for HMAC operations:

```toml  
default_secret = "your-default-secret-here"
```

Usage:
```bash
# Uses default secret from config
jwt-hack encode '{"sub":"1234"}'

# Override with command line
jwt-hack encode '{"sub":"1234"}' --secret=different-secret
```

### Default Algorithm
Configure the default signing algorithm:

```toml
default_algorithm = "HS512"
```

Supported algorithms:
- `HS256`, `HS384`, `HS512` (HMAC)
- `RS256`, `RS384`, `RS512` (RSA)
- `ES256`, `ES384` (ECDSA)

### Default Wordlist
Set default wordlist for cracking operations:

```toml
default_wordlist = "/opt/wordlists/jwt-secrets.txt"
```

Usage:
```bash
# Uses default wordlist
jwt-hack crack <TOKEN>

# Override with specific wordlist
jwt-hack crack -w /path/to/other/wordlist.txt <TOKEN>
```

### Default Private Key
Configure default private key path:

```toml
default_private_key = "/path/to/default/key.pem"
```

## Environment Variables

Override configuration with environment variables:

```bash
# Default secret
export JWT_HACK_DEFAULT_SECRET="env-secret"

# Default algorithm  
export JWT_HACK_DEFAULT_ALGORITHM="RS256"

# Default wordlist
export JWT_HACK_DEFAULT_WORDLIST="/path/to/wordlist.txt"

# Default private key
export JWT_HACK_DEFAULT_PRIVATE_KEY="/path/to/key.pem"

# Configuration file path
export JWT_HACK_CONFIG="/path/to/config.toml"
```

## Command Line Priority

Configuration options follow this priority order (highest to lowest):

1. **Command line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Built-in defaults** (lowest priority)

Example:
```bash
# Config file has: default_secret = "config-secret"
# Environment has: JWT_HACK_DEFAULT_SECRET="env-secret"
# Command line: --secret=cli-secret

jwt-hack encode '{"sub":"1234"}' --secret=cli-secret
# Uses: cli-secret (command line wins)

jwt-hack encode '{"sub":"1234"}'
# Uses: env-secret (environment wins over config file)
```

## Configuration Management

### Generate Default Configuration
Create a default configuration file:

```bash
# Create config directory if it doesn't exist
mkdir -p ~/.config/jwt-hack

# Create basic configuration
cat > ~/.config/jwt-hack/config.toml << EOF
default_secret = "change-me-please"
default_algorithm = "HS256"
default_wordlist = "~/wordlists/common.txt"
EOF
```

### Validate Configuration
Test your configuration:

```bash
# Test with specific config file
jwt-hack --config ~/.config/jwt-hack/config.toml encode '{"test":"payload"}'

# Verify settings are loaded correctly
jwt-hack version  # Shows config file location if found
```

### Per-Project Configuration
Use project-specific configuration files:

```bash
# Project directory structure
project/
├── config.toml
├── wordlists/
└── keys/

# Use project config
cd project
jwt-hack --config ./config.toml crack <TOKEN>
```

## Advanced Configuration

### Wordlist Collections
Organize multiple wordlists:

```toml
[wordlists]
common = "/wordlists/common-passwords.txt"
large = "/wordlists/rockyou.txt"
custom = "/wordlists/app-specific.txt"
```

### Key Management
Configure multiple key files:

```toml
[keys]
rsa_private = "/keys/rsa-private.pem"
rsa_public = "/keys/rsa-public.pem"
ecdsa_private = "/keys/ecdsa-private.pem"
```

### Performance Tuning
Configure performance settings:

```toml
[performance]
default_concurrency = 8
max_memory_usage = "1GB"
timeout = 300
```

## Security Considerations

### Sensitive Data in Config
Avoid storing sensitive secrets in configuration files:

```toml
# BAD: Hardcoded secret in config
default_secret = "super-secret-key"

# BETTER: Reference to secure location
default_secret_file = "/secure/path/secret.txt"

# BEST: Use environment variables for secrets
# default_secret loaded from JWT_HACK_DEFAULT_SECRET
```

### File Permissions
Secure configuration files:

```bash
# Set restrictive permissions
chmod 600 ~/.config/jwt-hack/config.toml

# Verify permissions
ls -la ~/.config/jwt-hack/config.toml
# Should show: -rw------- (user read/write only)
```

### Configuration Validation
JWT-HACK validates configuration on startup:

- Checks file paths exist
- Validates algorithm names
- Warns about insecure settings
- Reports configuration errors clearly

## Troubleshooting

### Configuration Not Loading
```bash
# Check if config file exists
ls -la ~/.config/jwt-hack/config.toml

# Test with explicit config path
jwt-hack --config ~/.config/jwt-hack/config.toml version

# Enable debug output
JWT_HACK_DEBUG=true jwt-hack encode '{"test":"1"}'
```

### Invalid Configuration
```bash
# Check configuration syntax
toml-lint ~/.config/jwt-hack/config.toml

# Test configuration loading
jwt-hack --config ~/.config/jwt-hack/config.toml version
```

### Permission Issues
```bash
# Fix configuration directory permissions
chmod 755 ~/.config/jwt-hack

# Fix configuration file permissions
chmod 600 ~/.config/jwt-hack/config.toml
```