+++
toc = true
title = "Configuration"
weight = 3
+++

JWT-HACK supports configuration through a configuration file and command-line options. Command-line flags always take precedence over values from the config file.

## Configuration File

JWT-HACK uses TOML format for configuration files. The default configuration file location is the platform config directory:

- **Linux**: `~/.config/jwt-hack/config.toml` (or `$XDG_CONFIG_HOME/jwt-hack/config.toml`)
- **macOS**: `~/Library/Application Support/jwt-hack/config.toml`
- **Windows**: `%APPDATA%\jwt-hack\config.toml`

Setting `XDG_CONFIG_HOME` overrides the base directory on any platform.

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
- `RS256`, `RS384`, `RS512` (RSA PKCS#1 v1.5)
- `PS256`, `PS384`, `PS512` (RSA-PSS)
- `ES256`, `ES384`, `ES512` (ECDSA)
- `EdDSA` (Ed25519)

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

JWT-HACK does not read the default secret, algorithm, wordlist, or private key
from environment variables. Those values come only from the configuration file
(or the corresponding command-line flag).

A small number of environment variables affect other behavior — `XDG_CONFIG_HOME`
(config file location) and `JWT_HACK_WORDLIST_DIR` (server-mode wordlist paths).
See [Environment Variables](/reference/environment-variables) for details.

## Setting Priority

Configuration values follow this priority order (highest to lowest):

1. **Command line arguments** (highest priority)
2. **Configuration file** (`default_*` keys)
3. **Built-in defaults** (lowest priority)

Example:
```bash
# Config file has: default_secret = "config-secret"
# Command line: --secret=cli-secret

jwt-hack encode '{"sub":"1234"}' --secret=cli-secret
# Uses: cli-secret (command line wins)

jwt-hack encode '{"sub":"1234"}'
# Uses: config-secret (from the config file)
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
Test that a config file loads without a parse error by running any command with it:

```bash
# A TOML syntax error causes jwt-hack to exit with a "Failed to parse config file" error
jwt-hack --config ~/.config/jwt-hack/config.toml encode '{"test":"payload"}'
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

## Available Configuration Keys

The configuration file currently supports exactly these top-level keys, all optional:

| Key                   | Type   | Description                                        |
|-----------------------|--------|----------------------------------------------------|
| `default_secret`      | string | Default HMAC secret                                |
| `default_algorithm`   | string | Default algorithm for `encode`                     |
| `default_wordlist`    | string | Default wordlist path for `crack`/`scan`           |
| `default_private_key` | string | Default private key path for asymmetric algorithms |

Unknown keys are ignored, so there are no `[wordlists]`, `[keys]`, or
`[performance]` sections — only the flat keys above.

## Security Considerations

### Sensitive Data in Config
A secret placed in `default_secret` is stored in plain text in the config file.
If that is a concern, omit it from the file and pass `--secret` per command
instead. There is no `default_secret_file` key.

### File Permissions
Secure configuration files:

```bash
# Set restrictive permissions
chmod 600 ~/.config/jwt-hack/config.toml

# Verify permissions
ls -la ~/.config/jwt-hack/config.toml
# Should show: -rw------- (user read/write only)
```

### Configuration Loading
On startup, JWT-HACK parses the config file as TOML. Invalid TOML causes it to
exit with a "Failed to parse config file" error. Values such as algorithm names
and key/wordlist paths are not validated at load time — they are only used (and
may error) when the relevant command runs.

## Troubleshooting

### Configuration Not Loading
The default config file is only read if it exists at the platform config path. If
it is not being picked up:

```bash
# Confirm the file exists at the expected location (Linux example)
ls -la ~/.config/jwt-hack/config.toml

# Or point jwt-hack at the file explicitly
jwt-hack --config /path/to/config.toml encode '{"test":"1"}'
```

### Invalid Configuration
```bash
# A parse error names the file; check its TOML syntax
jwt-hack --config /path/to/config.toml encode '{"test":"1"}'
```

### Permission Issues
```bash
# Fix configuration directory permissions
chmod 755 ~/.config/jwt-hack

# Fix configuration file permissions
chmod 600 ~/.config/jwt-hack/config.toml
```
