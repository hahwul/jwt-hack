---
title: "Options & Flags"
weight: 2
---

JWT-HACK provides a consistent set of options and flags across all commands for flexible JWT testing and analysis.

## Global Options

These options are available across all commands:

### Help and Version

```bash
jwt-hack --help        # Show general help
jwt-hack --version     # Show version information
jwt-hack <command> --help  # Show command-specific help
```

## Common Authentication Options

### Secret-Based (HMAC)

For HS256, HS384, HS512 algorithms:

```bash
--secret <SECRET>      # Shared secret for HMAC algorithms
```

Example:
```bash
jwt-hack encode '{"sub":"1234"}' --secret=mysecret
jwt-hack verify <TOKEN> --secret=mysecret
```

### Key-Based (RSA/ECDSA)

For RS256, RS384, RS512, ES256, ES384, EdDSA algorithms:

```bash
--private-key <PATH>   # Path to private key (PEM format)
```

Example:
```bash
jwt-hack encode '{"sub":"1234"}' --private-key=private.pem --algorithm=RS256
jwt-hack verify <TOKEN> --private-key=public.pem
```

## Algorithm Selection

```bash
--algorithm <ALG>      # Specify JWT algorithm
```

Supported algorithms:
- **HMAC**: HS256, HS384, HS512
- **RSA**: RS256, RS384, RS512
- **ECDSA**: ES256, ES384
- **EdDSA**: EdDSA
- **None**: none (unsigned tokens)

Example:
```bash
jwt-hack encode '{"sub":"1234"}' --secret=test --algorithm=HS384
```

## Token Manipulation Options

### Custom Headers

```bash
--header <JSON>        # Add custom header fields
```

Example:
```bash
jwt-hack encode '{"sub":"1234"}' --secret=test --header='{"kid":"key1","typ":"JWT"}'
```

### Compression

```bash
--compress             # Enable DEFLATE compression
```

Example:
```bash
jwt-hack encode '{"data":"large payload"}' --secret=test --compress
```

### Unsigned Tokens

```bash
--no-signature         # Create unsigned token (none algorithm)
```

Example:
```bash
jwt-hack encode '{"test":"payload"}' --no-signature
```

## Verification Options

### Expiration Validation

```bash
--validate-exp         # Check token expiration
```

Example:
```bash
jwt-hack verify <TOKEN> --secret=test --validate-exp
```

## Cracking Options

### Mode Selection

```bash
-m, --mode <MODE>      # Attack mode: dictionary or brute
```

### Wordlist

```bash
-w, --wordlist <FILE>  # Path to wordlist file
```

### Brute Force

```bash
--max <LENGTH>         # Maximum length for brute force (default: 4)
--preset <CHARSET>     # Character set preset for brute force
```

### Performance

```bash
-c, --concurrency <NUM>  # Number of concurrent threads (default: 20)
--power                  # Use all available CPU cores
--verbose                # Show detailed progress
```

Example:
```bash
jwt-hack crack -w wordlist.txt <TOKEN>
jwt-hack crack -m brute <TOKEN> --max=5 --power --verbose
```

## Payload Generation Options

### Target Selection

```bash
--target <TYPE>        # Payload type: all, none, jku, x5u, alg_confusion, kid_sql, x5c, cty
```

### JKU/X5U Attack Options

```bash
--jwk-trust <DOMAIN>   # Trusted domain for bypass
--jwk-attack <DOMAIN>  # Attacker-controlled domain
--jwk-protocol <PROTO> # Protocol: http or https (default: https)
```

Example:
```bash
jwt-hack payload <TOKEN> --target=none
jwt-hack payload <TOKEN> --target=jku --jwk-attack=evil.com
```

## Output Control

### Verbosity

```bash
-v, --verbose          # Increase output verbosity
-q, --quiet            # Suppress non-error output
```

### Format

```bash
--json                 # Output in JSON format
--no-color             # Disable colored output
```

## Configuration File

JWT-HACK supports configuration via files in standard locations:

- `~/.config/jwt-hack/config.toml`
- `~/.jwt-hack/config.toml`
- `./jwt-hack.toml`

Configuration file example:
```toml
[default]
algorithm = "HS256"
concurrency = 20

[crack]
max_length = 6
power = true
```

Load custom config:
```bash
jwt-hack --config=/path/to/config.toml <command>
```

## Tips

### Combining Options

Options can be combined for complex operations:

```bash
jwt-hack encode '{"admin":true}' \
  --secret=supersecret \
  --algorithm=HS512 \
  --header='{"kid":"admin-key"}' \
  --compress
```

### Using Config Files

For repetitive operations, use config files to avoid typing options:

```bash
# Create config file
echo 'algorithm = "HS256"' > jwt-hack.toml
echo 'secret = "mysecret"' >> jwt-hack.toml

# Use automatically
jwt-hack encode '{"sub":"1234"}'
```
