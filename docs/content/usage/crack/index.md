---
title: "Crack Command"
weight: 4
---

The `crack` command attempts to discover JWT secrets using dictionary attacks, brute force methods, or field-specific cracking.

## Basic Usage

```bash
jwt-hack crack [OPTIONS] <TOKEN>
```

## Dictionary Attack

Use a wordlist to crack JWT secrets:

```bash
# Basic dictionary attack
jwt-hack crack -w wordlist.txt <TOKEN>

# Use custom wordlist
jwt-hack crack --wordlist=/path/to/custom/wordlist.txt <TOKEN>
```

## Brute Force Attack

Generate and test password combinations:

```bash
# Brute force up to 4 characters
jwt-hack crack -m brute <TOKEN> --max=4

# Brute force up to 6 characters (longer runtime)
jwt-hack crack --mode=brute <TOKEN> --max=6

# Use all CPU cores for faster cracking
jwt-hack crack -m brute <TOKEN> --max=4 --power
```

## Field-Specific Cracking ⚡ NEW

Target specific JWT header or payload fields instead of the signature secret:

```bash
# Crack 'kid' header field
jwt-hack crack <TOKEN> --mode field --field kid

# Crack 'jti' payload field
jwt-hack crack <TOKEN> --mode field --field jti --field-location payload

# Use pattern hint for smarter attacks
jwt-hack crack <TOKEN> --mode field --field kid --pattern "user" --max 6

# Use character presets
jwt-hack crack <TOKEN> --mode field --field sub --preset aZ19 --max 8
```

**Supported Field Locations:**
- `header` (default) - JWT header fields like `kid`, `jku`, `x5u`
- `payload` - JWT claims/payload fields like `jti`, `sub`, `user_id`

**Pattern-Based Candidates:**
When you provide a `--pattern`, JWT-HACK generates smart candidates:
- Original pattern
- Uppercase/lowercase variations
- Numbered variations (pattern0-pattern99)
- Plus full brute force combinations

## Attack Modes

### Dictionary Mode (Default)
Uses a wordlist file to test potential secrets:

```bash
jwt-hack crack -w passwords.txt <TOKEN>
```

**Wordlist Requirements:**
- Plain text file
- One password per line
- No size limit (handles large files efficiently)
- Automatic deduplication

### Brute Force Mode
Generates combinations of characters:

```bash
jwt-hack crack -m brute <TOKEN> --max=5
```

**Character Sets & Presets:**

Use `--preset` for common character sets:
- `az` - Lowercase letters (a-z)
- `AZ` - Uppercase letters (A-Z)
- `aZ` - All letters (a-zA-Z)
- `19` - Digits (0-9)
- `aZ19` - Alphanumeric (a-zA-Z0-9) - most common
- `ascii` - Full printable ASCII

Or use custom `--chars`:
```bash
jwt-hack crack -m brute <TOKEN> --chars "abc123!@#" --max 4
```

### Field Mode ⚡ NEW
Crack specific JWT header or payload fields:

```bash
jwt-hack crack -m field <TOKEN> --field <FIELD_NAME> [OPTIONS]
```

**Common Header Fields to Target:**
- `kid` - Key ID (often contains predictable values)
- `jku` - JWK Set URL
- `x5u` - X.509 URL
- `x5t` - X.509 thumbprint
- Custom header fields

**Common Payload Fields to Target:**
- `jti` - JWT ID (often sequential or predictable)
- `sub` - Subject (user identifiers)
- `user_id`, `username`, `email` - Application-specific fields
- `role`, `permissions` - Authorization fields

## Performance Options

### Concurrency Control
```bash
# Set custom thread count
jwt-hack crack -w wordlist.txt <TOKEN> -c 10

# Use maximum CPU cores (recommended)
jwt-hack crack -w wordlist.txt <TOKEN> --power
```

**Adaptive Performance:**
- JWT-HACK automatically calculates optimal chunk sizes
- Reduces lock contention by 40-60%
- Scales efficiently from 2 to 64+ cores
- Dynamic workload distribution

### Progress Monitoring
```bash
# Enable verbose output
jwt-hack crack -w wordlist.txt <TOKEN> --verbose

# Shows:
# - Current password being tested
# - Progress percentage  
# - Keys/second throughput
# - Real-time performance metrics
```

## Command Options

### Required
- `<TOKEN>` - The JWT token to crack

### Attack Mode Options
- `-m, --mode <MODE>` - Attack mode: `dict` (default), `brute`, or `field`
- `-w, --wordlist <FILE>` - Path to wordlist file (for dict mode)

### Character Set Options
- `--chars <CHARSET>` - Custom character set for brute force
- `--preset <PRESET>` - Preset character set: az, AZ, aZ, 19, aZ19, ascii
- `--max <LENGTH>` - Maximum length for brute force (default: 4)

### Field Mode Options ⚡ NEW
- `--field <NAME>` - Target field name (e.g., kid, jti, sub)
- `--field-location <LOCATION>` - Field location: `header` or `payload` (default: header)
- `--pattern <PATTERN>` - Expected pattern hint for smarter attacks

### Performance Options
- `-c, --concurrency <NUM>` - Number of threads (default: 20)
- `--power` - Use all available CPU cores
- `--verbose` - Show detailed progress information

## Compressed Token Support

JWT-HACK automatically handles DEFLATE-compressed tokens:

```bash
# Crack compressed JWT (detected automatically)
jwt-hack crack -w wordlist.txt <COMPRESSED_TOKEN>
```

The tool will:
- Detect compression automatically
- Decompress during verification
- Crack the original uncompressed secret

## Examples

### Dictionary Attack Examples
```bash
# Common passwords wordlist
jwt-hack crack -w /usr/share/wordlists/rockyou.txt <TOKEN>

# Custom application-specific wordlist
jwt-hack crack -w app-secrets.txt <TOKEN>

# SecLists common passwords
jwt-hack crack -w /opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt <TOKEN>
```

### Brute Force Examples
```bash
# Quick 3-character brute force with preset
jwt-hack crack -m brute <TOKEN> --preset aZ19 --max=3

# Intensive 5-character with all cores
jwt-hack crack -m brute <TOKEN> --preset aZ19 --max=5 --power --verbose

# Custom character set
jwt-hack crack -m brute <TOKEN> --chars "abc123!@#" --max=4 -c 8
```

### Field-Specific Cracking Examples ⚡ NEW
```bash
# Crack 'kid' header field (common target)
jwt-hack crack -m field <TOKEN> --field kid --preset aZ19 --max 5

# Crack 'jti' payload with pattern hint
jwt-hack crack -m field <TOKEN> --field jti --field-location payload \
  --pattern "txn" --max 6

# Crack user ID with numeric-only pattern
jwt-hack crack -m field <TOKEN> --field user_id --field-location payload \
  --preset 19 --max 8

# Crack 'sub' field with all CPU cores
jwt-hack crack -m field <TOKEN> --field sub --field-location payload \
  --preset aZ --max 4 --power
```

### Targeted Attacks
```bash
# Test common weak secrets first
echo -e "secret\npassword\ntest\n123456\nkey" | jwt-hack crack -w /dev/stdin <TOKEN>

# Application-specific patterns
jwt-hack crack -w company-keywords.txt <TOKEN>

# Field-specific with known pattern
jwt-hack crack -m field <TOKEN> --field kid --pattern "key" --max 4
```

## Wordlist Creation

### Generate Custom Wordlists
```bash
# Company/application-specific terms
echo -e "company\nappname\napi\ndev\ntest\nprod" > custom.txt

# Common patterns with variations
echo -e "secret123\npassword1\nkey2023\napi_key" > patterns.txt

# Combine multiple wordlists
cat wordlist1.txt wordlist2.txt > combined.txt
```

### Recommended Wordlists
- **RockYou** - Most common passwords from breaches
- **SecLists** - Comprehensive security testing wordlists
- **Custom Lists** - Application-specific terms and patterns

## Success Output

When a secret is found:

```
🎉 SECRET FOUND! 
Secret: mysecret123
Time taken: 2.5 seconds
Passwords tested: 1,247
```

## Performance Tips

### Dictionary Attacks
- Use targeted wordlists for faster results
- Start with common passwords
- Sort wordlists by frequency/likelihood

### Brute Force Attacks
- Start with shorter lengths (3-4 chars)
- Use `--power` flag for maximum performance
- Consider time vs. likelihood trade-offs

### General Optimization
- Use SSD storage for large wordlists
- Ensure adequate RAM for concurrent operations
- Monitor CPU usage with `--verbose`

## Security Considerations

### Responsible Disclosure
- Only crack tokens you own or have permission to test
- Follow responsible disclosure for vulnerabilities
- Document findings appropriately

### Rate Limiting
Be aware of potential rate limiting when testing live applications:
- Some applications may detect brute force attempts
- Use appropriate delays if testing against live systems
- Consider offline token analysis first