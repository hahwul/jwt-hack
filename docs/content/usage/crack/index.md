---
title: "Crack Command"
weight: 4
---

The `crack` command attempts to discover JWT secrets using dictionary attacks or brute force methods.

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

### Brute Force Mode
Generates combinations of characters:

```bash
jwt-hack crack -m brute <TOKEN> --max=5
```

**Character Sets:**
- Lowercase letters (a-z)
- Uppercase letters (A-Z)  
- Numbers (0-9)
- Special characters (!@#$%^&*)

## Performance Options

### Concurrency Control
```bash
# Set custom thread count
jwt-hack crack -w wordlist.txt <TOKEN> -c 10

# Use maximum CPU cores
jwt-hack crack -w wordlist.txt <TOKEN> --power
```

### Progress Monitoring
```bash
# Enable verbose output
jwt-hack crack -w wordlist.txt <TOKEN> --verbose

# Shows:
# - Current password being tested
# - Progress percentage
# - Estimated time remaining
# - Passwords tested per second
```

## Command Options

### Required
- `<TOKEN>` - The JWT token to crack

### Attack Mode Options
- `-w, --wordlist <FILE>` - Path to wordlist file
- `-m, --mode <MODE>` - Attack mode: dictionary (default) or brute

### Performance Options
- `-c, --concurrency <NUM>` - Number of threads (default: 20)
- `--max <LENGTH>` - Maximum length for brute force (default: 4)
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
# Quick 3-character brute force
jwt-hack crack -m brute <TOKEN> --max=3

# Intensive 5-character with all cores
jwt-hack crack -m brute <TOKEN> --max=5 --power --verbose

# Custom thread count
jwt-hack crack -m brute <TOKEN> --max=4 -c 8
```

### Targeted Attacks
```bash
# Test common weak secrets first
echo -e "secret\npassword\ntest\n123456\nkey" | jwt-hack crack -w /dev/stdin <TOKEN>

# Application-specific patterns
jwt-hack crack -w company-keywords.txt <TOKEN>
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