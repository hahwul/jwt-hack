+++
toc = true
title = "Crack Command"
weight = 4
+++

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

### Preset Wordlists

Instead of managing wordlist files yourself, use a numbered preset. The wordlist
is downloaded once into the config directory (`<config>/jwt-hack/wordlists/`) and
reused on subsequent runs. A checksum sidecar is stored alongside each download,
so a cached copy with a matching hash is served straight from disk, and the
download is skipped.

```bash
# Download (first run) and use the raft-medium-words wordlist
jwt-hack crack -p 1 <TOKEN>

# Long form
jwt-hack crack --wordlist-preset 2 <TOKEN>
```

Available presets:

| Preset | Name              | Source                                   |
|--------|-------------------|------------------------------------------|
| `1`    | raft-medium-words | SecLists (medium web-content wordlist)   |
| `2`    | raft-large-words  | SecLists (large web-content wordlist)    |
| `3`    | jwt-secrets       | Wallarm jwt-secrets (common JWT secrets) |

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

By default, brute force uses lowercase letters and digits
(`abcdefghijklmnopqrstuvwxyz0123456789`). You can override the character set with
`--chars`, or pick a built-in `--preset`:

| Preset  | Characters                                    |
|---------|-----------------------------------------------|
| `az`    | Lowercase letters (a-z)                       |
| `AZ`    | Uppercase letters (A-Z)                       |
| `aZ`    | Mixed-case letters (a-z, A-Z)                 |
| `19`    | Digits (0-9)                                  |
| `aZ19`  | Letters and digits (a-z, A-Z, 0-9)            |
| `ascii` | All printable ASCII (letters, digits, symbols) |

```bash
# Custom character set
jwt-hack crack -m brute <TOKEN> --chars="abcdef0123456789"

# Character-set preset
jwt-hack crack -m brute <TOKEN> --preset=aZ19
```

## Performance Options

### Concurrency Control
```bash
# Set custom thread count
jwt-hack crack -w wordlist.txt <TOKEN> -c 10

# Use maximum CPU cores
jwt-hack crack -w wordlist.txt <TOKEN> --power
```

### Progress Monitoring
A live progress bar is shown during cracking by default. The `--verbose` flag
additionally logs each candidate as it is tested:

```bash
# Enable verbose testing log
jwt-hack crack -w wordlist.txt <TOKEN> --verbose

# Logs each tested candidate, plus a "Found!" line when the secret is discovered.
```

When the run finishes, jwt-hack prints the discovered secret (if any), the elapsed
time, and the throughput in keys/sec.

## Command Options

### Required
- `<TOKEN>` - The JWT token to crack

### Attack Mode Options
- `-w, --wordlist <FILE>` - Path to wordlist file (dictionary mode)
- `-p, --wordlist-preset <ID>` - Download & use a preset wordlist (1=raft-medium-words, 2=raft-large-words, 3=jwt-secrets)
- `-m, --mode <MODE>` - Attack mode: `dict` (default) or `brute`

### Brute Force Options
- `--chars <CHARS>` - Character set to use (default: `abcdefghijklmnopqrstuvwxyz0123456789`)
- `--preset <PRESET>` - Character-set preset: `az`, `AZ`, `aZ`, `19`, `aZ19`, `ascii`
- `--min <LENGTH>` - Minimum candidate length (default: 1)
- `--max <LENGTH>` - Maximum candidate length (default: 4)

### Targeted Field Options
- `--target-field <FIELD>` - Target a specific JWT field for brute force (e.g. `kid`, `jti`)
- `--pattern <TEMPLATE>` - Pattern template for targeted values, using `{}` as the placeholder (e.g. `"../../keys/{}"`)

### Performance Options
- `-c, --concurrency <NUM>` - Number of threads (default: 20)
- `--power` - Use all available CPU cores
- `--verbose` - Log each tested candidate

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

When a secret is found, jwt-hack prints the secret, the elapsed time and
throughput, and the token:

```
✔ Secret found

  Secret  mysecret123
  Time    2s (498.80 keys/sec)
  Token   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

If no secret is found, it reports the number of candidates tried, the elapsed
time, and the throughput.

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
