+++
toc = true
title = "Scripting & Automation"
weight = 2
+++

JWT-HACK is designed to work well in scripts and automated workflows. Use the
global `--json` flag to get machine-readable output for any command.

## Exit Codes and Result Detection

> **Important:** JWT-HACK does **not** signal outcomes like "signature invalid" or
> "secret not found" through exit codes. Commands such as `decode`, `verify`, and
> `crack` still exit `0` in those cases — the result is reported in the output, not
> the status code. Do **not** branch on `jwt-hack verify ...` succeeding/failing.

Observed exit codes:

- **0** - The command ran (this includes "token invalid" and "secret not found")
- **1** - A hard error while producing `--json` output, or a config/runtime failure
- **2** - Invalid command-line arguments (from argument parsing)

To detect results reliably, use `--json` and inspect the response fields:

```bash
# verify → parse the "valid" boolean
jwt-hack --json verify "$TOKEN" --secret="$SECRET" | jq -e '.valid == true'

# crack → "found" is true and "value" holds the secret
jwt-hack --json crack -w wordlist.txt "$TOKEN" | jq -e '.found == true'
```

## Bash Scripting

### Basic Token Validation

```bash
#!/bin/bash

validate_token() {
    local token="$1"
    local secret="$2"

    # verify exits 0 even for an invalid signature, so check the JSON "valid" field.
    if [ "$(jwt-hack --json verify "$token" --secret="$secret" | jq -r '.valid')" = "true" ]; then
        echo "Token is valid"
        return 0
    else
        echo "Token is invalid"
        return 1
    fi
}

# Usage
if validate_token "$JWT_TOKEN" "$SECRET"; then
    echo "Proceeding with authenticated request"
else
    echo "Authentication failed"
    exit 1
fi
```

### Batch Token Processing

```bash
#!/bin/bash

# Process multiple tokens from file
while IFS= read -r token; do
    echo "Processing token: ${token:0:20}..."

    if jwt-hack decode "$token" > /dev/null 2>&1; then
        echo "✓ Valid format"
        jwt-hack decode "$token" | grep -E "(exp|iat)"
    else
        echo "✗ Invalid format"
    fi
    echo "---"
done < tokens.txt
```

### Automated Cracking

```bash
#!/bin/bash

crack_token() {
    local token="$1"
    local wordlist="$2"

    echo "Attempting to crack token..."

    # crack exits 0 whether or not a secret is found, so check the JSON output.
    local json secret
    json=$(jwt-hack --json crack -w "$wordlist" "$token")
    if [ "$(echo "$json" | jq -r '.found')" = "true" ]; then
        secret=$(echo "$json" | jq -r '.value')
        echo "SUCCESS: Secret found: $secret"
        return 0
    else
        echo "FAILED: Could not crack token"
        return 1
    fi
}

# Try multiple wordlists
wordlists=("/usr/share/wordlists/rockyou.txt" "custom.txt" "common.txt")

for wordlist in "${wordlists[@]}"; do
    if [[ -f "$wordlist" ]]; then
        echo "Trying wordlist: $wordlist"
        if crack_token "$JWT_TOKEN" "$wordlist"; then
            break
        fi
    fi
done
```

## Python Integration

### Using subprocess

```python
import subprocess
import json
import sys

def decode_jwt(token):
    """Decode a JWT and return the parsed JSON result, or None on error."""
    result = subprocess.run(
        ['jwt-hack', '--json', 'decode', token],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout or '{}')
    return data if data.get('success') else None

def verify_jwt(token, secret):
    """Verify a JWT signature. Returns True only if the JSON `valid` field is true."""
    result = subprocess.run(
        ['jwt-hack', '--json', 'verify', token, '--secret', secret],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout or '{}')
    return bool(data.get('valid'))

# Usage
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
if decode_result := decode_jwt(token):
    print("Token decoded successfully")
    print(decode_result)
else:
    print("Failed to decode token")
    sys.exit(1)
```

> Note: jwt-hack does not use exit codes to report an invalid signature or a
> failed crack — always pass `--json` and inspect the response fields
> (`valid`, `found`, `value`, …) rather than relying on `check=True`.

### Token Analysis Pipeline

```python
#!/usr/bin/env python3

import subprocess
import json
import re
from pathlib import Path

class JWTAnalyzer:
    def __init__(self):
        self.jwt_hack = "jwt-hack"

    def _run_json(self, *args):
        """Run a jwt-hack subcommand with --json and return the parsed result."""
        result = subprocess.run(
            [self.jwt_hack, '--json', *args],
            capture_output=True, text=True
        )
        return json.loads(result.stdout or '{}')

    def decode(self, token):
        """Decode JWT and return the structured JSON result."""
        data = self._run_json('decode', token)
        return data if data.get('success') else None

    def verify(self, token, secret):
        """Verify JWT signature via the JSON `valid` field."""
        data = self._run_json('verify', token, '--secret', secret)
        return bool(data.get('valid'))

    def crack(self, token, wordlist):
        """Attempt to crack the JWT secret; returns the secret or None."""
        data = self._run_json('crack', '-w', wordlist, token)
        return data.get('value') if data.get('found') else None

    def generate_payloads(self, token, target='all'):
        """Generate attack payloads (returns the JSON payload list)."""
        return self._run_json('payload', token, '--target', target)

# Usage example
analyzer = JWTAnalyzer()
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Analyze token
info = analyzer.decode(token)
if info:
    print("Token analysis:", info)

    # Try to crack it
    secret = analyzer.crack(token, "wordlist.txt")
    if secret:
        print(f"Secret found: {secret}")

        # Verify with found secret
        if analyzer.verify(token, secret):
            print("Secret verified!")
```

## CI/CD Integration

### GitHub Actions

```yaml
name: JWT Security Check

on: [push, pull_request]

jobs:
  jwt-security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2

    - name: Install JWT-HACK
      run: |
        cargo install jwt-hack

    - name: Analyze JWT tokens in code
      run: |
        # Find JWT tokens in code (simple regex)
        grep -r "eyJ[A-Za-z0-9_-]*\." . || true

    - name: Test JWT security
      run: |
        # Test any hardcoded tokens
        if [ -f "test-tokens.txt" ]; then
          while read token; do
            echo "Testing token: $token"
            jwt-hack decode "$token"
            jwt-hack crack -w common-passwords.txt "$token" || true
          done < test-tokens.txt
        fi
```

### Docker Integration

```dockerfile
FROM rust:1.75 as builder
RUN cargo install jwt-hack

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/jwt-hack /usr/local/bin/
COPY scripts/ /scripts/
ENTRYPOINT ["/scripts/analyze.sh"]
```

## Configuration Management

### Environment-Based Configuration

jwt-hack itself does not read these values from the environment, so read them into
shell variables and pass them explicitly as flags:

```bash
#!/bin/bash

# Set defaults from environment (your own variables, not read by jwt-hack)
SECRET="${SECRET:-default-secret}"
WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
CONCURRENCY="${CONCURRENCY:-$(nproc)}"

# Pass them explicitly on the command line
jwt-hack verify "$token" --secret="$SECRET"
jwt-hack crack -w "$WORDLIST" -c "$CONCURRENCY" "$token"
```

### Config File Generation

```bash
#!/bin/bash

# Generate jwt-hack config
mkdir -p ~/.config/jwt-hack

cat > ~/.config/jwt-hack/config.toml << EOF
default_secret = "${DEFAULT_SECRET}"
default_algorithm = "${DEFAULT_ALGORITHM:-HS256}"
default_wordlist = "${DEFAULT_WORDLIST}"
default_private_key = "${DEFAULT_PRIVATE_KEY}"
EOF

echo "Configuration generated at ~/.config/jwt-hack/config.toml"
```
