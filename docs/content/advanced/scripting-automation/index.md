---
title: "Scripting & Automation"
weight: 2
---

JWT-HACK is designed to work well in scripts and automated workflows.

## Exit Codes

JWT-HACK uses standard exit codes for automation:

- **0** - Success
- **1** - General error
- **2** - Invalid input/arguments
- **3** - Authentication/verification failure

## Bash Scripting

### Basic Token Validation

```bash
#!/bin/bash

validate_token() {
    local token="$1"
    local secret="$2"
    
    if jwt-hack verify "$token" --secret="$secret" > /dev/null 2>&1; then
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
    
    if result=$(jwt-hack crack -w "$wordlist" "$token" 2>&1); then
        echo "SUCCESS: Secret found!"
        echo "$result" | grep "Secret:"
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
    """Decode JWT token using jwt-hack"""
    try:
        result = subprocess.run(
            ['jwt-hack', 'decode', token],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None

def verify_jwt(token, secret):
    """Verify JWT token"""
    try:
        subprocess.run(
            ['jwt-hack', 'verify', token, '--secret', secret],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False

# Usage
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
if decode_result := decode_jwt(token):
    print("Token decoded successfully")
    print(decode_result)
else:
    print("Failed to decode token")
    sys.exit(1)
```

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
    
    def decode(self, token):
        """Decode JWT and extract information"""
        try:
            result = subprocess.run(
                [self.jwt_hack, 'decode', token],
                capture_output=True,
                text=True,
                check=True
            )
            return self._parse_decode_output(result.stdout)
        except subprocess.CalledProcessError:
            return None
    
    def verify(self, token, secret):
        """Verify JWT signature"""
        try:
            subprocess.run(
                [self.jwt_hack, 'verify', token, '--secret', secret],
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def crack(self, token, wordlist):
        """Attempt to crack JWT secret"""
        try:
            result = subprocess.run(
                [self.jwt_hack, 'crack', '-w', wordlist, token],
                capture_output=True,
                text=True,
                check=True
            )
            # Extract secret from output
            if match := re.search(r'Secret: (.+)', result.stdout):
                return match.group(1)
        except subprocess.CalledProcessError:
            pass
        return None
    
    def generate_payloads(self, token, target='all'):
        """Generate attack payloads"""
        try:
            result = subprocess.run(
                [self.jwt_hack, 'payload', token, '--target', target],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError:
            return None
    
    def _parse_decode_output(self, output):
        """Parse decode output to extract structured data"""
        # This would parse the actual output format
        # Implementation depends on jwt-hack output format
        return {"raw_output": output}

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

```bash
#!/bin/bash

# Set defaults from environment
JWT_HACK_SECRET="${JWT_HACK_SECRET:-default-secret}"
JWT_HACK_WORDLIST="${JWT_HACK_WORDLIST:-/usr/share/wordlists/rockyou.txt}"
JWT_HACK_CONCURRENCY="${JWT_HACK_CONCURRENCY:-$(nproc)}"

# Use in scripts
jwt-hack verify "$token" --secret="$JWT_HACK_SECRET"
jwt-hack crack -w "$JWT_HACK_WORDLIST" -c "$JWT_HACK_CONCURRENCY" "$token"
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