---
title: "Examples"
weight: 4
---

Practical examples for common JWT-HACK use cases and workflows.

## Basic Operations

### Decode a JWT Token

```bash
# Decode and display token contents
jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA
```

### Create a New JWT

```bash
# Create with HMAC-SHA256
jwt-hack encode '{"sub":"1234", "name":"John Doe", "admin":true}' --secret=mysecret

# Create with RSA
jwt-hack encode '{"sub":"1234", "role":"admin"}' --private-key=private.pem --algorithm=RS256
```

### Verify JWT Signature

```bash
# Verify HMAC token
jwt-hack verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SIG --secret=mysecret

# Verify RSA token with expiration
jwt-hack verify <RSA_TOKEN> --private-key=public.pem --validate-exp
```

## Security Testing Workflows

### Full Token Analysis

```bash
# Step 1: Decode to understand structure
jwt-hack decode <TOKEN>

# Step 2: Try cracking the secret
jwt-hack crack -w wordlist.txt <TOKEN>

# Step 3: Generate attack payloads
jwt-hack payload <TOKEN> --target=all
```

### Password Cracking

```bash
# Quick dictionary attack with common passwords
jwt-hack crack -w /usr/share/wordlists/rockyou.txt <TOKEN>

# Brute force attack (short secrets)
jwt-hack crack -m brute <TOKEN> --max=4 --power

# Custom wordlist with verbose output
jwt-hack crack -w custom-secrets.txt <TOKEN> --verbose
```

### None Algorithm Bypass

```bash
# Generate none algorithm payloads
jwt-hack payload <TOKEN> --target=none

# Test each variant manually
```

## Advanced Use Cases

### Compressed Tokens

```bash
# Create compressed JWT
jwt-hack encode '{"data":"very long payload content..."}' --secret=test --compress

# Decode automatically handles decompression
jwt-hack decode <COMPRESSED_TOKEN>

# Crack compressed token
jwt-hack crack -w wordlist.txt <COMPRESSED_TOKEN>
```

### Custom Headers

```bash
# Add custom header fields
jwt-hack encode '{"sub":"1234"}' \
  --secret=test \
  --header='{"kid":"key-123","x5u":"https://example.com/certs"}'
```

### Multiple Algorithms

```bash
# HS256 (HMAC SHA-256)
jwt-hack encode '{"sub":"1234"}' --secret=secret --algorithm=HS256

# HS512 (HMAC SHA-512)
jwt-hack encode '{"sub":"1234"}' --secret=secret --algorithm=HS512

# RS256 (RSA SHA-256)
jwt-hack encode '{"sub":"1234"}' --private-key=rsa.pem --algorithm=RS256

# ES256 (ECDSA SHA-256)
jwt-hack encode '{"sub":"1234"}' --private-key=ec.pem --algorithm=ES256
```

## Integration with Other Tools

### With curl

```bash
# Create token and use in API request
TOKEN=$(jwt-hack encode '{"sub":"user123"}' --secret=mysecret)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/data
```

### With jq

```bash
# Extract specific claims from decoded token
jwt-hack decode <TOKEN> --json | jq '.payload.sub'
```

## Performance Optimization

### Parallel Cracking

```bash
# Use all CPU cores
jwt-hack crack -m brute <TOKEN> --max=5 --power

# Custom concurrency
jwt-hack crack -w huge-wordlist.txt <TOKEN> -c 16
```

## Best Practices

### Always Decode First

```bash
# Before any attack, understand the token
jwt-hack decode <TOKEN>
```

### Use Targeted Wordlists

```bash
# Start with small, targeted wordlists
jwt-hack crack -w top-100.txt <TOKEN>

# Then try larger sets if needed
jwt-hack crack -w rockyou.txt <TOKEN>
```

### Responsible Testing

- Only test systems you own or have permission to test
- Always get written authorization
- Follow responsible disclosure practices
- Document all testing activities
