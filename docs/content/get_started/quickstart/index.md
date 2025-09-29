---
title: "Quick Start"
weight: 2
---

Get up and running with JWT-HACK in minutes with these basic examples.

## Basic Usage

### Decode a JWT Token

Decode a JWT to see its header and payload:

```bash
jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA
```

### Encode a JWT Token

Create a new JWT with a payload and secret:

```bash
jwt-hack encode '{"sub":"1234", "name":"test user"}' --secret=mysecret
```

### Verify a JWT Token

Verify a JWT's signature with a secret:

```bash
jwt-hack verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA --secret=test
```

### Crack a JWT Secret

Try to crack a JWT's secret using a wordlist:

```bash
jwt-hack crack -w wordlist.txt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.INVALID_SIGNATURE
```

### Generate Attack Payloads

Generate various attack payloads for security testing:

```bash
jwt-hack payload eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.INVALID_SIGNATURE --target=none
```

## Next Steps

- Explore the [Usage Guide](/usage/decode) for detailed command explanations
- Learn about [Advanced Features](/advanced/configuration) and configuration options
- Check out the [Contributing Guide](/contributing) if you want to help improve JWT-HACK