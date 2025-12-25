---
title: "Introduction"
weight: 1
---

JWT-HACK provides comprehensive JWT security testing capabilities with support for modern token formats and attack vectors.

## Core Features

| Mode    | Description                  | Support                                                      |
|---------|------------------------------|--------------------------------------------------------------|
| Encode  | JWT/JWE Encoder              | Secret based / Key based / Algorithm / Custom Header / DEFLATE Compression / JWE |
| Decode  | JWT/JWE Decoder              | Algorithm, Issued At Check, DEFLATE Compression, JWE Structure |
| Verify  | JWT Verifier                 | Secret based / Key based (for asymmetric algorithms)         |
| Crack   | Secret Cracker               | Dictionary Attack / Brute Force / DEFLATE Compression        |
| Payload | JWT Attack Payload Generator | none / jku&x5u / alg_confusion / kid_sql / x5c / cty         |
| MCP     | Model Context Protocol Server | AI model integration via standardized protocol               |

## Supported Algorithms

### Symmetric Algorithms (HMAC)
- **HS256** - HMAC using SHA-256
- **HS384** - HMAC using SHA-384  
- **HS512** - HMAC using SHA-512

### Asymmetric Algorithms (RSA/ECDSA)
- **RS256** - RSASSA-PKCS1-v1_5 using SHA-256
- **RS384** - RSASSA-PKCS1-v1_5 using SHA-384
- **RS512** - RSASSA-PKCS1-v1_5 using SHA-512
- **ES256** - ECDSA using P-256 and SHA-256
- **ES384** - ECDSA using P-384 and SHA-384

### Special Cases
- **None** - Unsigned tokens for testing

## JWT Attack Vectors

### Algorithm Confusion Attacks
- **None Algorithm Bypass** - Strip signature verification
- **Algorithm Substitution** - Change from RSA to HMAC
- **Key Confusion** - Use public key as HMAC secret

### Header Manipulation
- **JKU/X5U URL Attacks** - Malicious key URLs
- **KID SQL Injection** - Database injection via key ID
- **X5C Certificate Injection** - Malicious certificate chains
- **CTY Content Type Attacks** - MIME type confusion

## Advanced Capabilities

### DEFLATE Compression Support
JWT-HACK automatically detects and handles DEFLATE-compressed JWTs:
- Decode compressed tokens transparently
- Generate compressed tokens with `--compress` flag
- Support for cracking compressed token secrets

### JWE (JSON Web Encryption) Support
- Decode JWE token structure (5-part format)
- Display encryption details and components
- Analyze JWE headers and algorithms

### High Performance
- **Parallel Processing** - Multi-threaded cracking operations
- **Efficient Memory Usage** - Optimized for large wordlists
- **Progress Indicators** - Real-time feedback on long operations

### Model Context Protocol (MCP)
- Run as MCP server for AI model integration
- Standardized protocol for JWT analysis
- Compatible with various AI frameworks