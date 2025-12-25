---
title: "Decode Command"
weight: 1
---

The `decode` command analyzes JWT and JWE tokens, displaying their structure, headers, payloads, and validation information.

## Basic Usage

```bash
jwt-hack decode <TOKEN>
```

## JWT Token Decoding

Decode a standard JWT token to see its header and payload:

```bash
jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA
```

**Output includes:**
- Token algorithm and type
- Decoded header (JSON format)
- Decoded payload (JSON format)  
- Timestamp information (iat, exp, nbf if present)
- Token structure validation

## JWE Token Decoding

JWT-HACK automatically detects and decodes JWE (JSON Web Encryption) tokens:

```bash
jwt-hack decode eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZHVtbXlfaXZfMTIzNDU2.eyJ0ZXN0IjoiandlIn0.ZHVtbXlfdGFn
```

**JWE Output includes:**
- JWE header with encryption algorithm
- Encrypted key component
- Initialization vector (IV)
- Ciphertext
- Authentication tag
- 5-part structure validation

## DEFLATE Compression Support

JWT-HACK automatically detects and decompresses DEFLATE-compressed JWTs:

```bash
jwt-hack decode <COMPRESSED_JWT_TOKEN>
```

The tool will:
- Detect compression automatically
- Decompress the payload
- Display the original uncompressed content
- Show compression details in the output

## Timestamp Analysis

When JWT contains timestamp fields, the decode command provides:

- **iat (Issued At)** - When the token was created
- **exp (Expires)** - When the token expires  
- **nbf (Not Before)** - When the token becomes valid

Timestamps are displayed in both Unix timestamp and human-readable formats.

## Error Handling

The decode command handles various token formats gracefully:

- **Invalid Base64** - Shows decoding errors with context
- **Malformed JSON** - Displays JSON parsing errors
- **Invalid Structure** - Identifies structural issues
- **Missing Components** - Reports incomplete tokens

## Examples

### Standard JWT
```bash
# Decode a basic HMAC-signed JWT
jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SIGNATURE
```

### RSA-signed JWT
```bash  
# Decode an RSA-signed JWT
jwt-hack decode eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJleGFtcGxlIn0.SIGNATURE
```

### JWT with Custom Headers
```bash
# Decode JWT with custom header fields
jwt-hack decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.PAYLOAD.SIGNATURE
```