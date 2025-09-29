---
title: "Encode Command"
weight: 2
---

The `encode` command creates JWT tokens from JSON payloads with various signing options and algorithms.

## Basic Usage

```bash
jwt-hack encode <JSON_PAYLOAD> [OPTIONS]
```

## Secret-Based Signing (HMAC)

Create JWT tokens using HMAC algorithms with a shared secret:

```bash
# HS256 (default)
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --secret=mysecret

# HS384
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --secret=mysecret --algorithm=HS384

# HS512  
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --secret=mysecret --algorithm=HS512
```

## Key-Based Signing (RSA/ECDSA)

Create JWT tokens using asymmetric algorithms with private keys:

```bash
# RSA256
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --private-key=private.pem --algorithm=RS256

# RSA384
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --private-key=private.pem --algorithm=RS384

# RSA512
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --private-key=private.pem --algorithm=RS512

# ECDSA256
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --private-key=ec-private.pem --algorithm=ES256
```

## Unsigned Tokens

Create unsigned JWT tokens for testing:

```bash
jwt-hack encode '{"sub":"1234", "name":"John Doe"}' --no-signature
```

## Custom Headers

Add custom header fields to the JWT:

```bash
jwt-hack encode '{"sub":"1234"}' --secret=test --header='{"kid":"key1","typ":"JWT"}'
```

## DEFLATE Compression

Create compressed JWT tokens:

```bash
jwt-hack encode '{"sub":"1234", "data":"large payload"}' --secret=test --compress
```

The `--compress` flag:
- Compresses the payload using DEFLATE
- Reduces token size for large payloads
- Maintains compatibility with JWT standards
- Can be decoded automatically by the decode command

## JWE (JSON Web Encryption)

Create encrypted JWT tokens:

```bash
jwt-hack encode '{"sensitive":"data"}' --secret=test --jwe
```

JWE encoding:
- Encrypts the payload content
- Uses symmetric encryption with the provided secret
- Creates 5-part JWE structure
- Provides confidentiality in addition to integrity

## Command Options

### Required
- `<JSON_PAYLOAD>` - The JSON payload to encode

### Authentication Options
- `--secret <SECRET>` - Secret for HMAC algorithms
- `--private-key <PATH>` - Path to private key file for RSA/ECDSA

### Algorithm Options  
- `--algorithm <ALG>` - Algorithm to use (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384)
- `--no-signature` - Create unsigned token

### Additional Options
- `--header <JSON>` - Custom header fields as JSON
- `--compress` - Enable DEFLATE compression
- `--jwe` - Create JWE encrypted token

## Examples

### Standard JWT with HMAC
```bash
jwt-hack encode '{"sub":"user123","role":"admin","exp":1640995200}' --secret=my-secret-key
```

### JWT with RSA Signature
```bash
jwt-hack encode '{"iss":"myapp","aud":"users","exp":1640995200}' --private-key=rsa-key.pem --algorithm=RS256
```

### JWT with Custom Headers
```bash
jwt-hack encode '{"user":"john"}' --secret=test --header='{"kid":"key-1","alg":"HS256","typ":"JWT"}'
```

### Compressed JWT
```bash
jwt-hack encode '{"data":"very long payload content here..."}' --secret=test --compress
```

### Unsigned JWT for Testing
```bash
jwt-hack encode '{"test":"payload"}' --no-signature
```

## Key File Formats

JWT-HACK supports standard key file formats:

### RSA Private Keys
- **PKCS#1 format** - `-----BEGIN RSA PRIVATE KEY-----`
- **PKCS#8 format** - `-----BEGIN PRIVATE KEY-----`

### ECDSA Private Keys  
- **SEC1 format** - `-----BEGIN EC PRIVATE KEY-----`
- **PKCS#8 format** - `-----BEGIN PRIVATE KEY-----`

## Output

The encode command outputs:
- The complete JWT token
- Token structure breakdown
- Algorithm and signing information
- Any compression or encryption details