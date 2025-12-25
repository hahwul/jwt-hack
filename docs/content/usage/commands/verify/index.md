---
title: "Verify Command"
weight: 3
---

The `verify` command validates JWT token signatures and optionally checks expiration claims.

## Basic Usage

```bash
jwt-hack verify <TOKEN> [OPTIONS]
```

## Secret-Based Verification (HMAC)

Verify HMAC-signed tokens with a shared secret:

```bash
# Verify HS256 token
jwt-hack verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA --secret=test

# Try different secrets
jwt-hack verify <TOKEN> --secret=secret123
jwt-hack verify <TOKEN> --secret=password
```

## Key-Based Verification (RSA/ECDSA)

Verify asymmetric tokens using public keys:

```bash
# Verify RSA-signed token
jwt-hack verify <RSA_TOKEN> --private-key=public.pem

# Verify ECDSA-signed token  
jwt-hack verify <ECDSA_TOKEN> --private-key=ec-public.pem
```

## Expiration Validation

Check if the token has expired:

```bash
# Enable expiration validation
jwt-hack verify <TOKEN> --secret=test --validate-exp
```

With `--validate-exp`, the command will:
- Check the `exp` (expiration) claim
- Validate against current timestamp
- Report if the token is expired
- Show time remaining or time since expiration

## Command Options

### Required
- `<TOKEN>` - The JWT token to verify

### Authentication Options
- `--secret <SECRET>` - Secret for HMAC token verification
- `--private-key <PATH>` - Path to public key file for RSA/ECDSA verification

### Validation Options
- `--validate-exp` - Enable expiration time validation

## Verification Results

The verify command provides detailed output:

### Successful Verification
```
✓ Signature Valid
✓ Token Structure Valid
✓ Algorithm: HS256
✓ Expiration: Valid (expires in 2 hours)
```

### Failed Verification
```
✗ Signature Invalid
✓ Token Structure Valid
- Algorithm: HS256
- Reason: Incorrect secret or signature tampering
```

### Expiration Issues
```
✓ Signature Valid
✓ Token Structure Valid
✗ Expiration: Token expired 30 minutes ago
```

## Examples

### Basic HMAC Verification
```bash
# Verify with correct secret
jwt-hack verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SIGNATURE --secret=correct-secret

# Try with wrong secret (will fail)
jwt-hack verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SIGNATURE --secret=wrong-secret
```

### RSA Token Verification
```bash
# Verify RSA256 token with public key
jwt-hack verify <RSA_TOKEN> --private-key=rsa-public.pem
```

### Complete Validation
```bash
# Verify signature and check expiration
jwt-hack verify <TOKEN> --secret=mysecret --validate-exp
```

## Key File Requirements

### For RSA/ECDSA Verification
You need the **public key** corresponding to the private key used for signing:

```bash
# Extract public key from private key
openssl rsa -in private.pem -pubout -out public.pem

# Use public key for verification
jwt-hack verify <TOKEN> --private-key=public.pem
```

### Supported Public Key Formats
- **X.509 SubjectPublicKeyInfo** - `-----BEGIN PUBLIC KEY-----`
- **PKCS#1 RSA Public Key** - `-----BEGIN RSA PUBLIC KEY-----`

## Security Testing

The verify command is useful for security testing:

### Test Different Secrets
```bash
# Test common weak secrets
jwt-hack verify <TOKEN> --secret=secret
jwt-hack verify <TOKEN> --secret=password
jwt-hack verify <TOKEN> --secret=123456
jwt-hack verify <TOKEN> --secret=test
```

### Algorithm Confusion Testing
```bash
# Test if RSA token accepts HMAC verification (algorithm confusion)
jwt-hack verify <RSA_TOKEN> --secret=<PUBLIC_KEY_CONTENT>
```

### None Algorithm Testing
```bash
# Test unsigned tokens (none algorithm)
jwt-hack verify <NONE_TOKEN>
```

## Return Codes

The verify command uses exit codes for scripting:

- **0** - Verification successful
- **1** - Verification failed
- **2** - Token format error
- **3** - Expiration validation failed

Example usage in scripts:
```bash
if jwt-hack verify "$TOKEN" --secret="$SECRET"; then
    echo "Token is valid"
else
    echo "Token verification failed"
fi
```