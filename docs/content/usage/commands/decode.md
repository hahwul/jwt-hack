+++
toc = true
title = "decode"
weight = 1
+++

Decode a JWT or JWE and print its header, payload, and any recognizable timestamp claims. No secret or key needed: decode never verifies the signature, it just reads the token.

## Usage

```bash
jwt-hack decode <TOKEN>
```

```text
▎ DECODE ─────────────────────────────────────

  Algorithm     HS256
  Type          JWT

▎ Header
  {
    "alg": "HS256",
    "typ": "JWT"
  }

▎ Payload
  {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022,
    "iat_time": "2018-01-18 01:30:22 UTC"
  }
```

Any of `iat`, `exp`, and `nbf` present in the payload get a human-readable `*_time` sibling (UTC) alongside the raw Unix value.

## Options

Only the global flags apply. `--json` prints the decode as an object with `token_type`, `algorithm`, `typ`, `header`, and `payload`, which is what you want when feeding another tool.

```bash
jwt-hack --json decode "$TOKEN" | jq .payload
```

## JWE tokens

A 5-part token is detected as JWE automatically. You get the key-management `alg`, content `enc`, the component sizes (encrypted key, IV, ciphertext, auth tag), and a short list of encryption-layer concerns. The payload stays encrypted, decode will not pretend otherwise.

```bash
jwt-hack decode eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZHVtbXlfaXZfMTIzNDU2.eyJ0ZXN0IjoiandlIn0.ZHVtbXlfdGFn
```

```text
▎ DECODE · JWE ───────────────────────────────

  Key Mgmt      dir
  Encryption    A256GCM
  ...
▎ Security Issues
  ℹ️  Direct encryption mode - vulnerable to key brute force
  ⚠️  Authentication tag too short
```

## DEFLATE compression

Tokens with `"zip":"DEF"` in the header are decompressed transparently, so you see the original payload without extra flags. This pairs with [`encode --compress`](/usage/commands/encode/).

## Notes

- Decode is read-only. To check whether a signature is valid, use [verify](/usage/commands/verify/).
- Malformed Base64, broken JSON, or the wrong number of segments are reported with context instead of a silent failure.
