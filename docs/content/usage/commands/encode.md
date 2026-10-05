+++
toc = true
title = "encode"
weight = 2
+++

Turn a JSON payload into a signed JWT. Pick the algorithm, supply a secret or private key, and optionally compress the body or wrap it as a JWE.

## Usage

```bash
jwt-hack encode <JSON> [OPTIONS]
```

```bash
jwt-hack encode '{"sub":"1234","name":"test"}' --secret=mysecret
```

```text
▎ ENCODE ─────────────────────────────────────

  Algorithm     HS256
  Key           ****

▎ Token
  eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6InRlc3QifQ.U_Tt6tzc3i7_U4vt7lI_xMy_WbW3gLP5zbLU8aD1aT8
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--secret <SECRET>` | from config | HMAC key for HS256/HS384/HS512. |
| `--private-key <PRIVATE_KEY>` | from config | RSA, ECDSA, or EdDSA private key in PEM, for the asymmetric algorithms. |
| `--algorithm <ALGORITHM>` | config `default_algorithm`, then HS256 | HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, or EdDSA. |
| `--no-signature` | off | Emit an `alg: none` token with an empty signature. |
| `--header <KEY=VALUE>` | none | Add a custom header parameter. Repeat the flag for more than one. |
| `--compress` | off | DEFLATE the payload and add `"zip":"DEF"` to the header. |
| `--jwe` | off | Produce a JWE (encrypted) token instead of a JWS. |

The key field in the output is masked. With `--json` you get `token`, `algorithm`, `headers`, `compress`, and the token itself.

## Examples

HS384 instead of the default HS256:

```bash
jwt-hack encode '{"sub":"1234"}' --secret=mysecret --algorithm=HS384
```

RSA signing reads the private key from a PEM file (PKCS#1 `BEGIN RSA PRIVATE KEY` or PKCS#8 `BEGIN PRIVATE KEY`):

```bash
jwt-hack encode '{"iss":"myapp"}' --private-key=rsa-key.pem --algorithm=RS256
```

Custom headers go in as separate `key=value` flags, not a JSON object. This is how you set a `kid` for a crafted token:

```bash
jwt-hack encode '{"sub":"1234"}' --secret=test --header kid=key1 --header typ=JWT
```

An unsigned token, handy for quickly checking whether a server accepts `alg: none`:

```bash
jwt-hack encode '{"sub":"1234","admin":true}' --no-signature
```

Compress a large payload. [decode](/usage/commands/decode/) reads it back automatically:

```bash
jwt-hack encode '{"data":"...long payload..."}' --secret=test --compress
```

## Notes

- For generating ready-to-fire attack tokens (none variants, alg confusion, kid injection, tampered claims), reach for [payload](/usage/commands/payload/) rather than hand-rolling headers here.
- ECDSA private keys are accepted as SEC1 (`BEGIN EC PRIVATE KEY`) or PKCS#8.
