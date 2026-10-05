+++
toc = true
title = "server"
weight = 9
+++

`jwt-hack server` exposes decode, encode, verify, crack, payload and scan over a local JSON REST API, so you can drive jwt-hack from scripts, a CI step or a web frontend instead of the CLI.

```bash
# Default bind is 127.0.0.1:3000
jwt-hack server

# Listen on all interfaces
jwt-hack server --host 0.0.0.0 --port 8080

# Require an API key on every request
jwt-hack server --api-key "$KEY"
```

| Flag | Default | Description |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind address. Use `0.0.0.0` to accept remote connections |
| `--port` | `3000` | TCP port |
| `--api-key` | none | When set, every request must send a matching `X-API-KEY` header |

Every endpoint takes and returns `application/json`. CORS is open: any origin, method and header. If the port is already in use the server prints an error and exits non-zero rather than crashing.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET, POST | `/health` | Liveness check with the running version |
| POST | `/decode` | Decode a token into header, payload and algorithm |
| POST | `/encode` | Sign a JWT from JSON claims |
| POST | `/verify` | Check an HMAC signature |
| POST | `/crack` | Recover a weak HMAC secret by dictionary or brute force |
| POST | `/payload` | Generate attack tokens |
| POST | `/scan` | Run basic checks and an optional weak-secret probe |

An unknown route returns 404 and malformed JSON returns a 4xx. Application-level failures (bad token, wrong mode) come back as HTTP 200 with `"success": false` and an `error` string, so a client should check the `success` field, not just the status code. With `--api-key` set, a missing or wrong key returns 401.

## Health

```bash
curl -s http://127.0.0.1:3000/health
```

```json
{"status":"ok","version":"2.6.0"}
```

## Decode

Request `{"token": "..."}`. The `algorithm` field reports the real `alg` from the header.

```bash
curl -s http://127.0.0.1:3000/decode \
  -H 'Content-Type: application/json' \
  -d '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
```

```json
{"success":true,"header":{"alg":"HS256","typ":"JWT"},"payload":{"sub":"1234567890","name":"John Doe","iat":1516239022},"algorithm":"HS256","error":null}
```

## Encode

| Field | Default | Description |
| --- | --- | --- |
| `payload` | required | JSON claims object |
| `secret` | `""` | HMAC secret (HS256/384/512) |
| `algorithm` | `HS256` | Signing algorithm |
| `no_signature` | `false` | When true, emit an unsigned `alg:none` token and ignore `secret`/`algorithm` |
| `headers` | none | Extra header params as an array of `[key, value]` pairs |
| `compress` | `false` | DEFLATE the payload and add `"zip":"DEF"` |

Encoding over the API uses HMAC secrets or `none`. Signing with asymmetric private keys is not exposed here; use the CLI `encode` for that.

```bash
curl -s http://127.0.0.1:3000/encode \
  -H 'Content-Type: application/json' \
  -d '{"payload":{"sub":"1234567890","name":"John Doe"},"secret":"secret","algorithm":"HS256","headers":[["kid","abc123"]]}'
```

```json
{"success":true,"token":"eyJ...","error":null}
```

## Verify

Request `{"token": "...", "secret": "...", "validate_exp": false}`. Verification is HMAC only; an RSA/ECDSA/EdDSA token will not validate here.

```bash
curl -s http://127.0.0.1:3000/verify \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","secret":"your-256-bit-secret"}'
```

```json
{"success":true,"valid":true,"error":null}
```

If the token's header is `alg:none` and you send a non-empty secret, the server reports `valid:false` with an explanation instead of silently accepting it, so the `none` bypass is not mistaken for a valid signature.

## Crack

| Field | Default | Description |
| --- | --- | --- |
| `token` | required | Token to attack |
| `mode` | `dict` | `dict` or `brute` |
| `wordlist_content` | none | Inline array of candidate secrets (preferred for `dict`) |
| `wordlist` | none | Server-side file path. Disabled unless gated by `JWT_HACK_WORDLIST_DIR` (see below) |
| `preset` | none | Brute charset preset: `az`, `AZ`, `aZ`, `19`, `aZ19`, `ascii` |
| `chars` | `a-z0-9` | Brute charset when no preset is given |
| `min` / `max` | `1` / `4` | Brute length range |
| `concurrency` | `20` | Accepted for compatibility, not used by the current code |

```bash
# Dictionary with an inline wordlist
curl -s http://127.0.0.1:3000/crack \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","mode":"dict","wordlist_content":["secret","password","hunter2"]}'

# Brute force
curl -s http://127.0.0.1:3000/crack \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","mode":"brute","preset":"aZ19","max":3}'
```

```json
{"success":true,"secret":"secret","error":null}
```

When nothing matches you get `{"success":true,"secret":null,"error":"Secret not found"}`.

Cracking runs on a blocking thread so it can't stall `/health` and the other endpoints, and at most four crack or scan jobs run at once; extra requests wait for a slot. Brute force rejects a keyspace larger than 5,000,000 candidates and a `max` beyond the built-in brute-force length limit, so a single request can't pin a worker indefinitely.

### Server-side wordlist paths

The `wordlist` file path is a remote-controlled filesystem read, so it is off by default. To enable it, set `JWT_HACK_WORDLIST_DIR` to a directory; only paths that canonicalize to inside that directory are honored, which blocks `..` traversal and symlink escapes. Files must be regular files and are read up to 64 MiB. Prefer `wordlist_content` so clients never depend on server-side files.

## Payload

| Field | Default | Description |
| --- | --- | --- |
| `token` | required | Source token |
| `target` | all | Payload type, same values as the CLI `payload` command |
| `jwk_trust` | none | Trusted domain for `jku`/`x5u` scenarios |
| `jwk_attack` | none | Attacker domain for `jku`/`x5u` scenarios |
| `jwk_protocol` | `https` | `http` or `https` |
| `public_key` | none | Server public key (PEM) for RS256-to-HS256 confusion forging |

```bash
curl -s http://127.0.0.1:3000/payload \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","jwk_attack":"attacker.tld","target":"all"}'
```

```json
{"success":true,"payloads":[{"name":"Payload #1","token":"eyJ..."},{"name":"Payload #2","token":"eyJ..."}],"error":null}
```

See [payload](/usage/commands/payload/) for what each target produces.

## Scan

| Field | Default | Description |
| --- | --- | --- |
| `token` | required | Token to inspect |
| `skip_crack` | `false` | Skip the weak-secret probe |
| `wordlist_content` | none | Inline wordlist for the weak-secret probe |
| `wordlist` | none | Server-side path, same `JWT_HACK_WORDLIST_DIR` gating as `/crack` |
| `skip_payloads` | `false` | Accepted but unused; scan does not generate payloads |
| `max_crack_attempts` | `100` | Accepted but not enforced |

```bash
curl -s http://127.0.0.1:3000/scan \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","wordlist_content":["secret","your-256-bit-secret"]}'
```

```json
{"success":true,"vulnerabilities":["Weak secret found: your-256-bit-secret"],"secret":"your-256-bit-secret","error":null}
```

The checks are: `alg:none`, an expired `exp`, an unparseable token (`Invalid token format`), and, unless `skip_crack` is set and a wordlist is supplied, a weak-secret probe that reports the secret both in the `vulnerabilities` list and the top-level `secret` field.

## Exposure

This is a testing tool, not a hardened service. If you bind it beyond localhost, set `--api-key` to require `X-API-KEY` on every request (the key is compared in constant time), and put it behind your own auth, rate limiting and isolation. The `/crack` and `/scan` endpoints are CPU-heavy by design.
