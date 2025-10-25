---
title: "Server Command"
weight: 8
---

> Availability: The `server` command is introduced in v2.4.0 and is not yet released. It is unavailable in current binaries (Cargo/Homebrew/Snap/Docker). To try it early, build from the main branch:
>
> ```bash
> git clone https://github.com/hahwul/jwt-hack
> cd jwt-hack
> cargo install --path .
> ```
>
> Note: Pre-release code may change before the official v2.4.0 release.
>
# Server Command

The `server` command starts a local REST API that exposes JWT-HACK features over HTTP. It’s useful for automation, integrations, and UI frontends.

- Default bind: http://127.0.0.1:3000
- CORS: Allowed from any origin
- Content type: All endpoints expect and return application/json

## Usage

```/dev/null/help.txt#L1-20
Starts a REST API server for JWT operations

Usage: jwt-hack server [OPTIONS]

Global options (available to all subcommands):
      --config <CONFIG>  Path to configuration file

Server options:
      --host <HOST>      Host address to bind to [default: 127.0.0.1]
      --port <PORT>      Port number to listen on [default: 3000]
      --api-key <API_KEY>  API key to secure the REST API (validated via X-API-KEY header)
  -h, --help             Print help

Examples:
  # start on default 127.0.0.1:3000
  ./target/debug/jwt-hack server

  # start on all interfaces on port 8080
  ./target/debug/jwt-hack server --host 0.0.0.0 --port 8080

  # protect with API key (clients must send -H 'X-API-KEY: <KEY>')
  ./target/debug/jwt-hack server --api-key your-api-key

  # with a config file (global option)
  ./target/debug/jwt-hack --config ./jwt-hack.toml server
```

Note on configuration: the `--config` option is global. The server loads configuration at startup, but most REST behaviors described here do not require a config file.

## Endpoints

- GET/POST `/health` — Health check with version info
- POST `/decode` — Decode a JWT
- POST `/encode` — Create a JWT
- POST `/verify` — Verify a JWT signature
- POST `/crack` — Attempt to find a weak secret (dictionary or brute force)
- POST `/payload` — Generate attack payload tokens (for testing)
- POST `/scan` — Basic vulnerability scan and weak secret check

All endpoints return JSON. Most errors are reported as HTTP 200 with `success:false` and an `error` string. In rare internal failures, HTTP 500 may be returned with the same JSON shape via `{ success:false, error:"..." }`.

---

## Schemas

The following request and response shapes are supported.

### Health
- Request: none
- Response:
```/dev/null/health-response.json#L1-5
{
  "status": "ok",
  "version": "2.3.1"
}
```

### Decode
- Request:
```/dev/null/decode-request.json#L1-3
{
  "token": "eyJhbGciOi..."
}
```
- Response:
```/dev/null/decode-response.json#L1-16
{
  "success": true,
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
  },
  "algorithm": "HS256",
  "error": null
}
```

### Encode
- Request:
```/dev/null/encode-request.json#L1-20
{
  "payload": { "sub": "1234567890", "name": "John Doe", "iat": 1516239022 },

  // Optional. Used when signing with HMAC (HS256/HS384/HS512).
  // If "no_signature": true, this is ignored.
  "secret": "secret",

  // Optional. Defaults to "HS256".
  // Combined with "no_signature": true, you can produce "none" algorithm tokens.
  "algorithm": "HS256",

  // Optional. When true, produces an unsigned token ("alg":"none").
  "no_signature": false,

  // Optional. Additional header parameters as an array of 2-tuples.
  // Example below adds {"kid":"abc123", "cty":"JWT"} to the header.
  "headers": [["kid","abc123"], ["cty","JWT"]],

  // Optional. DEFLATE compression for payload; adds {"zip":"DEF"} to headers.
  "compress": false
}
```
- Response:
```/dev/null/encode-response.json#L1-6
{
  "success": true,
  "token": "eyJhbGciOi...signature",
  "error": null
}
```

Notes:
- The server-side encode API currently supports HMAC secrets and "none" algorithm. Asymmetric keys for encoding are not exposed over this REST API.

### Verify
- Request:
```/dev/null/verify-request.json#L1-10
{
  "token": "eyJhbGciOi...",
  // Optional HMAC secret; defaults to empty string when omitted.
  "secret": "secret",
  // Optional. When true, validates "exp" claim; when false, ignores it.
  "validate_exp": true
}
```
- Response:
```/dev/null/verify-response.json#L1-6
{
  "success": true,
  "valid": true,
  "error": null
}
```

Notes:
- The server-side verify API uses HMAC secrets. If the token was signed with RSA/ECDSA/EdDSA, this endpoint will not validate it successfully.

### Crack
- Request:
```/dev/null/crack-request.json#L1-18
{
  "token": "eyJhbGciOi...",
  // "dict" (default) or "brute"
  "mode": "dict",

  // Required when mode="dict": file path accessible to the server process
  // (e.g., "samples/wordlist.txt")
  "wordlist": "samples/wordlist.txt",

  // Used when mode="brute":
  // Either specify "preset" or provide a custom "chars" and "max".
  // Presets: "az", "AZ", "aZ", "19", "aZ19", "ascii"
  "preset": "aZ19",
  "chars": "abcdefghijklmnopqrstuvwxyz0123456789",
  "concurrency": 20,  // accepted but not leveraged by the current API code
  "max": 4
}
```
- Response:
```/dev/null/crack-response.json#L1-10
{
  "success": true,
  // The discovered secret (if any)
  "secret": "secret",
  // When no secret is found, API returns:
  // { "success": true, "secret": null, "error": "Secret not found" }
  "error": null
}
```

Notes:
- Dictionary mode requires a file path on the server host. The API does not upload wordlists.
- Brute-force tries all combinations up to `max` using `chars` or a `preset`.
- This endpoint executes synchronously and can be CPU-intensive; prefer small search spaces or offload heavy jobs to batch workers.

### Payload
- Request:
```/dev/null/payload-request.json#L1-12
{
  "token": "eyJhbGciOi...",
  // Optional trusted domain for jku/x5u scenarios
  "jwk_trust": "example.com",
  // Optional attacker-controlled domain for jku/x5u scenarios
  "jwk_attack": "attacker.tld",
  // http/https; defaults to "https"
  "jwk_protocol": "https",
  // Optional. Same values as CLI: "all,none,jku,x5u,alg_confusion,kid_sql,x5c,cty"
  "target": "all"
}
```
- Response:
```/dev/null/payload-response.json#L1-18
{
  "success": true,
  "payloads": [
    {
      "name": "Payload #1",
      "token": "eyJhbGciOi...payload1..."
    },
    {
      "name": "Payload #2",
      "token": "eyJhbGciOi...payload2..."
    }
  ],
  "error": null
}
```

Notes:
- The API returns a list of generated attack tokens labeled as `Payload #N`.
- Use these only in safe, controlled environments for security testing.

### Scan
- Request:
```/dev/null/scan-request.json#L1-12
{
  "token": "eyJhbGciOi...",
  // If true, skip dictionary-based weak secret check
  "skip_crack": false,
  // Accepted but not used by current server-side implementation
  "skip_payloads": false,
  // Optional path for wordlist (used if skip_crack=false)
  "wordlist": "samples/wordlist.txt",
  // Accepted but not enforced by current implementation
  "max_crack_attempts": 100
}
```
- Response:
```/dev/null/scan-response.json#L1-14
{
  "success": true,
  "vulnerabilities": [
    "Uses 'none' algorithm (unsigned token)",
    "Token is expired",
    "Weak secret found: secret",
    "Invalid token format"
  ],
  // Present only if a weak secret was found via wordlist
  "secret": "secret",
  "error": null
}
```

Notes:
- The scan performs:
  - Basic header check for `alg:"none"`.
  - Expiration check on `exp` if present.
  - Optional weak secret discovery via dictionary if `wordlist` is provided and `skip_crack` is false.
- It does not currently generate payloads despite accepting `skip_payloads` (reserved for future behavior).

---

## cURL Examples

Replace host/port as needed. If the server was started with --api-key, include -H 'X-API-KEY: <API_KEY>' in each request.  

### Health
```/dev/null/curl-health.sh#L1-3
curl -s http://127.0.0.1:3000/health
curl -s -X POST http://127.0.0.1:3000/health
```

### Decode
```/dev/null/curl-decode.sh#L1-4
curl -s http://127.0.0.1:3000/decode \
  -H 'Content-Type: application/json' \
  -d '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6InQifQ.f8oE7B4G3RzYQ0kQ1kSsm1oQ2wKT1L9WZbnzv2mC1pI"}'
```

### Encode (HS256)
```/dev/null/curl-encode-hs256.sh#L1-6
curl -s http://127.0.0.1:3000/encode \
  -H 'Content-Type: application/json' \
  -d '{
        "payload":{"sub":"1234567890","name":"John Doe","iat":1516239022},
        "secret":"secret","algorithm":"HS256","headers":[["kid","abc123"]]
      }'
```

### Encode (none)
```/dev/null/curl-encode-none.sh#L1-6
curl -s http://127.0.0.1:3000/encode \
  -H 'Content-Type: application/json' \
  -d '{
        "payload":{"sub":"123"},
        "no_signature":true
      }'
```

### Verify
```/dev/null/curl-verify.sh#L1-6
curl -s http://127.0.0.1:3000/verify \
  -H 'Content-Type: application/json' \
  -d '{
        "token":"<your-token>",
        "secret":"secret", "validate_exp":true
      }'
```

### Crack (dictionary)
```/dev/null/curl-crack-dict.sh#L1-5
curl -s http://127.0.0.1:3000/crack \
  -H 'Content-Type: application/json' \
  -d '{
        "token":"<your-token>", "mode":"dict", "wordlist":"samples/wordlist.txt"
      }'
```

### Crack (brute force)
```/dev/null/curl-crack-brute.sh#L1-6
curl -s http://127.0.0.1:3000/crack \
  -H 'Content-Type: application/json' \
  -d '{
        "token":"<your-token>", "mode":"brute",
        "preset":"aZ19", "max":3
      }'
```

### Payload generation
```/dev/null/curl-payload.sh#L1-7
curl -s http://127.0.0.1:3000/payload \
  -H 'Content-Type: application/json' \
  -d '{
        "token":"<your-token>",
        "jwk_trust":"example.com","jwk_attack":"attacker.tld",
        "jwk_protocol":"https","target":"all"
      }'
```

### Scan
```/dev/null/curl-scan.sh#L1-6
curl -s http://127.0.0.1:3000/scan \
  -H 'Content-Type: application/json' \
  -d '{
        "token":"<your-token>",
        "skip_crack":false, "wordlist":"samples/wordlist.txt"
      }'
```

---

## Operational Notes

- Bind address: Use `--host 0.0.0.0` to accept remote connections.
- CORS: Open (any origin, any method, any header).
- Performance: `/crack` can be CPU-heavy and synchronous; keep search spaces small or run behind a job queue.
- Security: This server is a testing tool. If exposed beyond localhost, use --api-key to require X-API-KEY on all requests and add additional safeguards (authN/Z, rate limits, isolation).  
- Errors: Most endpoints return HTTP 200 with `success:false` and `error`. Handle both the HTTP status and the `success` flag in clients.