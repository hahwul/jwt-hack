+++
toc = true
title = "jwks"
weight = 7
+++

`jwks` works with JSON Web Key Sets: it pulls keys from an endpoint, mints attacker-controlled key sets for `jku`/`x5u` injection, checks a token against every key in a set, and tests whether old keys left in rotation still verify a token.

```bash
jwt-hack jwks <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
| --- | --- |
| `fetch` | Download and display the keys at a JWKS endpoint |
| `spoof` | Generate an attacker RSA key set and, optionally, `jku`/`x5u` injection tokens |
| `verify` | Verify a token against every key in a JWKS (URL or file) |
| `rotate` | Verify a token against several key files to find rotation overlap |

`--json` works on every subcommand and prints a machine-readable object instead of the formatted view. Use it when piping into `jq` or another tool.

## fetch

Pull the key set and show each key. For RSA and EC keys `jwt-hack` reconstructs the public key as a PEM block you can paste straight into `jwks verify` or `payload --public-key`. Symmetric (`oct`) keys are reported as present but not expanded.

```bash
jwt-hack jwks fetch https://example.com/.well-known/jwks.json
```

The fetch has a 10 second timeout and rejects any response body over 5 MiB, so a hostile endpoint cannot hang the client or exhaust memory.

## spoof

Generate a fresh 2048-bit RSA key pair and emit it as a public JWKS plus the matching private key PEM. This is the key material you host when a target fetches its verification keys from a URL you can influence.

```bash
# Generate a spoofed key set with a chosen kid
jwt-hack jwks spoof --algorithm RS256 --kid demo-key
```

```
▎ SPOOFED JWKS ───────────────────────────────

  Algorithm         RS256

▎ JWKS (Public Key Set)
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "demo-key",
      "alg": "RS256",
      "use": "sig",
      "n": "s23eV18tRjkzs8honRo0DEuzqVDDvXDD8Dqi2N2yr-cy...",
      "e": "AQAB"
    }
  ]
}

▎ Private Key (PEM)
-----BEGIN PRIVATE KEY-----
...
```

| Flag | Default | Description |
| --- | --- | --- |
| `--algorithm` | `RS256` | Key algorithm. One of RS256, RS384, RS512, PS256, PS384, PS512. RSA only |
| `--kid` | `spoofed-key-<unix-ts>` | Key ID written into the JWK |
| `--token` | none | A token to re-sign with the spoofed private key; the signed token is printed |
| `--attacker-url` | none | Switch to injection mode and build `jku`/`x5u` payloads pointing at this URL |
| `-o`, `--output` | none | Write the JWKS JSON to this file so you can serve it |

Passing `--token` without `--attacker-url` just re-signs the token's claims with the new key and adds the `kid`, which is what you want when the target already trusts your key set by `kid`.

### jku/x5u injection

The `jku` and `x5u` headers tell a verifier where to fetch the key (a JWKS URL or a certificate URL). If the verifier trusts those headers without pinning the host, you point them at a JWKS you control and sign with your own key. `--attacker-url` builds that end to end: it generates the spoofed key set, re-signs the token's claims, and injects a `jku` and an `x5u` header so the forged token verifies against the key set you host.

```bash
# Requires --token; emits a jku payload (<url>/jwks.json) and an x5u payload (<url>/cert.pem)
jwt-hack jwks spoof --token "$TOKEN" --attacker-url https://attacker.example -o jwks.json
```

Host the written `jwks.json` (and a certificate at `/cert.pem` for the `x5u` variant) at the attacker URL, then send the matching injection token. For the broader set of header-injection payloads, including `kid` tricks and RS256-to-HS256 confusion, see [payload](/usage/commands/payload/).

## verify

Verify a token against every key in a JWKS and report which keys accept it. Give it either a live endpoint or a local file.

```bash
# Against a remote endpoint
jwt-hack jwks verify "$TOKEN" --url https://example.com/.well-known/jwks.json

# Against a saved key set
jwt-hack jwks verify "$TOKEN" --jwks-file ./jwks.json
```

RSA, EC (P-256, P-384, P-521) and `oct` keys are all supported. Expiration is not checked here, so a key match means the signature is valid regardless of `exp`. A trailing newline on the token is trimmed before verification, so piping a token in still works.

## rotate

Test a token against a pile of key files at once. This catches rotation leftovers: an old signing key that was rotated out but never removed from the verifier still accepts tokens, so a leaked or cracked old key keeps working.

```bash
# Every key file in a directory, plus one more
jwt-hack jwks rotate "$TOKEN" --keys-dir ./keys/ --key extra.pem
```

| Flag | Description |
| --- | --- |
| `--keys-dir` | Directory of key files; files ending in `.pem`, `.key`, `.pub`, `.txt` or no extension are collected |
| `--key` | A single key file. Repeat the flag to add several |

Each key is tried first as a public-key PEM and then as an HMAC secret (text keys) or raw secret bytes (binary keys), so a mixed directory of RSA public keys and HMAC secrets all get tested. One unreadable or binary file does not abort the batch. If more than one key verifies the token, `jwt-hack` warns that multiple keys overlap, which is the rotation-leftover signal.
