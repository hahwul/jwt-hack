+++
toc = true
title = "scan"
weight = 6
+++

Run a token through a set of heuristic checks in one pass: decode it, flag common weaknesses, try weak secrets on HS tokens, and suggest matching attack payloads. Use it to triage a token before deciding which of [crack](/usage/commands/crack/), [payload](/usage/commands/payload/), or [verify](/usage/commands/verify/) to run next.

## Usage

```bash
jwt-hack scan <TOKEN> [OPTIONS]
```

```text
▎ SCAN ───────────────────────────────────────

  Algorithm         HS256
  Type              JWT

▎ RESULTS ────────────────────────────────────

  ✓ PASS  None Algorithm         Token does not use 'none' algorithm
  ✓ PASS  Algorithm Confusion    Symmetric algorithm
  ...
  ▲ CRIT  Weak Secret            Uses weak secret: 'test'
  ◆ MED   Token Expiration       Missing 'exp', 'nbf', 'iat'
  ■ LOW   Missing Claims         Missing recommended claims: aud, iss, jti

▎ SUMMARY ────────────────────────────────────

  3 vulnerabilities found: 1 critical, 1 medium, 1 low
```

## What it checks

For a standard JWS (3-part token):

- `none` algorithm in use
- algorithm confusion risk: asymmetric algs are flagged for follow-up, not confirmed
- weak/guessable HMAC secret (HS* only; see below)
- `kid` header present (SQL/path-injection surface)
- `jku` / `x5u` headers (URL spoofing, remote JWKS)
- embedded `jwk` header
- `crit`, `b64` (RFC 7797), `zip`, and `typ` header misuse
- `alg` edge values and whether the signature segment is present
- ECDSA psychic-signature applicability
- `exp`/`nbf`/`iat` presence and whether `exp` has passed
- missing recommended claims (`aud`, `iss`, `jti`)
- sensitive data patterns in claims

A 5-part token is scanned as a JWE instead: the checks move to the encryption layer (key-management `alg`, content `enc`, CBC padding-oracle and compression risks), since there is no JWS signature to reason about.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-w, --wordlist <FILE>` | built-in list | Secrets to try for the weak-secret check. Falls back to a small built-in list if unset or unreadable. |
| `--max-crack-attempts <N>` | `100` | Cap on secrets tested during the weak-secret check. |
| `--skip-crack` | off | Skip the weak-secret check entirely. |
| `--skip-payloads` | off | Skip the attack-payload suggestions. |
| `--report <FILE>` | none | Write a report to a file; `.json` emits JSON, `.html`/`.htm` emits HTML. Any other extension errors. |

The weak-secret check only runs on HMAC tokens (HS256/384/512). For RS/ES/PS/EdDSA it reports as not applicable. Large wordlists slow the scan down, so cap it with `--max-crack-attempts` during triage or CI.

## Examples

Full scan, then export an HTML report for a ticket:

```bash
jwt-hack scan "$TOKEN" --report findings.html
```

Fast heuristics only, no cracking and no payloads:

```bash
jwt-hack scan "$TOKEN" --skip-crack --skip-payloads
```

CI-friendly run with a real wordlist but a bounded budget:

```bash
jwt-hack scan "$TOKEN" -w rockyou.txt --max-crack-attempts 200
```

## Notes

- Payload suggestions follow the findings: a `kid` header produces `kid` payloads, a clean token produces none. Suppress them with `--skip-payloads`.
- The weak-secret default list is small and meant for triage. Confirm a real crack with [crack](/usage/commands/crack/) and a proper wordlist.
- Asymmetric algorithms flagged for confusion are a prompt to test, not a confirmed finding. Verify with [payload](/usage/commands/payload/) `--target alg_confusion`.
