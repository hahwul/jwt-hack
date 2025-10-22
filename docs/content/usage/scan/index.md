---
title: "Scan Command"
weight: 7
---

The `scan` command runs a fast, heuristic assessment of a JWT. It decodes the token, performs common weakness checks, optionally tries weak secrets for HS* tokens, and can print example attack payloads for follow‑up testing.

## Basic Usage

```bash
jwt-hack scan <TOKEN> [OPTIONS]
```

## What the Scanner Checks

The current scanner performs the following checks:

- Token information
  - Displays algorithm and `typ` from the header.
- Timestamp checks
  - Presence of `exp` and whether it is expired.
  - Presence of `iat` and `nbf` (no ordering validation between `iat`, `nbf`, `exp`).
- “none” algorithm usage
  - Flags if the token actually uses the `none` algorithm.
- Weak/guessable secret (HS* only)
  - For HMAC tokens (HS256/384/512), tries a limited secret list (built‑in or provided wordlist).
- Algorithm confusion indicator
  - Flags asymmetric algorithms (RS/ES/PS/EdDSA) as “needs testing” for alg-confusion risks.
- Header misuse indicators
  - `kid` presence (possible SQL/path injection surfaces).
  - `jku` / `x5u` presence (possible URL spoofing / remote JWKS risks).
- Attack payload suggestions (optional)
  - Prints example payloads for detected issues: `none`, `alg_confusion`, `kid_sql`.

Notes:
- JWE (5-part) tokens are not supported by `scan`.
- Compressed JWT payloads (`zip: "DEF"`) are decoded but not separately highlighted as a finding.

## Options

```bash
# Skip cracking and payload generation
jwt-hack scan <TOKEN> --skip-crack --skip-payloads

# Provide a wordlist for weak-secret checks (HS* only)
jwt-hack scan <TOKEN> -w /path/to/wordlist.txt

# Limit secret attempts (useful for CI or quick runs)
jwt-hack scan <TOKEN> --max-crack-attempts 100
```

- `--skip-crack` — Skip dictionary-based weak-secret checks (only affects HS*).
- `--skip-payloads` — Skip the payload suggestion/generation section.
- `-w, --wordlist <FILE>` — Wordlist for weak-secret detection. If not provided or cannot be opened, a small built‑in list is used.
- `--max-crack-attempts <N>` — Limit tested secrets (default: 100).

Tip: Large wordlists can significantly increase scan time. Use `--max-crack-attempts` to cap work during triage or CI.

## Examples

### Quick Full Scan
```bash
jwt-hack scan eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.PAYLOAD.SIGN
```

### Scan With Wordlist
```bash
jwt-hack scan <TOKEN> -w samples/wordlist.txt
```

### Fast Heuristics Only (no cracking, no payloads)
```bash
jwt-hack scan <TOKEN> --skip-crack --skip-payloads
```

### CI-Friendly Scan (limit attempts)
```bash
jwt-hack scan <TOKEN> -w rockyou.txt --max-crack-attempts 200
```

## Typical Output

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  JWT VULNERABILITY SCANNER
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

━━━ Token Information ━━━
Algorithm: HS256
Type: JWT

━━━ Scan Results ━━━

✓ None Algorithm [INFO]
  Token does not use 'none' algorithm

✗ Weak Secret [CRITICAL]
  Token uses weak/common secret: 'secret'

✓ Algorithm Confusion [INFO]
  Token uses symmetric algorithm, not vulnerable to typical alg confusion

✗ Token Expiration [MEDIUM]
  Missing 'nbf' (not before) claim; Missing 'iat' (issued at) claim

✗ Missing Claims [LOW]
  Missing recommended claims: aud, iss, jti

✓ Kid Header Injection [INFO]
  No 'kid' header present

✓ JKU/X5U Header [INFO]
  No JKU/X5U headers present

━━━ Summary ━━━
Total Vulnerabilities Found: 3
  1 Critical
  1 Medium
  1 Low

⚠️  Review the vulnerabilities above and consider generating attack payloads.

━━━ Generating Attack Payloads ━━━
... (example payloads for 'none', 'alg_confusion', 'kid_sql')
```

If the scan finds no significant issues, you’ll see:
```
✓ No major vulnerabilities detected in this scan.
```

## Behavior Details and Limitations

- HS* only for weak-secret checks
  - Secret cracking runs only when the algorithm is HMAC (HS256/384/512). For non‑HS* tokens, this check is skipped as “Not applicable”.
- Algorithm confusion is heuristic
  - Asymmetric algorithms are flagged as “needs testing” (High) to prompt follow‑up validation; it is not a confirmed vulnerability by itself.
- JKU/X5U payloads
  - The scanner flags the presence of these headers, but the current payload generation prints examples for `none`, `alg_confusion`, and `kid_sql`. It does not print `jku/x5u` payload examples in this command’s output.

## Recommended Workflow

1. Run a quick scan to triage:
   ```bash
   jwt-hack scan <TOKEN>
   ```
2. If a weak secret is suspected (HS*):
   ```bash
   jwt-hack crack -w <WORDLIST> <TOKEN>
   ```
3. If payloads are suggested:
   ```bash
   jwt-hack payload <TOKEN> --target=all
   ```
4. Verify any hypotheses:
   ```bash
   jwt-hack verify <TOKEN> --secret=<KEY or PUBLIC_KEY>
   ```

## Troubleshooting

- JWE input: `scan` expects a JWT (3 parts). 5‑part JWE tokens are not supported.
- If the scan terminates early, ensure the token uses the standard `<header>.<payload>.<signature>` format.
- For faster results, use `--skip-crack` or set `--max-crack-attempts` to a small number.
- Wordlist path errors: provide an absolute path or a path relative to your project root.
- Usage hint (shown on errors):
  ```
  e.g jwt-hack scan {JWT_CODE} [--skip-crack] [--skip-payloads] [-w wordlist.txt]
  ```

## Security Notes

- Only scan tokens you own or have permission to test.
- Treat discovered secrets as sensitive; handle and store them securely.
- Use findings to harden your systems (strong secrets, enforce `exp`, avoid risky headers, validate key sources).