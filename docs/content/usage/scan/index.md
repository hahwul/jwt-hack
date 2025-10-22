---
title: "Scan Command"
weight: 7
---

The `scan` command performs an automated, end-to-end security assessment of a JWT. It combines decoding, heuristic checks, optional secret cracking, and attack payload suggestions in a single run.

## Basic Usage

```bash
jwt-hack scan <TOKEN> [OPTIONS]
```

## What the Scanner Checks

The scan runs a sequence of tests designed to quickly surface common JWT weaknesses:

- Token structure and header/payload inspection
- Timestamp sanity checks (iat/exp/nbf presence and order)
- Signature verification heuristics
- Weak/guessable secret detection (optional dictionary-based check)
- Algorithm-related risks (e.g., “none”/confusion vectors)
- Header misuse indicators (kid/jku/x5u patterns)
- Compression and JWE handling hints
- Actionable payload suggestions for follow-up testing

When enabled, the scanner will also generate relevant attack payload suggestions so you can immediately test suspected weaknesses with the `payload` command.

## Options

```bash
# Skip cracking and payload generation
jwt-hack scan <TOKEN> --skip-crack --skip-payloads

# Provide a wordlist for weak-secret checks
jwt-hack scan <TOKEN> -w /path/to/wordlist.txt

# Control max cracking attempts (useful for CI or quick runs)
jwt-hack scan <TOKEN> --max-crack-attempts 100
```

- `--skip-crack` - Skip dictionary-based weak-secret checks
- `--skip-payloads` - Skip payload suggestion/generation section
- `-w, --wordlist <FILE>` - Wordlist to use for weak-secret detection
- `--max-crack-attempts <N>` - Limit secret attempts for faster runs

Note: Large wordlists can make scans longer. Use `--max-crack-attempts` to cap work for quick triage.

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

Target: eyJhbGciOi...<truncated>

[1] Decode & Analysis
- alg: HS256, typ: JWT
- iat: 1516239022 (2018-01-18T01:30:22Z)
- exp: missing

[2] Signature & Secret Checks
- Signature format: present
- Weak secret check: FOUND (e.g. "secret")   <-- if wordlist hit
- Dictionary progress: 16/16 words tested     <-- sample

[3] Algorithm & Header Risks
- none algorithm acceptance: SUGGEST TESTING
- algorithm confusion: SUGGEST TESTING
- header review: kid/jku/x5u present: NO

[4] Payload Suggestions
- none algorithm payloads
- jku/x5u URL manipulation payloads
- kid SQL injection payloads
- alg confusion (RS -> HS) payloads

Result:
✗ Potential issues detected (see sections above)
```

If the scan finds no significant issues, you’ll see:
```
✓ No major vulnerabilities detected in this scan.
```

## Recommended Workflow

1. Run a quick scan to triage:
   ```bash
   jwt-hack scan <TOKEN>
   ```
2. If weak secret is suspected:
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