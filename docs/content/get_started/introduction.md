+++
toc = true
title = "Introduction"
weight = 1
+++

`jwt-hack` is a JWT and JWE security testing toolkit: one Rust binary that decodes, forges, verifies, cracks, and attacks tokens. It is meant for the offensive side of auth work, finding the bug before someone else does, but it reads and signs tokens just as happily for day-to-day debugging.

## What it does

| Command | What it is for |
|---------|----------------|
| [`decode`](/usage/commands/decode/) | Read a JWT or JWE: header, claims, timestamps. Handles DEFLATE and JWE structure. |
| [`encode`](/usage/commands/encode/) | Sign a token with any supported algorithm, custom headers, compression, or as JWE. |
| [`verify`](/usage/commands/verify/) | Check a signature against a secret or key, optionally the `exp` claim. |
| [`crack`](/usage/commands/crack/) | Recover an HMAC secret by dictionary or brute force, or guess a target field. |
| [`payload`](/usage/commands/payload/) | Generate attack tokens: none-alg, algorithm confusion, kid injection, jku/x5u, claim tampering, and more. |
| [`scan`](/usage/commands/scan/) | Run every check against a token and export a graded report. |
| [`jwks`](/usage/commands/jwks/) | Fetch, spoof, verify, and rotation-test JWKS key sets. |
| [`shell`](/usage/commands/shell/) | Interactive REPL with history and completion. |
| [`server`](/usage/commands/server/) | REST API over the same operations. |
| [`mcp`](/usage/commands/mcp/) | Expose the toolkit as tools for MCP clients like Claude. |

Every command takes `--json` for machine-readable output, so any of them drops into a script or pipeline.

## Supported algorithms

Signing: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, and the unsigned `none`.

JWE key management: `dir`, RSA-OAEP, RSA-OAEP-256, ECDH-ES, ECDH-ES with A128KW/A256KW, and standalone A128KW/A256KW. Content encryption is A128GCM or A256GCM.

## The attacks it covers

`payload` and `scan` know the common ways a JWT implementation goes wrong:

- Accepting `none` or a downgraded signature.
- Algorithm confusion, where an RS256 verifier is tricked into checking an HS256 token with the public key as the HMAC secret.
- `kid` header injection: SQL, path traversal, and predictable key IDs.
- `jku` and `x5u` pointing at attacker-hosted key material, including full JWKS spoofing via [`jwks`](/usage/commands/jwks/).
- Claim tampering: privilege escalation, expiry manipulation, and type confusion.
- Signature malleability and other parser quirks.

See [`payload`](/usage/commands/payload/) for the full target list.

## Format handling

DEFLATE-compressed tokens (`"zip":"DEF"`) are detected and decompressed on decode, produced with `--compress` on encode, and handled transparently while cracking. JWE tokens are recognized by their 5-part structure and broken down into their components.

## Performance

Cracking runs in parallel across cores (`--power` to use all of them), with progress reporting on long runs. Ready to try it? Start with [installation](/get_started/installation/) and the [quick start](/get_started/quickstart/).
