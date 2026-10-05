+++
toc = true
title = "payload"
weight = 5
+++

Generate attack tokens from an existing JWT. You give it a token, it rewrites headers, claims, or signatures into the shapes that break common verification mistakes, and prints each as a ready-to-send token.

## Usage

```bash
jwt-hack payload <TOKEN> [OPTIONS]
```

With no `--target`, it runs every category (`--target=all`). Narrow it to one or several comma-separated targets to keep the output readable:

```bash
jwt-hack payload "$TOKEN" --target none
```

```text
▎ None Algorithm (none)
  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0

▎ None Algorithm (NonE)
  eyJhbGciOiJOb25FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0

▎ None Algorithm (NONE)
  eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target <TYPE>` | `all` | One or more targets, comma-separated. See the table below. |
| `--public-key <PEM\|PATH>` | none | Server public key, inline PEM or a file path. Used by `alg_confusion` to forge a fully signed HS token with the key bytes as the HMAC secret. |
| `--jwk-attack <DOMAIN>` | none | Attacker-controlled domain for `jku`/`x5u`. Required for those targets. |
| `--jwk-trust <DOMAIN>` | none | A trusted domain to fold into bypass variants (e.g. `trusted.com@evil.com`). |
| `--jwk-protocol <PROTO>` | `https` | Protocol for the generated `jku`/`x5u` URLs. |

## Targets

### Algorithm

| Target | What it does |
|--------|--------------|
| `none` | `alg` set to `none`/`NonE`/`NONE` with an empty signature: the classic signature strip. |
| `alg_confusion` | Downgrade RS/PS/ES/EdDSA to the matching HS family. With `--public-key`, forges a fully signed HS token (public key bytes as the secret, across common PEM byte-normalizations); without it, emits the unsigned downgrade header plus a `none` variant. |
| `alg_edge` | Edge-case `alg` values that stress loose header parsers. |
| `alg_family_swap` | Cross-family swap (PS<->RS, ES family) while keeping `kid` so the server still resolves the same key. |
| `none_sig` | `alg: none` but with a non-empty signature, for verifiers that only string-match the alg. |

### Key resolution (kid / jwk / x5c)

| Target | What it does |
|--------|--------------|
| `kid_sql` | SQL injection strings in `kid`. |
| `kid_traversal` | Path traversal in `kid` pointing at a known file, signed with that file's bytes as the secret. |
| `kid_predictable` | Predictable key-file paths in `kid`. |
| `kid_wildcard` | Empty, null, and wildcard `kid` fallbacks, HS256-signed with an empty secret. |
| `kid_injection` | NoSQL (e.g. `{"$ne":null}`), OS command, SSTI, LDAP, and CRLF vectors in `kid`, emitted unsigned since the sink fires at key lookup. |
| `jwk_embed` | Embed an attacker RSA `jwk` in the header and sign with the matching private key. |
| `jwk_embed_ec` | Same, EC key, signed ES256. |
| `x5c` | Inject an `x5c` certificate chain header. |
| `x5c_signed` | Self-signed cert in `x5c` with a matching signature; verifiers that trust `x5c[0]` accept it. |

### URL / SSRF

| Target | What it does |
|--------|--------------|
| `jku` | Rewrite the `jku` header to attacker-controlled JWKS. Needs `--jwk-attack`. |
| `x5u` | Same, for the `x5u` certificate URL. Needs `--jwk-attack`. |
| `ssrf` | `jku`/`x5u` SSRF probe URLs (internal hosts, cloud metadata) without needing `--jwk-attack`. |

### Header tricks

| Target | What it does |
|--------|--------------|
| `cty` | `cty` content-type values aimed at XXE and deserialization sinks. |
| `crit` | `crit` header listing unknown params, to bypass verifiers that ignore it. |
| `b64` | RFC 7797 `b64: false` unencoded-payload variants. |
| `zip` | `zip` compression variants plus a decompression-bomb probe. |
| `typ_confusion` | `typ` set to other media types. |
| `dup_key` | Duplicate JSON keys (`alg`/`typ`/`kid`) in the header, built as raw JSON so dedup does not collapse them. |
| `nested` | Nested JWT via `cty: JWT`. |
| `header_quirks` | BOM, whitespace, and trailing-junk variations in the header JSON. |
| `jws_json` | JWS flattened JSON serialization instead of compact form. |

### Signature

| Target | What it does |
|--------|--------------|
| `empty_sig` | Strip the signature while keeping the original `alg`. |
| `psychic` | ECDSA all-zero "psychic" signature (CVE-2022-21449). |
| `sig_malleability` | ECDSA high-S (`s' = n - s`), a DER-encoded signature, and structural probes (all-zero, truncated, trailing-byte-extended). |

### Claims (token body)

Emitted as `alg: none`, so they land once a signature bypass is in hand. Re-sign with [encode](/usage/commands/encode/) if you recover the key.

| Target | What it does |
|--------|--------------|
| `claims_privesc` | Privilege-escalation claims: `role`, `admin`, `scope`, `groups`, and similar. |
| `claims_exp` | `exp`/`nbf`/`iat` manipulation, including type juggling and removal. |
| `claims_confusion` | `iss`/`aud`/`sub` confusion (array vs string, wildcards) plus a duplicate-key body. |
| `claim_injection` | XSS, SQLi, SSTI, log4j JNDI, path traversal, and CRLF sprayed into string-valued claims. |

### JWE

| Target | What it does |
|--------|--------------|
| `jwe` | JWE header-confusion and PBES2 `p2c` iteration-count DoS probes. Judge by the server's differential or latency response, not by successful decryption. |

## Examples

Point key resolution at an attacker JWKS, keeping a trusted host in the URL for filter bypasses:

```bash
jwt-hack payload "$TOKEN" --target jku,x5u --jwk-attack evil.com --jwk-trust trusted.com --jwk-protocol http
```

Forge a signed alg-confusion token once you have the server's RSA public key:

```bash
jwt-hack payload "$RSA_TOKEN" --target alg_confusion --public-key ./server-pub.pem
```

Dump everything to a file to feed an Intruder-style runner:

```bash
jwt-hack payload "$TOKEN" --target all > payloads.txt
```

## Notes

- An unknown `--target` prints a warning and is skipped; the valid list is printed with it.
- `jku`/`x5u`/`ssrf` only produce output when relevant; `jku` and `x5u` need `--jwk-attack` or they are skipped with a warning.
