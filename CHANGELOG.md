# Changelog

## v2.6.0

### Added
- JWE support: full key management (RSA-OAEP, RSA-OAEP-256, ECDH-ES, ECDH-ES+A128KW/A256KW, A128KW, A256KW, Direct) and content encryption (A128GCM, A256GCM), plus ES512 (P-521) JWT signing via josekit; new `encode_jwe`/`decrypt_jwe` APIs with roundtrip tests (#203)
- JWE attacks: decryption, key cracking, misconfiguration detection, and a padding-oracle detection module with statistical timing baselines
- JWKS support: `jwks` subcommand to fetch, spoof (jku/x5u), verify tokens against a JWKS, and test key-rotation vulnerabilities (#86)
- `--json` global output mode across all commands, plus `scan --report <path>` for JSON/HTML report export (#202)
- JWT attack coverage — `jwk_embed`, `kid_traversal`, `crit`, `b64`, `empty_sig`, and sensitive-claims/PII detection, with matching scan checks (#196)
- More attack payloads — `x5c_signed`, `psychic` (CVE-2022-21449), `typ_confusion`, `alg_edge`, `jku`/`x5u` SSRF probes, `zip` (DEFLATE bomb), and `kid_predictable`, with matching scan checks (#199)
- Eight more payload styles — `dup_key`, `nested`, `jwk_embed_ec`, `jws_json`, `alg_family_swap`, `none_sig`, `header_quirks`, and `kid_wildcard`; all participate in `--target all` (#200)
- `crack --min` to start brute force from a minimum password length (#208)
- `crack --target-field`/`--pattern` to brute-force specific JWT fields (kid, jti, jku, …) with custom patterns (#87)
- AUR packaging (`aur/PKGBUILD`, release workflow) and lockstep version scripts (`just vc`/`vu`) (#206)
- Supported-algorithms section in the README (#46)

### Changed
- Redesigned documentation site with the Cipher Lab theme — brand-green-on-midnight surface, monospace editorial headings, corner-bracket feature cards, and a token-preview visualizer (#197)
- `scan` now falls back to a header-only decode when strict parsing rejects a token, so shape detectors still fire on malformed inputs (array/null/whitespace `alg`, compressed-but-malformed payloads)

### Performance
- Reduced peak memory ~99% (15.9 GB → ~10 MB) via mimalloc and 100K-entry streaming wordlist batches, while throughput rose ~53% (939K → 1.44M keys/sec); `--power` pool capped at 32 (#208)
- Index-based brute force reuses a per-worker buffer instead of allocating a `String` per candidate; a `String` is allocated only on a hit
- Precompute the HS256 signing input once via `Hs256Verifier` instead of re-decoding the token per candidate
- Load wordlists directly into a `Vec` instead of routing every line through a `HashSet`
- Hoist target-field header/claims clones out of the hot loop into per-worker init
- `panic = "abort"` in the release profile shrinks the binary ~15% (8.58 MB → 7.25 MB)
- Stream brute-force combinations in the server API instead of materializing all of them (#179)

### Security
- Zeroize key material after use — JWE decryption keys, HMAC signatures, and wordlist candidates (#183)
- Replace panicking `unwrap()` with error propagation in production hot paths (#178)
- Recover from mutex poisoning in the crack module to prevent cascading panics across threads

### Fixed
- JWE attack module: reuse the original token header (avoids field-reorder mismatches), enforce exact AES-GCM key length, and guard short IV/tag slices
- `ci(homebrew)`: use `#{bin}` so the published formula's `test` block interpolates correctly

### Build
- Bump Rust to 1.96, `ratatui` 0.30, `rmcp` 1.1, `reqwest` 0.13, `crossterm` 0.29, `toml` 1.0, `ansi-to-tui` 8, plus Docker/Action dependency updates

## v2.5.0
- Interactive `shell` mode; refactored cracking/payload helpers; centralized the common-secrets constant; broader algorithm-confusion scan coverage; docs theme and logo updates

## v2.4.0
- REST API `server` command with optional API-key protection; `scan` command for comprehensive JWT vulnerability scanning; new Zola documentation site

## v2.3.1
- Fix missing fields in the MCP `Implementation` struct initialization

## v2.3.0
- `crack --preset` for character-set presets; release-build and SBOM GitHub Actions workflows

## v2.2.0
- MCP (Model Context Protocol) mode; EdDSA (Edwards-curve DSA) algorithm support

## v2.1.0
- JWT compression support (`zip:DEF` DEFLATE header); Snapcraft and Docker install methods

## v2.0.0
- Complete rewrite from Go to Rust; `verify` mode for signature validation; expanded attack payloads; unit tests for core modules

## v1.2.0
- `crack --max` flag for brute-force length control; arm64 Docker image (Go)

## v1.1.x
- jku/x5u bypass-type payloads; fix CVE-2020-26160; Homebrew tap (Go)

## v1.0.0
- Initial release — decode, encode, dictionary/brute-force cracking, and attack-payload generation (Go)
