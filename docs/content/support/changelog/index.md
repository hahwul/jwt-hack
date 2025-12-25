---
title: "Changelog"
weight: 3
---

Version history and release notes for JWT-HACK.

## v2.4.0 (2025-10-26)

**New Features:**
- Added `jwt-hack scan`: JWT vulnerability scanning capability
- Added `jwt-hack server`: API server mode for programmatic access
- Added `--config` flag: Support for configuration via HOME and XDG directories

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v2.4.0)
- [Full Changelog](https://github.com/hahwul/jwt-hack/compare/v2.3.1...v2.4.0)

## v2.3.1 (2025-09-13)

**Improvements:**
- Fixed MCP: Added missing fields to Implementation struct initialization
- Bumped to checkout v5 (GitHub action)

**Contributors:**
- @chenrui333 made their first contribution

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v2.3.1)
- [Full Changelog](https://github.com/hahwul/jwt-hack/compare/v2.3.0...v2.3.1)

## v2.3.0 (2025-09-11)

**New Features:**
- Added MCP Client Integration Examples
- Added `--preset` flag for crack mode with character set presets
- Added release binary and SBOM Workflows

**Contributors:**
- @chei-l made their first contribution

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v2.3.0)
- [Full Changelog](https://github.com/hahwul/jwt-hack/compare/v2.2.0...v2.3.0)

## v2.2.0 (2025-08-29)

**New Features:**
- Added JWE (JSON Web Encryption) support
- Added EdDSA (Edwards-curve Digital Signature Algorithm) support
- Added MCP (Model Context Protocol) server mode for AI model integration

**Improvements:**
- Updated Dockerfile dependencies and base image to Alpine 3.22
- Fixed Docker build issues

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v2.2.0)
- [Full Changelog](https://github.com/hahwul/jwt-hack/compare/v2.1.0...v2.2.0)

## v2.1.0 (2025-08-10)

**New Features:**
- Added JWT compression support with "zip": "DEF" header for DEFLATE compression
- Added comprehensive GitHub Copilot instructions for development

**Improvements:**
- High-Def Logo Upgrade
- Refactored to use Rust 1.58+ format string syntax
- Added default, build, and dev tasks to justfile
- Improved code comments

**Contributors:**
- @thezakman made their first contribution
- @Copilot made their first contribution

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v2.1.0)
- [Full Changelog](https://github.com/hahwul/jwt-hack/compare/v2.0.0...v2.1.0)

## v2.0.0 (2025-06-06)

**Major Changes:**
- **Core Engine Rewrite (Go → Rust)**: Complete rewrite in Rust for improved speed and stability
- **Expanded Cracking Support**: Added full support for PS & ES family algorithms
- **Revamped Console Output**: Beautiful terminal output redesign for better readability
- **Additional Attack Vectors**: Added SQL Injection (SQLi) testing modules for JWT claims

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v2.0.0)
- [Full Changelog](https://github.com/hahwul/jwt-hack/compare/v1.2.0...v2.0.0)

## v1.2.0 (2024-05-21)

**Improvements:**
- Support for Windows ARM64
- Migrated jwt-go to golang-jwt
- Updated dependencies and Go version (1.17 to 1.21)
- Added arm64 docker image builder
- Bumped to cosign for signing

**Contributors:**
- @isacaya contributed 'max' flag logic
- @ScriptIdiot contributed improvements

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v1.2.0)

## v1.1.2 (2021-12-24)

**Security:**
- Fixed CVE-2020-26160 vulnerability

**Improvements:**
- Updated test code
- Updated Go version

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v1.1.2)

## v1.1.1 (2021-10-14)

**Improvements:**
- Changed panic() to os.Exit()
- Added missing error handling

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v1.1.1)

## v1.1.0 (2021-10-03)

**New Features:**
- Added JKU and X5U payloads (bypass type)

**Resources:**
- [Release Notes](https://github.com/hahwul/jwt-hack/releases/tag/v1.1.0)

## Older Versions

For older version history, please visit the [GitHub Releases](https://github.com/hahwul/jwt-hack/releases) page.

## Release Notes

All releases include:
- Pre-built binaries for Linux (x86_64, aarch64)
- Pre-built binaries for macOS (x86_64, aarch64)
- SHA256 checksums for verification
- SBOM (Software Bill of Materials)

## How to Upgrade

### Using Cargo
```bash
cargo install jwt-hack --force
```

### Using Homebrew (macOS)
```bash
brew upgrade jwt-hack
```

### Using Snap (Ubuntu)
```bash
sudo snap refresh jwt-hack
```

### From Binary
Download the latest release from the [Releases Page](https://github.com/hahwul/jwt-hack/releases).

## Contributing

Found a bug or want to suggest a feature? Please open an issue on [GitHub Issues](https://github.com/hahwul/jwt-hack/issues).

Want to contribute code? Check out the [Contributing Guide](/support/contributing).
