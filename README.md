<div align="center">
  <picture>
    <img alt="JWT-HACK Logo" src="./images/logo.png" width="260px;">
  </picture>
  <p>JSON Web Token Hack Toolkit</p>
</div>

<p align="center">
  <a href="https://github.com/hahwul/jwt-hack/releases/latest"><img src="https://img.shields.io/github/v/release/hahwul/jwt-hack?style=for-the-badge&logoColor=%23000000&label=jwt-hack&labelColor=%23000000&color=%23000000"></a>
  <a href="https://app.codecov.io/gh/hahwul/jwt-hack"><img src="https://img.shields.io/codecov/c/gh/hahwul/jwt-hack?style=for-the-badge&logoColor=%23000000&labelColor=%23000000&color=%23000000"></a>
  <a href="https://github.com/hahwul/jwt-hack/blob/main/CONTRIBUTING.md"><img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=000000"></a>
  <a href="https://rust-lang.org"><img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"></a>
</p>

# JWT-Hack

A high-performance toolkit for testing, analyzing and attacking JSON Web Tokens.

## Installation

```bash
# From Homebrew
brew tap hahwul/jwt-hack
brew install jwt-hack

# From Cargo
cargo install jwt-hack

# From source
git clone https://github.com/hahwul/jwt-hack
cd jwt-hack
cargo install --path .
```

## Features

- **Decode** - Analyze JWT structure and claims
- **Encode** - Create custom JWTs with various algorithms
- **Crack** - Test JWT secrets with dictionary attacks or bruteforce
- **Payloads** - Generate attack payloads (alg none, jku/x5u)

## Basic Usage

### Decode a JWT
```bash
jwt-hack decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.CHANGED
```

### Encode a JWT
```bash
jwt-hack encode '{"sub":"1234"}' --secret=your-secret
```

### Crack a JWT
```bash
# Dictionary attack
jwt-hack crack -w wordlist.txt JWT_TOKEN

# Bruteforce attack
jwt-hack crack -m brute JWT_TOKEN --max=4
```

### Generate payloads
```bash
jwt-hack payload JWT_TOKEN --jwk-attack evil.com --jwk-trust trusted.com
```

## Advanced Options

### Encode Options
- `--algorithm` - Specify algorithm (default: HS256)
- `--no-signature` - Use 'none' algorithm
- `--private-key` - RSA/ECDSA private key file
- `--header` - Add custom header parameters

### Crack Options
- `-w, --wordlist` - Wordlist file for dictionary attack
- `-m, --mode` - Attack mode (dict/brute)
- `--chars` - Character set for bruteforce
- `--max` - Max length for bruteforce
- `--concurrency` - Parallel operations
- `--power` - Use all CPU cores

### Payload Options
- `--jwk-trust` - Trusted domain for jku/x5u
- `--jwk-attack` - Attack domain for jku/x5u
- `--jwk-protocol` - Protocol (http/https)

## Performance

Written in Rust for:
- Fast execution with large wordlists
- Memory efficiency
- Parallel processing
- Robust error handling

## Contributors

.
