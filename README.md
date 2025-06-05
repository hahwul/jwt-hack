<div align="center">
  <picture>
    <img alt="JWT-HACK Logo" src="https://raw.githubusercontent.com/hahwul/jwt-hack/refs/heads/v2/images/logo.png" width="260px;">
  </picture>
  <p>JSON Web Token Hack Toolkit</p>
</div>

<p align="center">
  <a href="https://github.com/hahwul/jwt-hack/releases/latest"><img src="https://img.shields.io/github/v/release/hahwul/jwt-hack?style=for-the-badge&logoColor=%23000000&label=jwt-hack&labelColor=%23000000&color=%23000000"></a>
  <a href="https://app.codecov.io/gh/hahwul/jwt-hack"><img src="https://img.shields.io/codecov/c/gh/hahwul/jwt-hack?style=for-the-badge&logoColor=%23000000&labelColor=%23000000&color=%23000000"></a>
  <a href="https://github.com/hahwul/jwt-hack/blob/main/CONTRIBUTING.md"><img src="https://img.shields.io/badge/CONTRIBUTIONS-WELCOME-000000?style=for-the-badge&labelColor=000000"></a>
  <a href="https://rust-lang.org"><img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"></a>
</p>

---

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

| Mode    | Description                  | Support                                                 |
|---------|------------------------------|---------------------------------------------------------|
| Encode  | JWT Encoder                  | Secret based /Key based / Algorithm / Custom Header     |
| Decode  | JWT Decoder                  | Algorithm, Issued At Check                              |
| Crack   | Secret Cracker               | Dictionary Attack / Brute Force                         |
| Payload | JWT Attack Payload Generator | none / jku&x5u / alg_confusion / kid_sql / x5c / cty    |

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

## Contribute

Urx is open-source project and made it with ❤️
if you want contribute this project, please see [CONTRIBUTING.md](./CONTRIBUTING.md) and Pull-Request with cool your contents.

[![](https://raw.githubusercontent.com/hahwul/jwt-hack/refs/heads/main/CONTRIBUTORS.svg)](https://github.com/hahwul/jwt-hack/graphs/contributors)
