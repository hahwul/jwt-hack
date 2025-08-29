<div align="center">
  <picture>
    <img alt="JWT-HACK Logo" src="https://raw.githubusercontent.com/hahwul/jwt-hack/refs/heads/main/images/logo.png" width="260px;">
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

### Cargo
```bash
cargo install jwt-hack
```

### Homebrew
```bash
brew install jwt-hack
```

### Snapcraft (Ubuntu)

```bash
sudo snap install jwt-hack
```

### From source
```bash
git clone https://github.com/hahwul/jwt-hack
cd jwt-hack
cargo install --path .
```

### Docker images
#### GHCR
```bash
docker pull ghcr.io/hahwul/jwt-hack:latest
```

#### Docker Hub
```bash
docker pull hahwul/jwt-hack:v2.2.0
```

## Features

| Mode    | Description                  | Support                                                      |
|---------|------------------------------|--------------------------------------------------------------|
| Encode  | JWT/JWE Encoder              | Secret based / Key based / Algorithm / Custom Header / DEFLATE Compression / JWE |
| Decode  | JWT/JWE Decoder              | Algorithm, Issued At Check, DEFLATE Compression, JWE Structure |
| Verify  | JWT Verifier                 | Secret based / Key based (for asymmetric algorithms)         |
| Crack   | Secret Cracker               | Dictionary Attack / Brute Force / DEFLATE Compression        |
| Payload | JWT Attack Payload Generator | none / jku&x5u / alg_confusion / kid_sql / x5c / cty         |
| MCP     | Model Context Protocol Server | AI model integration via standardized protocol               |

## Basic Usage

### Decode a JWT

You can decode both regular and DEFLATE-compressed JWTs. The tool will automatically detect and decompress compressed tokens.

```bash
jwt-hack decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.CHANGED
jwt-hack decode COMPRESSED_JWT_TOKEN
```

### Decode a JWE

Decode JWE (JSON Web Encryption) tokens to analyze their structure. The tool automatically detects JWE format (5 parts) and displays the encryption details.

```bash
# Decode JWE token structure
jwt-hack decode eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..ZHVtbXlfaXZfMTIzNDU2.eyJ0ZXN0IjoiandlIn0.ZHVtbXlfdGFn

# Shows JWE header, encrypted key, IV, ciphertext, and authentication tag
```

### Encode a JWT

```bash
jwt-hack encode '{"sub":"1234"}' --secret=your-secret
```

#### Encode a JWT with DEFLATE Compression

You can use the `--compress` option to apply DEFLATE compression to the JWT payload.

```bash
jwt-hack encode '{"sub":"1234"}' --secret=your-secret --compress
```

# With Private Key
ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P "" -f RS256.key
jwt-hack encode '{"a":"z"}' --private-key RS256.key --algorithm=RS256
```

### Encode a JWE

Create JWE (JSON Web Encryption) tokens for testing encrypted JWT scenarios.

```bash
# Basic JWE encoding
jwt-hack encode '{"sub":"1234", "data":"encrypted"}' --jwe --secret=your-secret

# JWE tokens are encrypted and can only be decrypted with the proper key
jwt-hack encode '{"sensitive":"data"}' --jwe
```

### Verify a JWT

Checks if a JWT's signature is valid using the provided secret or key.

```bash
# With Secret (HMAC algorithms like HS256, HS384, HS512)
jwt-hack verify YOUR_JWT_TOKEN_HERE --secret=your-256-bit-secret

# With Private Key (for asymmetric algorithms like RS256, ES256, EdDSA)
jwt-hack verify YOUR_JWT_TOKEN_HERE --private-key path/to/your/RS256_private.key
```

### Crack a JWT

Dictionary and brute force attacks also support JWTs compressed with DEFLATE.

```bash
# Dictionary attack
jwt-hack crack -w wordlist.txt JWT_TOKEN
jwt-hack crack -w wordlist.txt COMPRESSED_JWT_TOKEN

# Bruteforce attack
jwt-hack crack -m brute JWT_TOKEN --max=4
jwt-hack crack -m brute COMPRESSED_JWT_TOKEN --max=4
```

### Generate payloads

```bash
jwt-hack payload JWT_TOKEN --jwk-attack evil.com --jwk-trust trusted.com
```

### MCP (Model Context Protocol) Server Mode

jwt-hack can run as an MCP server, allowing AI models to interact with JWT functionality through a standardized protocol.

```bash
# Start MCP server (communicates via stdio)
jwt-hack mcp
```

The MCP server exposes the following tools:

| Tool | Description | Parameters |
|------|-------------|------------|
| `decode` | Decode JWT tokens | `token` (string) |
| `encode` | Encode JSON to JWT | `json` (string), `secret` (optional), `algorithm` (default: HS256), `no_signature` (boolean) |
| `verify` | Verify JWT signatures | `token` (string), `secret` (optional), `validate_exp` (boolean) |
| `crack` | Crack JWT tokens | `token` (string), `mode` (dict/brute), `chars` (string), `max` (number) |
| `payload` | Generate attack payloads | `token` (string), `target` (string), `jwk_attack` (optional), `jwk_protocol` (default: https) |

#### Example MCP Usage

The MCP server is designed to be used by AI models and MCP clients. Each tool accepts JSON parameters and returns structured responses.

**Decode Tool:**
```json
{
  "name": "decode",
  "arguments": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Encode Tool:**
```json
{
  "name": "encode",
  "arguments": {
    "json": "{\"sub\":\"1234\",\"name\":\"test\"}",
    "secret": "mysecret",
    "algorithm": "HS256"
  }
}
```

#### MCP Client Integration Examples

You can connect jwt-hack’s MCP server to popular MCP-enabled clients. Make sure the `jwt-hack` binary is on your system and accessible by the client.

**VSCode**

```json
{
  "servers": {
    "jwt-hack": {
      "type": "stdio",
      "command": "jwt-hack",
      "args": [
        "mcp"
      ]
    }
  },
  "inputs": []
}
```

**Claude Desktop**

```json
{
  "mcpServers": {
    "jwt-hack": {
      "command": "jwt-hack",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

## DEFLATE Compression Support

> **DEFLATE Compression Support**
> The `jwt-hack` toolkit supports DEFLATE compression for JWTs.
> - Use the `--compress` option with `encode` to generate compressed JWTs.
> - The `decode` and `crack` modes automatically detect and handle compressed JWTs.

## Contribute

Urx is open-source project and made it with ❤️
if you want contribute this project, please see [CONTRIBUTING.md](./CONTRIBUTING.md) and Pull-Request with cool your contents.

[![](https://raw.githubusercontent.com/hahwul/jwt-hack/refs/heads/main/CONTRIBUTORS.svg)](https://github.com/hahwul/jwt-hack/graphs/contributors)
