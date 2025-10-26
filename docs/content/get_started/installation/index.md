---
title: "Installation"
weight: 1
---

JWT-HACK can be installed in several ways, depending on your preference and environment.

## From Cargo

If you have Rust and Cargo installed, you can install JWT-HACK directly from [crates.io](https://crates.io/crates/jwt-hack):

```bash
cargo install jwt-hack
```

## From Homebrew

For macOS users, JWT-HACK is available via Homebrew:

```bash
brew install jwt-hack
```

## From Snapcraft (Ubuntu)

For Ubuntu users, JWT-HACK is available via Snap:

```bash
sudo snap install jwt-hack
```

## From Source

To build JWT-HACK from source, you'll need to have Rust and Cargo installed:

```bash
git clone https://github.com/hahwul/jwt-hack
cd jwt-hack
cargo install --path .
```

## From Docker

JWT-HACK is also available as Docker images:

### GitHub Container Registry
```bash
docker pull ghcr.io/hahwul/jwt-hack:latest
```

### Docker Hub
```bash
docker pull hahwul/jwt-hack:v2.4.0
```

## Verification

Once installed, verify that JWT-HACK is working correctly:

```bash
jwt-hack --version
```

You should see the version information and the JWT-HACK banner displayed.
