+++
toc = true
title = "Commands"
weight = 1
sort_by = "weight"
+++

Every `jwt-hack` subcommand, and the global flags that apply to all of them.

## Commands

- [decode](/usage/commands/decode/) - decode a JWT or JWE and show header, payload, and timestamp info
- [encode](/usage/commands/encode/) - build a JWT (or JWE) from a JSON payload and sign it
- [verify](/usage/commands/verify/) - check a signature, optionally validate `exp`
- [crack](/usage/commands/crack/) - recover an HMAC secret by dictionary or brute force
- [payload](/usage/commands/payload/) - generate attack payloads (none, alg confusion, kid injection, and more)
- [scan](/usage/commands/scan/) - run heuristic vulnerability checks against a token
- [jwks](/usage/commands/jwks/) - fetch, spoof, verify, and rotation-test JWKS endpoints
- [shell](/usage/commands/shell/) - interactive REPL for JWT operations
- [server](/usage/commands/server/) - run a REST API for the same operations
- [mcp](/usage/commands/mcp/) - run as a Model Context Protocol server
- `version` - print version, author, repo, and license

## Structure

```bash
jwt-hack <command> [OPTIONS] <ARGUMENTS>
jwt-hack <command> --help
```

## Global flags

These work on every command.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | off | Emit a JSON object to stdout instead of the formatted view. Use it for pipelines and scripting. |
| `--config <CONFIG>` | platform config dir | Path to a TOML config file. Without it, `jwt-hack` reads `$XDG_CONFIG_HOME/jwt-hack/config.toml` (or the OS equivalent) if present. |

The config file sets defaults that commands fall back to: `default_secret`, `default_algorithm`, `default_wordlist`, and `default_private_key`.

```toml
default_algorithm = "HS256"
default_secret = "my-secret"
default_wordlist = "/usr/share/wordlists/rockyou.txt"
```
