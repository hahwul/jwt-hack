+++
toc = true
title = "Configuration"
weight = 3
+++

A config file lets you set defaults so you stop retyping the same secret, algorithm, wordlist, or key path. Command-line flags always win over the file, and the file is optional: skip it and everything still works from flags.

## Where it lives

`jwt-hack` looks for `config.toml` in the platform config directory:

- **Linux**: `~/.config/jwt-hack/config.toml` (or `$XDG_CONFIG_HOME/jwt-hack/config.toml`)
- **macOS**: `~/Library/Application Support/jwt-hack/config.toml`
- **Windows**: `%APPDATA%\jwt-hack\config.toml`

Setting `XDG_CONFIG_HOME` to an absolute path moves the base directory on any platform. Point at a file somewhere else with the global `--config` flag:

```bash
jwt-hack --config ./project/config.toml decode "$TOKEN"
```

## Keys

The file is flat TOML. Every key is optional, and these four are the only ones it reads:

| Key | Type | Used as the default for |
| --- | --- | --- |
| `default_secret` | string | `--secret` (HMAC) |
| `default_algorithm` | string | `--algorithm` on `encode` |
| `default_wordlist` | string | `-w` on `crack` and `scan` |
| `default_private_key` | string | `--private-key` (asymmetric algorithms) |

```toml
default_secret = "my-default-secret"
default_algorithm = "HS256"
default_wordlist = "/usr/share/wordlists/rockyou.txt"
default_private_key = "~/.ssh/jwt-private.pem"
```

Anything else in the file is ignored. There are no `[wordlists]`, `[keys]`, or `[performance]` sections.

`default_algorithm` accepts HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, or EdDSA.

## How a value is chosen

Highest to lowest: command-line flag, then the config file, then the built-in default.

```bash
# default_secret = "config-secret" in the file

jwt-hack encode '{"sub":"1234"}' --secret=cli-secret   # uses cli-secret
jwt-hack encode '{"sub":"1234"}'                        # uses config-secret
```

## Notes

- A secret in `default_secret` sits in plain text on disk. If that matters, leave it out and pass `--secret` per command. There is no `default_secret_file` key. `chmod 600` the file either way.
- The file is parsed as TOML at startup. Bad syntax exits with a "Failed to parse config file" error that names the file. Algorithm names and key or wordlist paths are not checked until the command that needs them runs.
- Defaults come only from this file or from flags. No environment variable sets them. The two env vars `jwt-hack` does read are covered in [Environment Variables](/reference/environment-variables/).
