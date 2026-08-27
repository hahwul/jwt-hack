+++
toc = true
title = "Environment Variables"
weight = 1
+++

Environment variables that affect JWT-HACK behavior.

## Available Environment Variables

### `XDG_CONFIG_HOME`

Overrides the base directory used to locate the configuration file. When set,
JWT-HACK looks for its config at `$XDG_CONFIG_HOME/jwt-hack/config.toml`. When
unset, it falls back to the platform default config directory (see
[Configuration](/usage/configuration)).

```bash
export XDG_CONFIG_HOME="$HOME/.config"
# jwt-hack now reads ~/.config/jwt-hack/config.toml
```

### `JWT_HACK_WORDLIST_DIR`

Used only by the [`server`](/usage/commands/server) command. Server-side wordlist
**file paths** (the `wordlist` field in `/crack` and `/scan` requests) are
disabled by default; clients are expected to send inline wordlists via
`wordlist_content`. Setting `JWT_HACK_WORDLIST_DIR` to a directory re-enables
path-based wordlists, but only for files that resolve inside that directory —
paths outside it are rejected.

```bash
export JWT_HACK_WORDLIST_DIR=/opt/wordlists
jwt-hack server
# /crack and /scan may now reference wordlist files under /opt/wordlists
```

## Notes

- There are no environment variables for setting the default secret, algorithm,
  wordlist, or private key. Those are configured through the
  [configuration file](/usage/configuration) or per-command flags.
- The path to the configuration file itself is set with the global `--config`
  flag, not an environment variable.
