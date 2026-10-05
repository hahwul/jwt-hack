+++
toc = true
title = "shell"
weight = 8
+++

`jwt-hack shell` is an interactive TUI where you set a token and secret once and then run `decode`, `verify`, `crack` and the rest against them without retyping the token each time.

```bash
jwt-hack shell
```

It takes over the terminal (alternate screen, raw mode) and restores it on exit, including after a crash. The prompt shows the active algorithm and whether a token is loaded:

```
jwt-hack(HS256)[---]> set token eyJhbGciOiJIUzI1NiJ9...
jwt-hack(HS256)[JWT]>
```

## Session state

`set <key> <value>` stores a value for the rest of the session. The stored token and secret feed every command that needs them.

| Key | Used by |
| --- | --- |
| `token` | decode, verify, crack, payload, scan (when you don't pass one inline) |
| `secret` | encode, verify |
| `algorithm` | encode, and the prompt indicator |
| `private_key` | encode, verify (path to a PEM key) |
| `wordlist` | crack, scan (path to a dictionary file) |

`show` prints the current session. The secret is masked as `****` and never shown in full.

## Commands

| Command | Argument | What it does |
| --- | --- | --- |
| `set` | `<key> <value>` | Store a session value |
| `decode` | `[token]` | Decode the token (inline or from the session) |
| `encode` | `<json>` | Sign JSON claims with the session secret/key and algorithm |
| `verify` | `[token]` | Verify the token against the session secret or key |
| `crack` | `[token]` | Dictionary-crack the token using the session wordlist |
| `payload` | `[token]` | Generate attack payloads for the token |
| `scan` | `[token]` | Run the vulnerability checks against the token |
| `show` | | Print session state |
| `clear` | | Clear the output pane |
| `help` | | List commands and examples |
| `exit` / `quit` | | Leave the shell |

A short workflow:

```
set token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc
set secret hunter2
decode
verify
```

`crack` and `scan` run on a background thread, one at a time, so the shell stays responsive during a long dictionary run. While one is running, starting another reports that it is busy; wait for the result and retry. `crack` here is dictionary-only and pulls candidates from the session `wordlist`.

## Keys and completion

Tab completes commands, `set` keys, and algorithm names after `set algorithm`. When more than one candidate matches, Tab cycles forward and Shift+Tab backward; Esc cancels.

| Key | Action |
| --- | --- |
| Tab / Shift+Tab | Complete and cycle candidates |
| Up / Down | Walk command history |
| PgUp / PgDn | Scroll the output pane |
| Left / Right, Home / End | Move the cursor |
| Backspace / Delete | Delete a character |
| Ctrl+A / Ctrl+E | Jump to start / end of the line |
| Ctrl+U | Clear the input line |
| Ctrl+W | Delete the previous word |
| Ctrl+C | Exit |

## History

Command history persists to `shell_history` in the jwt-hack config directory (`$XDG_CONFIG_HOME/jwt-hack/` when that is set to an absolute path, otherwise the platform config dir, for example `~/.config/jwt-hack/` on Linux or `~/Library/Application Support/jwt-hack/` on macOS). It keeps the last 1000 entries and drops consecutive duplicates.

`set secret ...` and `set private_key ...` are never written to the history file, so a secret you type does not end up in plaintext on disk. The output pane is capped at 5000 lines so a long session doesn't grow memory without bound.
