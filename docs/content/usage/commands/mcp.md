+++
toc = true
title = "mcp"
weight = 10
+++

`jwt-hack mcp` runs jwt-hack as a Model Context Protocol server over stdio, so an MCP client such as Claude Desktop or Claude Code can call its JWT tools during a conversation.

```bash
jwt-hack mcp
```

There is no port. The client launches `jwt-hack mcp` as a subprocess and talks to it over stdin/stdout, so running it by hand in a terminal just waits for MCP messages and looks like it hangs. That is expected. The implementation uses the `rmcp` crate and speaks protocol version `2024-11-05`.

## Tools

The server advertises five tools. Note this is a subset of the CLI: there is no `jwks`, `scan` or `server` tool here.

| Tool | Parameters |
| --- | --- |
| `decode` | `token` |
| `encode` | `json`, `secret`, `algorithm` (default `HS256`), `no_signature` (default false) |
| `verify` | `token`, `secret`, `validate_exp` (default false) |
| `crack` | `token`, `mode` (default `dict`), `chars`, `preset`, `min` (default 1), `max` (default 4) |
| `payload` | `token`, `target` (default `all`), `jwk_attack`, `jwk_protocol` (default `https`), `public_key` |

A few behaviors worth knowing before you wire this up:

- `encode` requires a `secret` unless `no_signature` is true, in which case it emits an `alg:none` token.
- `verify` requires a `secret`. If the token is `alg:none` and you pass a non-empty secret, it is reported invalid rather than accepted, matching the CLI and REST surfaces.
- `crack` in `dict` mode does no file I/O; it tries jwt-hack's built-in common-secret list. `brute` mode is deliberately capped for interactive use: length 3 max, charset truncated to 10 characters, 100 attempts per length. Presets are `az`, `AZ`, `aZ`, `19`, `aZ19`, `ascii`.
- `payload` with `public_key` accepts a PEM literal or a file path and forges an RS256-to-HS256 confusion token. `jwk_trust` is not exposed here.

## Wiring it into a client

The command is the same everywhere: run `jwt-hack mcp` as a stdio subprocess. Make sure `jwt-hack` is on the `PATH` the client uses, or give an absolute path.

Claude Code, from the project root:

```bash
claude mcp add jwt-hack -- jwt-hack mcp
```

Claude Desktop, in `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "jwt-hack": {
      "command": "jwt-hack",
      "args": ["mcp"]
    }
  }
}
```

Any other MCP client takes the same two pieces, a command and its args. After connecting, have the client list tools; it should report `decode`, `encode`, `verify`, `crack` and `payload`.

## Example call

An MCP `tools/call` for `decode` looks like this:

```json
{
  "method": "tools/call",
  "params": {
    "name": "decode",
    "arguments": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
  }
}
```

The server returns the result as text content, for example the decoded header, claims and algorithm. Everything runs locally as a subprocess of the client, so tokens are never sent to a network service.
