+++
title = "Commands"
weight = 1
sort_by = "weight"

[extra]
+++

JWT-HACK provides a comprehensive set of commands for JWT security testing and analysis. Each command is designed for specific tasks in the JWT testing workflow.

## Available Commands

- **[decode](/usage/commands/decode)** - Decode and analyze JWT/JWE tokens
- **[encode](/usage/commands/encode)** - Create JWT tokens with custom payloads
- **[verify](/usage/commands/verify)** - Verify JWT signatures and expiration
- **[crack](/usage/commands/crack)** - Crack JWT secrets using dictionary or brute force
- **[payload](/usage/commands/payload)** - Generate attack payloads for security testing
- **[scan](/usage/commands/scan)** - Scan for JWT vulnerabilities
- **[server](/usage/commands/server)** - Run JWT-HACK as an API server
- **[mcp](/usage/commands/mcp)** - Model Context Protocol server mode

## Command Structure

All commands follow a consistent structure:

```bash
jwt-hack <command> [OPTIONS] <ARGUMENTS>
```

Get help for any command:

```bash
jwt-hack <command> --help
```
