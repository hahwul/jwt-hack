+++
toc = true
title = "MCP Server Mode"
weight = 6
+++

The `mcp` command runs JWT-HACK as a Model Context Protocol (MCP) server for AI model integration.

## Basic Usage

```bash
jwt-hack mcp
```

## What is MCP?

Model Context Protocol (MCP) is a standardized protocol that enables AI models to interact with external tools and services. When JWT-HACK runs in MCP mode, it exposes its JWT analysis capabilities to AI models through a structured interface.

## Starting the MCP Server

```bash
# Start the MCP server (communicates over stdio)
jwt-hack mcp

# The server will:
# - Speak the MCP protocol over stdin/stdout (stdio transport)
# - Expose JWT-HACK functionality as MCP tools
# - Process requests from an MCP-capable client
# - Return structured responses
```

The server uses the **stdio transport** — it reads requests from stdin and writes
responses to stdout. It is not a network server, so there is no port to configure;
an MCP client launches `jwt-hack mcp` as a subprocess and communicates over the pipe.

## Available MCP Tools

When running as an MCP server, JWT-HACK exposes these five tools:

- **decode** - Decode a JWT token and display its header, payload, and validation info
- **encode** - Encode JSON data into a JWT token with a specified algorithm
- **verify** - Verify a JWT token's signature and optionally validate expiration
- **crack** - Attempt to crack a JWT token using dictionary or bruteforce methods
- **payload** - Generate various JWT attack payloads for security testing

## Integration Examples

An MCP-capable client (such as a Claude or other agentic tool that supports MCP)
can call these tools during a conversation:

```
User: "Analyze this JWT token for security vulnerabilities"
Client: Calls the `decode`, `verify`, and `payload` tools on the JWT-HACK MCP server
Client: Receives structured results and summarizes them
```

Any client or framework that speaks MCP over stdio can connect to the server.

## MCP Protocol Features

### Structured Requests
```json
{
  "method": "tools/call",
  "params": {
    "name": "decode",
    "arguments": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

### Structured Responses
The server returns the tool result as structured MCP content, for example the
decoded header, payload, and algorithm for the `decode` tool.

## Configuration

### Client Configuration
Configure your MCP client to launch the JWT-HACK MCP server as a subprocess:

```json
{
  "mcp_servers": {
    "jwt-hack": {
      "command": "jwt-hack",
      "args": ["mcp"],
      "description": "JWT security analysis and testing"
    }
  }
}
```

## Use Cases

### Automated Security Analysis
AI models can perform comprehensive JWT security analysis:

1. **Token Analysis** - Decode and examine token structure
2. **Vulnerability Detection** - Identify security weaknesses
3. **Attack Vector Generation** - Create targeted test payloads
4. **Report Generation** - Summarize findings and recommendations

### Interactive Security Testing
Enable conversational security testing:

```
User: "Is this JWT token secure?"
AI + MCP: Analyzes token, identifies issues, suggests improvements
User: "Show me attack payloads for testing"
AI + MCP: Generates and explains relevant attack vectors
```

### Automated Penetration Testing
Integrate into automated testing workflows:
- **CI/CD Pipelines** - Analyze JWTs in automated tests
- **Security Scanners** - Add JWT analysis capabilities
- **Monitoring Systems** - Continuous JWT security assessment

## Benefits of MCP Integration

### For AI Models
- Access to specialized JWT security expertise
- Structured, reliable security analysis
- Real-time vulnerability assessment
- Consistent security recommendations

### For Security Teams
- Natural language interaction with security tools
- Automated analysis and reporting
- Integration with existing AI workflows
- Scalable security testing

## Technical Details

### Protocol Compliance
JWT-HACK's MCP server implements:
- The **Model Context Protocol** (built on the `rmcp` crate)
- **JSON-RPC 2.0** message format
- **stdio** transport layer (stdin/stdout)
- **Tool discovery** and capability advertisement

### Performance Characteristics
- **Low latency** - Fast response times for analysis
- **Concurrent requests** - Handle multiple AI model connections
- **Resource efficient** - Minimal memory and CPU overhead
- **Scalable** - Support for high-volume analysis

## Troubleshooting

Because the server uses the stdio transport, it is normally launched and managed
by the MCP client rather than run by hand. If you run `jwt-hack mcp` directly in a
terminal, it will wait for MCP messages on stdin and appear to "hang" — this is
expected. Common checks:

- Confirm the client is configured to launch `jwt-hack mcp` as a subprocess (see
  the client configuration above).
- Ensure `jwt-hack` is on the `PATH` the client uses.
- Verify the tool is discoverable by having the client list available tools; it
  should report `decode`, `encode`, `verify`, `crack`, and `payload`.

## Security Considerations

### Access Control
- The MCP server runs locally as a subprocess of the client (stdio transport)
- It does not open a network port, so it is only reachable by the launching client

### Data Privacy
- JWT tokens are processed locally
- No data transmitted to external services
- Full control over sensitive token analysis
