---
title: "MCP Server Mode"
weight: 6
---

The `mcp` command runs JWT-HACK as a Model Context Protocol (MCP) server for AI model integration.

## Basic Usage

```bash
jwt-hack mcp
```

## What is MCP?

Model Context Protocol (MCP) is a standardized protocol that enables AI models to interact with external tools and services. When JWT-HACK runs in MCP mode, it exposes its JWT analysis capabilities to AI models through a structured interface.

## Starting the MCP Server

```bash
# Start MCP server on default port
jwt-hack mcp

# The server will:
# - Listen for MCP connections
# - Expose JWT-HACK functionality as MCP tools
# - Process requests from AI models
# - Return structured responses
```

## Available MCP Tools

When running as an MCP server, JWT-HACK exposes these tools to AI models:

### JWT Analysis Tools
- **decode-jwt** - Decode and analyze JWT tokens
- **verify-jwt** - Verify JWT signatures
- **crack-jwt** - Attempt to crack JWT secrets
- **generate-payloads** - Create attack payloads

### Security Testing Tools
- **analyze-vulnerabilities** - Identify potential security issues
- **generate-reports** - Create security assessment reports
- **test-algorithms** - Test algorithm-specific vulnerabilities

## Integration Examples

### With OpenAI Models
AI models can request JWT analysis through the MCP protocol:

```
AI Model Request: "Analyze this JWT token for security vulnerabilities"
MCP Server: Executes decode, verify, and payload generation
AI Model: Receives structured analysis results
```

### With Local AI Models
Compatible with local AI frameworks that support MCP:
- **Ollama** with MCP plugins
- **LangChain** MCP integration
- **Custom AI applications** using MCP protocol

## MCP Protocol Features

### Structured Requests
```json
{
  "method": "tools/call",
  "params": {
    "name": "decode-jwt",
    "arguments": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
  }
}
```

### Structured Responses
```json
{
  "result": {
    "algorithm": "HS256",
    "header": {"alg": "HS256", "typ": "JWT"},
    "payload": {"sub": "1234", "name": "John Doe"},
    "vulnerabilities": ["weak_secret_suspected"],
    "recommendations": ["Use stronger secrets", "Enable expiration"]
  }
}
```

## Configuration

### Server Configuration
The MCP server can be configured through environment variables:

```bash
# Set custom port
export MCP_PORT=8080
jwt-hack mcp

# Enable debug logging
export MCP_DEBUG=true
jwt-hack mcp

# Set custom timeout
export MCP_TIMEOUT=30
jwt-hack mcp
```

### AI Model Configuration
Configure your AI model to connect to the JWT-HACK MCP server:

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
- **MCP 1.0 specification** compliance
- **JSON-RPC 2.0** message format
- **WebSocket** transport layer
- **Tool discovery** and capability advertisement

### Performance Characteristics
- **Low latency** - Fast response times for analysis
- **Concurrent requests** - Handle multiple AI model connections
- **Resource efficient** - Minimal memory and CPU overhead
- **Scalable** - Support for high-volume analysis

## Troubleshooting

### Connection Issues
```bash
# Check if MCP server is running
netstat -ln | grep :8080

# Test MCP connection manually
curl -X POST http://localhost:8080/mcp

# Enable debug logging
MCP_DEBUG=true jwt-hack mcp
```

### AI Model Integration
```bash
# Verify AI model can discover tools
# Check MCP protocol compatibility
# Validate request/response formats
```

## Development and Extensions

### Custom MCP Tools
The MCP server architecture allows for extending JWT-HACK with custom tools:

```rust
// Example: Add custom JWT analysis tool
impl McpTool for CustomJwtAnalyzer {
    fn name(&self) -> &str { "custom-analysis" }
    fn execute(&self, args: Value) -> Result<Value> {
        // Custom JWT analysis logic
    }
}
```

### Protocol Extensions
- Custom error handling
- Extended metadata support
- Streaming responses for long operations
- Batch processing capabilities

## Security Considerations

### Access Control
- MCP server runs locally by default
- Consider network security for remote access
- Implement authentication for production use

### Data Privacy
- JWT tokens are processed locally
- No data transmitted to external services
- Full control over sensitive token analysis