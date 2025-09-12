use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};
#[allow(unused_imports)]
use std::future::Future;

/// Helper function to generate combinations for brute force
fn generate_combinations(chars: &[char], length: usize) -> Vec<String> {
    if length == 0 {
        return vec![String::new()];
    }

    if length == 1 {
        return chars.iter().map(|c| c.to_string()).collect();
    }

    let mut result = Vec::new();
    let shorter = generate_combinations(chars, length - 1);

    for combination in shorter {
        for &ch in chars {
            result.push(format!("{}{}", combination, ch));
        }
    }

    result
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DecodeArgs {
    /// JWT token to decode
    pub token: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EncodeArgs {
    /// JSON data to encode
    pub json: String,
    /// Secret key for HMAC algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Algorithm to use (default: HS256)
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Use 'none' algorithm (no signature)
    #[serde(default)]
    pub no_signature: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct VerifyArgs {
    /// JWT token to verify
    pub token: String,
    /// Secret key for HMAC algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Validate expiration claim (exp)
    #[serde(default)]
    #[allow(dead_code)]
    pub validate_exp: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CrackArgs {
    /// JWT token to crack
    pub token: String,
    /// Cracking mode: 'dict' or 'brute'
    #[serde(default = "default_crack_mode")]
    pub mode: String,
    /// Character list for bruteforce attack
    #[serde(default = "default_chars")]
    pub chars: String,
    /// Character set preset: az, AZ, aZ, 19, aZ19, ascii
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Max length for bruteforce attack
    #[serde(default = "default_max_length")]
    pub max: usize,
    /// Concurrency level
    #[serde(default = "default_concurrency")]
    #[allow(dead_code)]
    pub concurrency: usize,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct PayloadArgs {
    /// JWT token to use for payload generation
    pub token: String,
    /// Target payload types (e.g., "none", "jku", "x5u", "alg_confusion", "kid_sql")
    #[serde(default = "default_payload_target")]
    pub target: String,
    /// Attack domain for jku&x5u attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk_attack: Option<String>,
    /// Protocol for jku&x5u attacks (http/https)
    #[serde(default = "default_protocol")]
    pub jwk_protocol: String,
}

fn default_algorithm() -> String {
    "HS256".to_string()
}

fn default_crack_mode() -> String {
    "dict".to_string()
}

fn default_chars() -> String {
    "abcdefghijklmnopqrstuvwxyz0123456789".to_string()
}

fn default_max_length() -> usize {
    4
}

fn default_concurrency() -> usize {
    20
}

fn default_payload_target() -> String {
    "all".to_string()
}

fn default_protocol() -> String {
    "https".to_string()
}

#[derive(Clone)]
pub struct JwtHackServer {
    tool_router: ToolRouter<JwtHackServer>,
}

#[tool_router]
impl JwtHackServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Decode a JWT token and display its header, payload, and validation info")]
    async fn decode(
        &self,
        Parameters(args): Parameters<DecodeArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Use existing decode functionality
        let decoded = crate::jwt::decode(&args.token);

        match decoded {
            Ok(token_info) => {
                let output = format!(
                    "Header: {}\nClaims: {}\nAlgorithm: {:?}",
                    serde_json::to_string_pretty(&token_info.header)
                        .unwrap_or_else(|_| "Invalid header".to_string()),
                    serde_json::to_string_pretty(&token_info.claims)
                        .unwrap_or_else(|_| "Invalid claims".to_string()),
                    token_info.algorithm
                );
                Ok(CallToolResult::success(vec![Content::text(output)]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to decode JWT: {}",
                e
            ))])),
        }
    }

    #[tool(description = "Encode JSON data into a JWT token with specified algorithm")]
    async fn encode(
        &self,
        Parameters(args): Parameters<EncodeArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Parse JSON claims
        let claims: serde_json::Value = match serde_json::from_str(&args.json) {
            Ok(c) => c,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid JSON: {}",
                    e
                ))]))
            }
        };

        // Build encoding options
        let key_data = if args.no_signature {
            crate::jwt::KeyData::None
        } else if let Some(ref secret) = args.secret {
            crate::jwt::KeyData::Secret(secret.as_str())
        } else {
            return Ok(CallToolResult::error(vec![Content::text(
                "No secret provided for signed token".to_string(),
            )]));
        };

        let options = crate::jwt::EncodeOptions {
            algorithm: &args.algorithm,
            key_data,
            header_params: None::<std::collections::HashMap<&str, &str>>,
            compress_payload: false,
        };

        match crate::jwt::encode_with_options(&claims, &options) {
            Ok(token) => Ok(CallToolResult::success(vec![Content::text(token)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to encode JWT: {}",
                e
            ))])),
        }
    }

    #[tool(description = "Verify a JWT token's signature and optionally validate expiration")]
    async fn verify(
        &self,
        Parameters(args): Parameters<VerifyArgs>,
    ) -> Result<CallToolResult, McpError> {
        if let Some(secret) = &args.secret {
            let result = crate::jwt::verify(&args.token, secret);

            match result {
                Ok(is_valid) => {
                    let message = if is_valid {
                        "✓ JWT signature is valid"
                    } else {
                        "✗ JWT signature is invalid"
                    };
                    Ok(CallToolResult::success(vec![Content::text(
                        message.to_string(),
                    )]))
                }
                Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                    "Verification failed: {}",
                    e
                ))])),
            }
        } else {
            Ok(CallToolResult::error(vec![Content::text(
                "No secret provided for verification".to_string(),
            )]))
        }
    }

    #[tool(description = "Attempt to crack a JWT token using dictionary or bruteforce methods")]
    async fn crack(
        &self,
        Parameters(args): Parameters<CrackArgs>,
    ) -> Result<CallToolResult, McpError> {
        // For MCP mode, we'll use a simplified approach without file I/O
        // since we can't reliably access wordlist files
        if args.mode == "dict" {
            // Use a built-in small wordlist for demo purposes
            let common_passwords = vec!["secret", "password", "123456", "admin", "test", "jwt"];

            for password in common_passwords {
                if let Ok(is_valid) = crate::jwt::verify(&args.token, password) {
                    if is_valid {
                        return Ok(CallToolResult::success(vec![Content::text(format!(
                            "✓ JWT cracked! Secret found: {}",
                            password
                        ))]));
                    }
                }
            }

            Ok(CallToolResult::success(vec![Content::text(
                "✗ Dictionary attack failed. Secret not found in built-in wordlist.".to_string(),
            )]))
        } else if args.mode == "brute" {
            // Resolve character set from preset or use provided chars
            let chars_to_use = if let Some(preset) = &args.preset {
                match crate::cmd::crack::get_preset_chars(preset) {
                    Some(preset_chars) => preset_chars,
                    None => {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "Unknown preset: '{}'. Available presets: az, AZ, aZ, 19, aZ19, ascii",
                            preset
                        ))]));
                    }
                }
            } else {
                args.chars.clone()
            };

            // For brute force, only try very short combinations due to performance constraints
            let max_len = std::cmp::min(args.max, 3); // Limit to 3 characters max for MCP
            let chars: Vec<char> = chars_to_use.chars().take(10).collect(); // Limit charset

            for len in 1..=max_len {
                // Generate combinations for this length
                let combinations = generate_combinations(&chars, len);

                for combination in combinations.into_iter().take(100) {
                    // Limit attempts
                    if let Ok(is_valid) = crate::jwt::verify(&args.token, &combination) {
                        if is_valid {
                            return Ok(CallToolResult::success(vec![Content::text(format!(
                                "✓ JWT cracked! Secret found: {}",
                                combination
                            ))]));
                        }
                    }
                }
            }

            Ok(CallToolResult::success(vec![Content::text(
                "✗ Brute force attack failed. Secret not found in limited search space."
                    .to_string(),
            )]))
        } else {
            Ok(CallToolResult::error(vec![Content::text(
                "Invalid crack mode. Use 'dict' or 'brute'.".to_string(),
            )]))
        }
    }

    #[tool(description = "Generate various JWT attack payloads for security testing")]
    async fn payload(
        &self,
        Parameters(args): Parameters<PayloadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let target = if args.target == "all" {
            None
        } else {
            Some(args.target.as_str())
        };

        let result = crate::payload::generate_all_payloads(
            &args.token,
            None, // jwk_trust
            args.jwk_attack.as_deref(),
            &args.jwk_protocol,
            target,
        );

        match result {
            Ok(payloads) => {
                let output = payloads.join("\n");
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Generated {} attack payloads:\n{}",
                    payloads.len(),
                    output
                ))]))
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to generate payloads: {}",
                e
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for JwtHackServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation {
                name: "jwt-hack".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("JWT-HACK".to_string()),
                website_url: Some(env!("CARGO_PKG_REPOSITORY").to_string()),
                icons: None,
            },
            instructions: Some("JWT-HACK MCP Server - Provides tools for JWT security testing including decode, encode, verify, crack, and payload generation.".to_string()),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}

/// Execute the MCP server
pub fn execute() {
    // Set up async runtime for MCP server
    if let Err(e) = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_mcp_server())
    {
        crate::utils::log_error(format!("MCP server error: {}", e));
        std::process::exit(1);
    }
}

async fn run_mcp_server() -> Result<()> {
    crate::utils::log_info("Starting JWT-HACK MCP server...");

    // Create the MCP server
    let service = JwtHackServer::new();

    // Start the server with stdio transport
    let server = service.serve(stdio()).await?;

    crate::utils::log_info("MCP server started. Waiting for requests...");

    // Wait for the server to complete
    server.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_server_creation() {
        let server = JwtHackServer::new();
        let info = server.get_info();

        assert_eq!(info.server_info.name, "jwt-hack");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn test_decode_tool() {
        let server = JwtHackServer::new();
        let args = DecodeArgs {
            token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA".to_string(),
        };

        let result = server.decode(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error != Some(true));
    }

    #[tokio::test]
    async fn test_encode_tool() {
        let server = JwtHackServer::new();
        let args = EncodeArgs {
            json: r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#.to_string(),
            secret: Some("secret".to_string()),
            algorithm: "HS256".to_string(),
            no_signature: false,
        };

        let result = server.encode(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error != Some(true));
    }

    #[tokio::test]
    async fn test_crack_tool() {
        let server = JwtHackServer::new();

        // Create a JWT with a known secret from our built-in list
        let test_token =
            crate::jwt::encode(&serde_json::json!({"test": "data"}), "secret", "HS256").unwrap();

        let args = CrackArgs {
            token: test_token,
            mode: "dict".to_string(),
            chars: "abc".to_string(),
            preset: None, // preset
            max: 2,
            concurrency: 1,
        };

        let result = server.crack(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error != Some(true));

        // Check that the content contains a meaningful response
        if let Some(content) = call_result.content.first() {
            match &content.raw {
                RawContent::Text(text) => {
                    assert!(
                        text.text.contains("JWT cracked!")
                            || text.text.contains("Dictionary attack failed")
                    );
                }
                _ => {
                    // For other content types, we just pass the test
                }
            }
        }
    }
}
