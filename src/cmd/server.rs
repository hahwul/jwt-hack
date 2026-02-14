use axum::{
    extract::{Json, State},
    http::StatusCode,
    middleware::from_fn_with_state,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use tower_http::cors::{Any, CorsLayer};

use crate::{crack, jwt, payload, utils};

/// Request/Response structures for API endpoints
#[derive(Debug, Deserialize, Serialize)]
pub struct DecodeRequest {
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DecodeResponse {
    pub success: bool,
    pub header: Option<serde_json::Map<String, Value>>,
    pub payload: Option<Value>,
    pub algorithm: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncodeRequest {
    pub payload: Value,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub no_signature: bool,
    #[serde(default)]
    pub headers: Option<Vec<(String, String)>>,
    #[serde(default)]
    pub compress: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncodeResponse {
    pub success: bool,
    pub token: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyRequest {
    pub token: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub validate_exp: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyResponse {
    pub success: bool,
    pub valid: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CrackRequest {
    pub token: String,
    #[serde(default = "default_crack_mode")]
    pub mode: String,
    #[serde(default)]
    pub wordlist: Option<String>,
    #[serde(default = "default_crack_chars")]
    pub chars: String,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_max_length")]
    pub max: usize,
}

fn default_crack_mode() -> String {
    "dict".to_string()
}

fn default_crack_chars() -> String {
    "abcdefghijklmnopqrstuvwxyz0123456789".to_string()
}

fn default_concurrency() -> usize {
    20
}

fn default_max_length() -> usize {
    4
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CrackResponse {
    pub success: bool,
    pub secret: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadRequest {
    pub token: String,
    #[serde(default)]
    pub jwk_trust: Option<String>,
    #[serde(default)]
    pub jwk_attack: Option<String>,
    #[serde(default = "default_jwk_protocol")]
    pub jwk_protocol: String,
    #[serde(default)]
    pub target: Option<String>,
}

fn default_jwk_protocol() -> String {
    "https".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadResponse {
    pub success: bool,
    pub payloads: Option<Vec<PayloadItem>>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PayloadItem {
    pub name: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanRequest {
    pub token: String,
    #[serde(default)]
    pub skip_crack: bool,
    #[serde(default)]
    pub skip_payloads: bool,
    #[serde(default)]
    pub wordlist: Option<String>,
    #[serde(default = "default_max_crack_attempts")]
    pub max_crack_attempts: usize,
}

fn default_max_crack_attempts() -> usize {
    100
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanResponse {
    pub success: bool,
    pub vulnerabilities: Option<Vec<String>>,
    pub secret: Option<String>,
    pub error: Option<String>,
}

/// Custom error type for API responses
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "success": false,
            "error": self.message
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        }
    }
}

/// Decode endpoint handler
async fn handle_decode(Json(req): Json<DecodeRequest>) -> Result<Json<DecodeResponse>, ApiError> {
    match jwt::decode(&req.token) {
        Ok(decoded) => {
            let header_map: serde_json::Map<String, Value> = decoded.header.into_iter().collect();

            Ok(Json(DecodeResponse {
                success: true,
                header: Some(header_map),
                payload: Some(decoded.claims),
                algorithm: Some(format!("{:?}", decoded.algorithm)),
                error: None,
            }))
        }
        Err(e) => Ok(Json(DecodeResponse {
            success: false,
            header: None,
            payload: None,
            algorithm: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Encode endpoint handler
async fn handle_encode(Json(req): Json<EncodeRequest>) -> Result<Json<EncodeResponse>, ApiError> {
    let algorithm = req.algorithm.as_deref().unwrap_or("HS256");
    let headers = req.headers.unwrap_or_default();

    let options = jwt::EncodeOptions {
        algorithm,
        key_data: if req.no_signature {
            jwt::KeyData::None
        } else {
            jwt::KeyData::Secret(req.secret.as_deref().unwrap_or(""))
        },
        header_params: if !headers.is_empty() {
            let mut map = std::collections::HashMap::new();
            for (k, v) in &headers {
                map.insert(k.as_str(), v.as_str());
            }
            Some(map)
        } else {
            None
        },
        compress_payload: req.compress,
    };

    match jwt::encode_with_options(&req.payload, &options) {
        Ok(token) => Ok(Json(EncodeResponse {
            success: true,
            token: Some(token),
            error: None,
        })),
        Err(e) => Ok(Json(EncodeResponse {
            success: false,
            token: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Verify endpoint handler
async fn handle_verify(Json(req): Json<VerifyRequest>) -> Result<Json<VerifyResponse>, ApiError> {
    let options = jwt::VerifyOptions {
        key_data: jwt::VerifyKeyData::Secret(req.secret.as_deref().unwrap_or("")),
        validate_exp: req.validate_exp,
        validate_nbf: false,
        leeway: 0,
    };

    match jwt::verify_with_options(&req.token, &options) {
        Ok(valid) => Ok(Json(VerifyResponse {
            success: true,
            valid: Some(valid),
            error: None,
        })),
        Err(e) => Ok(Json(VerifyResponse {
            success: false,
            valid: Some(false),
            error: Some(e.to_string()),
        })),
    }
}

/// Helper function to crack JWT using dictionary attack
fn crack_dict(token: &str, wordlist_path: &PathBuf) -> anyhow::Result<Option<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);

    for word in reader.lines().map_while(Result::ok) {
        if let Ok(true) = jwt::verify(token, &word) {
            return Ok(Some(word));
        }
    }

    Ok(None)
}

/// Helper function to crack JWT using brute force
fn crack_brute(token: &str, chars: &str, max_length: usize) -> anyhow::Result<Option<String>> {
    // Generate all combinations up to max_length
    let payloads = crack::generate_bruteforce_payloads(chars, max_length);

    for word in payloads {
        if let Ok(true) = jwt::verify(token, &word) {
            return Ok(Some(word));
        }
    }

    Ok(None)
}

/// Crack endpoint handler
async fn handle_crack(Json(req): Json<CrackRequest>) -> Result<Json<CrackResponse>, ApiError> {
    let mode = req.mode.to_lowercase();

    // For API, we need to handle cracking without blocking too long
    let result = match mode.as_str() {
        "dict" => {
            if let Some(wordlist_path) = req.wordlist {
                let path = PathBuf::from(wordlist_path);
                crack_dict(&req.token, &path)
            } else {
                return Ok(Json(CrackResponse {
                    success: false,
                    secret: None,
                    error: Some("Wordlist path required for dictionary attack".to_string()),
                }));
            }
        }
        "brute" => {
            let charset = if let Some(preset) = &req.preset {
                match preset.as_str() {
                    "az" => "abcdefghijklmnopqrstuvwxyz",
                    "AZ" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    "aZ" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                    "19" => "0123456789",
                    "aZ19" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    "ascii" => " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                    _ => &req.chars,
                }
            } else {
                &req.chars
            };
            crack_brute(&req.token, charset, req.max)
        }
        _ => {
            return Ok(Json(CrackResponse {
                success: false,
                secret: None,
                error: Some(format!("Invalid mode: {}. Use 'dict' or 'brute'", mode)),
            }));
        }
    };

    match result {
        Ok(Some(secret)) => Ok(Json(CrackResponse {
            success: true,
            secret: Some(secret),
            error: None,
        })),
        Ok(None) => Ok(Json(CrackResponse {
            success: true,
            secret: None,
            error: Some("Secret not found".to_string()),
        })),
        Err(e) => Ok(Json(CrackResponse {
            success: false,
            secret: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Payload endpoint handler
async fn handle_payload(
    Json(req): Json<PayloadRequest>,
) -> Result<Json<PayloadResponse>, ApiError> {
    let target = req.target.as_deref();

    match payload::generate_all_payloads(
        &req.token,
        req.jwk_trust.as_deref(),
        req.jwk_attack.as_deref(),
        &req.jwk_protocol,
        target,
    ) {
        Ok(payloads) => {
            let payload_items: Vec<PayloadItem> = payloads
                .into_iter()
                .enumerate()
                .map(|(i, token)| PayloadItem {
                    name: format!("Payload #{}", i + 1),
                    token,
                })
                .collect();

            Ok(Json(PayloadResponse {
                success: true,
                payloads: Some(payload_items),
                error: None,
            }))
        }
        Err(e) => Ok(Json(PayloadResponse {
            success: false,
            payloads: None,
            error: Some(e.to_string()),
        })),
    }
}

/// Scan endpoint handler
async fn handle_scan(Json(req): Json<ScanRequest>) -> Result<Json<ScanResponse>, ApiError> {
    let mut vulnerabilities = Vec::new();
    let mut found_secret = None;

    // Perform basic token analysis
    match jwt::decode(&req.token) {
        Ok(decoded) => {
            // Check for weak algorithm
            if let Some(alg) = decoded.header.get("alg") {
                if let Some(alg_str) = alg.as_str() {
                    if alg_str.to_uppercase() == "NONE" {
                        vulnerabilities.push("Uses 'none' algorithm (unsigned token)".to_string());
                    }
                }
            }

            // Check for expired tokens
            if let Some(exp) = decoded.claims.get("exp") {
                if let Some(exp_val) = exp.as_i64() {
                    let now = chrono::Utc::now().timestamp();
                    if exp_val < now {
                        vulnerabilities.push("Token is expired".to_string());
                    }
                }
            }
        }
        Err(_) => {
            vulnerabilities.push("Invalid token format".to_string());
        }
    }

    // Try to crack if not skipped
    if !req.skip_crack {
        if let Some(wordlist_path) = &req.wordlist {
            let path = PathBuf::from(wordlist_path);
            if let Ok(Some(secret)) = crack_dict(&req.token, &path) {
                vulnerabilities.push(format!("Weak secret found: {}", secret));
                found_secret = Some(secret);
            }
        }
    }

    Ok(Json(ScanResponse {
        success: true,
        vulnerabilities: Some(vulnerabilities),
        secret: found_secret,
        error: None,
    }))
}

/// Health check endpoint
async fn handle_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Middleware to enforce optional API key header
async fn api_key_middleware(
    State(expected_key): State<Option<String>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    if let Some(expected) = expected_key.as_deref() {
        let provided = req.headers().get("X-API-KEY").and_then(|v| v.to_str().ok());
        if provided != Some(expected) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": "Unauthorized"
                })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Build and configure the router
fn build_router(api_key: Option<String>) -> Router {
    // Configure CORS to allow requests from any origin
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        .route("/health", post(handle_health).get(handle_health))
        .route("/decode", post(handle_decode))
        .route("/encode", post(handle_encode))
        .route("/verify", post(handle_verify))
        .route("/crack", post(handle_crack))
        .route("/payload", post(handle_payload))
        .route("/scan", post(handle_scan))
        .layer(cors);

    // Attach API key authentication middleware (no-op if api_key is None)
    router.layer(from_fn_with_state(api_key, api_key_middleware))
}

/// Execute the server command
pub async fn execute(host: &str, port: u16) {
    utils::log_info("Starting JWT-HACK REST API server".to_string());
    utils::log_info(format!("Listening on http://{}:{}", host, port));
    utils::log_info("Available endpoints:".to_string());
    utils::log_info("  POST /health      - Health check".to_string());
    utils::log_info("  POST /decode      - Decode JWT token".to_string());
    utils::log_info("  POST /encode      - Encode JWT token".to_string());
    utils::log_info("  POST /verify      - Verify JWT token".to_string());
    utils::log_info("  POST /crack       - Crack JWT secret".to_string());
    utils::log_info("  POST /payload     - Generate attack payloads".to_string());
    utils::log_info("  POST /scan        - Scan JWT for vulnerabilities".to_string());

    let app = build_router(None);
    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    utils::log_success(format!("Server started successfully on {}", addr));

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}

pub async fn execute_with_api_key(host: &str, port: u16, api_key: &str) {
    utils::log_info("Starting JWT-HACK REST API server".to_string());
    utils::log_info(format!("Listening on http://{}:{}", host, port));
    utils::log_info("Available endpoints:".to_string());
    utils::log_info("  POST /health      - Health check".to_string());
    utils::log_info("  POST /decode      - Decode JWT token".to_string());
    utils::log_info("  POST /encode      - Encode JWT token".to_string());
    utils::log_info("  POST /verify      - Verify JWT token".to_string());
    utils::log_info("  POST /crack       - Crack JWT secret".to_string());
    utils::log_info("  POST /payload     - Generate attack payloads".to_string());
    utils::log_info("  POST /scan        - Scan JWT for vulnerabilities".to_string());
    utils::log_info("API key protection enabled (header: X-API-KEY)".to_string());

    let app = build_router(Some(api_key.to_string()));
    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    utils::log_success(format!("Server started successfully on {}", addr));

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_crack_mode() {
        assert_eq!(default_crack_mode(), "dict");
    }

    #[test]
    fn test_default_crack_chars() {
        assert_eq!(
            default_crack_chars(),
            "abcdefghijklmnopqrstuvwxyz0123456789"
        );
    }

    #[test]
    fn test_default_concurrency() {
        assert_eq!(default_concurrency(), 20);
    }

    #[test]
    fn test_default_max_length() {
        assert_eq!(default_max_length(), 4);
    }

    #[test]
    fn test_default_jwk_protocol() {
        assert_eq!(default_jwk_protocol(), "https");
    }

    #[test]
    fn test_default_max_crack_attempts() {
        assert_eq!(default_max_crack_attempts(), 100);
    }

    #[tokio::test]
    async fn test_handle_decode_valid_token() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let req = DecodeRequest {
            token: token.to_string(),
        };

        let result = handle_decode(Json(req)).await;
        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert!(response.success);
        assert!(response.header.is_some());
        assert!(response.payload.is_some());
    }

    #[tokio::test]
    async fn test_handle_decode_invalid_token() {
        let req = DecodeRequest {
            token: "invalid.token".to_string(),
        };

        let result = handle_decode(Json(req)).await;
        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert!(!response.success);
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_handle_encode_with_secret() {
        let req = EncodeRequest {
            payload: serde_json::json!({"sub": "test"}),
            secret: Some("test_secret".to_string()),
            algorithm: Some("HS256".to_string()),
            no_signature: false,
            headers: None,
            compress: false,
        };

        let result = handle_encode(Json(req)).await;
        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert!(response.success);
        assert!(response.token.is_some());
    }

    #[tokio::test]
    async fn test_handle_verify_correct_secret() {
        // First encode a token
        let token =
            jwt::encode(&serde_json::json!({"sub": "test"}), "test_secret", "HS256").unwrap();

        let req = VerifyRequest {
            token,
            secret: Some("test_secret".to_string()),
            validate_exp: false,
        };

        let result = handle_verify(Json(req)).await;
        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert!(response.success);
        assert_eq!(response.valid, Some(true));
    }

    #[tokio::test]
    async fn test_handle_health() {
        let result = handle_health().await;
        let json = result.0;
        assert_eq!(json["status"], "ok");
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_api_key_middleware_unauthorized() {
        use axum::{body::Body, http::Request};
        use tower::Service;

        let mut app = build_router(Some("testkey".to_string()));

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let res = Service::call(&mut app, req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_middleware_authorized() {
        use axum::{body::Body, http::Request};
        use tower::Service;

        let mut app = build_router(Some("testkey".to_string()));

        let mut req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        req.headers_mut()
            .insert("X-API-KEY", "testkey".parse().unwrap());

        let res = Service::call(&mut app, req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn test_crack_dict_found() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let secret = "secret123";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "wrong_secret").unwrap();
        writeln!(file, "secret123").unwrap();
        writeln!(file, "another_wrong").unwrap();

        let path = file.path().to_path_buf();
        let result = crack_dict(&token, &path);

    fn test_crack_brute_success() {
        let secret = "ab";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        let result = crack_brute(&token, "abc", 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(secret.to_string()));
    }

    #[test]
    fn test_crack_dict_not_found() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let secret = "secret123";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "wrong_secret").unwrap();
        writeln!(file, "another_wrong").unwrap();

        let path = file.path().to_path_buf();
        let result = crack_dict(&token, &path);

    fn test_crack_brute_failure() {
        let secret = "ab";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        let result = crack_brute(&token, "cde", 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_crack_dict_file_error() {
        let token = "some_token";
        let path = PathBuf::from("/non/existent/file/path");
        let result = crack_dict(token, &path);

        assert!(result.is_err());
    fn test_crack_brute_length_limit() {
        let secret = "abc";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        // Max length is 2, secret is length 3
        let result = crack_brute(&token, "abc", 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }
}
