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
    /// Inline wordlist (one secret per entry). Preferred over `wordlist` in server
    /// mode so clients never need the server to open a server-side file path.
    #[serde(default)]
    pub wordlist_content: Option<Vec<String>>,
    /// Server-side wordlist file path. Only honored when it resolves inside the
    /// directory named by the `JWT_HACK_WORDLIST_DIR` env var (otherwise rejected).
    #[serde(default)]
    pub wordlist: Option<String>,
    #[serde(default = "default_crack_chars")]
    pub chars: String,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_min_length")]
    pub min: usize,
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

fn default_min_length() -> usize {
    1
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
    #[serde(default)]
    pub public_key: Option<String>,
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
    /// Inline wordlist (one secret per entry); preferred over `wordlist`.
    #[serde(default)]
    pub wordlist_content: Option<Vec<String>>,
    /// Server-side wordlist file path, gated by `JWT_HACK_WORDLIST_DIR` (see CrackRequest).
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
            // Read the real `alg` before consuming `header`; `decoded.algorithm`
            // is an HS256 sentinel for `none`/`ES512`/unrepresentable values.
            let algorithm = decoded.alg_str();
            let header_map: serde_json::Map<String, Value> = decoded.header.into_iter().collect();

            Ok(Json(DecodeResponse {
                success: true,
                header: Some(header_map),
                payload: Some(decoded.claims),
                algorithm: Some(algorithm),
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
    // `no_signature` means an unsigned alg:none token. The algorithm must be
    // forced to "none" (as the CLI does); leaving it at the requested/default
    // algorithm while passing KeyData::None makes encode_with_options fail with
    // "No key or secret provided".
    let algorithm = if req.no_signature {
        "none"
    } else {
        req.algorithm.as_deref().unwrap_or("HS256")
    };
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
    // A 'none' token carries no signature. If the caller supplied a (non-empty)
    // secret, reporting it as valid would silently ignore that secret — the classic
    // alg:none bypass — so report it as invalid instead.
    if req
        .secret
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        if let Ok(decoded) = jwt::decode(&req.token) {
            let is_none = decoded
                .header
                .get("alg")
                .and_then(|v| v.as_str())
                .map(|a| a.eq_ignore_ascii_case("none"))
                .unwrap_or(false);
            if is_none {
                return Ok(Json(VerifyResponse {
                    success: true,
                    valid: Some(false),
                    error: Some(
                        "Token uses 'none' algorithm and carries no signature; cannot be verified against the provided secret".to_string(),
                    ),
                }));
            }
        }
    }

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

/// Maximum wordlist size (bytes) the server will read for a dictionary attack.
/// Bounds memory/time and prevents pointing the endpoint at huge or special files.
const MAX_WORDLIST_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Bounds how many crack/scan operations run concurrently. `spawn_blocking` already
/// keeps a single crack off the async runtime, but without this cap a burst of
/// requests could still occupy many blocking threads and saturate CPU. Excess
/// requests wait asynchronously for a permit instead of piling on.
static CRACK_LIMITER: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Where a dictionary attack draws its candidate secrets from.
enum WordlistSource {
    /// Candidates sent inline in the request body.
    Inline(Vec<String>),
    /// An allow-list-validated server-side file path.
    Path(PathBuf),
}

impl WordlistSource {
    /// Run the dictionary attack for this source (intended for a blocking thread).
    fn crack(self, token: &str) -> anyhow::Result<Option<String>> {
        match self {
            WordlistSource::Inline(words) => Ok(crack_words(token, words)),
            WordlistSource::Path(path) => crack_dict(token, &path),
        }
    }
}

/// Resolve the dictionary source from a request: inline content is preferred, then a
/// gated file path. Returns `Ok(None)` when neither was supplied.
fn wordlist_source(
    content: Option<Vec<String>>,
    path: Option<&String>,
) -> anyhow::Result<Option<WordlistSource>> {
    if let Some(words) = content {
        Ok(Some(WordlistSource::Inline(words)))
    } else if let Some(path) = path {
        Ok(Some(WordlistSource::Path(resolve_wordlist_path(path)?)))
    } else {
        Ok(None)
    }
}

/// Try each candidate secret against the token, returning the first that verifies.
fn crack_words<I: IntoIterator<Item = String>>(token: &str, words: I) -> Option<String> {
    words
        .into_iter()
        .find(|word| matches!(jwt::verify(token, word), Ok(true)))
}

/// Resolve a client-supplied wordlist path against the operator-configured allow-list.
///
/// In server mode the path originates from a remote request body, so opening an
/// arbitrary path would be an unauthenticated file-read primitive. We only honor
/// paths that canonicalize to a location inside `JWT_HACK_WORDLIST_DIR` (which also
/// defeats `..` traversal and symlink escapes). If the env var is unset, server-side
/// paths are disabled entirely and clients must send `wordlist_content` inline.
fn resolve_wordlist_path(requested: &str) -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("JWT_HACK_WORDLIST_DIR").ok_or_else(|| {
        anyhow::anyhow!(
            "server-side wordlist file paths are disabled; send `wordlist_content` inline, \
             or set JWT_HACK_WORDLIST_DIR to an allowed directory to enable path-based wordlists"
        )
    })?;
    let base = std::fs::canonicalize(&base)
        .map_err(|e| anyhow::anyhow!("JWT_HACK_WORDLIST_DIR is not accessible: {}", e))?;
    let candidate = std::fs::canonicalize(PathBuf::from(requested))
        .map_err(|e| anyhow::anyhow!("wordlist path is not accessible: {}", e))?;
    if !candidate.starts_with(&base) {
        anyhow::bail!("wordlist path is outside the allowed directory");
    }
    Ok(candidate)
}

/// Helper function to crack JWT using a dictionary file (already allow-list validated).
fn crack_dict(token: &str, wordlist_path: &PathBuf) -> anyhow::Result<Option<String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read};

    // Reject non-regular files (directories, devices like /dev/zero, FIFOs) and
    // oversized files so the endpoint can't be turned into a blocking/DoS file reader.
    let metadata = std::fs::metadata(wordlist_path)?;
    if !metadata.is_file() {
        anyhow::bail!("wordlist path is not a regular file");
    }
    if metadata.len() > MAX_WORDLIST_BYTES {
        anyhow::bail!(
            "wordlist file is too large ({} bytes, limit {} bytes)",
            metadata.len(),
            MAX_WORDLIST_BYTES
        );
    }

    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file).take(MAX_WORDLIST_BYTES);

    // `split(b'\n')` reads raw bytes, so a non-UTF-8 line is lossy-decoded into a
    // candidate rather than terminating the iterator early (as `lines()` +
    // `map_while(Result::ok)` did, silently skipping the rest of the wordlist). The
    // outer `.take(MAX_WORDLIST_BYTES)` bounds total bytes read.
    let words = reader.split(b'\n').map_while(Result::ok).map(|line| {
        String::from_utf8_lossy(&line)
            .trim_end_matches('\r')
            .to_string()
    });
    Ok(crack_words(token, words))
}

/// Helper function to crack JWT using brute force
fn crack_brute(
    token: &str,
    chars: &str,
    min_length: usize,
    max_length: usize,
) -> anyhow::Result<Option<String>> {
    if min_length < 1 {
        anyhow::bail!("min length must be at least 1, got {}", min_length);
    }
    if min_length > max_length {
        anyhow::bail!(
            "min length ({}) cannot exceed max length ({})",
            min_length,
            max_length
        );
    }
    if max_length > crack::brute::MAX_BRUTE_LENGTH {
        anyhow::bail!(
            "max length {} exceeds supported brute-force limit of {}",
            max_length,
            crack::brute::MAX_BRUTE_LENGTH
        );
    }

    // Bound the total keyspace a single HTTP request can enumerate. The per-length
    // cap above does NOT bound runtime (e.g. a 62-char charset at length 8 is ~2e14
    // candidates), which would pin a worker for an unbounded time. Reject requests
    // whose keyspace exceeds a ceiling that still responds promptly.
    const MAX_BRUTE_CANDIDATES: u128 = 5_000_000;
    let charset_size = chars.chars().count() as u128;
    let mut total: u128 = 0;
    for length in min_length..=max_length {
        total = total.saturating_add(charset_size.saturating_pow(length as u32));
        if total > MAX_BRUTE_CANDIDATES {
            anyhow::bail!(
                "requested brute-force keyspace is too large for the server endpoint \
                 (charset {} chars, lengths {}-{} exceed the {} candidate ceiling)",
                charset_size,
                min_length,
                max_length,
                MAX_BRUTE_CANDIDATES
            );
        }
    }

    // Stream combinations chunk by chunk instead of loading all into memory
    const CHUNK_SIZE: usize = 10000;
    for length in min_length..=max_length {
        for chunk in crack::brute::generate_combinations_chunked(chars, length, CHUNK_SIZE) {
            for word in chunk {
                if let Ok(true) = jwt::verify(token, &word) {
                    return Ok(Some(word));
                }
            }
        }
    }

    Ok(None)
}

/// Crack endpoint handler
async fn handle_crack(Json(req): Json<CrackRequest>) -> Result<Json<CrackResponse>, ApiError> {
    // Limit concurrent crack work across all requests (released when this handler returns).
    let _permit = CRACK_LIMITER.acquire().await.map_err(|e| ApiError {
        status: StatusCode::SERVICE_UNAVAILABLE,
        message: format!("crack limiter unavailable: {e}"),
    })?;

    // Run the synchronous, CPU/IO-bound crack on a blocking thread so it cannot pin
    // a Tokio worker and starve /health and every other endpoint (request DoS).
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<String>> {
        let mode = req.mode.to_lowercase();
        match mode.as_str() {
            "dict" => match wordlist_source(req.wordlist_content, req.wordlist.as_ref())? {
                Some(source) => source.crack(&req.token),
                None => anyhow::bail!(
                    "Dictionary attack requires `wordlist_content` (inline) or `wordlist` (path)"
                ),
            },
            "brute" => {
                let charset: String = if let Some(preset) = &req.preset {
                    match preset.as_str() {
                        "az" => "abcdefghijklmnopqrstuvwxyz".to_string(),
                        "AZ" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
                        "aZ" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
                        "19" => "0123456789".to_string(),
                        "aZ19" => {
                            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                                .to_string()
                        }
                        "ascii" => " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~".to_string(),
                        _ => req.chars.clone(),
                    }
                } else {
                    req.chars.clone()
                };
                crack_brute(&req.token, &charset, req.min, req.max)
            }
            other => anyhow::bail!("Invalid mode: {}. Use 'dict' or 'brute'", other),
        }
    })
    .await
    .map_err(|e| ApiError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: format!("crack task failed: {e}"),
    })?;

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
        req.public_key.as_deref(),
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

            // Check for expired tokens. Read the NumericDate with a float-aware
            // helper (RFC 7519 §2) so a valid float `exp` isn't silently skipped.
            if let Some(exp_val) = decoded
                .claims
                .get("exp")
                .and_then(utils::numeric_date_seconds)
            {
                let now = chrono::Utc::now().timestamp();
                if exp_val < now {
                    vulnerabilities.push("Token is expired".to_string());
                }
            }
        }
        Err(_) => {
            vulnerabilities.push("Invalid token format".to_string());
        }
    }

    // Try to crack if not skipped. Offload to a blocking thread so the dictionary
    // read/verify loop does not block the async runtime.
    if !req.skip_crack {
        let source = match wordlist_source(req.wordlist_content.clone(), req.wordlist.as_ref()) {
            Ok(source) => source,
            Err(e) => {
                vulnerabilities.push(format!("Wordlist rejected: {}", e));
                None
            }
        };
        if let Some(source) = source {
            let _permit = CRACK_LIMITER.acquire().await.map_err(|e| ApiError {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: format!("crack limiter unavailable: {e}"),
            })?;
            let token = req.token.clone();
            let crack_result = tokio::task::spawn_blocking(move || source.crack(&token))
                .await
                .map_err(|e| ApiError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: format!("scan crack task failed: {e}"),
                })?;
            if let Ok(Some(secret)) = crack_result {
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
        // Constant-time comparison to avoid leaking how many leading bytes match
        // via response timing (a byte-by-byte key-recovery side channel).
        let authorized = provided
            .map(|p| crate::utils::constant_time_eq(p.as_bytes(), expected.as_bytes()))
            .unwrap_or(false);
        if !authorized {
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

/// Bind the server's TCP listener. Returns a clean `io::Error` instead of
/// panicking so the caller can report the common "address already in use" /
/// invalid-address cases without a backtrace.
async fn bind_listener(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await
}

/// Bind `addr` and serve `app`. Bind and serve failures are reported as clean
/// error lines and exit non-zero, replacing the previous `.expect(...)` panics
/// (which, under the release profile's `panic = "abort"`, printed a Rust panic +
/// backtrace note for an everyday "port already in use" situation).
async fn serve_app(app: Router, addr: &str) {
    let listener = match bind_listener(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            utils::log_error(format!("Failed to bind to {addr}: {e}"));
            std::process::exit(1);
        }
    };

    utils::log_success(format!("Server started successfully on {}", addr));

    if let Err(e) = axum::serve(listener, app).await {
        utils::log_error(format!("Server error: {e}"));
        std::process::exit(1);
    }
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
    serve_app(app, &addr).await;
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
    serve_app(app, &addr).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    async fn test_handle_encode_no_signature_produces_none_token() {
        // no_signature must yield an unsigned alg:none token, not an error. The
        // handler previously kept algorithm=HS256 while passing KeyData::None, so
        // encoding failed with "No key or secret provided".
        let req = EncodeRequest {
            payload: serde_json::json!({"sub": "test"}),
            secret: None,
            algorithm: None,
            no_signature: true,
            headers: None,
            compress: false,
        };

        let response = handle_encode(Json(req)).await.unwrap().0;
        assert!(
            response.success,
            "no_signature encode failed: {:?}",
            response.error
        );
        let token = response.token.expect("token");
        let decoded = jwt::decode(&token).expect("decode none token");
        assert_eq!(
            decoded.header.get("alg").and_then(|v| v.as_str()),
            Some("none"),
            "no_signature must emit alg:none"
        );
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
    async fn test_bind_listener_ok_on_ephemeral_port() {
        // Binding an ephemeral port succeeds and yields a real local address.
        let listener = bind_listener("127.0.0.1:0")
            .await
            .expect("ephemeral bind should succeed");
        assert!(listener.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_bind_listener_reports_error_instead_of_panicking() {
        // Re-binding an already-bound address must return Err (which serve_app turns
        // into a clean error line) rather than panic as the old `.expect` did.
        let first = bind_listener("127.0.0.1:0")
            .await
            .expect("first bind should succeed");
        let addr = first.local_addr().expect("addr");
        let second = bind_listener(&addr.to_string()).await;
        assert!(
            second.is_err(),
            "re-binding an in-use port must error, not panic"
        );
    }

    #[tokio::test]
    async fn test_bind_listener_rejects_invalid_address() {
        // A malformed host:port must surface as an error, never a panic.
        let result = bind_listener("not a valid addr").await;
        assert!(result.is_err());
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
    fn test_crack_brute_success() {
        let secret = "ab";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        let result = crack_brute(&token, "abc", 1, 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(secret.to_string()));
    }

    #[test]
    fn test_crack_brute_failure() {
        let secret = "ab";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        let result = crack_brute(&token, "cde", 1, 3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_crack_brute_length_limit() {
        let secret = "abc";
        let token = jwt::encode(&serde_json::json!({"sub": "test"}), secret, "HS256").unwrap();

        // Max length is 2, secret is length 3
        let result = crack_brute(&token, "abc", 1, 2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_wordlist_source_prefers_inline() {
        // Inline content wins and never touches the filesystem or the env allow-list.
        let path = "/etc/passwd".to_string();
        let src = wordlist_source(Some(vec!["a".to_string()]), Some(&path)).unwrap();
        assert!(matches!(src, Some(WordlistSource::Inline(_))));
        // Neither source supplied -> no crack source.
        assert!(wordlist_source(None, None).unwrap().is_none());
    }

    #[tokio::test]
    async fn test_handle_crack_inline_wordlist() {
        let token = jwt::encode(&serde_json::json!({"sub": "x"}), "letmein", "HS256").unwrap();
        let req = CrackRequest {
            token,
            mode: "dict".to_string(),
            wordlist_content: Some(vec![
                "nope".to_string(),
                "letmein".to_string(),
                "other".to_string(),
            ]),
            wordlist: None,
            chars: default_crack_chars(),
            preset: None,
            concurrency: 1,
            min: 1,
            max: 4,
        };
        let resp = handle_crack(Json(req)).await.unwrap().0;
        assert!(resp.success);
        assert_eq!(resp.secret.as_deref(), Some("letmein"));
    }

    // ---- Router-level endpoint tests (mock HTTP requests through build_router) ----

    /// Drive a mock request through the full router and return (status, json body).
    async fn call_router(
        app: &mut Router,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        use axum::body::Body;
        use axum::http::Request;
        use tower::Service;

        let builder = Request::builder().method(method).uri(uri);
        let req = match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        };

        let res = Service::call(app, req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn test_router_health_endpoint() {
        let mut app = build_router(None);
        let (status, body) = call_router(&mut app, "GET", "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn test_router_decode_endpoint() {
        let mut app = build_router(None);
        let token = jwt::encode(
            &serde_json::json!({"sub": "1234", "name": "Jane"}),
            "s",
            "HS256",
        )
        .unwrap();
        let (status, body) =
            call_router(&mut app, "POST", "/decode", Some(json!({"token": token}))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);
        assert_eq!(body["payload"]["name"], "Jane");
    }

    #[tokio::test]
    async fn test_router_encode_then_verify_roundtrip() {
        let mut app = build_router(None);

        // Encode
        let (status, body) = call_router(
            &mut app,
            "POST",
            "/encode",
            Some(json!({"payload": {"sub": "abc"}, "secret": "topsecret", "algorithm": "HS256"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);
        let token = body["token"].as_str().expect("token").to_string();

        // Verify (correct secret)
        let (status, body) = call_router(
            &mut app,
            "POST",
            "/verify",
            Some(json!({"token": token, "secret": "topsecret"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], true);

        // Verify (wrong secret)
        let (_status, body) = call_router(
            &mut app,
            "POST",
            "/verify",
            Some(json!({"token": token, "secret": "nope"})),
        )
        .await;
        assert_eq!(body["valid"], false);
    }

    #[tokio::test]
    async fn test_router_crack_brute_endpoint() {
        let mut app = build_router(None);
        let token = jwt::encode(&serde_json::json!({"sub": "x"}), "ab", "HS256").unwrap();
        let (status, body) = call_router(
            &mut app,
            "POST",
            "/crack",
            Some(json!({"token": token, "mode": "brute", "chars": "ab", "min": 1, "max": 3})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);
        assert_eq!(body["secret"], "ab");
    }

    #[tokio::test]
    async fn test_router_crack_dict_inline_endpoint() {
        let mut app = build_router(None);
        let token = jwt::encode(&serde_json::json!({"sub": "x"}), "hunter2", "HS256").unwrap();
        let (status, body) = call_router(
            &mut app,
            "POST",
            "/crack",
            Some(json!({
                "token": token,
                "mode": "dict",
                "wordlist_content": ["foo", "hunter2", "bar"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["secret"], "hunter2");
    }

    #[tokio::test]
    async fn test_router_payload_endpoint() {
        let mut app = build_router(None);
        let token = jwt::encode(&serde_json::json!({"sub": "x"}), "s", "HS256").unwrap();
        let (status, body) = call_router(
            &mut app,
            "POST",
            "/payload",
            Some(json!({"token": token, "target": "none"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);
        assert!(
            body["payloads"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false),
            "expected at least one payload"
        );
    }

    #[tokio::test]
    async fn test_router_scan_endpoint_finds_weak_secret() {
        let mut app = build_router(None);
        let token = jwt::encode(&serde_json::json!({"sub": "x"}), "test", "HS256").unwrap();
        let (status, body) = call_router(
            &mut app,
            "POST",
            "/scan",
            Some(json!({
                "token": token,
                "skip_payloads": true,
                "wordlist_content": ["nope", "test"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], true);
        assert_eq!(body["secret"], "test");
    }

    #[tokio::test]
    async fn test_router_unknown_route_is_404() {
        let mut app = build_router(None);
        let (status, _body) =
            call_router(&mut app, "POST", "/does-not-exist", Some(json!({}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_router_invalid_json_is_client_error() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::Service;

        let mut app = build_router(None);
        let req = Request::builder()
            .method("POST")
            .uri("/decode")
            .header("content-type", "application/json")
            .body(Body::from("this is not json"))
            .unwrap();
        let res = Service::call(&mut app, req).await.unwrap();
        assert!(
            res.status().is_client_error(),
            "malformed JSON should yield a 4xx, got {}",
            res.status()
        );
    }

    #[tokio::test]
    async fn test_router_api_key_gates_endpoints() {
        let mut app = build_router(Some("secret-key".to_string()));

        // Without the key, a normal endpoint is rejected.
        let (status, _b) =
            call_router(&mut app, "POST", "/decode", Some(json!({"token": "a.b.c"}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // With the key, the request is processed.
        use axum::body::Body;
        use axum::http::Request;
        use tower::Service;
        let token = jwt::encode(&serde_json::json!({"sub": "x"}), "s", "HS256").unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/decode")
            .header("content-type", "application/json")
            .header("X-API-KEY", "secret-key")
            .body(Body::from(json!({"token": token}).to_string()))
            .unwrap();
        let res = Service::call(&mut app, req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
