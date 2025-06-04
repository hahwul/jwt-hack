use anyhow::{anyhow, Result};
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::Value;
use std::collections::HashMap;

/// JWT Decoded token data
#[derive(Debug, Clone)]
pub struct DecodedToken {
    pub header: HashMap<String, Value>,
    pub claims: Value,
    pub algorithm: Algorithm,
}

/// Encoding key types for JWT
pub enum KeyData<'a> {
    /// Secret for HMAC algorithms
    Secret(&'a str),
    /// RSA or ECDSA private key in PEM format
    PrivateKeyPem(&'a str),
    /// RSA or ECDSA private key in DER format
    #[allow(dead_code)]
    PrivateKeyDer(&'a [u8]),
    /// No key (for 'none' algorithm)
    None,
}

/// Advanced encode options for JWT token
pub struct EncodeOptions<'a> {
    /// The algorithm to use for signing
    pub algorithm: &'a str,
    /// The key data (secret or private key)
    pub key_data: KeyData<'a>,
    /// Optional header parameters to add
    pub header_params: Option<HashMap<&'a str, &'a str>>,
}

impl<'a> Default for EncodeOptions<'a> {
    fn default() -> Self {
        Self {
            algorithm: "HS256",
            key_data: KeyData::Secret(""),
            header_params: None,
        }
    }
}

/// Encode JSON claims into a JWT token with default options
#[allow(dead_code)]
pub fn encode(claims: &Value, secret: &str, alg_str: &str) -> Result<String> {
    let options = EncodeOptions {
        algorithm: alg_str,
        key_data: KeyData::Secret(secret),
        header_params: None,
    };
    
    encode_with_options(claims, &options)
}

/// Encode JSON claims into a JWT token with advanced options
pub fn encode_with_options(claims: &Value, options: &EncodeOptions) -> Result<String> {
    use std::collections::BTreeMap;
    // Parse algorithm
    let algorithm = match options.algorithm.to_uppercase().as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "NONE" => Algorithm::HS256, // Internally we'll use HS256 but with an empty signature
        _ => return Err(anyhow!("Unsupported algorithm: {}", options.algorithm)),
    };

    // Create header with any additional parameters
    let mut header = Header::new(algorithm);
    if let Some(params) = &options.header_params {
        for (key, value) in params {
            // Add custom headers as additional claims
            match *key {
                "typ" => header.typ = Some(value.to_string()),
                "cty" => header.cty = Some(value.to_string()),
                _ => { /* Other headers will be handled by jsonwebtoken */ }
            }
        }
    }
    
    // Handle "none" algorithm specially
    if options.algorithm.to_uppercase() == "NONE" {
        // For "none", we create the token without a signature
        // For "none" algorithm, we need to create a custom header with "alg":"none"
        let mut header_map = BTreeMap::new();
        header_map.insert("alg".to_string(), Value::String("none".to_string()));
        header_map.insert("typ".to_string(), Value::String("JWT".to_string()));
        
        // Add any additional header parameters
        if let Some(params) = &options.header_params {
            for (key, value) in params {
                header_map.insert(key.to_string(), Value::String(value.to_string()));
            }
        }
        
        let header_json = serde_json::to_string(&header_map)?;
        let claims_json = serde_json::to_string(claims)?;
        
        let encoded_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(header_json.as_bytes());
        let encoded_claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claims_json.as_bytes());
            
        return Ok(format!("{}.{}.''", encoded_header, encoded_claims));
    }

    // Create encoding key based on the key data
    let encoding_key = match &options.key_data {
        KeyData::Secret(secret) => {
            match algorithm {
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                    EncodingKey::from_secret(secret.as_bytes())
                },
                _ => return Err(anyhow!("HMAC algorithms require a secret key"))
            }
        },
        KeyData::PrivateKeyPem(pem) => {
            match algorithm {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 |
                Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                    EncodingKey::from_rsa_pem(pem.as_bytes())?
                },
                Algorithm::ES256 | Algorithm::ES384 => {
                    EncodingKey::from_ec_pem(pem.as_bytes())?
                },
                _ => return Err(anyhow!("Algorithm {:?} not compatible with PEM key", algorithm))
            }
        },
        KeyData::PrivateKeyDer(der) => {
            match algorithm {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 |
                Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                    EncodingKey::from_rsa_der(der)
                },
                Algorithm::ES256 | Algorithm::ES384 => {
                    EncodingKey::from_ec_der(der)
                },
                _ => return Err(anyhow!("Algorithm {:?} not compatible with DER key", algorithm))
            }
        },
        KeyData::None => {
            return Err(anyhow!("No key provided for algorithm {:?}", algorithm))
        }
    };

    // Encode JWT token
    let token = jsonwebtoken::encode(&header, claims, &encoding_key)?;
    Ok(token)
}

/// Decode a JWT token without verifying its signature
pub fn decode(token: &str) -> Result<DecodedToken> {
    // Split the token and handle potential errors
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid token format"));
    }

    // Extract header
    let header_b64 = parts[0];
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| anyhow!("Invalid header encoding"))?;
    let header_str = String::from_utf8(header_bytes)?;
    let header: HashMap<String, Value> = serde_json::from_str(&header_str)?;

    // Extract algorithm
    let alg_value = header
        .get("alg")
        .ok_or_else(|| anyhow!("Missing 'alg' in header"))?;
    let alg_str = alg_value
        .as_str()
        .ok_or_else(|| anyhow!("'alg' is not a string"))?;

    // Parse algorithm
    let algorithm = match alg_str.to_uppercase().as_str() {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "NONE" => Algorithm::HS256, // Treat 'none' as HS256 for parsing
        _ => return Err(anyhow!("Unsupported algorithm: {}", alg_str)),
    };

    // Extract payload (claims)
    let payload_b64 = parts[1];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| anyhow!("Invalid payload encoding"))?;
    let payload_str = String::from_utf8(payload_bytes)?;
    let claims: Value = serde_json::from_str(&payload_str)?;

    Ok(DecodedToken {
        header,
        claims,
        algorithm,
    })
}

/// Verification key types for JWT
pub enum VerifyKeyData<'a> {
    /// Secret for HMAC algorithms
    Secret(&'a str),
    /// RSA or ECDSA public key in PEM format
    #[allow(dead_code)]
    PublicKeyPem(&'a str),
    /// RSA or ECDSA public key in DER format
    #[allow(dead_code)]
    PublicKeyDer(&'a [u8]),
}

/// Advanced verification options for JWT token
pub struct VerifyOptions<'a> {
    /// The key data (secret or public key)
    pub key_data: VerifyKeyData<'a>,
    /// Whether to validate the expiration claim
    pub validate_exp: bool,
    /// Whether to validate the not-before claim
    pub validate_nbf: bool,
    /// Leeway in seconds for time-based claims
    pub leeway: u64,
}

impl<'a> Default for VerifyOptions<'a> {
    fn default() -> Self {
        Self {
            key_data: VerifyKeyData::Secret(""),
            validate_exp: false,
            validate_nbf: false,
            leeway: 0,
        }
    }
}

/// Verify a JWT token with a given secret
pub fn verify(token: &str, secret: &str) -> Result<bool> {
    let options = VerifyOptions {
        key_data: VerifyKeyData::Secret(secret),
        ..Default::default()
    };
    
    verify_with_options(token, &options)
}

/// Verify a JWT token with advanced options
pub fn verify_with_options(token: &str, options: &VerifyOptions) -> Result<bool> {
    // Create validation
    let mut validation = Validation::new(Algorithm::HS256);
    validation.insecure_disable_signature_validation(); // We'll validate manually
    validation.validate_exp = options.validate_exp;
    validation.validate_nbf = options.validate_nbf;
    validation.leeway = options.leeway;

    // Try to decode the token without validation
    let decoded_token = decode(token)?;

    // Handle "none" algorithm specially
    if let Some(alg) = decoded_token.header.get("alg") {
        if let Some(alg_str) = alg.as_str() {
            if alg_str.to_uppercase() == "NONE" {
                // For "none" algorithm, we don't verify any signature
                return Ok(true);
            }
        }
    }

    // Split the token
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 3 {
        return Err(anyhow!("Invalid token format for verification"));
    }

    // Get message and signature parts
    let message = format!("{}.{}", parts[0], parts[1]);
    let signature_b64 = parts[2];
    
    // If signature is empty, it's likely a "none" algorithm token
    if signature_b64.is_empty() {
        return Ok(false);
    }

    // Decode signature
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| anyhow!("Invalid signature encoding"))?;

    // Get decoding key based on algorithm and key data
    match &options.key_data {
        VerifyKeyData::Secret(secret) => {
            match decoded_token.algorithm {
                Algorithm::HS256 => {
                    let key = hmac_sha256::HMAC::mac(message.as_bytes(), secret.as_bytes());
                    Ok(signature == key.as_slice())
                },
                Algorithm::HS384 | Algorithm::HS512 => {
                    // For HS384 and HS512, use jsonwebtoken directly
                    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
                    let mut validation = Validation::new(decoded_token.algorithm);
                    validation.validate_exp = options.validate_exp;
                    validation.validate_nbf = options.validate_nbf;
                    validation.leeway = options.leeway;
                    let result = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation);
                    Ok(result.is_ok())
                },
                _ => Err(anyhow!("HMAC key provided but algorithm is {:?}", decoded_token.algorithm)),
            }
        },
        VerifyKeyData::PublicKeyPem(pem) => {
            match decoded_token.algorithm {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 |
                Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                    let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes())?;
                    let mut validation = Validation::new(decoded_token.algorithm);
                    validation.validate_exp = options.validate_exp;
                    validation.validate_nbf = options.validate_nbf;
                    validation.leeway = options.leeway;
                    let result = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation);
                    Ok(result.is_ok())
                },
                Algorithm::ES256 | Algorithm::ES384 => {
                    let decoding_key = DecodingKey::from_ec_pem(pem.as_bytes())?;
                    let mut validation = Validation::new(decoded_token.algorithm);
                    validation.validate_exp = options.validate_exp;
                    validation.validate_nbf = options.validate_nbf;
                    validation.leeway = options.leeway;
                    let result = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation);
                    Ok(result.is_ok())
                },
                _ => Err(anyhow!("Public key provided but algorithm is {:?}", decoded_token.algorithm)),
            }
        },
        VerifyKeyData::PublicKeyDer(der) => {
            match decoded_token.algorithm {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 |
                Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                    let decoding_key = DecodingKey::from_rsa_der(der);
                    let mut validation = Validation::new(decoded_token.algorithm);
                    validation.validate_exp = options.validate_exp;
                    validation.validate_nbf = options.validate_nbf;
                    validation.leeway = options.leeway;
                    let result = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation);
                    Ok(result.is_ok())
                },
                Algorithm::ES256 | Algorithm::ES384 => {
                    let decoding_key = DecodingKey::from_ec_der(der);
                    let mut validation = Validation::new(decoded_token.algorithm);
                    validation.validate_exp = options.validate_exp;
                    validation.validate_nbf = options.validate_nbf;
                    validation.leeway = options.leeway;
                    let result = jsonwebtoken::decode::<Value>(token, &decoding_key, &validation);
                    Ok(result.is_ok())
                },
                _ => Err(anyhow!("Public key provided but algorithm is {:?}", decoded_token.algorithm)),
            }
        }
    }
}
