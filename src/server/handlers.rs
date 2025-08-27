//! # Request Handlers Module  
//!
//! This module contains HTTP request handlers for the Fernet web server.
//! Each handler is responsible for processing specific endpoint requests
//! with comprehensive error handling and performance optimization.
//!
//! ## Handler Design Principles
//!
//! - **Security First**: All input validation and sanitization
//! - **Performance**: Zero-copy operations where possible
//! - **Error Handling**: Secure error responses without information leakage
//! - **Observability**: Comprehensive metrics and logging

use crate::crypto::CryptoService;
use crate::error::{FernetWebError, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{HeaderMap, Request, Response, StatusCode};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, instrument, warn};

/// Handler for decrypt endpoint requests
///
/// This handler processes POST requests to /decrypt, performing the complete
/// cryptographic workflow: RSA key decryption followed by Fernet payload decryption.
///
/// ## Security Features
/// - Comprehensive header validation
/// - Payload size limits
/// - Rate limiting (future)
/// - Secure error responses
///
/// ## Performance Characteristics
/// - **Target Latency**: <10ms p99
/// - **Memory Usage**: Minimal allocations, zero-copy where possible
/// - **Concurrency**: Fully async, supports thousands of concurrent requests
#[derive(Debug)]
pub struct DecryptHandler {
    /// Shared cryptographic service for all operations
    pub crypto_service: Arc<CryptoService>,
}

impl DecryptHandler {
    /// Create a new decrypt handler
    ///
    /// ## Parameters
    /// - `crypto_service`: Shared cryptographic service instance
    ///
    /// ## Returns
    /// Returns a new `DecryptHandler` instance
    pub fn new(crypto_service: Arc<CryptoService>) -> Self {
        Self { crypto_service }
    }

    /// Handle POST /decrypt requests
    ///
    /// Processes requests containing RSA-encrypted symmetric keys and
    /// Fernet-encrypted payloads, returning the decrypted payload data.
    ///
    /// ## Request Format
    /// ```
    /// POST /decrypt
    /// Content-Type: application/octet-stream
    /// symmetric-key-uuid: <uuid>
    /// validator-hotkey: <hotkey>
    /// miner-hotkey: <hotkey>
    /// 
    /// <fernet-encrypted-payload-bytes>
    /// ```
    ///
    /// ## Response Format
    /// Success: Raw decrypted payload bytes
    /// Error: JSON error response
    ///
    /// ## Parameters
    /// - `request`: HTTP request containing encrypted data
    /// - `remote_addr`: Client IP address for logging
    ///
    /// ## Returns
    /// Returns HTTP response with decrypted data or error
    ///
    /// ## Performance
    /// - **Latency**: <10ms p99 for typical payloads
    /// - **Throughput**: >10k req/sec target
    /// - **Memory**: Zero-copy operations where possible
    #[instrument(level = "debug", name = "decrypt_handler", skip(self, request))]
    pub async fn handle(
        &self,
        request: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>> {
        debug!("Processing decrypt request from {}", remote_addr);

        // Extract and validate headers
        let headers = request.headers();
        let request_headers = self.extract_request_headers(headers)?;

        // Read request body (encrypted payload)
        let body = request.into_body();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| {
                warn!("Failed to read request body from {}: {}", remote_addr, e);
                FernetWebError::request_error(format!("Failed to read request body: {}", e))
            })?
            .to_bytes();

        // Validate payload size
        if body_bytes.len() > crate::MAX_PAYLOAD_SIZE {
            warn!(
                "Payload too large from {}: {} bytes (max: {})",
                remote_addr,
                body_bytes.len(),
                crate::MAX_PAYLOAD_SIZE
            );
            return Err(FernetWebError::request_error(format!(
                "Payload too large: {} bytes (max: {})",
                body_bytes.len(),
                crate::MAX_PAYLOAD_SIZE
            )));
        }

        if body_bytes.is_empty() {
            warn!("Empty payload from {}", remote_addr);
            return Err(FernetWebError::request_error(
                "Empty payload".to_string(),
            ));
        }

        // Convert body bytes to string for Fernet token processing
        let encrypted_payload = String::from_utf8(body_bytes.to_vec()).map_err(|e| {
            warn!("Invalid UTF-8 in payload from {}: {}", remote_addr, e);
            FernetWebError::request_error(format!("Invalid payload encoding: {}", e))
        })?;

        // Step 1: Decrypt the symmetric key using RSA
        debug!("Decrypting symmetric key with UUID: {}", request_headers.symmetric_key_uuid);
        let symmetric_key = self
            .crypto_service
            .decrypt_symmetric_key(&request_headers.symmetric_key_uuid)
            .await?;

        // Step 2: Decrypt the payload using Fernet with the symmetric key
        debug!("Decrypting payload with Fernet");
        let decrypted_payload = self
            .crypto_service
            .decrypt_payload(&symmetric_key, &encrypted_payload)
            .await?;

        debug!(
            "Successfully decrypted payload: {} bytes -> {} bytes",
            encrypted_payload.len(),
            decrypted_payload.len()
        );

        // Return raw decrypted bytes
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .header("cache-control", "no-cache, no-store, must-revalidate")
            .header("content-length", decrypted_payload.len())
            .body(Full::new(Bytes::from(decrypted_payload)))?)
    }

    /// Extract and validate required headers from the request
    ///
    /// Validates that all required headers are present and properly formatted.
    ///
    /// ## Parameters
    /// - `headers`: HTTP headers from the request
    ///
    /// ## Returns
    /// Returns extracted headers or validation error
    ///
    /// ## Required Headers
    /// - `symmetric-key-uuid`: UUID identifying the symmetric key
    /// - `validator-hotkey`: Validator identification key
    /// - `miner-hotkey`: Miner identification key
    fn extract_request_headers(&self, headers: &HeaderMap) -> Result<DecryptRequestHeaders> {
        let symmetric_key_uuid = self
            .get_required_header(headers, "symmetric-key-uuid")?
            .to_string();

        let validator_hotkey = self
            .get_required_header(headers, "validator-hotkey")?
            .to_string();

        let miner_hotkey = self
            .get_required_header(headers, "miner-hotkey")?
            .to_string();

        // Validate header formats
        self.validate_header_formats(&symmetric_key_uuid, &validator_hotkey, &miner_hotkey)?;

        Ok(DecryptRequestHeaders {
            symmetric_key_uuid,
            validator_hotkey,
            miner_hotkey,
        })
    }

    /// Extract a required header value from the request
    ///
    /// ## Parameters
    /// - `headers`: HTTP headers map
    /// - `header_name`: Name of the required header
    ///
    /// ## Returns
    /// Returns header value as string or error if missing/invalid
    fn get_required_header<'a>(&self, headers: &'a HeaderMap, header_name: &str) -> Result<&'a str> {
        headers
            .get(header_name)
            .ok_or_else(|| {
                FernetWebError::request_error(format!("Missing required header: {}", header_name))
            })?
            .to_str()
            .map_err(|e| {
                FernetWebError::request_error(format!(
                    "Invalid header value for {}: {}",
                    header_name, e
                ))
            })
    }

    /// Validate the format of extracted headers
    ///
    /// Performs basic validation on header values to ensure they meet
    /// expected format requirements.
    ///
    /// ## Parameters
    /// - `symmetric_key_uuid`: UUID string to validate
    /// - `validator_hotkey`: Validator hotkey to validate  
    /// - `miner_hotkey`: Miner hotkey to validate
    ///
    /// ## Returns
    /// Returns `Ok(())` if valid, error otherwise
    fn validate_header_formats(
        &self,
        symmetric_key_uuid: &str,
        validator_hotkey: &str,
        miner_hotkey: &str,
    ) -> Result<()> {
        // Validate symmetric key UUID format (basic length check)
        if symmetric_key_uuid.is_empty() || symmetric_key_uuid.len() > 256 {
            return Err(FernetWebError::request_error(
                "Invalid symmetric key UUID format".to_string(),
            ));
        }

        // Validate hotkey formats (basic length and character checks)
        if validator_hotkey.is_empty() || validator_hotkey.len() > 256 {
            return Err(FernetWebError::request_error(
                "Invalid validator hotkey format".to_string(),
            ));
        }

        if miner_hotkey.is_empty() || miner_hotkey.len() > 256 {
            return Err(FernetWebError::request_error(
                "Invalid miner hotkey format".to_string(),
            ));
        }

        // Additional validation: check for basic alphanumeric/base64 characters
        let valid_chars = |s: &str| {
            s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '/')
        };

        if !valid_chars(symmetric_key_uuid) {
            return Err(FernetWebError::request_error(
                "Invalid characters in symmetric key UUID".to_string(),
            ));
        }

        if !valid_chars(validator_hotkey) {
            return Err(FernetWebError::request_error(
                "Invalid characters in validator hotkey".to_string(),
            ));
        }

        if !valid_chars(miner_hotkey) {
            return Err(FernetWebError::request_error(
                "Invalid characters in miner hotkey".to_string(),
            ));
        }

        Ok(())
    }
}

/// Extracted and validated headers from decrypt requests
///
/// This struct contains all the required headers for processing
/// decrypt requests, validated for format and security.
#[derive(Debug, Clone)]
struct DecryptRequestHeaders {
    /// Symmetric key identifier (used as encrypted symmetric key)
    symmetric_key_uuid: String,
    /// Validator identification hotkey
    validator_hotkey: String,
    /// Miner identification hotkey  
    miner_hotkey: String,
}

/// Generic request handler trait for extensibility
///
/// This trait allows for consistent handler interfaces and
/// makes it easy to add new endpoint handlers in the future.
pub trait RequestHandler: Send + Sync {
    /// Handle an HTTP request
    ///
    /// ## Parameters
    /// - `request`: HTTP request to process
    /// - `remote_addr`: Client IP address
    ///
    /// ## Returns
    /// Returns HTTP response or error
    async fn handle(
        &self,
        request: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>>;
}

impl RequestHandler for DecryptHandler {
    async fn handle(
        &self,
        request: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>> {
        self.handle(request, remote_addr).await
    }
}

/// Handler registry for managing multiple endpoint handlers
///
/// This struct provides a centralized way to manage and route
/// requests to appropriate handlers based on path and method.
#[derive(Debug)]
pub struct HandlerRegistry {
    /// Map of route patterns to handler types (simplified for now)
    routes: HashMap<String, String>,
    /// Decrypt handler instance
    decrypt_handler: Option<DecryptHandler>,
}

impl HandlerRegistry {
    /// Create a new empty handler registry
    ///
    /// ## Returns
    /// Returns a new `HandlerRegistry` instance
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            decrypt_handler: None,
        }
    }

    /// Register the decrypt handler
    ///
    /// ## Parameters
    /// - `handler`: Decrypt handler instance to register
    pub fn register_decrypt_handler(&mut self, handler: DecryptHandler) {
        self.routes.insert("POST:/decrypt".to_string(), "decrypt".to_string());
        self.decrypt_handler = Some(handler);
    }

    /// Handle a request for the given route
    ///
    /// ## Parameters
    /// - `route`: Route pattern to handle
    /// - `request`: HTTP request
    /// - `remote_addr`: Client IP address
    ///
    /// ## Returns
    /// Returns handler result if route is supported
    pub async fn handle_request(
        &self,
        route: &str,
        request: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Option<Result<Response<Full<Bytes>>>> {
        match route {
            "POST:/decrypt" => {
                if let Some(ref handler) = self.decrypt_handler {
                    Some(handler.handle(request, remote_addr).await)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get all registered routes
    ///
    /// ## Returns
    /// Returns vector of all registered route patterns
    pub fn get_routes(&self) -> Vec<String> {
        self.routes.keys().cloned().collect()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoService;
    use hyper::HeaderMap;
    use http::{HeaderName, HeaderValue};
    use std::str::FromStr;
    use tempfile::NamedTempFile;
    use std::io::Write;

    const TEST_RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6
zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQK
CAQEAsamplekeyfortest4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNL
O6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBA
QKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNk
yTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiW
jNLO6zI6O4r1wNkyTCBPOI+R+wIBAQ==
-----END RSA PRIVATE KEY-----"#;

    async fn create_test_crypto_service() -> Arc<CryptoService> {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", TEST_RSA_KEY).unwrap();
        
        // For testing, we'll create a crypto service that uses stubs
        Arc::new(CryptoService::new(temp_file.path()).await.unwrap())
    }

    #[tokio::test]
    async fn test_decrypt_handler_creation() {
        let crypto_service = create_test_crypto_service().await;
        let handler = DecryptHandler::new(crypto_service);
        
        // Just test creation for now
        assert!(format!("{:?}", handler).contains("DecryptHandler"));
    }

    #[test]
    fn test_header_extraction_success() {
        // Create a dummy crypto service for testing
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("symmetric-key-uuid").unwrap(),
            HeaderValue::from_str("test-uuid-123").unwrap(),
        );
        headers.insert(
            HeaderName::from_str("validator-hotkey").unwrap(),
            HeaderValue::from_str("validator-key-456").unwrap(),
        );
        headers.insert(
            HeaderName::from_str("miner-hotkey").unwrap(),
            HeaderValue::from_str("miner-key-789").unwrap(),
        );

        let result = handler.extract_request_headers(&headers);
        assert!(result.is_ok());
        
        let headers = result.unwrap();
        assert_eq!(headers.symmetric_key_uuid, "test-uuid-123");
        assert_eq!(headers.validator_hotkey, "validator-key-456");
        assert_eq!(headers.miner_hotkey, "miner-key-789");
    }

    #[test]
    fn test_header_extraction_missing_header() {
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        let headers = HeaderMap::new(); // Empty headers
        
        let result = handler.extract_request_headers(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_validation_empty_values() {
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        let result = handler.validate_header_formats("", "validator", "miner");
        assert!(result.is_err());
    }

    #[test]
    fn test_header_validation_too_long() {
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        let long_string = "a".repeat(300);
        let result = handler.validate_header_formats(&long_string, "validator", "miner");
        assert!(result.is_err());
    }

    #[test]
    fn test_header_validation_invalid_chars() {
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        let result = handler.validate_header_formats("uuid<>", "validator", "miner");
        assert!(result.is_err());
    }

    #[test]
    fn test_header_validation_success() {
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        let result = handler.validate_header_formats("uuid-123", "validator_key", "miner+key");
        assert!(result.is_ok());
    }

    #[test]
    fn test_handler_registry() {
        let mut registry = HandlerRegistry::new();
        assert_eq!(registry.get_routes().len(), 0);
        
        let crypto_service = tokio_test::block_on(create_test_crypto_service());
        let handler = DecryptHandler::new(crypto_service);
        
        registry.register_decrypt_handler(handler);
        assert_eq!(registry.get_routes().len(), 1);
        assert!(registry.get_routes().contains(&"POST:/decrypt".to_string()));
    }

    #[test]
    fn test_handler_registry_default() {
        let registry = HandlerRegistry::default();
        assert_eq!(registry.get_routes().len(), 0);
    }

    #[test]
    fn test_decrypt_request_headers_debug() {
        let headers = DecryptRequestHeaders {
            symmetric_key_uuid: "test-uuid".to_string(),
            validator_hotkey: "validator".to_string(),
            miner_hotkey: "miner".to_string(),
        };
        
        let debug_str = format!("{:?}", headers);
        assert!(debug_str.contains("test-uuid"));
        assert!(debug_str.contains("validator"));
        assert!(debug_str.contains("miner"));
    }

    #[test]
    fn test_decrypt_request_headers_clone() {
        let headers = DecryptRequestHeaders {
            symmetric_key_uuid: "test-uuid".to_string(),
            validator_hotkey: "validator".to_string(),
            miner_hotkey: "miner".to_string(),
        };
        
        let cloned = headers.clone();
        assert_eq!(cloned.symmetric_key_uuid, headers.symmetric_key_uuid);
        assert_eq!(cloned.validator_hotkey, headers.validator_hotkey);
        assert_eq!(cloned.miner_hotkey, headers.miner_hotkey);
    }
}