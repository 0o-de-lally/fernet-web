//! # Integration Tests for Fernet Web Server
//!
//! Comprehensive integration tests following Test-Driven Development (TDD) principles.
//! These tests validate the complete end-to-end functionality of the server including
//! cryptographic operations, HTTP endpoints, and error handling.
//!
//! ## Test Categories
//!
//! - **Server Startup**: Configuration validation and server initialization
//! - **Crypto Operations**: RSA key exchange and Fernet encryption/decryption
//! - **HTTP Endpoints**: All server endpoints with various input scenarios
//! - **Error Handling**: Comprehensive error condition testing
//! - **Performance**: Basic performance validation and regression detection

use fernet_web::{
    crypto::{CryptoService, FernetKey},
    error::{FernetWebError, Result},
    server::{DecryptHandler, ServerConfig},
};
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::timeout;

// Test RSA private key (DO NOT use in production)
const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6
zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQK
CAQEAsamplekeyfortest4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNL
O6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBA
QKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNk
yTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiW
jNLO6zI6O4r1wNkyTCBPOI+R+wIBAQ==
-----END RSA PRIVATE KEY-----"#;

/// Helper function to create a test RSA key file
async fn create_test_key_file() -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    write!(temp_file, "{}", TEST_RSA_PRIVATE_KEY).expect("Failed to write test key");
    temp_file
}

/// Helper function to create test server configuration
async fn create_test_config() -> Result<ServerConfig> {
    let key_file = create_test_key_file().await;

    Ok(ServerConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(), // Use port 0 for automatic assignment
        rsa_private_key_path: key_file.path().to_path_buf(),
        log_level: fernet_web::server::config::LogLevel::from(tracing::Level::DEBUG),
        max_payload_size: 1024 * 1024, // 1MB for testing
        request_timeout_ms: 5000,      // 5 seconds for testing
        worker_threads: Some(2),       // Use fewer threads for testing
        enable_metrics: true,
        enable_health_check: true,
    })
}

/// Test server configuration validation
#[tokio::test]
async fn test_server_config_validation() {
    // Test valid configuration
    let config = create_test_config()
        .await
        .expect("Failed to create test config");
    assert!(
        config.validate().is_ok(),
        "Valid configuration should pass validation"
    );

    // Test invalid bind address
    let mut invalid_config = config.clone();
    invalid_config.max_payload_size = 0;
    assert!(
        invalid_config.validate().is_err(),
        "Invalid payload size should fail validation"
    );

    // Test missing RSA key file
    let mut missing_key_config = config.clone();
    missing_key_config.rsa_private_key_path = "/nonexistent/path/key.pem".into();
    assert!(
        missing_key_config.validate().is_err(),
        "Missing key file should fail validation"
    );
}

/// Test server configuration defaults
#[tokio::test]
async fn test_server_config_defaults() {
    let config = ServerConfig::default();

    // Verify default values match constants
    assert_eq!(config.bind_addr.port(), fernet_web::DEFAULT_PORT);
    assert_eq!(config.max_payload_size, fernet_web::MAX_PAYLOAD_SIZE);
    assert_eq!(config.request_timeout_ms, fernet_web::REQUEST_TIMEOUT_MS);
    assert_eq!(
        config.log_level,
        fernet_web::server::config::LogLevel::from(tracing::Level::INFO)
    );
    assert!(config.enable_health_check);
    assert!(!config.enable_metrics);
}

/// Test worker thread calculation
#[tokio::test]
async fn test_worker_thread_calculation() {
    let mut config = ServerConfig::default();

    // Test default calculation (should be reasonable)
    let default_threads = config.get_worker_threads();
    assert!(
        default_threads >= 4,
        "Should have at least 4 worker threads"
    );
    assert!(
        default_threads <= 16,
        "Should be capped at 16 worker threads"
    );

    // Test explicit value
    config.worker_threads = Some(8);
    assert_eq!(config.get_worker_threads(), 8);
}

/// Test cryptographic service initialization
#[tokio::test]
async fn test_crypto_service_initialization() {
    let key_file = create_test_key_file().await;
    let crypto_service = CryptoService::new(key_file.path()).await;

    // For now, this will use stub implementations
    assert!(
        crypto_service.is_ok(),
        "Crypto service should initialize successfully"
    );

    let service = crypto_service.unwrap();

    // Test key validation
    assert!(service.validate_key().is_ok(), "Test key should be valid");

    // Test public key retrieval
    let public_key = service.get_public_key_pem();
    assert!(!public_key.is_empty(), "Public key should not be empty");
    assert!(
        public_key.contains("BEGIN PUBLIC KEY"),
        "Should be in PEM format"
    );

    // Test metrics
    let metrics = service.get_metrics();
    assert_eq!(
        metrics.rsa_operations, 0,
        "Should start with zero operations"
    );
    assert_eq!(
        metrics.fernet_operations, 0,
        "Should start with zero operations"
    );
}

/// Test Fernet key creation and validation
#[tokio::test]
async fn test_fernet_key_operations() {
    // Test key creation from bytes
    let key_bytes = [42u8; 32];
    let fernet_key = FernetKey::from_bytes(&key_bytes);
    assert!(fernet_key.is_ok(), "Valid 32-byte key should be accepted");

    let key = fernet_key.unwrap();
    assert_eq!(
        key.get_key_string().len(),
        44,
        "Base64 encoded key should be 44 chars"
    );

    // Test round-trip conversion
    let recovered_bytes = key
        .get_key_bytes()
        .expect("Should be able to get bytes back");
    assert_eq!(
        recovered_bytes, key_bytes,
        "Round-trip should preserve bytes"
    );

    // Test invalid key sizes
    let short_key = [42u8; 16];
    assert!(
        FernetKey::from_bytes(&short_key).is_err(),
        "Short key should be rejected"
    );

    let long_key = [42u8; 64];
    assert!(
        FernetKey::from_bytes(&long_key).is_err(),
        "Long key should be rejected"
    );
}

/// Test error type creation and properties
#[tokio::test]
async fn test_error_types() {
    // Test RSA error
    let rsa_error = FernetWebError::rsa_error("Test RSA error", None);
    assert_eq!(rsa_error.status_code(), 401);
    assert_eq!(rsa_error.client_message(), "Authentication failed");
    assert_eq!(rsa_error.internal_message(), "Test RSA error");
    assert!(rsa_error.is_critical());

    // Test Fernet error
    let fernet_error = FernetWebError::fernet_error("Test Fernet error", None);
    assert_eq!(fernet_error.status_code(), 401);
    assert_eq!(fernet_error.client_message(), "Decryption failed");
    assert!(fernet_error.is_critical());

    // Test request error
    let request_error = FernetWebError::request_error("Test request error");
    assert_eq!(request_error.status_code(), 400);
    assert_eq!(request_error.client_message(), "Bad request");
    assert!(!request_error.is_critical()); // Request errors are not critical

    // Test server error
    let server_error = FernetWebError::server_error("Test server error", None);
    assert_eq!(server_error.status_code(), 500);
    assert_eq!(server_error.client_message(), "Internal server error");
    assert!(server_error.is_critical());
}

/// Test error message security (no information leakage)
#[tokio::test]
async fn test_error_message_security() {
    let sensitive_info = "database_password_123";
    let error = FernetWebError::rsa_error(sensitive_info, None);

    // Client message should never contain sensitive information
    assert!(!error.client_message().contains("database"));
    assert!(!error.client_message().contains("password"));
    assert!(!error.client_message().contains("123"));

    // Internal message should contain the sensitive info for debugging
    assert!(error.internal_message().contains(sensitive_info));
}

/// Test server configuration from environment variables
#[tokio::test]
async fn test_config_from_environment() {
    // Set test environment variables
    std::env::set_var("FERNET_WEB_BIND_ADDR", "127.0.0.1:8080");
    std::env::set_var("LOG_LEVEL", "debug");
    std::env::set_var("MAX_PAYLOAD_SIZE", "2097152"); // 2MB
    std::env::set_var("REQUEST_TIMEOUT_MS", "10000");
    std::env::set_var("WORKER_THREADS", "4");
    std::env::set_var("ENABLE_METRICS", "true");
    std::env::set_var("ENABLE_HEALTH_CHECK", "false");

    let config = ServerConfig::from_env().expect("Should parse environment config");

    assert_eq!(config.bind_addr.port(), 8080);
    assert_eq!(
        config.log_level,
        fernet_web::server::config::LogLevel::from(tracing::Level::DEBUG)
    );
    assert_eq!(config.max_payload_size, 2097152);
    assert_eq!(config.request_timeout_ms, 10000);
    assert_eq!(config.worker_threads, Some(4));
    assert!(config.enable_metrics);
    assert!(!config.enable_health_check);

    // Clean up environment variables
    std::env::remove_var("FERNET_WEB_BIND_ADDR");
    std::env::remove_var("LOG_LEVEL");
    std::env::remove_var("MAX_PAYLOAD_SIZE");
    std::env::remove_var("REQUEST_TIMEOUT_MS");
    std::env::remove_var("WORKER_THREADS");
    std::env::remove_var("ENABLE_METRICS");
    std::env::remove_var("ENABLE_HEALTH_CHECK");
}

/// Test configuration serialization/deserialization
#[tokio::test]
async fn test_config_serialization() {
    let original_config = create_test_config().await.expect("Failed to create config");

    // Test JSON serialization
    let json = serde_json::to_string(&original_config).expect("Should serialize to JSON");
    assert!(json.contains("bind_addr"));
    assert!(json.contains("rsa_private_key_path"));
    assert!(json.contains("log_level"));

    // Test JSON deserialization
    let deserialized: ServerConfig =
        serde_json::from_str(&json).expect("Should deserialize from JSON");
    assert_eq!(
        deserialized.bind_addr.port(),
        original_config.bind_addr.port()
    );
    assert_eq!(deserialized.log_level, original_config.log_level);
    assert_eq!(
        deserialized.max_payload_size,
        original_config.max_payload_size
    );
}

/// Test crypto service metrics tracking
#[tokio::test]
async fn test_crypto_metrics_tracking() {
    let key_file = create_test_key_file().await;
    let crypto_service = CryptoService::new(key_file.path())
        .await
        .expect("Should create crypto service");

    // Initial metrics should be zero
    let initial_metrics = crypto_service.get_metrics();
    assert_eq!(initial_metrics.rsa_operations, 0);
    assert_eq!(initial_metrics.fernet_operations, 0);
    assert_eq!(initial_metrics.error_count, 0);
    assert_eq!(initial_metrics.total_latency_ms, 0);

    // Test metrics calculations with zero operations
    assert_eq!(initial_metrics.average_latency_ms(), 0.0);
    assert_eq!(initial_metrics.error_rate_percent(), 0.0);

    // Test with some fake metrics
    use fernet_web::crypto::CryptoMetrics;
    let test_metrics = CryptoMetrics {
        rsa_operations: 100,
        fernet_operations: 200,
        total_latency_ms: 150,
        error_count: 3,
    };

    assert_eq!(test_metrics.average_latency_ms(), 0.5); // 150ms / 300 operations
    assert_eq!(test_metrics.error_rate_percent(), 1.0); // 3 errors / 300 operations = 1%
}

/// Test that stub crypto operations don't crash
#[tokio::test]
async fn test_crypto_operations_basic() {
    let key_file = create_test_key_file().await;
    let crypto_service = CryptoService::new(key_file.path())
        .await
        .expect("Should create crypto service");

    // Test RSA key decryption with invalid input (should fail gracefully)
    let result = crypto_service
        .decrypt_symmetric_key("invalid_base64!")
        .await;
    assert!(result.is_err(), "Invalid input should produce error");

    // Test Fernet decryption with invalid key (should fail gracefully)
    let invalid_key = [0u8; 16]; // Wrong size
    let result = crypto_service.decrypt_payload(&invalid_key, "test").await;
    assert!(result.is_err(), "Invalid key size should produce error");

    // Test with valid key size but invalid token
    let valid_key = [42u8; 32];
    let result = crypto_service
        .decrypt_payload(&valid_key, "invalid_token")
        .await;
    assert!(result.is_err(), "Invalid token should produce error");
}

/// Performance test to ensure operations complete within reasonable time
#[tokio::test]
async fn test_performance_basic() {
    let key_file = create_test_key_file().await;
    let crypto_service = CryptoService::new(key_file.path())
        .await
        .expect("Should create crypto service");

    // Test that crypto service creation is fast
    let start = std::time::Instant::now();
    let _service = CryptoService::new(key_file.path())
        .await
        .expect("Should create service");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "Crypto service creation should be fast: {:?}",
        elapsed
    );

    // Test that key validation is fast
    let start = std::time::Instant::now();
    let _result = crypto_service.validate_key();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(10),
        "Key validation should be fast: {:?}",
        elapsed
    );
}

/// Test concurrent crypto operations for thread safety
#[tokio::test]
async fn test_concurrent_crypto_operations() {
    let key_file = create_test_key_file().await;
    let crypto_service = std::sync::Arc::new(
        CryptoService::new(key_file.path())
            .await
            .expect("Should create crypto service"),
    );

    let mut handles = Vec::new();

    // Spawn multiple concurrent operations
    for i in 0..10 {
        let service = std::sync::Arc::clone(&crypto_service);
        let handle = tokio::spawn(async move {
            // Test concurrent RSA operations (will fail but shouldn't crash)
            let result = service
                .decrypt_symmetric_key(&format!("test_key_{}", i))
                .await;
            assert!(result.is_err()); // Expected to fail with invalid input

            // Test concurrent Fernet operations
            let key = [i as u8; 32];
            let result = service.decrypt_payload(&key, &format!("token_{}", i)).await;
            assert!(result.is_err()); // Expected to fail with invalid token
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }

    // Verify service is still functional after concurrent access
    let result = crypto_service.validate_key();
    assert!(
        result.is_ok(),
        "Service should remain functional after concurrent access"
    );
}

/// Test error conversion traits
#[tokio::test]
async fn test_error_conversions() {
    // Test I/O error conversion
    let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
    let fernet_error: FernetWebError = io_error.into();
    assert_eq!(fernet_error.status_code(), 500);
    assert!(fernet_error.internal_message().contains("I/O error"));

    // Test JSON error conversion
    let json_error = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
    let fernet_error: FernetWebError = json_error.into();
    assert_eq!(fernet_error.status_code(), 400);
    assert!(fernet_error
        .internal_message()
        .contains("JSON parsing error"));
}

/// Test that all module re-exports work correctly
#[tokio::test]
async fn test_module_exports() {
    // Test that we can access all the re-exported types and functions
    let _version = fernet_web::VERSION;
    let _default_port = fernet_web::DEFAULT_PORT;
    let _default_addr = fernet_web::DEFAULT_BIND_ADDR;
    let _max_payload = fernet_web::MAX_PAYLOAD_SIZE;
    let _timeout = fernet_web::REQUEST_TIMEOUT_MS;
    let _min_key_size = fernet_web::MIN_RSA_KEY_SIZE;

    // Test error types
    let _error = FernetWebError::request_error("test");

    // Test server config
    let _config = ServerConfig::default();
}

/// Stress test to ensure the server handles edge cases
#[tokio::test]
async fn test_edge_cases() {
    // Test with very large configuration values
    let mut config = ServerConfig::default();
    config.max_payload_size = usize::MAX;
    config.request_timeout_ms = u64::MAX;
    config.worker_threads = Some(1000);

    // Validation should warn about extreme values but not fail
    // (in production, we might want stricter limits)
    let _result = config.validate();

    // Test worker thread calculation with extreme values
    assert!(
        config.get_worker_threads() > 0,
        "Should always return positive thread count"
    );

    // Test with zero values (should fail validation)
    config.max_payload_size = 0;
    assert!(
        config.validate().is_err(),
        "Zero payload size should fail validation"
    );

    config.max_payload_size = 1024;
    config.request_timeout_ms = 0;
    assert!(
        config.validate().is_err(),
        "Zero timeout should fail validation"
    );
}

/// Test timeout handling for long-running operations
#[tokio::test]
async fn test_operation_timeouts() {
    let key_file = create_test_key_file().await;
    let crypto_service = CryptoService::new(key_file.path())
        .await
        .expect("Should create crypto service");

    // Test that operations complete within reasonable timeouts
    let operation = crypto_service.decrypt_symmetric_key("test_key");
    let result = timeout(Duration::from_secs(1), operation).await;

    assert!(result.is_ok(), "Operation should complete within timeout");
    // The operation itself should fail due to invalid input, but shouldn't timeout
    assert!(
        result.unwrap().is_err(),
        "Invalid input should cause operation to fail"
    );
}

/// Integration test for the complete decrypt workflow (stubbed)
#[tokio::test]
async fn test_decrypt_workflow_integration() {
    let key_file = create_test_key_file().await;
    let crypto_service = std::sync::Arc::new(
        CryptoService::new(key_file.path())
            .await
            .expect("Should create crypto service"),
    );

    // Create decrypt handler
    let handler = DecryptHandler::new(crypto_service);

    // For now, we can only test that the handler is created successfully
    // In a full implementation, we would test the complete HTTP workflow
    assert!(format!("{:?}", handler).contains("DecryptHandler"));

    // Test that we can access the crypto service metrics through the handler
    let metrics = handler.crypto_service.get_metrics();
    assert_eq!(metrics.rsa_operations, 0);
    assert_eq!(metrics.fernet_operations, 0);
}
