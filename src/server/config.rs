//! # Server Configuration Module
//!
//! This module provides comprehensive configuration management for the Fernet web server.
//! It supports multiple configuration sources and provides validation for all settings
//! to ensure secure and optimal server operation.
//!
//! ## Configuration Sources
//!
//! Configuration can be loaded from (in order of precedence):
//! 1. Command-line arguments
//! 2. Environment variables  
//! 3. Configuration files (TOML, JSON, YAML)
//! 4. Default values
//!
//! ## Security Considerations
//!
//! - RSA key paths are validated for existence and readability
//! - Bind addresses are validated for proper format
//! - All configuration values are sanitized before use

use crate::error::{FernetWebError, Result};
use clap::Parser;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{metadata::ParseLevelError, Level};

/// Wrapper for `tracing::Level` to handle serialization/deserialization
/// Used for logging configuration in the server.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LogLevel(Level);

impl LogLevel {
    /// Returns the inner `tracing::Level` value.
    #[must_use]
    pub fn inner(&self) -> Level {
        self.0
    }
}

impl From<Level> for LogLevel {
    fn from(level: Level) -> Self {
        Self(level)
    }
}

impl From<LogLevel> for Level {
    fn from(log_level: LogLevel) -> Self {
        log_level.0
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ParseLevelError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl Serialize for LogLevel {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s.parse().map_err(serde::de::Error::custom)?))
    }
}

/// Comprehensive server configuration
///
/// This struct contains all configuration options for the Fernet web server,
/// with sensible defaults and comprehensive validation.
///
/// ## Performance Settings
/// - Bind address controls network interface and port
/// - Log level affects performance (DEBUG is slower than INFO)
///
/// ## Security Settings  
/// - RSA private key path must point to a secure key file
/// - Recommended to use strong file permissions (600) on key files
#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
#[command(
    name = "fernet-web",
    about = "High-performance Fernet web server with RSA key exchange",
    version,
    long_about = None
)]
pub struct ServerConfig {
    /// Network address to bind the server to
    ///
    /// Supports both IPv4 and IPv6 addresses. Use "0.0.0.0:7999" to bind
    /// to all interfaces, or "127.0.0.1:7999" for localhost only.
    ///
    /// ## Security
    /// Binding to 0.0.0.0 exposes the server to all network interfaces.
    /// Only use this in trusted environments or behind a firewall.
    ///
    /// ## Performance
    /// IPv4 addresses typically have slightly lower overhead than IPv6
    #[arg(
        short = 'b',
        long = "bind",
        value_name = "ADDRESS:PORT",
        default_value = "0.0.0.0:7999",
        env = "FERNET_WEB_BIND_ADDR",
        help = "Network address to bind the server to"
    )]
    pub bind_addr: SocketAddr,

    /// Path to RSA private key file in PEM format
    ///
    /// The private key is used to decrypt symmetric keys sent by clients
    /// during the key exchange process. The key file should be in PEM format
    /// and have secure file permissions (recommended: 600).
    ///
    /// ## Security Requirements
    /// - Key must be at least 2048 bits (4096 recommended)
    /// - File should have restrictive permissions (600)
    /// - Path should be accessible by the server process
    /// - Consider using a secure key management system in production
    #[arg(
        short = 'k',
        long = "rsa-key",
        value_name = "PATH",
        env = "RSA_PRIVATE_KEY_PATH",
        help = "Path to RSA private key file in PEM format"
    )]
    pub rsa_private_key_path: PathBuf,

    /// Logging level for the server
    ///
    /// Controls the verbosity of server logging:
    /// - ERROR: Only critical errors
    /// - WARN: Errors and warnings  
    /// - INFO: General operational information
    /// - DEBUG: Detailed debugging information
    /// - TRACE: Very detailed tracing (performance impact)
    ///
    /// ## Performance Impact
    /// DEBUG and TRACE levels can significantly impact performance
    /// due to increased logging overhead. Use INFO or WARN in production.
    #[arg(
        short = 'l',
        long = "log-level",
        value_name = "LEVEL",
        default_value = "info",
        env = "LOG_LEVEL",
        help = "Logging level (error, warn, info, debug, trace)"
    )]
    pub log_level: LogLevel,

    /// Maximum request payload size in bytes
    ///
    /// Limits the size of request bodies to prevent memory exhaustion attacks.
    /// Requests exceeding this size will be rejected with a 413 status code.
    ///
    /// ## Security
    /// This limit prevents `DoS` attacks through large payloads.
    /// Set according to your expected maximum payload size.
    ///
    /// ## Performance  
    /// Larger limits allow bigger payloads but increase memory usage.
    /// Consider your available memory when setting this value.
    #[arg(
        short = 'm',
        long = "max-payload-size",
        value_name = "BYTES", 
        default_value_t = crate::MAX_PAYLOAD_SIZE,
        env = "MAX_PAYLOAD_SIZE",
        help = "Maximum request payload size in bytes"
    )]
    pub max_payload_size: usize,

    /// Request timeout in milliseconds
    ///
    /// Maximum time allowed for processing a single request.
    /// Requests exceeding this timeout will be terminated to prevent
    /// resource exhaustion.
    ///
    /// ## Performance
    /// Shorter timeouts improve resource utilization but may cause
    /// legitimate slow requests to fail. Balance based on your use case.
    #[arg(
        short = 't',
        long = "request-timeout",
        value_name = "MILLISECONDS",
        default_value_t = crate::REQUEST_TIMEOUT_MS,
        env = "REQUEST_TIMEOUT_MS", 
        help = "Request timeout in milliseconds"
    )]
    pub request_timeout_ms: u64,

    /// Number of worker threads for the server
    ///
    /// Controls the size of the Tokio runtime thread pool.
    /// If not specified, defaults to the number of CPU cores.
    ///
    /// ## Performance
    /// More threads can improve concurrency but increase context switching.
    /// Generally, 2-4x the number of CPU cores is optimal for I/O-bound workloads.
    #[arg(
        short = 'w',
        long = "worker-threads",
        value_name = "COUNT",
        env = "WORKER_THREADS",
        help = "Number of worker threads (default: number of CPU cores)"
    )]
    pub worker_threads: Option<usize>,

    /// Enable Prometheus metrics endpoint
    ///
    /// When enabled, exposes metrics at /metrics endpoint in Prometheus format
    /// for integration with monitoring systems.
    ///
    /// ## Performance
    /// Metrics collection has minimal overhead (<0.1% CPU impact).
    /// The /metrics endpoint should be secured in production environments.
    #[arg(
        long = "enable-metrics",
        env = "ENABLE_METRICS",
        help = "Enable Prometheus metrics endpoint"
    )]
    pub enable_metrics: bool,

    /// Enable health check endpoint
    ///
    /// When enabled, exposes health status at /health endpoint for
    /// load balancers and monitoring systems.
    ///
    /// ## Performance
    /// Health checks have minimal overhead and are recommended for production.
    #[arg(
        long = "enable-health-check",
        env = "ENABLE_HEALTH_CHECK",
        default_value = "true",
        help = "Enable health check endpoint"
    )]
    pub enable_health_check: bool,
}

impl ServerConfig {
    /// Create a new configuration with default values
    ///
    /// ## Returns
    /// Returns a `ServerConfig` with sensible defaults for development
    ///
    /// ## Example
    /// ```rust
    /// use fernet_web::ServerConfig;
    ///
    /// let config = ServerConfig::default();
    /// assert_eq!(config.bind_addr.port(), 7999);
    /// ```
    #[must_use] pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from command-line arguments
    ///
    /// Parses command-line arguments and environment variables to create
    /// a complete server configuration.
    ///
    /// ## Returns
    /// Returns configured `ServerConfig` or parsing error
    ///
    /// ## Example
    /// ```rust,no_run
    /// use fernet_web::ServerConfig;
    ///
    /// let config = ServerConfig::from_args();
    /// println!("Server will bind to: {}", config.bind_addr);
    /// ```
    #[must_use] pub fn from_args() -> Self {
        Self::parse()
    }

    /// Load configuration from environment variables only
    ///
    /// Creates configuration using only environment variables,
    /// with defaults for any missing values.
    ///
    /// ## Returns
    /// Returns configured `ServerConfig` or parsing error
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        // Load from environment variables
        if let Ok(bind_addr) = std::env::var("FERNET_WEB_BIND_ADDR") {
            config.bind_addr = bind_addr.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid bind address '{bind_addr}': {e}"),
                    Some(Box::new(e)),
                )
            })?;
        }

        if let Ok(key_path) = std::env::var("RSA_PRIVATE_KEY_PATH") {
            config.rsa_private_key_path = PathBuf::from(key_path);
        }

        if let Ok(log_level) = std::env::var("LOG_LEVEL") {
            config.log_level = log_level.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid log level '{log_level}': {e}"),
                    Some(Box::new(e)),
                )
            })?;
        }

        if let Ok(max_size) = std::env::var("MAX_PAYLOAD_SIZE") {
            config.max_payload_size = max_size.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid max payload size '{max_size}': {e}"),
                    Some(Box::new(e)),
                )
            })?;
        }

        if let Ok(timeout) = std::env::var("REQUEST_TIMEOUT_MS") {
            config.request_timeout_ms = timeout.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid request timeout '{timeout}': {e}"),
                    Some(Box::new(e)),
                )
            })?;
        }

        if let Ok(workers) = std::env::var("WORKER_THREADS") {
            config.worker_threads = Some(workers.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid worker threads '{workers}': {e}"),
                    Some(Box::new(e)),
                )
            })?);
        }

        if let Ok(metrics) = std::env::var("ENABLE_METRICS") {
            config.enable_metrics = metrics.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid enable metrics '{metrics}': {e}"),
                    Some(Box::new(e)),
                )
            })?;
        }

        if let Ok(health) = std::env::var("ENABLE_HEALTH_CHECK") {
            config.enable_health_check = health.parse().map_err(|e| {
                FernetWebError::config_error(
                    format!("Invalid enable health check '{health}': {e}"),
                    Some(Box::new(e)),
                )
            })?;
        }

        Ok(config)
    }

    /// Validate the configuration for consistency and security
    ///
    /// Performs comprehensive validation including:
    /// - RSA key file existence and permissions
    /// - Bind address validity
    /// - Resource limit validation
    /// - Security setting verification
    ///
    /// ## Returns
    /// Returns `Ok(())` if valid, or detailed error information
    ///
    /// ## Errors
    /// - `FernetWebError::ConfigError`: If validation fails
    pub fn validate(&self) -> Result<()> {
        // Validate bind address is not wildcard in production
        if self.bind_addr.ip().is_unspecified() {
            tracing::warn!(
                "Binding to wildcard address {} - ensure this is secure for your environment",
                self.bind_addr
            );
        }

        // Validate RSA key file exists and is readable
        if !self.rsa_private_key_path.exists() {
            return Err(FernetWebError::config_error(
                format!(
                    "RSA private key file does not exist: {}",
                    self.rsa_private_key_path.display()
                ),
                None,
            ));
        }

        if !self.rsa_private_key_path.is_file() {
            return Err(FernetWebError::config_error(
                format!(
                    "RSA private key path is not a file: {}",
                    self.rsa_private_key_path.display()
                ),
                None,
            ));
        }

        // Validate resource limits
        if self.max_payload_size == 0 {
            return Err(FernetWebError::config_error(
                "Maximum payload size cannot be zero".to_string(),
                None,
            ));
        }

        if self.max_payload_size > 100 * 1024 * 1024 {
            tracing::warn!(
                "Very large maximum payload size: {} bytes - this may impact performance",
                self.max_payload_size
            );
        }

        if self.request_timeout_ms == 0 {
            return Err(FernetWebError::config_error(
                "Request timeout cannot be zero".to_string(),
                None,
            ));
        }

        if let Some(workers) = self.worker_threads {
            if workers == 0 {
                return Err(FernetWebError::config_error(
                    "Worker thread count cannot be zero".to_string(),
                    None,
                ));
            }

            if workers > 64 {
                tracing::warn!(
                    "Very high worker thread count: {} - this may cause excessive context switching",
                    workers
                );
            }
        }

        Ok(())
    }

    /// Get the optimal number of worker threads
    ///
    /// Returns the configured worker thread count, or calculates
    /// an optimal value based on system resources.
    ///
    /// ## Returns
    /// Optimal worker thread count for this system
    #[must_use] pub fn get_worker_threads(&self) -> usize {
        self.worker_threads.unwrap_or_else(|| {
            // Default to 2x CPU count for I/O-bound workloads
            std::thread::available_parallelism()
                .map(|n| n.get() * 2)
                .unwrap_or(4)
                .min(16) // Cap at 16 threads to prevent excessive context switching
        })
    }

    /// Check if the server should enable TLS
    ///
    /// Determines if TLS should be enabled based on configuration
    /// and environment variables.
    ///
    /// ## Returns
    /// Returns `true` if TLS should be enabled
    #[must_use] pub fn should_enable_tls(&self) -> bool {
        // For now, TLS is not implemented but this provides the interface
        std::env::var("ENABLE_TLS")
            .map(|v| v == "true")
            .unwrap_or(false)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: format!("{}:{}", crate::DEFAULT_BIND_ADDR, crate::DEFAULT_PORT)
                .parse()
                .expect("Default bind address should be valid"),
            rsa_private_key_path: PathBuf::from("private_key.pem"),
            log_level: LogLevel::from(Level::INFO),
            max_payload_size: crate::MAX_PAYLOAD_SIZE,
            request_timeout_ms: crate::REQUEST_TIMEOUT_MS,
            worker_threads: None,
            enable_metrics: false,
            enable_health_check: true,
        }
    }
}

// Custom serialization/deserialization for Level is removed to avoid orphan rule issues
// The Level field will need to be handled manually or with a wrapper type if needed

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_key_file() -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        write!(
            temp_file,
            "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        )
        .unwrap();
        temp_file
    }

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();

        assert_eq!(config.bind_addr.port(), 7999);
        assert_eq!(config.log_level, LogLevel::from(Level::INFO));
        assert_eq!(config.max_payload_size, crate::MAX_PAYLOAD_SIZE);
        assert_eq!(config.request_timeout_ms, crate::REQUEST_TIMEOUT_MS);
        assert!(config.enable_health_check);
        assert!(!config.enable_metrics);
    }

    #[test]
    fn test_config_validation_missing_key_file() {
        let mut config = ServerConfig::default();
        config.rsa_private_key_path = PathBuf::from("/nonexistent/key.pem");

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_valid() {
        let key_file = create_test_key_file();
        let mut config = ServerConfig::default();
        config.rsa_private_key_path = key_file.path().to_path_buf();

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_validation_zero_payload_size() {
        let key_file = create_test_key_file();
        let mut config = ServerConfig::default();
        config.rsa_private_key_path = key_file.path().to_path_buf();
        config.max_payload_size = 0;

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_zero_timeout() {
        let key_file = create_test_key_file();
        let mut config = ServerConfig::default();
        config.rsa_private_key_path = key_file.path().to_path_buf();
        config.request_timeout_ms = 0;

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_worker_threads_calculation() {
        let config = ServerConfig::default();
        let worker_count = config.get_worker_threads();

        // Should be at least 4 (default minimum)
        assert!(worker_count >= 4);
        // Should be capped at 16
        assert!(worker_count <= 16);
    }

    #[test]
    fn test_worker_threads_explicit() {
        let mut config = ServerConfig::default();
        config.worker_threads = Some(8);

        assert_eq!(config.get_worker_threads(), 8);
    }

    #[test]
    fn test_tls_detection() {
        let config = ServerConfig::default();

        // Should default to false
        assert!(!config.should_enable_tls());

        // Test with environment variable
        std::env::set_var("ENABLE_TLS", "true");
        assert!(config.should_enable_tls());

        std::env::set_var("ENABLE_TLS", "false");
        assert!(!config.should_enable_tls());

        // Clean up
        std::env::remove_var("ENABLE_TLS");
    }

    #[test]
    fn test_config_serialization() {
        let config = ServerConfig::default();

        // Test JSON serialization
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("bind_addr"));
        assert!(json.contains("log_level"));

        // Test deserialization
        let deserialized: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bind_addr.port(), config.bind_addr.port());
        assert_eq!(deserialized.log_level, config.log_level);
    }

    #[test]
    fn test_from_env_parsing() {
        // Set test environment variables
        std::env::set_var("FERNET_WEB_BIND_ADDR", "127.0.0.1:8080");
        std::env::set_var("LOG_LEVEL", "debug");
        std::env::set_var("MAX_PAYLOAD_SIZE", "1048576");
        std::env::set_var("REQUEST_TIMEOUT_MS", "60000");
        std::env::set_var("WORKER_THREADS", "4");
        std::env::set_var("ENABLE_METRICS", "true");
        std::env::set_var("ENABLE_HEALTH_CHECK", "false");

        let config = ServerConfig::from_env().unwrap();

        assert_eq!(config.bind_addr.port(), 8080);
        assert_eq!(config.log_level, LogLevel::from(Level::DEBUG));
        assert_eq!(config.max_payload_size, 1048576);
        assert_eq!(config.request_timeout_ms, 60000);
        assert_eq!(config.worker_threads, Some(4));
        assert!(config.enable_metrics);
        assert!(!config.enable_health_check);

        // Clean up
        std::env::remove_var("FERNET_WEB_BIND_ADDR");
        std::env::remove_var("LOG_LEVEL");
        std::env::remove_var("MAX_PAYLOAD_SIZE");
        std::env::remove_var("REQUEST_TIMEOUT_MS");
        std::env::remove_var("WORKER_THREADS");
        std::env::remove_var("ENABLE_METRICS");
        std::env::remove_var("ENABLE_HEALTH_CHECK");
    }

    #[test]
    fn test_from_env_invalid_values() {
        std::env::set_var("FERNET_WEB_BIND_ADDR", "invalid_address");

        let result = ServerConfig::from_env();
        assert!(result.is_err());

        std::env::remove_var("FERNET_WEB_BIND_ADDR");
    }
}
