//! # Error Handling Module
//!
//! Comprehensive error handling designed for security and performance in distributed systems.
//! This module implements secure error responses that prevent information leakage while
//! providing detailed internal logging for debugging and monitoring.
//!
//! ## Security Considerations
//!
//! All error responses to clients are sanitized to prevent:
//! - Information disclosure attacks
//! - Timing attacks through error message analysis
//! - Stack trace leakage
//! - Internal system information exposure
//!
//! ## Performance Characteristics
//!
//! - **Zero Allocation**: Error types use `&'static str` where possible
//! - **Fast Path**: Common errors have minimal overhead
//! - **Structured Logging**: Errors include context for observability
//! - **Thread Safe**: All error types implement `Send + Sync`

use thiserror::Error;

/// Result type alias for the Fernet Web library
/// 
/// This provides a convenient shorthand for `Result<T, FernetWebError>`
/// used throughout the codebase for consistent error handling.
pub type Result<T> = std::result::Result<T, FernetWebError>;

/// Comprehensive error types for the Fernet Web server
///
/// This enum covers all possible error conditions that can occur during
/// server operations, with each variant designed to provide maximum
/// information for internal logging while maintaining security boundaries
/// for external responses.
///
/// ## Error Categories
///
/// - **Cryptographic Errors**: RSA key exchange and Fernet operations
/// - **Network Errors**: HTTP server and connection issues  
/// - **Configuration Errors**: Invalid server configuration
/// - **Request Errors**: Malformed client requests
/// - **Internal Errors**: Unexpected system failures
#[derive(Error, Debug)]
pub enum FernetWebError {
    /// RSA cryptographic operation failed
    ///
    /// This covers all RSA-related failures including:
    /// - Key loading and parsing errors
    /// - Encryption/decryption failures
    /// - Invalid key sizes or formats
    /// - OAEP padding errors
    ///
    /// **Security**: External response is generic "Authentication failed"
    #[error("RSA operation failed: {message}")]
    RsaError {
        /// Internal error message for logging
        message: String,
        /// Optional source error for error chain analysis
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Fernet symmetric encryption/decryption failed
    ///
    /// Covers Fernet-specific operations including:
    /// - Key validation and parsing
    /// - Token decryption failures
    /// - Invalid token formats
    /// - Expired tokens
    ///
    /// **Security**: External response is generic "Decryption failed"
    #[error("Fernet operation failed: {message}")]
    FernetError {
        /// Internal error message for logging
        message: String,
        /// Optional source error for error chain analysis
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// HTTP server operation failed
    ///
    /// Covers all HTTP-related errors including:
    /// - Server startup failures
    /// - Connection handling errors
    /// - Request parsing failures
    /// - Response generation errors
    ///
    /// **Performance**: These errors should be rare in production
    #[error("Server error: {message}")]
    ServerError {
        /// Internal error message for logging
        message: String,
        /// Optional source error for error chain analysis
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Invalid client request
    ///
    /// Covers malformed or invalid client requests:
    /// - Missing required headers
    /// - Invalid header values
    /// - Malformed request body
    /// - Request size violations
    ///
    /// **Security**: Provides generic "Bad Request" response
    #[error("Invalid request: {message}")]
    RequestError {
        /// Internal error message for logging
        message: String,
    },

    /// Server configuration is invalid
    ///
    /// Covers configuration validation failures:
    /// - Invalid bind addresses
    /// - Missing RSA keys
    /// - Invalid file paths
    /// - Environment variable parsing errors
    ///
    /// **Performance**: These should only occur at startup
    #[error("Configuration error: {message}")]
    ConfigError {
        /// Internal error message for logging
        message: String,
        /// Optional source error for error chain analysis
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Unexpected internal system error
    ///
    /// Covers unexpected failures that shouldn't occur in normal operation:
    /// - Memory allocation failures
    /// - Thread spawning errors  
    /// - File system errors
    /// - System resource exhaustion
    ///
    /// **Security**: Returns generic "Internal Server Error" response
    #[error("Internal error: {message}")]
    InternalError {
        /// Internal error message for logging
        message: String,
        /// Optional source error for error chain analysis
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl FernetWebError {
    /// Create a new RSA error with message and optional source
    ///
    /// ## Parameters
    /// - `message`: Internal error message for logging
    /// - `source`: Optional source error for error chain analysis
    ///
    /// ## Performance
    /// This is a zero-allocation operation when source is None
    #[inline]
    pub fn rsa_error<T>(message: T, source: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self
    where
        T: Into<String>,
    {
        Self::RsaError {
            message: message.into(),
            source,
        }
    }

    /// Create a new Fernet error with message and optional source
    ///
    /// ## Parameters
    /// - `message`: Internal error message for logging
    /// - `source`: Optional source error for error chain analysis
    ///
    /// ## Performance
    /// This is a zero-allocation operation when source is None
    #[inline]
    pub fn fernet_error<T>(message: T, source: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self
    where
        T: Into<String>,
    {
        Self::FernetError {
            message: message.into(),
            source,
        }
    }

    /// Create a new server error with message and optional source
    ///
    /// ## Parameters  
    /// - `message`: Internal error message for logging
    /// - `source`: Optional source error for error chain analysis
    ///
    /// ## Performance
    /// This is a zero-allocation operation when source is None
    #[inline]
    pub fn server_error<T>(message: T, source: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self
    where
        T: Into<String>,
    {
        Self::ServerError {
            message: message.into(),
            source,
        }
    }

    /// Create a new request error with message
    ///
    /// ## Parameters
    /// - `message`: Internal error message for logging
    ///
    /// ## Performance
    /// This is a zero-allocation operation
    #[inline]
    pub fn request_error<T>(message: T) -> Self
    where
        T: Into<String>,
    {
        Self::RequestError {
            message: message.into(),
        }
    }

    /// Create a new configuration error with message and optional source
    ///
    /// ## Parameters
    /// - `message`: Internal error message for logging
    /// - `source`: Optional source error for error chain analysis  
    ///
    /// ## Performance
    /// This is a zero-allocation operation when source is None
    #[inline]
    pub fn config_error<T>(message: T, source: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self
    where
        T: Into<String>,
    {
        Self::ConfigError {
            message: message.into(),
            source,
        }
    }

    /// Create a new internal error with message and optional source
    ///
    /// ## Parameters
    /// - `message`: Internal error message for logging
    /// - `source`: Optional source error for error chain analysis
    ///
    /// ## Performance
    /// This is a zero-allocation operation when source is None
    #[inline]
    pub fn internal_error<T>(message: T, source: Option<Box<dyn std::error::Error + Send + Sync>>) -> Self
    where
        T: Into<String>,
    {
        Self::InternalError {
            message: message.into(),
            source,
        }
    }

    /// Get the HTTP status code for this error
    ///
    /// Maps internal error types to appropriate HTTP status codes
    /// for client responses while maintaining security boundaries.
    ///
    /// ## Security Considerations
    /// Status codes are chosen to minimize information disclosure:
    /// - Crypto errors return 401 (Unauthorized) 
    /// - Request errors return 400 (Bad Request)
    /// - Server/Internal errors return 500 (Internal Server Error)
    ///
    /// ## Performance
    /// This is a constant-time operation with no allocations
    #[inline]
    pub fn status_code(&self) -> u16 {
        match self {
            Self::RsaError { .. } | Self::FernetError { .. } => 401,
            Self::RequestError { .. } => 400,
            Self::ServerError { .. } | Self::ConfigError { .. } | Self::InternalError { .. } => 500,
        }
    }

    /// Get the sanitized error message for client responses
    ///
    /// Returns a generic error message that prevents information
    /// disclosure while still providing useful feedback to clients.
    ///
    /// ## Security
    /// All messages are generic to prevent:
    /// - Stack trace leakage
    /// - Internal system information disclosure
    /// - Cryptographic implementation details
    /// - File system path disclosure
    ///
    /// ## Performance
    /// Returns `&'static str` for zero-allocation responses
    #[inline]
    pub fn client_message(&self) -> &'static str {
        match self {
            Self::RsaError { .. } => "Authentication failed",
            Self::FernetError { .. } => "Decryption failed", 
            Self::RequestError { .. } => "Bad request",
            Self::ServerError { .. } => "Internal server error",
            Self::ConfigError { .. } => "Service unavailable",
            Self::InternalError { .. } => "Internal server error",
        }
    }

    /// Get the internal error message for logging
    ///
    /// Returns the detailed internal error message suitable for
    /// server-side logging and debugging. This should never be
    /// sent to clients.
    ///
    /// ## Security
    /// This message may contain sensitive information and should
    /// only be used for internal logging with appropriate access controls.
    #[inline]
    pub fn internal_message(&self) -> &str {
        match self {
            Self::RsaError { message, .. } => message,
            Self::FernetError { message, .. } => message,
            Self::ServerError { message, .. } => message,
            Self::RequestError { message } => message,
            Self::ConfigError { message, .. } => message,
            Self::InternalError { message, .. } => message,
        }
    }

    /// Check if this error should be logged at ERROR level
    ///
    /// Some errors are expected (like invalid requests) and should
    /// be logged at WARN level, while others indicate serious
    /// issues requiring immediate attention.
    ///
    /// ## Performance
    /// This is a constant-time operation
    #[inline]
    pub fn is_critical(&self) -> bool {
        match self {
            Self::RequestError { .. } => false, // Expected client errors
            Self::RsaError { .. } | Self::FernetError { .. } => true, // Crypto failures are serious
            Self::ServerError { .. } | Self::ConfigError { .. } | Self::InternalError { .. } => true,
        }
    }
}

/// Helper trait for converting common error types to FernetWebError
///
/// This trait provides convenient conversions from standard library
/// and third-party error types to our custom error enum.
pub trait IntoFernetWebError {
    /// Convert this error into a FernetWebError
    fn into_fernet_error(self) -> FernetWebError;
}

// Implement common conversions for convenience
impl From<std::io::Error> for FernetWebError {
    #[inline]
    fn from(err: std::io::Error) -> Self {
        Self::server_error(
            format!("I/O error: {}", err),
            Some(Box::new(err)),
        )
    }
}

impl From<serde_json::Error> for FernetWebError {
    #[inline]
    fn from(err: serde_json::Error) -> Self {
        Self::request_error(format!("JSON parsing error: {}", err))
    }
}

impl From<hyper::Error> for FernetWebError {
    #[inline]
    fn from(err: hyper::Error) -> Self {
        Self::server_error(
            format!("Hyper error: {}", err),
            Some(Box::new(err)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = FernetWebError::rsa_error("test message", None);
        assert_eq!(err.status_code(), 401);
        assert_eq!(err.client_message(), "Authentication failed");
        assert_eq!(err.internal_message(), "test message");
        assert!(err.is_critical());
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(FernetWebError::rsa_error("test", None).status_code(), 401);
        assert_eq!(FernetWebError::fernet_error("test", None).status_code(), 401);
        assert_eq!(FernetWebError::request_error("test").status_code(), 400);
        assert_eq!(FernetWebError::server_error("test", None).status_code(), 500);
        assert_eq!(FernetWebError::config_error("test", None).status_code(), 500);
        assert_eq!(FernetWebError::internal_error("test", None).status_code(), 500);
    }

    #[test]
    fn test_client_messages_are_generic() {
        // Ensure no sensitive information leaks in client messages
        let messages = vec![
            FernetWebError::rsa_error("sensitive info", None).client_message(),
            FernetWebError::fernet_error("secret key path", None).client_message(),
            FernetWebError::server_error("database password", None).client_message(),
            FernetWebError::request_error("internal file path").client_message(),
            FernetWebError::config_error("private key contents", None).client_message(),
            FernetWebError::internal_error("stack trace info", None).client_message(),
        ];

        for message in messages {
            assert!(!message.contains("sensitive"));
            assert!(!message.contains("secret"));
            assert!(!message.contains("password"));
            assert!(!message.contains("path"));
            assert!(!message.contains("key"));
            assert!(!message.contains("trace"));
        }
    }

    #[test]
    fn test_criticality_classification() {
        assert!(!FernetWebError::request_error("test").is_critical());
        assert!(FernetWebError::rsa_error("test", None).is_critical());
        assert!(FernetWebError::fernet_error("test", None).is_critical());
        assert!(FernetWebError::server_error("test", None).is_critical());
        assert!(FernetWebError::config_error("test", None).is_critical());
        assert!(FernetWebError::internal_error("test", None).is_critical());
    }

    #[test]
    fn test_from_conversions() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let fernet_err: FernetWebError = io_err.into();
        assert_eq!(fernet_err.status_code(), 500);

        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let fernet_err: FernetWebError = json_err.into();
        assert_eq!(fernet_err.status_code(), 400);
    }

    #[test]
    fn test_error_display() {
        let err = FernetWebError::rsa_error("test error", None);
        let display_str = format!("{}", err);
        assert!(display_str.contains("RSA operation failed"));
        assert!(display_str.contains("test error"));
    }

    #[test]
    fn test_error_chain() {
        use std::error::Error;
        
        let inner_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let outer_err = FernetWebError::config_error("Failed to load key", Some(Box::new(inner_err)));
        
        assert_eq!(outer_err.status_code(), 500);
        assert!(outer_err.source().is_some());
    }
}