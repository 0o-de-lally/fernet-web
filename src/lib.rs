//! # Fernet Web Server Library
//!
//! A high-performance web server library for authenticating and decrypting message payloads
//! encrypted with Fernet symmetric encryption. This library provides a generic decryption
//! server that can be integrated into applications requiring secure payload handling.
//!
//! ## Features
//!
//! - **High Performance**: Built on Hyper for maximum throughput (>10k req/sec target)
//! - **Security First**: RSA key exchange with Fernet symmetric encryption
//! - **Generic Payloads**: Library users define their own payload types
//! - **Comprehensive Error Handling**: Secure error responses without information leakage
//! - **Production Ready**: Designed for Linux and AWS Lambda deployment
//!
//! ## Architecture
//!
//! The library follows a modular design with clear separation of concerns:
//!
//! - [`error`] - Custom error types with security-focused error handling
//! - [`crypto`] - RSA key exchange and Fernet encryption/decryption operations
//! - [`server`] - Hyper-based HTTP server with configurable endpoints
//!
//! ## Security Model
//!
//! 1. **Initial Key Exchange**: Client sends RSA-encrypted symmetric key
//! 2. **Authentication**: Validator hotkey and UUID-based identification
//! 3. **Payload Decryption**: Fernet decryption of message payloads
//! 4. **Error Handling**: Generic error responses prevent information leakage
//!
//! ## Performance Characteristics
//!
//! - **Latency Target**: < 10ms p99 for decrypt operations
//! - **Memory Usage**: < 50MB baseline, zero-copy operations where possible
//! - **CPU Efficiency**: Optimized crypto operations with minimal overhead
//! - **Async/Await**: Non-blocking I/O throughout the entire stack
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use fernet_web::{ServerConfig, start_server};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ServerConfig {
//!         bind_addr: "0.0.0.0:7999".parse::<SocketAddr>()?,
//!         rsa_private_key_path: "private_key.pem".into(),
//!         log_level: tracing::Level::INFO,
//!     };
//!     
//!     start_server(config).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Thread Safety
//!
//! All public APIs are thread-safe and designed for concurrent usage in multi-threaded
//! environments. Internal state uses appropriate synchronization primitives.

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![allow(clippy::module_name_repetitions)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod crypto;
pub mod error;
pub mod server;

// Re-export commonly used types for convenience
pub use error::{FernetWebError, Result};
pub use server::{start_server, ServerConfig};

/// Version information for the library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default server port as specified in the README
pub const DEFAULT_PORT: u16 = 7999;

/// Default bind address for the server
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0";

/// Maximum payload size in bytes (16MB to prevent `DoS` attacks)
///
/// This limit prevents memory exhaustion attacks while allowing
/// reasonable payload sizes for most use cases.
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Timeout for individual request processing in milliseconds
///
/// Requests exceeding this timeout will be terminated to prevent
/// resource exhaustion and ensure consistent response times.
pub const REQUEST_TIMEOUT_MS: u64 = 30_000;

/// RSA key minimum size in bits for security
///
/// Keys below this size are considered insecure and will be rejected
/// to maintain cryptographic security standards.
pub const MIN_RSA_KEY_SIZE: usize = 2048;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_reasonable() {
        // Verify our constants make sense
        assert!(MAX_PAYLOAD_SIZE > 1024); // At least 1KB
        assert!(MAX_PAYLOAD_SIZE < 100 * 1024 * 1024); // Less than 100MB
        assert!(REQUEST_TIMEOUT_MS > 1000); // At least 1 second
        assert!(REQUEST_TIMEOUT_MS < 300_000); // Less than 5 minutes
        assert!(MIN_RSA_KEY_SIZE >= 2048); // Industry minimum
        assert_eq!(DEFAULT_PORT, 7999); // Matches README
    }

    #[test]
    fn test_version_is_valid() {
        // Ensure version string is not empty
        assert!(!VERSION.is_empty());

        // Basic semver validation (should have at least one dot)
        assert!(VERSION.contains('.'));
    }
}
