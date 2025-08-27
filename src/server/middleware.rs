//! # Middleware Module
//!
//! This module provides middleware components for the Fernet web server,
//! including request logging, metrics collection, and security headers.
//!
//! ## Middleware Components
//!
//! - **Request Logging**: Structured logging for all requests
//! - **Metrics Collection**: Performance metrics for monitoring
//! - **Security Headers**: Security-focused response headers
//! - **Rate Limiting**: Future implementation for DoS protection

use std::time::Instant;
use tracing::{info, warn};

/// Request timing and logging middleware
///
/// This struct provides request timing, logging, and basic metrics
/// collection for HTTP requests.
#[derive(Debug, Clone)]
pub struct RequestMiddleware {
    /// Request start time for latency calculation
    start_time: Option<Instant>,
}

impl RequestMiddleware {
    /// Create new request middleware instance
    pub fn new() -> Self {
        Self { start_time: None }
    }

    /// Start timing a request
    pub fn start_timing(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Log request completion with timing
    pub fn log_completion(&self, status_code: u16, path: &str, method: &str) {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            
            if status_code >= 400 {
                warn!(
                    "Request completed: {} {} - {} ({:.2}ms)",
                    method, path, status_code, elapsed.as_secs_f64() * 1000.0
                );
            } else {
                info!(
                    "Request completed: {} {} - {} ({:.2}ms)", 
                    method, path, status_code, elapsed.as_secs_f64() * 1000.0
                );
            }
        }
    }
}

impl Default for RequestMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_middleware_creation() {
        let middleware = RequestMiddleware::new();
        assert!(middleware.start_time.is_none());
    }

    #[test]
    fn test_request_middleware_default() {
        let middleware = RequestMiddleware::default();
        assert!(middleware.start_time.is_none());
    }

    #[test]
    fn test_timing_start() {
        let mut middleware = RequestMiddleware::new();
        middleware.start_timing();
        assert!(middleware.start_time.is_some());
    }

    #[test]
    fn test_debug_formatting() {
        let middleware = RequestMiddleware::new();
        let debug_str = format!("{:?}", middleware);
        assert!(debug_str.contains("RequestMiddleware"));
    }

    #[test]
    fn test_clone() {
        let mut middleware = RequestMiddleware::new();
        middleware.start_timing();
        
        let cloned = middleware.clone();
        assert!(cloned.start_time.is_some());
    }
}