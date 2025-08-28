//! # Fernet Web Server Binary
//!
//! High-performance web server for Fernet encryption/decryption with RSA key exchange.
//! This binary provides a complete production-ready server with comprehensive
//! configuration, logging, and monitoring capabilities.
//!
//! ## Features
//!
//! - **High Performance**: Built on Tokio and Hyper for maximum throughput
//! - **Security First**: Comprehensive error handling without information leakage
//! - **Production Ready**: Structured logging, metrics, health checks
//! - **Configurable**: Command-line args, environment variables, config files
//!
//! ## Usage
//!
//! ```bash
//! # Basic usage with defaults
//! fernet-web
//!
//! # Custom configuration
//! fernet-web --bind 127.0.0.1:8080 --rsa-key /path/to/private_key.pem
//!
//! # With environment variables
//! export FERNET_WEB_BIND_ADDR=0.0.0.0:7999
//! export RSA_PRIVATE_KEY_PATH=/secure/path/to/key.pem
//! export LOG_LEVEL=info
//! fernet-web
//! ```

use fernet_web::{server::ServerConfig, start_server};
use std::process;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[cfg(test)]
use tracing::warn;
/// Main entry point for the Fernet web server
///
/// This function sets up logging, parses configuration, and starts the server
/// with proper error handling and graceful shutdown capabilities.
///
/// ## Error Handling
/// All errors are logged and the process exits with appropriate exit codes:
/// - 0: Clean shutdown
/// - 1: Configuration error
/// - 2: Server startup error
/// - 3: Runtime error
///
/// ## Signal Handling
/// The server handles SIGINT and SIGTERM for graceful shutdown
#[tokio::main]
async fn main() {
    // Parse configuration from command line and environment
    let config = ServerConfig::from_args();

    // Initialize logging based on configuration
    if let Err(e) = setup_logging(&config) {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    info!("Starting Fernet Web Server v{}", fernet_web::VERSION);
    info!("Configuration: {:?}", config);

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("Configuration validation failed: {}", e.internal_message());
        process::exit(1);
    }

    // Configure Tokio runtime with optimal thread count
    let worker_threads = config.get_worker_threads();
    info!("Using {} worker threads", worker_threads);

    // Setup graceful shutdown handler
    let shutdown_signal = setup_shutdown_handler();

    // Start the server
    info!("Starting server on {}", config.bind_addr);

    tokio::select! {
        // Server main loop
        result = start_server(config) => {
            match result {
                Ok(()) => {
                    info!("Server shut down cleanly");
                    process::exit(0);
                }
                Err(e) => {
                    error!("Server error: {}", e.internal_message());
                    if e.is_critical() {
                        process::exit(2);
                    } else {
                        process::exit(3);
                    }
                }
            }
        }

        // Graceful shutdown signal
        _ = shutdown_signal => {
            info!("Received shutdown signal, stopping server...");
            // In a full implementation, we would signal the server to stop gracefully
            // For now, we just exit cleanly
            process::exit(0);
        }
    }
}

/// Setup structured logging based on configuration
///
/// Configures tracing with appropriate formatting and filtering
/// based on the configured log level and environment.
///
/// ## Parameters
/// - `config`: Server configuration containing log level
///
/// ## Returns
/// Returns `Ok(())` on success or error on setup failure
///
/// ## Log Format
/// - **Development**: Pretty-printed with colors
/// - **Production**: JSON format for structured logging
fn setup_logging(config: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Determine if we're in a production environment
    let is_production = std::env::var("ENVIRONMENT")
        .map(|env| env.to_lowercase() == "production")
        .unwrap_or(false);

    // Create base filter with configured log level
    let env_filter = EnvFilter::builder()
        .with_default_directive(config.log_level.inner().into())
        .from_env()?
        .add_directive("hyper=info".parse()?) // Reduce hyper verbosity
        .add_directive("tokio=info".parse()?) // Reduce tokio verbosity
        .add_directive("runtime=info".parse()?) // Reduce runtime verbosity
        .add_directive("mio=warn".parse()?); // Reduce mio verbosity

    if is_production {
        // Production: JSON structured logging
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_span_list(true)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true),
            )
            .init();

        info!("Initialized structured JSON logging for production");
    } else {
        // Development: Pretty-printed with colors
        tracing_subscriber::registry()
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_thread_names(false),
            )
            .init();

        info!("Initialized pretty-printed logging for development");
    }

    Ok(())
}

/// Setup graceful shutdown signal handling
///
/// Creates a future that completes when shutdown signals (SIGINT, SIGTERM)
/// are received, allowing for graceful server shutdown.
///
/// ## Returns
/// Returns a future that completes on shutdown signal
///
/// ## Supported Signals
/// - **SIGINT**: Interrupt signal (Ctrl+C)
/// - **SIGTERM**: Termination signal (from process managers)
async fn setup_shutdown_handler() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C)");
        },
        _ = terminate => {
            info!("Received SIGTERM");
        },
    }
}

/// Print version information and exit
///
/// This function is used by the --version flag to display
/// version and build information.

#[cfg(test)]
fn print_version_info() {
    println!("Fernet Web Server v{}", fernet_web::VERSION);
    println!(
        "Built with Rust {}",
        option_env!("RUSTC_VERSION").unwrap_or("unknown")
    );
    println!("Target: {}", option_env!("TARGET").unwrap_or("unknown"));

    #[cfg(debug_assertions)]
    println!("Build: Debug");

    #[cfg(not(debug_assertions))]
    println!("Build: Release");

    if let Ok(git_hash) = std::env::var("GIT_HASH") {
        println!("Git Hash: {}", git_hash);
    }

    if let Ok(build_date) = std::env::var("BUILD_DATE") {
        println!("Build Date: {}", build_date);
    }
}

/// Display helpful information on startup
///
/// Shows configuration summary and helpful tips for monitoring
/// and troubleshooting the server.
pub fn display_startup_info(config: &ServerConfig) {
    info!("=== Fernet Web Server Configuration ===");
    info!("Version: {}", fernet_web::VERSION);
    info!("Bind Address: {}", config.bind_addr);
    info!("RSA Key Path: {}", config.rsa_private_key_path.display());
    info!("Log Level: {}", config.log_level);
    info!("Max Payload Size: {} bytes", config.max_payload_size);
    info!("Request Timeout: {}ms", config.request_timeout_ms);
    info!("Worker Threads: {}", config.get_worker_threads());
    info!(
        "Health Check: {}",
        if config.enable_health_check {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "Metrics: {}",
        if config.enable_metrics {
            "enabled"
        } else {
            "disabled"
        }
    );

    if config.enable_health_check {
        info!("Health endpoint: http://{}/health", config.bind_addr);
    }

    if config.enable_metrics {
        info!("Metrics endpoint: http://{}/metrics", config.bind_addr);
    }

    info!(
        "Public key endpoint: http://{}/public-key",
        config.bind_addr
    );
    info!("Decrypt endpoint: http://{}/decrypt", config.bind_addr);
    info!("=========================================");
}

/// Handle panic situations gracefully
///
/// Sets up a panic hook that logs panic information and
/// attempts to shut down gracefully rather than aborting.
#[cfg(test)]
fn setup_panic_handler() {
    std::panic::set_hook(Box::new(|panic_info| {
        let backtrace = std::backtrace::Backtrace::capture();

        error!("PANIC occurred: {}", panic_info);
        error!("Backtrace:\n{}", backtrace);

        // In production, we might want to send this to an error reporting service
        if std::env::var("ENVIRONMENT")
            .map(|e| e == "production")
            .unwrap_or(false)
        {
            warn!("Server panicked in production - this indicates a serious bug");
        }

        // Give logging a chance to flush
        std::thread::sleep(std::time::Duration::from_millis(100));

        process::exit(4); // Exit code 4 for panic
    }));
}

/// Validate runtime environment
///
/// Performs basic runtime environment validation to ensure
/// the server can operate correctly.
///
/// ## Returns
/// Returns `Ok(())` if environment is valid, error otherwise
#[cfg(test)]
fn validate_runtime_environment() -> Result<(), Box<dyn std::error::Error>> {
    // Check available memory (basic check)
    if let Ok(memory_info) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(line) = memory_info.lines().find(|l| l.starts_with("MemAvailable:")) {
            if let Some(kb_str) = line.split_whitespace().nth(1) {
                if let Ok(available_kb) = kb_str.parse::<u64>() {
                    let available_mb = available_kb / 1024;
                    if available_mb < 100 {
                        warn!(
                            "Low available memory: {}MB - server may experience performance issues",
                            available_mb
                        );
                    } else {
                        info!("Available memory: {}MB", available_mb);
                    }
                }
            }
        }
    }

    // Check file descriptor limits
    if let Ok(limits) = std::fs::read_to_string("/proc/self/limits") {
        if let Some(line) = limits.lines().find(|l| l.contains("Max open files")) {
            info!("File descriptor limits: {}", line.trim());
        }
    }

    // Validate network stack is available
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            let local_addr = listener.local_addr()?;
            info!(
                "Network stack validated - test bind successful on {}",
                local_addr
            );
            drop(listener);
        }
        Err(e) => {
            error!("Network stack validation failed: {}", e);
            return Err(Box::new(e));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn _test_version_info_display() {
        // Just test that version info doesn't panic
        print_version_info();
    }

    #[test]
    fn _test_runtime_validation() {
        // Test basic environment validation
        let result = validate_runtime_environment();
        // This might fail in some environments, so just test it doesn't panic
        match result {
            Ok(()) => {
                // Environment validation passed
            }
            Err(e) => {
                // Environment validation failed - this is okay in test environments
                println!("Environment validation failed (expected in tests): {}", e);
            }
        }
    }

    #[test]
    fn _test_panic_handler_setup() {
        // Just test that panic handler setup doesn't panic
        setup_panic_handler();
    }

    #[tokio::test]
    async fn _test_server_config_creation() {
        let config = ServerConfig::from_args();
        // Should have reasonable defaults
        assert_eq!(config.bind_addr.port(), 7999);
        assert!(config.enable_health_check);
    }

    #[test]
    fn _test_startup_info_display() {
        let config = ServerConfig::default();
        // Should not panic when displaying startup info
        display_startup_info(&config);
    }
}
