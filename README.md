# Fernet Web Server

A high-performance web server written in Rust that authenticates and decrypts message payloads encrypted with Fernet symmetric encryption. Built with Hyper for maximum performance and designed for production deployment on Linux and AWS environments.

## Overview

This server implements secure communication patterns using:
- **RSA asymmetric encryption** for initial symmetric key exchange
- **Fernet symmetric encryption** for payload decryption
- **Rust Hyper** for high-performance HTTP handling
- **Test-driven development** with comprehensive benchmarking

## Architecture

The server follows a modular design inspired by the [rayonlabs/nineteen](https://github.com/rayonlabs/nineteen/blob/production/miner/server.py) and [rayonlabs/fiber](https://github.com/rayonlabs/fiber/blob/production/fiber/encrypted/miner/security/encryption.py) implementations:

- **Authentication Layer**: RSA-based key exchange with OAEP padding
- **Encryption Layer**: Fernet symmetric encryption for message payloads
- **Web Layer**: Hyper-based HTTP server with configurable endpoints
- **Security Layer**: Header-based authentication with comprehensive error handling

## Security Model

1. **Initial Key Exchange**: Client sends RSA-encrypted symmetric key
2. **Authentication**: Validator hotkey and UUID-based identification
3. **Payload Decryption**: Fernet decryption of message payloads
4. **Error Handling**: Secure failure modes without information leakage

## Development Requirements

- **Rust Version**: Stable Rust (latest stable release)
- **Target Platforms**: Linux x86_64, AWS Lambda (linux-musl)
- **Development Approach**: Test-driven development (TDD)
- **Performance**: Continuous benchmarking with regression detection

## Build and Development

### Prerequisites

```bash
# Install Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable

# Add cross-compilation targets
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-musl
```

### Building

```bash
# Development build
cargo build

# Release build for Linux
cargo build --release --target x86_64-unknown-linux-gnu

# AWS-optimized build
cargo build --release --target x86_64-unknown-linux-musl
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Test with coverage
cargo test --all-features
```

### Benchmarking

```bash
# Run benchmarks
cargo bench

# Run specific benchmark
cargo bench bench_name

# Generate benchmark reports
cargo bench -- --output-format html
```

## Configuration

Environment variables:
- `FERNET_WEB_PORT`: Server port (default: 7999)
- `FERNET_WEB_HOST`: Bind address (default: 0.0.0.0)
- `RSA_PRIVATE_KEY_PATH`: Path to RSA private key file
- `LOG_LEVEL`: Logging level (debug, info, warn, error)

## Generic Payload Types

**Important**: This library provides a generic decryption server. The message payload type is **always generic** - developers who import this library must define their own payload types in their application code. 

Type definition responsibility:
- **Library users** define payload struct/types in their own code
- **Configuration** of payload types via CLI arguments or config files
- **Deserialization** handled by the importing application after decryption

### Testing Payload Structure

For testing purposes, use a dummy struct that matches this function signature pattern:

```rust
// Example test payload structure based on Python equivalent
struct TestPayload {
    // Define fields matching your decrypt_general_payload requirements
}

// Headers that must be present (based on Python function args):
// - symmetric_key_uuid: String (Header)
// - validator_hotkey: String (Header) 
// - miner_hotkey: String (Header)
// - encrypted_payload: Vec<u8> (Body)
```

## API Endpoints

### POST /decrypt
Decrypt Fernet-encrypted payloads after RSA key exchange. Returns raw decrypted bytes that the importing application must deserialize to their specific payload type.

**Headers:**
- `symmetric-key-uuid`: Symmetric key identifier
- `validator-hotkey`: Validator identification
- `miner-hotkey`: Miner identification

**Body:** Fernet-encrypted payload (bytes)

**Response:** Decrypted payload bytes (application must deserialize to their specific type)

## Deployment

### Docker
```dockerfile
FROM rust:1-alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/fernet-web /usr/local/bin/
EXPOSE 7999
CMD ["fernet-web"]
```

### AWS Lambda
Use the `lambda-runtime` crate for serverless deployment with the `x86_64-unknown-linux-musl` target.

## CI/CD

GitHub Actions automatically:
- Run unit tests on all commits
- Execute benchmark suite
- Report performance metrics
- Build for multiple targets (Linux, AWS)
- Generate coverage reports

## Performance Goals

- **Latency**: < 10ms p99 for decrypt operations
- **Throughput**: > 10k requests/second
- **Memory**: < 50MB baseline usage
- **CPU**: Efficient crypto operations with minimal overhead

## Security Considerations

- RSA keys should be 2048+ bits
- Fernet keys are 256-bit URL-safe base64 encoded
- All decryption failures return generic 401 errors
- No sensitive information in logs or error messages
- Secure key storage and rotation practices

## Contributing

1. Write tests first (TDD approach)
2. Ensure all benchmarks pass without regression
3. Follow Rust security best practices
4. Update documentation for API changes