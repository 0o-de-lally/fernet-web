//! # Cryptographic Operations Benchmarks
//!
//! Comprehensive benchmarks for RSA key exchange and Fernet encryption/decryption operations.
//! These benchmarks validate that the server meets performance targets and detect regressions.
//!
//! ## Performance Targets
//!
//! - **RSA 2048-bit**: <5ms per operation
//! - **RSA 4096-bit**: <15ms per operation  
//! - **Fernet Decrypt**: <1ms for 1KB payload, <10ms for 1MB payload
//! - **Memory Usage**: <100KB per operation
//!
//! ## Regression Detection
//!
//! These benchmarks should be run on every commit to detect performance regressions.
//! Any increase >10% in latency should be investigated.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fernet_web::crypto::{CryptoService, FernetKey};
use std::io::Write;
use std::time::Duration;
use tempfile::NamedTempFile;

// Test RSA private key for benchmarking (DO NOT use in production)
const BENCHMARK_RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6
zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQK
CAQEAsamplekeyfortest4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNL
O6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBA
QKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNk
yTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiW
jNLO6zI6O4r1wNkyTCBPOI+R+wIBAQ==
-----END RSA PRIVATE KEY-----"#;

/// Create a temporary RSA key file for benchmarking
fn create_benchmark_key_file() -> NamedTempFile {
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(temp_file, "{}", BENCHMARK_RSA_KEY).expect("Failed to write key");
    temp_file
}

/// Create a crypto service for benchmarking
async fn create_benchmark_crypto_service() -> CryptoService {
    let key_file = create_benchmark_key_file();
    CryptoService::new(key_file.path())
        .await
        .expect("Failed to create crypto service for benchmarking")
}

/// Benchmark crypto service initialization
fn bench_crypto_service_creation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("crypto_service_creation", |b| {
        b.iter(|| {
            let _service = black_box(rt.block_on(create_benchmark_crypto_service()));
        });
    });
}

/// Benchmark RSA key validation
fn bench_rsa_key_validation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    c.bench_function("rsa_key_validation", |b| {
        b.iter(|| {
            let result = crypto_service.validate_key();
            black_box(result)
        });
    });
}

/// Benchmark RSA symmetric key decryption with various input sizes
fn bench_rsa_decrypt_symmetric_key(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    // Test different encrypted key sizes (base64 encoded)
    let test_keys = vec![
        ("small", "dGVzdGtleTE="), // "testkey1" base64 encoded
        ("medium", "dGhpc2lzYWxvbmdlcnRlc3RrZXlmb3JiZW5jaG1hcmtpbmc="), // longer test key
        ("large", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // Very long key (will likely fail but tests performance)
    ];

    let mut group = c.benchmark_group("rsa_decrypt_symmetric_key");

    for (name, key) in test_keys {
        group.bench_with_input(BenchmarkId::new("decrypt", name), &key, |b, key| {
            b.iter(|| {
                // This will likely fail with stub implementation, but measures performance
                let result = rt.block_on(crypto_service.decrypt_symmetric_key(key));
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark Fernet key creation and validation
fn bench_fernet_key_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("fernet_key_operations");

    // Benchmark key creation from bytes
    let key_bytes = [42u8; 32];
    group.bench_function("create_from_bytes", |b| {
        b.iter(|| {
            let result = FernetKey::from_bytes(black_box(&key_bytes));
            black_box(result)
        });
    });

    // Benchmark key string generation
    let fernet_key = FernetKey::from_bytes(&key_bytes).unwrap();
    group.bench_function("get_key_string", |b| {
        b.iter(|| {
            let key_string = fernet_key.get_key_string();
            black_box(key_string)
        });
    });

    // Benchmark key bytes recovery
    group.bench_function("get_key_bytes", |b| {
        b.iter(|| {
            let result = fernet_key.get_key_bytes();
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark Fernet payload decryption with various payload sizes
fn bench_fernet_payload_decryption(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    // Test payloads of different sizes
    let payload_sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
    ];

    let mut group = c.benchmark_group("fernet_payload_decryption");

    for (name, size) in payload_sizes {
        group.throughput(Throughput::Bytes(size as u64));

        let test_key = [42u8; 32];
        let test_payload = "test_token_".repeat(size / 11); // Approximate size

        group.bench_with_input(
            BenchmarkId::new("decrypt", name),
            &(test_key, test_payload),
            |b, (key, payload)| {
                b.iter(|| {
                    // This will likely fail with stub implementation, but measures performance
                    let result = rt.block_on(crypto_service.decrypt_payload(key, payload));
                    black_box(result)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark concurrent crypto operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = std::sync::Arc::new(rt.block_on(create_benchmark_crypto_service()));

    let mut group = c.benchmark_group("concurrent_operations");

    // Benchmark concurrent RSA operations
    let concurrency_levels = vec![1, 2, 4, 8, 16];

    for concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("rsa_concurrent", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for i in 0..concurrency {
                            let service = std::sync::Arc::clone(&crypto_service);
                            let handle = tokio::spawn(async move {
                                let result = service
                                    .decrypt_symmetric_key(&format!("test_key_{}", i))
                                    .await;
                                black_box(result)
                            });
                            handles.push(handle);
                        }

                        // Wait for all operations to complete
                        for handle in handles {
                            let _ = handle.await;
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_usage(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    c.bench_function("memory_pattern_rsa_decrypt", |b| {
        b.iter(|| {
            // This benchmark helps identify memory allocation patterns
            let result = rt.block_on(crypto_service.decrypt_symmetric_key("test_key"));
            black_box(result)
        });
    });

    c.bench_function("memory_pattern_fernet_decrypt", |b| {
        b.iter(|| {
            let key = [42u8; 32];
            let result = rt.block_on(crypto_service.decrypt_payload(&key, "test_payload"));
            black_box(result)
        });
    });
}

/// Benchmark error handling performance
fn bench_error_handling(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    let mut group = c.benchmark_group("error_handling");

    // Benchmark RSA error handling
    group.bench_function("rsa_invalid_input", |b| {
        b.iter(|| {
            let result = rt.block_on(crypto_service.decrypt_symmetric_key("invalid_base64!"));
            black_box(result) // Should be an error
        });
    });

    // Benchmark Fernet error handling
    group.bench_function("fernet_invalid_key_size", |b| {
        b.iter(|| {
            let invalid_key = [0u8; 16]; // Wrong size
            let result = rt.block_on(crypto_service.decrypt_payload(&invalid_key, "test"));
            black_box(result) // Should be an error
        });
    });

    // Benchmark Fernet error handling with valid key but invalid token
    group.bench_function("fernet_invalid_token", |b| {
        b.iter(|| {
            let valid_key = [42u8; 32];
            let result = rt.block_on(crypto_service.decrypt_payload(&valid_key, "invalid_token"));
            black_box(result) // Should be an error
        });
    });

    group.finish();
}

/// Benchmark metrics collection overhead
fn bench_metrics_collection(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    c.bench_function("metrics_collection", |b| {
        b.iter(|| {
            let metrics = crypto_service.get_metrics();
            black_box(metrics)
        });
    });
}

/// Benchmark public key retrieval
fn bench_public_key_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    c.bench_function("get_public_key_pem", |b| {
        b.iter(|| {
            let public_key = crypto_service.get_public_key_pem();
            black_box(public_key)
        });
    });
}

/// Comprehensive benchmark comparing operations at different scales
fn bench_scalability(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let crypto_service = rt.block_on(create_benchmark_crypto_service());

    let mut group = c.benchmark_group("scalability");

    // Set longer measurement time for scalability tests
    group.measurement_time(Duration::from_secs(10));

    let operation_counts = vec![1, 10, 100, 1000];

    for count in operation_counts {
        group.bench_with_input(
            BenchmarkId::new("sequential_operations", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    rt.block_on(async {
                        for i in 0..count {
                            let result = crypto_service
                                .decrypt_symmetric_key(&format!("key_{}", i))
                                .await;
                            black_box(result);
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

// Configure benchmarks with appropriate settings
criterion_group!(
    name = crypto_benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(5))
        .sample_size(100)
        .warm_up_time(Duration::from_secs(2));
    targets =
        bench_crypto_service_creation,
        bench_rsa_key_validation,
        bench_rsa_decrypt_symmetric_key,
        bench_fernet_key_operations,
        bench_fernet_payload_decryption,
        bench_concurrent_operations,
        bench_memory_usage,
        bench_error_handling,
        bench_metrics_collection,
        bench_public_key_operations,
        bench_scalability
);

criterion_main!(crypto_benches);
