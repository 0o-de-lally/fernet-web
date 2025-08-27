//! # End-to-End Performance Benchmarks
//!
//! Comprehensive end-to-end benchmarks that simulate complete workflows
//! from client request to server response. These benchmarks validate
//! the overall system performance under realistic conditions.
//!
//! ## Benchmark Scenarios
//!
//! - **Complete Decrypt Workflow**: RSA key exchange + Fernet decryption
//! - **Error Handling Paths**: Various error conditions and recovery
//! - **Load Testing**: High concurrency and sustained load
//! - **Resource Utilization**: Memory and CPU usage patterns

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fernet_web::{crypto::CryptoService, server::DecryptHandler};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

// Benchmark RSA key
const BENCHMARK_RSA_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6
zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQK
CAQEAsamplekeyfortest4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNL
O6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBA
QKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNk
yTCBPOI+R+wIBAQKCAQEA4qiWjNLO6zI6O4r1wNkyTCBPOI+R+wIBAQKCAQEA4qiW
jNLO6zI6O4r1wNkyTCBPOI+R+wIBAQ==
-----END RSA PRIVATE KEY-----"#;

/// Test scenario configuration
struct BenchmarkScenario {
    name: &'static str,
    payload_size: usize,
    concurrent_requests: usize,
    error_rate_percent: f32,
}

/// Create comprehensive test scenarios
fn create_test_scenarios() -> Vec<BenchmarkScenario> {
    vec![
        BenchmarkScenario {
            name: "light_load",
            payload_size: 1024, // 1KB
            concurrent_requests: 1,
            error_rate_percent: 0.0,
        },
        BenchmarkScenario {
            name: "medium_load",
            payload_size: 10 * 1024, // 10KB
            concurrent_requests: 4,
            error_rate_percent: 1.0,
        },
        BenchmarkScenario {
            name: "heavy_load",
            payload_size: 100 * 1024, // 100KB
            concurrent_requests: 16,
            error_rate_percent: 2.0,
        },
        BenchmarkScenario {
            name: "stress_test",
            payload_size: 1024 * 1024, // 1MB
            concurrent_requests: 32,
            error_rate_percent: 5.0,
        },
    ]
}

/// Setup benchmark environment
async fn setup_benchmark_environment() -> (Arc<CryptoService>, DecryptHandler) {
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    write!(temp_file, "{}", BENCHMARK_RSA_KEY).expect("Failed to write key");

    let crypto_service = Arc::new(
        CryptoService::new(temp_file.path())
            .await
            .expect("Failed to create crypto service"),
    );

    let handler = DecryptHandler::new(Arc::clone(&crypto_service));

    (crypto_service, handler)
}

/// Benchmark complete decrypt workflow
fn bench_complete_decrypt_workflow(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("complete_decrypt_workflow");

    let scenarios = create_test_scenarios();

    for scenario in scenarios.iter().take(2) {
        // Limit to first 2 scenarios for this benchmark
        group.throughput(Throughput::Bytes(scenario.payload_size as u64));

        group.bench_with_input(
            BenchmarkId::new("full_workflow", scenario.name),
            scenario,
            |b, scenario| {
                b.iter(|| {
                    rt.block_on(async {
                        // Step 1: RSA key decryption (will fail with stub, but measures performance)
                        let rsa_start = std::time::Instant::now();
                        let _rsa_result = crypto_service
                            .decrypt_symmetric_key("test_encrypted_key")
                            .await;
                        let rsa_duration = rsa_start.elapsed();

                        // Step 2: Fernet payload decryption (will fail with stub, but measures performance)
                        let fernet_start = std::time::Instant::now();
                        let test_key = [42u8; 32];
                        let test_payload = "x".repeat(scenario.payload_size);
                        let _fernet_result = crypto_service
                            .decrypt_payload(&test_key, &test_payload)
                            .await;
                        let fernet_duration = fernet_start.elapsed();

                        black_box((rsa_duration, fernet_duration))
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark error handling performance across the entire stack
fn bench_error_handling_scenarios(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("error_handling_scenarios");

    // Benchmark different error scenarios
    let error_scenarios = vec![
        ("invalid_rsa_key", "invalid_base64!"),
        ("empty_rsa_key", ""),
        ("malformed_rsa_key", "not-base64-at-all<>"),
        (
            "very_long_rsa_key",
            "a_very_long_key_placeholder_for_benchmark",
        ),
    ];

    for (name, key) in error_scenarios {
        group.bench_with_input(BenchmarkId::new("rsa_errors", name), &key, |b, key| {
            b.iter(|| {
                let result = rt.block_on(crypto_service.decrypt_symmetric_key(key));
                black_box(result) // Should be an error
            });
        });
    }

    // Benchmark Fernet error scenarios
    let fernet_scenarios = vec![
        ("invalid_key_size", ([0u8; 16], "test_token")), // Wrong key size
        ("empty_token", ([0u8; 16], "")),                // Empty token with wrong key size
        ("invalid_token", ([0u8; 16], "invalid_token")), // Invalid token with wrong key size
        (
            "large_token",
            ([0u8; 16], "very_large_token_placeholder_for_benchmark"),
        ), // Very large token with wrong key size
    ];

    for (name, (key, token)) in fernet_scenarios {
        group.bench_with_input(
            BenchmarkId::new("fernet_errors", name),
            &(key, token),
            |b, (key, token)| {
                b.iter(|| {
                    let result = rt.block_on(crypto_service.decrypt_payload(key, token));
                    black_box(result) // Should be an error
                });
            },
        );
    }

    group.finish();
}

/// Benchmark concurrent operations under load
fn bench_concurrent_load_scenarios(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("concurrent_load");
    group.measurement_time(Duration::from_secs(10)); // Longer measurement for load tests

    let load_scenarios = vec![
        ("low_concurrency", 4),
        ("medium_concurrency", 16),
        ("high_concurrency", 64),
        ("extreme_concurrency", 128),
    ];

    for (name, concurrency) in load_scenarios {
        group.bench_with_input(
            BenchmarkId::new("mixed_operations", name),
            &concurrency,
            |b, &concurrency| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for i in 0..concurrency {
                            let service = Arc::clone(&crypto_service);
                            let handle = tokio::spawn(async move {
                                // Mix of RSA and Fernet operations
                                if i % 2 == 0 {
                                    // RSA operation
                                    let result =
                                        service.decrypt_symmetric_key(&format!("key_{}", i)).await;
                                    black_box(result)
                                } else {
                                    // Fernet operation
                                    let key = [i as u8; 32];
                                    let payload = format!("payload_{}", i);
                                    let result = service.decrypt_payload(&key, &payload).await;
                                    black_box(result)
                                }
                            });
                            handles.push(handle);
                        }

                        // Wait for all operations
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

/// Benchmark system resource utilization patterns
fn bench_resource_utilization(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("resource_utilization");

    // Benchmark memory allocation patterns under sustained load
    group.bench_function("sustained_rsa_operations", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Perform multiple operations to test memory usage patterns
                for i in 0..100 {
                    let result = crypto_service
                        .decrypt_symmetric_key(&format!("sustained_key_{}", i))
                        .await;
                    black_box(result);
                }
            })
        });
    });

    group.bench_function("sustained_fernet_operations", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Perform multiple Fernet operations
                for i in 0..100 {
                    let key = [i as u8; 32];
                    let payload = format!("sustained_payload_{}", i);
                    let result = crypto_service.decrypt_payload(&key, &payload).await;
                    black_box(result);
                }
            })
        });
    });

    // Test memory usage with varying payload sizes
    let payload_sizes = vec![1024, 10240, 102400]; // 1KB, 10KB, 100KB

    for size in payload_sizes {
        group.bench_with_input(
            BenchmarkId::new("memory_usage", format!("{}KB", size / 1024)),
            &size,
            |b, &size| {
                b.iter(|| {
                    rt.block_on(async {
                        let key = [42u8; 32];
                        let payload = "x".repeat(size);

                        // Perform operation multiple times to test memory patterns
                        for _ in 0..10 {
                            let result = crypto_service.decrypt_payload(&key, &payload).await;
                            black_box(result);
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark metrics collection overhead under load
fn bench_metrics_overhead(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("metrics_overhead");

    // Benchmark metrics collection frequency
    let collection_frequencies = vec![1, 10, 100, 1000];

    for frequency in collection_frequencies {
        group.bench_with_input(
            BenchmarkId::new("metrics_collection", format!("every_{}_ops", frequency)),
            &frequency,
            |b, &frequency| {
                b.iter(|| {
                    rt.block_on(async {
                        for i in 0..frequency {
                            // Perform operation
                            let result = crypto_service
                                .decrypt_symmetric_key(&format!("metrics_key_{}", i))
                                .await;
                            black_box(result);

                            // Collect metrics at specified frequency
                            if i == frequency - 1 {
                                let metrics = crypto_service.get_metrics();
                                black_box(metrics);
                            }
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark error recovery and resilience
fn bench_error_recovery(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("error_recovery");

    // Test recovery after various error conditions
    group.bench_function("recovery_after_rsa_errors", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Generate some errors
                for i in 0..10 {
                    let result = crypto_service
                        .decrypt_symmetric_key(&format!("invalid_key_{}", i))
                        .await;
                    black_box(result); // Should be errors
                }

                // Test that service is still functional
                let validation_result = crypto_service.validate_key();
                let metrics = crypto_service.get_metrics();
                black_box((validation_result, metrics))
            })
        });
    });

    group.bench_function("recovery_after_fernet_errors", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Generate Fernet errors
                for i in 0..10 {
                    let invalid_key = [i as u8; 16]; // Wrong size
                    let result = crypto_service
                        .decrypt_payload(&invalid_key, &format!("token_{}", i))
                        .await;
                    black_box(result); // Should be errors
                }

                // Test functionality recovery
                let public_key = crypto_service.get_public_key_pem().to_string();
                let metrics = crypto_service.get_metrics();
                black_box((public_key, metrics))
            })
        });
    });

    group.finish();
}

/// Benchmark service lifecycle operations
fn bench_service_lifecycle(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("service_lifecycle");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20); // Fewer samples for expensive operations

    // Benchmark complete service setup and teardown
    group.bench_function("complete_setup_teardown", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Setup
                let (crypto_service, handler) = setup_benchmark_environment().await;

                // Perform some operations
                let validation_result = crypto_service.validate_key();
                let metrics = crypto_service.get_metrics();
                let public_key = crypto_service.get_public_key_pem().to_string();

                black_box((handler, validation_result, metrics, public_key))
                // Teardown happens automatically when variables go out of scope
            })
        });
    });

    group.finish();
}

/// Benchmark realistic workload simulation
fn bench_realistic_workload(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (crypto_service, _handler) = rt.block_on(setup_benchmark_environment());

    let mut group = c.benchmark_group("realistic_workload");
    group.measurement_time(Duration::from_secs(15)); // Longer for realistic workloads

    // Simulate a realistic mix of operations
    group.bench_function("mixed_realistic_load", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::new();

                // Spawn tasks that simulate realistic usage patterns
                for i in 0..20 {
                    let service = Arc::clone(&crypto_service);
                    let handle = tokio::spawn(async move {
                        // 80% successful operations, 20% errors (realistic ratio)
                        if i % 5 == 0 {
                            // Error case
                            let result = service.decrypt_symmetric_key("invalid_key").await;
                            black_box(result);
                        } else {
                            // Success case (will still error with stub, but simulates the pattern)
                            let rsa_result = service
                                .decrypt_symmetric_key(&format!("valid_key_{}", i))
                                .await;

                            // Follow up with Fernet operation
                            let key = [i as u8; 32];
                            let payload = format!("payload_data_{}", i);
                            let fernet_result = service.decrypt_payload(&key, &payload).await;

                            black_box((rsa_result, fernet_result));
                        }
                    });
                    handles.push(handle);
                }

                // Wait for all tasks
                for handle in handles {
                    let _ = handle.await;
                }

                // Collect metrics (as would happen in real usage)
                let metrics = crypto_service.get_metrics();
                black_box(metrics)
            })
        });
    });

    group.finish();
}

// Configure benchmarks for end-to-end testing
criterion_group!(
    name = e2e_benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(50)
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_complete_decrypt_workflow,
        bench_error_handling_scenarios,
        bench_concurrent_load_scenarios,
        bench_resource_utilization,
        bench_metrics_overhead,
        bench_error_recovery,
        bench_service_lifecycle,
        bench_realistic_workload
);

criterion_main!(e2e_benches);
