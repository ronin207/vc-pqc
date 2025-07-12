use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vc_pqc::loquat::{
    benchmark::{LoquatBenchmark, BenchmarkConfig, HashType},
    setup::loquat_setup,
    keygen::keygen_with_params,
    sign::loquat_sign,
    verify::loquat_verify,
};

fn bench_loquat_setup(c: &mut Criterion) {
    c.bench_function("loquat_setup_128", |b| {
        b.iter(|| {
            black_box(loquat_setup(128)).unwrap()
        })
    });
    
    c.bench_function("loquat_setup_256", |b| {
        b.iter(|| {
            black_box(loquat_setup(256)).unwrap()
        })
    });
}

fn bench_loquat_keygen(c: &mut Criterion) {
    let params = loquat_setup(128).unwrap();
    
    c.bench_function("loquat_keygen_128", |b| {
        b.iter(|| {
            black_box(keygen_with_params(&params)).unwrap()
        })
    });
}

fn bench_loquat_sign(c: &mut Criterion) {
    let params = loquat_setup(128).unwrap();
    let keypair = keygen_with_params(&params).unwrap();
    let message = b"benchmark message";
    
    c.bench_function("loquat_sign_128", |b| {
        b.iter(|| {
            black_box(loquat_sign(message, &keypair, &params)).unwrap()
        })
    });
}

fn bench_loquat_verify(c: &mut Criterion) {
    let params = loquat_setup(128).unwrap();
    let keypair = keygen_with_params(&params).unwrap();
    let message = b"benchmark message";
    let signature = loquat_sign(message, &keypair, &params).unwrap();
    
    c.bench_function("loquat_verify_128", |b| {
        b.iter(|| {
            black_box(loquat_verify(message, &signature, &keypair.public_key, &params)).unwrap()
        })
    });
}

fn bench_loquat_full_flow(c: &mut Criterion) {
    let message = b"benchmark message";
    
    c.bench_function("loquat_full_flow_128", |b| {
        b.iter(|| {
            let params = black_box(loquat_setup(128)).unwrap();
            let keypair = black_box(keygen_with_params(&params)).unwrap();
            let signature = black_box(loquat_sign(message, &keypair, &params)).unwrap();
            let valid = black_box(loquat_verify(message, &signature, &keypair.public_key, &params)).unwrap();
            assert!(valid);
        })
    });
}

fn bench_security_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_levels");
    
    for &security_level in &[128, 192, 256] {
        group.bench_with_input(
            format!("setup_{}", security_level),
            &security_level,
            |b, &security_level| {
                b.iter(|| {
                    black_box(loquat_setup(security_level)).unwrap()
                })
            },
        );
    }
    
    group.finish();
}

fn bench_custom_benchmark_suite(c: &mut Criterion) {
    c.bench_function("custom_benchmark_quick", |b| {
        b.iter(|| {
            let benchmark = LoquatBenchmark {
                configs: vec![
                    BenchmarkConfig {
                        security_level: 128,
                        num_iterations: 1,
                        message_size: 32,
                        hash_type: HashType::ShaSHAKE,
                    },
                ],
            };
            black_box(benchmark.run_full_benchmark())
        })
    });
}

criterion_group!(
    benches,
    bench_loquat_setup,
    bench_loquat_keygen,
    bench_loquat_sign,
    bench_loquat_verify,
    bench_loquat_full_flow,
    bench_security_levels,
    bench_custom_benchmark_suite
);

criterion_main!(benches);