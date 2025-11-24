use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vc_pqc::{
    loquat::{
        benchmark::{BenchmarkConfig, HashType, LoquatBenchmark},
        field_utils::F,
        keygen::keygen_with_params,
        setup::loquat_setup,
        sign::loquat_sign,
        verify::loquat_verify,
    },
    snarks::{
        aurora_prove, aurora_verify, fractal_prove, fractal_verify, AuroraParams, FractalParams,
        R1csConstraint, R1csInstance, R1csWitness,
    },
};

const PAPER_CONSTRAINT_QUERIES: usize = 8;
const PAPER_WITNESS_QUERIES: usize = 8;
const PAPER_RECURSION_LAYERS: usize = 2;

fn bench_loquat_setup(c: &mut Criterion) {
    c.bench_function("loquat_setup_128", |b| {
        b.iter(|| black_box(loquat_setup(128)).unwrap())
    });

    c.bench_function("loquat_setup_256", |b| {
        b.iter(|| black_box(loquat_setup(256)).unwrap())
    });
}

fn bench_loquat_keygen(c: &mut Criterion) {
    let params = loquat_setup(128).unwrap();

    c.bench_function("loquat_keygen_128", |b| {
        b.iter(|| black_box(keygen_with_params(&params)).unwrap())
    });
}

fn bench_loquat_sign(c: &mut Criterion) {
    let params = loquat_setup(128).unwrap();
    let keypair = keygen_with_params(&params).unwrap();
    let message = b"benchmark message";

    c.bench_function("loquat_sign_128", |b| {
        b.iter(|| black_box(loquat_sign(message, &keypair, &params)).unwrap())
    });
}

fn bench_loquat_verify(c: &mut Criterion) {
    let params = loquat_setup(128).unwrap();
    let keypair = keygen_with_params(&params).unwrap();
    let message = b"benchmark message";
    let signature = loquat_sign(message, &keypair, &params).unwrap();

    c.bench_function("loquat_verify_128", |b| {
        b.iter(|| {
            black_box(loquat_verify(
                message,
                &signature,
                &keypair.public_key,
                &params,
            ))
            .unwrap()
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
            let valid = black_box(loquat_verify(
                message,
                &signature,
                &keypair.public_key,
                &params,
            ))
            .unwrap();
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
            |b, &security_level| b.iter(|| black_box(loquat_setup(security_level)).unwrap()),
        );
    }

    group.finish();
}

fn bench_custom_benchmark_suite(c: &mut Criterion) {
    c.bench_function("custom_benchmark_quick", |b| {
        b.iter(|| {
            let benchmark = LoquatBenchmark {
                configs: vec![BenchmarkConfig {
                    security_level: 128,
                    num_iterations: 1,
                    message_size: 32,
                    hash_type: HashType::ShaSHAKE,
                }],
            };
            black_box(benchmark.run_full_benchmark())
        })
    });
}

fn sample_r1cs_instance() -> (R1csInstance, R1csWitness) {
    let num_variables = 4; // 1 (constant) + x + y + z
    let mut a = vec![F::zero(); num_variables];
    a[1] = F::one();
    let mut b = vec![F::zero(); num_variables];
    b[2] = F::one();
    let mut c = vec![F::zero(); num_variables];
    c[3] = F::one();
    let constraint = R1csConstraint::new(a, b, c);
    let instance = R1csInstance::new(num_variables, vec![constraint]).unwrap();
    let witness = R1csWitness::new(vec![F::new(3), F::new(5), F::new(15)]);
    (instance, witness)
}

fn bench_aurora_pipeline(c: &mut Criterion) {
    let (instance, witness) = sample_r1cs_instance();
    let aurora_params = AuroraParams {
        constraint_query_count: PAPER_CONSTRAINT_QUERIES,
        witness_query_count: PAPER_WITNESS_QUERIES,
    };

    c.bench_function("aurora_prove_standard", |b| {
        b.iter(|| black_box(aurora_prove(&instance, &witness, &aurora_params)).unwrap())
    });

    let proof = aurora_prove(&instance, &witness, &aurora_params).unwrap();
    c.bench_function("aurora_verify_standard", |b| {
        b.iter(|| {
            let verified =
                black_box(aurora_verify(&instance, &proof, &aurora_params, None)).unwrap();
            assert!(verified.is_some());
        })
    });

    c.bench_function("aurora_round_trip_standard", |b| {
        b.iter(|| {
            let proof = aurora_prove(&instance, &witness, &aurora_params).unwrap();
            let verified = aurora_verify(&instance, &proof, &aurora_params, None)
                .unwrap()
                .is_some();
            assert!(verified);
        })
    });
}

fn bench_fractal_pipeline(c: &mut Criterion) {
    let (instance, witness) = sample_r1cs_instance();
    let fractal_params = FractalParams {
        aurora: AuroraParams {
            constraint_query_count: PAPER_CONSTRAINT_QUERIES,
            witness_query_count: PAPER_WITNESS_QUERIES,
        },
        recursion_layers: PAPER_RECURSION_LAYERS,
    };

    c.bench_function("fractal_prove_standard", |b| {
        b.iter(|| black_box(fractal_prove(&instance, &witness, &fractal_params)).unwrap())
    });

    let proof = fractal_prove(&instance, &witness, &fractal_params).unwrap();
    c.bench_function("fractal_verify_standard", |b| {
        b.iter(|| {
            let valid = black_box(fractal_verify(&instance, &proof, &fractal_params)).unwrap();
            assert!(valid);
        })
    });

    c.bench_function("fractal_round_trip_standard", |b| {
        b.iter(|| {
            let proof = fractal_prove(&instance, &witness, &fractal_params).unwrap();
            assert!(fractal_verify(&instance, &proof, &fractal_params).unwrap());
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
    bench_custom_benchmark_suite,
    bench_aurora_pipeline,
    bench_fractal_pipeline
);

criterion_main!(benches);
