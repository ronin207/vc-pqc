pub mod setup;
pub mod keygen;
pub mod iop_key_id;
pub mod sign;
pub mod verify;
pub mod benchmark;

// Re-export key types and functions for easy access
pub use setup::{LoquatPublicParams, loquat_setup};
pub use keygen::{LoquatKeyPair, keygen_with_params, legendre_prf};
pub use sign::{LoquatSignature, loquat_sign};
pub use verify::loquat_verify_algorithm_7;
pub use benchmark::{LoquatBenchmark, PerformanceMetrics, BenchmarkConfig, HashType,
                   run_complete_benchmark, run_sha_benchmark, run_griffin_benchmark}; 