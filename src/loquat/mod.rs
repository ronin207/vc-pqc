//! Core Loquat Post-Quantum Signature Scheme
//!
//! Implementation of the Loquat signature scheme from "Loquat: A SNARK-Friendly
//! Post-Quantum Signature based on the Legendre PRF" by Zhang et al.
//!
//! This module contains the complete implementation of Algorithms 1-7 from the paper:
//! - Algorithm 1: IOP-based Key Identification
//! - Algorithm 2: Public Parameter Setup
//! - Algorithm 3: Key Generation
//! - Algorithm 4-6: Signature Generation Workflow
//! - Algorithm 7: Signature Verification

pub mod errors;
pub mod field_utils;
pub mod setup;
pub mod keygen;
pub mod iop_key_id;
pub mod sumcheck;
pub mod sign;
pub mod verify;
pub mod field_p127;
pub mod merkle;
pub mod ldt;

pub mod benchmark;
pub mod tests;

// Re-export core types for convenience
pub use errors::{LoquatError, LoquatResult};
pub use setup::{LoquatPublicParams, loquat_setup};

pub use sign::{LoquatSignature, loquat_sign};
pub use verify::loquat_verify;
pub use iop_key_id::{IOPProof, IOPInstance, IOPWitness, iop_key_identification, verify_iop_proof};
pub use sumcheck::{UnivariateSumcheckProof, generate_sumcheck_proof, verify_sumcheck_proof};
pub use benchmark::{LoquatBenchmark, BenchmarkConfig, PerformanceMetrics, HashType};