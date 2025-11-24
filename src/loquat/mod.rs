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

pub mod encoding;
pub mod errors;
pub mod fft;
pub mod field_p127;
pub mod field_utils;
#[cfg(feature = "guest")]
pub mod guest;
#[cfg(feature = "std")]
pub mod iop_key_id;
#[cfg(feature = "std")]
pub mod keygen;
pub mod ldt;
pub mod merkle;
pub mod setup;
pub mod sign;
pub mod sumcheck;
pub mod transcript;
pub mod verify;

#[cfg(feature = "std")]
pub mod benchmark;
#[cfg(feature = "std")]
pub mod tests;

// Re-export core types for convenience
pub use errors::{LoquatError, LoquatResult};
#[cfg(feature = "std")]
pub use setup::loquat_setup;
pub use setup::LoquatPublicParams;

#[cfg(feature = "std")]
pub use benchmark::{BenchmarkConfig, HashType, LoquatBenchmark, PerformanceMetrics};
#[cfg(feature = "guest")]
pub use guest::loquat_verify_guest;
#[cfg(feature = "std")]
pub use iop_key_id::{iop_key_identification, verify_iop_proof, IOPInstance, IOPProof, IOPWitness};
#[cfg(feature = "std")]
pub use keygen::{keygen_with_params, LoquatKeyPair};
#[cfg(feature = "std")]
pub use sign::flatten_signature_for_hash;
#[cfg(feature = "std")]
pub use sign::loquat_sign;
pub use sign::{LoquatSignature, LoquatSignatureArtifact, LoquatSigningTranscript};
#[cfg(feature = "std")]
pub use sumcheck::generate_sumcheck_proof;
pub use sumcheck::{verify_sumcheck_proof, UnivariateSumcheckProof};
pub use transcript::Transcript;
pub use verify::loquat_verify;
