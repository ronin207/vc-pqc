//! Transparent SNARK proof-of-concept implementations inspired by
//! Aurora (IACR 2018/828) and Fractal (IACR 2019/1076).
//!
//! The goal of this module is to provide a Rust-native playground that
//! mirrors the multi-oracle IOP structure described in the papers:
//! - Rank-1 Constraint System (R1CS) front-end with explicit witness commitments.
//! - Sumcheck + low-degree style checks instantiated with the reusable Loquat
//!   sumcheck/LDT components.
//! - Recursive folding (à la Fractal) that compresses Aurora proofs via
//!   challenge-driven linking constraints.
//!
//! These proofs are *not* production SNARKs, but every stage aligns with the
//! numbered steps in the original specifications so that future work can
//! swap the simplified gadgets with fully optimised polynomial commitments.

#[cfg(not(feature = "std"))]
compile_error!("The SNARK prototypes require the `std` feature.");

pub mod aurora;
pub mod fractal;
pub mod loquat_r1cs;
pub mod r1cs;

pub use aurora::{
    aurora_prove, aurora_prove_with_options, aurora_verify, AuroraParams, AuroraProof,
    AuroraProverOptions, AuroraVerificationHints, AuroraVerificationResult,
};
pub use fractal::{fractal_prove, fractal_verify, FractalParams, FractalProof};
pub use loquat_r1cs::build_loquat_r1cs;
pub use r1cs::{R1csConstraint, R1csInstance, R1csWitness};
