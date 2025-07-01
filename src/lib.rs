//! VC-PQC: Post-Quantum Verifiable Credentials
//! 
//! This library provides two main components:
//! 
//! 1. **Loquat**: A SNARK-friendly post-quantum signature scheme based on the Legendre PRF
//! 2. **Anonymous Credentials**: Privacy-preserving verifiable credentials built on Loquat
//! 
//! ## Core Loquat Signature Scheme
//! 
//! The `loquat` module implements the complete Loquat signature scheme from the paper
//! "Loquat: A SNARK-Friendly Post-Quantum Signature based on the Legendre PRF".
//! 
//! ```rust
//! use vc_pqc::{loquat_setup, keygen_with_params, loquat_sign, loquat_verify};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! 
//! // Setup with 128-bit security
//! let params = loquat_setup(128)?;
//! let keypair = keygen_with_params(&params)?;
//! 
//! // Sign and verify
//! let message = b"Hello, post-quantum world!";
//! let signature = loquat_sign(message, &keypair, &params)?;
//! let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//! 
//! ## Anonymous Credentials
//! 
//! The `anoncreds` module provides W3C Verifiable Credentials compatible anonymous
//! credentials with selective disclosure and zero-knowledge proofs.
//! 
//! ```rust,ignore
//! use vc_pqc::anoncreds::{CredentialIssuer, CredentialAttribute};
//! use vc_pqc::loquat::loquat_setup;
//! 
//! // Setup issuer
//! let params = loquat_setup(128)?;
//! let mut issuer = CredentialIssuer::new("Government_ID", &params)?;
//! 
//! // Issue credential
//! let attributes = vec![
//!     CredentialAttribute::new("age", 25, false), // Hidden
//!     CredentialAttribute::new("citizenship", 840, false), // Hidden (USA)
//! ];
//! let credential = issuer.issue_credential(
//!     b"holder_pseudonym".to_vec(),
//!     attributes,
//!     "identity_v1"
//! )?;
//! ```

pub mod loquat;
// pub mod anoncreds;

// Re-export commonly used types for convenience
pub use loquat::{
    LoquatError, LoquatResult, LoquatPublicParams, LoquatSignature,
    loquat_setup, loquat_sign, loquat_verify
};

pub use loquat::keygen::{LoquatKeyPair, keygen_with_params};

/*
pub use anoncreds::{
    CredentialIssuer, CredentialAttribute, AnonymousCredential, 
    SelectiveDisclosureRequest, SelectiveDisclosureVerifier
};
*/