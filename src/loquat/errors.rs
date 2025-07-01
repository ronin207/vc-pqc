/// Comprehensive error handling for the Loquat signature scheme implementation
/// 
/// This module provides detailed error types that help with debugging and
/// ensure robust error handling throughout the cryptographic implementation.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoquatError {
    #[error("Invalid field parameter: {message}")]
    InvalidField { message: String },
    
    #[error("Key generation failed after {attempts} attempts: {reason}")]
    KeyGenFailure { attempts: usize, reason: String },
    
    #[error("Invalid key generation: {details}")]
    InvalidKeyGeneration { details: String },
    
    #[error("Proof verification failed: {reason}")]
    VerificationFailure { reason: String },
    
    #[error("Parameter validation failed: {constraint}")]
    InvalidParameters { constraint: String },
    
    #[error("Cryptographic operation failed: {operation} - {details}")]
    CryptoError { operation: String, details: String },
    
    #[error("IOP proof generation failed: {phase} - {details}")]
    IOPError { phase: String, details: String },
    
    #[error("Sumcheck protocol error: {step} - {details}")]
    SumcheckError { step: String, details: String },
    
    #[error("Low-Degree Test error: {component} - {details}")]
    LDTError { component: String, details: String },
    
    #[error("Merkle tree operation failed: {operation} - {details}")]
    MerkleError { operation: String, details: String },
    
    #[error("Serialization error: {details}")]
    SerializationError { details: String },
    
    #[error("Invalid signature format: {reason}")]
    InvalidSignature { reason: String },
    
    #[error("Setup error: {phase} - {details}")]
    SetupError { phase: String, details: String },
}

impl LoquatError {
    pub fn invalid_field(msg: &str) -> Self {
        LoquatError::InvalidField { 
            message: msg.to_string() 
        }
    }
    
    pub fn keygen_failure(attempts: usize, reason: &str) -> Self {
        LoquatError::KeyGenFailure { 
            attempts, 
            reason: reason.to_string() 
        }
    }
    
    pub fn verification_failure(reason: &str) -> Self {
        LoquatError::VerificationFailure { 
            reason: reason.to_string() 
        }
    }
    
    pub fn invalid_parameters(constraint: &str) -> Self {
        LoquatError::InvalidParameters { 
            constraint: constraint.to_string() 
        }
    }
    
    pub fn crypto_error(operation: &str, details: &str) -> Self {
        LoquatError::CryptoError { 
            operation: operation.to_string(), 
            details: details.to_string() 
        }
    }
    
    pub fn iop_error(phase: &str, details: &str) -> Self {
        LoquatError::IOPError { 
            phase: phase.to_string(), 
            details: details.to_string() 
        }
    }
    
    pub fn sumcheck_error(step: &str, details: &str) -> Self {
        LoquatError::SumcheckError { 
            step: step.to_string(), 
            details: details.to_string() 
        }
    }
    
    pub fn ldt_error(component: &str, details: &str) -> Self {
        LoquatError::LDTError { 
            component: component.to_string(), 
            details: details.to_string() 
        }
    }
    
    pub fn merkle_error(operation: &str, details: &str) -> Self {
        LoquatError::MerkleError { 
            operation: operation.to_string(), 
            details: details.to_string() 
        }
    }
    
    pub fn invalid_signature(reason: &str) -> Self {
        LoquatError::InvalidSignature { 
            reason: reason.to_string() 
        }
    }
    
    pub fn setup_error(phase: &str, details: &str) -> Self {
        LoquatError::SetupError { 
            phase: phase.to_string(), 
            details: details.to_string() 
        }
    }
}

/// Result type alias for convenience
pub type LoquatResult<T> = Result<T, LoquatError>;

// Conversion traits for error interoperability
impl From<String> for LoquatError {
    fn from(msg: String) -> Self {
        LoquatError::CryptoError {
            operation: "generic".to_string(),
            details: msg,
        }
    }
}

impl From<LoquatError> for String {
    fn from(err: LoquatError) -> Self {
        err.to_string()
    }
}