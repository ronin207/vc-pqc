#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};
use core::fmt;
#[cfg(feature = "std")]
use std::string::{String, ToString};

#[derive(Debug, Clone)]
pub enum LoquatError {
    InvalidField { message: String },
    KeyGenFailure { attempts: usize, reason: String },
    InvalidKeyGeneration { details: String },
    VerificationFailure { reason: String },
    InvalidParameters { constraint: String },
    CryptoError { operation: String, details: String },
    IOPError { phase: String, details: String },
    SumcheckError { step: String, details: String },
    LDTError { component: String, details: String },
    MerkleError { operation: String, details: String },
    SerializationError { details: String },
    InvalidSignature { reason: String },
    SetupError { phase: String, details: String },
}

impl LoquatError {
    pub fn invalid_field(msg: &str) -> Self {
        LoquatError::InvalidField {
            message: msg.to_string(),
        }
    }

    pub fn keygen_failure(attempts: usize, reason: &str) -> Self {
        LoquatError::KeyGenFailure {
            attempts,
            reason: reason.to_string(),
        }
    }

    pub fn verification_failure(reason: &str) -> Self {
        LoquatError::VerificationFailure {
            reason: reason.to_string(),
        }
    }

    pub fn invalid_parameters(constraint: &str) -> Self {
        LoquatError::InvalidParameters {
            constraint: constraint.to_string(),
        }
    }

    pub fn crypto_error(operation: &str, details: &str) -> Self {
        LoquatError::CryptoError {
            operation: operation.to_string(),
            details: details.to_string(),
        }
    }

    pub fn iop_error(phase: &str, details: &str) -> Self {
        LoquatError::IOPError {
            phase: phase.to_string(),
            details: details.to_string(),
        }
    }

    pub fn sumcheck_error(step: &str, details: &str) -> Self {
        LoquatError::SumcheckError {
            step: step.to_string(),
            details: details.to_string(),
        }
    }

    pub fn ldt_error(component: &str, details: &str) -> Self {
        LoquatError::LDTError {
            component: component.to_string(),
            details: details.to_string(),
        }
    }

    pub fn merkle_error(operation: &str, details: &str) -> Self {
        LoquatError::MerkleError {
            operation: operation.to_string(),
            details: details.to_string(),
        }
    }

    pub fn invalid_signature(reason: &str) -> Self {
        LoquatError::InvalidSignature {
            reason: reason.to_string(),
        }
    }

    pub fn serialization_error(details: &str) -> Self {
        LoquatError::SerializationError {
            details: details.to_string(),
        }
    }

    pub fn setup_error(phase: &str, details: &str) -> Self {
        LoquatError::SetupError {
            phase: phase.to_string(),
            details: details.to_string(),
        }
    }
}

/// Result type alias for convenience
pub type LoquatResult<T> = Result<T, LoquatError>;

impl fmt::Display for LoquatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoquatError::InvalidField { message } => {
                write!(f, "Invalid field parameter: {message}")
            }
            LoquatError::KeyGenFailure { attempts, reason } => {
                write!(
                    f,
                    "Key generation failed after {attempts} attempts: {reason}"
                )
            }
            LoquatError::InvalidKeyGeneration { details } => {
                write!(f, "Invalid key generation: {details}")
            }
            LoquatError::VerificationFailure { reason } => {
                write!(f, "Proof verification failed: {reason}")
            }
            LoquatError::InvalidParameters { constraint } => {
                write!(f, "Parameter validation failed: {constraint}")
            }
            LoquatError::CryptoError { operation, details } => {
                write!(f, "Cryptographic operation failed: {operation} - {details}")
            }
            LoquatError::IOPError { phase, details } => {
                write!(f, "IOP proof generation failed: {phase} - {details}")
            }
            LoquatError::SumcheckError { step, details } => {
                write!(f, "Sumcheck protocol error: {step} - {details}")
            }
            LoquatError::LDTError { component, details } => {
                write!(f, "Low-Degree Test error: {component} - {details}")
            }
            LoquatError::MerkleError { operation, details } => {
                write!(f, "Merkle tree operation failed: {operation} - {details}")
            }
            LoquatError::SerializationError { details } => {
                write!(f, "Serialization error: {details}")
            }
            LoquatError::InvalidSignature { reason } => {
                write!(f, "Invalid signature format: {reason}")
            }
            LoquatError::SetupError { phase, details } => {
                write!(f, "Setup error: {phase} - {details}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LoquatError {}

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
