#![cfg(feature = "guest")]

use super::{field_utils::F, setup::LoquatPublicParams, sign::LoquatSignature};
use crate::{LoquatError, LoquatResult};

/// Guest-compatible verification entry point.
///
/// This will eventually run inside the RISC Zero guest to replicate Algorithm 7.
/// For now it is a thin wrapper that either delegates to the standard verifier
/// (when `std` is available) or returns a placeholder error under `no_std`.
pub fn loquat_verify_guest(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[F],
    params: &LoquatPublicParams,
) -> LoquatResult<bool> {
    #[cfg(feature = "std")]
    {
        super::verify::loquat_verify(message, signature, public_key, params)
    }

    #[cfg(not(feature = "std"))]
    {
        let _ = (message, signature, public_key, params);
        Err(LoquatError::verification_failure(
            "guest verification not yet implemented",
        ))
    }
}
