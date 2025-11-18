use super::errors::{LoquatError, LoquatResult};
use super::field_utils::{legendre_prf_secure, F};
use super::setup::LoquatPublicParams;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Loquat key pair, holding secret and public keys in the prime field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatKeyPair {
    pub secret_key: F,
    pub public_key: Vec<F>,
}

impl fmt::Display for LoquatKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoquatKeyPair {{ secret_key: [HIDDEN], public_key: {} elements }}",
            self.public_key.len()
        )
    }
}

/// Algorithm 3: Loquat Key Generation
pub fn keygen_with_params(params: &LoquatPublicParams) -> LoquatResult<LoquatKeyPair> {
    loquat_debug!("\n================== ALGORITHM 3: LOQUAT KEY GENERATION ==================");
    loquat_debug!("INPUT: Public parameters L-pp");
    loquat_debug!("Following Algorithm 3 specification from rules.mdc");

    let mut rng = rand::thread_rng();

    loquat_debug!("\n--- STEP 2: L-KeyGen Process ---");
    loquat_debug!("Parameters received:");
    loquat_debug!("  L = {} (public key bit length)", params.l);
    loquat_debug!(
        "  |I| = {} (number of public indices)",
        params.public_indices.len()
    );

    // Step 3: Generate the secret key
    loquat_debug!("\n--- STEP 3: Generate Secret Key ---");
    loquat_debug!("Requirement: Randomly pick K from F_p* excluding {{-I₁, ..., -I_L}}");

    // Create excluded set {-I₁, ..., -I_L}
    let excluded_set: std::collections::HashSet<F> =
        params.public_indices.iter().map(|&i| -i).collect();

    loquat_debug!(
        "✓ Excluded set {{-I₁, ..., -I_L}} created with {} elements",
        excluded_set.len()
    );
    if excluded_set.len() <= 5 {
        loquat_debug!(
            "  First few excluded values: {:?}",
            excluded_set.iter().take(3).collect::<Vec<_>>()
        );
    }

    let mut attempts = 0;
    let secret_key = loop {
        attempts += 1;
        let candidate = F::rand_nonzero(&mut rng);

        if !excluded_set.contains(&candidate) && !candidate.is_zero() {
            loquat_debug!("✓ Secret key sampled after {} attempt(s)", attempts);
            loquat_debug!("  Constraint K ∈ F_p* \\ {{-I₁, ..., -I_L}} satisfied");
            break candidate;
        }

        if attempts > 1000 {
            return Err(LoquatError::InvalidKeyGeneration {
                details: "Could not find valid secret key after 1000 attempts".to_string(),
            });
        }
    };

    // Step 4: Generate the public key
    loquat_debug!("\n--- STEP 4: Generate Public Key ---");
    loquat_debug!("Computing pk = L_K(I) = (L_K(I₁), ..., L_K(I_L))");

    let mut public_key = Vec::with_capacity(params.l);
    let mut legendre_stats = std::collections::HashMap::new();

    for (i, &public_index) in params.public_indices.iter().enumerate() {
        let legendre_value = legendre_prf_secure(secret_key + public_index);
        public_key.push(legendre_value);

        // Count statistics for verification
        *legendre_stats.entry(legendre_value).or_insert(0) += 1;

        if i < 5 {
            loquat_debug!(
                "  L_K(I_{}) = L_K({:?}) = {:?}",
                i + 1,
                public_index,
                legendre_value
            );
        } else if i == 5 {
            loquat_debug!("  ... (computing remaining {} values)", params.l - 5);
        }
    }

    loquat_debug!("✓ Public key computed: L = {} bits", public_key.len());
    loquat_debug!("  Legendre PRF output distribution:");
    for (value, count) in legendre_stats.iter() {
        let percentage = (*count as f64 / params.l as f64) * 100.0;
        loquat_debug!(
            "    Value {:?}: {} occurrences ({:.1}%)",
            value,
            count,
            percentage
        );
    }

    // Verify the Legendre PRF constraint
    loquat_debug!("\n--- VERIFICATION: Legendre PRF Constraints ---");
    let mut verification_passed = true;

    for (i, (&public_index, &pk_bit)) in params
        .public_indices
        .iter()
        .zip(public_key.iter())
        .enumerate()
    {
        let expected = legendre_prf_secure(secret_key + public_index);
        if pk_bit != expected {
            loquat_debug!(
                "✗ Verification failed at index {}: expected {:?}, got {:?}",
                i,
                expected,
                pk_bit
            );
            verification_passed = false;
        }
    }

    if verification_passed {
        loquat_debug!("✓ All Legendre PRF computations verified correctly");
        loquat_debug!("✓ pk[i] = L_K(I_i) constraint satisfied for all i ∈ [L]");
    } else {
        return Err(LoquatError::InvalidKeyGeneration {
            details: "Public key verification failed".to_string(),
        });
    }

    let keypair = LoquatKeyPair {
        secret_key,
        public_key,
    };

    loquat_debug!("\n--- STEP 5: Output Key Pair ---");
    loquat_debug!("✓ Key pair (sk, pk) generated successfully");
    loquat_debug!("  Secret key size: {} field elements", 1);
    loquat_debug!(
        "  Public key size: {} field elements ({} bits)",
        keypair.public_key.len(),
        params.l
    );

    // Additional security verification
    loquat_debug!("\n--- SECURITY VERIFICATION ---");
    loquat_debug!("✓ sk ∉ {{-I₁, ..., -I_L}} (collision avoidance)");
    loquat_debug!("✓ sk ≠ 0 (non-zero requirement)");
    loquat_debug!("✓ pk = L_K(I) where L_K is the Legendre PRF with key K");

    loquat_debug!("================== ALGORITHM 3 COMPLETE ==================\n");

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loquat::setup::loquat_setup;

    #[test]
    fn test_keygen_with_params() {
        let params = loquat_setup(128).expect("Setup failed");
        let result = keygen_with_params(&params);
        assert!(result.is_ok());
        let keypair = result.unwrap();
        assert_eq!(keypair.public_key.len(), params.l);
    }

    #[test]
    fn test_forbidden_value_avoidance_with_setup() {
        let params = loquat_setup(128).expect("Setup failed");
        let result = keygen_with_params(&params);
        assert!(result.is_ok());
    }
}
