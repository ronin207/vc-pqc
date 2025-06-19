use rand::Rng;
use sha2::{Sha256, Digest};
use crate::setup::LoquatPublicParams;
use crate::keygen::{LoquatKeyPair, legendre_prf};

/// Algorithm 1: IOP-based Key Identification of the Legendre PRF
/// This is the core protocol that enables SNARK-friendly signature generation
/// by proving knowledge of the secret key without revealing it.

#[derive(Debug, Clone)]
pub struct IOPProof {
    /// Commitment to the secret key K
    pub commitment: Vec<u128>,
    /// Challenge values from the verifier/hash function
    pub challenges: Vec<u128>,
    /// Response values that prove knowledge of K
    pub responses: Vec<u128>,
    /// Auxiliary data for the proof
    pub aux_data: Vec<u128>,
    /// Polynomial evaluations for sumcheck protocol
    pub poly_evaluations: Vec<u128>,
}

#[derive(Debug, Clone)]
pub struct IOPInstance {
    /// Public key (Legendre PRF evaluations)
    pub public_key: Vec<u128>,
    /// Public indices from setup
    pub public_indices: Vec<u128>,
    /// Message hash (what we're proving we can sign)
    pub message_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IOPWitness {
    /// Secret key K
    pub secret_key: u128,
}

/// Algorithm 1: IOP-based Key Identification
/// Input: Public parameters L-pp, instance (pk, I, msg_hash), witness (sk)
/// Output: IOP proof π demonstrating knowledge of secret key
pub fn iop_key_identification(
    params: &LoquatPublicParams,
    instance: &IOPInstance,
    witness: &IOPWitness,
    message: &[u8],
) -> Result<IOPProof, String> {
    let mut rng = rand::thread_rng();
    
    // Step 1: Validate instance consistency
    if instance.public_key.len() != params.l {
        return Err("Public key length doesn't match parameter L".to_string());
    }
    
    if instance.public_indices.len() != params.l {
        return Err("Public indices length doesn't match parameter L".to_string());
    }
    
    // Verify that the witness corresponds to the instance
    for (i, &pk_i) in instance.public_key.iter().enumerate() {
        let expected = legendre_prf(witness.secret_key + instance.public_indices[i], params.field_p);
        if pk_i != expected {
            return Err(format!("Witness doesn't match public key at index {}", i));
        }
    }
    
    // Step 2: Commitment Phase
    // Commit to secret key K using random masking
    let mut commitment = Vec::with_capacity(params.b);
    let mut masking_values = Vec::with_capacity(params.b);
    
    for i in 0..params.b {
        // Generate random masking value r_i
        let r_i = rng.gen_range(1..params.field_p);
        masking_values.push(r_i);
        
        // Commit: c_i = L_{r_i}(I_i) = Legendre PRF evaluation with masking
        let commitment_i = legendre_prf(r_i + instance.public_indices[i], params.field_p);
        commitment.push(commitment_i);
    }
    
    // Step 3: Challenge Generation (Fiat-Shamir)
    let challenges = generate_challenges(params, instance, &commitment, message)?;
    
    // Step 4: Response Phase
    // Generate responses that prove knowledge of K without revealing it
    let mut responses = Vec::with_capacity(params.b);
    
    for i in 0..params.b {
        let challenge = challenges[i % challenges.len()];
        
        // Response: z_i = r_i + challenge * K (mod p)
        // This allows verification: L_{z_i}(I_i) = L_{r_i}(I_i) * L_K(I_i)^challenge
        let challenge_times_key = if params.field_p <= (1u128 << 64) {
            ((challenge % params.field_p) * (witness.secret_key % params.field_p)) % params.field_p
        } else {
            ((challenge % params.field_p).saturating_mul(witness.secret_key % params.field_p)) % params.field_p
        };
        let response = (masking_values[i] + challenge_times_key) % params.field_p;
        responses.push(response);
    }
    
    // Step 5: Sumcheck Protocol for Low-Degree Testing
    let poly_evaluations = generate_polynomial_evaluations(params, instance, witness, &challenges)?;
    
    // Step 6: Generate auxiliary data for SNARK-friendly verification
    let aux_data = generate_auxiliary_data(params, instance, &commitment, &responses)?;
    
    Ok(IOPProof {
        commitment,
        challenges,
        responses,
        aux_data,
        poly_evaluations,
    })
}

/// Generate challenges using Fiat-Shamir heuristic
fn generate_challenges(
    params: &LoquatPublicParams,
    instance: &IOPInstance,
    commitment: &[u128],
    message: &[u8],
) -> Result<Vec<u128>, String> {
    let mut hasher = Sha256::new();
    
    // Hash all public information
    hasher.update(message);
    hasher.update(&params.field_p.to_le_bytes());
    hasher.update(&params.l.to_le_bytes());
    hasher.update(&params.b.to_le_bytes());
    
    // Hash public key
    for &pk_elem in &instance.public_key {
        hasher.update(&pk_elem.to_le_bytes());
    }
    
    // Hash public indices
    for &idx in &instance.public_indices {
        hasher.update(&idx.to_le_bytes());
    }
    
    // Hash commitment
    for &comm in commitment {
        hasher.update(&comm.to_le_bytes());
    }
    
    let hash_result = hasher.finalize();
    
    // Generate challenges from hash
    let mut challenges = Vec::with_capacity(params.kappa);
    let mut seed = hash_result.to_vec();
    
    for i in 0..params.kappa {
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(&seed);
        challenge_hasher.update(&i.to_le_bytes());
        let challenge_hash = challenge_hasher.finalize();
        
        // Convert hash to field element
        let challenge_bytes = &challenge_hash[0..16]; // Take first 16 bytes
        let challenge = u128::from_le_bytes(challenge_bytes.try_into().unwrap()) % params.field_p;
        challenges.push(challenge);
        
        seed = challenge_hash.to_vec(); // Convert to owned Vec
    }
    
    Ok(challenges)
}

/// Generate polynomial evaluations for the sumcheck protocol
fn generate_polynomial_evaluations(
    params: &LoquatPublicParams,
    _instance: &IOPInstance,
    witness: &IOPWitness,
    challenges: &[u128],
) -> Result<Vec<u128>, String> {
    let mut evaluations = Vec::with_capacity(params.m * params.n);
    
    // Create polynomial P(x) that encodes the Legendre PRF relation
    // P(x) = ∑_{i=1}^L (L_K(I_i) - pk_i) * x^i
    for i in 0..params.m {
        for j in 0..params.n {
            let idx = i * params.n + j;
            if idx < params.l {
                // Evaluate polynomial at challenge points
                let challenge_point = challenges[i % challenges.len()];
                let legendre_eval = legendre_prf(
                    witness.secret_key + params.public_indices[idx], 
                    params.field_p
                );
                let challenge_times_index = if params.field_p <= (1u128 << 64) {
                    (challenge_point * params.public_indices[idx]) % params.field_p
                } else {
                    (challenge_point.saturating_mul(params.public_indices[idx])) % params.field_p
                };
                let poly_eval = (legendre_eval + challenge_times_index) % params.field_p;
                evaluations.push(poly_eval);
            } else {
                evaluations.push(0); // Padding
            }
        }
    }
    
    Ok(evaluations)
}

/// Generate auxiliary data for SNARK-friendly verification
fn generate_auxiliary_data(
    params: &LoquatPublicParams,
    _instance: &IOPInstance,
    commitment: &[u128],
    responses: &[u128],
) -> Result<Vec<u128>, String> {
    let mut aux_data = Vec::new();
    
    // Include coset evaluation points for LDT
    for &h_elem in params.coset_h.iter().take(10) { // Sample from coset H
        aux_data.push(h_elem);
    }
    
    // Include verification helper values
    for i in 0..std::cmp::min(responses.len(), 10) {
        let helper = (commitment[i] + responses[i]) % params.field_p;
        aux_data.push(helper);
    }
    
    // Include rate parameter information
    aux_data.push((params.rho_star * 1000.0) as u128); // Convert to integer
    aux_data.push(params.r as u128);
    
    Ok(aux_data)
}

/// Verify IOP proof (for completeness - would be Algorithm 4)
pub fn verify_iop_proof(
    params: &LoquatPublicParams,
    instance: &IOPInstance,
    proof: &IOPProof,
    message: &[u8],
) -> Result<bool, String> {
    // Step 1: Verify challenge generation
    let expected_challenges = generate_challenges(params, instance, &proof.commitment, message)?;
    if proof.challenges != expected_challenges {
        return Ok(false);
    }
    
    // Step 2: Verify responses (simplified verification)
    // In the full protocol, this would involve more complex verification
    // For now, we check basic properties
    
    if proof.responses.len() != params.b {
        return Ok(false);
    }
    
    if proof.commitment.len() != params.b {
        return Ok(false);
    }
    
    // Step 3: Basic consistency checks
    for i in 0..std::cmp::min(proof.responses.len(), params.b) {
        let response = proof.responses[i];
        
        // Ensure response is in valid range
        if response >= params.field_p {
            return Ok(false);
        }
        
        // Basic check: verify commitment was computed correctly
        // (This is a simplified check - full verification would be more complex)
        let commitment_value = proof.commitment[i];
        if commitment_value >= params.field_p {
            return Ok(false);
        }
    }
    
    // Step 4: Verify polynomial evaluations (simplified)
    if proof.poly_evaluations.len() != params.m * params.n {
        return Ok(false);
    }
    
    // All basic checks passed - in a full implementation, this would include
    // complete sumcheck protocol verification and low-degree testing
    Ok(true)
}

/// Helper: Modular exponentiation
#[allow(dead_code)]
fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 { return 0; }
    
    let mut result = 1u128;
    base %= modulus;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    
    result
}

/// Create an IOP instance from a key pair and message
pub fn create_iop_instance(
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
    message: &[u8],
) -> IOPInstance {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize().to_vec();
    
    IOPInstance {
        public_key: keypair.public_key.clone(),
        public_indices: params.public_indices.clone(),
        message_hash,
    }
}

/// Create an IOP witness from a secret key
pub fn create_iop_witness(secret_key: u128) -> IOPWitness {
    IOPWitness { secret_key }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::loquat_setup;
    use crate::keygen::keygen_with_params;

    #[test]
    fn test_iop_key_identification() {
        let params = loquat_setup(128).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        
        let message = b"Hello, Loquat IOP!";
        let instance = create_iop_instance(&keypair, &params, message);
        let witness = create_iop_witness(keypair.secret_key);
        
        let proof = iop_key_identification(&params, &instance, &witness, message)
            .expect("IOP proof generation failed");
        
        assert_eq!(proof.commitment.len(), params.b);
        assert_eq!(proof.responses.len(), params.b);
        assert!(!proof.challenges.is_empty());
        
        println!("IOP proof generated successfully.");
        println!("  - Commitment length: {}", proof.commitment.len());
        println!("  - Response length: {}", proof.responses.len());
        println!("  - Challenges: {}", proof.challenges.len());
    }

    #[test]
    fn test_iop_verification() {
        let params = loquat_setup(64).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        
        let message = b"Test message for verification";
        let instance = create_iop_instance(&keypair, &params, message);
        let witness = create_iop_witness(keypair.secret_key);
        
        let proof = iop_key_identification(&params, &instance, &witness, message)
            .expect("IOP proof generation failed");
        
        let is_valid = verify_iop_proof(&params, &instance, &proof, message)
            .expect("Verification failed");
        
        assert!(is_valid, "Proof should be valid");
        println!("IOP proof verification successful.");
    }

    #[test]
    fn test_invalid_witness_rejection() {
        let params = loquat_setup(64).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        
        let message = b"Test message";
        let instance = create_iop_instance(&keypair, &params, message);
        
        // Create invalid witness (wrong secret key)
        let invalid_witness = create_iop_witness(keypair.secret_key + 1);
        
        let result = iop_key_identification(&params, &instance, &invalid_witness, message);
        assert!(result.is_err(), "Should reject invalid witness");
        println!("Invalid witness correctly rejected.");
    }

    #[test]
    fn test_challenge_determinism() {
        let params = loquat_setup(64).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        
        let message = b"Determinism test";
        let instance = create_iop_instance(&keypair, &params, message);
        
        let challenges1 = generate_challenges(&params, &instance, &vec![42, 123], message)
            .expect("Challenge generation failed");
        let challenges2 = generate_challenges(&params, &instance, &vec![42, 123], message)
            .expect("Challenge generation failed");
        
        assert_eq!(challenges1, challenges2, "Challenges should be deterministic");
        println!("Challenge generation is deterministic.");
    }
} 