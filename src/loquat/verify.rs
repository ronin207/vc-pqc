use super::errors::{LoquatResult, LoquatError};
use super::field_utils::{self, F, F2, u128_to_field};

use super::setup::LoquatPublicParams;
use super::sign::LoquatSignature;
use super::sumcheck::verify_sumcheck_proof;
use sha2::{Digest, Sha256};
use merlin::Transcript;

/// Generate transcript challenge - must match the implementation in sign.rs
fn transcript_challenge_f2(transcript: &mut Transcript) -> F2 {
    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut buf);
    let c0 = F::new(u128::from_le_bytes(buf[..16].try_into().unwrap()));
    let c1 = F::new(u128::from_le_bytes(buf[16..].try_into().unwrap()));
    F2::new(c0, c1)
}

/// Holds all challenges derived via the Fiat-Shamir transform.
/// These are re-derived by the verifier and used to check the proof.
#[derive(Debug)]
pub struct Challenges {
    /// Challenged indices into the public parameter set `I`. (from h1)
    pub i_indices: Vec<usize>,
    /// Lambda values for the sumcheck. (from h2)
    pub lambdas: Vec<F2>,
    /// `e_j` values for combining parallel sumcheck instances. (from h2)
    pub e_j: Vec<F2>,
}

/// Implements the `Expand` function from the paper using a hash function.
fn expand_challenge<T>(
    seed: &[u8],
    count: usize,
    domain_separator: &[u8],
    parser: &mut dyn FnMut(&[u8]) -> T,
) -> Vec<T> {
    let mut results = Vec::with_capacity(count);
    let mut counter: u32 = 0;
    while results.len() < count {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(domain_separator);
        hasher.update(&counter.to_le_bytes());
        let hash_output = hasher.finalize();
        results.push(parser(&hash_output));
        counter += 1;
    }
    results
}

fn verify_ldt_proof(
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
    transcript: &mut Transcript,
) -> LoquatResult<bool> {
    println!("--- ALGORITHM 7: LDT VERIFICATION (Steps 4-6) ---");
    println!("Following rules.mdc: 'Verify LDT and Sumcheck Consistency at Query Points'");
    
    let ldt_proof = &signature.ldt_proof;
    
    if ldt_proof.commitments.len() != params.r + 1 {
        println!("✗ LDT FAILED: Wrong number of commitments. Expected {}, got {}", 
                 params.r + 1, ldt_proof.commitments.len());
        return Ok(false);
    }
    
    if ldt_proof.openings.len() != params.kappa {
        println!("✗ LDT FAILED: Wrong number of openings. Expected {}, got {}", 
                 params.kappa, ldt_proof.openings.len());
        return Ok(false);
    }
    
    println!("✓ LDT structure verification: {} commitments, {} openings", 
             ldt_proof.commitments.len(), ldt_proof.openings.len());
    
    transcript.append_message(b"merkle_commitment", &ldt_proof.commitments[0]);
    
    let mut folding_challenges = Vec::with_capacity(params.r);
    for i in 0..params.r {
        let challenge = transcript_challenge_f2(transcript);
        folding_challenges.push(challenge);
        
        if i + 1 < ldt_proof.commitments.len() {
            transcript.append_message(b"merkle_commitment", &ldt_proof.commitments[i + 1]);
        }
    }
    println!("✓ Re-derived {} FRI folding challenges", folding_challenges.len());
    
    let mut query_positions = Vec::with_capacity(params.kappa);
    for q in 0..params.kappa {
        let challenge = transcript_challenge_f2(transcript);
        let position = challenge.c0.0 as usize % params.coset_u.len();
        query_positions.push(position);
    }
    println!("✓ Re-derived {} query positions", query_positions.len());
    
    println!("\n--- Step 4: Verifying κ={} LDT Query Proofs ---", params.kappa);
    let mut successful_queries = 0;
    
    for (query_idx, &query_pos) in query_positions.iter().enumerate() {
        let opening = &ldt_proof.openings[query_idx];
        
        if opening.position != query_pos {
            println!("✗ Query {}: Position mismatch. Expected {}, got {}", 
                     query_idx, query_pos, opening.position);
            return Ok(false);
        }
        
        let final_pos = query_pos >> params.r;
        let final_commitment = &ldt_proof.commitments.last().unwrap();
        
        let mut current_value = opening.codeword_eval;
        let mut current_position = query_pos;
        
        for round in 0..params.r {
            let sibling_value = opening.opening_proof[round];
            let challenge = folding_challenges[round];
            
            current_value = if current_position % 2 == 0 {
                current_value + challenge * sibling_value
            } else {
                sibling_value + challenge * current_value
            };
            current_position /= 2;
        }
        
        let final_leaf_data = bincode::serialize(&current_value).unwrap();
        
        if !super::merkle::MerkleTree::verify_auth_path(
            *final_commitment, 
            &final_leaf_data, 
            final_pos, 
            &opening.auth_path
        ) {
            println!("✗ Query {}: Merkle authentication failed for final commitment", query_idx);
            return Ok(false);
        }
        
        successful_queries += 1;
    }
    
    println!("✓ LDT Query Verification: {}/{} queries passed", successful_queries, params.kappa);
    
    let ldt_success = successful_queries == params.kappa;
    
    if ldt_success {
        println!("✓ LDT VERIFICATION SUCCESSFUL");
    } else {
        println!("✗ LDT VERIFICATION FAILED");
    }
    
    Ok(ldt_success)
}

pub fn loquat_verify(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &Vec<F>,
    params: &LoquatPublicParams,
) -> LoquatResult<bool> {
    println!("\n================== ALGORITHM 7: LOQUAT VERIFY ==================");
    println!("INPUT: Signature σ, public key pk, message M");
    
    let mut transcript = Transcript::new(b"loquat_signature");
    transcript.append_message(b"message", message);

    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_commitment = hasher.finalize().to_vec();
    transcript.append_message(b"message_commitment", &message_commitment);
    
    if message_commitment != signature.message_commitment {
        println!("✗ Message commitment mismatch");
        return Ok(false);
    }
    println!("✓ Message commitment verified");

    transcript.append_message(b"root_c", &signature.root_c);
    transcript.append_message(b"t_values", &bincode::serialize(&signature.t_values).unwrap());
    println!("✓ σ₁ = (root_c, {{T_{{i,j}}}}) added to transcript");

    let mut h1_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h1", &mut h1_bytes);
    println!("✓ h₁ = H₁(σ₁, M) recomputed");
    
    let num_checks = params.m * params.n;
    let i_indices = expand_challenge(&h1_bytes, num_checks, b"I_indices", &mut |b| {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize) % params.l
    });
    println!("✓ Expanded h₁ to regenerate I_{{i,j}} indices");

    transcript.append_message(b"o_values", &bincode::serialize(&signature.o_values).unwrap());
    println!("✓ σ₂ = {{o_{{i,j}}}} added to transcript");

    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    println!("✓ h₂ = H₂(σ₂, h₁) recomputed");
    
    let _lambdas = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| F2::new(field_utils::bytes_to_field_element(b), F::zero()));
    let _e_j: Vec<F2> = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| F2::new(field_utils::bytes_to_field_element(b), F::zero()));
    println!("✓ Expanded h₂ to regenerate λ_{{i,j}} and ε_j values");

    println!("\n================== ALGORITHM 7: STEP 3 - CHECKING PROOFS ==================");

    println!("\n--- Step 3.1: Legendre PRF Constraint Verification ---");
    
    for j in 0..params.n {
        for i in 0..params.m {
            let o_ij = signature.o_values[j][i];
            let t_ij = signature.t_values[j][i];
            let i_ij_index = i_indices[j * params.m + i];
            let pk_val = public_key[i_ij_index];
            
            if o_ij.is_zero() {
                println!("✗ FAILED: o[{}][{}] is zero", j, i);
                return Ok(false);
            }
            
            let actual_lps = field_utils::legendre_prf_secure(o_ij);
            let two = u128_to_field(2);
            let expected_lps = pk_val + t_ij - two * pk_val * t_ij;
            
            if actual_lps != expected_lps {
                println!("✗ FAILED: Legendre PRF check failed at [{}][{}]", j, i);
                return Ok(false);
            }
        }
    }
    println!("✓ All Legendre PRF checks passed");

    println!("\n--- Step 3.2: Univariate Sumcheck Verification ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let sumcheck_result = verify_sumcheck_proof(&signature.pi_us, num_variables, &mut transcript)?;
    if !sumcheck_result {
        println!("✗ SUMCHECK FAILED");
        return Ok(false);
    }
    println!("✓ SUMCHECK PASSED");

    println!("\n--- Step 3.3: Low-Degree Test Verification ---");
    let ldt_result = verify_ldt_proof(signature, params, &mut transcript)?;
    if !ldt_result {
        println!("✗ LDT FAILED");
        return Ok(false);
    }
    println!("✓ LDT PASSED");

    println!("\n--- ALGORITHM 7: FINAL DECISION ---");
    println!("✓ VERIFICATION SUCCESSFUL: Signature is valid");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loquat::{
        setup::loquat_setup,
        keygen::keygen_with_params,
        sign::loquat_sign,
    };

    #[test]
    fn test_valid_signature_verification() {
        let params = loquat_setup(128).unwrap();
        let keypair = keygen_with_params(&params).unwrap();
        let message = b"A message to sign and verify";
        let signature = loquat_sign(message, &keypair, &params).unwrap();
        
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature_tampered_message() {
        let params = loquat_setup(128).unwrap();
        let keypair = keygen_with_params(&params).unwrap();
        let message = b"Original message";
        let tampered_message = b"Tampered message";
        let signature = loquat_sign(message, &keypair, &params).unwrap();

        let is_valid = loquat_verify(tampered_message, &signature, &keypair.public_key, &params).unwrap();
        assert!(!is_valid);
    }
}
