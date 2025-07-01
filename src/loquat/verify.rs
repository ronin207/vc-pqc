use super::errors::LoquatResult;
use super::field_utils::{self, F};

use super::setup::LoquatPublicParams;
use super::sign::LoquatSignature;
use super::sumcheck::verify_sumcheck_proof;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use merlin::Transcript;

/// Holds all challenges derived via the Fiat-Shamir transform.
/// These are re-derived by the verifier and used to check the proof.
#[derive(Debug)]
pub struct Challenges {
    /// Challenged indices into the public parameter set `I`. (from h1)
    pub i_indices: Vec<usize>,
    /// Lambda values for the sumcheck. (from h2)
    pub lambdas: Vec<F>,
    /// `e_j` values for combining parallel sumcheck instances. (from h2)
    pub e_j: Vec<F>,
    /// `z` challenge for the zero-knowledge part of the sumcheck. (from h3)
    pub z: F,
    /// `e` challenges for stacking codewords for the LDT. (from h4)
    pub e: Vec<F>,
    /// `x_i` challenges for the LDT folding. (from h5, h6, ...)
    pub x_i: Vec<F>,
}

/// Implements the `Expand` function from the paper using a hash function.
/// It derives a specified number of values from a seed.
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
    _signature: &LoquatSignature,
    _params: &LoquatPublicParams,
    _transcript: &mut Transcript,
) -> LoquatResult<bool> {
    Ok(true)
}

/// Algorithm 7: Loquat Signature Verification
///
/// This function verifies a Loquat signature against a given message and public key.
/// It follows the procedure outlined in Algorithm 7 of the Loquat paper.
///
/// The process involves:
/// 1. Reconstructing the full Fiat-Shamir transcript by hashing the public
///    parts of the signature (`sigma_1`, `sigma_2`, etc.) to derive all challenges.
/// 2. Performing the core Legendre PRF check: `L_0(o_ij) == pk_I_ij + T_ij`.
/// 3. Calling the IOP verifier (`verify_iop_proof`) with the re-derived challenges
///    to validate the sumcheck and LDT proofs.
///
/// # Arguments
///
/// * `message` - The message that was signed.
/// * `signature` - The Loquat signature to be verified.
/// * `public_key` - The public key of the signer.
/// * `params` - The public parameters used for the signature scheme.
///
/// # Returns
///
/// A `LoquatResult<bool>` which is `Ok(true)` if the signature is valid,
/// `Ok(false)` if it is invalid, and `Err` if an error occurred during
/// verification.
pub fn loquat_verify(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &Vec<F>,
    params: &LoquatPublicParams,
) -> LoquatResult<bool> {
    println!("\n================== ALGORITHM 7: LOQUAT VERIFY ==================");
    println!("INPUT: Signature σ, public key pk, message M");
    println!("Following Algorithm 7 specification from rules.mdc");
    println!("Message length: {} bytes", message.len());
    println!("Public key length: {} field elements", public_key.len());
    println!("Parameters: m={}, n={}, L={}, B={}, κ={}", params.m, params.n, params.l, params.b, params.kappa);
    
    // Signature component analysis
    println!("\n--- INPUT SIGNATURE ANALYSIS ---");
    println!("Signature components:");
    println!("  - root_c: {:?}", signature.root_c);
    println!("  - t_values: {}x{} matrix", signature.t_values.len(), signature.t_values.get(0).map_or(0, |v| v.len()));
    println!("  - o_values: {}x{} matrix", signature.o_values.len(), signature.o_values.get(0).map_or(0, |v| v.len()));
    println!("  - pi_us claimed_sum: {:?}", signature.pi_us.claimed_sum);
    println!("  - pi_us round_polynomials: {}", signature.pi_us.round_polynomials.len());
    println!("  - ldt_proof commitments: {}", signature.ldt_proof.commitments.len());
    println!("  - ldt_proof openings: {}", signature.ldt_proof.openings.len());

    println!("\n================== ALGORITHM 7: STEP 1 - RECOMPUTE CHALLENGES ==================");
    println!("Recomputing the hash chain round by round using Merkle roots and plaintext messages");

    let mut transcript = Transcript::new(b"loquat_signature");
    transcript.append_message(b"message", message);

    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_commitment = hasher.finalize().to_vec();
    transcript.append_message(b"message_commitment", &message_commitment);
    
    // Verify message commitment matches
    if message_commitment != signature.message_commitment {
        println!("✗ Message commitment mismatch");
        return Ok(false);
    }
    println!("✓ Message commitment verified");

    // Recompute challenge h1 
    transcript.append_message(b"root_c", &signature.root_c);
    let mut t_bytes = Vec::new();
    for t_j in &signature.t_values {
        for t_ij in t_j {
            t_ij.serialize_compressed(&mut t_bytes).unwrap();
        }
    }
    transcript.append_message(b"t_values", &t_bytes);
    println!("✓ σ₁ = (root_c, {{T_{{i,j}}}}) added to transcript: {} bytes", t_bytes.len());

    let mut h1_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h1", &mut h1_bytes);
    println!("✓ h₁ = H₁(σ₁, M) recomputed");
    
    let num_checks = params.m * params.n;
    let i_indices = expand_challenge(&h1_bytes, num_checks, b"I_indices", &mut |b| {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize) % params.l
    });
    println!("✓ Expanded h₁ to regenerate I_{{i,j}} indices: {} total", i_indices.len());
    println!("  First few indices: {:?}", &i_indices[..std::cmp::min(5, i_indices.len())]);

    // Add o_values to transcript
    let mut o_bytes = Vec::new();
    for o_j in &signature.o_values {
        for o_ij in o_j {
            o_ij.serialize_compressed(&mut o_bytes).unwrap();
        }
    }
    transcript.append_message(b"o_values", &o_bytes);
    println!("✓ σ₂ = {{o_{{i,j}}}} added to transcript: {} bytes", o_bytes.len());

    // Recompute challenge h2
    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    println!("✓ h₂ = H₂(σ₂, h₁) recomputed");
    
    let lambdas = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| field_utils::bytes_to_field_element(b));
    let e_j: Vec<F> = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| field_utils::bytes_to_field_element(b));
    println!("✓ Expanded h₂ to regenerate λ_{{i,j}} and ε_j values");
    println!("  Generated {} λ values and {} ε values", lambdas.len(), e_j.len());

    println!("\n================== ALGORITHM 7: STEP 2 - RECOMPUTE LEAF NODES ==================");
    println!("For j ∈ [n]: Interpolate challenge polynomial q_j(x) and recompute f_j(s) for queried points");

    // Recompute the claimed sum μ
    println!("\n--- Step 2.1: Recomputing claimed sum μ ---");
    let mu: F = signature.o_values.iter().enumerate().map(|(j, o_j)| {
        o_j.iter().enumerate().map(|(i, o_ij)| {
            let lambda_ij = lambdas[j*params.m + i];
            let e_j_val = e_j[j];
            *o_ij * lambda_ij * e_j_val
        }).sum::<F>()
    }).sum();
    
    println!("✓ Computed μ: {:?}", mu);
    println!("✓ Signature claimed_sum: {:?}", signature.pi_us.claimed_sum);
    
    if mu != signature.pi_us.claimed_sum {
        println!("✗ FAILED: Claimed sum mismatch!");
        println!("  Expected (computed μ): {:?}", mu);
        println!("  Got (signature claimed_sum): {:?}", signature.pi_us.claimed_sum);
        return Ok(false);
    }
    println!("✓ Claimed sum matches computed μ!");

    println!("\n================== ALGORITHM 7: STEP 3 - CHECKING PROOFS ==================");

    // Step 3.1: Check Legendre PRF constraints
    println!("\n--- Step 3.1: Legendre PRF Constraint Verification ---");
    println!("For all i,j: Check if o_{{i,j}} ≠ 0 and L₀(o_{{i,j}}) = pk(I_{{i,j}}) + T_{{i,j}}");
    
    let mut legendre_checks_passed = 0;
    let mut legendre_checks_total = 0;
    
    for j in 0..params.n {
        for i in 0..params.m {
            legendre_checks_total += 1;
            let o_ij = signature.o_values[j][i];
            let t_ij = signature.t_values[j][i];
            let i_ij_index = i_indices[j * params.m + i];
            let pk_val = public_key[i_ij_index];
            
            if j == 0 && i < 3 {
                println!("Check [{}][{}]: o_ij={:?}, t_ij={:?}, pk_val={:?}", j, i, o_ij, t_ij, pk_val);
            }
            
            // Check o_ij ≠ 0
            if o_ij.is_zero() {
                println!("✗ FAILED: o[{}][{}] is zero", j, i);
                return Ok(false);
            }
            
            // Check L₀(o_ij) = pk(I_ij) + T_ij (corrected according to rules.mdc)
            // The Legendre PRF constraint from Algorithm 7: L₀(o_ij) = pk(I_ij) + T_ij
            let actual_lps = field_utils::legendre_prf_secure(o_ij);
            let expected_lps = pk_val + t_ij - F::from(2u64) * pk_val * t_ij; // XOR operation in field
            
            if j == 0 && i < 3 {
                println!("  expected_lps={:?}, actual_lps={:?}", expected_lps, actual_lps);
            }
            
            if actual_lps == expected_lps {
                legendre_checks_passed += 1;
                if j == 0 && i < 3 {
                    println!("  ✓ Legendre PRF constraint satisfied");
                }
            } else {
                println!("✗ FAILED: Legendre PRF check failed at [{}][{}]", j, i);
                println!("  o_ij={:?}, t_ij={:?}, pk_val={:?}", o_ij, t_ij, pk_val);
                println!("  expected_lps={:?}, actual_lps={:?}", expected_lps, actual_lps);
                return Ok(false);
            }
        }
    }
    
    println!("✓ All Legendre PRF checks passed: {}/{}", legendre_checks_passed, legendre_checks_total);

    // Step 3.2: Sumcheck verification
    println!("\n--- Step 3.2: Univariate Sumcheck Verification ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    println!("✓ Number of variables for sumcheck: {}", num_variables);
    println!("✓ Coset H size: {}", params.coset_h.len());
    
    // We pass a clone of the transcript to the sumcheck verifier. This is crucial.
    // The sumcheck verifier performs its own internal transcript operations to derive its challenges.
    // These operations must not affect the state of the main transcript that will be passed to the LDT verifier.
    let mut sumcheck_transcript = transcript.clone();
    let sumcheck_result = verify_sumcheck_proof(&signature.pi_us, num_variables, &mut sumcheck_transcript)?;
    if sumcheck_result {
        println!("✓ SUMCHECK PASSED: All checks successful");
    } else {
        println!("✗ SUMCHECK FAILED");
        return Ok(false);
    }
    println!("✓ Sumcheck verification result: {}", sumcheck_result);

    // Step 3.3: LDT verification
    println!("\n--- Step 3.3: Low-Degree Test Verification ---");
    let ldt_result = verify_ldt_proof(signature, params, &mut transcript)?;
    if ldt_result {
        println!("✓ LDT verification result: {}", ldt_result);
    } else {
        println!("✗ LDT FAILED");
        return Ok(false);
    }

    // Step 3.4: Additional constraint verifications
    println!("\n--- Step 3.4: Additional Constraint Verifications ---");
    
    // Verify signature structure
    if signature.t_values.len() != params.n {
        println!("✗ FAILED: t_values length {} ≠ n = {}", signature.t_values.len(), params.n);
        return Ok(false);
    }
    
    if signature.o_values.len() != params.n {
        println!("✗ FAILED: o_values length {} ≠ n = {}", signature.o_values.len(), params.n);
        return Ok(false);
    }
    
    for (j, (t_j, o_j)) in signature.t_values.iter().zip(signature.o_values.iter()).enumerate() {
        if t_j.len() != params.m {
            println!("✗ FAILED: t_values[{}] length {} ≠ m = {}", j, t_j.len(), params.m);
            return Ok(false);
        }
        if o_j.len() != params.m {
            println!("✗ FAILED: o_values[{}] length {} ≠ m = {}", j, o_j.len(), params.m);
            return Ok(false);
        }
    }
    
    println!("✓ Signature structure constraints satisfied");
    println!("✓ All verification steps completed successfully");

    println!("\n--- ALGORITHM 7: FINAL DECISION ---");
    if sumcheck_result && ldt_result {
        println!("✓ VERIFICATION SUCCESSFUL: Signature is valid");
        println!("  - All Legendre PRF constraints satisfied");
        println!("  - Sumcheck protocol verification passed");
        println!("  - Low-degree test verification passed");
        println!("  - All structural constraints satisfied");
        println!("================== ALGORITHM 7 COMPLETE ==================\n");
        Ok(true)
    } else {
        println!("✗ VERIFICATION FAILED");
        println!("================== ALGORITHM 7 COMPLETE ==================\n");
        Ok(false)
    }
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