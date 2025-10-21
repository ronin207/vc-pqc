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
    
    if signature.fri_codewords.len() != params.r + 1
        || signature.fri_rows.len() != params.r + 1
        || signature.fri_challenges.len() != params.r
    {
        println!("✗ Signature missing FRI folding transcript");
        return Ok(false);
    }

    if signature.fri_rows[0].len() != signature.pi_rows.len() {
        println!("✗ Π row count mismatch");
        return Ok(false);
    }

    for (idx, layer) in signature.fri_codewords.iter().enumerate() {
        let leaves: Vec<Vec<u8>> = layer.iter().map(|v| bincode::serialize(v).unwrap()).collect();
        let tree = super::merkle::MerkleTree::new(&leaves);
        let root = tree.root().ok_or_else(|| LoquatError::MerkleError {
            operation: "verify_fri_root".to_string(),
            details: "Merkle tree root is empty".to_string(),
        })?;
        if root.as_slice() != ldt_proof.commitments[idx] {
            println!("✗ FRI commitment mismatch at layer {}", idx);
            return Ok(false);
        }
    }

    if folding_challenges != signature.fri_challenges {
        println!("✗ Folding challenges mismatch between signer and verifier");
        return Ok(false);
    }

    let chunk_size = 1 << params.eta;

    println!("\n--- Step 4: Verifying κ={} LDT Query Proofs ---", params.kappa);
    for (query_idx, opening) in ldt_proof.openings.iter().enumerate() {
        let challenge = transcript_challenge_f2(transcript);
        let expected_pos = challenge.c0.0 as usize % signature.fri_codewords[0].len();
        if opening.position != expected_pos {
            println!("✗ Query {}: position mismatch with transcript challenge", query_idx);
            return Ok(false);
        }
        if opening.position >= signature.fri_codewords[0].len() {
            println!("✗ Query {}: position out of range", query_idx);
            return Ok(false);
        }
        if opening.codeword_chunks.len() != params.r
            || opening.row_chunks.len() != params.r
        {
            println!("✗ Query {}: incomplete folding data", query_idx);
            return Ok(false);
        }

        let mut fold_index = opening.position;
        for round in 0..params.r {
            let layer_len = signature.fri_codewords[round].len();
            let chunk_len = chunk_size.min(layer_len);
            let chunk_start = if layer_len > chunk_size {
                (fold_index / chunk_size) * chunk_size
            } else {
                0
            };
            let chunk_end = (chunk_start + chunk_len).min(layer_len);

            let expected_chunk = &signature.fri_codewords[round][chunk_start..chunk_end];
            if opening.codeword_chunks[round] != expected_chunk {
                println!("✗ Query {}: codeword chunk mismatch at round {}", query_idx, round);
                return Ok(false);
            }

            let mut coeff = F2::one();
            let mut folded_val = F2::zero();
            for &val in expected_chunk {
                folded_val += val * coeff;
                coeff *= signature.fri_challenges[round];
            }

            let expected_next = signature.fri_codewords[round + 1][fold_index / chunk_size];
            if folded_val != expected_next {
                println!("✗ Query {}: codeword folding inconsistency at round {}", query_idx, round);
                return Ok(false);
            }

            if signature.fri_rows[round].len() != opening.row_chunks[round].len() {
                println!("✗ Query {}: row chunk count mismatch at round {}", query_idx, round);
                return Ok(false);
            }

            for (row_idx, chunk) in opening.row_chunks[round].iter().enumerate() {
                let expected_row_chunk = &signature.fri_rows[round][row_idx][chunk_start..chunk_end];
                if chunk != expected_row_chunk {
                    println!("✗ Query {}: Π row chunk mismatch at round {}, row {}", query_idx, round, row_idx);
                    return Ok(false);
                }

                let mut coeff = F2::one();
                let mut folded_row = F2::zero();
                for &val in chunk {
                    folded_row += val * coeff;
                    coeff *= signature.fri_challenges[round];
                }

                let expected_row_next = signature.fri_rows[round + 1][row_idx][fold_index / chunk_size];
                if folded_row != expected_row_next {
                    println!("✗ Query {}: Π row folding inconsistency at round {}, row {}", query_idx, round, row_idx);
                    return Ok(false);
                }
            }

            if layer_len > chunk_size {
                fold_index /= chunk_size;
            } else {
                fold_index = 0;
            }
        }

        let final_expected = signature.fri_codewords.last().unwrap()[fold_index];
        if opening.final_eval != final_expected {
            println!("✗ Query {}: final folded evaluation mismatch", query_idx);
            return Ok(false);
        }

        let leaf_bytes = bincode::serialize(&opening.final_eval).unwrap();
        if !super::merkle::MerkleTree::verify_auth_path(
            ldt_proof.commitments.last().unwrap().as_ref(),
            &leaf_bytes,
            fold_index,
            &opening.auth_path,
        ) {
            println!("✗ Query {}: final Merkle authentication failed", query_idx);
            return Ok(false);
        }
    }

    println!("✓ LDT Query Verification: {} queries passed", params.kappa);
    println!("✓ LDT VERIFICATION SUCCESSFUL");
    Ok(true)
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
    
    let lambda_scalars: Vec<F> = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| field_utils::bytes_to_field_element(b));
    let epsilon_vals: Vec<F2> = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| F2::new(field_utils::bytes_to_field_element(b), F::zero()));
    println!("✓ Expanded h₂ to regenerate λ_{{i,j}} and ε_j values");

    if signature.pi_rows.len() != 8 {
        println!("✗ Signature missing stacked matrix rows");
        return Ok(false);
    }

    if signature.c_prime_evals.len() != params.n
        || signature.s_evals.len() != params.coset_u.len()
        || signature.h_evals.len() != params.coset_u.len()
        || signature.f_prime_evals.len() != params.coset_u.len()
        || signature.p_evals.len() != params.coset_u.len()
        || signature.f0_evals.len() != params.coset_u.len()
        || signature.pi_rows.iter().any(|row| row.len() != params.coset_u.len())
    {
        println!("✗ Signature has inconsistent evaluation vector lengths");
        return Ok(false);
    }

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

    let mut mu_check = F2::zero();
    for j in 0..params.n {
        let epsilon = epsilon_vals[j];
        for i in 0..params.m {
            let lambda_scalar = lambda_scalars[j * params.m + i];
            let o_scalar = signature.o_values[j][i];
            mu_check += epsilon * F2::new(lambda_scalar * o_scalar, F::zero());
        }
    }
    if mu_check != signature.mu {
        println!("✗ μ mismatch between prover and verifier");
        return Ok(false);
    }
    println!("✓ μ value verified");

    if signature.e_vector.len() != 8 {
        println!("✗ e-vector length mismatch");
        return Ok(false);
    }

    let mut c_row_expected = Vec::with_capacity(params.coset_u.len());
    for idx in 0..params.coset_u.len() {
        let mut sum = F2::zero();
        for j in 0..params.n {
            sum += signature.c_prime_evals[j][idx];
        }
        c_row_expected.push(sum);
    }
    if c_row_expected != signature.pi_rows[0] {
        println!("✗ Stacked matrix ĉ′ row mismatch");
        return Ok(false);
    }
    if signature.s_evals != signature.pi_rows[1]
        || signature.h_evals != signature.pi_rows[2]
        || signature.p_evals != signature.pi_rows[3]
    {
        println!("✗ Π₀ rows do not match stored evaluations");
        return Ok(false);
    }

    for row_idx in 0..4 {
        let exponent = params
            .rho_star_num
            .checked_sub(params.rho_numerators[row_idx])
            .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_i"))? as u128;
        let mut scaled_expected = Vec::with_capacity(params.coset_u.len());
        for (value, &y) in signature.pi_rows[row_idx].iter().zip(params.coset_u.iter()) {
            let y_pow = y.pow(exponent);
            scaled_expected.push(*value * y_pow);
        }
        if scaled_expected != signature.pi_rows[row_idx + 4] {
            println!("✗ Π₁ row {} mismatch", row_idx + 1);
            return Ok(false);
        }
    }
    println!("✓ Π rows verified");

    let mut f0_expected = vec![F2::zero(); params.coset_u.len()];
    for (row_idx, row) in signature.pi_rows.iter().enumerate() {
        let coeff = signature.e_vector[row_idx];
        for (col, value) in row.iter().enumerate() {
            f0_expected[col] += coeff * *value;
        }
    }
    if f0_expected != signature.f0_evals {
        println!("✗ f^(0) evaluations mismatch");
        return Ok(false);
    }
    println!("✓ f^(0) evaluations verified");

    println!("\n--- Step 3.2: Univariate Sumcheck Verification ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let sumcheck_result = verify_sumcheck_proof(&signature.pi_us, num_variables, &mut transcript)?;
    if !sumcheck_result {
        println!("✗ SUMCHECK FAILED");
        return Ok(false);
    }
    println!("✓ SUMCHECK PASSED");

    transcript.append_message(b"root_s", &signature.root_s);
    transcript.append_message(b"s_sum", &bincode::serialize(&signature.s_sum).unwrap());
    println!("✓ σ₃ = (root_s, S) added to transcript");

    let mut h3_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h3", &mut h3_bytes);
    let expected_z_scalar = field_utils::bytes_to_field_element(&h3_bytes);
    let expected_z = F2::new(expected_z_scalar, F::zero());
    if expected_z != signature.z_challenge {
        println!("✗ Z challenge mismatch");
        return Ok(false);
    }
    println!("✓ h₃ challenge verified");

    transcript.append_message(b"root_h", &signature.root_h);
    println!("✓ σ₄ = (root_h) added to transcript");

    let mut h4_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h4", &mut h4_bytes);
    let expected_e_vector = expand_challenge(&h4_bytes, 8, b"e_vector", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });
    if expected_e_vector != signature.e_vector {
        println!("✗ e-vector mismatch in Algorithm 5");
        return Ok(false);
    }
    println!("✓ h₄ challenge verified");

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
