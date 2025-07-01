use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{F};
use crate::loquat::ark_serde;
use ark_poly::{univariate::DensePolynomial, Polynomial, DenseUVPolynomial};
use ark_ff::{PrimeField, Zero, One};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use ark_serialize::CanonicalSerialize;

/// Univariate Sumcheck proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnivariateSumcheckProof {
    /// Round polynomials g_1(X), ..., g_v(X) for v variables
    #[serde(with = "ark_serde::vec")]
    pub round_polynomials: Vec<DensePolynomial<F>>,
    /// Final evaluation P(r_1, ..., r_v)
    #[serde(with = "ark_serde")]
    pub final_evaluation: F,
    /// Claimed sum over the hypercube
    #[serde(with = "ark_serde")]
    pub claimed_sum: F,
}

/// Generate sumcheck proof for multilinear polynomial
pub fn generate_sumcheck_proof(
    polynomial_evals: &[F],
    claimed_sum: F,
    num_variables: usize,
    transcript: &mut Transcript,
) -> LoquatResult<UnivariateSumcheckProof> {
    println!("\n--- SUMCHECK PROOF GENERATION ---");
    println!("Polynomial evaluations length: {}", polynomial_evals.len());
    println!("Expected length (2^{}): {}", num_variables, 1 << num_variables);
    println!("Claimed sum: {:?}", claimed_sum);
    println!("First few evaluations: {:?}", &polynomial_evals[..std::cmp::min(8, polynomial_evals.len())]);

    if polynomial_evals.len() != (1 << num_variables) {
        return Err(LoquatError::SumcheckError {
            step: "proof_generation".to_string(),
            details: format!("Polynomial evaluations length {} doesn't match 2^{}", polynomial_evals.len(), num_variables)
        });
    }

    let mut round_polynomials = Vec::with_capacity(num_variables);
    let mut challenges = Vec::new();
    let mut current_evals = polynomial_evals.to_vec();
    
    let computed_sum: F = polynomial_evals.iter().sum();
    println!("Computed sum from polynomial_evals: {:?}", computed_sum);
    
    if computed_sum != claimed_sum {
        println!("WARNING: Computed sum != claimed sum");
        println!("  Computed: {:?}", computed_sum);
        println!("  Claimed:  {:?}", claimed_sum);
    }
    
    let mut sum_bytes = Vec::new();
    claimed_sum.serialize_compressed(&mut sum_bytes).unwrap();
    transcript.append_message(b"claimed_sum", &sum_bytes);

    for round_idx in 0..num_variables {
        println!("\n  Prover Round {}: ", round_idx);
        println!("    Current evaluations length: {}", current_evals.len());
        
        let mut round_poly_evals = Vec::new();
        // For a multilinear polynomial, the round polynomial g_j is linear.
        // We only need to evaluate it at 2 points (0 and 1) to determine it.
        for eval_point in 0..2 {
            let mut partial_sum = F::zero();
            for i in 0..current_evals.len() / 2 {
                let val_0 = current_evals[2 * i];
                let val_1 = current_evals[2 * i + 1];
                // Evaluate g_j(eval_point)
                let interpolated = val_0 + (val_1 - val_0) * F::from(eval_point as u64);
                partial_sum += interpolated;
            }
            round_poly_evals.push(partial_sum);
        }
        
        println!("    g_{}(0): {:?}", round_idx, round_poly_evals[0]);
        println!("    g_{}(1): {:?}", round_idx, round_poly_evals[1]);
        println!("    g_{}(0) + g_{}(1): {:?}", round_idx, round_idx, round_poly_evals[0] + round_poly_evals[1]);
        
        // Construct the linear polynomial g(X) = c0 + c1*X from g(0) and g(1).
        // c0 = g(0), c1 = g(1) - g(0).
        let round_poly = DensePolynomial::from_coefficients_vec(vec![round_poly_evals[0], round_poly_evals[1] - round_poly_evals[0]]);
        println!("    Polynomial degree: {}", round_poly.degree());
        round_polynomials.push(round_poly.clone());
        let mut poly_bytes = Vec::new();
        round_poly.serialize_compressed(&mut poly_bytes).unwrap();
        transcript.append_message(b"round_poly", &poly_bytes);

        let challenge = transcript_challenge(transcript);
        println!("    Challenge: {:?}", challenge);
        challenges.push(challenge);

        let mut next_evals = Vec::new();
        for i in 0..current_evals.len() / 2 {
            let val_0 = current_evals[2 * i];
            let val_1 = current_evals[2 * i + 1];
            next_evals.push(val_0 + (val_1 - val_0) * challenge);
        }
        current_evals = next_evals;
        println!("    Next evaluations length: {}", current_evals.len());
    }
    
    let final_evaluation = current_evals[0];
    println!("\nFinal evaluation: {:?}", final_evaluation);
    println!("Generated {} round polynomials", round_polynomials.len());
    
    Ok(UnivariateSumcheckProof {
        round_polynomials,
        final_evaluation,
        claimed_sum,
    })
}

/// Verify sumcheck proof
pub fn verify_sumcheck_proof(
    proof: &UnivariateSumcheckProof,
    num_variables: usize,
    transcript: &mut Transcript,
) -> LoquatResult<bool> {
    println!("\n--- SUMCHECK VERIFICATION DETAILS ---");
    println!("Number of variables: {}", num_variables);
    println!("Proof round polynomials: {}", proof.round_polynomials.len());
    println!("Proof claimed sum: {:?}", proof.claimed_sum);
    println!("Proof final evaluation: {:?}", proof.final_evaluation);
    println!("Following Univariate Sumcheck protocol from rules.mdc");

    if proof.round_polynomials.len() != num_variables {
        println!("✗ SUMCHECK FAILED: Wrong number of round polynomials");
        println!("  Expected: {}, Got: {}", num_variables, proof.round_polynomials.len());
        return Ok(false);
    }

    let mut sum_bytes = Vec::new();
    proof.claimed_sum.serialize_compressed(&mut sum_bytes).unwrap();
    transcript.append_message(b"claimed_sum", &sum_bytes);
    println!("✓ Claimed sum added to transcript");

    let mut last_sum = proof.claimed_sum;
    println!("Starting verification with claimed sum: {:?}", last_sum);

    for (round_index, round_poly) in proof.round_polynomials.iter().enumerate() {
        println!("\n  Round {}: ", round_index);
        println!("    Polynomial degree: {}", round_poly.degree());
        
        // Verify sum constraint: p(0) + p(1) should equal last_sum
        let p_0 = round_poly.evaluate(&F::zero());
        let p_1 = round_poly.evaluate(&F::one());
        let current_sum = p_0 + p_1;
        
        println!("    p(0): {:?}", p_0);
        println!("    p(1): {:?}", p_1);
        println!("    p(0) + p(1): {:?}", current_sum);
        println!("    Expected sum (last_sum): {:?}", last_sum);
        
        if current_sum != last_sum {
            println!("✗ SUMCHECK FAILED at round {}: Sum constraint violation", round_index);
            println!("  p(0) + p(1) = {:?}", current_sum);
            println!("  Expected: {:?}", last_sum);
            return Ok(false);
        }
        
        println!("    ✓ Sum constraint satisfied: p(0) + p(1) = last_sum");

        // Add polynomial to transcript and get challenge
        let mut poly_bytes = Vec::new();
        round_poly.serialize_compressed(&mut poly_bytes).unwrap();
        transcript.append_message(b"round_poly", &poly_bytes);
        
        let challenge = transcript_challenge(transcript);
        println!("    Challenge: {:?}", challenge);
        
        // Evaluate polynomial at challenge point
        let p_challenge = round_poly.evaluate(&challenge);
        last_sum = p_challenge;
        println!("    p(challenge): {:?}", p_challenge);
        println!("    Next evaluations length: {}", 1 << (num_variables - round_index - 1));
    }

    println!("\nFinal evaluation check:");
    println!("  Computed final value: {:?}", last_sum);
    println!("  Proof final evaluation: {:?}", proof.final_evaluation);
    
    if last_sum != proof.final_evaluation {
        println!("✗ SUMCHECK FAILED: Final evaluation mismatch");
        println!("  Computed: {:?}", last_sum);
        println!("  Expected: {:?}", proof.final_evaluation);
        return Ok(false);
    }

    println!("  Match: {}", last_sum == proof.final_evaluation);
    println!("✓ SUMCHECK VERIFICATION COMPLETE: All rounds passed");
    Ok(true)
}

fn transcript_challenge(transcript: &mut Transcript) -> F {
    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut buf);
    F::from_le_bytes_mod_order(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;

    #[test]
    fn test_sumcheck_protocol() {
        let num_variables = 2;
        let polynomial_evals = vec![F::from(1u64), F::from(2u64), F::from(3u64), F::from(4u64)];
        
        let mut prover_transcript = Transcript::new(b"test_sumcheck");
        let proof = generate_sumcheck_proof(&polynomial_evals, F::from(10u64), num_variables, &mut prover_transcript).unwrap();
        
        let mut verifier_transcript = Transcript::new(b"test_sumcheck");
        let is_valid = verify_sumcheck_proof(&proof, num_variables, &mut verifier_transcript).unwrap();

        assert!(is_valid, "Sumcheck proof should verify");
        assert_eq!(proof.claimed_sum, F::from(10u64));
    }
}