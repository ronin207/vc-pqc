use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{F, F2};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// Represents a simple linear polynomial, g(X) = c0 + c1*X.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinearPolynomial {
    pub c0: F2,
    pub c1: F2,
}

impl LinearPolynomial {
    pub fn new(c0: F2, c1: F2) -> Self {
        Self { c0, c1 }
    }

    pub fn evaluate(&self, point: &F2) -> F2 {
        self.c0 + self.c1 * *point
    }
}

/// Univariate Sumcheck proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnivariateSumcheckProof {
    /// Round polynomials g_1(X), ..., g_v(X) for v variables
    pub round_polynomials: Vec<LinearPolynomial>,
    /// Final evaluation P(r_1, ..., r_v)
    pub final_evaluation: F2,
    /// Claimed sum over the hypercube
    pub claimed_sum: F2,
}

/// Generate sumcheck proof for multilinear polynomial
pub fn generate_sumcheck_proof(
    polynomial_evals: &[F2],
    claimed_sum: F2,
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
            details: format!("Polynomial evaluations length {} doesn't match 2^{\n}", polynomial_evals.len(), num_variables)
        });
    }

    let mut round_polynomials = Vec::with_capacity(num_variables);
    let mut challenges = Vec::new();
    let mut current_evals = polynomial_evals.to_vec();
    
    let computed_sum: F2 = polynomial_evals.iter().sum();
    println!("Computed sum from polynomial_evals: {:?}", computed_sum);
    
    if computed_sum != claimed_sum {
        println!("WARNING: Computed sum != claimed sum");
        println!("  Computed: {:?}", computed_sum);
        println!("  Claimed:  {:?}", claimed_sum);
    }
    
    transcript.append_message(b"claimed_sum", &bincode::serialize(&claimed_sum).unwrap());

    for round_idx in 0..num_variables {
        println!("\n  Prover Round {}: ", round_idx);
        println!("    Current evaluations length: {}", current_evals.len());
        
        let mut round_poly_evals = Vec::new();
        // For a multilinear polynomial, the round polynomial g_j is linear.
        // We only need to evaluate it at 2 points (0 and 1) to determine it.
        for eval_point in 0..2 {
            let mut partial_sum = F2::zero();
            for i in 0..current_evals.len() / 2 {
                let val_0 = current_evals[2 * i];
                let val_1 = current_evals[2 * i + 1];
                // Evaluate g_j(eval_point)
                let interpolated = val_0 + (val_1 - val_0) * F2::new(F::new(eval_point), F::zero());
                partial_sum = partial_sum + interpolated;
            }
            round_poly_evals.push(partial_sum);
        }
        
        println!("    g_{}(0): {:?}", round_idx, round_poly_evals[0]);
        println!("    g_{}(1): {:?}", round_idx, round_poly_evals[1]);
        println!("    g_{}(0) + g_{}(1): {:?}", round_idx, round_idx, round_poly_evals[0] + round_poly_evals[1]);
        
        // Construct the linear polynomial g(X) = c0 + c1*X from g(0) and g(1).
        let c0 = round_poly_evals[0];
        let c1 = round_poly_evals[1] - c0;
        let round_poly = LinearPolynomial::new(c0, c1);

        round_polynomials.push(round_poly.clone());
        transcript.append_message(b"round_poly", &bincode::serialize(&round_poly).unwrap());

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

    transcript.append_message(b"claimed_sum", &bincode::serialize(&proof.claimed_sum).unwrap());
    println!("✓ Claimed sum added to transcript");

    let mut last_sum = proof.claimed_sum;
    println!("Starting verification with claimed sum: {:?}", last_sum);

    for (round_index, round_poly) in proof.round_polynomials.iter().enumerate() {
        println!("\n  Round {}: ", round_index);
        
        // Verify sum constraint: p(0) + p(1) should equal last_sum
        let p_0 = round_poly.evaluate(&F2::zero());
        let p_1 = round_poly.evaluate(&F2::one());
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
        transcript.append_message(b"round_poly", &bincode::serialize(round_poly).unwrap());
        
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

fn transcript_challenge(transcript: &mut Transcript) -> F2 {
    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut buf);
    // For simplicity, we'll create an F2 element from two F elements derived from the hash.
    let c0 = F::new(u128::from_le_bytes(buf[..16].try_into().unwrap()));
    let c1 = F::new(u128::from_le_bytes(buf[16..].try_into().unwrap()));
    F2::new(c0, c1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;

    #[test]
    fn test_sumcheck_protocol() {
        let num_variables = 2;
        let polynomial_evals = vec![
            F2::new(F::new(1), F::zero()), 
            F2::new(F::new(2), F::zero()), 
            F2::new(F::new(3), F::zero()), 
            F2::new(F::new(4), F::zero()),
        ];
        let claimed_sum = F2::new(F::new(10), F::zero());
        
        let mut prover_transcript = Transcript::new(b"test_sumcheck");
        let proof = generate_sumcheck_proof(&polynomial_evals, claimed_sum, num_variables, &mut prover_transcript).unwrap();
        
        let mut verifier_transcript = Transcript::new(b"test_sumcheck");
        let is_valid = verify_sumcheck_proof(&proof, num_variables, &mut verifier_transcript).unwrap();

        assert!(is_valid, "Sumcheck proof should verify");
        assert_eq!(proof.claimed_sum, claimed_sum);
    }
}
