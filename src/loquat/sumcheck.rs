use super::transcript::Transcript;
use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{field2_to_bytes, F, F2};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::cmp;

/// Represents a simple linear polynomial, g(X) = c0 + c1*X.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinearPolynomial {
    pub c0: F2,
    pub c1: F2,
}

fn append_f2_message(transcript: &mut Transcript, label: &'static [u8], value: &F2) {
    let bytes = field2_to_bytes(value);
    transcript.append_message(label, &bytes);
}

fn append_linear_polynomial(transcript: &mut Transcript, poly: &LinearPolynomial) {
    let c0_bytes = field2_to_bytes(&poly.c0);
    let c1_bytes = field2_to_bytes(&poly.c1);
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(&c0_bytes);
    buffer[32..].copy_from_slice(&c1_bytes);
    transcript.append_message(b"round_poly", &buffer);
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
#[cfg(feature = "std")]
pub fn generate_sumcheck_proof(
    polynomial_evals: &[F2],
    claimed_sum: F2,
    num_variables: usize,
    transcript: &mut Transcript,
) -> LoquatResult<UnivariateSumcheckProof> {
    loquat_debug!("\n--- SUMCHECK PROOF GENERATION ---");
    loquat_debug!("Polynomial evaluations length: {}", polynomial_evals.len());
    loquat_debug!(
        "Expected length (2^{}): {}",
        num_variables,
        1 << num_variables
    );
    loquat_debug!("Claimed sum: {:?}", claimed_sum);
    loquat_debug!(
        "First few evaluations: {:?}",
        &polynomial_evals[..cmp::min(8, polynomial_evals.len())]
    );

    if polynomial_evals.len() != (1 << num_variables) {
        return Err(crate::loquat::errors::LoquatError::SumcheckError {
            step: "proof_generation".to_string(),
            details: format!(
                "Polynomial evaluations length {} doesn't match 2^{\n}",
                polynomial_evals.len(),
                num_variables
            ),
        });
    }

    let mut round_polynomials = Vec::with_capacity(num_variables);
    let mut challenges = Vec::new();
    let mut current_evals = polynomial_evals.to_vec();

    let computed_sum: F2 = polynomial_evals.iter().sum();
    loquat_debug!("Computed sum from polynomial_evals: {:?}", computed_sum);

    if computed_sum != claimed_sum {
        loquat_debug!("WARNING: Computed sum != claimed sum");
        loquat_debug!("  Computed: {:?}", computed_sum);
        loquat_debug!("  Claimed:  {:?}", claimed_sum);
    }

    append_f2_message(transcript, b"claimed_sum", &claimed_sum);

    for round_idx in 0..num_variables {
        #[cfg(not(feature = "std"))]
        let _ = round_idx;
        loquat_debug!("\n  Prover Round {}: ", round_idx);
        loquat_debug!("    Current evaluations length: {}", current_evals.len());

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

        loquat_debug!("    g_{}(0): {:?}", round_idx, round_poly_evals[0]);
        loquat_debug!("    g_{}(1): {:?}", round_idx, round_poly_evals[1]);
        loquat_debug!(
            "    g_{}(0) + g_{}(1): {:?}",
            round_idx,
            round_idx,
            round_poly_evals[0] + round_poly_evals[1]
        );

        // Construct the linear polynomial g(X) = c0 + c1*X from g(0) and g(1).
        let c0 = round_poly_evals[0];
        let c1 = round_poly_evals[1] - c0;
        let round_poly = LinearPolynomial::new(c0, c1);

        round_polynomials.push(round_poly.clone());
        append_linear_polynomial(transcript, &round_poly);

        let challenge = transcript_challenge(transcript);
        loquat_debug!("    Challenge: {:?}", challenge);
        challenges.push(challenge);

        let mut next_evals = Vec::new();
        for i in 0..current_evals.len() / 2 {
            let val_0 = current_evals[2 * i];
            let val_1 = current_evals[2 * i + 1];
            next_evals.push(val_0 + (val_1 - val_0) * challenge);
        }
        current_evals = next_evals;
        loquat_debug!("    Next evaluations length: {}", current_evals.len());
    }

    let final_evaluation = current_evals[0];
    loquat_debug!("\nFinal evaluation: {:?}", final_evaluation);
    loquat_debug!("Generated {} round polynomials", round_polynomials.len());

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
    loquat_debug!("\n--- SUMCHECK VERIFICATION DETAILS ---");
    loquat_debug!("Number of variables: {}", num_variables);
    loquat_debug!("Proof round polynomials: {}", proof.round_polynomials.len());
    loquat_debug!("Proof claimed sum: {:?}", proof.claimed_sum);
    loquat_debug!("Proof final evaluation: {:?}", proof.final_evaluation);
    loquat_debug!("Following Univariate Sumcheck protocol from rules.mdc");

    if proof.round_polynomials.len() != num_variables {
        loquat_debug!("✗ SUMCHECK FAILED: Wrong number of round polynomials");
        loquat_debug!(
            "  Expected: {}, Got: {}",
            num_variables,
            proof.round_polynomials.len()
        );
        return Ok(false);
    }

    append_f2_message(transcript, b"claimed_sum", &proof.claimed_sum);
    loquat_debug!("✓ Claimed sum added to transcript");

    let mut last_sum = proof.claimed_sum;
    loquat_debug!("Starting verification with claimed sum: {:?}", last_sum);

    for (round_index, round_poly) in proof.round_polynomials.iter().enumerate() {
        #[cfg(not(feature = "std"))]
        let _ = round_index;
        loquat_debug!("\n  Round {}: ", round_index);

        // Verify sum constraint: p(0) + p(1) should equal last_sum
        let p_0 = round_poly.evaluate(&F2::zero());
        let p_1 = round_poly.evaluate(&F2::one());
        let current_sum = p_0 + p_1;

        loquat_debug!("    p(0): {:?}", p_0);
        loquat_debug!("    p(1): {:?}", p_1);
        loquat_debug!("    p(0) + p(1): {:?}", current_sum);
        loquat_debug!("    Expected sum (last_sum): {:?}", last_sum);

        if current_sum != last_sum {
            loquat_debug!(
                "✗ SUMCHECK FAILED at round {}: Sum constraint violation",
                round_index
            );
            loquat_debug!("  p(0) + p(1) = {:?}", current_sum);
            loquat_debug!("  Expected: {:?}", last_sum);
            return Ok(false);
        }

        loquat_debug!("    ✓ Sum constraint satisfied: p(0) + p(1) = last_sum");

        // Add polynomial to transcript and get challenge
        append_linear_polynomial(transcript, round_poly);

        let challenge = transcript_challenge(transcript);
        loquat_debug!("    Challenge: {:?}", challenge);

        // Evaluate polynomial at challenge point
        let p_challenge = round_poly.evaluate(&challenge);
        last_sum = p_challenge;
        loquat_debug!("    p(challenge): {:?}", p_challenge);
        loquat_debug!(
            "    Next evaluations length: {}",
            1 << (num_variables - round_index - 1)
        );
    }

    loquat_debug!("\nFinal evaluation check:");
    loquat_debug!("  Computed final value: {:?}", last_sum);
    loquat_debug!("  Proof final evaluation: {:?}", proof.final_evaluation);

    if last_sum != proof.final_evaluation {
        loquat_debug!("✗ SUMCHECK FAILED: Final evaluation mismatch");
        loquat_debug!("  Computed: {:?}", last_sum);
        loquat_debug!("  Expected: {:?}", proof.final_evaluation);
        return Ok(false);
    }

    loquat_debug!("  Match: {}", last_sum == proof.final_evaluation);
    loquat_debug!("✓ SUMCHECK VERIFICATION COMPLETE: All rounds passed");
    Ok(true)
}

pub fn replay_sumcheck_challenges(
    proof: &UnivariateSumcheckProof,
    num_variables: usize,
    transcript: &mut Transcript,
) -> LoquatResult<Vec<F2>> {
    if proof.round_polynomials.len() != num_variables {
        return Err(LoquatError::sumcheck_error(
            "challenge_replay",
            "round polynomial length mismatch",
        ));
    }
    append_f2_message(transcript, b"claimed_sum", &proof.claimed_sum);
    let mut challenges = Vec::with_capacity(num_variables);
    let mut last_sum = proof.claimed_sum;
    for round_poly in &proof.round_polynomials {
        let p0 = round_poly.evaluate(&F2::zero());
        let p1 = round_poly.evaluate(&F2::one());
        if p0 + p1 != last_sum {
            return Err(LoquatError::sumcheck_error(
                "challenge_replay",
                "sum constraint mismatch",
            ));
        }
        append_linear_polynomial(transcript, round_poly);
        let challenge = transcript_challenge(transcript);
        challenges.push(challenge);
        last_sum = round_poly.evaluate(&challenge);
    }
    if last_sum != proof.final_evaluation {
        return Err(LoquatError::sumcheck_error(
            "challenge_replay",
            "final evaluation mismatch",
        ));
    }
    Ok(challenges)
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
    use crate::loquat::transcript::Transcript;

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
        let proof = generate_sumcheck_proof(
            &polynomial_evals,
            claimed_sum,
            num_variables,
            &mut prover_transcript,
        )
        .unwrap();

        let mut verifier_transcript = Transcript::new(b"test_sumcheck");
        let is_valid =
            verify_sumcheck_proof(&proof, num_variables, &mut verifier_transcript).unwrap();

        assert!(is_valid, "Sumcheck proof should verify");
        assert_eq!(proof.claimed_sum, claimed_sum);
    }
}
