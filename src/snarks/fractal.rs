use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{bytes_to_field_element, field_to_bytes, F};
use crate::loquat::transcript::Transcript;
use crate::snarks::aurora::{
    aurora_digest, aurora_prove_with_options, aurora_verify, AuroraParams, AuroraProof,
    AuroraProverOptions, AuroraVerificationHints,
};
use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};
use serde::{Deserialize, Serialize};
use std::vec::Vec;

#[derive(Debug, Clone)]
pub struct FractalParams {
    pub aurora: AuroraParams,
    pub recursion_layers: usize,
}

impl Default for FractalParams {
    fn default() -> Self {
        Self {
            aurora: AuroraParams::default(),
            recursion_layers: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldLayerProof {
    pub challenge: F,
    pub proof: AuroraProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FractalProof {
    pub base_proof: AuroraProof,
    pub fold_layers: Vec<FoldLayerProof>,
    pub final_digest: F,
}

pub fn fractal_prove(
    instance: &R1csInstance,
    witness: &R1csWitness,
    params: &FractalParams,
) -> LoquatResult<FractalProof> {
    let base_proof = aurora_prove_with_options(
        instance,
        witness,
        &params.aurora,
        &AuroraProverOptions::default(),
    )?;
    let mut fold_layers = Vec::with_capacity(params.recursion_layers);
    let mut current_digest = digest_to_field(aurora_digest(&base_proof)?);

    for layer in 0..params.recursion_layers {
        let challenge = derive_fold_challenge(layer, current_digest);
        let (fold_instance, fold_witness) = build_fold_instance(current_digest, challenge)?;
        let layer_proof = aurora_prove_with_options(
            &fold_instance,
            &fold_witness,
            &params.aurora,
            &AuroraProverOptions {
                explicit_witness_queries: vec![1, 2],
            },
        )?;
        fold_layers.push(FoldLayerProof {
            challenge,
            proof: layer_proof,
        });
        current_digest = current_digest + challenge;
    }

    Ok(FractalProof {
        base_proof,
        fold_layers,
        final_digest: current_digest,
    })
}

pub fn fractal_verify(
    instance: &R1csInstance,
    proof: &FractalProof,
    params: &FractalParams,
) -> LoquatResult<bool> {
    let base_result = match aurora_verify(instance, &proof.base_proof, &params.aurora, None)? {
        Some(result) => result,
        None => return Ok(false),
    };
    drop(base_result); // base proof does not expose public witness slots

    let mut current_digest = digest_to_field(aurora_digest(&proof.base_proof)?);
    if proof.fold_layers.len() != params.recursion_layers {
        return Ok(false);
    }

    for (layer_idx, fold_layer) in proof.fold_layers.iter().enumerate() {
        let expected_challenge = derive_fold_challenge(layer_idx, current_digest);
        if expected_challenge != fold_layer.challenge {
            return Ok(false);
        }
        let (fold_instance, _) = build_fold_instance(current_digest, fold_layer.challenge)?;
        let hints = AuroraVerificationHints {
            explicit_witness_queries: vec![1, 2],
        };
        let layer_result = match aurora_verify(
            &fold_instance,
            &fold_layer.proof,
            &params.aurora,
            Some(&hints),
        )? {
            Some(result) => result,
            None => return Ok(false),
        };
        let x_current = layer_result
            .opened(1)
            .ok_or_else(|| LoquatError::verification_failure("missing x_current opening"))?;
        let x_next = layer_result
            .opened(2)
            .ok_or_else(|| LoquatError::verification_failure("missing x_next opening"))?;
        if x_current != current_digest {
            return Ok(false);
        }
        if x_next != x_current + fold_layer.challenge {
            return Ok(false);
        }
        current_digest = x_next;
    }

    Ok(current_digest == proof.final_digest)
}

fn build_fold_instance(current: F, challenge: F) -> LoquatResult<(R1csInstance, R1csWitness)> {
    let num_variables = 3;
    let mut constraint_a0 = vec![F::zero(); num_variables];
    constraint_a0[1] = F::one();
    let mut constraint_b0 = vec![F::zero(); num_variables];
    constraint_b0[0] = F::one();
    let mut constraint_c0 = vec![F::zero(); num_variables];
    constraint_c0[0] = current;

    let mut constraint_a1 = vec![F::zero(); num_variables];
    constraint_a1[1] = -F::one();
    constraint_a1[2] = F::one();
    let mut constraint_b1 = vec![F::zero(); num_variables];
    constraint_b1[0] = F::one();
    let mut constraint_c1 = vec![F::zero(); num_variables];
    constraint_c1[0] = challenge;

    let instance = R1csInstance::new(
        num_variables,
        vec![
            R1csConstraint::new(constraint_a0, constraint_b0, constraint_c0),
            R1csConstraint::new(constraint_a1, constraint_b1, constraint_c1),
        ],
    )?;
    let witness = R1csWitness::new(vec![current, current + challenge]);
    Ok((instance, witness))
}

fn derive_fold_challenge(layer: usize, digest: F) -> F {
    let mut transcript = Transcript::new(b"fractal_fold");
    transcript.append_message(b"layer", &(layer as u64).to_le_bytes());
    transcript.append_message(b"digest", &field_to_bytes(&digest));
    let mut buf = [0u8; 16];
    transcript.challenge_bytes(b"alpha", &mut buf);
    bytes_to_field_element(&buf)
}

fn digest_to_field(digest: [u8; 32]) -> F {
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&digest[..16]);
    bytes_to_field_element(&truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snarks::aurora::AuroraParams;
    use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};

    fn sample_instance() -> (R1csInstance, R1csWitness) {
        let num_variables = 4;
        let mut a = vec![F::zero(); num_variables];
        a[1] = F::one();
        let mut b = vec![F::zero(); num_variables];
        b[2] = F::one();
        let mut c = vec![F::zero(); num_variables];
        c[3] = F::one();
        let instance =
            R1csInstance::new(num_variables, vec![R1csConstraint::new(a, b, c)]).unwrap();
        let witness = R1csWitness::new(vec![F::new(3), F::new(7), F::new(21)]);
        (instance, witness)
    }

    #[test]
    fn fractal_round_trip() {
        let (instance, witness) = sample_instance();
        let params = FractalParams {
            aurora: AuroraParams {
                constraint_query_count: 2,
                witness_query_count: 3,
            },
            recursion_layers: 2,
        };
        let proof = fractal_prove(&instance, &witness, &params).unwrap();
        assert!(fractal_verify(&instance, &proof, &params).unwrap());
    }
}
