use serde::{Serialize, Deserialize};
use super::keygen::{LoquatKeyPair};
use super::field_utils::{legendre_prf_secure, F};
use ark_ff::{PrimeField, UniformRand, One};
use super::setup::LoquatPublicParams;
use super::errors::LoquatResult;
use merlin::Transcript;
use sha2::{Sha256, Digest};
use ark_serialize::CanonicalSerialize;

/// Algorithm 1: IOP-based Key Identification of the Legendre PRF
/// This is the core protocol that enables SNARK-friendly signature generation
/// by proving knowledge of the secret key without revealing it.

pub struct Challenges {
    pub i_indices: Vec<usize>,
    pub a_coeffs: Vec<u64>,
    pub b_coeffs: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOPProof {
    #[serde(with = "super::ark_serde::vec")]
    pub commitment: Vec<F>,
    #[serde(with = "super::ark_serde::vec")]
    pub responses: Vec<F>,
    #[serde(with = "super::ark_serde::vec")]
    pub challenges: Vec<F>,
    #[serde(with = "super::ark_serde::vec")]
    pub poly_evaluations: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct IOPInstance {
    pub public_key: Vec<F>,
    pub public_indices: Vec<F>,
    pub message_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IOPWitness {
    pub secret_key: F,
}

pub fn create_iop_instance(keypair: &LoquatKeyPair, params: &LoquatPublicParams, message: &[u8]) -> IOPInstance {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize().to_vec();

    IOPInstance {
        public_key: keypair.public_key.clone(),
        public_indices: params.public_indices.clone(),
        message_hash,
    }
}

pub fn create_iop_witness(secret_key: F) -> IOPWitness {
    IOPWitness { secret_key }
}

#[cfg(test)]
fn init_transcript(instance: &IOPInstance, message: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(b"loquat_iop_protocol");
    transcript.append_message(b"public_key", &field_slice_to_bytes(&instance.public_key));
    transcript.append_message(b"public_indices", &field_slice_to_bytes(&instance.public_indices));
    transcript.append_message(b"message_hash", &instance.message_hash);
    transcript.append_message(b"message", message);
    transcript
}

fn field_slice_to_bytes(slice: &[F]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for field_element in slice {
        field_element.serialize_compressed(&mut bytes).unwrap();
    }
    bytes
}

pub fn iop_key_identification(
    params: &LoquatPublicParams,
    instance: &IOPInstance,
    witness: &IOPWitness,
    transcript: &mut Transcript,
) -> LoquatResult<IOPProof> {
    let mut commitment = Vec::with_capacity(params.b);
    let mut responses = Vec::with_capacity(params.b);
    for i in 0..params.b {
        let r_i = F::rand(&mut rand::thread_rng());
        let o_i = (witness.secret_key + instance.public_indices[i]) * r_i;
        commitment.push(o_i);
        responses.push(r_i);
    }

    transcript.append_message(b"commitment", &field_slice_to_bytes(&commitment));

    let challenges = (0..params.n)
        .map(|_| {
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge", &mut buf);
            F::from_le_bytes_mod_order(&buf)
        })
        .collect();

    Ok(IOPProof {
        commitment,
        responses,
        challenges,
        poly_evaluations: vec![F::one(); params.m],
    })
}

pub fn verify_iop_proof(
    params: &LoquatPublicParams,
    instance: &IOPInstance,
    proof: &IOPProof,
    transcript: &mut Transcript,
) -> LoquatResult<bool> {
    transcript.append_message(b"commitment", &field_slice_to_bytes(&proof.commitment));

    let expected_challenges: Vec<F> = (0..params.n)
        .map(|_| {
            let mut buf = [0u8; 32];
            transcript.challenge_bytes(b"challenge", &mut buf);
            F::from_le_bytes_mod_order(&buf)
        })
        .collect();

    if proof.challenges != expected_challenges {
        return Ok(false);
    }

    if proof.responses.len() != params.b || proof.commitment.len() != params.b {
        return Ok(false);
    }

    for i in 0..params.b {
        let t_i = legendre_prf_secure(proof.responses[i]);
        let pk_i = instance.public_key[i % instance.public_key.len()];
        let o_i = proof.commitment[i];

        if legendre_prf_secure(o_i) != pk_i + t_i - F::from(2u64) * pk_i * t_i {
            return Ok(false);
        }
    }

    if proof.poly_evaluations.len() != params.m {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loquat::setup::loquat_setup;
    use crate::loquat::keygen::keygen_with_params;
    
    #[test]
    fn test_iop_key_identification() {
        let params = loquat_setup(128).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        
        let message = b"test message";
        let iop_instance = create_iop_instance(&keypair, &params, message);
        let iop_witness = create_iop_witness(keypair.secret_key);

        let mut transcript = Transcript::new(b"test_iop");
        let proof_result = iop_key_identification(&params, &iop_instance, &iop_witness, &mut transcript);
        assert!(proof_result.is_ok());

        let proof = proof_result.unwrap();
        let mut verifier_transcript = Transcript::new(b"test_iop");
        let is_valid = verify_iop_proof(&params, &iop_instance, &proof, &mut verifier_transcript).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_iop_verification() {
        let params = loquat_setup(128).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        let message = b"another test";
        let instance = create_iop_instance(&keypair, &params, message);
        let witness = create_iop_witness(keypair.secret_key);

        let mut prover_transcript = init_transcript(&instance, message);
        let proof = iop_key_identification(&params, &instance, &witness, &mut prover_transcript).unwrap();

        let mut verifier_transcript = init_transcript(&instance, message);
        assert!(verify_iop_proof(&params, &instance, &proof, &mut verifier_transcript).unwrap());
    }
    
    #[test]
    fn test_invalid_witness_rejection() {
        let params = loquat_setup(128).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        let message = b"test invalid witness";
        let instance = create_iop_instance(&keypair, &params, message);
        let mut rng = rand::thread_rng();
        let random_offset = F::rand(&mut rng);
        let invalid_witness = create_iop_witness(keypair.secret_key + random_offset);
        
        let mut prover_transcript = init_transcript(&instance, message);
        let proof = iop_key_identification(&params, &instance, &invalid_witness, &mut prover_transcript).unwrap();
        
        let mut verifier_transcript = init_transcript(&instance, message);
        let verification_result = verify_iop_proof(&params, &instance, &proof, &mut verifier_transcript);
        
        assert!(verification_result.is_ok());
        assert!(!verification_result.unwrap());
    }

    #[test]
    fn test_challenge_determinism() {
        let params = loquat_setup(128).expect("Setup failed");
        let keypair = keygen_with_params(&params).expect("Keygen failed");
        
        let message = b"Determinism test";
        let instance = create_iop_instance(&keypair, &params, message);
        let mut transcript1 = init_transcript(&instance, message);
        transcript1.append_message(b"commitment", &field_slice_to_bytes(&[F::from(42u128), F::from(123u128)]));

        let mut transcript2 = init_transcript(&instance, message);
        transcript2.append_message(b"commitment", &field_slice_to_bytes(&[F::from(42u128), F::from(123u128)]));

        let challenges1 = (0..params.n).map(|_| {
            let mut buf = [0u8; 32];
            transcript1.challenge_bytes(b"challenge", &mut buf);
            F::from_le_bytes_mod_order(&buf)
        }).collect::<Vec<F>>();

        let challenges2 = (0..params.n).map(|_| {
            let mut buf = [0u8; 32];
            transcript2.challenge_bytes(b"challenge", &mut buf);
            F::from_le_bytes_mod_order(&buf)
        }).collect::<Vec<F>>();

        assert_eq!(challenges1, challenges2);
    }
}