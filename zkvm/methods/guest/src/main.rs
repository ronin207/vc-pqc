#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vc_pqc::loquat::{loquat_verify, LoquatPublicParams, LoquatSignature, field_utils::F};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
struct CredentialSignature {
    message: Vec<u8>,
    signature: LoquatSignature,
    issuer_public_key: Vec<F>,
}

#[derive(Serialize, Deserialize)]
struct CredentialPair {
    credential: CredentialSignature,
    nym_message: Vec<u8>,
    nym_signature: LoquatSignature,
}

#[derive(Serialize, Deserialize)]
struct MerkleProof {
    leaf: Vec<u8>,
    index: u32,
    path: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct RevocationProof {
    root: [u8; 32],
    proof: MerkleProof,
}

#[derive(Serialize, Deserialize)]
struct GuestInput {
    params: LoquatPublicParams,
    credential_pairs: Vec<CredentialPair>,
    merkle_root: [u8; 32],
    attribute_proofs: Vec<MerkleProof>,
    revocation_proof: Option<RevocationProof>,
}

#[derive(Default, Serialize, Deserialize)]
struct Counters {
    loquat_verifies: u32,
    hash_calls: u32,
    merkle_nodes: u32,
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    credential_checks_passed: bool,
    attribute_checks_passed: bool,
    revocation_check_passed: bool,
    counters: Counters,
}

fn main() {
    let input: GuestInput = env::read();
    let mut counters = Counters::default();

    if input.credential_pairs.is_empty() {
        panic!("at least one credential pair required");
    }

    for pair in &input.credential_pairs {
        verify_loquat_signature(
            &pair.credential.message,
            &pair.credential.signature,
            &pair.credential.issuer_public_key,
            &input.params,
            &mut counters,
        );

        verify_loquat_signature(
            &pair.nym_message,
            &pair.nym_signature,
            &pair.credential.issuer_public_key,
            &input.params,
            &mut counters,
        );
    }

    for proof in &input.attribute_proofs {
        if !verify_merkle_proof(&input.merkle_root, proof, &mut counters) {
            panic!("attribute Merkle proof failed");
        }
    }

    let revocation_check_passed = if let Some(revocation) = &input.revocation_proof {
        if !verify_merkle_proof(&revocation.root, &revocation.proof, &mut counters) {
            panic!("revocation Merkle proof failed");
        }
        true
    } else {
        true
    };

    let output = GuestOutput {
        credential_checks_passed: true,
        attribute_checks_passed: true,
        revocation_check_passed,
        counters,
    };

    env::commit(&output);
}

fn verify_loquat_signature(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &Vec<F>,
    params: &LoquatPublicParams,
    counters: &mut Counters,
) {
    counters.loquat_verifies = counters.loquat_verifies.saturating_add(1);
    match loquat_verify(message, signature, public_key, params) {
        Ok(true) => {}
        Ok(false) => panic!("Loquat signature rejected"),
        Err(_) => panic!("Loquat verification error"),
    }
}

fn verify_merkle_proof(root: &[u8; 32], proof: &MerkleProof, counters: &mut Counters) -> bool {
    let mut current_hash = hash_leaf(&proof.leaf, counters);
    counters.merkle_nodes = counters.merkle_nodes.saturating_add(1);
    let mut index = proof.index as usize;

    for sibling in &proof.path {
        counters.merkle_nodes = counters.merkle_nodes.saturating_add(1);
        current_hash = if index % 2 == 0 {
            hash_internal(&current_hash, sibling, counters)
        } else {
            hash_internal(sibling, &current_hash, counters)
        };
        index /= 2;
    }

    current_hash == *root
}

fn hash_leaf(data: &[u8], counters: &mut Counters) -> [u8; 32] {
    counters.hash_calls = counters.hash_calls.saturating_add(1);
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32], counters: &mut Counters) -> [u8; 32] {
    counters.hash_calls = counters.hash_calls.saturating_add(1);
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
