use std::time::Instant;

use bincode::Options;
use methods::{ZKVM_RISC0_ELF, ZKVM_RISC0_ID};
use rand::{rngs::OsRng, RngCore};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use vc_pqc::{
    loquat::{
        field_utils::F,
        keygen::keygen_with_params,
        merkle::MerkleTree,
        LoquatPublicParams,
        LoquatSignature,
    },
    loquat_setup,
    LoquatError, LoquatResult,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CredentialSignature {
    message: Vec<u8>,
    signature: LoquatSignature,
    issuer_public_key: Vec<F>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CredentialPair {
    credential: CredentialSignature,
    nym_message: Vec<u8>,
    nym_signature: LoquatSignature,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MerkleProof {
    leaf: Vec<u8>,
    index: u32,
    path: Vec<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RevocationProof {
    root: [u8; 32],
    proof: MerkleProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct GuestInput {
    params: LoquatPublicParams,
    credential_pairs: Vec<CredentialPair>,
    merkle_root: [u8; 32],
    attribute_proofs: Vec<MerkleProof>,
    revocation_proof: Option<RevocationProof>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Counters {
    loquat_verifies: u32,
    hash_calls: u32,
    merkle_nodes: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct GuestOutput {
    credential_checks_passed: bool,
    attribute_checks_passed: bool,
    revocation_check_passed: bool,
    counters: Counters,
}

#[derive(Debug)]
struct SweepResult {
    k: usize,
    s: usize,
    m: usize,
    trace_length: u64,
    prove_time_ms: f64,
    proof_size_bytes: usize,
    counters: Counters,
}

const K_VALUES: &[usize] = &[1, 2, 6, 14, 30];
const S_VALUES: &[usize] = &[1, 3, 10];
const M_VALUES: &[usize] = &[16, 64, 256];

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    if let Err(error) = run() {
        tracing::error!("host execution failed: {error:?}");
        std::process::exit(1);
    }
}

fn run() -> LoquatResult<()> {
    info!("configuring Loquat public parameters");
    let params = loquat_setup(128)?;

    let mut results = Vec::new();

    for &k in K_VALUES {
        for &s in S_VALUES {
            for &m in M_VALUES {
                info!("running ShowCre guest with k={k}, s={s}, m={m}");
                let sweep_result = execute_combination(&params, k, s, m)?;
                debug!(
                    "combination (k={k}, s={s}, m={m}) counters: {:?}",
                    sweep_result.counters
                );
                results.push(sweep_result);
            }
        }
    }

    print_summary(&results);

    Ok(())
}

fn execute_combination(
    params: &LoquatPublicParams,
    k: usize,
    s: usize,
    m: usize,
) -> LoquatResult<SweepResult> {
    if s > m {
        return Err(LoquatError::invalid_parameters(
            "attribute proofs requested exceed Merkle leaves",
        ));
    }

    let (attribute_proofs, merkle_root) = build_attribute_proofs(m, s)?;

    let mut credential_pairs = Vec::with_capacity(k);
    let mut revocation_leaves = Vec::with_capacity(k);
    let mut rng = OsRng;

    for idx in 0..k {
        let (pair, encoded_public_key) =
            generate_credential_pair(params, &merkle_root, &mut rng, idx)?;
        revocation_leaves.push(encoded_public_key);
        credential_pairs.push(pair);
    }

    let revocation_proof = build_revocation_proof(&revocation_leaves)?;

    let guest_input = GuestInput {
        params: params.clone(),
        credential_pairs,
        merkle_root,
        attribute_proofs,
        revocation_proof,
    };

    let env = ExecutorEnv::builder()
        .write(&guest_input)
        .map_err(|err| LoquatError::SerializationError {
            details: format!("failed to serialise guest input: {err}"),
        })?
        .build()
        .map_err(|err| LoquatError::crypto_error("build_executor_env", &err.to_string()))?;

    let prover = default_prover();
    let start = Instant::now();
    let prove_info = prover
        .prove(env, ZKVM_RISC0_ELF)
        .map_err(|err| LoquatError::crypto_error("prove_execution", &err.to_string()))?;
    let prove_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    let receipt = prove_info.receipt;
    receipt
        .verify(ZKVM_RISC0_ID)
        .map_err(|err| LoquatError::verification_failure(&format!(
            "receipt verification failed: {err}"
        )))?;

    let journal: GuestOutput = receipt
        .journal
        .decode()
        .map_err(|err| LoquatError::SerializationError {
            details: format!("failed to decode guest journal: {err}"),
        })?;

    if !journal.credential_checks_passed || !journal.attribute_checks_passed {
        return Err(LoquatError::verification_failure(
            "guest reported ShowCre verification failure",
        ));
    }

    if !journal.revocation_check_passed {
        warn!("revocation proof check reported failure");
    }

    let proof_size_bytes = receipt.seal_size();
    let trace_length = prove_info.stats.total_cycles;

    Ok(SweepResult {
        k,
        s,
        m,
        trace_length,
        prove_time_ms,
        proof_size_bytes,
        counters: journal.counters,
    })
}

fn generate_credential_pair(
    params: &LoquatPublicParams,
    merkle_root: &[u8; 32],
    rng: &mut OsRng,
    seed_hint: usize,
) -> LoquatResult<(CredentialPair, Vec<u8>)> {
    let keypair = keygen_with_params(params)?;

    let credential_message = merkle_root.to_vec();
    let credential_signature =
        vc_pqc::loquat::sign::loquat_sign(&credential_message, &keypair, params)?;

    let nym_message = generate_nym_message(rng, seed_hint);
    let nym_signature = vc_pqc::loquat::sign::loquat_sign(&nym_message, &keypair, params)?;

    let encoded_public_key = encode_public_key(&keypair.public_key)?;

    Ok((
        CredentialPair {
            credential: CredentialSignature {
                message: credential_message,
                signature: credential_signature,
                issuer_public_key: keypair.public_key.clone(),
            },
            nym_message,
            nym_signature,
        },
        encoded_public_key,
    ))
}

fn build_attribute_proofs(m: usize, s: usize) -> LoquatResult<(Vec<MerkleProof>, [u8; 32])> {
    let leaves: Vec<Vec<u8>> = (0..m)
        .map(|i| format!("attribute-{i:04}").into_bytes())
        .collect();
    let padded_leaves = pad_leaves(&leaves);
    let tree = MerkleTree::new(&padded_leaves);
    let root_vec = tree.root().ok_or_else(|| {
        LoquatError::invalid_parameters("Merkle tree root unavailable for empty leaf set")
    })?;
    let merkle_root: [u8; 32] = root_vec
        .as_slice()
        .try_into()
        .map_err(|_| LoquatError::serialization_error("unexpected Merkle root length"))?;

    let proofs = (0..s)
        .map(|idx| {
            let path_vec = tree.generate_auth_path(idx);
            let path: LoquatResult<Vec<[u8; 32]>> = path_vec
                .into_iter()
                .map(|node| {
                    node
                        .as_slice()
                        .try_into()
                        .map_err(|_| LoquatError::serialization_error("unexpected path node size"))
                })
                .collect();

            path.map(|converted| MerkleProof {
                leaf: leaves[idx].clone(),
                index: idx as u32,
                path: converted,
            })
        })
        .collect::<LoquatResult<Vec<_>>>()?;

    Ok((proofs, merkle_root))
}

fn build_revocation_proof(leaves: &[Vec<u8>]) -> LoquatResult<Option<RevocationProof>> {
    if leaves.is_empty() {
        return Ok(None);
    }

    let padded_leaves = pad_leaves(leaves);
    let tree = MerkleTree::new(&padded_leaves);
    let root_vec = tree.root().ok_or_else(|| {
        LoquatError::invalid_parameters("revocation Merkle tree has no root")
    })?;
    let root: [u8; 32] = root_vec
        .as_slice()
        .try_into()
        .map_err(|_| LoquatError::serialization_error("unexpected revocation root length"))?;

    let path_vec = tree.generate_auth_path(0);
    let path: Vec<[u8; 32]> = path_vec
        .into_iter()
        .map(|node| {
            node.as_slice()
                .try_into()
                .map_err(|_| LoquatError::serialization_error("unexpected revocation path size"))
        })
        .collect::<LoquatResult<Vec<_>>>()?;

    Ok(Some(RevocationProof {
        root,
        proof: MerkleProof {
            leaf: leaves[0].clone(),
            index: 0,
            path,
        },
    }))
}

fn encode_public_key(public_key: &[F]) -> LoquatResult<Vec<u8>> {
    default_bincode_options()
        .serialize(public_key)
        .map_err(|err| LoquatError::serialization_error(&format!(
            "failed to encode public key: {err}"
        )))
}

fn pad_leaves(leaves: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut padded = leaves.to_vec();
    let target = padded.len().next_power_of_two();
    let last = padded.last().cloned().unwrap();
    while padded.len() < target {
        padded.push(last.clone());
    }
    padded
}

fn default_bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

fn generate_nym_message(rng: &mut OsRng, seed_hint: usize) -> Vec<u8> {
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);

    let mut hasher = Sha256::new();
    hasher.update(&random_bytes);
    hasher.update(seed_hint.to_le_bytes());
    hasher.finalize().to_vec()
}

fn print_summary(results: &[SweepResult]) {
    if results.is_empty() {
        warn!("no results collected during sweep");
        return;
    }

    println!("\n=== ShowCre zkVM Sweep Results ===");
    println!(
        "{:<4} {:<4} {:<5} {:>12} {:>12} {:>12} {:>16} {:>14} {:>16}",
        "k", "s", "m", "trace(cyc)", "prove(ms)", "proof(bytes)", "loquat verifications", "hash calls", "merkle nodes"
    );

    for result in results {
        println!(
            "{:<4} {:<4} {:<5} {:>12} {:>12.2} {:>12} {:>16} {:>14} {:>16}",
            result.k,
            result.s,
            result.m,
            result.trace_length,
            result.prove_time_ms,
            result.proof_size_bytes,
            result.counters.loquat_verifies,
            result.counters.hash_calls,
            result.counters.merkle_nodes,
        );
    }
}
