use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{field2_to_bytes, field_to_bytes, F, F2};
use crate::loquat::merkle::MerkleTree;
use crate::loquat::sumcheck::{
    generate_sumcheck_proof, replay_sumcheck_challenges, verify_sumcheck_proof,
    UnivariateSumcheckProof,
};
use crate::loquat::transcript::Transcript;
use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::vec::Vec;

const TRANSCRIPT_LABEL: &[u8] = b"aurora_poc";

#[derive(Debug, Clone)]
pub struct AuroraParams {
    pub constraint_query_count: usize,
    pub witness_query_count: usize,
}

impl Default for AuroraParams {
    fn default() -> Self {
        Self {
            constraint_query_count: 4,
            witness_query_count: 4,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuroraProverOptions {
    pub explicit_witness_queries: Vec<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct AuroraVerificationHints {
    pub explicit_witness_queries: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct AuroraVerificationResult {
    opened_witness_values: HashMap<usize, F>,
}

impl AuroraVerificationResult {
    pub fn opened(&self, index: usize) -> Option<F> {
        self.opened_witness_values.get(&index).copied()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessOpening {
    pub index: usize,
    pub value: F,
    pub auth_path: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintQueryProof {
    pub constraint_index: usize,
    pub residual_value: F2,
    pub residual_auth_path: Vec<Vec<u8>>,
    pub witness_openings: Vec<WitnessOpening>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuroraProof {
    pub witness_root: [u8; 32],
    pub residual_root: [u8; 32],
    pub num_constraints_log2: usize,
    pub sumcheck_proof: UnivariateSumcheckProof,
    pub residual_evals: Vec<F2>,
    pub constraint_queries: Vec<ConstraintQueryProof>,
    pub explicit_witness_queries: Vec<usize>,
    pub witness_query_openings: Vec<WitnessOpening>,
}

pub fn aurora_prove(
    instance: &R1csInstance,
    witness: &R1csWitness,
    params: &AuroraParams,
) -> LoquatResult<AuroraProof> {
    aurora_prove_with_options(instance, witness, params, &AuroraProverOptions::default())
}

pub fn aurora_prove_with_options(
    instance: &R1csInstance,
    witness: &R1csWitness,
    params: &AuroraParams,
    options: &AuroraProverOptions,
) -> LoquatResult<AuroraProof> {
    witness.validate(instance)?;
    let mut explicit = options.explicit_witness_queries.clone();
    explicit.sort_unstable();
    explicit.dedup();
    for &index in &explicit {
        if index >= instance.num_variables {
            return Err(LoquatError::invalid_parameters(
                "explicit witness query out of range",
            ));
        }
    }

    let assignment = witness.full_assignment();
    let constraint_count = instance.num_constraints();
    let padded_constraints = constraint_count.max(1);
    let log_size = ceil_log2(padded_constraints);
    let eval_len = 1usize << log_size;

    let mut residual_evals = vec![F2::zero(); eval_len];
    for (idx, constraint) in instance.constraints.iter().enumerate() {
        let (a_eval, b_eval, c_eval) = constraint.evaluate(&assignment);
        residual_evals[idx] = F2::new(a_eval * b_eval - c_eval, F::zero());
    }

    let (residual_tree, residual_root) = build_merkle_from_f2(&residual_evals)?;
    let (witness_tree, witness_root) = build_merkle_from_f(&assignment)?;

    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"instance", &instance.digest());
    transcript.append_message(b"witness_root", &witness_root);
    transcript.append_message(b"residual_root", &residual_root);

    let claimed_sum: F2 = residual_evals.iter().copied().sum();
    let sumcheck_proof =
        generate_sumcheck_proof(&residual_evals, claimed_sum, log_size, &mut transcript)?;

    let constraint_indices = sample_indices(
        &mut transcript,
        b"constraint_queries",
        params.constraint_query_count.min(constraint_count),
        constraint_count,
    )?;
    let constraint_set: BTreeSet<usize> = constraint_indices.into_iter().collect();
    let mut constraint_queries = Vec::with_capacity(constraint_set.len());
    for index in constraint_set.iter().copied() {
        constraint_queries.push(build_constraint_query(
            instance,
            &assignment,
            &witness_tree,
            &residual_evals,
            &residual_tree,
            index,
        )?);
    }

    let random_witness_indices = sample_indices(
        &mut transcript,
        b"witness_queries",
        params.witness_query_count,
        instance.num_variables,
    )?;
    let mut witness_query_set: BTreeSet<usize> = random_witness_indices.into_iter().collect();
    witness_query_set.extend(explicit.iter().copied());
    let mut witness_query_openings = Vec::with_capacity(witness_query_set.len());
    for index in witness_query_set {
        witness_query_openings.push(build_witness_opening(index, &assignment, &witness_tree)?);
    }

    Ok(AuroraProof {
        witness_root,
        residual_root,
        num_constraints_log2: log_size,
        sumcheck_proof,
        residual_evals,
        constraint_queries,
        explicit_witness_queries: explicit,
        witness_query_openings,
    })
}

pub fn aurora_verify(
    instance: &R1csInstance,
    proof: &AuroraProof,
    params: &AuroraParams,
    hints: Option<&AuroraVerificationHints>,
) -> LoquatResult<Option<AuroraVerificationResult>> {
    let expected_log = ceil_log2(instance.num_constraints().max(1));
    if proof.num_constraints_log2 != expected_log {
        return Ok(None);
    }
    let expected_len = 1usize << proof.num_constraints_log2;
    if proof.residual_evals.len() != expected_len {
        return Ok(None);
    }
    let recomputed_root = compute_merkle_root_from_f2(&proof.residual_evals)?;
    if recomputed_root != proof.residual_root {
        return Ok(None);
    }

    let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
    transcript.append_message(b"instance", &instance.digest());
    transcript.append_message(b"witness_root", &proof.witness_root);
    transcript.append_message(b"residual_root", &proof.residual_root);

    let mut replay_transcript = transcript.clone();
    let challenges = replay_sumcheck_challenges(
        &proof.sumcheck_proof,
        proof.num_constraints_log2,
        &mut replay_transcript,
    )?;
    if !verify_sumcheck_proof(
        &proof.sumcheck_proof,
        proof.num_constraints_log2,
        &mut transcript,
    )? {
        return Ok(None);
    }
    let poly_eval = evaluate_multilinear(&proof.residual_evals, &challenges)?;
    if poly_eval != proof.sumcheck_proof.final_evaluation {
        return Ok(None);
    }

    let constraint_indices = sample_indices(
        &mut transcript,
        b"constraint_queries",
        params
            .constraint_query_count
            .min(instance.num_constraints()),
        instance.num_constraints(),
    )?;
    let constraint_set: BTreeSet<usize> = constraint_indices.into_iter().collect();
    if proof.constraint_queries.len() != constraint_set.len() {
        return Ok(None);
    }

    let mut opened_witness: HashMap<usize, F> = HashMap::new();
    for query in &proof.constraint_queries {
        if !constraint_set.contains(&query.constraint_index) {
            return Ok(None);
        }
        if !verify_constraint_query(
            instance,
            &proof.witness_root,
            &proof.residual_root,
            query,
            &mut opened_witness,
        )? {
            return Ok(None);
        }
    }

    let mut expected_explicit = match hints {
        Some(h) => h.explicit_witness_queries.clone(),
        None => proof.explicit_witness_queries.clone(),
    };
    expected_explicit.sort_unstable();
    expected_explicit.dedup();
    if hints.is_some() {
        let mut proof_explicit = proof.explicit_witness_queries.clone();
        proof_explicit.sort_unstable();
        proof_explicit.dedup();
        if proof_explicit != expected_explicit {
            return Ok(None);
        }
    }
    let random_witness_indices = sample_indices(
        &mut transcript,
        b"witness_queries",
        params.witness_query_count,
        instance.num_variables,
    )?;
    let mut witness_set: BTreeSet<usize> = random_witness_indices.into_iter().collect();
    witness_set.extend(expected_explicit.iter().copied());
    if proof.witness_query_openings.len() != witness_set.len() {
        return Ok(None);
    }
    for opening in &proof.witness_query_openings {
        if !witness_set.contains(&opening.index) {
            return Ok(None);
        }
        if !verify_witness_opening(&proof.witness_root, opening)? {
            return Ok(None);
        }
        update_opened_witness(&mut opened_witness, opening.index, opening.value)?;
        witness_set.remove(&opening.index);
    }
    if !witness_set.is_empty() {
        return Ok(None);
    }

    Ok(Some(AuroraVerificationResult {
        opened_witness_values: opened_witness,
    }))
}

pub fn aurora_digest(proof: &AuroraProof) -> LoquatResult<[u8; 32]> {
    let bytes = bincode_options()
        .serialize(proof)
        .map_err(|err| LoquatError::serialization_error(&format!("aurora digest encode: {err}")))?;
    Ok(Sha256::digest(bytes).into())
}

fn build_constraint_query(
    instance: &R1csInstance,
    assignment: &[F],
    witness_tree: &MerkleTree,
    residuals: &[F2],
    residual_tree: &MerkleTree,
    index: usize,
) -> LoquatResult<ConstraintQueryProof> {
    if index >= instance.num_constraints() {
        return Err(LoquatError::invalid_parameters(
            "constraint query out of range",
        ));
    }
    let constraint = &instance.constraints[index];
    let mut witness_openings = Vec::new();
    for var_index in constraint.support() {
        witness_openings.push(build_witness_opening(var_index, assignment, witness_tree)?);
    }
    let residual_value = residuals
        .get(index)
        .copied()
        .ok_or_else(|| LoquatError::iop_error("constraint_query", "missing residual value"))?;
    let residual_auth_path = residual_tree.generate_auth_path(index);
    Ok(ConstraintQueryProof {
        constraint_index: index,
        residual_value,
        residual_auth_path,
        witness_openings,
    })
}

fn build_witness_opening(
    index: usize,
    assignment: &[F],
    tree: &MerkleTree,
) -> LoquatResult<WitnessOpening> {
    let value = assignment
        .get(index)
        .copied()
        .ok_or_else(|| LoquatError::invalid_parameters("witness opening index out of range"))?;
    let auth_path = tree.generate_auth_path(index);
    Ok(WitnessOpening {
        index,
        value,
        auth_path,
    })
}

fn verify_constraint_query(
    instance: &R1csInstance,
    witness_root: &[u8; 32],
    residual_root: &[u8; 32],
    proof: &ConstraintQueryProof,
    opened_witness: &mut HashMap<usize, F>,
) -> LoquatResult<bool> {
    let constraint = match instance.constraints.get(proof.constraint_index) {
        Some(value) => value,
        None => return Ok(false),
    };
    if !MerkleTree::verify_auth_path(
        residual_root,
        field2_to_bytes(&proof.residual_value),
        proof.constraint_index,
        &proof.residual_auth_path,
    ) {
        return Ok(false);
    }

    let mut local_values: HashMap<usize, F> = HashMap::new();
    local_values.insert(0, F::one());
    for opening in &proof.witness_openings {
        if !verify_witness_opening(witness_root, opening)? {
            return Ok(false);
        }
        update_opened_witness(&mut local_values, opening.index, opening.value)?;
        update_opened_witness(opened_witness, opening.index, opening.value)?;
    }

    let (a_eval, b_eval, c_eval) = evaluate_constraint_with_openings(constraint, &local_values)?;
    let residual = F2::new(a_eval * b_eval - c_eval, F::zero());
    Ok(residual == proof.residual_value)
}

fn evaluate_constraint_with_openings(
    constraint: &R1csConstraint,
    assignments: &HashMap<usize, F>,
) -> LoquatResult<(F, F, F)> {
    Ok((
        partial_inner_product(&constraint.a, assignments)?,
        partial_inner_product(&constraint.b, assignments)?,
        partial_inner_product(&constraint.c, assignments)?,
    ))
}

fn partial_inner_product(coeffs: &[F], assignments: &HashMap<usize, F>) -> LoquatResult<F> {
    let mut sum = F::zero();
    for (idx, coeff) in coeffs.iter().enumerate() {
        if coeff.is_zero() {
            continue;
        }
        let value = assignments
            .get(&idx)
            .copied()
            .ok_or_else(|| LoquatError::verification_failure("missing witness opening"))?;
        sum += *coeff * value;
    }
    Ok(sum)
}

fn verify_witness_opening(root: &[u8], opening: &WitnessOpening) -> LoquatResult<bool> {
    Ok(MerkleTree::verify_auth_path(
        root,
        field_to_bytes(&opening.value),
        opening.index,
        &opening.auth_path,
    ))
}

fn update_opened_witness(
    cache: &mut HashMap<usize, F>,
    index: usize,
    value: F,
) -> LoquatResult<()> {
    match cache.get(&index) {
        Some(existing) if *existing != value => Err(LoquatError::verification_failure(
            "inconsistent witness opening detected",
        )),
        _ => {
            cache.insert(index, value);
            Ok(())
        }
    }
}

fn evaluate_multilinear(evals: &[F2], challenges: &[F2]) -> LoquatResult<F2> {
    if evals.is_empty() {
        return Ok(F2::zero());
    }
    if evals.len() != (1usize << challenges.len()) {
        return Err(LoquatError::verification_failure(
            "invalid multilinear evaluation table",
        ));
    }
    let mut current = evals.to_vec();
    for challenge in challenges {
        if current.len() % 2 != 0 {
            return Err(LoquatError::verification_failure(
                "unexpected multilinear evaluation length",
            ));
        }
        let mut next = Vec::with_capacity(current.len() / 2);
        for i in 0..current.len() / 2 {
            let v0 = current[2 * i];
            let v1 = current[2 * i + 1];
            next.push(v0 + (*challenge) * (v1 - v0));
        }
        current = next;
    }
    Ok(current[0])
}

fn sample_indices(
    transcript: &mut Transcript,
    label: &[u8],
    count: usize,
    upper_bound: usize,
) -> LoquatResult<Vec<usize>> {
    if count == 0 || upper_bound == 0 {
        return Ok(Vec::new());
    }
    let mut seed = [0u8; 32];
    transcript.challenge_bytes(label, &mut seed);
    let mut indices = Vec::with_capacity(count);
    let mut counter = 0u64;
    while indices.len() < count {
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        for chunk in digest.chunks_exact(8) {
            if indices.len() == count {
                break;
            }
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            indices.push((value as usize) % upper_bound);
        }
        counter = counter.wrapping_add(1);
    }
    Ok(indices)
}

fn ceil_log2(value: usize) -> usize {
    if value <= 1 {
        return 0;
    }
    let mut v = value - 1;
    let mut pow = 0usize;
    while v > 0 {
        pow += 1;
        v >>= 1;
    }
    pow
}

fn build_merkle_from_f(values: &[F]) -> LoquatResult<(MerkleTree, [u8; 32])> {
    let leaves = serialize_field_leaves(values);
    build_merkle_tree(&leaves)
}

fn build_merkle_from_f2(values: &[F2]) -> LoquatResult<(MerkleTree, [u8; 32])> {
    let leaves = serialize_field2_leaves(values);
    build_merkle_tree(&leaves)
}

fn compute_merkle_root_from_f2(values: &[F2]) -> LoquatResult<[u8; 32]> {
    let leaves = serialize_field2_leaves(values);
    let (_, root) = build_merkle_tree(&leaves)?;
    Ok(root)
}

fn build_merkle_tree(leaves: &[Vec<u8>]) -> LoquatResult<(MerkleTree, [u8; 32])> {
    if leaves.is_empty() {
        return Err(LoquatError::merkle_error(
            "commit",
            "at least one leaf required",
        ));
    }
    let mut padded = leaves.to_vec();
    let target = padded.len().next_power_of_two().max(1);
    let pad_value = vec![0u8; leaves[0].len()];
    while padded.len() < target {
        padded.push(pad_value.clone());
    }
    let tree = MerkleTree::new(&padded);
    let root_vec = tree
        .root()
        .ok_or_else(|| LoquatError::merkle_error("commit", "empty tree root"))?;
    let root: [u8; 32] = root_vec.try_into().map_err(|v: Vec<u8>| {
        LoquatError::merkle_error("commit", &format!("root length {}", v.len()))
    })?;
    Ok((tree, root))
}

fn serialize_field_leaves(values: &[F]) -> Vec<Vec<u8>> {
    values.iter().map(|v| field_to_bytes(v).to_vec()).collect()
}

fn serialize_field2_leaves(values: &[F2]) -> Vec<Vec<u8>> {
    values.iter().map(|v| field2_to_bytes(v).to_vec()).collect()
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};

    fn multiplication_instance() -> (R1csInstance, R1csWitness) {
        let num_variables = 4; // 1 (constant) + x + y + z
        let mut a = vec![F::zero(); num_variables];
        a[1] = F::one();
        let mut b = vec![F::zero(); num_variables];
        b[2] = F::one();
        let mut c = vec![F::zero(); num_variables];
        c[3] = F::one();
        let constraint = R1csConstraint::new(a, b, c);
        let instance = R1csInstance::new(num_variables, vec![constraint]).unwrap();
        let witness = R1csWitness::new(vec![F::new(3), F::new(5), F::new(15)]);
        (instance, witness)
    }

    #[test]
    fn aurora_round_trip() {
        let params = AuroraParams::default();
        let (instance, witness) = multiplication_instance();
        let proof = aurora_prove(&instance, &witness, &params).unwrap();
        let result = aurora_verify(&instance, &proof, &params, None).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn aurora_detects_tampering() {
        let params = AuroraParams::default();
        let (instance, witness) = multiplication_instance();
        let mut proof = aurora_prove(&instance, &witness, &params).unwrap();
        proof.residual_evals[0] = F2::one();
        let result = aurora_verify(&instance, &proof, &params, None).unwrap();
        assert!(result.is_none());
    }
}
