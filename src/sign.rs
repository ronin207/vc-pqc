use rand::Rng;
use sha2::{Sha256, Digest};
use std::time::{Duration, Instant};
use crate::setup::LoquatPublicParams;
use crate::keygen::{LoquatKeyPair, legendre_prf};
use crate::iop_key_id::{IOPProof, iop_key_identification, verify_iop_proof, create_iop_instance, create_iop_witness};

/// Complete Loquat signature containing all components from Algorithms 4-6
#[derive(Debug, Clone)]
pub struct LoquatSignature {
    /// Core IOP proof from Algorithm 1
    pub iop_proof: IOPProof,
    /// Message commitment from Phase 1
    pub message_commitment: Vec<u8>,
    /// Residuosity symbols from Phase 2
    pub residuosity_symbols: Vec<u128>,
    /// Witness vector for univariate sumcheck from Phase 3
    pub sumcheck_witness: Vec<u128>,
    /// Zero-knowledge masks for sumcheck from Phase 3 (continued)
    pub sumcheck_masks: Vec<u128>,
    /// Sumcheck proof from Phase 4
    pub sumcheck_proof: SumcheckProof,
    /// Stacked codeword for LDT from Phase 5
    pub ldt_codeword: Vec<u128>,
    /// LDT folding proof from Phase 6
    pub ldt_folding: LDTFoldingProof,
    /// LDT query responses from Phase 7
    pub ldt_queries: Vec<LDTQuery>,
    /// Signature metadata
    pub signature_metadata: SignatureMetadata,
}

/// Sumcheck proof structure for Phase 4
#[derive(Debug, Clone)]
pub struct SumcheckProof {
    /// Round polynomials for each sumcheck round
    pub round_polynomials: Vec<Vec<u128>>,
    /// Evaluation points for verification
    pub evaluation_points: Vec<u128>,
    /// Final evaluation at random point
    pub final_evaluation: u128,
    /// Number of variables in the sumcheck
    pub num_variables: usize,
}

/// LDT folding proof structure for Phase 6
#[derive(Debug, Clone)]
pub struct LDTFoldingProof {
    /// Folded polynomials at each round
    pub folded_polynomials: Vec<Vec<u128>>,
    /// Random challenges for folding
    pub folding_challenges: Vec<u128>,
    /// Merkle tree commitments for each fold
    pub merkle_commitments: Vec<Vec<u8>>,
    /// Number of folding rounds
    pub num_rounds: usize,
}

/// LDT query structure for Phase 7
#[derive(Debug, Clone)]
pub struct LDTQuery {
    /// Query position in the codeword
    pub position: usize,
    /// Queried value
    pub value: u128,
    /// Authentication path (Merkle proof)
    pub auth_path: Vec<Vec<u8>>,
    /// Consistency check values
    pub consistency_values: Vec<u128>,
}

/// Signature metadata
#[derive(Debug, Clone)]
pub struct SignatureMetadata {
    /// Signature version
    pub version: u32,
    /// Timestamp (Unix timestamp)
    pub timestamp: u64,
    /// Random nonce for uniqueness
    pub nonce: u64,
    /// Security parameter used
    pub security_parameter: usize,
}

/// Algorithm 4: Loquat Sign (Part 1) - Phases 1, 2, and 3
pub fn loquat_sign_phase_1_to_3(
    message: &[u8],
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
) -> Result<(Vec<u8>, Vec<u128>, Vec<u128>), String> {
    let mut rng = rand::thread_rng();
    
    // Phase 1: Commit to secret key and randomness
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.update(&keypair.secret_key.to_le_bytes());
    hasher.update(b"LOQUAT_SIGNATURE_DOMAIN");
    hasher.update(&params.field_p.to_le_bytes());
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce: u64 = rng.gen();
    
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    
    let message_commitment = hasher.finalize().to_vec();
    
    // Phase 2: Compute residuosity symbols
    let mut residuosity_symbols = Vec::with_capacity(params.b);
    
    for i in 0..params.b {
        let challenge_index = i % params.l;
        let challenge_value = params.public_indices[challenge_index];
        let input = (keypair.secret_key + challenge_value) % params.field_p;
        let residuosity = legendre_prf(input, params.field_p);
        residuosity_symbols.push(residuosity);
    }
    
    // Phase 3: Compute witness vector for univariate sumcheck
    let mut sumcheck_witness = Vec::with_capacity(params.m * params.n);
    
    for i in 0..params.m {
        for j in 0..params.n {
            let idx = i * params.n + j;
            if idx < params.b {
                let public_index = params.public_indices[idx % params.l];
                let computed_residuosity = residuosity_symbols[idx];
                
                let witness_coeff = (legendre_prf(
                    (keypair.secret_key + public_index) % params.field_p, 
                    params.field_p
                ) + params.field_p - computed_residuosity) % params.field_p;
                
                sumcheck_witness.push(witness_coeff);
            } else {
                sumcheck_witness.push(0);
            }
        }
    }
    
    Ok((message_commitment, residuosity_symbols, sumcheck_witness))
}

/// Algorithm 5: Loquat Sign (Part 2) - Phases 3 (continued), 4, and 5
pub fn loquat_sign_phase_4_to_5(
    sumcheck_witness: &[u128],
    params: &LoquatPublicParams,
) -> Result<(Vec<u128>, SumcheckProof, Vec<u128>), String> {
    let mut rng = rand::thread_rng();
    
    // Phase 3 (continued): Generate zero-knowledge masks
    let mut sumcheck_masks = Vec::with_capacity(sumcheck_witness.len());
    for _ in 0..sumcheck_witness.len() {
        let mask = rng.gen_range(0..params.field_p);
        sumcheck_masks.push(mask);
    }
    
    // Phase 4: Univariate sumcheck protocol
    let num_variables = (sumcheck_witness.len() as f64).log2().ceil() as usize;
    let mut round_polynomials = Vec::with_capacity(num_variables);
    let mut evaluation_points = Vec::with_capacity(num_variables);
    
    let mut current_witness = sumcheck_witness.to_vec();
    
    for round in 0..num_variables {
        let step_size = 1 << (num_variables - round - 1);
        let mut round_poly = Vec::new();
        
        // Compute round polynomial g_round(X)
        for eval_point in 0..3 {
            let mut partial_sum = 0u128;
            
            for i in (0..current_witness.len()).step_by(2 * step_size) {
                if i + step_size < current_witness.len() {
                    let val_0 = current_witness[i];
                    let val_1 = current_witness[i + step_size];
                    
                    let interpolated = if eval_point == 0 {
                        val_0
                    } else if eval_point == 1 {
                        val_1
                    } else {
                        (2 * val_1 + params.field_p - val_0) % params.field_p
                    };
                    
                    partial_sum = (partial_sum + interpolated) % params.field_p;
                }
            }
            
            round_poly.push(partial_sum);
        }
        
        round_polynomials.push(round_poly);
        
        let eval_point = rng.gen_range(0..params.field_p);
        evaluation_points.push(eval_point);
        
        // Update witness for next round
        let mut next_witness = Vec::new();
        for i in (0..current_witness.len()).step_by(2 * step_size) {
            if i + step_size < current_witness.len() {
                let val_0 = current_witness[i];
                let val_1 = current_witness[i + step_size];
                
                let interpolated = ((params.field_p - eval_point) * val_0 + eval_point * val_1) % params.field_p;
                next_witness.push(interpolated);
            }
        }
        current_witness = next_witness;
    }
    
    let final_evaluation = if current_witness.is_empty() { 0 } else { current_witness[0] };
    
    let sumcheck_proof = SumcheckProof {
        round_polynomials,
        evaluation_points,
        final_evaluation,
        num_variables,
    };
    
    // Phase 5: Stacking codeword for LDT
    let mut ldt_codeword = Vec::with_capacity(params.coset_u.len());
    
    for &eval_point in &params.coset_u {
        let mut evaluation = 0u128;
        let mut power = 1u128;
        
        for &coeff in sumcheck_witness {
            evaluation = (evaluation + (coeff * power) % params.field_p) % params.field_p;
            power = (power * eval_point) % params.field_p;
        }
        
        ldt_codeword.push(evaluation);
    }
    
    Ok((sumcheck_masks, sumcheck_proof, ldt_codeword))
}

/// Algorithm 6: Loquat Sign (Part 3) - Phases 6 and 7
pub fn loquat_sign_phase_6_to_7(
    ldt_codeword: &[u128],
    params: &LoquatPublicParams,
) -> Result<(LDTFoldingProof, Vec<LDTQuery>), String> {
    let mut rng = rand::thread_rng();
    
    // Phase 6: LDT folding protocol
    let num_rounds = params.r;
    let mut folded_polynomials = Vec::with_capacity(num_rounds);
    let mut folding_challenges = Vec::with_capacity(num_rounds);
    let mut merkle_commitments = Vec::with_capacity(num_rounds);
    
    let mut current_codeword = ldt_codeword.to_vec();
    
    for _round in 0..num_rounds {
        let challenge = rng.gen_range(1..params.field_p);
        folding_challenges.push(challenge);
        
        // Fold: new[i] = old[2i] + challenge * old[2i+1]
        let mut folded = Vec::new();
        for i in 0..(current_codeword.len() / 2) {
            let val_even = current_codeword[2 * i];
            let val_odd = if 2 * i + 1 < current_codeword.len() {
                current_codeword[2 * i + 1]
            } else {
                0
            };
            
            let folded_val = (val_even + challenge * val_odd) % params.field_p;
            folded.push(folded_val);
        }
        
        folded_polynomials.push(folded.clone());
        
        let merkle_commitment = compute_merkle_commitment(&folded);
        merkle_commitments.push(merkle_commitment);
        
        current_codeword = folded;
    }
    
    let ldt_folding = LDTFoldingProof {
        folded_polynomials,
        folding_challenges,
        merkle_commitments,
        num_rounds,
    };
    
    // Phase 7: LDT query phase
    let num_queries = params.kappa;
    let mut ldt_queries = Vec::with_capacity(num_queries);
    
    for _ in 0..num_queries {
        let position = rng.gen_range(0..ldt_codeword.len());
        let value = ldt_codeword[position];
        
        let auth_path = generate_auth_path(ldt_codeword, position);
        
        let mut consistency_values = Vec::new();
        let mut check_pos = position;
        
        for round in 0..num_rounds {
            if round < ldt_folding.folded_polynomials.len() {
                let folded_poly = &ldt_folding.folded_polynomials[round];
                let folded_pos = check_pos / 2;
                
                if folded_pos < folded_poly.len() {
                    consistency_values.push(folded_poly[folded_pos]);
                }
                
                check_pos = folded_pos;
            }
        }
        
        ldt_queries.push(LDTQuery {
            position,
            value,
            auth_path,
            consistency_values,
        });
    }
    
    Ok((ldt_folding, ldt_queries))
}

/// Complete Loquat signing algorithm (Algorithms 4, 5, and 6 combined)
pub fn loquat_sign(
    message: &[u8],
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
) -> Result<LoquatSignature, String> {
    let mut rng = rand::thread_rng();
    
    // Generate core IOP proof (Algorithm 1)
    let instance = create_iop_instance(keypair, params, message);
    let witness = create_iop_witness(keypair.secret_key);
    let iop_proof = iop_key_identification(params, &instance, &witness, message)?;
    
    // Algorithm 4: Phases 1-3
    let (message_commitment, residuosity_symbols, sumcheck_witness) = 
        loquat_sign_phase_1_to_3(message, keypair, params)?;
    
    // Algorithm 5: Phases 4-5
    let (sumcheck_masks, sumcheck_proof, ldt_codeword) = 
        loquat_sign_phase_4_to_5(&sumcheck_witness, params)?;
    
    // Algorithm 6: Phases 6-7
    let (ldt_folding, ldt_queries) = 
        loquat_sign_phase_6_to_7(&ldt_codeword, params)?;
    
    let signature_metadata = SignatureMetadata {
        version: 1,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nonce: rng.gen(),
        security_parameter: if params.field_p >= (1u128 << 60) { 128 } else { 64 },
    };
    
    Ok(LoquatSignature {
        iop_proof,
        message_commitment,
        residuosity_symbols,
        sumcheck_witness,
        sumcheck_masks,
        sumcheck_proof,
        ldt_codeword,
        ldt_folding,
        ldt_queries,
        signature_metadata,
    })
}

/// Verify complete Loquat signature
pub fn loquat_verify(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[u128],
    params: &LoquatPublicParams,
) -> Result<bool, String> {
    // Verify core IOP proof
    let instance = crate::iop_key_id::IOPInstance {
        public_key: public_key.to_vec(),
        public_indices: params.public_indices.clone(),
        message_hash: {
            let mut hasher = Sha256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        },
    };
    
    let iop_valid = verify_iop_proof(params, &instance, &signature.iop_proof, message)?;
    if !iop_valid {
        return Ok(false);
    }
    
    // Verify residuosity symbols consistency
    if signature.residuosity_symbols.len() != params.b {
        return Ok(false);
    }
    
    // Verify sumcheck proof
    if !verify_sumcheck_proof(&signature.sumcheck_proof, &signature.sumcheck_witness, params)? {
        return Ok(false);
    }
    
    // Verify LDT proof
    if !verify_ldt_proof(&signature.ldt_folding, &signature.ldt_queries, &signature.ldt_codeword, params)? {
        return Ok(false);
    }
    
    Ok(true)
}

// Enhanced Merkle tree implementation for LDT protocol
/// Complete Merkle tree structure for LDT folding
#[derive(Debug, Clone)]
struct MerkleTree {
    /// Leaf values (field elements)
    leaves: Vec<u128>,
    /// Internal node hashes (organized by levels)
    nodes: Vec<Vec<Vec<u8>>>,
    /// Root hash
    root: Vec<u8>,
}

impl MerkleTree {
    /// Build complete Merkle tree from leaf values
    fn new(leaves: Vec<u128>) -> Self {
        let mut tree = MerkleTree {
            leaves: leaves.clone(),
            nodes: Vec::new(),
            root: Vec::new(),
        };
        
        tree.build_tree();
        tree
    }
    
    /// Build the complete Merkle tree structure
    fn build_tree(&mut self) {
        let mut current_level = Vec::new();
        
        // Hash all leaf values to create bottom level
        for &leaf in &self.leaves {
            let mut hasher = Sha256::new();
            hasher.update(&leaf.to_le_bytes());
            hasher.update(b"LOQUAT_LEAF"); // Domain separation
            current_level.push(hasher.finalize().to_vec());
        }
        
        // Build tree level by level
        while current_level.len() > 1 {
            self.nodes.push(current_level.clone());
            let mut next_level = Vec::new();
            
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    // Pad with zero hash for odd-length levels
                    &vec![0u8; 32]
                };
                
                let mut hasher = Sha256::new();
                hasher.update(left);
                hasher.update(right);
                hasher.update(b"LOQUAT_NODE"); // Domain separation
                next_level.push(hasher.finalize().to_vec());
            }
            
            current_level = next_level;
        }
        
        // Set root (or empty if no leaves)
        self.root = current_level.into_iter().next().unwrap_or_else(|| vec![0u8; 32]);
    }
    
    /// Generate authentication path for a leaf at given position
    fn generate_auth_path(&self, position: usize) -> Result<Vec<Vec<u8>>, String> {
        if position >= self.leaves.len() {
            return Err(format!("Position {} out of bounds for {} leaves", position, self.leaves.len()));
        }
        
        let mut auth_path = Vec::new();
        let mut current_pos = position;
        
        // For each level from bottom to top
        for level in &self.nodes {
            let sibling_pos = if current_pos % 2 == 0 {
                current_pos + 1
            } else {
                current_pos - 1
            };
            
            let sibling_hash = if sibling_pos < level.len() {
                level[sibling_pos].clone()
            } else {
                // Sibling doesn't exist (odd number of nodes), use zero hash
                vec![0u8; 32]
            };
            
            auth_path.push(sibling_hash);
            current_pos /= 2;
        }
        
        Ok(auth_path)
    }
    
    /// Verify authentication path for a leaf
    fn verify_auth_path(&self, position: usize, leaf_value: u128, auth_path: &[Vec<u8>]) -> bool {
        if position >= self.leaves.len() || auth_path.len() != self.nodes.len() {
            return false;
        }
        
        // Start with leaf hash
        let mut hasher = Sha256::new();
        hasher.update(&leaf_value.to_le_bytes());
        hasher.update(b"LOQUAT_LEAF");
        let mut current_hash = hasher.finalize().to_vec();
        
        let mut current_pos = position;
        
        // Traverse up the tree using authentication path
        for sibling_hash in auth_path {
            let mut hasher = Sha256::new();
            
            if current_pos % 2 == 0 {
                // Current node is left child
                hasher.update(&current_hash);
                hasher.update(sibling_hash);
            } else {
                // Current node is right child
                hasher.update(sibling_hash);
                hasher.update(&current_hash);
            }
            
            hasher.update(b"LOQUAT_NODE");
            current_hash = hasher.finalize().to_vec();
            current_pos /= 2;
        }
        
        // Should equal root hash
        current_hash == self.root
    }
    
    /// Get root hash
    fn get_root(&self) -> &[u8] {
        &self.root
    }
}

/// Compute Merkle commitment with complete tree structure
fn compute_merkle_commitment(data: &[u128]) -> Vec<u8> {
    let tree = MerkleTree::new(data.to_vec());
    tree.get_root().to_vec()
}

/// Generate complete authentication path using Merkle tree
fn generate_auth_path(codeword: &[u128], position: usize) -> Vec<Vec<u8>> {
    let tree = MerkleTree::new(codeword.to_vec());
    tree.generate_auth_path(position).unwrap_or_else(|_| {
        // Fallback to simple hash path for invalid positions
        vec![vec![0u8; 32]]
    })
}

fn verify_sumcheck_proof(
    proof: &SumcheckProof,
    witness: &[u128],
    _params: &LoquatPublicParams,
) -> Result<bool, String> {
    if proof.round_polynomials.len() != proof.num_variables {
        return Ok(false);
    }
    
    if proof.evaluation_points.len() != proof.num_variables {
        return Ok(false);
    }
    
    if witness.is_empty() && proof.final_evaluation != 0 {
        return Ok(false);
    }
    
    Ok(true)
}

/// Enhanced LDT proof verification with complete Merkle tree validation
fn verify_ldt_proof(
    folding: &LDTFoldingProof,
    queries: &[LDTQuery],
    codeword: &[u128],
    params: &LoquatPublicParams,
) -> Result<bool, String> {
    // Basic structural checks
    if folding.num_rounds != params.r {
        return Ok(false);
    }
    
    if queries.len() != params.kappa {
        return Ok(false);
    }
    
    if folding.folded_polynomials.len() != params.r {
        return Ok(false);
    }
    
    if folding.merkle_commitments.len() != params.r {
        return Ok(false);
    }
    
    // Build Merkle tree for original codeword
    let original_tree = MerkleTree::new(codeword.to_vec());
    
    // Verify each query
    for query in queries {
        // Check basic validity
        if query.position >= codeword.len() {
            return Ok(false);
        }
        
        if query.value != codeword[query.position] {
            return Ok(false);
        }
        
        // Verify authentication path for original codeword
        if !original_tree.verify_auth_path(query.position, query.value, &query.auth_path) {
            return Ok(false);
        }
        
        // Verify folding consistency
        let mut current_pos = query.position;
        let mut current_value = query.value;
        
        for (round, folded_poly) in folding.folded_polynomials.iter().enumerate() {
            // Check consistency value matches folded polynomial
            let folded_pos = current_pos / 2;
            if folded_pos >= folded_poly.len() {
                return Ok(false);
            }
            
            let expected_folded_value = folded_poly[folded_pos];
            if round < query.consistency_values.len() {
                if query.consistency_values[round] != expected_folded_value {
                    return Ok(false);
                }
            }
            
            // Verify folding operation: folded[i] = old[2i] + challenge * old[2i+1]
            if round < folding.folding_challenges.len() {
                let challenge = folding.folding_challenges[round];
                let even_pos = (current_pos / 2) * 2;
                let odd_pos = even_pos + 1;
                
                // Get the sibling value for folding verification
                if round == 0 {
                    // For first round, use original codeword
                    let even_val = if even_pos < codeword.len() { codeword[even_pos] } else { 0 };
                    let odd_val = if odd_pos < codeword.len() { codeword[odd_pos] } else { 0 };
                    let computed_fold = (even_val + challenge * odd_val) % params.field_p;
                    
                    if expected_folded_value != computed_fold {
                        return Ok(false);
                    }
                } else {
                    // For subsequent rounds, use previous folded polynomial
                    if round > 0 && round <= folding.folded_polynomials.len() {
                        let prev_poly = &folding.folded_polynomials[round - 1];
                        let even_val = if even_pos < prev_poly.len() { prev_poly[even_pos] } else { 0 };
                        let odd_val = if odd_pos < prev_poly.len() { prev_poly[odd_pos] } else { 0 };
                        let computed_fold = (even_val + challenge * odd_val) % params.field_p;
                        
                        if expected_folded_value != computed_fold {
                            return Ok(false);
                        }
                    }
                }
            }
            
            current_pos = folded_pos;
            current_value = expected_folded_value;
        }
        
        // Verify Merkle commitments for each folding round
        for (round, commitment) in folding.merkle_commitments.iter().enumerate() {
            if round < folding.folded_polynomials.len() {
                let folded_poly = &folding.folded_polynomials[round];
                let expected_commitment = compute_merkle_commitment(folded_poly);
                
                if commitment != &expected_commitment {
                    return Ok(false);
                }
            }
        }
    }
    
    Ok(true)
}

// Additional utility functions
pub fn loquat_sign_enhanced(
    message: &[u8],
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
    aad: Option<&[u8]>,
) -> Result<LoquatSignature, String> {
    let mut enhanced_message = message.to_vec();
    
    if let Some(additional_data) = aad {
        enhanced_message.extend_from_slice(b"||AAD:");
        enhanced_message.extend_from_slice(additional_data);
    }
    
    loquat_sign(&enhanced_message, keypair, params)
}

pub fn loquat_verify_enhanced(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[u128],
    params: &LoquatPublicParams,
    aad: Option<&[u8]>,
) -> Result<bool, String> {
    let mut enhanced_message = message.to_vec();
    
    if let Some(additional_data) = aad {
        enhanced_message.extend_from_slice(b"||AAD:");
        enhanced_message.extend_from_slice(additional_data);
    }
    
    loquat_verify(&enhanced_message, signature, public_key, params)
}

pub fn loquat_batch_verify(
    messages_and_signatures: &[(&[u8], &LoquatSignature)],
    public_keys: &[&[u128]],
    params: &LoquatPublicParams,
) -> Result<Vec<bool>, String> {
    let mut results = Vec::with_capacity(messages_and_signatures.len());
    
    for (i, (message, signature)) in messages_and_signatures.iter().enumerate() {
        if i >= public_keys.len() {
            return Err("Not enough public keys for batch verification".to_string());
        }
        
        let is_valid = loquat_verify(message, signature, public_keys[i], params)?;
        results.push(is_valid);
    }
    
    Ok(results)
}

pub fn estimate_signature_size(signature: &LoquatSignature) -> usize {
    let iop_size = signature.iop_proof.commitment.len() * 16 +
                   signature.iop_proof.responses.len() * 16 +
                   signature.iop_proof.challenges.len() * 16 +
                   signature.iop_proof.poly_evaluations.len() * 16 +
                   signature.iop_proof.aux_data.len() * 16;
    
    let message_commitment_size = signature.message_commitment.len();
    let residuosity_size = signature.residuosity_symbols.len() * 16;
    let sumcheck_size = signature.sumcheck_witness.len() * 16 +
                       signature.sumcheck_masks.len() * 16 +
                       signature.sumcheck_proof.round_polynomials.iter()
                           .map(|poly| poly.len() * 16).sum::<usize>() +
                       signature.sumcheck_proof.evaluation_points.len() * 16 + 16;
    
    let ldt_size = signature.ldt_codeword.len() * 16 +
                   signature.ldt_folding.folded_polynomials.iter()
                       .map(|poly| poly.len() * 16).sum::<usize>() +
                   signature.ldt_folding.folding_challenges.len() * 16 +
                   signature.ldt_folding.merkle_commitments.iter()
                       .map(|commit| commit.len()).sum::<usize>() +
                   signature.ldt_queries.iter()
                       .map(|query| 24 + query.auth_path.iter().map(|path| path.len()).sum::<usize>() + 
                            query.consistency_values.len() * 16).sum::<usize>();
    
    let metadata_size = 32;
    
    iop_size + message_commitment_size + residuosity_size + sumcheck_size + ldt_size + metadata_size
}

pub fn benchmark_signing(
    message: &[u8],
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
    iterations: usize,
) -> Result<(Duration, Duration), String> {
    let mut total_sign_time = Duration::new(0, 0);
    let mut total_verify_time = Duration::new(0, 0);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let signature = loquat_sign(message, keypair, params)?;
        total_sign_time += start.elapsed();
        
        let start = Instant::now();
        let _is_valid = loquat_verify(message, &signature, &keypair.public_key, params)?;
        total_verify_time += start.elapsed();
    }
    
    let avg_sign_time = total_sign_time / iterations as u32;
    let avg_verify_time = total_verify_time / iterations as u32;
    
    Ok((avg_sign_time, avg_verify_time))
} 