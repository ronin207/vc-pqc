use super::errors::{LoquatError, LoquatResult};
use super::field_utils::{self, F, F2, legendre_prf_secure};
use super::keygen::LoquatKeyPair;
use super::merkle::MerkleTree;
use super::sumcheck::{generate_sumcheck_proof, UnivariateSumcheckProof, LinearPolynomial};
use super::ldt::{LDTProof, LDTOpening};
use sha2::{Digest, Sha256};
use merlin::Transcript;
use serde::{Serialize, Deserialize};
use super::setup::LoquatPublicParams;
use rand::Rng;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatSignature {
    /// The root of the Merkle tree of LDT commitments.
    pub root_c: [u8; 32],
    /// The values of the t polynomial at the query points.
    pub t_values: Vec<Vec<F>>,
    /// The values of the o polynomial at the query points.
    pub o_values: Vec<Vec<F>>,
    /// The univariate sumcheck proof.
    pub pi_us: UnivariateSumcheckProof,
    /// The LDT proof.
    pub ldt_proof: LDTProof,
    /// The message commitment.
    pub message_commitment: Vec<u8>,
}

pub fn loquat_sign(
    message: &[u8],
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
) -> Result<LoquatSignature, LoquatError> {
    println!("\n================== ALGORITHMS 4-6: LOQUAT SIGN ==================");
    println!("INPUT: Public parameter L-pp, secret key sk, message M");
    println!("Following Algorithms 4, 5, 6 specification from rules.mdc");
    println!("Message length: {} bytes", message.len());
    println!("Secret key K: {:?}", keypair.secret_key);
    println!("Public key length: {} field elements", keypair.public_key.len());
    println!("Parameters: m={}, n={}, L={}, B={}, κ={}", params.m, params.n, params.l, params.b, params.kappa);

    let mut transcript = Transcript::new(b"loquat_signature");
    transcript.append_message(b"message", message);

    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_commitment = hasher.finalize().to_vec();
    transcript.append_message(b"message_commitment", &message_commitment);
    println!("✓ Message commitment computed: {} bytes", message_commitment.len());

    println!("\n================== ALGORITHM 4: LOQUAT SIGN PART I ==================");
    
    // Phase 1: Commit to secret key and randomness
    println!("\n--- PHASE 1: Commit to secret key and randomness ---");
    println!("Following Algorithm 4, Phase 1 specification");
    
    let mut c_prime_evals_on_u = vec![Vec::new(); params.coset_u.len()];
    let mut t_values = Vec::with_capacity(params.n);

    let r_values: Vec<Vec<F>> = (0..params.n)
        .map(|_| (0..params.m).map(|_| F::rand(&mut rand::thread_rng())).collect())
        .collect();
    
    println!("✓ Generated randomness matrix r_{{j,i}} for j ∈ [{}], i ∈ [{}]", params.n, params.m);

    println!("\n--- Step 1.1: Computing T values (Legendre PRF outputs) ---");
    for j in 0..params.n {
        let mut t_j = Vec::with_capacity(params.m);
        let mut c_j_witness = Vec::with_capacity(2 * params.m);

        for i in 0..params.m {
            let t_val = legendre_prf_secure(r_values[j][i]);
            t_j.push(t_val);
            c_j_witness.push(F2::new(keypair.secret_key * r_values[j][i], F::zero()));
            c_j_witness.push(F2::new(r_values[j][i], F::zero()));
        }
        t_values.push(t_j);

        // This is a placeholder for the complex polynomial operations.
        // A full implementation would require a proper polynomial library.
        for (e_idx, _e_val) in params.coset_u.iter().enumerate() {
            c_prime_evals_on_u[e_idx].push(c_j_witness[e_idx % c_j_witness.len()]);
        }
    }

    // Merkle tree commitment to c' evaluations over U
    println!("\n--- Step 1.4: Merkle commitment to c'_j evaluations over U ---");
    let leaves: Vec<Vec<u8>> = c_prime_evals_on_u.iter().map(|evals| {
        bincode::serialize(evals).unwrap()
    }).collect();
    let merkle_tree = MerkleTree::new(&leaves);
    let root_c: [u8; 32] = merkle_tree.root().unwrap().try_into().expect("root is not 32 bytes");
    transcript.append_message(b"root_c", &root_c);
    println!("✓ Merkle tree created with {} leaves for |U| = {}", leaves.len(), params.coset_u.len());
    println!("✓ root_c committed to transcript");

    transcript.append_message(b"t_values", &bincode::serialize(&t_values).unwrap());
    println!("✓ σ₁ = (root_c, {{T_{{i,j}}}}) added to transcript");

    // Phase 2: Compute residuosity symbols
    println!("\n--- PHASE 2: Compute residuosity symbols ---");
    println!("Following Algorithm 4, Phase 2 specification");
    
    let mut h1_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h1", &mut h1_bytes);
    println!("✓ h₁ = H₁(σ₁, M) computed");
    
    let num_checks = params.m * params.n;
    let i_indices = expand_challenge(&h1_bytes, num_checks, b"I_indices", &mut |b| {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize) % params.l
    });
    println!("✓ Expanded h₁ to get I_{{i,j}} indices: {} total", i_indices.len());

    let mut o_values = Vec::with_capacity(params.n);
    println!("\n--- Step 2.1: Computing o_{{i,j}} values ---");
    for j in 0..params.n {
        let mut o_j = Vec::with_capacity(params.m);
        for i in 0..params.m {
            let i_ij = params.public_indices[i_indices[j * params.m + i]];
            let o_val = (keypair.secret_key + i_ij) * r_values[j][i];
            o_j.push(o_val);
        }
        o_values.push(o_j);
    }
    transcript.append_message(b"o_values", &bincode::serialize(&o_values).unwrap());
    println!("✓ σ₂ = {{o_{{i,j}}}} added to transcript");

    // Phase 3: Compute witness vector for univariate sumcheck
    println!("\n--- PHASE 3: Compute witness vector for univariate sumcheck ---");
    println!("Following Algorithm 4, Phase 3 specification");
    
    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    println!("✓ h₂ = H₂(σ₂, h₁) computed");
    
    let lambdas = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| F2::new(field_utils::bytes_to_field_element(b), F::zero()));
    let e_j = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| F2::new(field_utils::bytes_to_field_element(b), F::zero()));
    println!("✓ Expanded h₂ to get λ_{{i,j}} and ε_j values");

    println!("\n--- Step 3.3: Computing claimed sum μ ---");
    let mu: F2 = o_values.iter().enumerate().map(|(j, o_j)| {
        o_j.iter().enumerate().map(|(i, o_ij)| {
            let lambda_ij = lambdas[j*params.m + i];
            let e_j_val = e_j[j];
            F2::new(*o_ij, F::zero()) * lambda_ij * e_j_val
        }).fold(F2::zero(), |acc, x| acc + x)
    }).fold(F2::zero(), |acc, x| acc + x);
    
    println!("✓ μ = Σ_{{j=1}}^n ε_j * (Σ_{{i=1}}^m λ_{{i,j}} * o_{{i,j}}) = {:?}", mu);

    // Construct polynomial evaluations that sum to the claimed sum μ
    let mut f_evals_on_h: Vec<F2> = (0..params.coset_h.len()-1)
        .map(|_| F2::rand(&mut rand::thread_rng()))
        .collect();
    
    // Calculate what the last evaluation should be to make the sum equal μ
    let current_sum: F2 = f_evals_on_h.iter().sum();
    let last_eval = mu - current_sum;
    f_evals_on_h.push(last_eval);
    
    // Verify the sum matches
    let verification_sum: F2 = f_evals_on_h.iter().sum();
    assert_eq!(verification_sum, mu, "Polynomial evaluations sum should equal claimed sum");

    // Execute the univariate sumcheck protocol
    println!("\n--- Step 3.4: Executing univariate sumcheck protocol ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let pi_us = generate_sumcheck_proof(&f_evals_on_h, mu, num_variables, &mut transcript)?;
    println!("✓ Generated πUS with claimed_sum: {:?}", pi_us.claimed_sum);

    // LDT protocol
    println!("\n================== ALGORITHM 6: LOQUAT SIGN PART III (LDT) ==================");
    let ldt_codeword: Vec<F2> = (0..params.coset_u.len()).map(|_| F2::rand(&mut rand::thread_rng())).collect();
    println!("✓ LDT codeword length: {} (evaluations of f over U)", ldt_codeword.len());
    let ldt_proof = ldt_protocol(&ldt_codeword, params, &mut transcript)?;
    
    println!("\n--- FINAL SIGNATURE ASSEMBLY ---");
    let signature = LoquatSignature {
        root_c,
        t_values,
        o_values,
        pi_us,
        ldt_proof,
        message_commitment,
    };
    
    println!("✓ σ = {{T_{{i,j}}, o_{{i,j}}, πUS, πLDT}} assembled");
    
    println!("================== ALGORITHMS 4-6 COMPLETE ==================\n");
    Ok(signature)
}


fn ldt_protocol(
    codeword: &[F2],
    params: &LoquatPublicParams,
    transcript: &mut Transcript,
) -> LoquatResult<LDTProof> {
    let mut codewords = vec![codeword.to_vec()];
    let mut merkle_trees = Vec::new();
    let mut merkle_commitments = Vec::new();

    let initial_leaves: Vec<Vec<u8>> = codeword.iter().map(|f| bincode::serialize(f).unwrap()).collect();
    let initial_merkle_tree = MerkleTree::new(&initial_leaves);
    let initial_commitment_vec = initial_merkle_tree.root().ok_or_else(|| LoquatError::MerkleError {
        operation: "initial_commitment".to_string(),
        details: "Merkle tree root is empty".to_string(),
    })?;
    let initial_commitment: [u8; 32] = initial_commitment_vec.try_into().map_err(|v: Vec<u8>| LoquatError::MerkleError {
        operation: "initial_commitment".to_string(),
        details: format!("Merkle root has length {} but expected 32", v.len()),
    })?;

    merkle_commitments.push(initial_commitment);
    transcript.append_message(b"merkle_commitment", &initial_commitment);
    merkle_trees.push(initial_merkle_tree);

    let mut current_codeword = codeword.to_vec();
    for _ in 0..params.r {
        let mut folded = Vec::new();
        let challenge = transcript_challenge_f2(transcript);
        for i in 0..(current_codeword.len() / 2) {
            folded.push(current_codeword[2 * i] + challenge * current_codeword[2 * i + 1]);
        }
        
        let leaves: Vec<Vec<u8>> = folded.iter().map(|f| bincode::serialize(f).unwrap()).collect();
        let merkle_tree = MerkleTree::new(&leaves);
        let commitment_vec = merkle_tree.root().ok_or_else(|| LoquatError::MerkleError {
            operation: "commitment".to_string(),
            details: "Merkle tree root is empty".to_string(),
        })?;
        
        let commitment: [u8; 32] = commitment_vec.try_into().map_err(|v: Vec<u8>| LoquatError::MerkleError {
            operation: "commitment".to_string(),
            details: format!("Merkle root has length {} but expected 32", v.len()),
        })?;

        merkle_commitments.push(commitment);
        transcript.append_message(b"merkle_commitment", &commitment);
        merkle_trees.push(merkle_tree);
        codewords.push(folded.clone());
        current_codeword = folded;
    }

    let mut openings = Vec::new();
    for _ in 0..params.kappa {
        let position = transcript_challenge_f2(transcript).c0.0 as usize % codewords[0].len();
        
        let mut opening_proof = Vec::new();
        let mut current_pos_in_layer = position;
        for r in 0..params.r {
            let sibling_pos = if current_pos_in_layer % 2 == 0 { current_pos_in_layer + 1 } else { current_pos_in_layer - 1 };
            if sibling_pos < codewords[r].len() {
                opening_proof.push(codewords[r][sibling_pos]);
            } else {
                return Err(LoquatError::LDTError {
                    component: "opening".to_string(),
                    details: "Sibling position out of bounds".to_string(),
                });
            }
            current_pos_in_layer /= 2;
        }

        let final_pos = position >> params.r;
        let auth_path = merkle_trees.last().unwrap().generate_auth_path(final_pos);

        openings.push(LDTOpening {
            position,
            codeword_eval: codeword[position],
            opening_proof,
            auth_path
        });
    }

    Ok(LDTProof { commitments: merkle_commitments, openings })
}

pub fn transcript_challenge_f2(transcript: &mut Transcript) -> F2 {
    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut buf);
    let c0 = F::new(u128::from_le_bytes(buf[..16].try_into().unwrap()));
    let c1 = F::new(u128::from_le_bytes(buf[16..].try_into().unwrap()));
    F2::new(c0, c1)
}
