use super::errors::{LoquatError, LoquatResult};
use super::field_utils::{self, F, legendre_prf_secure};
use super::keygen::LoquatKeyPair;
use super::merkle::MerkleTree;
use super::sumcheck::{generate_sumcheck_proof, UnivariateSumcheckProof};
use super::ldt::{LDTProof, LDTOpening};
use sha2::{Digest, Sha256};
use ark_poly::{univariate::DensePolynomial, Polynomial, DenseUVPolynomial, EvaluationDomain, Radix2EvaluationDomain};
use ark_ff::{PrimeField, Zero, One, UniformRand, Field};
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;
use serde::{Serialize, Deserialize};
use super::setup::LoquatPublicParams;

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
    #[serde(with = "super::ark_serde::vec_vec")]
    pub t_values: Vec<Vec<F>>,
    /// The values of the o polynomial at the query points.
    #[serde(with = "super::ark_serde::vec_vec")]
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
    
    let mut c_prime_polys = Vec::new();
    let mut t_values = Vec::with_capacity(params.n);
    let mut c_witnesses = Vec::new(); // Store for later use

    // CRITICAL: Generate all randomness r_j,i once and reuse it for T, c, and o values.
    let r_values: Vec<Vec<F>> = (0..params.n)
        .map(|_| (0..params.m).map(|_| F::rand(&mut rand::thread_rng())).collect())
        .collect();
    
    println!("✓ Generated randomness matrix r_{{j,i}} for j ∈ [{}], i ∈ [{}]", params.n, params.m);
    for j in 0..std::cmp::min(2, params.n) {
        for i in 0..std::cmp::min(3, params.m) {
            println!("  r[{}][{}]: {:?}", j, i, r_values[j][i]);
        }
    }

    println!("\n--- Step 1.1: Computing T values (Legendre PRF outputs) ---");
    for j in 0..params.n {
        let mut t_j = Vec::with_capacity(params.m);
        let mut c_j_witness = Vec::with_capacity(2 * params.m);

        for i in 0..params.m {
            let t_val = legendre_prf_secure(r_values[j][i]);
            t_j.push(t_val);
            // The witness vector c_j = (Kr_1, r_1, Kr_2, r_2, ..., Kr_m, r_m)
            c_j_witness.push(keypair.secret_key * r_values[j][i]);
            c_j_witness.push(r_values[j][i]);
            
            if j == 0 && i < 3 {
                println!("  T[{},{}] = L₀(r[{},{}]) = L₀({:?}) = {:?}", j+1, i+1, j, i, r_values[j][i], t_val);
                println!("  c[{}] witness pair: Kr={:?}, r={:?}", 2*i, keypair.secret_key * r_values[j][i], r_values[j][i]);
            }
        }
        t_values.push(t_j);
        c_witnesses.push(c_j_witness.clone()); // Store for later use

        println!("✓ Computed T_{} = (T_{{1,{}}}, ..., T_{{m,{}}})", j+1, j+1, j+1);
        println!("✓ Created witness vector c_{} = (Kr_{{1,{}}}, r_{{1,{}}}, ..., Kr_{{m,{}}}, r_{{m,{}}})", j+1, j+1, j+1, j+1, j+1);

        // Interpolation over coset H following our corrected approach
        println!("\n--- Step 1.2: Interpolating c_{} over coset H ---", j+1);
        if params.coset_h.len() != 2 * params.m {
            return Err(LoquatError::IOPError {
                phase: "witness_interpolation".to_string(),
                details: format!("Coset H size {} != 2*m = {}", params.coset_h.len(), 2 * params.m),
            });
        }

        // Create domain for the coset H
        let h_domain: Radix2EvaluationDomain<F> = EvaluationDomain::<F>::new(params.coset_h.len()).ok_or(LoquatError::IOPError {
            phase: "h_domain".to_string(),
            details: "Failed to create H domain".to_string(),
        })?;
        
        // Apply coset interpolation: c_tilde_j(coset_h[i]) = c_j_witness[i]
        let coset_leader = params.coset_h[0];
        let coset_leader_inv = coset_leader.inverse().ok_or(LoquatError::IOPError {
            phase: "coset_leader_inverse".to_string(),
            details: "Coset leader is not invertible".to_string(),
        })?;
        
        // Step 1: Use IFFT to find coefficients of p such that p(g[i]) = c_j_witness[i]
        let p_coeffs = h_domain.ifft(&c_j_witness);
        let p_poly = DensePolynomial::from_coefficients_vec(p_coeffs);
        
        // Step 2: c_tilde(x) = p(x / coset_leader) 
        let mut c_tilde_coeffs = Vec::new();
        let mut coset_leader_power = F::one();
        for coeff in p_poly.coeffs() {
            c_tilde_coeffs.push(*coeff * coset_leader_power);
            coset_leader_power *= coset_leader_inv;
        }
        
        let c_tilde_j = DensePolynomial::from_coefficients_vec(c_tilde_coeffs);

        println!("✓ Interpolated c_{} over H: degree {}", j+1, c_tilde_j.degree());

        // Add random polynomial for zero-knowledge
        println!("\n--- Step 1.3: Adding random polynomial for ZK ---");
        let r_hat_j = DensePolynomial::rand(params.kappa * (1 << params.eta), &mut rand::thread_rng());
        
        // Construct correct vanishing polynomial for coset H
        let mut z_h_coset = DensePolynomial::from_coefficients_vec(vec![F::one()]);
        for &h_point in &params.coset_h {
            let linear_factor = DensePolynomial::from_coefficients_vec(vec![-h_point, F::one()]);
            z_h_coset = &z_h_coset * &linear_factor;
        }
        
        let c_prime_j = c_tilde_j.clone() + &(&z_h_coset * &r_hat_j);
        
        println!("✓ c'_{} = c̃_{} + Z_H(x) * r̂_{}", j+1, j+1, j+1);
        println!("  deg(c̃_{}) = {}, deg(Z_H) = {}, deg(c'_{}) = {}", j+1, c_tilde_j.degree(), z_h_coset.degree(), j+1, c_prime_j.degree());
        
        if j == 0 {
            // Verify interpolation correctness
            println!("\n--- Verification: c'_{} evaluates correctly on H ---", j+1);
            for k in 0..std::cmp::min(4, params.coset_h.len()) {
                let h_val = params.coset_h[k];
                let c_prime_val = c_prime_j.evaluate(&h_val);
                let expected_val = c_j_witness[k]; 
                let z_h_val = z_h_coset.evaluate(&h_val);
                
                println!("  H[{}]: c'_{}({:?}) = {:?}, expected = {:?}", k, j+1, h_val, c_prime_val, expected_val);
                if z_h_val.is_zero() && (c_prime_val - expected_val).is_zero() {
                    println!("    ✓ Perfect: Z_H vanishes and evaluation matches witness");
                }
            }
        }
        
        c_prime_polys.push(c_prime_j);
    }

    // Merkle tree commitment to c' evaluations over U
    println!("\n--- Step 1.4: Merkle commitment to c'_j evaluations over U ---");
    let leaves: Vec<Vec<u8>> = (0..params.coset_u.len()).map(|e| {
        let mut leaf_data = Vec::new();
        for j in 0..params.n {
            let val = c_prime_polys[j].evaluate(&params.coset_u[e]);
            let mut bytes = Vec::new();
            val.serialize_compressed(&mut bytes).unwrap();
            leaf_data.extend_from_slice(&bytes);
        }
        leaf_data
    }).collect();
    let merkle_tree = MerkleTree::new(&leaves);
    let root_c: [u8; 32] = merkle_tree.root().unwrap().try_into().expect("root is not 32 bytes");
    transcript.append_message(b"root_c", &root_c);
    println!("✓ Merkle tree created with {} leaves for |U| = {}", leaves.len(), params.coset_u.len());
    println!("✓ root_c committed to transcript");

    let mut t_bytes = Vec::new();
    for t_j in &t_values {
        for t_ij in t_j {
            t_ij.serialize_compressed(&mut t_bytes).unwrap();
        }
    }
    transcript.append_message(b"t_values", &t_bytes);
    println!("✓ σ₁ = (root_c, {{T_{{i,j}}}}): {} bytes added to transcript", t_bytes.len());

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
    println!("  I_{{i,j}} ⊆ [L] constraint satisfied");
    println!("  First few indices: {:?}", &i_indices[..std::cmp::min(5, i_indices.len())]);

    let mut o_values = Vec::with_capacity(params.n);
    println!("\n--- Step 2.1: Computing o_{{i,j}} values ---");
    for j in 0..params.n {
        let mut o_j = Vec::with_capacity(params.m);
        for i in 0..params.m {
            let i_ij = params.public_indices[i_indices[j * params.m + i]];
            // CRITICAL: Use the same randomness r_values[j][i] from Phase 1.
            let o_val = (keypair.secret_key + i_ij) * r_values[j][i];
            o_j.push(o_val);
            
            if j == 0 && i < 3 {
                println!("  o[{},{}] = (K + I_{{i,j}}) * r[{},{}] = ({:?} + {:?}) * {:?} = {:?}", 
                    j+1, i+1, j, i, keypair.secret_key, i_ij, r_values[j][i], o_val);
            }
        }
        o_values.push(o_j);
        println!("✓ Computed o_{} = (o_{{1,{}}}, ..., o_{{m,{}}})", j+1, j+1, j+1);
    }
    let mut o_bytes = Vec::new();
    for o_j in &o_values {
        for o_ij in o_j {
            o_ij.serialize_compressed(&mut o_bytes).unwrap();
        }
    }
    transcript.append_message(b"o_values", &o_bytes);
    println!("✓ σ₂ = {{o_{{i,j}}}}: {} bytes added to transcript", o_bytes.len());

    // Phase 3: Compute witness vector for univariate sumcheck
    println!("\n--- PHASE 3: Compute witness vector for univariate sumcheck ---");
    println!("Following Algorithm 4, Phase 3 specification");
    
    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    println!("✓ h₂ = H₂(σ₂, h₁) computed");
    
    let lambdas = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| self::field_utils::bytes_to_field_element(b));
    let e_j = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| self::field_utils::bytes_to_field_element(b));
    println!("✓ Expanded h₂ to get λ_{{i,j}} and ε_j values");
    println!("  Generated {} λ values and {} ε values", lambdas.len(), e_j.len());

    println!("\n--- Step 3.1: Constructing q_j polynomials ---");
    let mut f_polys = Vec::new();
    for j in 0..params.n {
        let mut q_j_witness = Vec::with_capacity(2 * params.m);
        for i in 0..params.m {
            let lambda_ij = lambdas[j * params.m + i];
            let i_ij = params.public_indices[i_indices[j * params.m + i]];
            // The witness vector q_j = (λ_1, λ_1*I_1, λ_2, λ_2*I_2, ..., λ_m, λ_m*I_m)
            q_j_witness.push(lambda_ij);
            q_j_witness.push(lambda_ij * i_ij);
            
            if j == 0 && i < 3 {
                println!("  q[{}] witness pair: λ={:?}, λ*I={:?}", 2*i, lambda_ij, lambda_ij * i_ij);
            }
        }
        
        // Apply the same coset interpolation approach as for c_j
        let h_domain: Radix2EvaluationDomain<F> = EvaluationDomain::<F>::new(params.coset_h.len()).ok_or(LoquatError::IOPError {
            phase: "q_h_domain".to_string(),
            details: "Failed to create H domain for q".to_string(),
        })?;
        
        let coset_leader = params.coset_h[0];
        let coset_leader_inv = coset_leader.inverse().ok_or(LoquatError::IOPError {
            phase: "q_coset_leader_inverse".to_string(),
            details: "Coset leader is not invertible for q".to_string(),
        })?;
        
        let q_p_coeffs = h_domain.ifft(&q_j_witness);
        let q_p_poly = DensePolynomial::from_coefficients_vec(q_p_coeffs);
        
        let mut q_tilde_coeffs = Vec::new();
        let mut coset_leader_power = F::one();
        for coeff in q_p_poly.coeffs() {
            q_tilde_coeffs.push(*coeff * coset_leader_power);
            coset_leader_power *= coset_leader_inv;
        }
        
        let q_tilde_j = DensePolynomial::from_coefficients_vec(q_tilde_coeffs);
        
        println!("✓ Interpolated q_{} over H: degree {}", j+1, q_tilde_j.degree());
        
        if j == 0 {
            // Verify q polynomial correctness
            println!("--- Verification: q_{} evaluates correctly on H ---", j+1);
            for k in 0..std::cmp::min(4, params.coset_h.len()) {
                let h_val = params.coset_h[k];
                let q_val = q_tilde_j.evaluate(&h_val);
                let expected_val = q_j_witness[k];
                let match_status = if (q_val - expected_val).is_zero() { "✓" } else { "✗" };
                println!("  H[{}]: q_{}({:?}) = {:?}, expected = {:?} {}", k, j+1, h_val, q_val, expected_val, match_status);
            }
        }
        
        // Compute f_j(x) = c'_j(x) * q_j(x)
        let f_j = &c_prime_polys[j] * &q_tilde_j;
        f_polys.push(f_j);
        println!("✓ Computed f_{} = c'_{} * q_{}", j+1, j+1, j+1);
    }

    println!("\n--- Step 3.2: Computing combined polynomial f(x) ---");
    let f_poly = f_polys.iter().zip(e_j.iter()).fold(DensePolynomial::zero(), |acc, (p, &e)| acc + p * e);
    println!("✓ f(x) = Σ_{{j=1}}^n ε_j * f_j(x), degree = {}", f_poly.degree());

    let f_evals: Vec<F> = params.coset_h.iter().map(|x| f_poly.evaluate(x)).collect();
    
    println!("\n--- Step 3.3: Computing claimed sum μ ---");
    let mu: F = o_values.iter().enumerate().map(|(j, o_j)| {
        o_j.iter().enumerate().map(|(i, o_ij)| {
            let lambda_ij = lambdas[j*params.m + i];
            let e_j_val = e_j[j];
            *o_ij * lambda_ij * e_j_val
        }).sum::<F>()
    }).sum();
    
    println!("✓ μ = Σ_{{j=1}}^n ε_j * (Σ_{{i=1}}^m λ_{{i,j}} * o_{{i,j}}) = {:?}", mu);
    println!("✓ Σ_{{a∈H}} f(a) = {:?}", f_evals.iter().sum::<F>());
    
    // Verify the fundamental sumcheck constraint
    if f_evals.iter().sum::<F>() == mu {
        println!("✓ CRITICAL CONSTRAINT SATISFIED: Σ_{{a∈H}} f(a) = μ");
    } else {
        println!("✗ CRITICAL CONSTRAINT VIOLATED: Polynomial sum ≠ μ");
        return Err(LoquatError::IOPError {
            phase: "sumcheck_constraint".to_string(),
            details: "Polynomial sum does not match claimed sum".to_string(),
        });
    }

    // Execute the univariate sumcheck protocol
    println!("\n--- Step 3.4: Executing univariate sumcheck protocol ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    println!("✓ Sumcheck parameters: {} variables, claimed sum μ = {:?}", num_variables, mu);
    let pi_us = generate_sumcheck_proof(&f_evals, mu, num_variables, &mut transcript)?;
    println!("✓ Generated πUS with claimed_sum: {:?}", pi_us.claimed_sum);

    // LDT protocol
    println!("\n================== ALGORITHM 6: LOQUAT SIGN PART III (LDT) ==================");
    let ldt_codeword: Vec<F> = params.coset_u.iter().map(|x| f_poly.evaluate(x)).collect();
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
    println!("  Components: T values ({}x{}), o values ({}x{}), sumcheck proof, LDT proof", 
             signature.t_values.len(), signature.t_values.get(0).map_or(0, |v| v.len()),
             signature.o_values.len(), signature.o_values.get(0).map_or(0, |v| v.len()));
    
    println!("================== ALGORITHMS 4-6 COMPLETE ==================\n");
    Ok(signature)
}


fn ldt_protocol(
    codeword: &[F],
    params: &LoquatPublicParams,
    transcript: &mut Transcript,
) -> LoquatResult<LDTProof> {
    let mut codewords = vec![codeword.to_vec()];
    let mut merkle_trees = Vec::new();
    let mut merkle_commitments = Vec::new();

    // Commit to the original codeword (f(0)) before folding.
    let initial_leaves: Vec<Vec<u8>> = codeword.iter().map(|f| {
        let mut bytes = Vec::new();
        f.serialize_compressed(&mut bytes).unwrap();
        bytes
    }).collect();
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
        let challenge = transcript_challenge(transcript);
        for i in 0..(current_codeword.len() / 2) {
            folded.push(current_codeword[2 * i] + challenge * current_codeword[2 * i + 1]);
        }
        
        let leaves: Vec<Vec<u8>> = folded.iter().map(|f| {
            let mut bytes = Vec::new();
            f.serialize_compressed(&mut bytes).unwrap();
            bytes
        }).collect();
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
        let position = transcript_challenge(transcript).into_bigint().0[0] as usize % codewords[0].len();
        
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

pub fn transcript_challenge(transcript: &mut Transcript) -> F {
    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut buf);
    F::from_le_bytes_mod_order(&buf)
}