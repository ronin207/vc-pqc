use super::errors::{LoquatError, LoquatResult};
use super::field_utils::{self, F, F2, legendre_prf_secure};
use super::keygen::LoquatKeyPair;
use super::merkle::MerkleTree;
use super::sumcheck::{generate_sumcheck_proof, UnivariateSumcheckProof};
use super::ldt::{LDTProof, LDTOpening};
use super::fft::{evaluate_on_coset, interpolate_on_coset};
use sha2::{Digest, Sha256};
use merlin::Transcript;
use serde::{Serialize, Deserialize};
use super::setup::LoquatPublicParams;
use std::cmp;

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
    /// Merkle root for s evaluations.
    pub root_s: [u8; 32],
    /// Merkle root for h evaluations.
    pub root_h: [u8; 32],
    /// The values of the t polynomial at the query points.
    pub t_values: Vec<Vec<F>>,
    /// The values of the o polynomial at the query points.
    pub o_values: Vec<Vec<F>>,
    /// Masked evaluations ĉ'_j over U for each j.
    pub c_prime_evals: Vec<Vec<F2>>,
    /// Evaluations of ŝ over U.
    pub s_evals: Vec<F2>,
    /// Evaluations of ĥ over U.
    pub h_evals: Vec<F2>,
    /// Evaluations of f′ over U.
    pub f_prime_evals: Vec<F2>,
    /// Evaluations of p̂ over U.
    pub p_evals: Vec<F2>,
    /// Stacked matrix rows Π (Π0 followed by Π1).
    pub pi_rows: Vec<Vec<F2>>,
    /// Evaluations of f^{(0)} over U.
    pub f0_evals: Vec<F2>,
    /// FRI folding challenges h_{5+i}.
    pub fri_challenges: Vec<F2>,
    /// FRI layer codewords f^{(i)} evaluations.
    pub fri_codewords: Vec<Vec<F2>>,
    /// FRI layer row evaluations Π^{(i)}.
    pub fri_rows: Vec<Vec<Vec<F2>>>,
    /// Challenge vector e used in Algorithm 5.
    pub e_vector: Vec<F2>,
    /// Sum Σ_{a∈H} ŝ(a).
    pub s_sum: F2,
    /// Claimed sum μ.
    pub mu: F2,
    /// Challenge z used in Algorithm 5.
    pub z_challenge: F2,
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
    
    println!("\n--- Step 1.1: Computing T values (Legendre PRF outputs) ---");

    let mut rng = rand::thread_rng();
    let mut c_prime_evals_on_u: Vec<Vec<F2>> = vec![Vec::with_capacity(params.n); params.coset_u.len()];
    let mut c_prime_on_u_per_j: Vec<Vec<F2>> = Vec::with_capacity(params.n);
    let mut c_on_h_per_j: Vec<Vec<F2>> = Vec::with_capacity(params.n);
    let mut t_values = Vec::with_capacity(params.n);
    let mut r_values: Vec<Vec<F>> = vec![Vec::with_capacity(params.m); params.n];

    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let z_h_on_u: Vec<F2> = params
        .coset_u
        .iter()
        .map(|&u| u.pow(h_order) - z_h_constant)
        .collect();

    println!("✓ Generated vanishing polynomial values Z_H(x) over U");

    println!("✓ Sampling randomness matrix r_{{j,i}} and constructing masked polynomials");

    let u_len = params.coset_u.len();
    for j in 0..params.n {
        let mut t_j = Vec::with_capacity(params.m);
        let mut c_j_evals_on_h = Vec::with_capacity(2 * params.m);

        for _ in 0..params.m {
            let r_sample = F::rand_nonzero(&mut rng);
            r_values[j].push(r_sample);
            let t_val = legendre_prf_secure(r_sample);
            t_j.push(t_val);
            c_j_evals_on_h.push(F2::new(keypair.secret_key * r_sample, F::zero()));
            c_j_evals_on_h.push(F2::new(r_sample, F::zero()));
        }
        t_values.push(t_j);
        c_on_h_per_j.push(c_j_evals_on_h.clone());

        let c_hat_coeffs = interpolate_on_coset(&c_j_evals_on_h, params.h_shift, params.h_generator)?;
        let mut c_hat_coeffs_padded = vec![F2::zero(); u_len];
        c_hat_coeffs_padded[..c_hat_coeffs.len()].copy_from_slice(&c_hat_coeffs);
        let c_hat_on_u = evaluate_on_coset(&c_hat_coeffs_padded, params.u_shift, params.u_generator)?;

        let mut r_hat_coeffs = vec![F2::zero(); u_len];
        let mask_bound = params.kappa.saturating_mul(1 << params.eta);
        if u_len > 0 {
            let max_index = cmp::min(mask_bound, u_len - 1);
            for coeff in r_hat_coeffs.iter_mut().take(max_index + 1) {
                *coeff = F2::rand(&mut rng);
            }
        }
        let r_hat_on_u = evaluate_on_coset(&r_hat_coeffs, params.u_shift, params.u_generator)?;

        let mut c_prime_on_u = Vec::with_capacity(u_len);
        for i in 0..u_len {
            let value = c_hat_on_u[i] + (z_h_on_u[i] * r_hat_on_u[i]);
            c_prime_evals_on_u[i].push(value);
            c_prime_on_u.push(value);
        }
        c_prime_on_u_per_j.push(c_prime_on_u);
    }

    println!("✓ Generated randomness matrix r_{{j,i}} for j ∈ [{}], i ∈ [{}]", params.n, params.m);
    println!("✓ Masked commitments prepared for Merkle binding over U");

    println!("✓ Computed masked evaluations ĉ'_j|_U for all j ∈ [n]");

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
    
    let lambda_scalars = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| field_utils::bytes_to_field_element(b));
    let epsilon_vals = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| F2::new(field_utils::bytes_to_field_element(b), F::zero()));
    println!("✓ Expanded h₂ to get λ_{{i,j}} and ε_j values");

    println!("\n--- Step 3.3: Building witness polynomial data ---");
    let mut f_on_h = vec![F2::zero(); params.coset_h.len()];
    let mut f_on_u = vec![F2::zero(); params.coset_u.len()];

    for j in 0..params.n {
        let epsilon = epsilon_vals[j];

        let mut q_eval_on_h = Vec::with_capacity(2 * params.m);
        for i in 0..params.m {
            let lambda_scalar = lambda_scalars[j * params.m + i];
            let lambda_f2 = F2::new(lambda_scalar, F::zero());
            let index = i_indices[j * params.m + i];
            let public_i = params.public_indices[index];
            let public_f2 = F2::new(public_i, F::zero());
            q_eval_on_h.push(lambda_f2);
            q_eval_on_h.push(lambda_f2 * public_f2);
        }

        let q_hat_coeffs = interpolate_on_coset(&q_eval_on_h, params.h_shift, params.h_generator)?;
        let mut q_hat_coeffs_padded = vec![F2::zero(); params.coset_u.len()];
        q_hat_coeffs_padded[..q_hat_coeffs.len()].copy_from_slice(&q_hat_coeffs);
        let q_hat_on_u = evaluate_on_coset(&q_hat_coeffs_padded, params.u_shift, params.u_generator)?;

        let c_prime_on_u = &c_prime_on_u_per_j[j];
        for i in 0..params.coset_u.len() {
            let value = c_prime_on_u[i] * q_hat_on_u[i];
            f_on_u[i] += epsilon * value;
        }

        let c_on_h = &c_on_h_per_j[j];
        for (idx, (c_val, q_val)) in c_on_h.iter().zip(q_eval_on_h.iter()).enumerate() {
            f_on_h[idx] += epsilon * (*c_val * *q_val);
        }
    }

    let mu: F2 = {
        let mut acc = F2::zero();
        for j in 0..params.n {
            let epsilon = epsilon_vals[j];
            for i in 0..params.m {
                let lambda_scalar = lambda_scalars[j * params.m + i];
                let o_scalar = o_values[j][i];
                let term = F2::new(lambda_scalar * o_scalar, F::zero());
                acc += epsilon * term;
            }
        }
        acc
    };

    let computed_mu: F2 = f_on_h.iter().copied().sum();
    if computed_mu != mu {
        println!("⚠️ Warning: Σ f_on_h = {:?}, expected μ = {:?}", computed_mu, mu);
    } else {
        println!("✓ Polynomial evaluations over H sum to μ");
    }
    println!("✓ μ = Σ_{{j=1}}^n ε_j * (Σ_{{i=1}}^m λ_{{i,j}} * o_{{i,j}}) = {:?}", mu);

    // Execute the univariate sumcheck protocol
    println!("\n--- Step 3.4: Executing univariate sumcheck protocol ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let pi_us = generate_sumcheck_proof(&f_on_h, mu, num_variables, &mut transcript)?;
    println!("✓ Generated πUS with claimed_sum: {:?}", pi_us.claimed_sum);

    println!("\n================== ALGORITHM 5: LOQUAT SIGN PART II ==================");
    let mask_degree_bound = 4 * params.m + (params.kappa * (1 << params.eta));
    let mut s_coeffs = vec![F2::zero(); params.coset_u.len()];
    if params.coset_u.len() > 0 {
        let coeff_bound = cmp::min(mask_degree_bound + 1, params.coset_u.len());
        for coeff in s_coeffs.iter_mut().take(coeff_bound) {
            *coeff = F2::rand(&mut rng);
        }
    }
    let s_on_u = evaluate_on_coset(&s_coeffs, params.u_shift, params.u_generator)?;
    let mut s_on_h = Vec::with_capacity(params.coset_h.len());
    for &point in params.coset_h.iter() {
        let mut value = F2::zero();
        let mut power = F2::one();
        for coeff in s_coeffs.iter() {
            value += *coeff * power;
            power *= point;
        }
        s_on_h.push(value);
    }
    let s_sum: F2 = s_on_h.iter().copied().sum();
    let s_leaves: Vec<Vec<u8>> = s_on_u.iter().map(|val| bincode::serialize(val).unwrap()).collect();
    let s_merkle = MerkleTree::new(&s_leaves);
    let root_s_vec = s_merkle.root().ok_or_else(|| LoquatError::MerkleError {
        operation: "s_commitment".to_string(),
        details: "Merkle tree root is empty".to_string(),
    })?;
    let root_s: [u8; 32] = root_s_vec.try_into().map_err(|v: Vec<u8>| LoquatError::MerkleError {
        operation: "s_commitment".to_string(),
        details: format!("Merkle root has length {} but expected 32", v.len()),
    })?;
    transcript.append_message(b"root_s", &root_s);
    transcript.append_message(b"s_sum", &bincode::serialize(&s_sum).unwrap());
    println!("✓ σ₃ = (root_s, S) added to transcript");

    let mut h3_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h3", &mut h3_bytes);
    let z_scalar = field_utils::bytes_to_field_element(&h3_bytes);
    let z = F2::new(z_scalar, F::zero());
    println!("✓ h₃ = H₃(σ₃, h₂) computed");

    let f_prime_on_u: Vec<F2> = f_on_u
        .iter()
        .zip(s_on_u.iter())
        .map(|(&f_val, &s_val)| z * f_val + s_val)
        .collect();
    let f_prime_on_h: Vec<F2> = f_on_h
        .iter()
        .zip(s_on_h.iter())
        .map(|(&f_val, &s_val)| z * f_val + s_val)
        .collect();

    let g_coeffs = interpolate_on_coset(&f_prime_on_h, params.h_shift, params.h_generator)?;
    let mut g_coeffs_padded = vec![F2::zero(); params.coset_u.len()];
    g_coeffs_padded[..g_coeffs.len()].copy_from_slice(&g_coeffs);
    let g_on_u = evaluate_on_coset(&g_coeffs_padded, params.u_shift, params.u_generator)?;

    let mut h_on_u = Vec::with_capacity(params.coset_u.len());
    for i in 0..params.coset_u.len() {
        let numerator = f_prime_on_u[i] - g_on_u[i];
        let denom = z_h_on_u[i];
        let denom_inv = denom
            .inverse()
            .ok_or_else(|| LoquatError::invalid_parameters("Encountered zero divisor in Z_H(u)"))?;
        h_on_u.push(numerator * denom_inv);
    }

    let h_leaves: Vec<Vec<u8>> = h_on_u.iter().map(|val| bincode::serialize(val).unwrap()).collect();
    let h_merkle = MerkleTree::new(&h_leaves);
    let root_h_vec = h_merkle.root().ok_or_else(|| LoquatError::MerkleError {
        operation: "h_commitment".to_string(),
        details: "Merkle tree root is empty".to_string(),
    })?;
    let root_h: [u8; 32] = root_h_vec.try_into().map_err(|v: Vec<u8>| LoquatError::MerkleError {
        operation: "h_commitment".to_string(),
        details: format!("Merkle root has length {} but expected 32", v.len()),
    })?;
    transcript.append_message(b"root_h", &root_h);
    println!("✓ σ₄ = (root_h) added to transcript");

    let mut h4_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h4", &mut h4_bytes);
    let e_vector = expand_challenge(&h4_bytes, 8, b"e_vector", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });
    println!("✓ h₄ = H₄(σ₄, h₃) computed");

    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    let z_mu_plus_s = z * mu + s_sum;
    let mut p_on_u = Vec::with_capacity(params.coset_u.len());
    for (idx, &x) in params.coset_u.iter().enumerate() {
        let numerator = h_size_scalar * f_prime_on_u[idx] - h_size_scalar * z_h_on_u[idx] * h_on_u[idx] - z_mu_plus_s;
        let denom = h_size_scalar * x;
        let denom_inv = denom
            .inverse()
            .ok_or_else(|| LoquatError::invalid_parameters("Encountered zero denominator in p(x) computation"))?;
        p_on_u.push(numerator * denom_inv);
    }

    let mut c_row = Vec::with_capacity(params.coset_u.len());
    for idx in 0..params.coset_u.len() {
        let mut sum = F2::zero();
        for j in 0..params.n {
            sum += c_prime_on_u_per_j[j][idx];
        }
        c_row.push(sum);
    }

    let base_rows = vec![c_row.clone(), s_on_u.clone(), h_on_u.clone(), p_on_u.clone()];
    let mut pi_rows = base_rows.clone();
    for (row_idx, base_row) in base_rows.iter().enumerate() {
        let exponent = params
            .rho_star_num
            .checked_sub(params.rho_numerators[row_idx])
            .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_i"))? as u128;
        let mut scaled_row = Vec::with_capacity(params.coset_u.len());
        for (value, &y) in base_row.iter().zip(params.coset_u.iter()) {
            let y_pow = y.pow(exponent);
            scaled_row.push(*value * y_pow);
        }
        pi_rows.push(scaled_row);
    }

    let mut f0_on_u = vec![F2::zero(); params.coset_u.len()];
    for (row_idx, row) in pi_rows.iter().enumerate() {
        let coeff = e_vector[row_idx];
        for (col, value) in row.iter().enumerate() {
            f0_on_u[col] += coeff * *value;
        }
    }
    println!("✓ f^(0) evaluations computed over U");

    println!("\n================== ALGORITHM 6: LOQUAT SIGN PART III (LDT) ==================");
    let ldt_codeword = f0_on_u.clone();
    println!("✓ LDT codeword length: {} (evaluations of f^(0) over U)", ldt_codeword.len());
    let (ldt_proof, fri_challenges, fri_codewords, fri_rows) =
        ldt_protocol(&pi_rows, &ldt_codeword, params, &mut transcript)?;
    
    println!("\n--- FINAL SIGNATURE ASSEMBLY ---");

    let signature = LoquatSignature {
        root_c,
        root_s,
        root_h,
        t_values,
        o_values,
        c_prime_evals: c_prime_on_u_per_j,
        s_evals: s_on_u,
        h_evals: h_on_u,
        f_prime_evals: f_prime_on_u,
        p_evals: p_on_u,
        pi_rows,
        f0_evals: f0_on_u,
        fri_challenges,
        fri_codewords,
        fri_rows,
        e_vector,
        s_sum,
        mu,
        z_challenge: z,
        pi_us,
        ldt_proof,
        message_commitment,
    };
    
    println!("✓ σ = {{root_c, root_s, root_h, T_{{i,j}}, o_{{i,j}}, πUS, πLDT}} assembled");
    
    println!("================== ALGORITHMS 4-6 COMPLETE ==================\n");
    Ok(signature)
}


fn ldt_protocol(
    pi_rows: &[Vec<F2>],
    codeword: &[F2],
    params: &LoquatPublicParams,
    transcript: &mut Transcript,
) -> LoquatResult<(LDTProof, Vec<F2>, Vec<Vec<F2>>, Vec<Vec<Vec<F2>>>)> {
    let chunk_size = 1 << params.eta;

    let mut layer_codewords = Vec::with_capacity(params.r + 1);
    layer_codewords.push(codeword.to_vec());
    let mut layer_rows = Vec::with_capacity(params.r + 1);
    layer_rows.push(pi_rows.to_vec());
    let mut folding_challenges = Vec::with_capacity(params.r);

    let mut merkle_trees = Vec::with_capacity(params.r + 1);
    let mut merkle_commitments = Vec::with_capacity(params.r + 1);

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
    let mut current_rows = pi_rows.to_vec();

    for _round in 0..params.r {
        let challenge = transcript_challenge_f2(transcript);
        folding_challenges.push(challenge);

        let mut next_codeword = Vec::with_capacity((current_codeword.len() + chunk_size - 1) / chunk_size);
        for chunk in current_codeword.chunks(chunk_size) {
            let mut coeff = F2::one();
            let mut acc = F2::zero();
            for &val in chunk {
                acc += val * coeff;
                coeff *= challenge;
            }
            next_codeword.push(acc);
        }
        layer_codewords.push(next_codeword.clone());

        let mut next_rows = Vec::with_capacity(current_rows.len());
        for row in current_rows.iter() {
            let mut folded_row = Vec::with_capacity((row.len() + chunk_size - 1) / chunk_size);
            for chunk in row.chunks(chunk_size) {
                let mut coeff = F2::one();
                let mut acc = F2::zero();
                for &val in chunk {
                    acc += val * coeff;
                    coeff *= challenge;
                }
                folded_row.push(acc);
            }
            next_rows.push(folded_row);
        }
        layer_rows.push(next_rows.clone());
        current_rows = next_rows;
        current_codeword = next_codeword;

        let leaves: Vec<Vec<u8>> = current_codeword.iter().map(|f| bincode::serialize(f).unwrap()).collect();
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
    }

    let mut openings = Vec::with_capacity(params.kappa);
    for _ in 0..params.kappa {
        let challenge = transcript_challenge_f2(transcript);
        let position = challenge.c0.0 as usize % layer_codewords[0].len();
        let mut fold_index = position;

        let mut codeword_chunks = Vec::with_capacity(params.r);
        let mut row_chunks = Vec::with_capacity(params.r);

        for round in 0..params.r {
            let layer_len = layer_codewords[round].len();
            let chunk_len = chunk_size.min(layer_len);
            let chunk_start = if layer_len > chunk_size {
                (fold_index / chunk_size) * chunk_size
            } else {
                0
            };
            let chunk_end = (chunk_start + chunk_len).min(layer_len);
            codeword_chunks.push(layer_codewords[round][chunk_start..chunk_end].to_vec());

            let mut rows_for_layer = Vec::with_capacity(layer_rows[round].len());
            for row in layer_rows[round].iter() {
                rows_for_layer.push(row[chunk_start..chunk_end].to_vec());
            }
            row_chunks.push(rows_for_layer);

            if layer_len > chunk_size {
                fold_index /= chunk_size;
            } else {
                fold_index = 0;
            }
        }

        let final_eval = layer_codewords.last().unwrap()[fold_index];
        let auth_path = merkle_trees.last().unwrap().generate_auth_path(fold_index);

        openings.push(LDTOpening {
            position,
            codeword_chunks,
            final_eval,
            row_chunks,
            auth_path,
        });
    }

    let proof = LDTProof {
        commitments: merkle_commitments,
        openings,
    };

    Ok((proof, folding_challenges, layer_codewords, layer_rows))
}

pub fn transcript_challenge_f2(transcript: &mut Transcript) -> F2 {
    let mut buf = [0u8; 32];
    transcript.challenge_bytes(b"challenge", &mut buf);
    let c0 = F::new(u128::from_le_bytes(buf[..16].try_into().unwrap()));
    let c1 = F::new(u128::from_le_bytes(buf[16..].try_into().unwrap()));
    F2::new(c0, c1)
}
