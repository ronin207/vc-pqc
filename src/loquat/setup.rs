use super::errors::{LoquatError, LoquatResult};
use super::field_utils::F;
use super::ark_serde;
use ark_ff::{Field, FftField, One, UniformRand, Zero};
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

/// Public parameters for the Loquat signature scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatPublicParams {
    // General Parameters
    /// The number of bits in the public key (L).
    pub l: usize,
    /// The number of challenged residuosity symbols (B ≤ L).
    pub b: usize,
    /// Publicly known random field elements I = {I_1, ..., I_L}.
    #[serde(with = "ark_serde::vec")]
    pub public_indices: Vec<F>,
    /// Degree bound for the witness polynomial (m). Must be a power of 2.
    pub m: usize,
    /// Number of parallel executions for the sumcheck protocol (n).
    pub n: usize,

    // Parameters for Univariate Sumcheck and LDT
    /// A multiplicative subgroup H ⊆ F_p of size 2m.
    #[serde(with = "ark_serde::vec")]
    pub coset_h: Vec<F>,
    /// A multiplicative subgroup U ⊆ F_p, disjoint from H.
    #[serde(with = "ark_serde::vec")]
    pub coset_u: Vec<F>,
    /// Localization parameter for the LDT (η).
    pub eta: usize,
    /// Query repetition parameter for the LDT (κ), for soundness amplification.
    pub kappa: usize,
    /// Maximum rate ρ* for the LDT, chosen as an inverse power of 2.
    pub rho_star: f64,
    /// Round complexity of the LDT (r).
    pub r: usize,
    /// A chain of r multiplicative subgroups derived from U.
    #[serde(with = "ark_serde::vec_vec")]
    pub u_subgroups: Vec<Vec<F>>,

    // Cryptographic Primitives
    /// Identifiers for collision-resistant hash functions used in the Fiat-Shamir transform.
    pub hash_functions: Vec<String>,
    /// Identifier for the expand function (used as a random oracle).
    pub expand_function: String,
}

impl std::fmt::Display for LoquatPublicParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Loquat Public Parameters:")?;
        writeln!(f, "  - Public Key Bits (L): {}", self.l)?;
        writeln!(f, "  - Challenge Symbols (B): {}", self.b)?;
        writeln!(f, "  - Degree Bound (m): {}", self.m)?;
        writeln!(f, "  - Parallel Executions (n): {}", self.n)?;
        writeln!(f, "  - Subgroup H size: {}", self.coset_h.len())?;
        writeln!(f, "  - Subgroup U size: {}", self.coset_u.len())?;
        writeln!(f, "  - LDT Localization (η): {}", self.eta)?;
        writeln!(f, "  - LDT Repetitions (κ): {}", self.kappa)?;
        writeln!(f, "  - LDT Rate (ρ*): {:.6}", self.rho_star)?;
        writeln!(f, "  - LDT Rounds (r): {}", self.r)?;
        writeln!(f, "  - Hash Functions: {} total", self.hash_functions.len())?;
        writeln!(
            f,
            "  - Public Indices: {} total",
            self.public_indices.len()
        )
    }
}

/// Finds a generator for a multiplicative subgroup of a given order.
fn find_subgroup_generator(order: u64) -> LoquatResult<F> {
    F::get_root_of_unity(order).ok_or_else(|| {
        LoquatError::invalid_parameters(&format!(
            "The field does not have a {}-th root of unity.",
            order
        ))
    })
}

/// Generates a multiplicative subgroup of a given size from a generator.
fn generate_multiplicative_subgroup(size: usize, generator: F) -> Vec<F> {
    let mut subgroup = Vec::with_capacity(size);
    let mut current = F::one();
    for _ in 0..size {
        subgroup.push(current);
        current *= generator;
    }
    subgroup
}

/// Generates a list of identifiers for hash functions.
fn generate_hash_functions(count: usize) -> Vec<String> {
    (1..=count)
        .map(|i| {
            if i == count {
                "H_RT".to_string() 
            } else {
                format!("H_{}", i)
            }
        })
        .collect()
}

pub fn loquat_setup(lambda: usize) -> LoquatResult<LoquatPublicParams> {
    println!("\n================== ALGORITHM 2: LOQUAT SETUP ==================");
    println!("INPUT: Security Parameter λ = {}", lambda);
    println!("Following Algorithm 2 specification from rules.mdc");
    
    let mut rng = rand::thread_rng();

    // Step 2: Public Parameters for Legendre PRF
    println!("\n--- STEP 2: Public Parameters for Legendre PRF ---");
    
    let l = match lambda {
        128 => 256,
        192 => 384,
        256 => 512,
        _ => return Err(LoquatError::invalid_parameters("Unsupported security level.")),
    };
    println!("✓ L (public key bits): {} (derived from λ={})", l, lambda);
    
    let b = l / 4;
    println!("✓ B (challenged residuosity symbols): {} (B ≤ L constraint satisfied)", b);

    let public_indices: Vec<F> = (0..l).map(|_| F::rand(&mut rng)).collect();
    println!("✓ I = {{I₁, ..., I_L}}: Generated {} random field elements from F_p", public_indices.len());
    println!("  First few I values: {:?}", &public_indices[..std::cmp::min(3, public_indices.len())]);

    let m = 16;
    let n = (b + m - 1) / m;
    println!("✓ m (degree bound): {} (power of 2 requirement satisfied)", m);
    println!("✓ n (parallel executions): {} (where m * n = {} ≥ B = {})", n, m * n, b);

    // Step 3: Public Parameters for Univariate Sumcheck and LDT
    println!("\n--- STEP 3: Public Parameters for Univariate Sumcheck and LDT ---");
    
    let eta = 2;
    println!("✓ η (localization parameter): {}", eta);
    
    let kappa = match lambda {
        128 => 80,
        192 => 112,
        256 => 128,
        _ => 80,
    };
    println!("✓ κ (query repetition parameter): {}", kappa);

    // Calculate required size for U first, then find the next power of two.
    let min_rate_denominator: usize = 4 * m + (kappa * (1 << eta));
    println!("✓ Minimum rate denominator: 4m + κ*2^η = 4*{} + {}*2^{} = {}", 
             m, kappa, eta, min_rate_denominator);
    
    let h_size = 2 * m;
    let u_size = min_rate_denominator.next_power_of_two();
    println!("✓ |H| = 2m = {}", h_size);
    println!("✓ |U| = {} (next power of 2 ≥ {})", u_size, min_rate_denominator);
    
    println!("\n--- Generating Multiplicative Subgroups ---");
    let g_h_generator = find_subgroup_generator(h_size as u64)?;
    let g_h = generate_multiplicative_subgroup(h_size, g_h_generator);
    println!("✓ Generated base subgroup G_H of size {} with generator {:?}", g_h.len(), g_h_generator);
    
    let g_u_generator = find_subgroup_generator(u_size as u64)?;
    let g_u = generate_multiplicative_subgroup(u_size, g_u_generator);    
    println!("✓ Generated base subgroup G_U of size {} with generator {:?}", g_u.len(), g_u_generator);
    
    // Generate cosets (not subgroups) as per the specification
    println!("\n--- Creating Multiplicative Cosets ---");
    let coset_leader_h = F::rand(&mut rng);
    let coset_h: Vec<F> = g_h.iter().map(|h| *h * coset_leader_h).collect();
    println!("✓ H: Multiplicative coset of size {} with leader {:?}", coset_h.len(), coset_leader_h);
    println!("  H[0:3] = {:?}", &coset_h[..std::cmp::min(3, coset_h.len())]);
    
    let h_set: HashSet<F> = coset_h.iter().cloned().collect();

    if h_set.contains(&F::zero()) {
        return Err(LoquatError::invalid_parameters("Coset H contains zero."));
    }
    println!("✓ Verified H does not contain zero");

    // Ensure H and U are disjoint by re-sampling the coset leader for U if necessary.
    println!("\n--- Ensuring H and U are Disjoint ---");
    let mut coset_u;
    let mut attempts = 0;
    loop {
        attempts += 1;
        let coset_leader_u = F::rand(&mut rng);
        coset_u = g_u.iter().map(|x| *x * coset_leader_u).collect::<Vec<F>>();
        let u_set: HashSet<F> = coset_u.iter().cloned().collect();
        
        if h_set.is_disjoint(&u_set) { 
            println!("✓ U: Multiplicative coset of size {} with leader {:?} (attempt {})", 
                     coset_u.len(), coset_leader_u, attempts);
            println!("✓ H ∩ U = ∅ (disjoint constraint satisfied)");
            break; 
        }

        if coset_leader_u.is_zero() {
            return Err(LoquatError::invalid_parameters("Coset leader for U is zero."));
        }
        if u_set.contains(&F::zero()) {
            return Err(LoquatError::invalid_parameters("Coset U contains zero."));
        }
        if attempts > 100 {
            return Err(LoquatError::invalid_parameters("Could not find disjoint cosets after 100 attempts."));
        }
    }

    if u_size < min_rate_denominator {
        return Err(LoquatError::invalid_parameters("LDT parameters are unsatisfiable."));
    }
    
    // Calculate ρ* (maximum rate)
    println!("\n--- Computing Maximum Rate ρ* ---");
    let min_rate = min_rate_denominator as f64 / u_size as f64;
    let rho_star = 2.0_f64.powi(min_rate.log2().floor() as i32 + 1);
    println!("✓ Minimum rate: {}/{} = {:.6}", min_rate_denominator, u_size, min_rate);
    println!("✓ ρ* (maximum rate): {:.6} (closest power of 2 > min_rate)", rho_star);

    let r = (((u_size as f64).log2() - (-rho_star.log2())) / eta as f64).floor() as usize;
    println!("✓ r (LDT round complexity): {} = floor((log₂|U| - log₂(1/ρ*)) / η)", r);

    // Generate U subgroups for LDT folding
    println!("\n--- Generating U Subgroup Chain for LDT ---");
    let mut u_subgroups = Vec::with_capacity(r);
    let mut current_u_elements = coset_u.clone();
    for i in 0..r {
        let next_u_elements: Vec<F> = current_u_elements
            .iter()
            .map(|x| x.pow([(1 << eta) as u64]))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        println!("✓ U^({}) generated: size {} (elements raised to 2^{})", i+1, next_u_elements.len(), eta);
        u_subgroups.push(next_u_elements.clone());
        current_u_elements = next_u_elements;
    }

    // Step 4: Cryptographic Primitives
    println!("\n--- STEP 4: Cryptographic Primitives ---");
    let hash_count = 5 + r + 1;
    let hash_functions = generate_hash_functions(hash_count);
    let expand_function = "SHAKE256-based expand function".to_string();
    println!("✓ Hash functions: {} total (H₁, ..., H₅₊ᵣ, H_MT)", hash_functions.len());
    println!("  Functions: {:?}", hash_functions);
    println!("✓ Expand function: {}", expand_function);

    let params = LoquatPublicParams {
        l, b, public_indices, m, n,
        coset_h, coset_u, eta, kappa, rho_star, r, u_subgroups,
        hash_functions, expand_function,
    };

    println!("\n--- STEP 5: Parameter Validation ---");
    validate_loquat_parameters(&params)?;
    println!("✓ All parameter constraints satisfied");
    
    println!("\n--- OUTPUT: L-pp Generated Successfully ---");
    println!("Parameters summary:");
    println!("  λ = {}, L = {}, B = {}, m = {}, n = {}", lambda, params.l, params.b, params.m, params.n);
    println!("  |H| = {}, |U| = {}, η = {}, κ = {}", params.coset_h.len(), params.coset_u.len(), params.eta, params.kappa);
    println!("  ρ* = {:.6}, r = {}", params.rho_star, params.r);
    println!("================== ALGORITHM 2 COMPLETE ==================\n");
    
    Ok(params)
}

fn validate_loquat_parameters(params: &LoquatPublicParams) -> LoquatResult<()> {
    if params.b > params.l {
        return Err(LoquatError::invalid_parameters("B > L"));
    }
    if params.m * params.n < params.b {
        return Err(LoquatError::invalid_parameters("m*n < B"));
    }
    if !params.m.is_power_of_two() {
        return Err(LoquatError::invalid_parameters("m is not a power of 2"));
    }
    if params.coset_h.len() != 2 * params.m {
        return Err(LoquatError::invalid_parameters("|H| != 2m"));
    }
    
    let h_set: HashSet<F> = params.coset_h.iter().cloned().collect();
    let u_set: HashSet<F> = params.coset_u.iter().cloned().collect();
    if !h_set.is_disjoint(&u_set) {
        return Err(LoquatError::invalid_parameters("H and U are not disjoint"));
    }

    let min_rate_check = (4.0 * params.m as f64 + (params.kappa * (1 << params.eta)) as f64)
        / params.coset_u.len() as f64;
    if params.rho_star <= min_rate_check {
        return Err(LoquatError::invalid_parameters("ρ* is too small"));
    }
    
    let k = -params.rho_star.log2();
    let expected_r = ((params.coset_u.len() as f64).log2() - k) / params.eta as f64;
    if params.r as f64 > expected_r {
        return Err(LoquatError::invalid_parameters("r does not match expected r"));
    }
    
    let expected_hash_count = 5 + params.r + 1;
    if params.hash_functions.len() != expected_hash_count {
        return Err(LoquatError::invalid_parameters("Incorrect number of hash functions"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loquat_setup_128bit() {
        let result = loquat_setup(128);
        assert!(result.is_ok());

        let params = result.unwrap();
        assert_eq!(params.l, 256);
        assert_eq!(params.b, 64);
        assert!(params.m * params.n >= params.b);
        assert!(params.m.is_power_of_two());
        assert_eq!(params.coset_h.len(), 2 * params.m);
        assert!(params.coset_u.len() > params.coset_h.len());
        assert!(validate_loquat_parameters(&params).is_ok());
    }

    #[test]
    fn test_different_security_levels() {
        for &lambda in &[128, 192, 256] {
            let result = loquat_setup(lambda);
            assert!(result.is_ok(), "Setup failed for lambda={}", lambda);
            let params = result.unwrap();
            assert!(validate_loquat_parameters(&params).is_ok());
        }
    }

    #[test]
    fn test_subgroup_disjointness() {
        let params = loquat_setup(128).unwrap();
        let h_set: HashSet<F> = params.coset_h.iter().cloned().collect();
        let u_set: HashSet<F> = params.coset_u.iter().cloned().collect();
        assert!(h_set.is_disjoint(&u_set), "Cosets H and U should be disjoint");
        assert!(!h_set.contains(&F::one()));
    }

    #[test]
    fn test_hash_functions_generation() {
        let hashes = generate_hash_functions(8);
        assert_eq!(hashes.len(), 8);
        assert_eq!(hashes[0], "H_1");
        assert_eq!(hashes[7], "H_RT");
    }

    #[test]
    fn test_invalid_security_level() {
        assert!(loquat_setup(100).is_err());
    }
}