use super::errors::{LoquatError, LoquatResult};
use super::field_utils::{F, F2};
use std::collections::HashSet;
use serde::{Serialize, Deserialize};
use rand::Rng;

/// Public parameters for the Loquat signature scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatPublicParams {
    // General Parameters
    pub l: usize,
    pub b: usize,
    pub public_indices: Vec<F>,
    pub m: usize,
    pub n: usize,

    // Parameters for Univariate Sumcheck and LDT
    pub coset_h: Vec<F2>,
    pub coset_u: Vec<F2>,
    pub eta: usize,
    pub kappa: usize,
    pub rho_star: f64,
    pub r: usize,
    pub u_subgroups: Vec<Vec<F2>>,

    // Cryptographic Primitives
    pub hash_functions: Vec<String>,
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

    let min_rate_denominator: usize = 4 * m + (kappa * (1 << eta));
    println!("✓ Minimum rate denominator: 4m + κ*2^η = {}", min_rate_denominator);
    
    let h_size = 2 * m;
    let u_size = min_rate_denominator.next_power_of_two();
    println!("✓ |H| = 2m = {}", h_size);
    println!("✓ |U| = {} (next power of 2 ≥ {})", u_size, min_rate_denominator);
    
    // Placeholder for coset generation
    let coset_h: Vec<F2> = (0..h_size).map(|_| F2::rand(&mut rng)).collect();
    let coset_u: Vec<F2> = (0..u_size).map(|_| F2::rand(&mut rng)).collect();

    let rho_star = 2.0_f64.powi(((min_rate_denominator as f64 / u_size as f64).log2()).floor() as i32 + 1);
    let r = (((u_size as f64).log2() - (-rho_star.log2())) / eta as f64).floor() as usize;
    println!("✓ r (LDT round complexity): {}", r);

    let u_subgroups: Vec<Vec<F2>> = (0..r).map(|_| (0..u_size).map(|_| F2::rand(&mut rng)).collect()).collect();

    // Step 4: Cryptographic Primitives
    let hash_count = 5 + r + 1;
    let hash_functions = generate_hash_functions(hash_count);
    let expand_function = "SHAKE256-based expand function".to_string();

    let params = LoquatPublicParams {
        l, b, public_indices, m, n,
        coset_h, coset_u, eta, kappa, rho_star, r, u_subgroups,
        hash_functions, expand_function,
    };

    println!("\n--- STEP 5: Parameter Validation ---");
    validate_loquat_parameters(&params)?;
    println!("✓ All parameter constraints satisfied");
    
    println!("\n--- OUTPUT: L-pp Generated Successfully ---");
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