use rand::Rng;
use std::collections::HashSet;

/// Algorithm 2: Loquat Setup - Public Parameters
/// Following the specification from the Loquat paper
#[derive(Debug, Clone)]
pub struct LoquatPublicParams {
    // Public Parameters for Legendre PRF
    /// Prime field F_p for sufficiently large p
    pub field_p: u128,
    /// Extension field F = F_p^2 containing large smooth multiplicative subgroups  
    pub extension_field_size: u128,
    /// The number of bits in the public key
    pub l: usize,
    /// Number of challenged residuosity symbols (B ≤ L)
    pub b: usize,
    /// Public indices I = {I_1, ..., I_L} where I_ℓ ←$ F_p
    pub public_indices: Vec<u128>,
    /// Degree bound (m × n = B with m being a power of 2)
    pub m: usize,
    /// Number of parallel executions
    pub n: usize,
    
    // Public Parameters for Univariate Sumcheck and LDT
    /// Multiplicative coset H ⊆ F with |H| = 2m
    pub coset_h: Vec<u128>,
    /// Smooth multiplicative coset U ⊆ F such that |U| > |H| and H ∩ U = ∅
    pub coset_u: Vec<u128>,
    /// Localisation parameter of LDT
    pub eta: usize,
    /// Query repetition parameter of LDT  
    pub kappa: usize,
    /// Maximum rate (closest power of 2) where ρ* > (4m + κ·2^η)/|U|
    pub rho_star: f64,
    /// Round complexity of LDT: r = ⌊(log₂(|U|) - log₂(1/ρ*))/η⌋
    pub r: usize,
    /// r multiplicative subgroups U^(1), ..., U^(r)
    pub u_subgroups: Vec<Vec<u128>>,
    
    // Hash functions and expand function
    /// Collision-resistant hash functions H_1, ..., H_{5+r}, H_RT
    pub hash_functions: Vec<String>,
    /// Expand function: F → F*
    pub expand_function: String,
}

impl std::fmt::Display for LoquatPublicParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "Loquat Public Parameters:\n\
             Field p: {}\n\
             Extension field size: {}\n\
             Public key length L: {}\n\
             Challenge parameter B: {}\n\
             Degree bound m: {}\n\
             Parallel executions n: {}\n\
             Coset H size: {}\n\
             Coset U size: {}\n\
             LDT localization η: {}\n\
             Query repetition κ: {}\n\
             Maximum rate ρ*: {:.6}\n\
             Round complexity r: {}\n\
             Hash functions: {}\n\
             Public indices count: {}",
            self.field_p,
            self.extension_field_size,
            self.l,
            self.b,
            self.m,
            self.n,
            self.coset_h.len(),
            self.coset_u.len(),
            self.eta,
            self.kappa,
            self.rho_star,
            self.r,
            self.hash_functions.len(),
            self.public_indices.len()
        )
    }
}

/// Generate a multiplicative coset of given size in the field
fn generate_multiplicative_coset(size: usize, field_p: u128, generator: u128) -> Vec<u128> {
    let mut coset = Vec::with_capacity(size);
    let mut current = generator;
    
    for _ in 0..size {
        coset.push(current);
        current = (current * generator) % field_p;
    }
    
    coset
}

/// Find a primitive root (generator) for the multiplicative group
fn find_primitive_root(p: u128) -> u128 {
    // For demonstration, we'll use a simple approach
    // In practice, this should use more sophisticated algorithms
    for g in 2..p {
        if is_primitive_root(g, p) {
            return g;
        }
        if g > 100 { // Limit search for performance
            break;
        }
    }
    2 // Fallback generator
}

/// Check if g is a primitive root modulo p
fn is_primitive_root(g: u128, p: u128) -> bool {
    // Simplified check - in practice should verify order is p-1
    if g >= p { return false; }
    
    // Check if g^((p-1)/q) ≠ 1 for all prime factors q of p-1
    // For simplicity, just check it's not 1
    mod_pow(g, (p - 1) / 2, p) != 1
}

/// Modular exponentiation
fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 { return 0; }
    
    let mut result = 1u128;
    base %= modulus;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    
    result
}

/// Generate hash function identifiers
fn generate_hash_functions(count: usize) -> Vec<String> {
    let mut hash_functions = Vec::with_capacity(count);
    
    for i in 1..=count {
        if i <= 5 {
            hash_functions.push(format!("H_{}", i));
        } else if i == count {
            hash_functions.push("H_RT".to_string());
        } else {
            hash_functions.push(format!("H_{}", i));
        }
    }
    
    hash_functions
}

/// Algorithm 2: Loquat Setup
/// Input: Security parameter λ
/// Output: Public parameters L-pp
pub fn loquat_setup(lambda: usize) -> Result<LoquatPublicParams, String> {
    let mut rng = rand::thread_rng();
    
    // Step 1: Generate Public Parameters for Legendre PRF
    
    // Prime field F_p for sufficiently large p
    // Using smaller primes for demonstration, production should use larger primes
    let field_p = match lambda {
        128 => (1u128 << 61) - 1,  // 2^61 - 1 for demo (should be 2^127 - 1)
        256 => (1u128 << 63) - 1,  // 2^63 - 1 for demo (should be 2^255 - 1)
        _ => (1u128 << 31) - 1,    // 2^31 - 1 for smaller security levels
    };
    
    // Extension field F = F_p^2
    let extension_field_size = field_p * field_p;
    
    // Public key length L
    let l = match lambda {
        128 => 256,
        256 => 512,
        _ => 128,
    };
    
    // Number of challenged residuosity symbols B ≤ L
    let b = l / 4; // B = L/4 as suggested in paper for efficiency
    
    // Generate public indices I = {I_1, ..., I_L} where I_ℓ ←$ F_p
    let mut public_indices = Vec::with_capacity(l);
    for _ in 0..l {
        let index = rng.gen_range(1..field_p); // Avoid 0
        public_indices.push(index);
    }
    
    // Degree bound m and parallel executions n such that m × n = B with m power of 2
    let m = (b as f64).sqrt().ceil() as usize;
    let m = m.next_power_of_two(); // Ensure m is power of 2
    let n = (b + m - 1) / m; // Ceiling division to ensure m × n ≥ B
    
    // Step 2: Generate Public Parameters for Univariate Sumcheck and LDT
    
    // Localisation parameter η (typically 2-4)
    let eta = 2;
    
    // Query repetition parameter κ (affects security vs efficiency trade-off)
    let kappa = match lambda {
        128 => 80,
        256 => 128,
        _ => 40,
    };
    
    // Generate multiplicative coset H ⊆ F with |H| = 2m
    let h_size = 2 * m;
    let h_generator = find_primitive_root(field_p);
    let coset_h = generate_multiplicative_coset(h_size, field_p, h_generator);
    
    // Generate smooth multiplicative coset U such that |U| > |H| and H ∩ U = ∅
    let u_size = (h_size * 8).next_power_of_two(); // |U| significantly larger than |H|
    let mut u_generator = h_generator + 1;
    
    // Ensure H ∩ U = ∅ by finding different generator
    loop {
        let candidate_u = generate_multiplicative_coset(u_size, field_p, u_generator);
        let h_set: HashSet<u128> = coset_h.iter().cloned().collect();
        let u_set: HashSet<u128> = candidate_u.iter().cloned().collect();
        
        if h_set.is_disjoint(&u_set) {
            break;
        }
        u_generator += 1;
        if u_generator >= field_p {
            return Err("Could not find disjoint cosets H and U".to_string());
        }
    }
    
    let coset_u = generate_multiplicative_coset(u_size, field_p, u_generator);
    
    // Maximum rate ρ* > (4m + κ·2^η)/|U|
    let min_rate = (4 * m + kappa * (1 << eta)) as f64 / u_size as f64;
    let rho_star = (min_rate * 2.0).ceil() / 2.0; // Round up to nearest 0.5
    
    // Round complexity r = ⌊(log₂(|U|) - log₂(1/ρ*))/η⌋
    let log_u = (u_size as f64).log2();
    let log_inv_rho = (-rho_star.log2()).max(0.0);
    let r = ((log_u - log_inv_rho) / eta as f64).floor() as usize;
    
    // Generate r multiplicative subgroups U^(1), ..., U^(r)
    let mut u_subgroups = Vec::with_capacity(r);
    let mut current_u = coset_u.clone();
    
    for _i in 0..r {
        let mut next_u = Vec::new();
        for &x in &current_u {
            let y = mod_pow(x, 1 << eta, field_p); // y = x^(2^η)
            if !next_u.contains(&y) {
                next_u.push(y);
            }
        }
        u_subgroups.push(next_u.clone());
        current_u = next_u;
    }
    
    // Generate collision-resistant hash functions H_1, ..., H_{5+r}, H_RT
    let hash_count = 5 + r + 1; // +1 for H_RT
    let hash_functions = generate_hash_functions(hash_count);
    
    // Expand function F → F*
    let expand_function = "SHA256-based expand function".to_string();
    
    Ok(LoquatPublicParams {
        field_p,
        extension_field_size,
        l,
        b,
        public_indices,
        m,
        n,
        coset_h,
        coset_u,
        eta,
        kappa,
        rho_star,
        r,
        u_subgroups,
        hash_functions,
        expand_function,
    })
}

/// Generate Loquat public parameters with default 128-bit security
pub fn setup() -> Result<LoquatPublicParams, String> {
    loquat_setup(128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loquat_setup_basic() {
        let result = loquat_setup(128);
        assert!(result.is_ok());
        
        let params = result.unwrap();
        assert!(params.field_p > 0);
        assert!(params.l > 0);
        assert!(params.b <= params.l);
        assert_eq!(params.m * params.n >= params.b, true);
        assert!(params.m.is_power_of_two());
        assert_eq!(params.coset_h.len(), 2 * params.m);
        assert!(params.coset_u.len() > params.coset_h.len());
    }

    #[test]
    fn test_different_security_levels() {
        for &lambda in &[64, 128, 256] {
            let result = loquat_setup(lambda);
            assert!(result.is_ok());
            
            let params = result.unwrap();
            assert!(params.field_p > 0);
            assert!(params.l > 0);
            assert!(params.b <= params.l);
        }
    }

    #[test]
    fn test_coset_disjoint() {
        let params = loquat_setup(128).unwrap();
        let h_set: HashSet<u128> = params.coset_h.iter().cloned().collect();
        let u_set: HashSet<u128> = params.coset_u.iter().cloned().collect();
        
        // H ∩ U = ∅
        assert!(h_set.is_disjoint(&u_set));
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 3, 5), 3); // 2^3 = 8 ≡ 3 (mod 5)
        assert_eq!(mod_pow(3, 4, 7), 4); // 3^4 = 81 ≡ 4 (mod 7)
        assert_eq!(mod_pow(5, 2, 13), 12); // 5^2 = 25 ≡ 12 (mod 13)
    }

    #[test]
    fn test_hash_functions_generation() {
        let hashes = generate_hash_functions(8);
        assert_eq!(hashes.len(), 8);
        assert_eq!(hashes[0], "H_1");
        assert_eq!(hashes[4], "H_5");
        assert_eq!(hashes[7], "H_RT");
    }
}
