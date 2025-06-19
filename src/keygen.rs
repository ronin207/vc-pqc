use rand::Rng;
use std::fmt;
use crate::setup::LoquatPublicParams;

/// Parameters for the Loquat key generation
pub struct LoquatParams {
    /// Prime field parameter p = 2^127 - 1 (as specified in the paper for 128-bit security)
    pub p: u128,
    /// Length of the public key (number of Legendre PRF evaluations)
    pub l: usize,
    /// Publicly accessible list I = (I_1, ..., I_L) chosen uniformly from F_p
    pub public_indices: Vec<u128>,
}

/// Loquat key pair
#[derive(Debug, Clone)]
pub struct LoquatKeyPair {
    pub secret_key: u128,
    pub public_key: Vec<u128>,
}

impl fmt::Display for LoquatKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LoquatKeyPair {{ secret_key: [HIDDEN], public_key: {} bits }}",
               self.public_key.len())
    }
}

/// Legendre PRF evaluation: L_K(a) = L_0(K + a) where L_0(a) = floor(1/2 * (1 - (a/p)))
/// Uses the Legendre symbol computed via Euler's criterion: (a/p) = a^((p-1)/2) mod p
pub fn legendre_prf(a: u128, p: u128) -> u128 {
    if a == 0 {
        return 0;
    }
    
    if a >= p {
        return legendre_prf(a % p, p);
    }
    
    // Compute Legendre symbol using Euler's criterion: (a/p) = a^((p-1)/2) mod p
    let legendre_symbol = mod_pow(a, (p - 1) / 2, p);
    
    // Convert to Legendre PRF output: L_0(a) = floor(1/2 * (1 - (a/p)))
    // If legendre_symbol = 1, then (a/p) = 1, so L_0(a) = floor(1/2 * (1-1)) = 0
    // If legendre_symbol = p-1, then (a/p) = -1, so L_0(a) = floor(1/2 * (1-(-1))) = 1
    if legendre_symbol == 1 {
        0
    } else if legendre_symbol == p - 1 {
        1  
    } else {
        // This shouldn't happen for a prime p and a ≠ 0
        0
    }
}

/// Modular exponentiation using binary exponentiation with overflow protection
fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    if modulus == 1 {
        return 0;
    }
    
    let mut result = 1u128;
    base %= modulus;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        exp >>= 1;
        if exp > 0 {
            base = mod_mul(base, base, modulus);
        }
    }
    
    result
}

/// Modular multiplication with overflow protection
fn mod_mul(a: u128, b: u128, modulus: u128) -> u128 {
    if modulus <= (1u128 << 64) {
        ((a % modulus) * (b % modulus)) % modulus
    } else {
        // For large modulus, use saturating multiplication
        (a % modulus).saturating_mul(b % modulus) % modulus
    }
}

/// Generates default Loquat parameters for demonstration
/// Note: Using production field sizes per paper specifications
pub fn generate_default_params() -> LoquatParams {
    // Production prime field as specified in the Loquat paper
    // Using p = 2^127 - 1 (Mersenne prime for 128-bit security)
    let p = (1u128 << 127) - 1; // Production value: 2^127 - 1
    
    // L = 256 for 128-bit security as suggested in paper
    let l = 256;
    
    // Generate public indices I = (I_1, ..., I_L) uniformly from F_p
    let mut rng = rand::thread_rng();
    let mut public_indices = Vec::with_capacity(l);
    
    for _ in 0..l {
        // Generate random element in F_p
        let index = rng.gen_range(1..p); // Avoid 0 to stay in F_p*
        public_indices.push(index);
    }
    
    LoquatParams {
        p,
        l,
        public_indices,
    }
}

/// Algorithm 3: Loquat Key Generation (updated to work with LoquatPublicParams)
/// Input: Loquat public parameters L-pp  
/// Output: Loquat key pair (sk, pk)
pub fn keygen_with_params(params: &LoquatPublicParams) -> Result<LoquatKeyPair, String> {
    let mut rng = rand::thread_rng();
    
    // Step 1: Sample secret key K ∈ F_p* avoiding forbidden values
    let mut secret_key;
    let max_attempts = 1000;
    let mut attempts = 0;
    
    loop {
        if attempts >= max_attempts {
            return Err("Failed to generate valid secret key after maximum attempts".to_string());
        }
        
        // Sample K uniformly from F_p* (non-zero elements)
        secret_key = rng.gen_range(1..params.field_p);
        
        // Check if K is forbidden: K + I_i = 0 (mod p) for any i
        // Equivalently: K = -I_i (mod p) for any i
        let mut is_forbidden = false;
        for &index in &params.public_indices {
            let forbidden_value = (params.field_p - index) % params.field_p;
            if secret_key == forbidden_value {
                is_forbidden = true;
                break;
            }
        }
        
        if !is_forbidden {
            break;
        }
        
        attempts += 1;
    }
    
    // Step 2: Compute public key pk = L_K(I) = (L_K(I_1), ..., L_K(I_L))
    let mut public_key = Vec::with_capacity(params.l);
    
    for i in 0..params.l {
        let index = params.public_indices[i];
        let input = (secret_key + index) % params.field_p;
        let prf_output = legendre_prf(input, params.field_p);
        public_key.push(prf_output);
    }
    
    Ok(LoquatKeyPair {
        secret_key,
        public_key,
    })
}

/// Compatibility function for the old LoquatParams interface
pub fn keygen_with_loquat_params(params: &LoquatParams) -> Result<LoquatKeyPair, String> {
    let mut rng = rand::thread_rng();
    
    // Convert to use the same logic but with old interface
    let mut secret_key;
    let max_attempts = 1000;
    let mut attempts = 0;
    
    loop {
        if attempts >= max_attempts {
            return Err("Failed to generate valid secret key after maximum attempts".to_string());
        }
        
        secret_key = rng.gen_range(1..params.p);
        
        let mut is_forbidden = false;
        for &index in &params.public_indices {
            let forbidden_value = (params.p - index) % params.p;
            if secret_key == forbidden_value {
                is_forbidden = true;
                break;
            }
        }
        
        if !is_forbidden {
            break;
        }
        
        attempts += 1;
    }
    
    let mut public_key = Vec::with_capacity(params.l);
    
    for i in 0..params.l {
        let index = params.public_indices[i];
        let input = (secret_key + index) % params.p;
        let prf_output = legendre_prf(input, params.p);
        public_key.push(prf_output);
    }
    
    Ok(LoquatKeyPair {
        secret_key,
        public_key,
    })
}

/// Main keygen function that uses default parameters and returns a formatted string
pub fn keygen() -> Result<LoquatKeyPair, String> {
    let params = generate_default_params();
    keygen_with_loquat_params(&params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legendre_prf() {
        let p = 2147483647u128; // 2^31 - 1 (Mersenne prime)
        
        // Test some known values
        assert_eq!(legendre_prf(1, p), 0); // 1 is always a quadratic residue
        assert_eq!(legendre_prf(0, p), 0); // 0 case
        
        // Test that function is deterministic
        let result1 = legendre_prf(42, p);
        let result2 = legendre_prf(42, p);
        assert_eq!(result1, result2);
        
        println!("Legendre PRF tests passed.");
    }

    #[test]
    fn test_keygen_basic() {
        let params = LoquatParams {
            p: 2147483647u128, // 2^31 - 1
            l: 10,
            public_indices: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        };
        
        let result = keygen_with_loquat_params(&params);
        assert!(result.is_ok());
        
        let keypair = result.unwrap();
        assert!(keypair.secret_key > 0);
        assert!(keypair.secret_key < params.p);
        assert_eq!(keypair.public_key.len(), params.l);
        
        println!("Basic key generation test passed.");
    }

    #[test]
    fn test_forbidden_values() {
        let params = LoquatParams {
            p: 101, // Small prime for testing
            l: 3,
            public_indices: vec![1, 2, 3],
        };
        
        let keypair = keygen_with_loquat_params(&params).unwrap();
        
        // Verify secret key is not forbidden
        for &index in &params.public_indices {
            let forbidden = (params.p - index) % params.p;
            assert_ne!(keypair.secret_key, forbidden, 
                "Secret key {} should not equal forbidden value {} (for index {})", 
                keypair.secret_key, forbidden, index);
        }
        
        println!("Forbidden values test passed.");
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 3, 5), 3); // 2^3 mod 5 = 8 mod 5 = 3
        assert_eq!(mod_pow(3, 2, 7), 2); // 3^2 mod 7 = 9 mod 7 = 2
        assert_eq!(mod_pow(5, 0, 7), 1); // 5^0 mod 7 = 1
        
        println!("Modular exponentiation tests passed.");
    }
}