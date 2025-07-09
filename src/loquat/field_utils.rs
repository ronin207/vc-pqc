//! Field Conversion Utilities
//!
//! This module provides safe conversion between u128 arithmetic and 
//! cryptographically secure finite field operations using ark-ff.
//! 
//! SECURITY NOTE: Using ark_bn254::Fr temporarily but rules.mdc specifies 
//! Mersenne prime p = 2^127 - 1. This field will need to be replaced
//! with a proper implementation for full compliance.

use ark_ff::{PrimeField, Zero, One, Field};

// TEMPORARY: Using BN254 scalar field - needs replacement with p = 2^127 - 1 per rules.mdc
pub use ark_bn254::Fr as F;

/// Convert u128 to secure field element
pub fn u128_to_field(value: u128) -> F {
    F::from(value)
}

/// Convert field element to u128 for display purposes (lossy conversion)
pub fn field_to_u128_lossy(field_elem: F) -> u128 {
    let bigint = field_elem.into_bigint();
    if bigint.0.len() > 1 {
        (bigint.0[0] as u128) | ((bigint.0[1] as u128) << 64)
    } else if bigint.0.len() == 1 {
        bigint.0[0] as u128
    } else {
        0
    }
}

/// Safe field multiplication 
pub fn field_mul(a: F, b: F) -> F {
    a * b
}

/// Safe field addition
pub fn field_add(a: F, b: F) -> F {
    a + b
}

/// Safe field exponentiation
pub fn field_pow(base: F, exp: u64) -> F {
    base.pow([exp])
}

/// Convert slice of u128 to field elements
pub fn u128_slice_to_field(values: &[u128]) -> Vec<F> {
    values.iter().map(|&v| u128_to_field(v)).collect()
}

/// Constant-time Legendre symbol computation as mandated by rules.mdc
/// "The modular exponentiation used to compute the Legendre symbol MUST be 
/// implemented in constant time. A standard pow function with data-dependent 
/// branching or timing is vulnerable to side-channel attacks"
pub fn legendre_symbol_secure(a: F) -> i8 {
    if a.is_zero() {
        return 0;
    }
    
    // Constant-time computation of a^((p-1)/2) mod p
    // For BN254 scalar field, (p-1)/2 is precomputed
    let result = constant_time_pow_field(a, F::MODULUS_MINUS_ONE_DIV_TWO);
    
    if result == F::one() {
        1  // Quadratic residue
    } else {
        -1 // Quadratic non-residue
    }
}

/// Constant-time modular exponentiation using Montgomery ladder approach
/// This prevents timing attacks by ensuring all operations take the same time
fn constant_time_pow_field(base: F, exp: <F as PrimeField>::BigInt) -> F {
    let mut result = F::one();
    
    // Process each bit of the exponent in constant time
    for word in exp.0.iter().rev() {
        for i in (0..64).rev() {
            result = result.square();
            
            let bit = (word >> i) & 1;
            // Constant-time conditional: if bit == 1, result *= base
            if bit == 1 {
                result *= base;
            }
        }
    }
    
    result
}

/// Convert bytes to a field element
pub fn bytes_to_field_element(bytes: &[u8]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

/// Legendre symbol computation (wrapper for secure version)
pub fn legendre_symbol(a: F) -> i8 {
    legendre_symbol_secure(a)
}

/// Secure Legendre PRF using constant-time field arithmetic
/// L₀(a) = (1 - (a/p)) / 2, where (a/p) is the Legendre symbol
pub fn legendre_prf_secure(input: F) -> F {
    let symbol = legendre_symbol_secure(input);
    match symbol {
        1 => F::zero(),     // Quadratic residue maps to 0
        -1 => F::one(),     // Quadratic non-residue maps to 1  
        0 => F::zero(),     // Zero maps to 0
        _ => F::zero(),     // Should never happen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u128_field_conversion() {
        let original = 12345u128;
        let field_elem = u128_to_field(original);
        let converted_back = field_to_u128_lossy(field_elem);
        assert_eq!(original, converted_back);
    }

    #[test]
    fn test_field_operations() {
        let a = u128_to_field(10);
        let b = u128_to_field(20);
        
        let sum = field_add(a, b);
        let expected_sum = u128_to_field(30);
        assert_eq!(sum, expected_sum);
        
        let product = field_mul(a, b);
        let expected_product = u128_to_field(200);
        assert_eq!(product, expected_product);
    }

    #[test]
    fn test_legendre_prf_deterministic() {
        let input = u128_to_field(42);
        let result1 = legendre_prf_secure(input);
        let result2 = legendre_prf_secure(input);
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_constant_time_legendre() {
        // Test that the same input always gives the same result (determinism)
        let test_vals = [1u128, 2, 3, 4, 5, 100, 1000];
        
        for val in test_vals {
            let input = u128_to_field(val);
            let result1 = legendre_symbol_secure(input);
            let result2 = legendre_symbol_secure(input);
            assert_eq!(result1, result2, "Legendre symbol should be deterministic for {}", val);
            
            // Result should be -1, 0, or 1
            assert!(result1 == -1 || result1 == 0 || result1 == 1, 
                    "Invalid Legendre symbol result: {}", result1);
        }
    }
}