//! Field Conversion Utilities
//!
//! This module provides safe conversion between u128 arithmetic and 
//! cryptographically secure finite field operations using ark-ff.

use ark_ff::{PrimeField, Zero, One, Field};
pub use ark_bn254::Fr as F;


/// Convert u128 to secure field element - ONLY for non-cryptographic values.
pub fn u128_to_field(value: u128) -> F {
    F::from(value)
}

/// Convert field element to u128 for display or non-crypto purposes.
/// WARNING: This is a lossy conversion for fields larger than u128.
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

/// Legendre symbol computation using secure field arithmetic
pub fn legendre_symbol_secure(a: F) -> i8 {
    if a.is_zero() {
        return 0;
    }
    
    // Compute a^((p-1)/2) mod p using secure field operations
    let modulus_minus_one = F::MODULUS_MINUS_ONE_DIV_TWO;
    let result = a.pow(modulus_minus_one);
    
    if result.is_one() {
        1  // Quadratic residue
    } else {
        -1 // Quadratic non-residue (result should be p-1 ≡ -1 mod p)
    }
}

/// Convert bytes to a field element.
pub fn bytes_to_field_element(bytes: &[u8]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

/// Legendre symbol computation.
pub fn legendre_symbol(a: F) -> i8 {
    legendre_symbol_secure(a)
}

/// Secure Legendre PRF using field arithmetic
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
}