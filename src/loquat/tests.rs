/// Comprehensive Test Suite for Loquat Implementation
///
/// This module contains comprehensive tests that validate the security,
/// correctness, and robustness of the Loquat signature scheme implementation.
/// Tests are organized by functionality and include both positive and
/// negative test cases.

#[cfg(test)]
mod integration_tests {
    use crate::loquat::field_utils::{legendre_prf_secure, u128_to_field, F, F2};
    use crate::loquat::keygen::keygen_with_params;
    use crate::loquat::setup::loquat_setup;
    use crate::loquat::sign::loquat_sign;
    use crate::loquat::verify::loquat_verify;
    use crate::loquat::field_p127::Fp2; // Import the new field types

    /// Test complete signature generation and verification flow
    #[test]
    fn test_complete_signature_flow() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"Integration test message for complete flow";

        let signature =
            loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");

        let is_valid =
            loquat_verify(message, &signature, &keypair.public_key, &params)
                .expect("Signature verification should complete");

        assert!(is_valid, "Valid signature should verify successfully");
    }

    /// Test signature unforgeability (wrong key rejection)
    #[test]
    fn test_signature_unforgeability() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair1 = keygen_with_params(&params).expect("Key generation 1 should succeed");
        let keypair2 = keygen_with_params(&params).expect("Key generation 2 should succeed");
        let message = b"Unforgeability test message";

        let signature =
            loquat_sign(message, &keypair1, &params).expect("Signature generation should succeed");

        let is_valid =
            loquat_verify(message, &signature, &keypair2.public_key, &params)
                .expect("Verification should complete");

        assert!(!is_valid, "Signature should not verify with wrong public key");
    }

    /// Test message binding (signature changes with different messages)
    #[test]
    fn test_message_binding() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message1 = b"Original message";
        let message2 = b"Modified message";

        let signature =
            loquat_sign(message1, &keypair, &params).expect("Signature generation should succeed");

        let is_valid =
            loquat_verify(message2, &signature, &keypair.public_key, &params)
                .expect("Verification should complete");

        assert!(!is_valid, "Signature should not verify for different message");
    }

    /// Test malformed signature rejection
    #[test]
    fn test_malformed_signature_rejection() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"Malformed signature test";

        let mut signature = loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");

        // Tamper with residuosity symbols
        if !signature.o_values.is_empty() && !signature.o_values[0].is_empty() {
            signature.o_values[0][0] = signature.o_values[0][0] + F::one();
            let is_valid =
                loquat_verify(message, &signature, &keypair.public_key, &params)
                    .expect("Verification should complete");
            assert!(!is_valid, "Tampered residuosity symbols should be rejected");
            signature.o_values[0][0] = signature.o_values[0][0] - F::one(); // Restore
        }
    }

    /// Test field arithmetic edge cases
    #[test]
    fn test_field_arithmetic_edge_cases() {
        // Test with 0 (should always return 0)
        assert_eq!(
            legendre_prf_secure(F::zero()),
            F::zero(),
            "Legendre PRF of 0 should be 0"
        );

        // Test with 1 (should always return 0 for quadratic residue)
        assert_eq!(
            legendre_prf_secure(F::one()),
            F::zero(),
            "Legendre PRF of 1 should be 0"
        );

        // Test determinism
        let test_val = u128_to_field(42);
        let result1 = legendre_prf_secure(test_val);
        let result2 = legendre_prf_secure(test_val);
        assert_eq!(result1, result2, "Legendre PRF should be deterministic");
    }

    #[test]
    fn test_empty_message_signature() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"";

        let signature = loquat_sign(message, &keypair, &params).expect("Signing an empty message should succeed");
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(is_valid, "Signature for empty message should be valid");
    }

    #[test]
    fn test_large_message_signature() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = vec![0u8; 10 * 1024]; // 10 KB message

        let signature = loquat_sign(&message, &keypair, &params).expect("Signing a large message should succeed");
        let is_valid = loquat_verify(&message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(is_valid, "Signature for large message should be valid");
    }

    #[test]
    fn test_tampered_signature_components() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"Tampering test";
        let mut signature = loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");

        // Tamper with Merkle root
        signature.root_c[0] ^= 1;
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(!is_valid, "Signature with tampered Merkle root should be invalid");
        signature.root_c[0] ^= 1; // Restore

        // Tamper with sumcheck proof
        signature.pi_us.claimed_sum = signature.pi_us.claimed_sum + Fp2::one();
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(!is_valid, "Signature with tampered sumcheck proof should be invalid");

        // Tamper with FRI layer commitment
        let mut signature = loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");
        signature.ldt_proof.commitments[1][0] ^= 1;
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(!is_valid, "Signature with tampered FRI commitment should be invalid");

        // Tamper with FRI codeword chunk
        let mut signature = loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");
        signature.fri_codewords[0][0] = signature.fri_codewords[0][0] + F2::one();
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(!is_valid, "Signature with tampered FRI codeword chunk should be invalid");

        // Tamper with Π row folding values
        let mut signature = loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");
        signature.fri_rows[0][0][0] = signature.fri_rows[0][0][0] + F2::one();
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).expect("Verification should complete");
        assert!(!is_valid, "Signature with tampered Π row folding data should be invalid");
    }

    #[test]
    fn test_invalid_setup_parameters() {
        assert!(loquat_setup(100).is_err(), "Setup should fail for unsupported security level");
    }

    #[test]
    fn test_public_key_mismatch() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair1 = keygen_with_params(&params).expect("Keygen should succeed");
        let keypair2 = keygen_with_params(&params).expect("Keygen should succeed");
        let message = b"Public key mismatch test";

        let signature = loquat_sign(message, &keypair1, &params).expect("Signing should succeed");
        let is_valid = loquat_verify(message, &signature, &keypair2.public_key, &params).expect("Verification should complete");
        assert!(!is_valid, "Verification should fail with a different public key");
    }

    #[test]
    fn test_different_security_levels() {
        for &lambda in &[128, 192, 256] {
            let params = loquat_setup(lambda).expect(&format!("Setup for {}-bit failed", lambda));
            let keypair = keygen_with_params(&params).expect(&format!("Keygen for {}-bit failed", lambda));
            let message = format!("Test message for {}-bit security", lambda).into_bytes();

            let signature = loquat_sign(&message, &keypair, &params).expect(&format!("Signing for {}-bit failed", lambda));
            let is_valid = loquat_verify(&message, &signature, &keypair.public_key, &params).expect(&format!("Verification for {}-bit failed", lambda));
            assert!(is_valid, "Signature should be valid for {}-bit security level", lambda);
        }
    }
}
