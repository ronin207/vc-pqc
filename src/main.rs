pub mod setup;
pub mod keygen;
pub mod iop_key_id;
pub mod sign;
pub mod verify;
pub mod benchmark;

use setup::loquat_setup;
use keygen::keygen_with_params;
use iop_key_id::{iop_key_identification, verify_iop_proof, create_iop_instance, create_iop_witness};
use sign::{loquat_sign, loquat_verify, loquat_sign_enhanced, loquat_verify_enhanced, 
          loquat_batch_verify, estimate_signature_size, benchmark_signing};
use std::env;
use benchmark::{LoquatBenchmark, run_complete_benchmark};

fn demo_security_level(lambda: usize) -> Result<(), String> {
    println!("Security Level: {}-bit", lambda);
    
    // Algorithm 2: Setup
    println!("Running Algorithm 2: Loquat Setup...");
    let params = loquat_setup(lambda)?;
    println!("   Generated public parameters:");
    println!("     - Field p: 2^{} - 1", (params.field_p as f64).log2().floor() as u32);
    println!("     - Public key length L: {}", params.l);
    println!("     - Challenge count B: {}", params.b);
    println!("     - Coset H size: {}", params.coset_h.len());
    println!("     - Coset U size: {}", params.coset_u.len());
    println!("     - Query repetitions kappa: {}", params.kappa);
    
    // Algorithm 3: Key Generation  
    println!("Running Algorithm 3: Key Generation...");
    let keypair = keygen_with_params(&params)?;
    println!("   Generated key pair:");
    println!("     - Secret key: [HIDDEN]");
    println!("     - Public key length: {}", keypair.public_key.len());
    
    // Algorithm 1: IOP-based Key Identification (Core Component)
    println!("Running Algorithm 1: IOP-based Key Identification...");
    let message = format!("Loquat signature test - {} bits", lambda);
    let instance = create_iop_instance(&keypair, &params, message.as_bytes());
    let witness = create_iop_witness(keypair.secret_key);
    
    let proof = iop_key_identification(&params, &instance, &witness, message.as_bytes())?;
    println!("   Generated IOP proof:");
    println!("     - Commitment length: {}", proof.commitment.len());
    println!("     - Response length: {}", proof.responses.len());
    println!("     - Challenge count: {}", proof.challenges.len());
    println!("     - Polynomial evaluations: {}", proof.poly_evaluations.len());
    println!("     - Auxiliary data: {}", proof.aux_data.len());
    
    // Verify the IOP proof
    println!("Verifying IOP proof...");
    let is_valid = verify_iop_proof(&params, &instance, &proof, message.as_bytes())?;
    if is_valid {
        println!("   Proof verification SUCCESSFUL");
    } else {
        println!("   Proof verification FAILED");
        return Err("Proof verification failed".to_string());
    }
    
    // Algorithm 4-6: Complete Signature Workflow
    println!("Running Algorithms 4-6: Complete Signature Generation & Verification...");
    let signature = loquat_sign(message.as_bytes(), &keypair, &params)?;
    println!("   Generated complete Loquat signature:");
    println!("     - IOP proof components: {}", proof.commitment.len() + proof.responses.len() + proof.challenges.len());
    println!("     - Message commitment: {} bytes", signature.message_commitment.len());
    println!("     - Signature metadata: version {}", signature.signature_metadata.version);
    
    let is_signature_valid = loquat_verify(message.as_bytes(), &signature, &keypair.public_key, &params)?;
    if is_signature_valid {
        println!("   Complete signature verification SUCCESSFUL");
    } else {
        println!("   Complete signature verification FAILED");
        return Err("Complete signature verification failed".to_string());
    }
    
    // Calculate signature size
    let signature_size = estimate_signature_size(&signature);
    println!("Complete signature size: {:.1} KB", signature_size as f64 / 1024.0);
    
    println!("{}", "-".repeat(60));
    Ok(())
}

fn demo_complete_signature_workflow() -> Result<(), String> {
    println!("Complete Loquat Signature Workflow Demo");
    println!("=======================================\n");
    
    // Use 128-bit security for detailed demo
    let lambda = 128;
    let params = loquat_setup(lambda)?;
    let keypair = keygen_with_params(&params)?;
    
    println!("Demonstrating all signature algorithms:\n");
    
    // Demo 1: Basic signature generation and verification
    println!("Demo 1: Basic Signature Generation (Algorithms 4-6)");
    let message1 = b"Hello, post-quantum cryptography!";
    
    let start_time = std::time::Instant::now();
    let signature1 = loquat_sign(message1, &keypair, &params)?;
    let sign_time = start_time.elapsed();
    
    let start_time = std::time::Instant::now();
    let is_valid1 = loquat_verify(message1, &signature1, &keypair.public_key, &params)?;
    let verify_time = start_time.elapsed();
    
    println!("  Message: \"{}\"", String::from_utf8_lossy(message1));
    println!("  Signed in {:.2?}", sign_time);
    println!("  Verified in {:.2?} (valid: {})", verify_time, is_valid1);
    println!("  Signature size: {:.1} KB\n", estimate_signature_size(&signature1) as f64 / 1024.0);
    
    // Demo 2: Enhanced signatures with Additional Authenticated Data (AAD)
    println!("Demo 2: Enhanced Signatures with AAD");
    let message2 = b"Secure transaction data";
    let aad = b"timestamp:2024-01-01,nonce:12345";
    
    let signature2 = loquat_sign_enhanced(message2, &keypair, &params, Some(aad))?;
    let is_valid2 = loquat_verify_enhanced(message2, &signature2, &keypair.public_key, &params, Some(aad))?;
    
    println!("  Message: \"{}\"", String::from_utf8_lossy(message2));
    println!("  AAD: \"{}\"", String::from_utf8_lossy(aad));
    println!("  Enhanced signature valid: {}", is_valid2);
    
    // Test that wrong AAD fails
    let wrong_aad = b"timestamp:2024-01-02,nonce:54321";
    let is_valid_wrong = loquat_verify_enhanced(message2, &signature2, &keypair.public_key, &params, Some(wrong_aad))?;
    println!("  Wrong AAD correctly rejected: {}\n", !is_valid_wrong);
    
    // Demo 3: Batch verification
    println!("Demo 3: Batch Signature Verification");
    let keypair2 = keygen_with_params(&params)?;
    let keypair3 = keygen_with_params(&params)?;
    
    let messages = [
        b"Batch message 1",
        b"Batch message 2", 
        b"Batch message 3",
    ];
    
    let signatures = [
        loquat_sign(messages[0], &keypair, &params)?,
        loquat_sign(messages[1], &keypair2, &params)?,
        loquat_sign(messages[2], &keypair3, &params)?,
    ];
    
    let messages_and_sigs: Vec<(&[u8], &sign::LoquatSignature)> = messages.iter()
        .zip(signatures.iter())
        .map(|(msg, sig)| (*msg as &[u8], sig))
        .collect();
    
    let public_keys = [
        &keypair.public_key[..],
        &keypair2.public_key[..], 
        &keypair3.public_key[..],
    ];
    
    let batch_start = std::time::Instant::now();
    let batch_results = loquat_batch_verify(&messages_and_sigs, &public_keys, &params)?;
    let batch_time = batch_start.elapsed();
    
    println!("  Batch verified {} signatures in {:.2?}", messages.len(), batch_time);
    println!("  All signatures valid: {}", batch_results.iter().all(|&valid| valid));
    println!("  Average per signature: {:.2?}\n", batch_time / messages.len() as u32);
    
    // Demo 4: Performance benchmarking
    println!("Demo 4: Performance Benchmarking");
    let bench_message = b"Performance benchmark message";
    let iterations = 10;
    
    let (avg_sign_time, avg_verify_time) = benchmark_signing(
        bench_message, &keypair, &params, iterations
    )?;
    
    println!("  Benchmarked {} iterations", iterations);
    println!("  Average signing time: {:.2?}", avg_sign_time);
    println!("  Average verification time: {:.2?}", avg_verify_time);
    println!("  Signing throughput: {:.1} signatures/second", 1.0 / avg_sign_time.as_secs_f64());
    println!("  Verification throughput: {:.1} verifications/second\n", 1.0 / avg_verify_time.as_secs_f64());
    
    // Demo 5: Security demonstrations
    println!("Demo 5: Security Property Demonstrations");
    
    // Test message tampering detection
    let original_message = b"Original secure message";
    let tampered_message = b"Tampered secure message";
    let sig_original = loquat_sign(original_message, &keypair, &params)?;
    let tampering_detected = !loquat_verify(tampered_message, &sig_original, &keypair.public_key, &params)?;
    println!("  Message tampering detected: {}", tampering_detected);
    
    // Test wrong public key rejection  
    let wrong_key_rejected = !loquat_verify(original_message, &sig_original, &keypair2.public_key, &params)?;
    println!("  Wrong public key rejected: {}", wrong_key_rejected);
    
    // Test signature replay protection (different nonce should create different signature)
    let sig1 = loquat_sign(original_message, &keypair, &params)?;
    let sig2 = loquat_sign(original_message, &keypair, &params)?;
    let replay_protection = sig1.signature_metadata.nonce != sig2.signature_metadata.nonce;
    println!("  Replay protection (different nonces): {}", replay_protection);
    
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() > 1 {
        match args[1].as_str() {
            "benchmark" => {
                println!("Running Loquat Performance Benchmark Suite");
                if let Err(e) = run_complete_benchmark() {
                    eprintln!("Benchmark failed: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "quick-bench" => {
                if let Err(e) = benchmark::LoquatBenchmark::quick_test() {
                    eprintln!("Quick benchmark failed: {}", e);
                    std::process::exit(1);
                }
                return;
            }
            "help" | "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {
                println!("Unknown command: {}", args[1]);
                print_help();
                std::process::exit(1);
            }
        }
    }

    println!("Loquat Post-Quantum Signature Scheme - Complete Implementation");
    println!("==============================================================\n");
    
    println!("Implementation of Algorithms 1-6 from:");
    println!("\"Loquat: A SNARK-Friendly Post-Quantum Signature based on the Legendre PRF\"");
    println!("by Zhang et al. (https://eprint.iacr.org/2024/868.pdf)\n");
    
    println!("Testing different security levels:\n");
    
    // Demo different security levels with complete workflow
    for &lambda in &[64, 128, 256] {
        if let Err(e) = demo_security_level(lambda) {
            println!("Error in {}-bit demo: {}", lambda, e);
            continue;
        }
        println!();
    }
    
    // Demo complete signature workflow
    if let Err(e) = demo_complete_signature_workflow() {
        println!("Error in complete signature workflow demo: {}", e);
    }
    
    // println!("🎯 Complete Algorithm Implementation:");
    // println!("   • Algorithm 1: IOP-based key identification of Legendre PRF");
    // println!("   • Algorithm 2: Complete parameter setup with cosets and hash functions");
    // println!("   • Algorithm 3: Secure key generation avoiding forbidden values");
    // println!("   • Algorithm 4: Message preprocessing with domain separation");
    // println!("   • Algorithm 5: Complete signature generation workflow");
    // println!("   • Algorithm 6: Comprehensive signature verification\n");
    
    // println!("🔐 Security Features Demonstrated:");
    // println!("   • Zero-knowledge proofs (secret key never revealed)");
    // println!("   • Message integrity protection (tampering detection)");
    // println!("   • Public key authentication (wrong key rejection)");
    // println!("   • Replay attack protection (unique nonces)");
    // println!("   • Additional authenticated data (AAD) support");
    // println!("   • Batch verification capability\n");
    
    // println!("🔬 SNARK Compatibility:");
    // println!("   • Polynomial evaluations for sumcheck protocol");
    // println!("   • Low-degree testing via cosets H and U");
    // println!("   • Collision-resistant hash function integration");
    // println!("   • ~148K R1CS constraints for verification circuit");
    // println!("   • Ready for Aurora/Fractal proof composition\n");
    
    // println!("⚡ Performance Characteristics:");
    // println!("   • Demo fields: ~3ms signing, ~1ms verification");
    // println!("   • Paper (production): 5.04s signing, 0.21s verification");
    // println!("   • Signature size: ~4.6KB (demo), 46KB (production)");
    // println!("   • Batch verification: Linear scaling with optimizations");
    // println!("   • SNARK-friendly: 7-175× better than MPC-in-the-head\n");
    
    // println!("🚀 Applications Ready:");
    // println!("   • Post-quantum digital signatures");
    // println!("   • Aggregate signature schemes"); 
    // println!("   • Ring signature protocols");
    // println!("   • Blockchain integration");
    // println!("   • Zero-knowledge proof systems");
    // println!("   • SNARK circuit verification\n");
    
    // println!("✅ All algorithms (1-6) implemented and tested successfully!");
    // println!("   🌟 Complete Loquat signature scheme ready for production use!");
}

fn print_help() {
    println!("Loquat Post-Quantum Signature Scheme");
    println!();
    println!("USAGE:");
    println!("    cargo run [COMMAND]");
    println!();
    println!("COMMANDS:");
    println!("    benchmark     Run complete performance benchmark suite");
    println!("    quick-bench   Run quick performance test (3 iterations)");
    println!("    help          Show this help message");
    println!();
    println!("If no command is provided, runs the default demo.");
}
