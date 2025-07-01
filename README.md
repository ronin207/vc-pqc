## Overview

Loquat is a novel post-quantum signature scheme that:
- Is based on the **Legendre PRF** (Pseudorandom Function)
- Provides **SNARK-friendly** verification (148K R1CS constraints)
- Offers **stateless many-time signing**
- Uses only **symmetric-key primitives** for security assumptions
- Enables **zero-knowledge proofs** of signature validity

## Algorithm Suite

### Algorithm 1: IOP-based Key Identification of the Legendre PRF

The core protocol that enables SNARK-friendly signature generation by proving knowledge of the secret key without revealing it.

**Input**: L-pp, Instance (pk, I, msg_hash), Witness (secret key K)

**Algorithm Steps**:
1. **Commitment Phase**: Generate random masks and commit using Legendre PRF
2. **Challenge Generation**: Use Fiat-Shamir heuristic for non-interactive challenges  
3. **Response Phase**: Create zero-knowledge responses proving knowledge of K
4. **Polynomial Evaluations**: Generate evaluations for sumcheck protocol
5. **Auxiliary Data**: Include coset points for Low-Degree Testing

**Output**: IOP Proof π with commitments, challenges, responses, and auxiliary data

### Algorithm 2: Loquat Setup

**Input**: Security parameter λ

**Parameters Generated**:
- **Legendre PRF Parameters**: Field 𝔽p, length L, challenge count B, public indices I
- **Sumcheck/LDT Parameters**: Cosets H and U, localization η, repetition κ, rate ρ*
- **Hash Functions**: Collision-resistant functions H₁...H₅₊ᵣ, H_RT

**Output**: Complete public parameters L-pp

### Algorithm 3: Key Generation

**Input**: Public parameters L-pp

**Algorithm Steps**:
1. **Generate Secret Key**: K ←$ 𝔽p* avoiding forbidden values {-I₁, ..., -I_L}
2. **Generate Public Key**: pk := L_K(I) = (L_K(I₁), ..., L_K(I_L))

**Output**: Key pair (sk, pk)

### Algorithm 4: Loquat Sign (Part 1) - Phases 1, 2, and 3

**Phase 1: Commit to Secret Key and Randomness**
```
commitment = Hash(message || secret_key || domain_sep || timestamp || nonce)
```

**Phase 2: Compute Residuosity Symbols**
```
For i = 1 to B:
    residuosity[i] = L_K(I_i) // Legendre PRF evaluation
```

**Phase 3: Compute Witness Vector for Univariate Sumcheck**
```
witness[i] = L_K(I_i) - residuosity[i] (mod p)
// Encodes the relation that proves correct computation
```

### Algorithm 5: Loquat Sign (Part 2) - Phases 3 (continued), 4, and 5

**Phase 3 (continued): Enable Zero-Knowledge of Univariate Sumcheck**
```
For each witness coefficient:
    mask[i] ←$ F_p  // Random masking for zero-knowledge
```

**Phase 4: Univariate Sumcheck Protocol**
```
For round = 1 to log|witness|:
    compute g_round(X) = partial sum polynomial
    challenge ←$ F_p via Fiat-Shamir
    fold witness using challenge
```

**Phase 5: Stacking Codeword for LDT**
```
For each u ∈ U:  // Evaluate witness polynomial on coset U
    codeword[u] = ∑ᵢ witness[i] * uⁱ
```

### Algorithm 6: Loquat Sign (Part 3) - Phases 6 and 7

**Phase 6: LDT Folding Protocol**
```
For round = 1 to r:
    challenge ←$ F_p
    fold: new[i] = old[2i] + challenge * old[2i+1]
    merkle_commit(folded_codeword)
```

**Phase 7: LDT Query Phase**
```
For query = 1 to κ:
    position ←$ [|codeword|]
    generate authentication_path
    verify folding consistency
```

## Signature Structure

```rust
struct LoquatSignature {
    iop_proof: IOPProof,              // Algorithm 1 output
    message_commitment: Vec<u8>,       // Phase 1
    residuosity_symbols: Vec<u128>,    // Phase 2
    sumcheck_witness: Vec<u128>,       // Phase 3
    sumcheck_masks: Vec<u128>,         // Phase 3 (continued)
    sumcheck_proof: SumcheckProof,     // Phase 4
    ldt_codeword: Vec<u128>,          // Phase 5
    ldt_folding: LDTFoldingProof,     // Phase 6
    ldt_queries: Vec<LDTQuery>,       // Phase 7
    signature_metadata: SignatureMetadata,
}
```

## Signature Generation Workflow

```
Algorithm 2 (Setup) → Algorithm 3 (Key Generation) → 
Algorithm 1 (IOP Proof) → Algorithm 4 (Phases 1-3) → 
Algorithm 5 (Phases 4-5) → Algorithm 6 (Phases 6-7) → Complete Signature
```

## Verification Workflow

1. **Verify IOP Proof** (Algorithm 1): Check zero-knowledge proof of key knowledge
2. **Verify Message Commitment**: Ensure message integrity and domain separation
3. **Verify Residuosity Symbols**: Check consistency with challenge count B
4. **Verify Sumcheck Proof**: Validate univariate sumcheck protocol execution
5. **Verify LDT Proof**: Check Low-Degree Test folding and query responses

## Security Properties

### Cryptographic Security
- **EUF-CMA Security**: Existentially unforgeable under chosen message attacks
- **Zero-Knowledge**: Secret key never revealed during signing or verification
- **Post-Quantum Security**: Based on Legendre symbol pseudorandomness assumption

### Implementation Security
- **Message Integrity**: Hash-based message commitments prevent tampering
- **Replay Protection**: Unique nonces prevent signature replay attacks
- **Domain Separation**: Prevents cross-protocol attacks
- **Public Key Authentication**: Wrong keys are cryptographically rejected

## SNARK-Friendly Design

### Circuit Characteristics
- **R1CS Constraints**: ~148K constraints for verification circuit
- **Field Arithmetic**: All operations over finite fields
- **Polynomial Relations**: Sumcheck protocol for efficient verification
- **Low-Degree Testing**: Enables proximity testing in SNARK circuits

### SNARK Integration Points
1. **IOP Proof Verification**: Convert to arithmetic circuit constraints
2. **Sumcheck Protocol**: Native support in SNARK frameworks
3. **Legendre PRF Evaluation**: Efficient in R1CS representation
4. **Hash Function Calls**: Use SNARK-friendly hash functions
5. **Polynomial Evaluations**: Direct translation to circuit constraints

## Advanced Features

### Additional Authenticated Data (AAD)
```rust
let signature = loquat_sign_enhanced(message, keypair, params, Some(aad))?;
let is_valid = loquat_verify_enhanced(message, signature, pk, params, Some(aad))?;
```

### Batch Verification
```rust
let results = loquat_batch_verify(&messages_and_signatures, &public_keys, &params)?;
// Verify multiple signatures simultaneously with better amortized performance
```

### Performance Benchmarking
```rust
let (avg_sign_time, avg_verify_time) = benchmark_signing(message, keypair, params, 100)?;
```

## Usage Example

```rust
use vc_pqc::*;

// Algorithm 2: Setup public parameters
let params = loquat_setup(128)?;

// Algorithm 3: Generate key pair
let keypair = keygen_with_params(&params)?;

// Algorithms 4-6: Complete signature generation
let message = b"Hello, post-quantum world!";
let signature = loquat_sign(message, &keypair, &params)?;

// Complete signature verification
let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)?;
assert!(is_valid);

println!("Signature size: {:.1} KB", estimate_signature_size(&signature) as f64 / 1024.0);
```

## Testing

Run the complete test suite:
```bash
cargo test    # All 13 tests pass
cargo run     # Complete demo with all algorithms
```

## Implementation Architecture

### Module Structure
```
src/
├── setup.rs      - Algorithm 2: Parameter generation
├── keygen.rs     - Algorithm 3: Key generation  
├── iop_key_id.rs - Algorithm 1: IOP-based key identification
├── sign.rs       - Algorithms 4-6: Complete signing protocol
└── main.rs       - Integration and demonstration
```

## References

- [Original Paper](https://eprint.iacr.org/2024/868.pdf): "Loquat: A SNARK-Friendly Post-Quantum Signature based on the Legendre PRF"
- CRYPTO 2024 publication by Zhang et al.
- Legendre PRF construction and security analysis  
- Univariate sumcheck and low-degree testing protocols
- SNARK-friendly signature scheme design principles

## License

This implementation is for educational and research purposes, demonstrating all six algorithms from the Loquat paper with complete functionality and SNARK-ready components. 

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ronin207/vc-pqc)
