# Implementation Roadmap

To bring the codebase in line with Algorithms 2–7, follow the staged plan below.
Each stage depends on earlier phases to ensure consistency.

## Stage 1 – Foundation
1. **Field & RNG correctness**
   - Ensure `Fp127::rand` samples uniformly from \( \mathbb{F}_p \setminus \{0\} \) when
     required (e.g., helper for \( \mathbb{F}_p^\* \)).
   - Remove verbose logging of secret material in keygen/sign.
2. **Coset generation**
   - Implement deterministic multiplicative subgroups \(H\) and \(U\) using roots of
     unity in \( \mathbb{F}_{p^2} \).
   - Derive the coset ladder \(U^{(i)}\) via powering map \(x \mapsto x^{2^\eta}\).
3. **Hash / Expand utilities**
   - Provide concrete hash functions \(H_1,\ldots,H_{5+r}, H_{MT}\) backed by SHA-256 /
     SHAKE-256 instances.
   - Implement `expand_challenge` variants that output in \( \mathbb{F}_p^\* \),
     \( \mathbb{F} \), and index sets respecting domain separation.

## Stage 2 – Polynomial Infrastructure
1. **FFT/IFFT support**
   - Add interpolation/evaluation routines over multiplicative cosets (can lean on
     radix-2 FFT for \(2^k\) sized sets).
2. **Helper polynomials**
   - Implement vanishing polynomial \( Z_H(x) \) and utilities to evaluate/lift
     vectors to polynomials.
   - Build structures for \( \hat{c}_j, \hat{c}'_j, \hat{q}_j, \hat{f}_j \) with masking.
3. **Merkle tree bindings**
   - Define serialisation format for vector evaluations across all phases to feed the
     Merkle commitments \( \text{root}_c, \text{root}_s, \text{root}_h, \text{root}_{f^{(i)}} \).

## Stage 3 – Signing Phases
1. **Phase 1 implementation**
   - Sample \( r_{i,j} \in \mathbb{F}_p^\* \), construct \( c_j \), perform interpolation,
     masking, and Merkle commitment to obtain \( \text{root}_c \).
2. **Phase 3 wiring**
   - Generate \( q_j \), compute \( \hat{f}_j \), assemble \( \hat{f} \), evaluate on \(U\),
     and derive claimed sum \( \mu \) in sync with the vector data.
3. **Algorithm 5 data flow**
   - Sample \( \hat{s} \), compute \( \hat{f}' \), split into \( \hat{g} \) and \( \hat{h} \),
     derive \( \hat{p} \), stack matrix \( \Pi \), and commit to \( \text{root}_s \) and
     \( \text{root}_h \).
4. **Algorithm 6 folding**
   - Implement layered Merkle commitments \( \text{root}_{f^{(i)}} \) using actual folded
     vectors driven by transcript challenges; collect opening data for query sets.
5. **Signature packaging**
   - Extend `LoquatSignature` to include all Merkle roots, vector slices, and
     coefficients required by Algorithms 5–6.

## Stage 4 – Verification
1. **Transcript reconstruction**
   - Recompute every challenge and rebuild the polynomial evaluations from
     committed data.
2. **Legendre & algebraic checks**
   - Recalculate \( \hat{c}'_j, \hat{q}_j, \hat{f}_j, \hat{f}', \hat{g}, \hat{h}, \hat{p} \) at the
     queried points and validate the defining relations.
3. **Sumcheck / LDT validation**
   - Wire the computed evaluations into `verify_sumcheck_proof` and a new LDT
     verifier that matches the layered Merkle openings.
4. **Robust error handling**
   - Provide descriptive failure cases that identify which check failed.

## Stage 5 – Testing & Documentation
1. Build unit/integration tests for each phase (setup invariants, signing rounds,
   verification rejection cases).
2. Update README with build instructions, parameter choices, and security notes.
3. Maintain the docs in `docs/` to track compliance progress.

Executing stages in order will incrementally close the spec gaps without breaking
dependent components.
