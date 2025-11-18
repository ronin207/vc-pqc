# BDEC Proof-of-Concept Plan

This checklist captures the minimal steps needed to prototype the BDEC layer
on top of the existing Loquat implementation (based on ProSec 2024).

## 1. Specification Extraction
- [x] Re-read BDEC section of the paper and extract the exact algorithms
      (Setup, Sign, Verify) and their data dependencies.
- [x] Identify additional commitments/challenges beyond Loquat (e.g., extra
      Merkle roots, polynomial relations, batched transcripts).
- [x] Note transcript symbols (σ₅, …, σ₅₊ᵣ, etc.) and ensure they don’t collide
      with existing Loquat labels.

## 2. API & Data Structures
- [x] Decide whether BDEC lives in the same crate (feature-gated) or a sibling
      module; document import paths.
- [x] Define minimal structs for BDEC proofs/signatures, wrapping `LoquatSignature`
      and adding BDEC-specific commitments.
- [x] Expose helper interfaces (`bdec_setup`, `bdec_prigen`, `bdec_nym_key`,
      `bdec_issue_credential`, `bdec_show_credential`) that call Loquat primitives
      under the hood.
- [ ] Document the expected transcript fields so Loquat can export any required
      intermediate data (e.g., Π rows, folding layers).

## 3. Implementation Milestones
- [x] BDEC setup: reuse Loquat public parameters; add extra parameters if BDEC
      requires them (e.g., batching limits).
- [x] BDEC signing:
  - [x] Run Loquat signing to obtain base signature and transcript data.
  - [x] Compute additional BDEC commitments (following the paper).
  - [x] Assemble the combined BDEC proof/signature structure.
- [x] BDEC verification:
  - [x] Re-run Loquat verification (or replay the transcript pieces) for base checks.
  - [x] Validate the BDEC-specific commitments and equations.
  - [x] Ensure Merkle paths/transcript updates follow the paper’s order.

## 4. Testing
- [x] Happy-path test: generate a BDEC signature and verify it.
- [x] Tamper tests: flip a BDEC commitment/challenge to confirm verification fails.
- [ ] Edge tests (optional for PoC): small batches, minimal rounds, etc.

## 5. Documentation
- [x] Add a short README/plan note describing how BDEC builds on Loquat, including
      transcript naming and the current hash-based proof placeholder.
- [ ] Update `docs/loquat_gap_analysis.md` once BDEC PoC is in place.
- [ ] Note any known limitations (e.g., random coset generation, field size) that
      remain in the PoC.

## 6. Nice-to-Have (Optional)
- [ ] Simple benchmarks to measure BDEC overhead vs pure Loquat.
- [ ] Serialization helpers if BDEC proof objects need to be persisted.
- [ ] Future work list (e.g., full subgroup generation, constant-time auditing).


---

## PoC Status Notes
- The PoC reuses Loquat signatures, adds pseudonym helpers, credential issuance,
  and selective disclosure. The zkSNARK proof from ProSec 2024 is temporarily
  modelled by a hash commitment; future work will plug in an actual proving
  system (e.g., Risc Zero or Circom) during benchmarking.
