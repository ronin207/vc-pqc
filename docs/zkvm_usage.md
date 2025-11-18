# zkVM Host Workflow Notes

- Run the host demo from the repository root:  
  `RISC0_DEV_MODE=1 cargo run -p host --manifest-path zkvm/Cargo.toml`
- Toggle verbose Loquat tracing with `RUST_LOG` (default hides it):  
  `RUST_LOG=loquat=debug` restores the full algorithm transcript.
- The host now sets up Alice’s issuer key pair, issues credential `C₁ = (Mynum, H(S₁), σ)`, and samples Bob’s private values `(Mynum, S₁, S₂)` before launching the zkVM.
- Public inputs to the zkVM: Loquat params, issuer public key, and the target hash `T = H(H(Mynum, S₁), S₂)` that Cathy expects.
- Private witness bundled for the guest: the credential components plus Bob’s secrets `(Mynum, S₁, S₂)` and (optionally) Alice’s signing key for consistency checks.
- Inside the zkVM, the guest re-hashes `S₁`, validates the Loquat signature over `Mynum || H(S₁)`, recomputes `H(H(Mynum, S₁), S₂)`, and verifies it matches the public `T`.
- Receipt verification still succeeds once the guest accepts the credential and nested hash relation (omit `RISC0_DEV_MODE` for production receipts).
- Debug logging (`loquat=debug`, `host=info`) only emits Boolean flags and aggregate counters; no raw witness data or attribute values are written to the journal or logs, keeping selective-disclosure proofs zero-knowledge by default.
