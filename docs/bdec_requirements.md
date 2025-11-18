# BDEC Requirements Trace

## Primary Sources
- `2024-868.pdf`: Defines the Loquat signature scheme, including algorithms for setup, key generation, signing, verification, and transcript structure required for SNARK-friendly proofs.
- `ProSec2024.pdf`: Presents the Blockchain-based Digital Education Credential (BDEC) framework, specifying participant roles, algorithms (`Setup`, `PriGen`, `NymKey`, `CreGen`, `CreVer`, `ShowCre`, `ShowVer`, `RevCre`), and security goals (unforgeability, anonymity, unlinkability, conditional linkability, revocation).

## Algorithm Requirements
1. **Setup (`parSetup`)**
   - Runs Loquat setup to obtain signature parameters (`Sig.pp`) and a zkSNARK CRS.
   - Outputs public parameters `par` and initial revocation list `LR = ∅`.

2. **User Key Generation (`PriGen`)**
   - Generates a long-term Loquat key pair `(sk_U, pk_U)` for each user.
   - Keys remain private unless revocation requires publishing `pk_U`.

3. **Pseudonym Keys (`NymKey`)**
   - User samples a random pseudonym public key `ppk_{U,TA}`.
   - Pseudonym secret key `psk_{U,TA}` is a signature of `ppk_{U,TA}` under `sk_U`:
     `psk_{U,TA} = Sig.Sign(sk_U, ppk_{U,TA})`.

4. **Credential Issuance (`CreGen`)**
   - User signs the hashed attribute list `h_{U,TA} = H(A)` to obtain credential signature `c_{U,TA}`.
   - Generates a zkSNARK proof `ĉ_{U,TA}` showing:
       1. `c_{U,TA}` verifies under `pk_U`.
       2. `psk_{U,TA}` verifies `ppk_{U,TA}` under `pk_U`.
   - Publishes `(c_{U,TA}, ĉ_{U,TA}, A, aux, ppk_{U,TA})`.

5. **Credential Verification (`CreVer`)**
   - Recomputes `h_{U,TA}` and verifies the zkSNARK proof for the two signature checks.

6. **Credential Showing (`ShowCre`)**
   - For a set of credentials `(c^{(j)}_{U,TA}, ppk^{(j)}_{U,TA})_{j=1..k}`, the user:
       1. Generates a pseudonym for the verifier `(ppk_{U,V}, psk_{U,V})`.
       2. Signs `h_{U,V} = H(A)` to obtain `c_{U,V}`.
       3. Produces zkSNARK proof `ĉ_{U,V}` attesting that every included pseudonym key and the verifier pseudonym verify under `pk_U`, and that `c_{U,V}` validates `h_{U,V}`.

7. **Show Verification (`ShowVer`)**
   - Checks the zkSNARK proof for all embedded signature verifications and the disclosed attribute hash.

8. **Revocation (`RevCre`)**
   - On compromise, user publishes `pk_U` to `LR`.
   - Verifiers reject submissions when any credential signature verifies under a revoked `pk_U`.

## Security Targets
- **Unforgeability:** Relies on EUF-CMA security of Loquat and knowledge soundness of the zkSNARK.
- **Anonymity & Unlinkability:** Follow from pseudonym randomness and zero-knowledge of both signature scheme and zkSNARK.
- **Conditional Linkability:** Achieved by proving multiple pseudonym keys originate from the same `sk_U`.
- **Revocation:** Requires verifiers to cross-check credential signatures against the revocation list.

## Implementation Implications
- Loquat APIs must expose signing/verification for arbitrary messages to support pseudonym keys and attribute hashes.
- BDEC data structures need to track:
  - Long-term keys (`pk_U`)
  - Pseudonym signatures
  - Credential signatures and attribute hashes
  - Proof artifacts (hash-placeholder today; zkSNARK in future RISC Zero integration)
- Host logic must enforce signature checks and revocation before delegating to the zkVM proof placeholder.

These notes serve as the requirements reference for aligning the Rust implementation with the academic specification.
