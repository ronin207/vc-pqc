# Current Implementation vs. Specification

The table below aligns critical requirements from Algorithms 2–7 (see
`docs/loquat_requirements.md`) with the present codebase status.

| Spec Component | Expected Behaviour | Current Code Location | Status / Gap |
| --- | --- | --- | --- |
| **Algorithm 2**: coset construction | Build multiplicative cosets \(H, U\), ladder \(U^{(i)}\) using roots-of-unity structure and ensure disjointness | `src/loquat/setup.rs` | Random `F2::rand` samples (lines 117-125) break coset structure; \( \rho^\*, r \) computed from floats, not from actual subgroup sizes; hash functions recorded as strings without instantiation |
| Legendre indices | Sample \(I_\ell\) uniformly and enforce \(m\cdot n = B\) | `setup.rs` lines 83-93 | Uses `F::rand` without rejection for zero; `m` hard-coded 16, no security-level tuning; `n` computed via ceiling but not checked against power-of-two constraints |
| Hash/Expand oracles | Provide concrete hash functions \(H_1,\ldots,H_{5+r}, H_{MT}\) and `Expand` mapping | `setup.rs` lines 126-134 | Placeholder string list; no binding to actual hash implementations |
| **Algorithm 3**: secret key sampling | Draw \(K\) uniformly from \( \mathbb{F}_p^\* \setminus \{-I_\ell\} \) | `src/loquat/keygen.rs` lines 33-87 | Uses `F::rand` (includes zero) with rejection, but Legendre PRF secrets logged to stdout; must guarantee uniformity under modulo reduction |
| Public key computation | Evaluate Legendre PRF with masked inputs | `keygen.rs` lines 88-123 | Utilizes `legendre_prf_secure`, but no guarantee that field arithmetic is constant-time; debug prints expose secret key samples |
| **Algorithm 4 Phase 1** | Interpolate \( \hat{c}_j \) on \(H\), mask with \(Z_H\hat{r}\), commit | `src/loquat/sign.rs` lines 78-142 | ✅ Implemented via FFT: ĉ and ĉ′ built on real cosets; non-zero randomness enforced; Merkle leaves bind masked codewords |
| Phase 2 | Expand to indices \( I_{i,j} \), compute \(o_{i,j}\) | `sign.rs` lines 200-204 | ✅ Uses SHA-256 derived indices; randomness sampled in \( \mathbb{F}_p^\* \) |
| Phase 3 | Build \( \hat{q}_j, \hat{f}_j, \hat{f} \); run ZK sumcheck | `sign.rs` lines 220-283 | ✅ FFT-based interpolation/evaluation links witness polynomials to commitments |
| **Algorithm 5** | Sample \( \hat{s}, z, \hat{h}, \hat{p}, \Pi, f^{(0)} \), commit to \( \text{root}_s, \text{root}_h \) | `sign.rs` | ✅ Π and f^(0) computed; full FRI folding/verification implemented |
| **Algorithm 6** | Execute folding (FRI-style), record \( \text{root}_{f^{(i)}} \), gather open paths | `sign.rs::ldt_protocol` | ✅ Folding uses Π-based f^(0), Merkle roots & row chunks verified |
| **Algorithm 7** | Recompute challenges, polynomials, verify Merkle paths, sumcheck, LDT | `src/loquat/verify.rs` | ✅ Reconstructs Π, f^(0), folding layers, confirms Merkle paths and algebraic checks |

This mapping should be kept in sync as implementation progresses.
