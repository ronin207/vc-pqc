# Loquat Specification Requirements (from 2024-868.pdf)

This document condenses the mandatory requirements for Algorithms 2–7 to guide
implementation work.

## Algorithm 2 – Loquat Setup
- **Finite fields**: choose prime field \( \mathbb{F}_p \) with large prime \( p \) and
  extension field \( \mathbb{F} = \mathbb{F}_{p^2} \) containing smooth multiplicative
  cosets.
- **Parameters**:
  - \( L \in \mathbb{N} \): number of Legendre PRF outputs in the public key.
  - \( B \leq L \): number of challenged residuosity symbols.
  - \( I = \{I_1,\ldots,I_L\} \subset \mathbb{F}_p \) sampled uniformly.
  - \( m \) (power of two) and \( n \) with \( m \cdot n = B \).
  - \( H \subset \mathbb{F} \) multiplicative coset of size \( 2m \).
  - \( \eta \): localization parameter (positive integer).
  - \( \kappa \): query repetition parameter.
  - \( U \subset \mathbb{F} \) smooth multiplicative coset disjoint from \( H \) with
    \( |U| > |H| \).
  - \( \rho^\* \) chosen as the closest power of two greater than
    \( \frac{4m + \kappa \cdot 2^\eta}{|U|} \).
  - \( r = \left\lfloor \frac{\log_2 |U| - \log_2(1/\rho^\*)}{\eta} \right\rfloor \):
    round complexity of the LDT.
  - Coset ladder \( U^{(0)} = U, U^{(i)} = \{ x^{2^\eta} \mid x \in U^{(i-1)} \} \) for
    \( i \in [1, r] \).
- **Hash functions**: instantiate \( H_1,\ldots,H_{5+r}, H_{MT} \) as distinct
  collision-resistant hashes; define `Expand` as an oracle from \( \mathbb{F} \) to the
  required product sets.
- **Output**: public parameters \( L\text{-pp} = ( \mathbb{F}_p, \mathbb{F}, p, L, B, I,
  m, n, H, U, (U^{(i)})_{i\in[r]}, \rho^\*, r, \kappa, \eta, (H_i)_{i\in[5+r]}, H_{MT},
  \text{Expand}) \).

## Algorithm 3 – Key Generation
- Sample \( K \gets \mathbb{F}_p^\* \setminus \{-I_1,\ldots,-I_L\} \).
- Compute public key \( \text{pk} = (L_K(I_1),\ldots,L_K(I_L)) \) where
  \( L_K(a) = L_0(K+a) \), \( L_0 \) is the Legendre PRF bit.
- Output \( (sk = K, pk) \).

## Algorithm 4 – Loquat Sign (Part I)
### Phase 1 (Commit to secret key and randomness)
- For each \( j \in [n] \):
  - Sample \( r_{1,j},\ldots,r_{m,j} \gets \mathbb{F}_p^\* \).
  - Compute \( T_{i,j} = L_0(r_{i,j}) \).
  - Form vector \( c_j = (K r_{1,j}, r_{1,j}, \ldots, K r_{m,j}, r_{m,j}) \in \mathbb{F}_p^{2m} \)
    and lift to \( \mathbb{F}^{2m} \).
  - Interpolate \( \hat{c}_j(x) \) over \( H \).
  - Sample blinding polynomial \( \hat{r}(x) \) of degree \( \kappa \cdot 2^\eta \).
  - Compute masked polynomial \( \hat{c}'_j(x) = \hat{c}_j(x) + Z_H(x)\,\hat{r}(x) \) with
    degree \( < 2m + \kappa 2^\eta \).
- For each \( e \in [|U|] \), compute leaf
  \( \text{leaf}_e = H_c(\hat{c}'_1(U[e]),\ldots,\hat{c}'_n(U[e])) \).
- Commit using Merkle tree to obtain \( \text{root}_c \).
- Set \( \sigma_1 = (\text{root}_c, (T_{i,j})_{i,j}) \).

### Phase 2 (Compute residuosity symbols)
- Derive \( h_1 = H_1(\sigma_1, M) \); expand to indices \( I_{i,j} \in I \).
- For each \( (i,j) \), compute \( o_{i,j} = (K + I_{i,j}) r_{i,j} \).
- Set \( \sigma_2 = (o_{i,j})_{i,j} \).

### Phase 3 (Witness for univariate sumcheck)
- Derive \( h_2 = H_2(\sigma_2, h_1) \); expand to \( (\lambda_{i,j})_{i,j} \in \mathbb{F}_p \)
  and \( (\epsilon_j)_{j\in[n]} \in \mathbb{F} \).
- For each \( j \):
  - Form \( q_j = (\lambda_{1,j}, \lambda_{1,j} I_{1,j}, \ldots, \lambda_{m,j}, \lambda_{m,j} I_{m,j}) \)
    and lift to \( \mathbb{F}^{2m} \).
  - Interpolate \( \hat{q}_j(x) \) over \( H \).
  - Compute \( \hat{f}_j(x) = \hat{c}'_j(x) \cdot \hat{q}_j(x) \).
- Define \( \hat{f}(x) = \sum_{j=1}^n \epsilon_j \hat{f}_j(x) \) (degree < \( 4m + \kappa 2^\eta \)).
- Compute claimed sum \( \mu = \sum_{j=1}^n \epsilon_j \sum_{i=1}^m \lambda_{i,j} o_{i,j} \).
- Execute zero-knowledge univariate sumcheck on \((F, U, H, 4m + \kappa 2^\eta, \mu, \hat{f}(x))\)
  obtaining partial signature \( \pi_{\text{US}} \).

## Algorithm 5 – Loquat Sign (Part II)
- Sample masking polynomial \( \hat{s}(x) \) of degree \( 4m + \kappa 2^\eta - 1 \),
  compute \( S = \sum_{a \in H} \hat{s}(a) \), and commit to \( \hat{s}|_U \) obtaining
  \( \text{root}_s \).
- Derive \( h_3 = H_3(\sigma_3, h_2) \); expand to vector \( z \).
- Form \( \hat{f}'(x) = z \cdot \hat{f}(x) + \hat{s}(x) \).
- Split \( \hat{f}'(x) = \hat{g}(x) + Z_H(x)\hat{h}(x) \) with degree bounds in the paper.
- Commit to \( \hat{h}|_U \) obtaining \( \text{root}_h \).
- Derive \( h_4 = H_4(\sigma_4, h_3) \); expand to \( e \in \mathbb{F}^8 \).
- Build stacked code matrix \( \Pi \) by vertically stacking
  \( \hat{c}'|_U, \hat{s}|_U, \hat{h}|_U, \hat{p}|_U \) and applying rate-adjustment exponents.
- Compute \( f^{(0)} = e^\top \cdot \Pi \in \text{RS}[U, \rho^\*] \).

## Algorithm 6 – Loquat Sign (Part III)
- Initialize \( \hat{f}^{(0)} = f^{(0)} \); perform folding rounds indexed by \( i \in [0, r) \):
  - Commit to \( f^{(i)} \) with Merkle root \( \text{root}_{f^{(i)}} \).
  - Derive challenges \( h_{5+i} \), expand to \( x^{(i)} \in \mathbb{F} \).
  - For each \( y \in U^{(i+1)} \), interpolate \( \hat{P}^{(i)}_y \) on the coset \( S^{(i)}_y \)
    and append evaluations at \( x^{(i)} \) to form \( f^{(i+1)} \).
- After \( r \) rounds, interpolate \( \hat{f}^{(r)} \), commit to its first coefficients, and
  derive query sets \( (S_1,\ldots,S_\kappa) \subset U \) via \( h_{5+r} \).
- Sample the Merkle openings for all queried leaves in
  \( \text{root}_c, \text{root}_s, \text{root}_h, \text{root}_{f^{(i)}} \) and bundle them into
  \( \pi_{\text{LDT}} \). Return coefficients of \( \hat{f}^{(r)} \) as mandated.

## Algorithm 7 – Loquat Verify
1. Recompute transcript challenges \( h_1,\ldots,h_{5+r} \) from the provided Merkle roots,
   plaintext components, and message \( M \).
2. Reconstruct polynomials \( \hat{c}'_j, \hat{s}, \hat{h}, \hat{f}, \hat{p}, f^{(i)} \) at the queried
   locations; verify that they satisfy the algebraic relations defined in Algorithms 4–6.
3. Check Legendre constraints: for every \( (i,j) \), ensure \( o_{i,j} \neq 0 \) and
   \( L_0(o_{i,j}) = pk_{I_{i,j}} + T_{i,j} \).
4. Verify all Merkle authentication paths.
5. Validate the univariate sumcheck proof \( \pi_{\text{US}} \).
6. Run the LDT consistency checks across all folded layers using the revealed queries and
   coefficients.
7. Accept if every check passes; otherwise reject.

---

This distilled checklist should remain synchronized with the implementation.
