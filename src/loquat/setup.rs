use super::errors::{LoquatError, LoquatResult};
use super::field_utils::{F, F2};
use rand::Rng;
use serde::{Deserialize, Serialize};

const MAX_GENERATOR_ATTEMPTS: usize = 1 << 16;
const FP2_TWO_ADIC_EXPONENT: usize = 128;
const FP2_ODD_COFACTOR: u128 = (1u128 << 126) - 1;

/// Public parameters for the Loquat signature scheme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatPublicParams {
    // General Parameters
    pub l: usize,
    pub b: usize,
    pub public_indices: Vec<F>,
    pub m: usize,
    pub n: usize,

    // Parameters for Univariate Sumcheck and LDT
    pub coset_h: Vec<F2>,
    pub coset_u: Vec<F2>,
    pub h_shift: F2,
    pub h_generator: F2,
    pub u_shift: F2,
    pub u_generator: F2,
    pub eta: usize,
    pub kappa: usize,
    pub rho_star: f64,
    pub rho_star_num: usize,
    pub rho_numerators: [usize; 4],
    pub r: usize,
    pub u_subgroups: Vec<Vec<F2>>,

    // Cryptographic Primitives
    pub hash_functions: Vec<HashFunctionDescriptor>,
    pub expand_domain: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashFunctionDescriptor {
    pub label: String,
    pub domain_separator: Vec<u8>,
}

impl std::fmt::Display for LoquatPublicParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Loquat Public Parameters:")?;
        writeln!(f, "  - Public Key Bits (L): {}", self.l)?;
        writeln!(f, "  - Challenge Symbols (B): {}", self.b)?;
        writeln!(f, "  - Degree Bound (m): {}", self.m)?;
        writeln!(f, "  - Parallel Executions (n): {}", self.n)?;
        writeln!(f, "  - Subgroup H size: {}", self.coset_h.len())?;
        writeln!(f, "  - Subgroup U size: {}", self.coset_u.len())?;
        writeln!(f, "  - H shift: {:?}", self.h_shift)?;
        writeln!(f, "  - U shift: {:?}", self.u_shift)?;
        writeln!(f, "  - LDT Localization (η): {}", self.eta)?;
        writeln!(f, "  - LDT Repetitions (κ): {}", self.kappa)?;
        writeln!(f, "  - LDT Rate (ρ*): {:.6}", self.rho_star)?;
        writeln!(f, "  - LDT Rate Numerator (ρ*_num): {}", self.rho_star_num)?;
        writeln!(f, "  - LDT Rounds (r): {}", self.r)?;
        writeln!(f, "  - Hash Functions: {} total", self.hash_functions.len())?;
        writeln!(
            f,
            "  - Public Indices: {} total",
            self.public_indices.len()
        )
    }
}

fn generate_hash_functions(count: usize) -> Vec<HashFunctionDescriptor> {
    (1..=count)
        .map(|i| {
            let label = if i == count {
                "H_RT".to_string()
            } else {
                format!("H_{}", i)
            };
            let domain_separator = format!("Loquat/{}", label).into_bytes();
            HashFunctionDescriptor { label, domain_separator }
        })
        .collect()
}

fn log2_pow2(value: usize) -> usize {
    debug_assert!(value.is_power_of_two());
    (usize::BITS - 1 - value.leading_zeros()) as usize
}

fn find_generator_for_power(power: usize, rng: &mut impl Rng) -> LoquatResult<F2> {
    if power == 0 {
        return Ok(F2::one());
    }
    if power > FP2_TWO_ADIC_EXPONENT {
        return Err(LoquatError::setup_error(
            "coset_generation",
            "requested power exceeds two-adic valuation of F_{p^2}*",
        ));
    }
    let reduction_steps = FP2_TWO_ADIC_EXPONENT
        .checked_sub(power)
        .ok_or_else(|| LoquatError::setup_error("coset_generation", "power too large"))?;

    for _ in 0..MAX_GENERATOR_ATTEMPTS {
        let base = F2::rand_nonzero(rng);
        let mut candidate = base.pow(FP2_ODD_COFACTOR);
        for _ in 0..reduction_steps {
            candidate = candidate * candidate;
        }
        if candidate == F2::one() {
            continue;
        }
        if candidate.pow_two(power) != F2::one() {
            continue;
        }
        if candidate.pow_two(power - 1) == F2::one() {
            continue;
        }
        return Ok(candidate);
    }

    Err(LoquatError::setup_error(
        "coset_generation",
        "failed to sample generator with desired power-of-two order",
    ))
}

fn generate_coset_elements(generator: F2, size: usize, shift: F2) -> Vec<F2> {
    let mut elements = Vec::with_capacity(size);
    let mut accumulator = F2::one();
    for _ in 0..size {
        elements.push(shift * accumulator);
        accumulator *= generator;
    }
    elements
}

fn build_power_of_two_coset(
    size: usize,
    rng: &mut impl Rng,
) -> LoquatResult<(Vec<F2>, F2, F2)> {
    if !size.is_power_of_two() {
        return Err(LoquatError::invalid_parameters(
            "coset size must be a power of two",
        ));
    }
    let power = size.trailing_zeros() as usize;
    let generator = find_generator_for_power(power, rng)?;
    let shift = F2::rand_nonzero(rng);
    let elements = generate_coset_elements(generator, size, shift);
    Ok((elements, generator, shift))
}

fn cosets_intersect(a: &[F2], b: &[F2]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x == y))
}

pub fn loquat_setup(lambda: usize) -> LoquatResult<LoquatPublicParams> {
    println!("\n================== ALGORITHM 2: LOQUAT SETUP ==================");
    println!("INPUT: Security Parameter λ = {}", lambda);

    let mut rng = rand::thread_rng();

    println!("\n--- STEP 2: Public Parameters for Legendre PRF ---");
    let l = match lambda {
        128 => 256,
        192 => 384,
        256 => 512,
        _ => return Err(LoquatError::invalid_parameters("Unsupported security level.")),
    };
    println!("✓ L (public key bits): {} (derived from λ={})", l, lambda);

    let b = l / 4;
    println!("✓ B (challenged residuosity symbols): {} (B ≤ L constraint satisfied)", b);

    let public_indices: Vec<F> = (0..l).map(|_| F::rand(&mut rng)).collect();
    println!("✓ I = {{I₁, ..., I_L}}: Generated {} random field elements from F_p", public_indices.len());

    let m = 16;
    let n = (b + m - 1) / m;
    println!("✓ m (degree bound): {} (power of 2 requirement satisfied)", m);
    println!("✓ n (parallel executions): {} (where m * n = {} ≥ B = {})", n, m * n, b);

    println!("\n--- STEP 3: Public Parameters for Univariate Sumcheck and LDT ---");

    let eta = 2;
    println!("✓ η (localization parameter): {}", eta);

    let kappa = match lambda {
        128 => 80,
        192 => 112,
        256 => 128,
        _ => 80,
    };
    println!("✓ κ (query repetition parameter): {}", kappa);

    let min_rate_denominator: usize = 4 * m + (kappa * (1 << eta));
    println!("✓ Minimum rate denominator: 4m + κ*2^η = {}", min_rate_denominator);

    let h_size = 2 * m;
    let (coset_h, generator_h, shift_h) = build_power_of_two_coset(h_size, &mut rng)?;
    println!("✓ |H| = {}", coset_h.len());

    let u_size = min_rate_denominator.next_power_of_two();
    let mut coset_u_attempts = 0usize;
    let (coset_u, generator_u, shift_u) = loop {
        let (candidate, gen, shift) = build_power_of_two_coset(u_size, &mut rng)?;
        coset_u_attempts += 1;
        if !cosets_intersect(&coset_h, &candidate) {
            break (candidate, gen, shift);
        }
        if coset_u_attempts > MAX_GENERATOR_ATTEMPTS {
            return Err(LoquatError::setup_error(
                "coset_generation",
                "failed to sample U disjoint from H",
            ));
        }
    };
    println!("✓ |U| = {} (next power of 2 ≥ {})", coset_u.len(), min_rate_denominator);

    let mut rho_star_value = 1usize;
    while rho_star_value * coset_u.len() <= min_rate_denominator {
        rho_star_value <<= 1;
    }
    let rho_star_num = rho_star_value * coset_u.len();
    let rho_star = rho_star_num as f64 / coset_u.len() as f64;

    let rho1_num = 2 * m + (kappa * (1 << eta)) + 1;
    let rho2_num = 4 * m + (kappa * (1 << eta));
    let rho3_num = 2 * m + (kappa * (1 << eta));
    let rho4_num = 2 * m - 1;
    let rho_numerators = [rho1_num, rho2_num, rho3_num, rho4_num];

    let log_u = log2_pow2(coset_u.len());
    let rho_star_log = if rho_star_value.is_power_of_two() {
        log2_pow2(rho_star_value)
    } else {
        ((rho_star_value as f64).log2().ceil()) as usize
    };
    let r = ((log_u + rho_star_log) / eta).max(1);
    println!("✓ ρ* = {} (power of two bound)", rho_star_value);
    println!("✓ r (LDT round complexity): {}", r);

    let mut u_subgroups = Vec::with_capacity(r);
    let mut current_size = coset_u.len();
    let mut current_shift = shift_u;
    let mut current_generator = generator_u;
    for round in 0..r {
        current_size = (current_size >> eta).max(1);
        current_shift = current_shift.pow_two(eta);
        current_generator = current_generator.pow_two(eta);
        let layer = generate_coset_elements(current_generator, current_size, current_shift);
        println!("  • U({}) size: {}", round + 1, layer.len());
        u_subgroups.push(layer);
    }

    let hash_count = 5 + r + 1;
    let hash_functions = generate_hash_functions(hash_count);
    let expand_domain = b"Loquat/Expand".to_vec();

    let params = LoquatPublicParams {
        l,
        b,
        public_indices,
        m,
        n,
        coset_h,
        coset_u,
        h_shift: shift_h,
        h_generator: generator_h,
        u_shift: shift_u,
        u_generator: generator_u,
        eta,
        kappa,
        rho_star,
        rho_star_num,
        rho_numerators,
        r,
        u_subgroups,
        hash_functions,
        expand_domain,
    };

    println!("\n--- STEP 5: Parameter Validation ---");
    validate_loquat_parameters(&params)?;
    println!("✓ All parameter constraints satisfied");

    println!("\n--- OUTPUT: L-pp Generated Successfully ---");
    Ok(params)
}

fn validate_loquat_parameters(params: &LoquatPublicParams) -> LoquatResult<()> {
    if params.b > params.l {
        return Err(LoquatError::invalid_parameters("B > L"));
    }
    if params.m * params.n < params.b {
        return Err(LoquatError::invalid_parameters("m*n < B"));
    }
    if !params.m.is_power_of_two() {
        return Err(LoquatError::invalid_parameters("m is not a power of 2"));
    }
    if params.coset_h.len() != 2 * params.m {
        return Err(LoquatError::invalid_parameters("|H| != 2m"));
    }
    if !params.coset_u.len().is_power_of_two() {
        return Err(LoquatError::invalid_parameters("|U| must be a power of two"));
    }
    if cosets_intersect(&params.coset_h, &params.coset_u) {
        return Err(LoquatError::invalid_parameters("H and U must be disjoint"));
    }
    if params.u_subgroups.len() != params.r {
        return Err(LoquatError::invalid_parameters("number of U layers must equal r"));
    }
    for &num in params.rho_numerators.iter() {
        if num > params.rho_star_num {
            return Err(LoquatError::invalid_parameters("ρ_i > ρ*"));
        }
    }
    if params.h_generator.pow(params.coset_h.len() as u128) != F2::one() {
        return Err(LoquatError::invalid_parameters("invalid H generator order"));
    }
    if params.coset_h.len() > 1 && params.h_generator.pow((params.coset_h.len() / 2) as u128) == F2::one() {
        return Err(LoquatError::invalid_parameters("H generator order too small"));
    }
    if params.u_generator.pow(params.coset_u.len() as u128) != F2::one() {
        return Err(LoquatError::invalid_parameters("invalid U generator order"));
    }
    let mut expected_len = params.coset_u.len();
    for (idx, layer) in params.u_subgroups.iter().enumerate() {
        expected_len = (expected_len >> params.eta).max(1);
        if layer.len() != expected_len {
            return Err(LoquatError::invalid_parameters(&format!(
                "unexpected size for U({}): expected {}, found {}",
                idx + 1,
                expected_len,
                layer.len()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_functions_generation() {
        let hashes = generate_hash_functions(4);
        assert_eq!(hashes.len(), 4);
        assert_eq!(hashes[0].label, "H_1");
        assert_eq!(hashes[3].label, "H_RT");
        assert_eq!(hashes[0].domain_separator, b"Loquat/H_1");
    }

    #[test]
    fn test_coset_generator_power() {
        let mut rng = rand::thread_rng();
        let size = 32;
        let (_coset, generator, _shift) = build_power_of_two_coset(size, &mut rng).unwrap();
        let power = size.trailing_zeros() as usize;
        assert_eq!(generator.pow_two(power), F2::one());
        if power > 0 {
            assert_ne!(generator.pow_two(power - 1), F2::one());
        }
    }

    #[test]
    fn test_loquat_setup_parameters() {
        let params = loquat_setup(128).expect("setup should succeed");
        assert_eq!(params.l, 256);
        assert_eq!(params.b, 64);
        assert!(params.m.is_power_of_two());
        assert_eq!(params.coset_h.len(), 2 * params.m);
        assert!(params.r >= 1);
        assert_eq!(params.u_subgroups.len(), params.r);
        assert_eq!(params.coset_h.first().copied().unwrap(), params.h_shift);
        assert_eq!(params.coset_u.first().copied().unwrap(), params.u_shift);
        assert_eq!(params.rho_numerators.len(), 4);
        assert!(params.rho_star_num >= params.rho_numerators[1]);
        assert!(validate_loquat_parameters(&params).is_ok());
    }

    #[test]
    fn test_invalid_security_level() {
        assert!(loquat_setup(100).is_err());
    }
}
