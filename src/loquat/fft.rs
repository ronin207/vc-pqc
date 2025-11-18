use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{F, F2};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

fn ensure_power_of_two(len: usize) -> LoquatResult<()> {
    if len == 0 {
        return Err(LoquatError::invalid_parameters("FFT length must be > 0"));
    }
    if !len.is_power_of_two() {
        return Err(LoquatError::invalid_parameters(
            "FFT length must be a power of two",
        ));
    }
    Ok(())
}

fn validate_generator(root: F2, domain_size: usize) -> LoquatResult<()> {
    let n = domain_size as u128;
    if root.pow(n) != F2::one() {
        return Err(LoquatError::invalid_parameters("root^n != 1 in FFT domain"));
    }
    if domain_size > 1 && root.pow(n / 2) == F2::one() {
        return Err(LoquatError::invalid_parameters(
            "root does not have full order for FFT domain",
        ));
    }
    Ok(())
}

fn bit_reverse_permutation(values: &mut [F2]) {
    let n = values.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
}

fn pow_usize(base: F2, exp: usize) -> F2 {
    base.pow(exp as u128)
}

pub fn fft_in_place(values: &mut [F2], root: F2) -> LoquatResult<()> {
    ensure_power_of_two(values.len())?;
    validate_generator(root, values.len())?;

    bit_reverse_permutation(values);

    let n = values.len();
    let mut len = 2;
    while len <= n {
        let step = n / len;
        let w_len = pow_usize(root, step);
        for i in (0..n).step_by(len) {
            let mut w = F2::one();
            let half = len / 2;
            for j in 0..half {
                let u = values[i + j];
                let t = values[i + j + half] * w;
                values[i + j] = u + t;
                values[i + j + half] = u - t;
                w *= w_len;
            }
        }
        len <<= 1;
    }
    Ok(())
}

pub fn ifft_in_place(values: &mut [F2], root: F2) -> LoquatResult<()> {
    ensure_power_of_two(values.len())?;
    let inv_root = root
        .inverse()
        .ok_or_else(|| LoquatError::invalid_parameters("FFT root has no inverse"))?;
    fft_in_place(values, inv_root)?;

    let n = values.len() as u128;
    let inv_n_scalar = F::new(n)
        .inverse()
        .ok_or_else(|| LoquatError::invalid_parameters("invalid FFT scale factor"))?;
    let inv_n = F2::new(inv_n_scalar, F::zero());
    for value in values.iter_mut() {
        *value *= inv_n;
    }
    Ok(())
}

pub fn evaluate_on_coset(coeffs: &[F2], shift: F2, generator: F2) -> LoquatResult<Vec<F2>> {
    if coeffs.is_empty() {
        return Ok(Vec::new());
    }
    ensure_power_of_two(coeffs.len())?;
    validate_generator(generator, coeffs.len())?;

    let mut scaled_coeffs = coeffs.to_vec();
    let mut shift_power = F2::one();
    for coeff in scaled_coeffs.iter_mut() {
        *coeff *= shift_power;
        shift_power *= shift;
    }
    fft_in_place(&mut scaled_coeffs, generator)?;
    Ok(scaled_coeffs)
}

pub fn interpolate_on_coset(evaluations: &[F2], shift: F2, generator: F2) -> LoquatResult<Vec<F2>> {
    if evaluations.is_empty() {
        return Ok(Vec::new());
    }
    ensure_power_of_two(evaluations.len())?;
    validate_generator(generator, evaluations.len())?;
    let shift_inv = shift
        .inverse()
        .ok_or_else(|| LoquatError::invalid_parameters("coset shift must be non-zero"))?;

    let mut spectrum = evaluations.to_vec();
    ifft_in_place(&mut spectrum, generator)?;

    let mut coeffs = Vec::with_capacity(spectrum.len());
    let mut power = F2::one();
    for val in spectrum.into_iter() {
        coeffs.push(val * power);
        power *= shift_inv;
    }
    Ok(coeffs)
}

pub fn coset_shift_generator(coset: &[F2]) -> LoquatResult<(F2, F2)> {
    if coset.is_empty() {
        return Err(LoquatError::invalid_parameters("coset must be non-empty"));
    }
    let shift = coset[0];
    if coset.len() == 1 {
        return Ok((shift, F2::one()));
    }
    let inv_shift = shift
        .inverse()
        .ok_or_else(|| LoquatError::invalid_parameters("coset shift must be non-zero"))?;
    let generator = coset[1] * inv_shift;
    if shift * generator != coset[1] {
        return Err(LoquatError::invalid_parameters(
            "coset elements do not form geometric progression",
        ));
    }
    Ok((shift, generator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loquat::field_p127::Fp2;
    use crate::loquat::loquat_setup;
    use rand::{rngs::StdRng, SeedableRng};

    fn derive_coset_parameters(coset: &[F2]) -> (F2, F2) {
        let shift = coset[0];
        let generator = if coset.len() > 1 {
            let inv_shift = shift.inverse().expect("shift should be invertible");
            coset[1] * inv_shift
        } else {
            F2::one()
        };
        (shift, generator)
    }

    fn naive_evaluate(coeffs: &[F2], point: F2) -> F2 {
        let mut acc = F2::zero();
        for coeff in coeffs.iter().rev() {
            acc *= point;
            acc += *coeff;
        }
        acc
    }

    #[test]
    fn test_fft_matches_naive_evaluations() {
        let params = loquat_setup(128).expect("setup should succeed");
        let coset = &params.coset_h;
        let (shift, generator) = derive_coset_parameters(coset);

        let mut rng = StdRng::seed_from_u64(42);
        let coeffs: Vec<F2> = (0..coset.len()).map(|_| Fp2::rand(&mut rng)).collect();

        let fft_evals = evaluate_on_coset(&coeffs, shift, generator).expect("fft eval succeeds");
        for (point, value) in coset.iter().zip(fft_evals.iter()) {
            let expected = naive_evaluate(&coeffs, *point);
            assert_eq!(*value, expected);
        }
    }

    #[test]
    fn test_fft_ifft_roundtrip() {
        let params = loquat_setup(128).expect("setup should succeed");
        let coset = &params.coset_h;
        let (shift, generator) = derive_coset_parameters(coset);

        let mut rng = StdRng::seed_from_u64(7);
        let coeffs: Vec<F2> = (0..coset.len()).map(|_| Fp2::rand(&mut rng)).collect();

        let values = evaluate_on_coset(&coeffs, shift, generator).expect("forward fft");
        let recovered = interpolate_on_coset(&values, shift, generator).expect("inverse fft");
        assert_eq!(coeffs, recovered);
    }

    #[test]
    fn test_fft_constant_polynomial() {
        let params = loquat_setup(128).expect("setup should succeed");
        let coset = &params.coset_h;
        let (shift, generator) = derive_coset_parameters(coset);

        let constant = F2::new(F::one(), F::zero());
        let mut coeffs = vec![F2::zero(); coset.len()];
        coeffs[0] = constant;
        let values = evaluate_on_coset(&coeffs, shift, generator).expect("fft");
        for v in values {
            assert_eq!(v, constant);
        }
    }
}
