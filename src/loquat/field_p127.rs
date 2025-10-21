//! Custom Field Implementation for p = 2^127 - 1

use std::ops::{Add, Sub, Mul, Div, Neg, AddAssign, SubAssign, MulAssign};
use std::fmt;
use std::iter::Sum;
use rand::Rng;
use serde::{Serialize, Deserialize, Serializer, Deserializer};

// The prime modulus p = 2^127 - 1
const MODULUS: u128 = (1 << 127) - 1;

/// Represents an element in the prime field F_p where p = 2^127 - 1.
#[derive(Copy, Clone, PartialEq, Eq, Default, Hash)] // ADDED Hash
pub struct Fp127(pub u128);

// --- Core Field Arithmetic ---

impl Add for Fp127 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (sum, carry) = self.0.overflowing_add(rhs.0);
        let result = if carry { sum.wrapping_add(1) } else { sum };
        if result >= MODULUS { Self(result - MODULUS) } else { Self(result) }
    }
}

impl Sub for Fp127 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (res, borrow) = self.0.overflowing_sub(rhs.0);
        if borrow { Self(res.wrapping_add(MODULUS)) } else { Self(res) }
    }
}

impl Mul for Fp127 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        // Stable 128-bit multiplication
        let a = self.0;
        let b = rhs.0;
        let a_lo = a as u64 as u128;
        let a_hi = a >> 64;
        let b_lo = b as u64 as u128;
        let b_hi = b >> 64;

        let p0 = a_lo * b_lo;
        let p1 = a_lo * b_hi;
        let p2 = a_hi * b_lo;
        let p3 = a_hi * b_hi;

        let p1_lo = p1 as u64 as u128;
        let p1_hi = p1 >> 64;
        let p2_lo = p2 as u64 as u128;
        let p2_hi = p2 >> 64;

        let middle = p1_lo + p2_lo + (p0 >> 64);
        let lo = (middle << 64) | (p0 & u64::MAX as u128);
        let hi = p3 + p1_hi + p2_hi + (middle >> 64);

        // Fast reduction for p = 2^127 - 1
        let result = (hi << 1) + (hi >> 127) + (lo >> 127) + (lo & MODULUS);
        Self(result % MODULUS)
    }
}

impl Div for Fp127 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self { self * rhs.inverse().expect("Division by zero") }
}

impl Neg for Fp127 {
    type Output = Self;
    fn neg(self) -> Self { if self.0 == 0 { self } else { Self(MODULUS - self.0) } }
}

impl AddAssign for Fp127 { fn add_assign(&mut self, rhs: Self) { *self = *self + rhs; } }
impl SubAssign for Fp127 { fn sub_assign(&mut self, rhs: Self) { *self = *self - rhs; } }
impl MulAssign for Fp127 { fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; } }

impl Fp127 {
    pub fn new(val: u128) -> Self { Self(val % MODULUS) }
    pub fn zero() -> Self { Self(0) }
    pub fn one() -> Self { Self(1) }
    pub fn is_zero(&self) -> bool { self.0 == 0 }

    pub fn pow(self, exp: u128) -> Self {
        let mut res = Self::one();
        let mut base = self;
        let mut e = exp;
        while e > 0 {
            if e % 2 == 1 { res *= base; }
            base *= base;
            e /= 2;
        }
        res
    }

    pub fn inverse(self) -> Option<Self> {
        if self.is_zero() { return None; }
        Some(self.pow(MODULUS - 2))
    }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        loop {
            let candidate = rng.gen::<u128>() & ((1u128 << 127) - 1);
            if candidate < MODULUS {
                return Self(candidate);
            }
        }
    }

    pub fn rand_nonzero<R: Rng>(rng: &mut R) -> Self {
        loop {
            let value = Self::rand(rng);
            if !value.is_zero() {
                return value;
            }
        }
    }
}

impl fmt::Debug for Fp127 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Fp127(0x{:x})", self.0) }
}

impl Serialize for Fp127 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0.to_le_bytes())
    }
}

impl<'de> Deserialize<'de> for Fp127 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"16 bytes"));
        }
        let val = u128::from_le_bytes(bytes.try_into().unwrap());
        Ok(Fp127::new(val))
    }
}

// --- Extension Field Fp2 ---
lazy_static::lazy_static! {
    static ref QNR: Fp127 = Fp127::new(3);
}

#[derive(Copy, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Fp2 {
    pub c0: Fp127,
    pub c1: Fp127,
}

impl Fp2 {
    pub fn new(c0: Fp127, c1: Fp127) -> Self { Self { c0, c1 } }
    pub fn zero() -> Self { Self::new(Fp127::zero(), Fp127::zero()) }
    pub fn one() -> Self { Self::new(Fp127::one(), Fp127::zero()) }
    pub fn is_zero(&self) -> bool { self.c0.is_zero() && self.c1.is_zero() }

    pub fn rand<R: Rng>(rng: &mut R) -> Self {
        Self::new(Fp127::rand(rng), Fp127::rand(rng))
    }

    pub fn rand_nonzero<R: Rng>(rng: &mut R) -> Self {
        loop {
            let candidate = Self::rand(rng);
            if !candidate.is_zero() {
                return candidate;
            }
        }
    }

    pub fn inverse(self) -> Option<Self> {
        if self.is_zero() { return None; }
        let denominator = self.c0*self.c0 - self.c1*self.c1 * *QNR;
        let inv_denom = denominator.inverse()?;
        Some(Self::new(self.c0 * inv_denom, -self.c1 * inv_denom))
    }

    pub fn pow_two(self, exponent: usize) -> Self {
        let mut result = self;
        for _ in 0..exponent {
            result *= result;
        }
        result
    }

    pub fn pow(self, mut exp: u128) -> Self {
        let mut result = Self::one();
        let mut base = self;
        while exp > 0 {
            if exp & 1 == 1 {
                result *= base;
            }
            base *= base;
            exp >>= 1;
        }
        result
    }
}

impl Add for Fp2 { 
    type Output = Self;
    fn add(self, rhs: Self) -> Self { Self::new(self.c0 + rhs.c0, self.c1 + rhs.c1) }
}

impl Sub for Fp2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self { Self::new(self.c0 - rhs.c0, self.c1 - rhs.c1) }
}

impl Mul for Fp2 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let ac = self.c0 * rhs.c0;
        let bd = self.c1 * rhs.c1;
        let ad_plus_bc = (self.c0 + self.c1) * (rhs.c0 + rhs.c1) - ac - bd;
        Self::new(ac + bd * *QNR, ad_plus_bc)
    }
}

impl Neg for Fp2 {
    type Output = Self;
    fn neg(self) -> Self { Self::new(-self.c0, -self.c1) }
}

impl AddAssign for Fp2 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Fp2 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for Fp2 {
    fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; }
}

impl Sum for Fp2 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + b)
    }
}

impl<'a> Sum<&'a Fp2> for Fp2 {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), |a, b| a + *b)
    }
}

impl fmt::Debug for Fp2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Fp2({:?}, {:?})", self.c0, self.c1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp127_rand_nonzero() {
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let sample = Fp127::rand_nonzero(&mut rng);
            assert!(!sample.is_zero());
        }
    }

    #[test]
    fn test_fp2_pow_two_matches_squaring() {
        let mut rng = rand::thread_rng();
        let sample = Fp2::rand_nonzero(&mut rng);
        let squared = sample * sample;
        assert_eq!(sample.pow_two(1), squared);
        assert_eq!(sample.pow_two(2), squared * squared);
    }
}
