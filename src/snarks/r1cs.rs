use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::field_utils::{field_to_bytes, F};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::vec::Vec;

/// Describes a single R1CS constraint `<a, z> * <b, z> = <c, z>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1csConstraint {
    pub a: Vec<F>,
    pub b: Vec<F>,
    pub c: Vec<F>,
}

impl R1csConstraint {
    pub fn new(a: Vec<F>, b: Vec<F>, c: Vec<F>) -> Self {
        Self { a, b, c }
    }

    pub fn len(&self) -> usize {
        self.a.len()
    }

    pub fn evaluate(&self, assignment: &[F]) -> (F, F, F) {
        (
            inner_product(&self.a, assignment),
            inner_product(&self.b, assignment),
            inner_product(&self.c, assignment),
        )
    }

    pub fn support(&self) -> Vec<usize> {
        let mut indices = Vec::new();
        for (idx, coeff) in self.a.iter().enumerate() {
            if !coeff.is_zero() {
                indices.push(idx);
            }
        }
        for (idx, coeff) in self.b.iter().enumerate() {
            if !coeff.is_zero() {
                indices.push(idx);
            }
        }
        for (idx, coeff) in self.c.iter().enumerate() {
            if !coeff.is_zero() {
                indices.push(idx);
            }
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }
}

/// Public statement consisting of constraint system metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1csInstance {
    pub num_variables: usize,
    pub constraints: Vec<R1csConstraint>,
}

impl R1csInstance {
    pub fn new(num_variables: usize, constraints: Vec<R1csConstraint>) -> LoquatResult<Self> {
        if num_variables == 0 {
            return Err(LoquatError::invalid_parameters(
                "R1CS instances require at least one variable (the constant 1).",
            ));
        }
        for (idx, constraint) in constraints.iter().enumerate() {
            if constraint.len() != num_variables
                || constraint.b.len() != num_variables
                || constraint.c.len() != num_variables
            {
                return Err(LoquatError::invalid_parameters(&format!(
                    "constraint {} does not match num_variables",
                    idx
                )));
            }
        }
        Ok(Self {
            num_variables,
            constraints,
        })
    }

    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.num_variables.to_le_bytes());
        for constraint in &self.constraints {
            absorb_vector(&mut hasher, &constraint.a);
            absorb_vector(&mut hasher, &constraint.b);
            absorb_vector(&mut hasher, &constraint.c);
        }
        hasher.finalize().into()
    }
}

/// Private assignment (without the constant 1 slot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1csWitness {
    pub assignment: Vec<F>,
}

impl R1csWitness {
    pub fn new(assignment: Vec<F>) -> Self {
        Self { assignment }
    }

    pub fn validate(&self, instance: &R1csInstance) -> LoquatResult<()> {
        if instance.num_variables != self.assignment.len() + 1 {
            return Err(LoquatError::invalid_parameters(
                "witness length does not match instance",
            ));
        }
        Ok(())
    }

    pub fn full_assignment(&self) -> Vec<F> {
        let mut assignment = Vec::with_capacity(self.assignment.len() + 1);
        assignment.push(F::one());
        assignment.extend_from_slice(&self.assignment);
        assignment
    }
}

fn inner_product(lhs: &[F], rhs: &[F]) -> F {
    debug_assert_eq!(lhs.len(), rhs.len());
    let mut acc = F::zero();
    for (a, b) in lhs.iter().zip(rhs.iter()) {
        acc += *a * *b;
    }
    acc
}

fn absorb_vector(hasher: &mut Sha256, values: &[F]) {
    for value in values {
        hasher.update(field_to_bytes(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r1cs_roundtrip() {
        let constraint = R1csConstraint::new(
            vec![F::one(), F::one()],
            vec![F::one(), F::zero()],
            vec![F::zero(), F::one()],
        );
        let instance = R1csInstance::new(2, vec![constraint]).unwrap();
        let witness = R1csWitness::new(vec![F::one()]);
        witness.validate(&instance).unwrap();
        assert_eq!(instance.num_constraints(), 1);
        assert_eq!(instance.digest().len(), 32);
    }
}
