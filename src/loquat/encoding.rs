use super::field_utils::{
    field2_to_bytes, field_to_bytes, serialize_field2_slice, serialize_field_slice, F, F2,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Serialize a matrix of field elements into a length-prefixed byte vector.
pub fn serialize_field_matrix(matrix: &[Vec<F>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(matrix.len() as u32).to_le_bytes());
    for row in matrix {
        out.extend_from_slice(&(row.len() as u32).to_le_bytes());
        out.extend_from_slice(&serialize_field_slice(row));
    }
    out
}

/// Serialize a matrix of F² elements into a length-prefixed byte vector.
pub fn serialize_field2_matrix(matrix: &[Vec<F2>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(matrix.len() as u32).to_le_bytes());
    for row in matrix {
        out.extend_from_slice(&(row.len() as u32).to_le_bytes());
        out.extend_from_slice(&serialize_field2_slice(row));
    }
    out
}

/// Serialize a vector of field elements into bytes with a length prefix.
pub fn serialize_field_vector(values: &[F]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    out.extend_from_slice(&serialize_field_slice(values));
    out
}

/// Serialize a vector of F² elements into bytes with a length prefix.
pub fn serialize_field2_vector(values: &[F2]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u32).to_le_bytes());
    out.extend_from_slice(&serialize_field2_slice(values));
    out
}

/// Convert each F² element into a fixed-length byte vector (32 bytes) for Merkle leaves.
pub fn serialize_field2_leaves(values: &[F2]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| field2_to_bytes(value).to_vec())
        .collect()
}

/// Convert each row of F² elements into a byte vector for Merkle leaves.
pub fn serialize_field2_matrix_leaves(matrix: &[Vec<F2>]) -> Vec<Vec<u8>> {
    matrix
        .iter()
        .map(|row| serialize_field2_slice(row))
        .collect()
}

/// Serialize a single F element into a `Vec<u8>`.
pub fn serialize_field(value: &F) -> Vec<u8> {
    field_to_bytes(value).to_vec()
}

/// Serialize a single F² element into a `Vec<u8>`.
pub fn serialize_field2(value: &F2) -> Vec<u8> {
    field2_to_bytes(value).to_vec()
}
