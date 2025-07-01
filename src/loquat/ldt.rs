use serde::{Serialize, Deserialize};
use super::field_utils::F;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDTProof {
    pub commitments: Vec<[u8; 32]>,
    pub openings: Vec<LDTOpening>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDTOpening {
    pub position: usize,
    #[serde(with = "super::ark_serde")]
    pub codeword_eval: F,
    #[serde(with = "super::ark_serde::vec")]
    pub opening_proof: Vec<F>,
    pub auth_path: Vec<Vec<u8>>,
}
