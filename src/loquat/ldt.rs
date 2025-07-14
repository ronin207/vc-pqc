use serde::{Serialize, Deserialize};
use super::field_utils::{F, F2};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDTProof {
    pub commitments: Vec<[u8; 32]>,
    pub openings: Vec<LDTOpening>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDTOpening {
    pub position: usize,
    pub codeword_eval: F2,
    pub opening_proof: Vec<F2>,
    pub auth_path: Vec<Vec<u8>>,
}
