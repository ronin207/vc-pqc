//! Merkle Tree Implementation for Loquat
//
// This module provides a Merkle tree implementation for use in the LDT phase
// of the Loquat signature scheme.

use sha2::{Sha256, Digest};

/// A Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<Vec<u8>>,
    leaf_count: usize,
}

impl MerkleTree {
    /// Create a new Merkle tree from a set of leaves.
    pub fn new<T: AsRef<[u8]>>(leaves: &[T]) -> Self {
        let leaf_count = leaves.len();
        if leaf_count == 0 {
            return Self { nodes: vec![], leaf_count: 0 };
        }
        let mut nodes = vec![vec![0u8; 32]; 2 * leaf_count];

        // Copy leaves into the tree
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[leaf_count + i] = Sha256::digest(leaf.as_ref()).to_vec();
        }

        // Build the tree from the leaves up
        for i in (1..leaf_count).rev() {
            let mut hasher = Sha256::new();
            hasher.update(&nodes[2 * i]);
            hasher.update(&nodes[2 * i + 1]);
            nodes[i] = hasher.finalize().to_vec();
        }
        
        Self { nodes, leaf_count }
    }

    /// Get the root of the tree.
    pub fn root(&self) -> Option<Vec<u8>> {
        if self.nodes.is_empty() {
            None
        } else {
            Some(self.nodes[1].clone())
        }
    }

    /// Generate an authentication path for a leaf.
    pub fn generate_auth_path(&self, leaf_index: usize) -> Vec<Vec<u8>> {
        if leaf_index >= self.leaf_count {
            return vec![];
        }
        let mut path = Vec::new();
        let mut current_index = leaf_index + self.leaf_count;

        while current_index > 1 {
            let sibling_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
            path.push(self.nodes[sibling_index].clone());
            current_index /= 2;
        }

        path
    }

    /// Verify an authentication path.
    pub fn verify_auth_path<T: AsRef<[u8]>>(root: &[u8], leaf: T, leaf_index: usize, path: &[Vec<u8>]) -> bool {
        let mut current_hash = Sha256::digest(leaf.as_ref()).to_vec();
        let mut current_index_in_level = leaf_index;

        for sibling_hash in path {
            let mut hasher = Sha256::new();
            if current_index_in_level % 2 == 0 {
                hasher.update(&current_hash);
                hasher.update(sibling_hash);
            } else {
                hasher.update(sibling_hash);
                hasher.update(&current_hash);
            }
            current_hash = hasher.finalize().to_vec();
            current_index_in_level /= 2;
        }

        current_hash == root
    }
}