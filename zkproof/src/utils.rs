// ============================================
// utils.rs — ZK Proof Utilities
// ============================================

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_two(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn hash_u64(value: u64) -> [u8; 32] {
    hash_bytes(&value.to_le_bytes())
}

pub fn hash_field_elements(elements: &[u64]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for elem in elements {
        hasher.update(elem.to_le_bytes());
    }
    hasher.finalize().into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub nodes: Vec<[u8; 32]>,
    pub depth: usize,
}

impl MerkleTree {
    pub fn new(leaf_values: &[u64]) -> Self {
        assert!(!leaf_values.is_empty(), "MerkleTree: no leaves");

        let leaves: Vec<[u8; 32]> = leaf_values
            .iter()
            .map(|&v| hash_u64(v))
            .collect();

        let depth = (leaves.len() as f64).log2().ceil() as usize;
        let mut nodes = leaves.clone();

        let target_size = 1 << depth;
        while nodes.len() < target_size {
            nodes.push([0u8; 32]);
        }

        let mut level = nodes.clone();
        let mut all_nodes = level.clone();

        while level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..level.len()).step_by(2) {
                let left = &level[i];
                let right = if i + 1 < level.len() {
                    &level[i + 1]
                } else {
                    &level[i]
                };
                next_level.push(hash_two(left, right));
            }
            all_nodes.extend_from_slice(&next_level);
            level = next_level;
        }

        MerkleTree {
            leaves,
            nodes: all_nodes,
            depth,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        *self.nodes.last().unwrap_or(&[0u8; 32])
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    pub fn proof(&self, index: usize) -> MerkleProof {
        let mut siblings = Vec::new();
        let mut current = index;
        let leaf_count = 1 << self.depth;

        let mut level_start = 0;
        let mut level_size = leaf_count;

        while level_size > 1 {
            let sibling = if current % 2 == 0 {
                current + 1
            } else {
                current - 1
            };

            if sibling < level_start + level_size {
                siblings.push(
                    self.nodes[level_start + sibling % level_size]
                );
            } else {
                siblings.push([0u8; 32]);
            }

            level_start += level_size;
            level_size /= 2;
            current /= 2;
        }

        MerkleProof {
            index,
            leaf: self.leaves[index.min(self.leaves.len() - 1)],
            siblings,
            root: self.root(),
        }
    }

    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        let mut index = proof.index;

        for sibling in &proof.siblings {
            current = if index % 2 == 0 {
                hash_two(&current, sibling)
            } else {
                hash_two(sibling, &current)
            };
            index /= 2;
        }

        current == proof.root
    }
}

// PartialEq added here — needed by prover tests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MerkleProof {
    pub index: usize,
    pub leaf: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    pub fn new(label: &str) -> Self {
        Transcript {
            state: label.as_bytes().to_vec(),
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        self.state.extend_from_slice(data);
    }

    pub fn absorb_u64(&mut self, value: u64) {
        self.state.extend_from_slice(&value.to_le_bytes());
    }

    pub fn absorb_hash(&mut self, hash: &[u8; 32]) {
        self.state.extend_from_slice(hash);
    }

    pub fn squeeze_challenge(&self) -> u64 {
        let hash = hash_bytes(&self.state);
        u64::from_le_bytes(hash[..8].try_into().unwrap())
    }

    pub fn squeeze_hash(&self) -> [u8; 32] {
        hash_bytes(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_deterministic() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_different_inputs() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_u64_deterministic() {
        let h1 = hash_u64(42);
        let h2 = hash_u64(42);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_u64_different() {
        let h1 = hash_u64(1);
        let h2 = hash_u64(2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_two_order_matters() {
        let a = hash_u64(1);
        let b = hash_u64(2);
        let h1 = hash_two(&a, &b);
        let h2 = hash_two(&b, &a);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_field_elements() {
        let elems = vec![1u64, 2, 3, 4];
        let h1 = hash_field_elements(&elems);
        let h2 = hash_field_elements(&elems);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let tree = MerkleTree::new(&[42]);
        assert!(!tree.root_hex().is_empty());
    }

    #[test]
    fn test_merkle_tree_root_deterministic() {
        let t1 = MerkleTree::new(&[1, 2, 3, 4]);
        let t2 = MerkleTree::new(&[1, 2, 3, 4]);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn test_merkle_tree_different_leaves_different_root() {
        let t1 = MerkleTree::new(&[1, 2, 3, 4]);
        let t2 = MerkleTree::new(&[1, 2, 3, 5]);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn test_merkle_proof_verify() {
        let tree = MerkleTree::new(&[10, 20, 30, 40]);
        let proof = tree.proof(0);
        assert!(MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_all_leaves() {
        let values = vec![10u64, 20, 30, 40, 50, 60, 70, 80];
        let tree = MerkleTree::new(&values);
        for i in 0..values.len() {
            let proof = tree.proof(i);
            assert!(
                MerkleTree::verify_proof(&proof),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_proof_tampered_fails() {
        let tree = MerkleTree::new(&[10, 20, 30, 40]);
        let mut proof = tree.proof(0);
        proof.leaf = hash_u64(999);
        assert!(!MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new("mpc");
        t1.absorb_u64(42);
        let mut t2 = Transcript::new("mpc");
        t2.absorb_u64(42);
        assert_eq!(t1.squeeze_challenge(), t2.squeeze_challenge());
    }

    #[test]
    fn test_transcript_different_inputs() {
        let mut t1 = Transcript::new("mpc");
        t1.absorb_u64(42);
        let mut t2 = Transcript::new("mpc");
        t2.absorb_u64(43);
        assert_ne!(t1.squeeze_challenge(), t2.squeeze_challenge());
    }

    #[test]
    fn test_transcript_squeeze_hash() {
        let mut t = Transcript::new("test");
        t.absorb_u64(100);
        let h = t.squeeze_hash();
        assert_eq!(h.len(), 32);
    }
}