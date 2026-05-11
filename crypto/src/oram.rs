// ============================================
// oram.rs — Oblivious RAM (Path ORAM)
// ============================================
// Problem this solves:
// Even if data is encrypted, an attacker watching
// your memory access patterns can learn secrets.
//
// Example:
// You have an encrypted database of medical records.
// Attacker watches: you always access address 42
// right before prescribing insulin.
// Attacker learns: patient has diabetes.
// No encryption was broken — just patterns observed.
//
// ORAM solution:
// Every memory access — read OR write —
// touches a random set of locations.
// Real access is hidden among fake accesses.
// Attacker sees random noise, learns nothing.
//
// We implement Path ORAM — the most practical variant.
// Used in secure enclaves, MPC systems, and
// privacy-preserving databases.
//
// Path ORAM Structure:
// Data is stored in a binary tree of "buckets".
// Each data block is assigned a random leaf.
// To access block i:
//   1. Read entire path from root to leaf_i
//   2. Find block i somewhere on the path
//   3. Re-encrypt and write path back
//   4. Assign block i a new random leaf
// Every access reads/writes the same amount of data.
// ============================================

use std::collections::HashMap;
use rand::Rng;

// ============================================
// Constants
// ============================================

const BUCKET_SIZE: usize = 4;
const EMPTY_BLOCK_ID: u64 = u64::MAX;

// ============================================
// Block — one unit of data in the ORAM
// ============================================

#[derive(Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub data: Vec<u8>,
    pub leaf: usize,
}

impl Block {
    pub fn new(id: u64, data: Vec<u8>, leaf: usize) -> Self {
        Block { id, data, leaf }
    }

    pub fn empty() -> Self {
        Block {
            id: EMPTY_BLOCK_ID,
            data: vec![0u8; 8],
            leaf: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.id == EMPTY_BLOCK_ID
    }
}

// ============================================
// Bucket — one node in the ORAM tree
// ============================================

#[derive(Debug, Clone)]
pub struct Bucket {
    pub blocks: Vec<Block>,
}

impl Bucket {
    pub fn new() -> Self {
        Bucket {
            blocks: vec![Block::empty(); BUCKET_SIZE],
        }
    }

    pub fn add(&mut self, block: Block) -> bool {
        for slot in &mut self.blocks {
            if slot.is_empty() {
                *slot = block;
                return true;
            }
        }
        false
    }

    pub fn remove(&mut self, block_id: u64) -> Option<Block> {
        for slot in &mut self.blocks {
            if slot.id == block_id {
                let block = slot.clone();
                *slot = Block::empty();
                return Some(block);
            }
        }
        None
    }

    pub fn real_blocks(&self) -> Vec<&Block> {
        self.blocks.iter().filter(|b| !b.is_empty()).collect()
    }

    pub fn count(&self) -> usize {
        self.blocks.iter().filter(|b| !b.is_empty()).count()
    }
}

// ============================================
// PathOram — the main ORAM structure
// ============================================

pub struct PathOram {
    tree: Vec<Bucket>,
    position_map: HashMap<u64, usize>,
    stash: Vec<Block>,
    pub height: usize,       // <-- fixed: now pub
    num_leaves: usize,
}

impl PathOram {
    pub fn new(capacity: usize) -> Self {
        let height = (capacity as f64).log2().ceil() as usize + 1;
        let num_leaves = 1 << height;
        let total_nodes = 2 * num_leaves;
        let tree = vec![Bucket::new(); total_nodes];

        PathOram {
            tree,
            position_map: HashMap::new(),
            stash: Vec::new(),
            height,
            num_leaves,
        }
    }

    fn random_leaf(&self) -> usize {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..self.num_leaves)
    }

    fn path_indices(&self, leaf: usize) -> Vec<usize> {
        let mut indices = Vec::new();
        let mut node = self.num_leaves + leaf;
        while node >= 1 {
            indices.push(node);
            node /= 2;
        }
        indices.reverse();
        indices
    }

    fn read_path(&mut self, leaf: usize) {
        let indices = self.path_indices(leaf);
        for idx in indices {
            if idx < self.tree.len() {
                let bucket = &mut self.tree[idx];
                for block in bucket.blocks.iter_mut() {
                    if !block.is_empty() {
                        self.stash.push(block.clone());
                        *block = Block::empty();
                    }
                }
            }
        }
    }

    fn write_path(&mut self, leaf: usize) {
        let indices = self.path_indices(leaf);

        // Drain stash into local vec first.
        // This releases the borrow on self.stash
        // so we can call self.path_indices() freely.
        let mut local_stash: Vec<Block> =
            self.stash.drain(..).collect();

        for &idx in indices.iter().rev() {
            if idx >= self.tree.len() {
                continue;
            }

            let mut next_stash = Vec::new();

            for block in local_stash.drain(..) {
                if block.is_empty() {
                    continue;
                }

                let block_leaf = *self.position_map
                    .get(&block.id)
                    .unwrap_or(&block.leaf);

                // Safe to call — self.stash is not borrowed
                let block_path = self.path_indices(block_leaf);

                if block_path.contains(&idx)
                    && self.tree[idx].count() < BUCKET_SIZE
                {
                    self.tree[idx].add(block);
                } else {
                    next_stash.push(block);
                }
            }

            local_stash = next_stash;
        }

        // Put leftover blocks back into stash
        self.stash = local_stash;
    }

    pub fn write(&mut self, id: u64, data: Vec<u8>) {
        let new_leaf = self.random_leaf();
        self.position_map.insert(id, new_leaf);
        let old_leaf = new_leaf;

        self.read_path(old_leaf);

        // Remove old version if exists
        self.stash.retain(|b| b.id != id);

        // Add new version
        self.stash.push(Block::new(id, data, new_leaf));

        self.write_path(old_leaf);
    }

    pub fn read(&mut self, id: u64) -> Option<Vec<u8>> {
        let current_leaf = *self.position_map.get(&id)?;

        let new_leaf = self.random_leaf();
        self.position_map.insert(id, new_leaf);

        self.read_path(current_leaf);

        let mut found_data = None;
        for block in &mut self.stash {
            if block.id == id {
                found_data = Some(block.data.clone());
                block.leaf = new_leaf;
                break;
            }
        }

        self.write_path(current_leaf);

        found_data
    }

    pub fn contains(&self, id: u64) -> bool {
        self.position_map.contains_key(&id)
    }

    pub fn stash_size(&self) -> usize {
        self.stash.iter().filter(|b| !b.is_empty()).count()
    }

    pub fn total_blocks(&self) -> usize {
        let tree_count: usize =
            self.tree.iter().map(|b| b.count()).sum();
        tree_count + self.stash_size()
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_creation() {
        let block = Block::new(1, vec![1, 2, 3], 0);
        assert_eq!(block.id, 1);
        assert_eq!(block.data, vec![1, 2, 3]);
        assert!(!block.is_empty());
    }

    #[test]
    fn test_empty_block() {
        let block = Block::empty();
        assert!(block.is_empty());
        assert_eq!(block.id, EMPTY_BLOCK_ID);
    }

    #[test]
    fn test_bucket_add_and_count() {
        let mut bucket = Bucket::new();
        assert_eq!(bucket.count(), 0);
        bucket.add(Block::new(1, vec![1], 0));
        assert_eq!(bucket.count(), 1);
        bucket.add(Block::new(2, vec![2], 0));
        assert_eq!(bucket.count(), 2);
    }

    #[test]
    fn test_bucket_remove() {
        let mut bucket = Bucket::new();
        bucket.add(Block::new(42, vec![9, 9], 0));
        let removed = bucket.remove(42);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, 42);
        assert_eq!(bucket.count(), 0);
    }

    #[test]
    fn test_bucket_full() {
        let mut bucket = Bucket::new();
        for i in 0..BUCKET_SIZE {
            let added = bucket.add(
                Block::new(i as u64, vec![1], 0)
            );
            assert!(added);
        }
        let added = bucket.add(Block::new(99, vec![1], 0));
        assert!(!added);
    }

    #[test]
    fn test_oram_write_and_read() {
        let mut oram = PathOram::new(16);
        oram.write(1, vec![10, 20, 30]);
        let data = oram.read(1);
        assert!(data.is_some());
        assert_eq!(data.unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn test_oram_read_nonexistent_returns_none() {
        let mut oram = PathOram::new(16);
        let data = oram.read(999);
        assert!(data.is_none());
    }

    #[test]
    fn test_oram_contains() {
        let mut oram = PathOram::new(16);
        assert!(!oram.contains(1));
        oram.write(1, vec![1, 2, 3]);
        assert!(oram.contains(1));
    }

    #[test]
    fn test_oram_multiple_blocks() {
        let mut oram = PathOram::new(16);
        oram.write(1, vec![1]);
        oram.write(2, vec![2]);
        oram.write(3, vec![3]);
        assert_eq!(oram.read(1).unwrap(), vec![1]);
        assert_eq!(oram.read(2).unwrap(), vec![2]);
        assert_eq!(oram.read(3).unwrap(), vec![3]);
    }

    #[test]
    fn test_oram_overwrite_block() {
        let mut oram = PathOram::new(16);
        oram.write(1, vec![1, 2, 3]);
        oram.write(1, vec![9, 9, 9]);
        let data = oram.read(1);
        assert_eq!(data.unwrap(), vec![9, 9, 9]);
    }

    #[test]
    fn test_oram_read_multiple_times() {
        let mut oram = PathOram::new(16);
        oram.write(42, vec![7, 7, 7]);
        let d1 = oram.read(42).unwrap();
        let d2 = oram.read(42).unwrap();
        let d3 = oram.read(42).unwrap();
        assert_eq!(d1, vec![7, 7, 7]);
        assert_eq!(d2, vec![7, 7, 7]);
        assert_eq!(d3, vec![7, 7, 7]);
    }

    #[test]
    fn test_path_indices_root_to_leaf() {
        let oram = PathOram::new(8);
        let path = oram.path_indices(0);
        assert_eq!(path[0], 1);
        assert_eq!(path.len(), oram.height + 1);
    }

    #[test]
    fn test_oram_store_u64_values() {
        let mut oram = PathOram::new(16);
        let share_value: u64 = 123456789;
        let bytes = share_value.to_le_bytes().to_vec();
        oram.write(1, bytes.clone());
        let retrieved = oram.read(1).unwrap();
        let recovered = u64::from_le_bytes(
            retrieved.try_into().unwrap()
        );
        assert_eq!(recovered, share_value);
    }
}