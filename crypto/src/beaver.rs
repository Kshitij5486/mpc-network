// ============================================
// beaver.rs — Beaver Triple Generation
// ============================================
// Beaver triples are the fuel for SPDZ multiplication.
// Every secure multiplication consumes one triple.
// They are generated BEFORE the computation starts
// in what is called the "offline phase".
//
// A Beaver triple is (a, b, c) where c = a * b
// a and b are random numbers
// c is their product
// All three are secret shared among parties
//
// Why generate them in advance?
// Because generating them requires expensive
// cryptographic operations (Oblivious Transfer).
// By doing this offline, the online computation
// phase becomes very fast — just local additions.
//
// Think of it like meal prep:
// Offline phase = chop all vegetables in advance
// Online phase = cooking is fast because prep is done
// ============================================

use crate::field::{FieldElement, PRIME};
use crate::mac::{AuthenticatedShare, MacKey};
use crate::spdz::BeaverTriple;
use rand::Rng;

// ============================================
// TriplePool — a collection of pre-generated triples
// ============================================
// In real MPC, parties generate thousands of triples
// before the computation starts.
// Each multiplication consumes one triple from the pool.
// When pool is empty, generate more (offline phase again).
// ============================================

pub struct TriplePool {
    triples: Vec<BeaverTriple>,
    next_index: usize,
}

impl TriplePool {
    // Create a new empty pool
    pub fn new() -> Self {
        TriplePool {
            triples: Vec::new(),
            next_index: 0,
        }
    }

    // ============================================
    // generate — fill the pool with n triples
    // ============================================
    // In real MPC this uses Oblivious Transfer (OT)
    // between parties so no party learns a,b,c fully.
    // Here we generate them directly for testing.
    // The real OT-based generation comes in Sprint 2
    // when we have the network layer.
    // ============================================
    pub fn generate(&mut self, count: usize, key: &MacKey) {
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            // Generate random a and b
            let a_val: u64 = rng.gen_range(1..PRIME);
            let b_val: u64 = rng.gen_range(1..PRIME);

            // Compute c = a * b in our field
            let a_fe = FieldElement::new(a_val);
            let b_fe = FieldElement::new(b_val);
            let c_fe = a_fe.mul(&b_fe);

            // Create authenticated shares for each
            let a = AuthenticatedShare::new(a_val, key);
            let b = AuthenticatedShare::new(b_val, key);
            let c = AuthenticatedShare::new(c_fe.value, key);

            self.triples.push(BeaverTriple { a, b, c });
        }
    }

    // ============================================
    // next — consume one triple from the pool
    // ============================================
    // Returns None if pool is exhausted.
    // In production: trigger offline phase to refill.
    // ============================================
    pub fn next(&mut self) -> Option<BeaverTriple> {
        if self.next_index >= self.triples.len() {
            return None; // pool exhausted
        }
        let triple = self.triples[self.next_index];
        self.next_index += 1;
        Some(triple)
    }

    // How many triples are left in the pool
    pub fn remaining(&self) -> usize {
        self.triples.len() - self.next_index
    }

    // How many triples have been consumed
    pub fn consumed(&self) -> usize {
        self.next_index
    }

    // Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.next_index >= self.triples.len()
    }

    // Reset pool — reuse same triples (only for testing)
    // In production NEVER reuse triples — security breaks
    pub fn reset(&mut self) {
        self.next_index = 0;
    }
}

// ============================================
// verify_triple — check a triple is valid
// ============================================
// Verifies that:
// 1. All three MAC tags are correct
// 2. c == a * b (the core relationship)
//
// In real MPC parties do a sacrifice protocol
// to verify triples without revealing them.
// Here we verify directly for testing.
// ============================================

pub fn verify_triple(triple: &BeaverTriple, key: &MacKey) -> bool {
    // Check all MAC tags
    if !triple.a.verify(key) {
        return false;
    }
    if !triple.b.verify(key) {
        return false;
    }
    if !triple.c.verify(key) {
        return false;
    }

    // Check the core relationship: c == a * b
    let expected_c = triple.a.value.mul(&triple.b.value);
    triple.c.value == expected_c
}

// ============================================
// generate_single_triple — create one triple
// ============================================
// Convenience function for when you need
// exactly one triple without a pool.
// ============================================

pub fn generate_single_triple(key: &MacKey) -> BeaverTriple {
    let mut pool = TriplePool::new();
    pool.generate(1, key);
    pool.next().unwrap()
}

// ============================================
// OfflinePhase — manages the full offline preprocessing
// ============================================
// In a real MPC system, before any computation:
// 1. Parties agree on how many multiplications needed
// 2. They run offline phase to generate that many triples
// 3. Online phase begins — triples consumed one by one
//
// This struct manages that lifecycle.
// ============================================

pub struct OfflinePhase {
    pub triple_pool: TriplePool,
    pub mac_key: MacKey,
    pub party_count: usize,
}

impl OfflinePhase {
    // Initialize offline phase for a computation
    // mul_count = number of multiplications expected
    // party_count = number of parties in computation
    pub fn new(mul_count: usize, party_count: usize, mac_key: MacKey) -> Self {
        let mut pool = TriplePool::new();
        // Generate slightly more than needed as buffer
        let buffer = mul_count + 10;
        pool.generate(buffer, &mac_key);

        OfflinePhase {
            triple_pool: pool,
            mac_key,
            party_count,
        }
    }

    // Get next triple for a multiplication
    pub fn get_triple(&mut self) -> Option<BeaverTriple> {
        self.triple_pool.next()
    }

    // How many multiplications can still be performed
    pub fn multiplications_remaining(&self) -> usize {
        self.triple_pool.remaining()
    }

    // Verify all remaining triples in pool are valid
    pub fn verify_all_triples(&self) -> bool {
        self.triple_pool.triples.iter().all(|t| {
            verify_triple(t, &self.mac_key)
        })
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_key() -> MacKey {
        MacKey::from_value(7)
    }

    #[test]
    fn test_generate_single_triple() {
        let key = setup_key();
        let triple = generate_single_triple(&key);
        // c must equal a * b
        let expected_c = triple.a.value.mul(&triple.b.value);
        assert_eq!(triple.c.value, expected_c);
    }

    #[test]
    fn test_verify_triple_valid() {
        let key = setup_key();
        let triple = generate_single_triple(&key);
        assert!(verify_triple(&triple, &key));
    }

    #[test]
    fn test_verify_triple_tampered_c() {
        let key = setup_key();
        let mut triple = generate_single_triple(&key);
        // Tamper with c — break the a*b=c relationship
        triple.c.value = FieldElement::new(999);
        // Verification must fail
        assert!(!verify_triple(&triple, &key));
    }

    #[test]
    fn test_pool_generate_correct_count() {
        let key = setup_key();
        let mut pool = TriplePool::new();
        pool.generate(10, &key);
        assert_eq!(pool.remaining(), 10);
    }

    #[test]
    fn test_pool_next_consumes_triple() {
        let key = setup_key();
        let mut pool = TriplePool::new();
        pool.generate(5, &key);
        let triple = pool.next();
        assert!(triple.is_some());
        assert_eq!(pool.remaining(), 4);
        assert_eq!(pool.consumed(), 1);
    }

    #[test]
    fn test_pool_exhausted_returns_none() {
        let key = setup_key();
        let mut pool = TriplePool::new();
        pool.generate(2, &key);
        pool.next(); // consume 1
        pool.next(); // consume 2
        // Pool should be empty now
        assert!(pool.is_empty());
        assert!(pool.next().is_none());
    }

    #[test]
    fn test_pool_reset() {
        let key = setup_key();
        let mut pool = TriplePool::new();
        pool.generate(3, &key);
        pool.next();
        pool.next();
        assert_eq!(pool.remaining(), 1);
        // Reset — triples can be reused (testing only)
        pool.reset();
        assert_eq!(pool.remaining(), 3);
    }

    #[test]
    fn test_all_generated_triples_are_valid() {
        let key = setup_key();
        let mut pool = TriplePool::new();
        pool.generate(20, &key);
        // Every triple must satisfy c = a * b
        for triple in &pool.triples {
            assert!(verify_triple(triple, &key));
        }
    }

    #[test]
    fn test_offline_phase_initialization() {
        let key = setup_key();
        let offline = OfflinePhase::new(5, 3, key);
        // Should have generated 5 + 10 = 15 triples
        assert_eq!(offline.multiplications_remaining(), 15);
    }

    #[test]
    fn test_offline_phase_verify_all_triples() {
        let key = setup_key();
        let offline = OfflinePhase::new(10, 3, key);
        // All triples must be valid
        assert!(offline.verify_all_triples());
    }

    #[test]
    fn test_offline_phase_get_triple() {
        let key = setup_key();
        let mut offline = OfflinePhase::new(5, 3, key);
        let before = offline.multiplications_remaining();
        let triple = offline.get_triple();
        assert!(triple.is_some());
        assert_eq!(offline.multiplications_remaining(), before - 1);
    }

    #[test]
    fn test_triples_are_random() {
        let key = setup_key();
        let t1 = generate_single_triple(&key);
        let t2 = generate_single_triple(&key);
        // Two triples should have different a values
        // (with overwhelming probability)
        assert_ne!(t1.a.value.value, t2.a.value.value);
    }
}