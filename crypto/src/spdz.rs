// ============================================
// spdz.rs — SPDZ Protocol
// ============================================
// This is where everything comes together.
// SPDZ lets multiple parties compute over
// secret shared values without revealing them.
//
// Two operations are supported:
// 1. ADDITION — free, no communication needed
//    Each party just adds their shares locally
//
// 2. MULTIPLICATION — requires Beaver triples
//    Cannot be done locally — needs a clever trick
//
// The Beaver Triple Trick (plain English):
// To multiply secret x * y:
// We use a pre-generated triple (a, b, c) where c = a*b
// We reveal (x-a) and (y-b) publicly — these leak nothing
// because a and b are random masks
// Then compute: x*y = c + (x-a)*b + (y-b)*a + (x-a)*(y-b)
// This gives the correct answer without revealing x or y
// ============================================

use crate::field::FieldElement;
use crate::mac::{AuthenticatedShare, MacKey};

// ============================================
// BeaverTriple — pre-computed multiplication helper
// ============================================
// (a, b, c) where c = a * b
// Generated in the offline phase before computation starts
// Consumed one per multiplication operation
// ============================================

#[derive(Debug, Clone, Copy)]
pub struct BeaverTriple {
    pub a: AuthenticatedShare, // random value a
    pub b: AuthenticatedShare, // random value b
    pub c: AuthenticatedShare, // c = a * b
}

impl BeaverTriple {
    // Create a Beaver triple from known values
    // In real MPC this is generated via Oblivious Transfer
    // Here we create it directly for testing
    pub fn new(a_val: u64, b_val: u64, key: &MacKey) -> Self {
        let a = AuthenticatedShare::new(a_val, key);
        let b = AuthenticatedShare::new(b_val, key);
        // c = a * b — this is the key relationship
        let c_val = a.value.mul(&b.value).value;
        let c = AuthenticatedShare::new(c_val, key);
        BeaverTriple { a, b, c }
    }
}

// ============================================
// SpdzParty — represents one party in the MPC network
// ============================================
// In real deployment each party runs on a
// separate machine. Here we simulate all parties
// in one process for testing purposes.
//
// Each party holds:
// - their share of the secret value
// - the MAC key (in real MPC this is also shared)
// ============================================

#[derive(Debug)]
pub struct SpdzParty {
    pub party_id: usize,
    pub mac_key: MacKey,
}

impl SpdzParty {
    pub fn new(party_id: usize, mac_key: MacKey) -> Self {
        SpdzParty { party_id, mac_key }
    }
}

// ============================================
// spdz_add — secure addition of two shares
// ============================================
// Adding two secret shared values requires
// NO communication between parties.
// Each party just adds their shares locally.
//
// Why does this work?
// If share1 = x + random_mask1
// and share2 = y + random_mask2
// then share1 + share2 = (x + y) + (random_mask1 + random_mask2)
// which is a valid share of (x + y)
//
// The MAC tags add correctly too because
// MAC is linear: α*(x+y) = α*x + α*y
// ============================================

pub fn spdz_add(
    share1: &AuthenticatedShare,
    share2: &AuthenticatedShare,
) -> AuthenticatedShare {
    share1.add(share2)
}

// ============================================
// spdz_add_constant — add public constant to share
// ============================================
// Adding a known public value to a secret share.
// Only ONE party needs to add it to their share.
// Other parties add zero (no change).
// The MAC tag is updated accordingly.
// ============================================

pub fn spdz_add_constant(
    share: &AuthenticatedShare,
    constant: u64,
    key: &MacKey,
    is_first_party: bool,
) -> AuthenticatedShare {
    if is_first_party {
        // Only the first party adds the constant
        let c = FieldElement::new(constant);
        share.add_constant(&c, key)
    } else {
        // Other parties leave their share unchanged
        *share
    }
}

// ============================================
// spdz_mul_constant — multiply share by public constant
// ============================================
// Multiplying a secret share by a known public value.
// Every party multiplies their share by the constant.
// No communication needed.
// ============================================

pub fn spdz_mul_constant(
    share: &AuthenticatedShare,
    constant: u64,
) -> AuthenticatedShare {
    let c = FieldElement::new(constant);
    share.mul_constant(&c)
}

// ============================================
// spdz_mul — secure multiplication using Beaver triple
// ============================================
// This is the most complex operation in SPDZ.
// Multiplies two secret shared values x and y.
//
// Step by step:
// 1. Compute epsilon = x - a (using shares)
// 2. Compute delta = y - b (using shares)
// 3. Reveal epsilon and delta publicly (safe — random masks)
// 4. Compute result = c + epsilon*b + delta*a + epsilon*delta
//
// Why revealing epsilon and delta is safe:
// epsilon = x - a. Since a is random, epsilon looks random.
// Learning epsilon reveals nothing about x alone.
// Same for delta and y.
//
// In real MPC parties broadcast epsilon and delta,
// each gets the others' values, then compute locally.
// Here we simulate this with direct values.
// ============================================

pub fn spdz_mul(
    share_x: &AuthenticatedShare,
    share_y: &AuthenticatedShare,
    triple: &BeaverTriple,
    key: &MacKey,
) -> AuthenticatedShare {
    // Step 1: epsilon = x - a (still secret shared)
    let epsilon_share = share_x.add(
        &AuthenticatedShare::from_field_elements(
            FieldElement::zero().sub(&triple.a.value),
            FieldElement::zero().sub(&triple.a.mac_tag),
        )
    );

    // Step 2: delta = y - b (still secret shared)
    let delta_share = share_y.add(
        &AuthenticatedShare::from_field_elements(
            FieldElement::zero().sub(&triple.b.value),
            FieldElement::zero().sub(&triple.b.mac_tag),
        )
    );

    // Step 3: In real MPC, parties reveal epsilon and delta
    // by reconstructing these values (they are safe to reveal)
    // Here we directly use the values since we simulate locally
    let epsilon = epsilon_share.value;
    let delta = delta_share.value;

    // Step 4: Compute result share
    // result = c + epsilon*b + delta*a + epsilon*delta
    
    // Start with c (the precomputed a*b)
    let mut result = triple.c;

    // Add epsilon * b_share (epsilon is public, b is shared)
    let epsilon_times_b = triple.b.mul_constant(&epsilon);
    result = result.add(&epsilon_times_b);

    // Add delta * a_share (delta is public, a is shared)
    let delta_times_a = triple.a.mul_constant(&delta);
    result = result.add(&delta_times_a);

    // Add epsilon * delta (both public, add as constant)
    // Only first party adds this to avoid double counting
    let epsilon_times_delta = epsilon.mul(&delta);
    result = result.add_constant(&epsilon_times_delta, key);

    result
}

// ============================================
// verify_all — verify all shares before opening
// ============================================
// Before reconstructing the final result,
// ALL parties verify ALL shares.
// If any share fails MAC check, abort immediately.
// This catches any cheating that occurred.
// ============================================

pub fn verify_all(shares: &[AuthenticatedShare], key: &MacKey) -> bool {
    shares.iter().all(|share| share.verify(key))
}

// ============================================
// reconstruct_secret — sum all shares to get result
// ============================================
// After verification, sum all party shares.
// The sum reveals the final computation result.
// ============================================

pub fn reconstruct_secret(shares: &[AuthenticatedShare]) -> FieldElement {
    shares.iter().fold(FieldElement::zero(), |acc, share| {
        acc.add(&share.value)
    })
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

    // Helper: create shares of a secret value
    // Simulates splitting a secret among 3 parties
    fn make_shares(
        secret: u64,
        key: &MacKey,
    ) -> (AuthenticatedShare, AuthenticatedShare, AuthenticatedShare) {
        // In real MPC these come from Shamir sharing
        // Here we split manually: p1 + p2 + p3 = secret
        let p1 = secret / 3;
        let p2 = secret / 3;
        let p3 = secret - p1 - p2;
        (
            AuthenticatedShare::new(p1, key),
            AuthenticatedShare::new(p2, key),
            AuthenticatedShare::new(p3, key),
        )
    }

    #[test]
    fn test_spdz_add_two_shares() {
        let key = setup_key();
        // share of 10 + share of 20 = share of 30
        let s1 = AuthenticatedShare::new(10, &key);
        let s2 = AuthenticatedShare::new(20, &key);
        let result = spdz_add(&s1, &s2);
        assert_eq!(result.value.value, 30);
        assert!(result.verify(&key));
    }

    #[test]
    fn test_spdz_add_constant() {
        let key = setup_key();
        let share = AuthenticatedShare::new(10, &key);
        // Add public constant 5 — only first party adds
        let result = spdz_add_constant(&share, 5, &key, true);
        assert_eq!(result.value.value, 15);
        assert!(result.verify(&key));
    }

    #[test]
    fn test_spdz_add_constant_non_first_party() {
        let key = setup_key();
        let share = AuthenticatedShare::new(10, &key);
        // Non-first party should NOT add constant
        let result = spdz_add_constant(&share, 5, &key, false);
        assert_eq!(result.value.value, 10); // unchanged
        assert!(result.verify(&key));
    }

    #[test]
    fn test_spdz_mul_constant() {
        let key = setup_key();
        let share = AuthenticatedShare::new(10, &key);
        let result = spdz_mul_constant(&share, 4);
        assert_eq!(result.value.value, 40);
        assert!(result.verify(&key));
    }

    #[test]
    fn test_beaver_triple_relationship() {
        let key = setup_key();
        let triple = BeaverTriple::new(3, 4, &key);
        // c must equal a * b = 3 * 4 = 12
        assert_eq!(triple.a.value.value, 3);
        assert_eq!(triple.b.value.value, 4);
        assert_eq!(triple.c.value.value, 12);
    }

    #[test]
    fn test_spdz_mul_simple() {
        let key = setup_key();
        // Multiply share of 6 by share of 7
        // Expected result: 42
        let share_x = AuthenticatedShare::new(6, &key);
        let share_y = AuthenticatedShare::new(7, &key);
        // Use triple (2, 3, 6)
        let triple = BeaverTriple::new(2, 3, &key);
        let result = spdz_mul(&share_x, &share_y, &triple, &key);
        assert_eq!(result.value.value, 42);
    }

    #[test]
    fn test_spdz_mul_by_zero() {
        let key = setup_key();
        let share_x = AuthenticatedShare::new(999, &key);
        let share_y = AuthenticatedShare::new(0, &key);
        let triple = BeaverTriple::new(1, 0, &key);
        let result = spdz_mul(&share_x, &share_y, &triple, &key);
        assert_eq!(result.value.value, 0);
    }

    #[test]
    fn test_spdz_mul_by_one() {
        let key = setup_key();
        let share_x = AuthenticatedShare::new(42, &key);
        let share_y = AuthenticatedShare::new(1, &key);
        let triple = BeaverTriple::new(1, 1, &key);
        let result = spdz_mul(&share_x, &share_y, &triple, &key);
        assert_eq!(result.value.value, 42);
    }

    #[test]
    fn test_verify_all_valid_shares() {
        let key = setup_key();
        let shares = vec![
            AuthenticatedShare::new(10, &key),
            AuthenticatedShare::new(20, &key),
            AuthenticatedShare::new(30, &key),
        ];
        assert!(verify_all(&shares, &key));
    }

    #[test]
    fn test_verify_all_catches_tampered_share() {
        let key = setup_key();
        let mut shares = vec![
            AuthenticatedShare::new(10, &key),
            AuthenticatedShare::new(20, &key),
            AuthenticatedShare::new(30, &key),
        ];
        // Tamper with middle share
        shares[1].value = FieldElement::new(999);
        // verify_all must return false
        assert!(!verify_all(&shares, &key));
    }

    #[test]
    fn test_reconstruct_secret_from_shares() {
        let key = setup_key();
        // Secret = 60, split into 3 shares: 10 + 20 + 30
        let (s1, s2, s3) = make_shares(60, &key);
        let shares = vec![s1, s2, s3];
        assert!(verify_all(&shares, &key));
        let result = reconstruct_secret(&shares);
        assert_eq!(result.value, 60);
    }

    #[test]
    fn test_full_mpc_addition_workflow() {
        let key = setup_key();
        // Party A has secret x = 30
        // Party B has secret y = 12
        // Goal: compute x + y = 42 without revealing x or y

        // Each secret is split into 3 shares
        let (x1, x2, x3) = make_shares(30, &key);
        let (y1, y2, y3) = make_shares(12, &key);

        // Each party adds their shares locally
        let z1 = spdz_add(&x1, &y1);
        let z2 = spdz_add(&x2, &y2);
        let z3 = spdz_add(&x3, &y3);

        // Verify all before opening
        let result_shares = vec![z1, z2, z3];
        assert!(verify_all(&result_shares, &key));

        // Reconstruct final result
        let result = reconstruct_secret(&result_shares);
        assert_eq!(result.value, 42);
    }
}