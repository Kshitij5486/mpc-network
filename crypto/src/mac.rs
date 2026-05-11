// ============================================
// mac.rs — Message Authentication Codes
// ============================================
// This file solves one critical problem:
// How do we know a party didn't tamper with their share?
//
// Without MACs:
// Party A holds share = 500
// Party A is malicious, changes it to 999
// Nobody can detect this — result is wrong silently
//
// With MACs:
// Every share has a cryptographic "tag" attached
// If you change the share value, the tag breaks
// Broken tag = cheating detected = party gets slashed
//
// How it works:
// There is a global secret key called ALPHA (α)
// known to nobody individually (it is also secret shared)
// For a share value x, the MAC tag is:
// tag = α * x  (multiplication in our field)
//
// To verify: check that tag == α * x
// If someone changes x to x', then:
// tag ≠ α * x' (with overwhelming probability)
// Cheating detected.
// ============================================

use crate::field::{FieldElement, PRIME};
use rand::Rng;

// ============================================
// MacKey — the global authentication key
// ============================================
// In real MPC, this key is SECRET SHARED too.
// No single party knows the full alpha.
// Each party holds a share of alpha.
// Here we implement the single-party version first.
// ============================================

#[derive(Debug, Clone, Copy)]
pub struct MacKey {
    pub alpha: FieldElement, // the global MAC key
}

impl MacKey {
    // Create a new random MAC key
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let alpha = rng.gen_range(1..PRIME);
        MacKey {
            alpha: FieldElement::new(alpha),
        }
    }

    // Create a MAC key from a known value (for testing)
    pub fn from_value(alpha: u64) -> Self {
        MacKey {
            alpha: FieldElement::new(alpha),
        }
    }
}

// ============================================
// AuthenticatedShare — a share with a MAC tag
// ============================================
// This is what each party actually holds.
// Not just a raw share value, but a share
// with a cryptographic proof of authenticity.
//
// value = the share itself
// mac_tag = alpha * value
//
// Both value and mac_tag are field elements.
// ============================================

#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedShare {
    pub value: FieldElement,   // the share value
    pub mac_tag: FieldElement, // alpha * value
}

impl AuthenticatedShare {
    // Create a new authenticated share
    // Automatically computes the MAC tag
    pub fn new(value: u64, key: &MacKey) -> Self {
        let value_fe = FieldElement::new(value);
        // tag = alpha * value
        let mac_tag = key.alpha.mul(&value_fe);
        AuthenticatedShare {
            value: value_fe,
            mac_tag,
        }
    }

    // Create from raw field elements (used in reconstruction)
    pub fn from_field_elements(
        value: FieldElement,
        mac_tag: FieldElement,
    ) -> Self {
        AuthenticatedShare { value, mac_tag }
    }

    // ============================================
    // verify — check if MAC tag is valid
    // ============================================
    // Returns true if tag == alpha * value
    // Returns false if someone tampered with value
    //
    // This is called when a party "opens" their share
    // during the reconstruction phase.
    // All parties verify each other's shares.
    // ============================================
    pub fn verify(&self, key: &MacKey) -> bool {
        // Recompute what the tag should be
        let expected_tag = key.alpha.mul(&self.value);
        // Compare with actual tag
        self.mac_tag == expected_tag
    }

    // ============================================
    // add — add two authenticated shares
    // ============================================
    // If share1 has tag1 = α*x1
    // and share2 has tag2 = α*x2
    // then (share1 + share2) has tag = α*(x1+x2)
    //                                = α*x1 + α*x2
    //                                = tag1 + tag2
    //
    // This means we can add shares AND their tags
    // without knowing alpha. Linearity is the key property.
    // ============================================
    pub fn add(&self, other: &AuthenticatedShare) -> AuthenticatedShare {
        AuthenticatedShare {
            value: self.value.add(&other.value),
            mac_tag: self.mac_tag.add(&other.mac_tag),
        }
    }

    // ============================================
    // add_constant — add a public constant to share
    // ============================================
    // When adding a public value c to a secret share x:
    // new_value = x + c
    // new_tag = α*(x + c) = α*x + α*c = tag + α*c
    // ============================================
    pub fn add_constant(
        &self,
        constant: &FieldElement,
        key: &MacKey,
    ) -> AuthenticatedShare {
        let new_value = self.value.add(constant);
        // new_tag = old_tag + alpha * constant
        let alpha_times_c = key.alpha.mul(constant);
        let new_tag = self.mac_tag.add(&alpha_times_c);
        AuthenticatedShare {
            value: new_value,
            mac_tag: new_tag,
        }
    }

    // ============================================
    // mul_constant — multiply share by public constant
    // ============================================
    // When multiplying secret share x by public value c:
    // new_value = x * c
    // new_tag = α*(x*c) = (α*x)*c = tag * c
    // ============================================
    pub fn mul_constant(&self, constant: &FieldElement) -> AuthenticatedShare {
        AuthenticatedShare {
            value: self.value.mul(constant),
            mac_tag: self.mac_tag.mul(constant),
        }
    }
}

// ============================================
// open — reveal and verify an authenticated share
// ============================================
// When a party wants to reveal their share:
// 1. They publish their value
// 2. Everyone verifies the MAC tag
// 3. If tag is valid, the value is accepted
// 4. If tag is invalid, cheating is detected
//
// Returns Some(value) if valid
// Returns None if MAC check fails (cheating detected)
// ============================================

pub fn open(share: &AuthenticatedShare, key: &MacKey) -> Option<FieldElement> {
    if share.verify(key) {
        Some(share.value)
    } else {
        None // cheating detected
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_tag_computed_correctly() {
        let key = MacKey::from_value(7);
        let share = AuthenticatedShare::new(5, &key);
        // tag should be 7 * 5 = 35
        assert_eq!(share.mac_tag.value, 35);
    }

    #[test]
    fn test_valid_share_verifies() {
        let key = MacKey::generate();
        let share = AuthenticatedShare::new(12345, &key);
        // A correctly created share should always verify
        assert!(share.verify(&key));
    }

    #[test]
    fn test_tampered_value_fails_verification() {
        let key = MacKey::generate();
        let mut share = AuthenticatedShare::new(100, &key);
        // Attacker changes the value but not the tag
        share.value = FieldElement::new(999);
        // Verification must fail
        assert!(!share.verify(&key));
    }

    #[test]
    fn test_tampered_tag_fails_verification() {
        let key = MacKey::generate();
        let mut share = AuthenticatedShare::new(100, &key);
        // Attacker changes the tag
        share.mac_tag = FieldElement::new(999);
        // Verification must fail
        assert!(!share.verify(&key));
    }

    #[test]
    fn test_open_valid_share() {
        let key = MacKey::generate();
        let share = AuthenticatedShare::new(42, &key);
        let result = open(&share, &key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, 42);
    }

    #[test]
    fn test_open_tampered_share_returns_none() {
        let key = MacKey::generate();
        let mut share = AuthenticatedShare::new(42, &key);
        // Tamper with the value
        share.value = FieldElement::new(100);
        // Open should return None — cheating detected
        let result = open(&share, &key);
        assert!(result.is_none());
    }

    #[test]
    fn test_add_two_authenticated_shares() {
        let key = MacKey::from_value(3);
        let share1 = AuthenticatedShare::new(10, &key);
        let share2 = AuthenticatedShare::new(20, &key);
        let sum = share1.add(&share2);
        // Value should be 10 + 20 = 30
        assert_eq!(sum.value.value, 30);
        // Tag should still verify
        assert!(sum.verify(&key));
    }

    #[test]
    fn test_add_constant_to_share() {
        let key = MacKey::from_value(3);
        let share = AuthenticatedShare::new(10, &key);
        let constant = FieldElement::new(5);
        let result = share.add_constant(&constant, &key);
        // Value should be 10 + 5 = 15
        assert_eq!(result.value.value, 15);
        // Tag should still verify
        assert!(result.verify(&key));
    }

    #[test]
    fn test_mul_constant_to_share() {
        let key = MacKey::from_value(3);
        let share = AuthenticatedShare::new(10, &key);
        let constant = FieldElement::new(4);
        let result = share.mul_constant(&constant);
        // Value should be 10 * 4 = 40
        assert_eq!(result.value.value, 40);
        // Tag should still verify
        assert!(result.verify(&key));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let key1 = MacKey::from_value(7);
        let key2 = MacKey::from_value(13);
        let share = AuthenticatedShare::new(100, &key1);
        // Verifying with wrong key should fail
        assert!(!share.verify(&key2));
    }

    #[test]
    fn test_zero_value_share() {
        let key = MacKey::generate();
        let share = AuthenticatedShare::new(0, &key);
        assert!(share.verify(&key));
        assert_eq!(open(&share, &key).unwrap().value, 0);
    }
}