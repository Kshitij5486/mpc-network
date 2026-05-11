// ============================================
// field.rs — Modular Arithmetic
// ============================================
// This is the mathematical foundation of everything.
// In normal math, numbers go to infinity.
// In cryptography, numbers wrap around a prime number.
// Example: clock arithmetic — after 12 comes 1, not 13.
// We do the same but with a large prime number.
// This makes math reversible and unpredictable — 
// both essential properties for cryptography.
// ============================================

// This prime number is what all our math wraps around.
// It is a Mersenne prime — specially chosen for fast arithmetic.
// Every computation in our MPC system uses this prime.
pub const PRIME: u64 = 2_305_843_009_213_693_951;

// ============================================
// FieldElement — a number inside our prime field
// ============================================
// Instead of working with raw u64 numbers,
// we wrap them in this struct.
// This guarantees the value is always less than PRIME.
// ============================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldElement {
    pub value: u64,
}

impl FieldElement {

    // Create a new FieldElement.
    // Automatically reduces value mod PRIME.
    // So FieldElement::new(PRIME + 5) gives value = 5.
    pub fn new(value: u64) -> Self {
        FieldElement {
            value: value % PRIME,
        }
    }

    // Create a FieldElement with value zero.
    pub fn zero() -> Self {
        FieldElement { value: 0 }
    }

    // Create a FieldElement with value one.
    pub fn one() -> Self {
        FieldElement { value: 1 }
    }

    // ============================================
    // ADDITION
    // (a + b) mod PRIME
    // Example: if PRIME = 97, then 90 + 30 = 120
    // 120 mod 97 = 23. Result is 23, not 120.
    // ============================================
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        // We use u128 temporarily to avoid overflow
        // because two u64 numbers added together
        // might exceed u64's maximum value.
        let result = (self.value as u128 + other.value as u128) 
                     % PRIME as u128;
        FieldElement::new(result as u64)
    }

    // ============================================
    // SUBTRACTION
    // (a - b) mod PRIME
    // We add PRIME before subtracting to avoid
    // negative numbers — Rust u64 cannot go negative.
    // Example: 3 - 5 mod 97 = 3 + 97 - 5 = 95
    // ============================================
    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        let result = (self.value as u128 
                      + PRIME as u128 
                      - other.value as u128) 
                     % PRIME as u128;
        FieldElement::new(result as u64)
    }

    // ============================================
    // MULTIPLICATION
    // (a * b) mod PRIME
    // We use u128 here because two u64 numbers
    // multiplied together can be up to 128 bits wide.
    // ============================================
    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        let result = (self.value as u128 * other.value as u128) 
                     % PRIME as u128;
        FieldElement::new(result as u64)
    }

    // ============================================
    // POWER
    // a^exponent mod PRIME
    // Used internally by inverse().
    // Uses "fast exponentiation" — squares the base
    // repeatedly instead of multiplying one by one.
    // Example: a^8 = ((a^2)^2)^2 — only 3 multiplications
    // instead of 7.
    // ============================================
    pub fn pow(&self, mut exponent: u64) -> FieldElement {
        let mut result = FieldElement::one();
        let mut base = *self;

        while exponent > 0 {
            // If exponent is odd, multiply result by base
            if exponent % 2 == 1 {
                result = result.mul(&base);
            }
            // Square the base
            base = base.mul(&base);
            // Halve the exponent
            exponent /= 2;
        }
        result
    }

    // ============================================
    // INVERSE
    // Finds a number such that: a * a_inverse = 1
    // This is division in our field: a / b = a * b_inverse
    // Uses Fermat's Little Theorem:
    // a^(PRIME-1) = 1 mod PRIME
    // Therefore: a^(PRIME-2) = a_inverse mod PRIME
    // ============================================
    pub fn inverse(&self) -> FieldElement {
        // Cannot invert zero — same as division by zero
        assert!(self.value != 0, "Cannot invert zero element");
        self.pow(PRIME - 2)
    }

    // ============================================
    // DIVISION
    // a / b = a * b_inverse
    // ============================================
    pub fn div(&self, other: &FieldElement) -> FieldElement {
        let inv = other.inverse();
        self.mul(&inv)
    }

    // Check if this element is zero
    pub fn is_zero(&self) -> bool {
        self.value == 0
    }
}

// ============================================
// TESTS
// Run with: cargo test
// Every test must pass before moving to next file.
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_reduces_mod_prime() {
        // Value larger than PRIME should wrap around
        let a = FieldElement::new(PRIME + 10);
        assert_eq!(a.value, 10);
    }

    #[test]
    fn test_addition() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(200);
        let c = a.add(&b);
        assert_eq!(c.value, 300);
    }

    #[test]
    fn test_addition_wraps_around_prime() {
        // Adding two large numbers should wrap around PRIME
        let a = FieldElement::new(PRIME - 1);
        let b = FieldElement::new(2);
        let c = a.add(&b);
        assert_eq!(c.value, 1);
    }

    #[test]
    fn test_subtraction() {
        let a = FieldElement::new(300);
        let b = FieldElement::new(100);
        let c = a.sub(&b);
        assert_eq!(c.value, 200);
    }

    #[test]
    fn test_subtraction_no_negative() {
        // 3 - 5 should not go negative
        // Result should be PRIME - 2
        let a = FieldElement::new(3);
        let b = FieldElement::new(5);
        let c = a.sub(&b);
        assert_eq!(c.value, PRIME - 2);
    }

    #[test]
    fn test_multiplication() {
        let a = FieldElement::new(6);
        let b = FieldElement::new(7);
        let c = a.mul(&b);
        assert_eq!(c.value, 42);
    }

    #[test]
    fn test_inverse() {
        let a = FieldElement::new(42);
        let inv = a.inverse();
        // a * a_inverse must equal 1
        let product = a.mul(&inv);
        assert_eq!(product.value, 1);
    }

    #[test]
    fn test_division() {
        let a = FieldElement::new(42);
        let b = FieldElement::new(6);
        let c = a.div(&b);
        // 42 / 6 = 7, verify by multiplying back
        let check = c.mul(&b);
        assert_eq!(check.value, 42);
    }

    #[test]
    fn test_zero() {
        let z = FieldElement::zero();
        assert_eq!(z.value, 0);
        assert!(z.is_zero());
    }

    #[test]
    fn test_additive_identity() {
        // a + 0 = a
        let a = FieldElement::new(999);
        let zero = FieldElement::zero();
        assert_eq!(a.add(&zero).value, a.value);
    }

    #[test]
    fn test_multiplicative_identity() {
        // a * 1 = a
        let a = FieldElement::new(999);
        let one = FieldElement::one();
        assert_eq!(a.mul(&one).value, a.value);
    }
}