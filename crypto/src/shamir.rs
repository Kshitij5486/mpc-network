// ============================================
// shamir.rs — Shamir Secret Sharing
// ============================================
// This is the heart of MPC.
// 
// The idea in plain English:
// You have a secret number (example: your salary = 50000).
// You split it into 5 pieces called "shares".
// Any 3 shares can reconstruct the secret.
// Any 2 shares reveal NOTHING about the secret.
//
// How? Using a polynomial (a math curve).
// Example with threshold t=3:
// f(x) = secret + a1*x + a2*x^2
// f(0) = secret (hidden)
// f(1), f(2), f(3), f(4), f(5) = the 5 shares
//
// With 3 points you can reconstruct any degree-2 curve.
// With 2 points you cannot — infinite curves fit 2 points.
// This is the security guarantee.
// ============================================

use crate::field::{FieldElement, PRIME};
use rand::Rng;

// ============================================
// Share — one piece of the secret
// ============================================
// x = the party index (1, 2, 3, ...)
// y = the actual share value f(x)
// Each party holds one Share.
// No party holds f(0) — that is the secret itself.
// ============================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Share {
    pub x: FieldElement, // party index
    pub y: FieldElement, // share value
}

impl Share {
    pub fn new(x: u64, y: u64) -> Self {
        Share {
            x: FieldElement::new(x),
            y: FieldElement::new(y),
        }
    }
}

// ============================================
// generate_random_field_element
// ============================================
// Generates a random number inside our prime field.
// Used to create random polynomial coefficients.
// Random coefficients = unpredictable shares = security.
// ============================================

fn random_field_element() -> FieldElement {
    let mut rng = rand::thread_rng();
    // Generate random u64, reduce mod PRIME
    let value: u64 = rng.gen_range(1..PRIME);
    FieldElement::new(value)
}

// ============================================
// evaluate_polynomial
// ============================================
// Given a polynomial defined by its coefficients,
// evaluate it at point x.
//
// coefficients = [a0, a1, a2, ...]
// f(x) = a0 + a1*x + a2*x^2 + a3*x^3 + ...
//
// We use Horner's method for efficiency:
// f(x) = a0 + x*(a1 + x*(a2 + x*(a3 + ...)))
// This reduces multiplications significantly.
// ============================================

fn evaluate_polynomial(coefficients: &[FieldElement], x: &FieldElement) -> FieldElement {
    // Start from the highest degree coefficient
    // and work backwards (Horner's method)
    let mut result = FieldElement::zero();

    for coeff in coefficients.iter().rev() {
        // result = result * x + coeff
        result = result.mul(x).add(coeff);
    }

    result
}

// ============================================
// split — split a secret into n shares
// ============================================
// secret: the number to hide
// threshold: minimum shares needed to reconstruct (t)
// total_shares: total number of shares to create (n)
//
// Steps:
// 1. Create a random polynomial of degree (threshold - 1)
//    where f(0) = secret
// 2. Evaluate the polynomial at x = 1, 2, 3, ..., n
// 3. Each evaluation is one share
// ============================================

pub fn split(secret: u64, threshold: usize, total_shares: usize) -> Vec<Share> {
    // Validate inputs
    assert!(threshold >= 2, "Threshold must be at least 2");
    assert!(total_shares >= threshold, "Total shares must be >= threshold");
    assert!(secret < PRIME, "Secret must be less than PRIME");

    // Build polynomial coefficients
    // coefficients[0] = secret = f(0)
    // coefficients[1..] = random values
    let mut coefficients = Vec::with_capacity(threshold);
    
    // First coefficient is the secret itself
    coefficients.push(FieldElement::new(secret));
    
    // Rest are random — this is what makes shares unpredictable
    for _ in 1..threshold {
        coefficients.push(random_field_element());
    }

    // Evaluate polynomial at x = 1, 2, 3, ..., total_shares
    // Each evaluation gives one share
    let mut shares = Vec::with_capacity(total_shares);
    
    for i in 1..=total_shares {
        let x = FieldElement::new(i as u64);
        let y = evaluate_polynomial(&coefficients, &x);
        shares.push(Share::new(i as u64, y.value));
    }

    shares
}

// ============================================
// reconstruct — rebuild secret from shares
// ============================================
// Takes any t or more shares and reconstructs f(0).
// Uses Lagrange Interpolation.
//
// Lagrange Interpolation in plain English:
// Given t points on a curve, find the curve,
// then evaluate it at x=0 to get the secret.
//
// Formula:
// f(0) = sum over i of: y_i * product over j≠i of: (0 - x_j) / (x_i - x_j)
//
// Each term is called a "Lagrange basis polynomial".
// They all add up to give f(0) = secret.
// ============================================

pub fn reconstruct(shares: &[Share]) -> u64 {
    assert!(shares.len() >= 2, "Need at least 2 shares to reconstruct");

    let mut secret = FieldElement::zero();

    for i in 0..shares.len() {
        // Start with y_i
        let mut numerator = shares[i].y;
        let mut denominator = FieldElement::one();

        for j in 0..shares.len() {
            if i == j {
                continue; // skip when i == j
            }

            // numerator *= (0 - x_j) = -x_j = PRIME - x_j
            let neg_xj = FieldElement::zero().sub(&shares[j].x);
            numerator = numerator.mul(&neg_xj);

            // denominator *= (x_i - x_j)
            let xi_minus_xj = shares[i].x.sub(&shares[j].x);
            denominator = denominator.mul(&xi_minus_xj);
        }

        // term = numerator / denominator = y_i * lagrange_basis(0)
        let term = numerator.div(&denominator);
        
        // Add this term to the running sum
        secret = secret.add(&term);
    }

    secret.value
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_creates_correct_number_of_shares() {
        let shares = split(12345, 3, 5);
        assert_eq!(shares.len(), 5);
    }

    #[test]
    fn test_reconstruct_with_all_shares() {
        let secret = 99999;
        let shares = split(secret, 3, 5);
        let recovered = reconstruct(&shares);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_reconstruct_with_minimum_shares() {
        // Should work with exactly threshold shares
        let secret = 42;
        let shares = split(secret, 3, 5);
        // Use only first 3 shares (the minimum)
        let recovered = reconstruct(&shares[..3]);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_reconstruct_with_different_share_subsets() {
        // Any subset of t shares should give same secret
        let secret = 777;
        let shares = split(secret, 3, 5);

        // Try shares 0,1,2
        let r1 = reconstruct(&shares[0..3]);
        // Try shares 1,2,3
        let r2 = reconstruct(&shares[1..4]);
        // Try shares 2,3,4
        let r3 = reconstruct(&shares[2..5]);

        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
        assert_eq!(r3, secret);
    }

    #[test]
    fn test_shares_look_random() {
        // Shares should not equal the secret
        let secret = 100;
        let shares = split(secret, 3, 5);
        for share in &shares {
            // Each share value should be different from secret
            // (with overwhelming probability)
            assert_ne!(share.y.value, secret);
        }
    }

    #[test]
    fn test_different_secrets_give_different_shares() {
        let shares1 = split(111, 3, 5);
        let shares2 = split(222, 3, 5);
        // First shares should differ
        assert_ne!(shares1[0].y.value, shares2[0].y.value);
    }

    #[test]
    fn test_large_secret() {
        // Test with a large secret value
        let secret = PRIME - 1;
        let shares = split(secret, 3, 5);
        let recovered = reconstruct(&shares[..3]);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_two_of_three_threshold() {
        // 2-of-3 threshold scheme
        let secret = 55555;
        let shares = split(secret, 2, 3);
        let recovered = reconstruct(&shares[..2]);
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_five_of_seven_threshold() {
        // 5-of-7 threshold scheme
        let secret = 123456789;
        let shares = split(secret, 5, 7);
        let recovered = reconstruct(&shares[..5]);
        assert_eq!(recovered, secret);
    }
}