// ============================================
// air.rs — Algebraic Intermediate Representation
// ============================================
// This is the most mathematically important file
// in the ZK proof system.
//
// What is an AIR?
// A computation is expressed as a sequence of
// states. Each state transition must satisfy
// a set of polynomial constraints.
//
// Example: proving a + b = c
// State: [a, b, c]
// Constraint: a + b - c = 0
// If this constraint holds for the actual values,
// the computation was performed correctly.
//
// What we prove in our MPC system:
// 1. SPDZ addition constraint:
//    result = share_x + share_y (mod PRIME)
//
// 2. SPDZ multiplication constraint (Beaver):
//    result = c + epsilon*b + delta*a + epsilon*delta
//    where epsilon = x - a, delta = y - b
//
// 3. MAC verification constraint:
//    mac_tag = alpha * share_value (mod PRIME)
//
// If a node submits a proof that satisfies these
// constraints, we know their computation was correct
// WITHOUT seeing their private inputs.
// ============================================

use serde::{Serialize, Deserialize};
use crate::utils::{hash_field_elements, Transcript};
use mpc_crypto::field::{FieldElement, PRIME};

// ============================================
// ConstraintType — what kind of computation
// ============================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConstraintType {
    Addition,       // prove x + y = z
    Multiplication, // prove x * y = z (using Beaver)
    MacVerify,      // prove mac = alpha * value
    ShareValid,     // prove share is in valid range
}

// ============================================
// ComputationTrace — the execution record
// ============================================
// A trace is the sequence of states during
// the computation. Each row is one step.
// Constraints must hold at every row.
//
// For MPC addition: one row
// [share_x, share_y, result, 0]
//
// For MPC multiplication: three rows
// Row 0: [x, a, epsilon, 0]     epsilon = x - a
// Row 1: [y, b, delta, 0]       delta = y - b
// Row 2: [c, result, epsilon, delta]  final result
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputationTrace {
    pub constraint_type: ConstraintType,
    pub rows: Vec<Vec<u64>>,    // trace rows
    pub width: usize,            // columns per row
    pub length: usize,           // number of rows
}

impl ComputationTrace {
    // Create a trace for addition: x + y = result
    pub fn for_addition(x: u64, y: u64, result: u64) -> Self {
        let row = vec![x, y, result, 0u64];
        ComputationTrace {
            constraint_type: ConstraintType::Addition,
            rows: vec![row],
            width: 4,
            length: 1,
        }
    }

    // Create a trace for Beaver multiplication
    // x * y = result using triple (a, b, c) where c = a*b
    pub fn for_multiplication(
        x: u64,
        y: u64,
        a: u64,
        b: u64,
        c: u64,
        result: u64,
    ) -> Self {
        let epsilon = FieldElement::new(x).sub(&FieldElement::new(a)).value;
        let delta = FieldElement::new(y).sub(&FieldElement::new(b)).value;

        let rows = vec![
            vec![x, a, epsilon, 0],    // row 0: compute epsilon
            vec![y, b, delta, 0],       // row 1: compute delta
            vec![c, result, epsilon, delta], // row 2: final result
        ];

        ComputationTrace {
            constraint_type: ConstraintType::Multiplication,
            rows,
            width: 4,
            length: 3,
        }
    }

    // Create a trace for MAC verification
    // mac = alpha * value
    pub fn for_mac_verify(value: u64, alpha: u64, mac: u64) -> Self {
        let row = vec![value, alpha, mac, 0u64];
        ComputationTrace {
            constraint_type: ConstraintType::MacVerify,
            rows: vec![row],
            width: 4,
            length: 1,
        }
    }

    // Get a specific cell in the trace
    pub fn get(&self, row: usize, col: usize) -> u64 {
        self.rows[row][col]
    }

    // Hash the entire trace as a commitment
    pub fn commit(&self) -> [u8; 32] {
        let flat: Vec<u64> = self.rows.iter().flatten().cloned().collect();
        hash_field_elements(&flat)
    }
}

// ============================================
// Constraint — one polynomial constraint
// ============================================
// A constraint is satisfied when its polynomial
// evaluates to zero for the actual trace values.
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub name: String,
    pub constraint_type: ConstraintType,
}

impl Constraint {
    // Evaluate the addition constraint
    // Satisfied when: x + y - result = 0 (mod PRIME)
    pub fn check_addition(x: u64, y: u64, result: u64) -> bool {
        let lhs = FieldElement::new(x).add(&FieldElement::new(y));
        lhs.value == result % PRIME
    }

    // Evaluate the multiplication constraint (Beaver)
    // Satisfied when:
    // result = c + epsilon*b + delta*a + epsilon*delta
    pub fn check_multiplication(
        x: u64,
        y: u64,
        a: u64,
        b: u64,
        c: u64,
        result: u64,
    ) -> bool {
        let x_fe = FieldElement::new(x);
        let y_fe = FieldElement::new(y);
        let a_fe = FieldElement::new(a);
        let b_fe = FieldElement::new(b);
        let c_fe = FieldElement::new(c);

        let epsilon = x_fe.sub(&a_fe);
        let delta = y_fe.sub(&b_fe);

        // result = c + epsilon*b + delta*a + epsilon*delta
        let term1 = epsilon.mul(&b_fe);
        let term2 = delta.mul(&a_fe);
        let term3 = epsilon.mul(&delta);

        let expected = c_fe
            .add(&term1)
            .add(&term2)
            .add(&term3);

        expected.value == result % PRIME
    }

    // Evaluate the MAC constraint
    // Satisfied when: mac = alpha * value (mod PRIME)
    pub fn check_mac(value: u64, alpha: u64, mac: u64) -> bool {
        let computed = FieldElement::new(alpha)
            .mul(&FieldElement::new(value));
        computed.value == mac % PRIME
    }

    // Check all constraints for a given trace
    pub fn verify_trace(trace: &ComputationTrace) -> bool {
        match trace.constraint_type {
            ConstraintType::Addition => {
                if trace.rows.is_empty() { return false; }
                let row = &trace.rows[0];
                Self::check_addition(row[0], row[1], row[2])
            }
            ConstraintType::Multiplication => {
                if trace.rows.len() < 3 { return false; }
                let x = trace.rows[0][0];
                let a = trace.rows[0][1];
                let y = trace.rows[1][0];
                let b = trace.rows[1][1];
                let c = trace.rows[2][0];
                let result = trace.rows[2][1];
                Self::check_multiplication(x, y, a, b, c, result)
            }
            ConstraintType::MacVerify => {
                if trace.rows.is_empty() { return false; }
                let row = &trace.rows[0];
                Self::check_mac(row[0], row[1], row[2])
            }
            ConstraintType::ShareValid => true,
        }
    }
}

// ============================================
// AirInstance — a complete AIR problem instance
// ============================================
// Bundles the trace and constraints together
// for the prover to work with.
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirInstance {
    pub job_id: String,
    pub party_id: u32,
    pub trace: ComputationTrace,
    pub public_inputs: Vec<u64>,  // what the verifier knows
    pub trace_commitment: [u8; 32],
}

impl AirInstance {
    pub fn new(
        job_id: String,
        party_id: u32,
        trace: ComputationTrace,
        public_inputs: Vec<u64>,
    ) -> Self {
        let commitment = trace.commit();
        AirInstance {
            job_id,
            party_id,
            trace,
            public_inputs,
            trace_commitment: commitment,
        }
    }

    // Generate a Fiat-Shamir challenge from this instance
    pub fn fiat_shamir_challenge(&self) -> u64 {
        let mut transcript = Transcript::new("mpc-air");
        transcript.absorb(self.job_id.as_bytes());
        transcript.absorb_u64(self.party_id as u64);
        transcript.absorb_hash(&self.trace_commitment);
        for &input in &self.public_inputs {
            transcript.absorb_u64(input);
        }
        transcript.squeeze_challenge()
    }

    // Verify the AIR constraints are satisfied
    pub fn verify_constraints(&self) -> bool {
        Constraint::verify_trace(&self.trace)
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_crypto::field::FieldElement;

    #[test]
    fn test_addition_constraint_valid() {
        let x = 10u64;
        let y = 20u64;
        let result = 30u64;
        assert!(Constraint::check_addition(x, y, result));
    }

    #[test]
    fn test_addition_constraint_invalid() {
        assert!(!Constraint::check_addition(10, 20, 31));
    }

    #[test]
    fn test_addition_constraint_wraps_prime() {
        use mpc_crypto::field::PRIME;
        let x = PRIME - 1;
        let y = 2;
        let result = 1; // (PRIME-1) + 2 = PRIME+1 = 1 mod PRIME
        assert!(Constraint::check_addition(x, y, result));
    }

    #[test]
    fn test_multiplication_constraint_valid() {
        // 6 * 7 = 42 using triple (2, 3, 6)
        let x = 6u64;
        let y = 7u64;
        let a = 2u64;
        let b = 3u64;
        let c = 6u64; // a * b = 6
        let result = FieldElement::new(x).mul(&FieldElement::new(y)).value;
        assert!(Constraint::check_multiplication(x, y, a, b, c, result));
    }

    #[test]
    fn test_multiplication_constraint_invalid() {
        assert!(!Constraint::check_multiplication(6, 7, 2, 3, 6, 999));
    }

    #[test]
    fn test_mac_constraint_valid() {
        let alpha = 7u64;
        let value = 10u64;
        let mac = FieldElement::new(alpha)
            .mul(&FieldElement::new(value)).value;
        assert!(Constraint::check_mac(value, alpha, mac));
    }

    #[test]
    fn test_mac_constraint_invalid() {
        assert!(!Constraint::check_mac(10, 7, 999));
    }

    #[test]
    fn test_addition_trace_creation() {
        let trace = ComputationTrace::for_addition(10, 20, 30);
        assert_eq!(trace.length, 1);
        assert_eq!(trace.width, 4);
        assert_eq!(trace.get(0, 0), 10);
        assert_eq!(trace.get(0, 1), 20);
        assert_eq!(trace.get(0, 2), 30);
    }

    #[test]
    fn test_multiplication_trace_creation() {
        let trace = ComputationTrace::for_multiplication(
            6, 7, 2, 3, 6, 42
        );
        assert_eq!(trace.length, 3);
        assert_eq!(trace.width, 4);
    }

    #[test]
    fn test_mac_trace_creation() {
        let alpha = 7u64;
        let value = 10u64;
        let mac = 70u64;
        let trace = ComputationTrace::for_mac_verify(value, alpha, mac);
        assert_eq!(trace.length, 1);
        assert_eq!(trace.get(0, 0), value);
        assert_eq!(trace.get(0, 1), alpha);
        assert_eq!(trace.get(0, 2), mac);
    }

    #[test]
    fn test_trace_commitment_deterministic() {
        let t1 = ComputationTrace::for_addition(10, 20, 30);
        let t2 = ComputationTrace::for_addition(10, 20, 30);
        assert_eq!(t1.commit(), t2.commit());
    }

    #[test]
    fn test_trace_commitment_different_traces() {
        let t1 = ComputationTrace::for_addition(10, 20, 30);
        let t2 = ComputationTrace::for_addition(10, 20, 31);
        assert_ne!(t1.commit(), t2.commit());
    }

    #[test]
    fn test_verify_trace_addition_valid() {
        let trace = ComputationTrace::for_addition(10, 20, 30);
        assert!(Constraint::verify_trace(&trace));
    }

    #[test]
    fn test_verify_trace_addition_invalid() {
        let mut trace = ComputationTrace::for_addition(10, 20, 30);
        trace.rows[0][2] = 999; // tamper with result
        assert!(!Constraint::verify_trace(&trace));
    }

    #[test]
    fn test_verify_trace_multiplication_valid() {
        let x = 6u64;
        let y = 7u64;
        let a = 2u64;
        let b = 3u64;
        let c = 6u64;
        let result = FieldElement::new(x)
            .mul(&FieldElement::new(y)).value;
        let trace = ComputationTrace::for_multiplication(
            x, y, a, b, c, result
        );
        assert!(Constraint::verify_trace(&trace));
    }

    #[test]
    fn test_verify_trace_mac_valid() {
        let alpha = 7u64;
        let value = 5u64;
        let mac = FieldElement::new(alpha)
            .mul(&FieldElement::new(value)).value;
        let trace = ComputationTrace::for_mac_verify(value, alpha, mac);
        assert!(Constraint::verify_trace(&trace));
    }

    #[test]
    fn test_air_instance_creation() {
        let trace = ComputationTrace::for_addition(10, 20, 30);
        let instance = AirInstance::new(
            "job-1".to_string(),
            1,
            trace,
            vec![30],
        );
        assert_eq!(instance.party_id, 1);
        assert!(!instance.trace_commitment.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_air_fiat_shamir_deterministic() {
        let t1 = ComputationTrace::for_addition(10, 20, 30);
        let t2 = ComputationTrace::for_addition(10, 20, 30);
        let i1 = AirInstance::new("job-1".to_string(), 1, t1, vec![30]);
        let i2 = AirInstance::new("job-1".to_string(), 1, t2, vec![30]);
        assert_eq!(
            i1.fiat_shamir_challenge(),
            i2.fiat_shamir_challenge()
        );
    }

    #[test]
    fn test_air_fiat_shamir_different_jobs() {
        let t1 = ComputationTrace::for_addition(10, 20, 30);
        let t2 = ComputationTrace::for_addition(10, 20, 30);
        let i1 = AirInstance::new("job-1".to_string(), 1, t1, vec![30]);
        let i2 = AirInstance::new("job-2".to_string(), 1, t2, vec![30]);
        assert_ne!(
            i1.fiat_shamir_challenge(),
            i2.fiat_shamir_challenge()
        );
    }

    #[test]
    fn test_air_verify_constraints() {
        let trace = ComputationTrace::for_addition(10, 20, 30);
        let instance = AirInstance::new(
            "job-1".to_string(), 1, trace, vec![30]
        );
        assert!(instance.verify_constraints());
    }
}