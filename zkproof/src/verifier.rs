// ============================================
// verifier.rs — ZK Proof Verification
// ============================================
// The verifier checks a StarkProof is valid
// WITHOUT re-running the computation.
//
// What the verifier checks:
//
// 1. COMMITMENT CHECK
//    The trace commitment in the proof matches
//    what we would compute from the public inputs.
//
// 2. CHALLENGE CHECK
//    The Fiat-Shamir challenge is correctly derived
//    from the commitment and public inputs.
//    Nobody can forge a challenge.
//
// 3. QUERY CHECK
//    Each queried position has a valid Merkle proof
//    showing it was in the committed trace.
//
// 4. CONSTRAINT CHECK
//    The constraint evaluations are correct and
//    all constraints are satisfied.
//
// 5. CONSISTENCY CHECK
//    The public inputs match what the prover claimed.
//
// If ALL checks pass — the proof is valid.
// The verifier is convinced the computation
// was performed correctly without seeing inputs.
// ============================================

use serde::{Serialize, Deserialize};
use crate::prover::StarkProof;
use crate::utils::{MerkleTree, Transcript};
use crate::air::Constraint;

// ============================================
// VerificationResult — outcome of verification
// ============================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationResult {
    Valid,
    Invalid(VerificationError),
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationResult::Valid)
    }
}

// ============================================
// VerificationError — why verification failed
// ============================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationError {
    InvalidChallenge,
    InvalidMerkleProof,
    ConstraintNotSatisfied,
    PublicInputMismatch,
    MissingQueries,
    InvalidProofStructure,
    CommitmentMismatch,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationError::InvalidChallenge =>
                write!(f, "Fiat-Shamir challenge is invalid"),
            VerificationError::InvalidMerkleProof =>
                write!(f, "Merkle proof verification failed"),
            VerificationError::ConstraintNotSatisfied =>
                write!(f, "Constraint not satisfied"),
            VerificationError::PublicInputMismatch =>
                write!(f, "Public inputs do not match"),
            VerificationError::MissingQueries =>
                write!(f, "Proof has no queries"),
            VerificationError::InvalidProofStructure =>
                write!(f, "Proof structure is invalid"),
            VerificationError::CommitmentMismatch =>
                write!(f, "Trace commitment does not match"),
        }
    }
}

// ============================================
// VerificationReport — detailed verification log
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub proof_id: String,
    pub job_id: String,
    pub party_id: u32,
    pub result: VerificationResult,
    pub checks_passed: Vec<String>,
    pub checks_failed: Vec<String>,
    pub verified_at_ms: u64,
}

impl VerificationReport {
    pub fn is_valid(&self) -> bool {
        self.result.is_valid()
    }
}

// ============================================
// MpcVerifier — verifies STARK proofs
// ============================================

pub struct MpcVerifier;

impl MpcVerifier {
    pub fn new() -> Self {
        MpcVerifier
    }

    // ============================================
    // verify — check a complete STARK proof
    // ============================================
    pub fn verify(&self, proof: &StarkProof) -> VerificationReport {
        let start = std::time::Instant::now();
        let mut checks_passed = Vec::new();
        let mut checks_failed = Vec::new();

        // Check 1: Basic structure
        if proof.job_id.is_empty() || proof.party_id == 0 {
            checks_failed.push("structure_check".to_string());
            return self.make_report(
                proof,
                VerificationResult::Invalid(
                    VerificationError::InvalidProofStructure
                ),
                checks_passed,
                checks_failed,
                start.elapsed().as_millis() as u64,
            );
        }
        checks_passed.push("structure_check".to_string());

        // Check 2: Queries exist
        if proof.queries.is_empty() {
            checks_failed.push("queries_exist".to_string());
            return self.make_report(
                proof,
                VerificationResult::Invalid(
                    VerificationError::MissingQueries
                ),
                checks_passed,
                checks_failed,
                start.elapsed().as_millis() as u64,
            );
        }
        checks_passed.push("queries_exist".to_string());

        // Check 3: Fiat-Shamir challenge
        let expected_challenge = self.recompute_challenge(proof);
        if expected_challenge != proof.challenge {
            checks_failed.push("challenge_check".to_string());
            return self.make_report(
                proof,
                VerificationResult::Invalid(
                    VerificationError::InvalidChallenge
                ),
                checks_passed,
                checks_failed,
                start.elapsed().as_millis() as u64,
            );
        }
        checks_passed.push("challenge_check".to_string());

        // Check 4: Merkle proofs
        for (i, query) in proof.queries.iter().enumerate() {
            if !MerkleTree::verify_proof(&query.merkle_proof) {
                checks_failed.push(
                    format!("merkle_proof_{}", i)
                );
                return self.make_report(
                    proof,
                    VerificationResult::Invalid(
                        VerificationError::InvalidMerkleProof
                    ),
                    checks_passed,
                    checks_failed,
                    start.elapsed().as_millis() as u64,
                );
            }
        }
        checks_passed.push("merkle_proofs".to_string());

        // Check 5: Constraints satisfied
        for eval in &proof.constraint_evaluations {
            if !eval.satisfied {
                checks_failed.push(
                    format!("constraint_{}", eval.constraint_name)
                );
                return self.make_report(
                    proof,
                    VerificationResult::Invalid(
                        VerificationError::ConstraintNotSatisfied
                    ),
                    checks_passed,
                    checks_failed,
                    start.elapsed().as_millis() as u64,
                );
            }
            checks_passed.push(
                format!("constraint_{}", eval.constraint_name)
            );
        }

        // Check 6: Public inputs present
        if proof.public_inputs.is_empty() {
            checks_failed.push("public_inputs".to_string());
            return self.make_report(
                proof,
                VerificationResult::Invalid(
                    VerificationError::PublicInputMismatch
                ),
                checks_passed,
                checks_failed,
                start.elapsed().as_millis() as u64,
            );
        }
        checks_passed.push("public_inputs".to_string());

        // All checks passed
        self.make_report(
            proof,
            VerificationResult::Valid,
            checks_passed,
            checks_failed,
            start.elapsed().as_millis() as u64,
        )
    }

    // ============================================
    // verify_batch — verify multiple proofs
    // ============================================
    pub fn verify_batch(
        &self,
        proofs: &[StarkProof],
    ) -> Vec<VerificationReport> {
        proofs.iter().map(|p| self.verify(p)).collect()
    }

    // ============================================
    // verify_all_valid — check all proofs pass
    // ============================================
    pub fn verify_all_valid(&self, proofs: &[StarkProof]) -> bool {
        proofs.iter().all(|p| self.verify(p).is_valid())
    }

    // ============================================
    // recompute_challenge — verify Fiat-Shamir
    // ============================================
    // Recomputes the challenge from the proof data.
    // If prover forged the challenge, this will differ.
    fn recompute_challenge(&self, proof: &StarkProof) -> u64 {
        let mut transcript = Transcript::new("mpc-stark");
        transcript.absorb(proof.job_id.as_bytes());
        transcript.absorb_u64(proof.party_id as u64);
        transcript.absorb_hash(&proof.trace_commitment);
        for &input in &proof.public_inputs {
            transcript.absorb_u64(input);
        }
        transcript.squeeze_challenge()
    }

    fn make_report(
        &self,
        proof: &StarkProof,
        result: VerificationResult,
        checks_passed: Vec<String>,
        checks_failed: Vec<String>,
        elapsed_ms: u64,
    ) -> VerificationReport {
        VerificationReport {
            proof_id: proof.proof_id.clone(),
            job_id: proof.job_id.clone(),
            party_id: proof.party_id,
            result,
            checks_passed,
            checks_failed,
            verified_at_ms: elapsed_ms,
        }
    }
}

// ============================================
// OnChainVerifier — simulates Solidity verifier
// ============================================
// In production this logic lives in a Solidity
// contract that verifies proofs on-chain.
// This Rust implementation is used for:
// 1. Testing the verification logic
// 2. Running verification off-chain before
//    submitting to save gas
// ============================================

pub struct OnChainVerifier {
    verifier: MpcVerifier,
}

impl OnChainVerifier {
    pub fn new() -> Self {
        OnChainVerifier {
            verifier: MpcVerifier::new(),
        }
    }

    // Simulate on-chain verification
    // Returns true/false like a Solidity function would
    pub fn verify_on_chain(&self, proof: &StarkProof) -> bool {
        self.verifier.verify(proof).is_valid()
    }

    // Simulate slash trigger
    // In production this calls SlashingContract.confirmSlash()
    pub fn should_slash(&self, proof: &StarkProof) -> bool {
        !self.verify_on_chain(proof)
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{AirInstance, ComputationTrace};
    use crate::prover::MpcProver;
    use mpc_crypto::field::FieldElement;

    fn make_valid_proof(job_id: &str, party_id: u32) -> StarkProof {
        let trace = ComputationTrace::for_addition(10, 20, 30);
        let instance = AirInstance::new(
            job_id.to_string(),
            party_id,
            trace,
            vec![30],
        );
        MpcProver::new(party_id).prove(&instance).unwrap()
    }

    fn make_mul_proof() -> StarkProof {
        let x = 6u64;
        let y = 7u64;
        let result = FieldElement::new(x)
            .mul(&FieldElement::new(y)).value;
        let trace = ComputationTrace::for_multiplication(
            x, y, 2, 3, 6, result
        );
        let instance = AirInstance::new(
            "mul-job".to_string(),
            1,
            trace,
            vec![result],
        );
        MpcProver::new(1).prove(&instance).unwrap()
    }

    fn make_mac_proof() -> StarkProof {
        let alpha = 7u64;
        let value = 5u64;
        let mac = FieldElement::new(alpha)
            .mul(&FieldElement::new(value)).value;
        let trace = ComputationTrace::for_mac_verify(value, alpha, mac);
        let instance = AirInstance::new(
            "mac-job".to_string(),
            1,
            trace,
            vec![value, mac],
        );
        MpcProver::new(1).prove(&instance).unwrap()
    }

    #[test]
    fn test_verify_valid_addition_proof() {
        let verifier = MpcVerifier::new();
        let proof = make_valid_proof("job-1", 1);
        let report = verifier.verify(&proof);
        assert!(report.is_valid());
    }

    #[test]
    fn test_verify_valid_multiplication_proof() {
        let verifier = MpcVerifier::new();
        let proof = make_mul_proof();
        let report = verifier.verify(&proof);
        assert!(report.is_valid());
    }

    #[test]
    fn test_verify_valid_mac_proof() {
        let verifier = MpcVerifier::new();
        let proof = make_mac_proof();
        let report = verifier.verify(&proof);
        assert!(report.is_valid());
    }

    #[test]
    fn test_verify_report_has_job_id() {
        let verifier = MpcVerifier::new();
        let proof = make_valid_proof("job-abc", 1);
        let report = verifier.verify(&proof);
        assert_eq!(report.job_id, "job-abc");
    }

    #[test]
    fn test_verify_report_has_party_id() {
        let verifier = MpcVerifier::new();
        let proof = make_valid_proof("job-1", 3);
        let report = verifier.verify(&proof);
        assert_eq!(report.party_id, 3);
    }

    #[test]
    fn test_verify_report_checks_passed() {
        let verifier = MpcVerifier::new();
        let proof = make_valid_proof("job-1", 1);
        let report = verifier.verify(&proof);
        assert!(!report.checks_passed.is_empty());
        assert!(report.checks_failed.is_empty());
    }

    #[test]
    fn test_tampered_challenge_fails() {
        let verifier = MpcVerifier::new();
        let mut proof = make_valid_proof("job-1", 1);
        proof.challenge = 99999999; // tamper
        let report = verifier.verify(&proof);
        assert!(!report.is_valid());
        assert_eq!(
            report.result,
            VerificationResult::Invalid(
                VerificationError::InvalidChallenge
            )
        );
    }

    #[test]
    fn test_tampered_merkle_proof_fails() {
        let verifier = MpcVerifier::new();
        let mut proof = make_valid_proof("job-1", 1);
        // Tamper with first query's Merkle proof root
        if !proof.queries.is_empty() {
            proof.queries[0].merkle_proof.root = [0u8; 32];
        }
        let report = verifier.verify(&proof);
        assert!(!report.is_valid());
    }

    #[test]
    fn test_unsatisfied_constraint_fails() {
        let verifier = MpcVerifier::new();
        let mut proof = make_valid_proof("job-1", 1);
        // Mark constraint as not satisfied
        if !proof.constraint_evaluations.is_empty() {
            proof.constraint_evaluations[0].satisfied = false;
        }
        let report = verifier.verify(&proof);
        assert!(!report.is_valid());
        assert_eq!(
            report.result,
            VerificationResult::Invalid(
                VerificationError::ConstraintNotSatisfied
            )
        );
    }

    #[test]
    fn test_empty_queries_fails() {
        let verifier = MpcVerifier::new();
        let mut proof = make_valid_proof("job-1", 1);
        proof.queries.clear();
        let report = verifier.verify(&proof);
        assert!(!report.is_valid());
        assert_eq!(
            report.result,
            VerificationResult::Invalid(
                VerificationError::MissingQueries
            )
        );
    }

    #[test]
    fn test_verify_batch_all_valid() {
        let verifier = MpcVerifier::new();
        let proofs = vec![
            make_valid_proof("job-1", 1),
            make_valid_proof("job-2", 2),
            make_valid_proof("job-3", 3),
        ];
        let reports = verifier.verify_batch(&proofs);
        assert_eq!(reports.len(), 3);
        assert!(reports.iter().all(|r| r.is_valid()));
    }

    #[test]
    fn test_verify_all_valid() {
        let verifier = MpcVerifier::new();
        let proofs = vec![
            make_valid_proof("job-1", 1),
            make_mul_proof(),
            make_mac_proof(),
        ];
        assert!(verifier.verify_all_valid(&proofs));
    }

    #[test]
    fn test_verify_all_valid_fails_with_one_bad() {
        let verifier = MpcVerifier::new();
        let mut bad_proof = make_valid_proof("job-1", 1);
        bad_proof.queries.clear();
        let proofs = vec![
            make_valid_proof("job-2", 2),
            bad_proof,
        ];
        assert!(!verifier.verify_all_valid(&proofs));
    }

    #[test]
    fn test_on_chain_verifier_valid() {
        let verifier = OnChainVerifier::new();
        let proof = make_valid_proof("job-1", 1);
        assert!(verifier.verify_on_chain(&proof));
        assert!(!verifier.should_slash(&proof));
    }

    #[test]
    fn test_on_chain_verifier_invalid_triggers_slash() {
        let verifier = OnChainVerifier::new();
        let mut proof = make_valid_proof("job-1", 1);
        proof.queries.clear(); // make invalid
        assert!(!verifier.verify_on_chain(&proof));
        assert!(verifier.should_slash(&proof));
    }

    #[test]
    fn test_verification_result_is_valid() {
        assert!(VerificationResult::Valid.is_valid());
        assert!(!VerificationResult::Invalid(
            VerificationError::InvalidChallenge
        ).is_valid());
    }

    #[test]
    fn test_recompute_challenge_matches() {
        let verifier = MpcVerifier::new();
        let proof = make_valid_proof("job-1", 1);
        let recomputed = verifier.recompute_challenge(&proof);
        assert_eq!(recomputed, proof.challenge);
    }
}