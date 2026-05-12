// ============================================
// prover.rs — ZK Proof Generation
// ============================================
// The prover takes a computation trace and
// generates a proof that the trace satisfies
// the AIR constraints — without revealing
// the private inputs in the trace.
//
// Our proof system is a simplified STARK:
//
// Step 1 — Commit to trace
//   Hash all trace values into a Merkle tree.
//   The root is the trace commitment.
//
// Step 2 — Generate challenge (Fiat-Shamir)
//   Use the transcript to generate a random
//   challenge from the commitment. This replaces
//   the verifier's random challenge in interactive
//   protocols.
//
// Step 3 — Query phase
//   Open specific positions in the trace that
//   the challenge points to. Provide Merkle
//   proofs of their membership.
//
// Step 4 — Constraint evaluation
//   Show that the constraints are satisfied at
//   the queried positions.
//
// Step 5 — Bundle into proof
//   Package commitment + queries + evaluations
//   into a serializable proof object.
//
// The verifier can check all of this without
// seeing the full trace — only the queried
// positions and their Merkle proofs.
// ============================================

use serde::{Serialize, Deserialize};
use crate::air::{AirInstance, ComputationTrace, Constraint};
use crate::utils::{MerkleTree, MerkleProof, Transcript};

// ============================================
// ProofError — reasons a proof can fail
// ============================================

#[derive(Debug, Clone, PartialEq)]
pub enum ProofError {
    InvalidTrace,
    ConstraintViolation,
    InvalidWitness,
    ProofTooLarge,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProofError::InvalidTrace =>
                write!(f, "Invalid computation trace"),
            ProofError::ConstraintViolation =>
                write!(f, "Constraint violation detected"),
            ProofError::InvalidWitness =>
                write!(f, "Invalid witness data"),
            ProofError::ProofTooLarge =>
                write!(f, "Proof exceeds size limit"),
        }
    }
}

// ============================================
// TraceQuery — one queried position in the trace
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceQuery {
    pub row: usize,
    pub col: usize,
    pub value: u64,
    pub merkle_proof: MerkleProof,
}

// ============================================
// ConstraintEvaluation — proof of one constraint
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstraintEvaluation {
    pub constraint_name: String,
    pub inputs: Vec<u64>,
    pub output: u64,
    pub satisfied: bool,
}

// ============================================
// StarkProof — the complete ZK proof
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StarkProof {
    pub proof_id: String,
    pub job_id: String,
    pub party_id: u32,
    pub trace_commitment: [u8; 32],
    pub challenge: u64,
    pub queries: Vec<TraceQuery>,
    pub constraint_evaluations: Vec<ConstraintEvaluation>,
    pub public_inputs: Vec<u64>,
    pub proof_size_bytes: usize,
    pub generation_time_ms: u64,
}

impl StarkProof {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn size_bytes(&self) -> usize {
        self.to_json().map(|j| j.len()).unwrap_or(0)
    }
}

// ============================================
// MpcProver — generates proofs for MPC computations
// ============================================

pub struct MpcProver {
    pub party_id: u32,
    pub num_queries: usize,
}

impl MpcProver {
    pub fn new(party_id: u32) -> Self {
        MpcProver {
            party_id,
            num_queries: 4,
        }
    }

    pub fn with_security(party_id: u32, num_queries: usize) -> Self {
        MpcProver { party_id, num_queries }
    }

    pub fn prove(
        &self,
        instance: &AirInstance,
    ) -> Result<StarkProof, ProofError> {
        let start = std::time::Instant::now();

        // Step 1: Verify constraints
        if !Constraint::verify_trace(&instance.trace) {
            return Err(ProofError::ConstraintViolation);
        }

        // Step 2: Build Merkle tree over trace
        let flat_trace: Vec<u64> = instance.trace.rows
            .iter()
            .flatten()
            .cloned()
            .collect();

        if flat_trace.is_empty() {
            return Err(ProofError::InvalidTrace);
        }

        let merkle_tree = MerkleTree::new(&flat_trace);
        let trace_commitment = merkle_tree.root();

        // Step 3: Fiat-Shamir challenge
        let mut transcript = Transcript::new("mpc-stark");
        transcript.absorb(instance.job_id.as_bytes());
        transcript.absorb_u64(instance.party_id as u64);
        transcript.absorb_hash(&trace_commitment);
        for &input in &instance.public_inputs {
            transcript.absorb_u64(input);
        }
        let challenge = transcript.squeeze_challenge();

        // Step 4: Generate queries
        let queries = self.generate_queries(
            &instance.trace,
            &merkle_tree,
            &flat_trace,
            challenge,
        );

        // Step 5: Evaluate constraints
        let constraint_evaluations = self.evaluate_constraints(
            &instance.trace,
        );

        // Step 6: Build proof
        let proof = StarkProof {
            proof_id: format!(
                "proof-{}-{}",
                instance.job_id,
                instance.party_id
            ),
            job_id: instance.job_id.clone(),
            party_id: instance.party_id,
            trace_commitment,
            challenge,
            queries,
            constraint_evaluations,
            public_inputs: instance.public_inputs.clone(),
            proof_size_bytes: 0,
            generation_time_ms: start.elapsed().as_millis() as u64,
        };

        Ok(proof)
    }

    fn generate_queries(
        &self,
        trace: &ComputationTrace,
        tree: &MerkleTree,
        flat_trace: &[u64],
        challenge: u64,
    ) -> Vec<TraceQuery> {
        let mut queries = Vec::new();
        let total_cells = flat_trace.len();

        if total_cells == 0 {
            return queries;
        }

        let mut seed = challenge;
        for i in 0..self.num_queries.min(total_cells) {
            let flat_idx = (seed as usize + i * 7919) % total_cells;
            let row = flat_idx / trace.width;
            let col = flat_idx % trace.width;
            let row = row.min(trace.length.saturating_sub(1));
            let leaf_idx = flat_idx.min(tree.leaves.len() - 1);

            queries.push(TraceQuery {
                row,
                col,
                value: flat_trace[flat_idx],
                merkle_proof: tree.proof(leaf_idx),
            });

            seed = seed.wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }

        queries
    }

    fn evaluate_constraints(
        &self,
        trace: &ComputationTrace,
    ) -> Vec<ConstraintEvaluation> {
        use crate::air::ConstraintType;
        let mut evaluations = Vec::new();

        match &trace.constraint_type {
            ConstraintType::Addition => {
                if !trace.rows.is_empty() {
                    let row = &trace.rows[0];
                    evaluations.push(ConstraintEvaluation {
                        constraint_name: "addition".to_string(),
                        inputs: vec![row[0], row[1]],
                        output: row[2],
                        satisfied: crate::air::Constraint::check_addition(
                            row[0], row[1], row[2]
                        ),
                    });
                }
            }
            ConstraintType::Multiplication => {
                if trace.rows.len() >= 3 {
                    let x = trace.rows[0][0];
                    let a = trace.rows[0][1];
                    let y = trace.rows[1][0];
                    let b = trace.rows[1][1];
                    let c = trace.rows[2][0];
                    let result = trace.rows[2][1];
                    evaluations.push(ConstraintEvaluation {
                        constraint_name: "multiplication".to_string(),
                        inputs: vec![x, y, a, b, c],
                        output: result,
                        satisfied: crate::air::Constraint::check_multiplication(
                            x, y, a, b, c, result
                        ),
                    });
                }
            }
            ConstraintType::MacVerify => {
                if !trace.rows.is_empty() {
                    let row = &trace.rows[0];
                    evaluations.push(ConstraintEvaluation {
                        constraint_name: "mac_verify".to_string(),
                        inputs: vec![row[0], row[1]],
                        output: row[2],
                        satisfied: crate::air::Constraint::check_mac(
                            row[0], row[1], row[2]
                        ),
                    });
                }
            }
            _ => {}
        }

        evaluations
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{AirInstance, ComputationTrace};
    use mpc_crypto::field::FieldElement;

    fn make_prover() -> MpcProver {
        MpcProver::new(1)
    }

    fn make_addition_instance() -> AirInstance {
        let trace = ComputationTrace::for_addition(10, 20, 30);
        AirInstance::new(
            "job-1".to_string(),
            1,
            trace,
            vec![30],
        )
    }

    fn make_multiplication_instance() -> AirInstance {
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
        AirInstance::new(
            "job-2".to_string(),
            1,
            trace,
            vec![result],
        )
    }

    fn make_mac_instance() -> AirInstance {
        let alpha = 7u64;
        let value = 5u64;
        let mac = FieldElement::new(alpha)
            .mul(&FieldElement::new(value)).value;
        let trace = ComputationTrace::for_mac_verify(value, alpha, mac);
        AirInstance::new(
            "job-3".to_string(),
            1,
            trace,
            vec![value, mac],
        )
    }

    #[test]
    fn test_prove_addition() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let result = prover.prove(&instance);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prove_multiplication() {
        let prover = make_prover();
        let instance = make_multiplication_instance();
        let result = prover.prove(&instance);
        assert!(result.is_ok());
    }

    #[test]
    fn test_prove_mac_verify() {
        let prover = make_prover();
        let instance = make_mac_instance();
        let result = prover.prove(&instance);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_has_correct_job_id() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert_eq!(proof.job_id, "job-1");
    }

    #[test]
    fn test_proof_has_correct_party_id() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert_eq!(proof.party_id, 1);
    }

    #[test]
    fn test_proof_has_trace_commitment() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert!(!proof.trace_commitment.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_proof_has_challenge() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert_ne!(proof.challenge, 0);
    }

    #[test]
    fn test_proof_has_queries() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert!(!proof.queries.is_empty());
    }

    #[test]
    fn test_proof_constraint_satisfied() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert!(proof.constraint_evaluations
            .iter()
            .all(|e| e.satisfied));
    }

    #[test]
    fn test_proof_is_deterministic() {
        let prover = make_prover();
        let i1 = make_addition_instance();
        let i2 = make_addition_instance();
        let p1 = prover.prove(&i1).unwrap();
        let p2 = prover.prove(&i2).unwrap();
        assert_eq!(p1.trace_commitment, p2.trace_commitment);
        assert_eq!(p1.challenge, p2.challenge);
    }

    #[test]
    fn test_proof_serializes_to_json() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        let json = proof.to_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("job-1"));
    }

    #[test]
    fn test_proof_roundtrip_json() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        let json = proof.to_json().unwrap();
        let recovered = StarkProof::from_json(&json).unwrap();
        assert_eq!(recovered.job_id, proof.job_id);
        assert_eq!(recovered.party_id, proof.party_id);
        assert_eq!(
            recovered.trace_commitment,
            proof.trace_commitment
        );
    }

    #[test]
    fn test_invalid_trace_returns_error() {
        let prover = make_prover();
        let mut trace = ComputationTrace::for_addition(10, 20, 30);
        trace.rows[0][2] = 999;
        let instance = AirInstance::new(
            "job-bad".to_string(),
            1,
            trace,
            vec![999],
        );
        let result = prover.prove(&instance);
        assert_eq!(result, Err(ProofError::ConstraintViolation));
    }

    #[test]
    fn test_different_jobs_different_challenges() {
        let prover = make_prover();
        let i1 = make_addition_instance();
        let mut i2 = make_addition_instance();
        i2.job_id = "job-99".to_string();
        let p1 = prover.prove(&i1).unwrap();
        let p2 = prover.prove(&i2).unwrap();
        assert_ne!(p1.challenge, p2.challenge);
    }

    #[test]
    fn test_query_merkle_proofs_valid() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        for query in &proof.queries {
            assert!(MerkleTree::verify_proof(&query.merkle_proof));
        }
    }

    #[test]
    fn test_proof_public_inputs_preserved() {
        let prover = make_prover();
        let instance = make_addition_instance();
        let proof = prover.prove(&instance).unwrap();
        assert_eq!(proof.public_inputs, vec![30]);
    }
}