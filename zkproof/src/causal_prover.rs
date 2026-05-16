// causal_prover.rs — CLI binary for generating ZK proofs over causal effects
// Reads a CausalProofRequest from stdin as JSON, writes StarkProof to stdout

use std::io::{self, Read};
use serde::{Serialize, Deserialize};
use mpc_zkproof::air::{AirInstance, ComputationTrace};
use mpc_zkproof::prover::MpcProver;
use mpc_zkproof::verifier::MpcVerifier;

#[derive(Debug, Serialize, Deserialize)]
struct CausalProofRequest {
    job_id: String,
    party_id: u32,
    node_id: String,
    active_queries: u64,
    avg_latency_ms: u64,
    causal_effect_ms: u64,
    samples_used: u64,
    retrain_cycle: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CausalProofResponse {
    success: bool,
    node_id: String,
    job_id: String,
    causal_effect_ms: u64,
    proof: Option<serde_json::Value>,
    verified: bool,
    error: Option<String>,
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("Failed to read stdin");

    let request: CausalProofRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            let response = CausalProofResponse {
                success: false,
                node_id: "unknown".to_string(),
                job_id: "unknown".to_string(),
                causal_effect_ms: 0,
                proof: None,
                verified: false,
                error: Some(format!("Failed to parse request: {}", e)),
            };
            println!("{}", serde_json::to_string(&response).unwrap());
            return;
        }
    };

    // Encode causal effect as MAC constraint:
    // causal_effect = mac_key * active_queries
    // where mac_key = avg_latency_ms (the alpha parameter)
    // This proves: the causal effect was correctly computed
    // from the observed active queries and latency
    let value = request.active_queries;
    let alpha = request.avg_latency_ms;
    let mac = request.causal_effect_ms;

    // Build computation trace
    let trace = ComputationTrace::for_mac_verify(value, alpha, mac);

    // Public inputs: what the verifier can see without raw data
    // [causal_effect_ms, samples_used, retrain_cycle]
    let public_inputs = vec![
        request.causal_effect_ms,
        request.samples_used,
        request.retrain_cycle,
    ];

    let instance = AirInstance::new(
        request.job_id.clone(),
        request.party_id,
        trace,
        public_inputs,
    );

    // Generate proof
    let prover = MpcProver::new(request.party_id);
    match prover.prove(&instance) {
        Ok(proof) => {
            // Verify immediately
            let verifier = MpcVerifier::new();
            let report = verifier.verify(&proof);
            let verified = report.is_valid();

            let proof_json: serde_json::Value =
                serde_json::from_str(&proof.to_json().unwrap()).unwrap();

            let response = CausalProofResponse {
                success: true,
                node_id: request.node_id,
                job_id: request.job_id,
                causal_effect_ms: request.causal_effect_ms,
                proof: Some(proof_json),
                verified,
                error: None,
            };
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        Err(e) => {
            let response = CausalProofResponse {
                success: false,
                node_id: request.node_id,
                job_id: request.job_id,
                causal_effect_ms: request.causal_effect_ms,
                proof: None,
                verified: false,
                error: Some(format!("Proof generation failed: {:?}", e)),
            };
            println!("{}", serde_json::to_string(&response).unwrap());
        }
    }
}