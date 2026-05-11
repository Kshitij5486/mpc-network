// ============================================
// node.rs — MPC Network Node
// ============================================
// A Node represents one participant in the
// MPC network. Each party runs one node.
//
// The node holds:
// - its own party ID (1, 2, 3, ...)
// - its private secret input
// - the MAC key for authentication
// - a list of connected peer addresses
// - the current job state
// ============================================

use std::collections::HashMap;
use mpc_crypto::mac::MacKey;
use crate::message::{Message, MessageEnvelope, Operation};

// ============================================
// NodeConfig — configuration for a node
// ============================================

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub party_id: u32,
    pub party_count: u32,
    pub listen_addr: String,   // e.g. "127.0.0.1:8001"
    pub peer_addrs: Vec<String>, // addresses of other nodes
}

impl NodeConfig {
    pub fn new(
        party_id: u32,
        party_count: u32,
        listen_addr: &str,
        peer_addrs: Vec<String>,
    ) -> Self {
        NodeConfig {
            party_id,
            party_count,
            listen_addr: listen_addr.to_string(),
            peer_addrs,
        }
    }
}

// ============================================
// JobState — state of a computation job
// ============================================

#[derive(Debug, Clone, PartialEq)]
pub enum JobState {
    Idle,                    // no job running
    WaitingForPeers,         // announced, waiting for ready signals
    CollectingShares,        // waiting for all shares to arrive
    Computing,               // running the MPC protocol
    WaitingForResults,       // waiting for other parties' outputs
    Complete(u64),           // job done, result is the u64
    Failed(String),          // job failed with reason
}

// ============================================
// Job — one computation job
// ============================================

#[derive(Debug, Clone)]
pub struct Job {
    pub job_id: String,
    pub operation: Operation,
    pub my_input: u64,           // this party's private input
    pub state: JobState,
    pub received_shares: HashMap<u32, (u64, u64, u64)>, // party_id -> (x, y, mac)
    pub ready_parties: Vec<u32>, // parties that sent JobReady
    pub open_shares: HashMap<u32, (u64, u64)>, // party_id -> (value, mac)
}

impl Job {
    pub fn new(job_id: String, operation: Operation, my_input: u64) -> Self {
        Job {
            job_id,
            operation,
            my_input,
            state: JobState::WaitingForPeers,
            received_shares: HashMap::new(),
            ready_parties: Vec::new(),
            open_shares: HashMap::new(),
        }
    }

    // Check if all parties have sent JobReady
    pub fn all_parties_ready(&self, party_count: u32) -> bool {
        self.ready_parties.len() >= party_count as usize
    }

    // Check if all shares have been received
    pub fn all_shares_received(&self, party_count: u32) -> bool {
        self.received_shares.len() >= party_count as usize
    }

    // Check if all open shares received for reconstruction
    pub fn all_open_shares_received(&self, party_count: u32) -> bool {
        self.open_shares.len() >= party_count as usize
    }
}

// ============================================
// MpcNode — the main node struct
// ============================================

pub struct MpcNode {
    pub config: NodeConfig,
    pub mac_key: MacKey,
    pub current_job: Option<Job>,
    pub message_log: Vec<MessageEnvelope>,
}

impl MpcNode {
    // Create a new node with given config
    pub fn new(config: NodeConfig) -> Self {
        MpcNode {
            config,
            mac_key: MacKey::generate(),
            current_job: None,
            message_log: Vec::new(),
        }
    }

    // Get this node's party ID
    pub fn party_id(&self) -> u32 {
        self.config.party_id
    }

    // Get total party count
    pub fn party_count(&self) -> u32 {
        self.config.party_count
    }

    // Check if node is currently busy with a job
    pub fn is_busy(&self) -> bool {
        self.current_job.is_some()
    }

    // Start a new job with this party's input
    pub fn start_job(
        &mut self,
        job_id: String,
        operation: Operation,
        my_input: u64,
    ) -> Result<(), String> {
        if self.is_busy() {
            return Err("Node is already running a job".to_string());
        }
        self.current_job = Some(Job::new(job_id, operation, my_input));
        Ok(())
    }

    // Process incoming message and return response messages
    pub fn handle_message(
        &mut self,
        envelope: MessageEnvelope,
    ) -> Vec<MessageEnvelope> {
        self.message_log.push(envelope.clone());
        let mut responses = Vec::new();

        match &envelope.payload {
            Message::Hello { from_party, party_count, version: _ } => {
                // Respond with HelloAck
                let ack = Message::HelloAck {
                    from_party: self.party_id(),
                    accepted: true,
                };
                responses.push(MessageEnvelope::new(
                    self.party_id(),
                    *from_party,
                    ack,
                ));
            }

            Message::JobAnnounce { job_id, party_count: _, operation } => {
                // Accept job and signal ready
                let _ = self.start_job(
                    job_id.clone(),
                    operation.clone(),
                    0, // input set separately
                );
                let ready = Message::JobReady {
                    job_id: job_id.clone(),
                    from_party: self.party_id(),
                };
                responses.push(MessageEnvelope::new(
                    self.party_id(),
                    255, // broadcast
                    ready,
                ));
            }

            Message::JobReady { job_id: _, from_party } => {
                if let Some(job) = &mut self.current_job {
                    if !job.ready_parties.contains(from_party) {
                        job.ready_parties.push(*from_party);
                    }
                }
            }

            Message::ShareMsg {
                job_id: _,
                from_party,
                to_party: _,
                share_x,
                share_y,
                mac_tag,
            } => {
                if let Some(job) = &mut self.current_job {
                    job.received_shares.insert(
                        *from_party,
                        (*share_x, *share_y, *mac_tag),
                    );
                    // Acknowledge receipt
                    let ack = Message::SharesReceived {
                        job_id: job.job_id.clone(),
                        from_party: self.party_id(),
                    };
                    responses.push(MessageEnvelope::new(
                        self.party_id(),
                        *from_party,
                        ack,
                    ));
                }
            }

            Message::OpenShare {
                job_id: _,
                from_party,
                share_value,
                mac_tag,
            } => {
                if let Some(job) = &mut self.current_job {
                    job.open_shares.insert(
                        *from_party,
                        (*share_value, *mac_tag),
                    );
                }
            }

            Message::Ping { from_party, timestamp } => {
                let pong = Message::Pong {
                    from_party: self.party_id(),
                    timestamp: *timestamp,
                };
                responses.push(MessageEnvelope::new(
                    self.party_id(),
                    *from_party,
                    pong,
                ));
            }

            Message::Abort { job_id: _, from_party: _, reason } => {
                if let Some(job) = &mut self.current_job {
                    job.state = JobState::Failed(reason.clone());
                }
            }

            _ => {
                // Other messages handled by network layer
            }
        }

        responses
    }

    // Complete current job with a result
    pub fn complete_job(&mut self, result: u64) {
        if let Some(job) = &mut self.current_job {
            job.state = JobState::Complete(result);
        }
    }

    // Get current job state
    pub fn job_state(&self) -> Option<&JobState> {
        self.current_job.as_ref().map(|j| &j.state)
    }

    // Clear completed job
    pub fn clear_job(&mut self) {
        if let Some(job) = &self.current_job {
            matches!(job.state, JobState::Complete(_) | JobState::Failed(_));
        }
        self.current_job = None;
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(party_id: u32) -> MpcNode {
        let config = NodeConfig::new(
            party_id,
            3,
            &format!("127.0.0.1:800{}", party_id),
            vec![],
        );
        MpcNode::new(config)
    }

    #[test]
    fn test_node_creation() {
        let node = make_node(1);
        assert_eq!(node.party_id(), 1);
        assert_eq!(node.party_count(), 3);
        assert!(!node.is_busy());
    }

    #[test]
    fn test_node_start_job() {
        let mut node = make_node(1);
        let result = node.start_job(
            "job-1".to_string(),
            Operation::Sum,
            42,
        );
        assert!(result.is_ok());
        assert!(node.is_busy());
    }

    #[test]
    fn test_node_cannot_start_two_jobs() {
        let mut node = make_node(1);
        node.start_job("job-1".to_string(), Operation::Sum, 10).unwrap();
        let result = node.start_job("job-2".to_string(), Operation::Sum, 20);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_handles_hello() {
        let mut node = make_node(1);
        let hello = Message::Hello {
            from_party: 2,
            party_count: 3,
            version: "0.1.0".to_string(),
        };
        let envelope = MessageEnvelope::new(2, 1, hello);
        let responses = node.handle_message(envelope);
        assert_eq!(responses.len(), 1);
        matches!(responses[0].payload, Message::HelloAck { .. });
    }

    #[test]
    fn test_node_handles_ping() {
        let mut node = make_node(1);
        let ping = Message::Ping { from_party: 2, timestamp: 9999 };
        let envelope = MessageEnvelope::new(2, 1, ping);
        let responses = node.handle_message(envelope);
        assert_eq!(responses.len(), 1);
        matches!(responses[0].payload, Message::Pong { .. });
    }

    #[test]
    fn test_node_handles_share_message() {
        let mut node = make_node(1);
        node.start_job("job-1".to_string(), Operation::Sum, 10).unwrap();
        let share = Message::ShareMsg {
            job_id: "job-1".to_string(),
            from_party: 2,
            to_party: 1,
            share_x: 2,
            share_y: 555,
            mac_tag: 777,
        };
        let envelope = MessageEnvelope::new(2, 1, share);
        node.handle_message(envelope);
        let job = node.current_job.as_ref().unwrap();
        assert!(job.received_shares.contains_key(&2));
    }

    #[test]
    fn test_node_handles_abort() {
        let mut node = make_node(1);
        node.start_job("job-1".to_string(), Operation::Sum, 10).unwrap();
        let abort = Message::Abort {
            job_id: "job-1".to_string(),
            from_party: 2,
            reason: "test abort".to_string(),
        };
        let envelope = MessageEnvelope::new(2, 1, abort);
        node.handle_message(envelope);
        matches!(
            node.job_state(),
            Some(JobState::Failed(_))
        );
    }

    #[test]
    fn test_node_complete_job() {
        let mut node = make_node(1);
        node.start_job("job-1".to_string(), Operation::Sum, 10).unwrap();
        node.complete_job(42);
        matches!(node.job_state(), Some(JobState::Complete(42)));
    }

    #[test]
    fn test_job_tracks_ready_parties() {
        let mut job = Job::new(
            "job-1".to_string(),
            Operation::Sum,
            10,
        );
        job.ready_parties.push(1);
        job.ready_parties.push(2);
        assert!(!job.all_parties_ready(3));
        job.ready_parties.push(3);
        assert!(job.all_parties_ready(3));
    }

    #[test]
    fn test_node_config() {
        let config = NodeConfig::new(
            2,
            3,
            "127.0.0.1:8002",
            vec!["127.0.0.1:8001".to_string()],
        );
        assert_eq!(config.party_id, 2);
        assert_eq!(config.listen_addr, "127.0.0.1:8002");
        assert_eq!(config.peer_addrs.len(), 1);
    }
}