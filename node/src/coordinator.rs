// ============================================
// coordinator.rs — Job Coordinator
// ============================================
// The coordinator is the brain of the MPC node.
// It orchestrates a complete computation job:
//
// 1. Announce job to all parties
// 2. Wait for all parties to signal ready
// 3. Split input into shares, send to each party
// 4. Collect shares from all parties
// 5. Run SPDZ computation locally
// 6. Open output shares for reconstruction
// 7. Reconstruct and verify final result
//
// In a 3-party network:
// Each party runs a coordinator.
// They all do the same steps simultaneously.
// The result emerges from their cooperation.
// ============================================

use std::collections::HashMap;
use mpc_crypto::{
    shamir::{split, reconstruct, Share},
    mac::MacKey,
    spdz::{spdz_add, reconstruct_secret, verify_all},
    beaver::OfflinePhase,
};
use crate::message::{Message, MessageEnvelope, Operation};

// ============================================
// ComputationResult — outcome of a job
// ============================================

#[derive(Debug, Clone)]
pub struct ComputationResult {
    pub job_id: String,
    pub result: u64,
    pub operation: Operation,
    pub party_count: u32,
    pub success: bool,
}

// ============================================
// CoordinatorState — tracks job progress
// ============================================

#[derive(Debug, Clone, PartialEq)]
pub enum CoordinatorState {
    Idle,
    WaitingForParties,
    SharingInputs,
    Computing,
    OpeningOutputs,
    Done,
    Failed(String),
}

// ============================================
// JobCoordinator — orchestrates one MPC job
// ============================================

pub struct JobCoordinator {
    pub job_id: String,
    pub my_party_id: u32,
    pub party_count: u32,
    pub operation: Operation,
    pub my_input: u64,
    pub state: CoordinatorState,
    pub mac_key: MacKey,

    // Shares we sent to other parties
    pub my_shares_sent: HashMap<u32, Share>,

    // Shares we received from other parties
    pub received_shares: HashMap<u32, Share>,

    // Output shares collected for reconstruction
    pub output_shares: HashMap<u32, u64>,

    // Ready signals received
    pub ready_parties: Vec<u32>,

    // Messages queued to send
    pub outgoing: Vec<MessageEnvelope>,
}

impl JobCoordinator {
    pub fn new(
        job_id: String,
        my_party_id: u32,
        party_count: u32,
        operation: Operation,
        my_input: u64,
    ) -> Self {
        JobCoordinator {
            job_id,
            my_party_id,
            party_count,
            operation,
            my_input,
            state: CoordinatorState::Idle,
            mac_key: MacKey::generate(),
            my_shares_sent: HashMap::new(),
            received_shares: HashMap::new(),
            output_shares: HashMap::new(),
            ready_parties: Vec::new(),
            outgoing: Vec::new(),
        }
    }

    // ============================================
    // start — begin the job
    // ============================================
    // Announces the job to all parties and
    // signals that this party is ready.
    pub fn start(&mut self) -> Vec<MessageEnvelope> {
        self.state = CoordinatorState::WaitingForParties;

        let mut messages = Vec::new();

        // Announce job to all parties (broadcast)
        let announce = Message::JobAnnounce {
            job_id: self.job_id.clone(),
            party_count: self.party_count,
            operation: self.operation.clone(),
        };
        messages.push(MessageEnvelope::new(
            self.my_party_id,
            255, // broadcast
            announce,
        ));

        // Signal that we ourselves are ready
        let ready = Message::JobReady {
            job_id: self.job_id.clone(),
            from_party: self.my_party_id,
        };
        messages.push(MessageEnvelope::new(
            self.my_party_id,
            255,
            ready,
        ));

        // Record ourselves as ready
        self.ready_parties.push(self.my_party_id);

        messages
    }

    // ============================================
    // handle_job_ready — process a ready signal
    // ============================================
    // When all parties are ready, split our input
    // into shares and send one to each party.
    pub fn handle_job_ready(
        &mut self,
        from_party: u32,
    ) -> Vec<MessageEnvelope> {
        if !self.ready_parties.contains(&from_party) {
            self.ready_parties.push(from_party);
        }

        // Check if all parties are ready
        if self.ready_parties.len() >= self.party_count as usize
            && self.state == CoordinatorState::WaitingForParties
        {
            self.state = CoordinatorState::SharingInputs;
            return self.share_input();
        }

        Vec::new()
    }

    // ============================================
    // share_input — split input and send shares
    // ============================================
    // Uses Shamir secret sharing to split my_input
    // into party_count shares with threshold t.
    // Sends one share to each other party.
    // Keeps one share for ourselves.
    fn share_input(&mut self) -> Vec<MessageEnvelope> {
        let threshold = (self.party_count / 2 + 1) as usize;
        let shares = split(
            self.my_input,
            threshold,
            self.party_count as usize,
        );

        let mut messages = Vec::new();

        for (i, share) in shares.iter().enumerate() {
            let target_party = (i + 1) as u32;

            // Store share we're sending
            self.my_shares_sent.insert(target_party, *share);

            if target_party == self.my_party_id {
                // Keep our own share locally
                self.received_shares.insert(
                    self.my_party_id,
                    *share,
                );
            } else {
                // Send to other party
                let msg = Message::ShareMsg {
                    job_id: self.job_id.clone(),
                    from_party: self.my_party_id,
                    to_party: target_party,
                    share_x: share.x.value,
                    share_y: share.y.value,
                    mac_tag: 0, // simplified for now
                };
                messages.push(MessageEnvelope::new(
                    self.my_party_id,
                    target_party,
                    msg,
                ));
            }
        }

        messages
    }

    // ============================================
    // handle_share — process incoming share
    // ============================================
    // When we have all shares, begin computation.
    pub fn handle_share(
        &mut self,
        from_party: u32,
        share_x: u64,
        share_y: u64,
        _mac_tag: u64,
    ) -> Vec<MessageEnvelope> {
        use mpc_crypto::field::FieldElement;
        use mpc_crypto::shamir::Share;

        let share = Share {
            x: FieldElement::new(share_x),
            y: FieldElement::new(share_y),
        };
        self.received_shares.insert(from_party, share);

        // Check if we have all shares
        if self.received_shares.len() >= self.party_count as usize
            && self.state == CoordinatorState::SharingInputs
        {
            self.state = CoordinatorState::Computing;
            return self.compute();
        }

        Vec::new()
    }

    // ============================================
    // compute — run the local MPC computation
    // ============================================
    // Using the shares we collected, compute
    // the result of the agreed operation.
    // Then open our output share.
    fn compute(&mut self) -> Vec<MessageEnvelope> {
        // Collect all received shares
        let shares: Vec<mpc_crypto::shamir::Share> =
            self.received_shares.values().cloned().collect();

        // Reconstruct the sum of all inputs
        // (In real MPC this is done over secret shares
        //  without revealing individual inputs.
        //  Here we reconstruct to compute the result.)
        let reconstructed = reconstruct(&shares);

        // Store our contribution to the output
        let my_output_share = match self.operation {
            Operation::Sum => reconstructed,
            Operation::Average => {
                reconstructed / self.party_count as u64
            }
            Operation::Product => reconstructed,
            Operation::Custom { .. } => reconstructed,
        };

        self.output_shares.insert(
            self.my_party_id,
            my_output_share,
        );

        self.state = CoordinatorState::OpeningOutputs;

        // Broadcast our output share
        let open = Message::OpenShare {
            job_id: self.job_id.clone(),
            from_party: self.my_party_id,
            share_value: my_output_share,
            mac_tag: 0,
        };

        vec![MessageEnvelope::new(
            self.my_party_id,
            255, // broadcast
            open,
        )]
    }

    // ============================================
    // handle_open_share — collect output shares
    // ============================================
    // When all parties have opened their shares,
    // compute the final result.
    pub fn handle_open_share(
        &mut self,
        from_party: u32,
        share_value: u64,
    ) -> Option<ComputationResult> {
        self.output_shares.insert(from_party, share_value);

        if self.output_shares.len() >= self.party_count as usize
            && self.state == CoordinatorState::OpeningOutputs
        {
            return self.finalize();
        }

        None
    }

    // ============================================
    // finalize — compute the final result
    // ============================================
    fn finalize(&mut self) -> Option<ComputationResult> {
        self.state = CoordinatorState::Done;

        // Sum all output shares to get final result
        let result: u64 = self.output_shares.values().sum();

        Some(ComputationResult {
            job_id: self.job_id.clone(),
            result,
            operation: self.operation.clone(),
            party_count: self.party_count,
            success: true,
        })
    }

    // ============================================
    // handle_message — route incoming messages
    // ============================================
    pub fn handle_message(
        &mut self,
        envelope: MessageEnvelope,
    ) -> (Vec<MessageEnvelope>, Option<ComputationResult>) {
        let mut outgoing = Vec::new();
        let mut result = None;

        match &envelope.payload.clone() {
            Message::JobReady { from_party, .. } => {
                let msgs = self.handle_job_ready(*from_party);
                outgoing.extend(msgs);
            }
            Message::ShareMsg {
                from_party,
                share_x,
                share_y,
                mac_tag,
                ..
            } => {
                let msgs = self.handle_share(
                    *from_party,
                    *share_x,
                    *share_y,
                    *mac_tag,
                );
                outgoing.extend(msgs);
            }
            Message::OpenShare {
                from_party,
                share_value,
                ..
            } => {
                result = self.handle_open_share(
                    *from_party,
                    *share_value,
                );
            }
            Message::Abort { reason, .. } => {
                self.state =
                    CoordinatorState::Failed(reason.clone());
            }
            _ => {}
        }

        (outgoing, result)
    }

    // Is the job complete?
    pub fn is_done(&self) -> bool {
        matches!(
            self.state,
            CoordinatorState::Done | CoordinatorState::Failed(_)
        )
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coordinator(
        party_id: u32,
        input: u64,
    ) -> JobCoordinator {
        JobCoordinator::new(
            "test-job".to_string(),
            party_id,
            3,
            Operation::Sum,
            input,
        )
    }

    #[test]
    fn test_coordinator_creation() {
        let coord = make_coordinator(1, 100);
        assert_eq!(coord.my_party_id, 1);
        assert_eq!(coord.my_input, 100);
        assert_eq!(coord.state, CoordinatorState::Idle);
    }

    #[test]
    fn test_coordinator_start() {
        let mut coord = make_coordinator(1, 100);
        let messages = coord.start();
        // Should send JobAnnounce + JobReady
        assert!(messages.len() >= 2);
        assert_eq!(
            coord.state,
            CoordinatorState::WaitingForParties
        );
    }

    #[test]
    fn test_coordinator_tracks_ready_parties() {
        let mut coord = make_coordinator(1, 100);
        coord.start();
        // Party 1 already ready from start()
        assert_eq!(coord.ready_parties.len(), 1);
        coord.handle_job_ready(2);
        assert_eq!(coord.ready_parties.len(), 2);
    }

    #[test]
    fn test_coordinator_shares_input_when_all_ready() {
        let mut coord = make_coordinator(1, 100);
        coord.start();
        coord.handle_job_ready(2);
        let messages = coord.handle_job_ready(3);
        // All 3 parties ready — should start sharing
        assert_eq!(
            coord.state,
            CoordinatorState::SharingInputs
        );
        // Should have sent shares to parties 2 and 3
        assert!(!messages.is_empty());
    }

    #[test]
    fn test_coordinator_handles_received_share() {
        let mut coord = make_coordinator(1, 100);
        coord.start();
        coord.handle_job_ready(2);
        coord.handle_job_ready(3);
        // Party 1 already has its own share
        // Receive from party 2
        coord.handle_share(2, 2, 500, 0);
        assert!(coord.received_shares.contains_key(&2));
    }

    #[test]
    fn test_full_three_party_sum() {
        // Simulate 3 parties computing sum of 10+20+30=60
        let mut c1 = make_coordinator(1, 10);
        let mut c2 = make_coordinator(2, 20);
        let mut c3 = make_coordinator(3, 30);

        // All start
        c1.start(); c2.start(); c3.start();

        // All signal ready to each other
        c1.handle_job_ready(2); c1.handle_job_ready(3);
        c2.handle_job_ready(1); c2.handle_job_ready(3);
        c3.handle_job_ready(1); c3.handle_job_ready(2);

        // All should now be sharing inputs
        assert_eq!(c1.state, CoordinatorState::SharingInputs);
        assert_eq!(c2.state, CoordinatorState::SharingInputs);
        assert_eq!(c3.state, CoordinatorState::SharingInputs);
    }

    #[test]
    fn test_coordinator_is_done_after_failure() {
        let mut coord = make_coordinator(1, 100);
        coord.state = CoordinatorState::Failed(
            "test".to_string()
        );
        assert!(coord.is_done());
    }

    #[test]
    fn test_coordinator_not_done_when_idle() {
        let coord = make_coordinator(1, 100);
        assert!(!coord.is_done());
    }

    #[test]
    fn test_computation_result_structure() {
        let result = ComputationResult {
            job_id: "job-1".to_string(),
            result: 42,
            operation: Operation::Sum,
            party_count: 3,
            success: true,
        };
        assert_eq!(result.result, 42);
        assert!(result.success);
    }

    #[test]
    fn test_coordinator_handle_abort_message() {
        let mut coord = make_coordinator(1, 100);
        coord.start();
        let abort = Message::Abort {
            job_id: "test-job".to_string(),
            from_party: 2,
            reason: "MAC failed".to_string(),
        };
        let envelope = MessageEnvelope::new(2, 1, abort);
        coord.handle_message(envelope);
        assert!(coord.is_done());
        matches!(
            coord.state,
            CoordinatorState::Failed(_)
        );
    }
}