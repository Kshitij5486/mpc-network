// ============================================
// message.rs — Messages between nodes
// ============================================
// This defines every message type that nodes
// send to each other over the network.
//
// Think of this as the "language" nodes speak.
// Every message has a type, a sender, and a payload.
// Messages are serialized to JSON for transmission.
// ============================================

use serde::{Deserialize, Serialize};

// ============================================
// Message — every possible message in the network
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    // ── Handshake ──────────────────────────
    // First message sent when two nodes connect.
    // Contains the sender's identity.
    Hello {
        from_party: u32,
        party_count: u32,
        version: String,
    },

    // Response to Hello — confirms connection
    HelloAck {
        from_party: u32,
        accepted: bool,
    },

    // ── Job coordination ───────────────────
    // Coordinator tells nodes a new job is ready
    JobAnnounce {
        job_id: String,
        party_count: u32,
        operation: Operation,
    },

    // Node confirms it is ready for the job
    JobReady {
        job_id: String,
        from_party: u32,
    },

    // ── Secret sharing ─────────────────────
    // Party sends their share of the input
    // to another party
    ShareMsg {
        job_id: String,
        from_party: u32,
        to_party: u32,
        share_x: u64,
        share_y: u64,
        mac_tag: u64,
    },

    // Party confirms they received all shares
    SharesReceived {
        job_id: String,
        from_party: u32,
    },

    // ── Beaver triple distribution ─────────
    // Coordinator sends pre-computed triple
    // to each party for multiplication
    TripleShare {
        job_id: String,
        to_party: u32,
        a_share: u64,
        b_share: u64,
        c_share: u64,
        a_mac: u64,
        b_mac: u64,
        c_mac: u64,
    },

    // ── Online computation ─────────────────
    // During multiplication, parties broadcast
    // epsilon = x - a and delta = y - b publicly
    // These are safe to reveal (masked by random a,b)
    BroadcastValue {
        job_id: String,
        from_party: u32,
        label: String,   // "epsilon" or "delta"
        value: u64,
    },

    // ── Output reconstruction ──────────────
    // Party opens their output share for reconstruction
    OpenShare {
        job_id: String,
        from_party: u32,
        share_value: u64,
        mac_tag: u64,
    },

    // Final result announced to all parties
    Result {
        job_id: String,
        value: u64,
        success: bool,
    },

    // ── Error handling ─────────────────────
    // Something went wrong — abort the job
    Abort {
        job_id: String,
        from_party: u32,
        reason: String,
    },

    // ── Heartbeat ──────────────────────────
    // Nodes ping each other to confirm alive
    Ping {
        from_party: u32,
        timestamp: u64,
    },

    Pong {
        from_party: u32,
        timestamp: u64,
    },
}

// ============================================
// Operation — what computation to perform
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    // Compute the sum of all parties' inputs
    Sum,
    // Compute the average of all parties' inputs
    Average,
    // Compute the product of all parties' inputs
    Product,
    // Custom computation (future extension)
    Custom { description: String },
}

// ============================================
// MessageEnvelope — wraps a message with metadata
// ============================================
// Every message sent over the wire is wrapped
// in an envelope that includes routing info.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub id: String,        // unique message ID
    pub from: u32,         // sender party ID
    pub to: u32,           // receiver party ID (255 = broadcast)
    pub payload: Message,  // the actual message
    pub timestamp: u64,    // unix timestamp millis
}

impl MessageEnvelope {
    pub fn new(from: u32, to: u32, payload: Message) -> Self {
        MessageEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            from,
            to,
            payload,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    // Serialize to JSON string for transmission
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    // Deserialize from JSON string received over network
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    // Is this a broadcast message (to all parties)?
    pub fn is_broadcast(&self) -> bool {
        self.to == 255
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_message_serializes() {
        let msg = Message::Hello {
            from_party: 1,
            party_count: 3,
            version: "0.1.0".to_string(),
        };
        let envelope = MessageEnvelope::new(1, 2, msg);
        let json = envelope.to_json();
        assert!(json.is_ok());
    }

    #[test]
    fn test_share_message_roundtrip() {
        let msg = Message::ShareMsg {
            job_id: "job-123".to_string(),
            from_party: 1,
            to_party: 2,
            share_x: 42,
            share_y: 999,
            mac_tag: 777,
        };
        let envelope = MessageEnvelope::new(1, 2, msg);
        let json = envelope.to_json().unwrap();
        let recovered = MessageEnvelope::from_json(&json).unwrap();
        assert_eq!(recovered.from, 1);
        assert_eq!(recovered.to, 2);
    }

    #[test]
    fn test_broadcast_envelope() {
        let msg = Message::Ping {
            from_party: 1,
            timestamp: 12345,
        };
        let envelope = MessageEnvelope::new(1, 255, msg);
        assert!(envelope.is_broadcast());
    }

    #[test]
    fn test_result_message() {
        let msg = Message::Result {
            job_id: "job-456".to_string(),
            value: 42,
            success: true,
        };
        let envelope = MessageEnvelope::new(0, 255, msg);
        let json = envelope.to_json().unwrap();
        assert!(json.contains("job-456"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_abort_message() {
        let msg = Message::Abort {
            job_id: "job-789".to_string(),
            from_party: 2,
            reason: "MAC verification failed".to_string(),
        };
        let envelope = MessageEnvelope::new(2, 255, msg);
        let json = envelope.to_json().unwrap();
        assert!(json.contains("MAC verification failed"));
    }

    #[test]
    fn test_envelope_has_unique_id() {
        let msg1 = Message::Ping { from_party: 1, timestamp: 1 };
        let msg2 = Message::Ping { from_party: 1, timestamp: 1 };
        let e1 = MessageEnvelope::new(1, 2, msg1);
        let e2 = MessageEnvelope::new(1, 2, msg2);
        // Each envelope gets a unique ID
        assert_ne!(e1.id, e2.id);
    }

    #[test]
    fn test_operation_serializes() {
        let op = Operation::Average;
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("Average"));
    }
}