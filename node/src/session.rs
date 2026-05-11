// ============================================
// session.rs — Session Management
// ============================================
// A session represents an active connection
// between two nodes. It tracks:
// - which party we are connected to
// - the state of that connection
// - messages sent and received
//
// Think of it like a phone call:
// The network layer is the phone line.
// The session is the conversation happening on it.
// ============================================

use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::message::{Message, MessageEnvelope};

// ============================================
// SessionState — state of one peer connection
// ============================================

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Connecting,      // TCP connected, waiting for Hello
    Handshaking,     // Hello sent, waiting for HelloAck
    Active,          // fully connected, ready for MPC
    Disconnected,    // connection lost
}

// ============================================
// Session — one active peer connection
// ============================================

#[derive(Debug)]
pub struct Session {
    pub peer_party_id: u32,
    pub peer_addr: String,
    pub state: SessionState,
    pub connected_at: Instant,
    pub last_ping: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub pending_messages: Vec<MessageEnvelope>,
}

impl Session {
    pub fn new(peer_party_id: u32, peer_addr: String) -> Self {
        Session {
            peer_party_id,
            peer_addr,
            state: SessionState::Connecting,
            connected_at: Instant::now(),
            last_ping: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            pending_messages: Vec::new(),
        }
    }

    // Mark session as active after handshake
    pub fn activate(&mut self) {
        self.state = SessionState::Active;
    }

    // Mark session as disconnected
    pub fn disconnect(&mut self) {
        self.state = SessionState::Disconnected;
    }

    // Check if session is usable for MPC
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    // Check if session is disconnected
    pub fn is_disconnected(&self) -> bool {
        self.state == SessionState::Disconnected
    }

    // Record that we sent a message
    pub fn record_sent(&mut self) {
        self.messages_sent += 1;
    }

    // Record that we received a message
    pub fn record_received(&mut self) {
        self.messages_received += 1;
        self.last_ping = Instant::now();
    }

    // Queue a message to send when session is ready
    pub fn queue_message(&mut self, envelope: MessageEnvelope) {
        self.pending_messages.push(envelope);
    }

    // Take all pending messages (drains the queue)
    pub fn take_pending(&mut self) -> Vec<MessageEnvelope> {
        self.pending_messages.drain(..).collect()
    }

    // How long has this session been alive
    pub fn age(&self) -> Duration {
        self.connected_at.elapsed()
    }

    // How long since last message received
    pub fn silence_duration(&self) -> Duration {
        self.last_ping.elapsed()
    }

    // Is the peer considered timed out?
    // In production this would be ~30 seconds
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.silence_duration() > timeout
    }
}

// ============================================
// SessionManager — manages all peer sessions
// ============================================

pub struct SessionManager {
    pub sessions: HashMap<u32, Session>,
    pub my_party_id: u32,
    pub expected_parties: u32,
}

impl SessionManager {
    pub fn new(my_party_id: u32, expected_parties: u32) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            my_party_id,
            expected_parties,
        }
    }

    // Add a new session for a peer
    pub fn add_session(
        &mut self,
        peer_party_id: u32,
        peer_addr: String,
    ) {
        let session = Session::new(peer_party_id, peer_addr);
        self.sessions.insert(peer_party_id, session);
    }

    // Get a session by party ID
    pub fn get_session(&self, party_id: u32) -> Option<&Session> {
        self.sessions.get(&party_id)
    }

    // Get a mutable session by party ID
    pub fn get_session_mut(
        &mut self,
        party_id: u32,
    ) -> Option<&mut Session> {
        self.sessions.get_mut(&party_id)
    }

    // Activate a session after successful handshake
    pub fn activate_session(&mut self, party_id: u32) -> bool {
        if let Some(session) = self.sessions.get_mut(&party_id) {
            session.activate();
            true
        } else {
            false
        }
    }

    // Mark a session as disconnected
    pub fn disconnect_session(&mut self, party_id: u32) {
        if let Some(session) = self.sessions.get_mut(&party_id) {
            session.disconnect();
        }
    }

    // Count of active sessions
    pub fn active_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.is_active())
            .count()
    }

    // Check if all expected parties are connected
    pub fn all_connected(&self) -> bool {
        // We need expected_parties - 1 connections
        // (we don't connect to ourselves)
        self.active_count() >= (self.expected_parties - 1) as usize
    }

    // Get all active session party IDs
    pub fn active_party_ids(&self) -> Vec<u32> {
        self.sessions
            .values()
            .filter(|s| s.is_active())
            .map(|s| s.peer_party_id)
            .collect()
    }

    // Remove disconnected sessions (cleanup)
    pub fn cleanup_disconnected(&mut self) {
        self.sessions.retain(|_, s| !s.is_disconnected());
    }

    // Handle a handshake message
    // Returns true if handshake completed successfully
    pub fn handle_handshake(
        &mut self,
        envelope: &MessageEnvelope,
    ) -> bool {
        match &envelope.payload {
            Message::Hello {
                from_party,
                party_count: _,
                version: _,
            } => {
                // Create session if not exists
                if !self.sessions.contains_key(from_party) {
                    self.add_session(
                        *from_party,
                        format!("party-{}", from_party),
                    );
                }
                if let Some(s) = self.sessions.get_mut(from_party) {
                    s.state = SessionState::Handshaking;
                    s.record_received();
                }
                true
            }
            Message::HelloAck {
                from_party,
                accepted,
            } => {
                if *accepted {
                    self.activate_session(*from_party);
                    if let Some(s) =
                        self.sessions.get_mut(from_party)
                    {
                        s.record_received();
                    }
                    true
                } else {
                    self.disconnect_session(*from_party);
                    false
                }
            }
            _ => false,
        }
    }

    // Total messages sent across all sessions
    pub fn total_sent(&self) -> u64 {
        self.sessions.values().map(|s| s.messages_sent).sum()
    }

    // Total messages received across all sessions
    pub fn total_received(&self) -> u64 {
        self.sessions.values().map(|s| s.messages_received).sum()
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Message, MessageEnvelope};

    fn make_manager() -> SessionManager {
        SessionManager::new(1, 3)
    }

    #[test]
    fn test_session_creation() {
        let session = Session::new(2, "127.0.0.1:8002".to_string());
        assert_eq!(session.peer_party_id, 2);
        assert_eq!(session.state, SessionState::Connecting);
        assert!(!session.is_active());
    }

    #[test]
    fn test_session_activate() {
        let mut session = Session::new(2, "127.0.0.1:8002".to_string());
        session.activate();
        assert!(session.is_active());
        assert_eq!(session.state, SessionState::Active);
    }

    #[test]
    fn test_session_disconnect() {
        let mut session = Session::new(2, "127.0.0.1:8002".to_string());
        session.activate();
        session.disconnect();
        assert!(session.is_disconnected());
        assert!(!session.is_active());
    }

    #[test]
    fn test_session_message_counts() {
        let mut session = Session::new(2, "127.0.0.1:8002".to_string());
        session.record_sent();
        session.record_sent();
        session.record_received();
        assert_eq!(session.messages_sent, 2);
        assert_eq!(session.messages_received, 1);
    }

    #[test]
    fn test_session_queue_and_take_pending() {
        let mut session = Session::new(2, "127.0.0.1:8002".to_string());
        let msg = Message::Ping { from_party: 1, timestamp: 42 };
        let envelope = MessageEnvelope::new(1, 2, msg);
        session.queue_message(envelope);
        assert_eq!(session.pending_messages.len(), 1);
        let pending = session.take_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(session.pending_messages.len(), 0);
    }

    #[test]
    fn test_session_timeout() {
        let session = Session::new(2, "127.0.0.1:8002".to_string());
        // Should not be timed out immediately
        assert!(!session.is_timed_out(Duration::from_secs(30)));
        // Should be timed out with zero duration
        assert!(session.is_timed_out(Duration::from_secs(0)));
    }

    #[test]
    fn test_manager_creation() {
        let mgr = make_manager();
        assert_eq!(mgr.my_party_id, 1);
        assert_eq!(mgr.expected_parties, 3);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_manager_add_session() {
        let mut mgr = make_manager();
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        assert!(mgr.get_session(2).is_some());
    }

    #[test]
    fn test_manager_activate_session() {
        let mut mgr = make_manager();
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        mgr.activate_session(2);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_manager_all_connected() {
        let mut mgr = make_manager();
        // Need 2 connections for 3-party MPC
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        mgr.activate_session(2);
        assert!(!mgr.all_connected()); // only 1 of 2 needed
        mgr.add_session(3, "127.0.0.1:8003".to_string());
        mgr.activate_session(3);
        assert!(mgr.all_connected()); // now 2 of 2
    }

    #[test]
    fn test_manager_handles_hello() {
        let mut mgr = make_manager();
        let hello = Message::Hello {
            from_party: 2,
            party_count: 3,
            version: "0.1.0".to_string(),
        };
        let envelope = MessageEnvelope::new(2, 1, hello);
        let result = mgr.handle_handshake(&envelope);
        assert!(result);
        assert!(mgr.get_session(2).is_some());
    }

    #[test]
    fn test_manager_handles_hello_ack() {
        let mut mgr = make_manager();
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        let ack = Message::HelloAck {
            from_party: 2,
            accepted: true,
        };
        let envelope = MessageEnvelope::new(2, 1, ack);
        let result = mgr.handle_handshake(&envelope);
        assert!(result);
        assert!(mgr.get_session(2).unwrap().is_active());
    }

    #[test]
    fn test_manager_rejected_hello_ack() {
        let mut mgr = make_manager();
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        let ack = Message::HelloAck {
            from_party: 2,
            accepted: false,
        };
        let envelope = MessageEnvelope::new(2, 1, ack);
        let result = mgr.handle_handshake(&envelope);
        assert!(!result);
        assert!(mgr.get_session(2).unwrap().is_disconnected());
    }

    #[test]
    fn test_manager_cleanup_disconnected() {
        let mut mgr = make_manager();
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        mgr.add_session(3, "127.0.0.1:8003".to_string());
        mgr.activate_session(2);
        mgr.disconnect_session(3);
        mgr.cleanup_disconnected();
        assert!(mgr.get_session(2).is_some());
        assert!(mgr.get_session(3).is_none());
    }

    #[test]
    fn test_manager_total_counts() {
        let mut mgr = make_manager();
        mgr.add_session(2, "127.0.0.1:8002".to_string());
        mgr.add_session(3, "127.0.0.1:8003".to_string());
        if let Some(s) = mgr.get_session_mut(2) {
            s.record_sent();
            s.record_sent();
        }
        if let Some(s) = mgr.get_session_mut(3) {
            s.record_received();
        }
        assert_eq!(mgr.total_sent(), 2);
        assert_eq!(mgr.total_received(), 1);
    }
}