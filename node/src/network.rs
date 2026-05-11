// ============================================
// network.rs — TCP Network Layer
// ============================================
// This handles the actual internet connections
// between nodes. Each node:
// 1. Listens on a TCP port for incoming connections
// 2. Connects to other nodes' TCP ports
// 3. Sends and receives MessageEnvelope over TCP
//
// Messages are sent as newline-delimited JSON.
// Each line = one complete MessageEnvelope.
// Simple, debuggable, and easy to test.
// ============================================

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use std::collections::HashMap;
use crate::message::MessageEnvelope;

// ============================================
// NetworkEvent — events the network layer emits
// ============================================
// The network layer runs in its own async task.
// It communicates with the node via these events.

#[derive(Debug)]
pub enum NetworkEvent {
    // A new peer connected to us
    PeerConnected {
        party_id: u32,
        addr: String,
    },
    // A peer disconnected
    PeerDisconnected {
        party_id: u32,
    },
    // A message arrived from a peer
    MessageReceived {
        envelope: MessageEnvelope,
    },
    // An error occurred
    Error {
        description: String,
    },
}

// ============================================
// NetworkHandle — controls the network layer
// ============================================
// The node uses this handle to:
// - Send messages to specific peers
// - Broadcast messages to all peers
// - Shut down the network

pub struct NetworkHandle {
    // Channel to send outgoing messages
    pub outgoing_tx: mpsc::Sender<(u32, MessageEnvelope)>,
    // Channel to receive incoming events
    pub incoming_rx: mpsc::Receiver<NetworkEvent>,
}

impl NetworkHandle {
    // Send a message to a specific party
    pub async fn send_to(
        &self,
        party_id: u32,
        envelope: MessageEnvelope,
    ) -> Result<(), String> {
        self.outgoing_tx
            .send((party_id, envelope))
            .await
            .map_err(|e| e.to_string())
    }

    // Receive the next network event
    pub async fn recv_event(&mut self) -> Option<NetworkEvent> {
        self.incoming_rx.recv().await
    }
}

// ============================================
// send_message — send one envelope over TCP
// ============================================
// Serializes envelope to JSON and sends it
// as a newline-terminated string over the stream.

pub async fn send_message(
    stream: &mut TcpStream,
    envelope: &MessageEnvelope,
) -> Result<(), String> {
    let json = envelope
        .to_json()
        .map_err(|e| format!("Serialize error: {}", e))?;

    let line = format!("{}\n", json);

    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("Send error: {}", e))?;

    Ok(())
}

// ============================================
// receive_message — receive one envelope over TCP
// ============================================
// Reads one newline-terminated line from the
// stream and deserializes it as a MessageEnvelope.

pub async fn receive_message(
    reader: &mut BufReader<tokio::net::tcp::ReadHalf<'_>>,
) -> Result<MessageEnvelope, String> {
    let mut line = String::new();

    let bytes_read = reader
        .read_line(&mut line)
        .await
        .map_err(|e| format!("Receive error: {}", e))?;

    if bytes_read == 0 {
        return Err("Connection closed".to_string());
    }

    MessageEnvelope::from_json(line.trim())
        .map_err(|e| format!("Deserialize error: {}", e))
}

// ============================================
// start_listener — listen for incoming connections
// ============================================
// Binds to a TCP port and accepts connections.
// Each connection is handled in its own async task.

pub async fn start_listener(
    addr: &str,
    event_tx: mpsc::Sender<NetworkEvent>,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Bind error on {}: {}", addr, e))?;

    log::info!("Listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                log::info!("New connection from {}", peer_addr);
                let tx = event_tx.clone();
                tokio::spawn(async move {
                    handle_incoming_connection(stream, tx).await;
                });
            }
            Err(e) => {
                let _ = event_tx
                    .send(NetworkEvent::Error {
                        description: format!("Accept error: {}", e),
                    })
                    .await;
            }
        }
    }
}

// ============================================
// handle_incoming_connection — read messages
// from a connected peer and emit events
// ============================================

async fn handle_incoming_connection(
    stream: TcpStream,
    event_tx: mpsc::Sender<NetworkEvent>,
) {
    let (read_half, _write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // Connection closed
                log::info!("Connection closed by peer");
                break;
            }
            Ok(_) => {
                match MessageEnvelope::from_json(line.trim()) {
                    Ok(envelope) => {
                        let _ = event_tx
                            .send(NetworkEvent::MessageReceived { envelope })
                            .await;
                    }
                    Err(e) => {
                        log::warn!("Failed to parse message: {}", e);
                    }
                }
            }
            Err(e) => {
                let _ = event_tx
                    .send(NetworkEvent::Error {
                        description: format!("Read error: {}", e),
                    })
                    .await;
                break;
            }
        }
    }
}

// ============================================
// connect_to_peer — connect to another node
// ============================================
// Attempts to connect to a peer at given address.
// Returns the TcpStream if successful.

pub async fn connect_to_peer(
    addr: &str,
) -> Result<TcpStream, String> {
    log::info!("Connecting to peer at {}", addr);
    TcpStream::connect(addr)
        .await
        .map_err(|e| format!("Connect error to {}: {}", addr, e))
}

// ============================================
// PeerMap — manages connections to all peers
// ============================================

pub struct PeerMap {
    // party_id -> write half of TCP connection
    peers: HashMap<u32, tokio::net::tcp::OwnedWriteHalf>,
}

impl PeerMap {
    pub fn new() -> Self {
        PeerMap {
            peers: HashMap::new(),
        }
    }

    // Add a peer connection
    pub fn add_peer(
        &mut self,
        party_id: u32,
        write_half: tokio::net::tcp::OwnedWriteHalf,
    ) {
        self.peers.insert(party_id, write_half);
    }

    // Remove a peer connection
    pub fn remove_peer(&mut self, party_id: u32) {
        self.peers.remove(&party_id);
    }

    // Check if peer is connected
    pub fn is_connected(&self, party_id: u32) -> bool {
        self.peers.contains_key(&party_id)
    }

    // How many peers are connected
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    // Send message to one peer
    pub async fn send_to_peer(
        &mut self,
        party_id: u32,
        envelope: &MessageEnvelope,
    ) -> Result<(), String> {
        let json = envelope
            .to_json()
            .map_err(|e| format!("Serialize error: {}", e))?;
        let line = format!("{}\n", json);

        if let Some(writer) = self.peers.get_mut(&party_id) {
            writer
                .write_all(line.as_bytes())
                .await
                .map_err(|e| format!("Send error: {}", e))?;
            Ok(())
        } else {
            Err(format!("Peer {} not connected", party_id))
        }
    }

    // Broadcast message to all peers
    pub async fn broadcast(
        &mut self,
        envelope: &MessageEnvelope,
    ) -> Vec<String> {
        let json = match envelope.to_json() {
            Ok(j) => format!("{}\n", j),
            Err(e) => return vec![format!("Serialize error: {}", e)],
        };

        let mut errors = Vec::new();
        for (party_id, writer) in &mut self.peers {
            if let Err(e) = writer.write_all(json.as_bytes()).await {
                errors.push(format!(
                    "Send error to party {}: {}", party_id, e
                ));
            }
        }
        errors
    }
}

// ============================================
// TESTS
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Message, MessageEnvelope};

    #[test]
    fn test_network_event_debug() {
        let event = NetworkEvent::Error {
            description: "test error".to_string(),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("test error"));
    }

    #[test]
    fn test_peer_map_creation() {
        let map = PeerMap::new();
        assert_eq!(map.peer_count(), 0);
    }

    #[test]
    fn test_peer_map_is_connected_false() {
        let map = PeerMap::new();
        assert!(!map.is_connected(1));
        assert!(!map.is_connected(2));
    }

    #[tokio::test]
    async fn test_tcp_listener_binds() {
        // Test that we can bind to a port
        let result = TcpListener::bind("127.0.0.1:19001").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connect_to_nonexistent_peer_fails() {
        // Connecting to nothing should fail gracefully
        let result = connect_to_peer("127.0.0.1:19999").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_send_and_receive_message() {
        // Start a listener on a free port
        let listener = TcpListener::bind("127.0.0.1:19002")
            .await
            .unwrap();

        let addr = listener.local_addr().unwrap().to_string();

        // Spawn server task
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, _) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let envelope = MessageEnvelope::from_json(
                line.trim()
            ).unwrap();
            assert_eq!(envelope.from, 1);
        });

        // Give server time to start
        tokio::time::sleep(
            tokio::time::Duration::from_millis(50)
        ).await;

        // Connect and send
        let mut client = TcpStream::connect(&addr).await.unwrap();
        let msg = Message::Ping { from_party: 1, timestamp: 42 };
        let envelope = MessageEnvelope::new(1, 2, msg);
        send_message(&mut client, &envelope).await.unwrap();
    }

    #[tokio::test]
    async fn test_message_channel() {
        let (tx, mut rx) = mpsc::channel::<NetworkEvent>(10);
        tx.send(NetworkEvent::PeerConnected {
            party_id: 1,
            addr: "127.0.0.1:8001".to_string(),
        }).await.unwrap();

        let event = rx.recv().await.unwrap();
        matches!(event, NetworkEvent::PeerConnected { .. });
    }
}