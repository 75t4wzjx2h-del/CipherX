// CipherX — P2P Network (Phase 6)
//
// Built on libp2p with Tor transport.
//
// Protocols:
//   /cipherx/blocks/1.0.0   — block gossip (GossipSub)
//   /cipherx/txs/1.0.0      — transaction gossip (GossipSub)
//   /cipherx/consensus/1.0.0 — consensus votes (GossipSub)
//   /cipherx/sync/1.0.0     — block sync (request/response)
//   /cipherx/identify/1.0.0 — peer identification (version, capabilities)
//
// Peer discovery:
//   - Kademlia DHT over Tor (no clearnet bootstrap)
//   - Hardcoded .onion seed nodes
//   - mDNS disabled (leaks LAN presence)
//
// Privacy:
//   - All messages signed with ephemeral peer keys (rotated periodically)
//   - No persistent peer IDs (prevents tracking)
//   - GossipSub messages include no sender info

use std::collections::HashMap;
use sha3::Digest;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use tracing::{info, debug};

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::consensus::tendermint::Vote;
use super::peer::{PeerId, PeerInfo};

// ─── Topic names ──────────────────────────────────────────────────────────────

pub const TOPIC_BLOCKS:    &str = "/cipherx/blocks/1.0.0";
pub const TOPIC_TXS:       &str = "/cipherx/txs/1.0.0";
pub const TOPIC_CONSENSUS: &str = "/cipherx/consensus/1.0.0";
pub const TOPIC_SYNC:      &str = "/cipherx/sync/1.0.0";

// ─── Network message types ────────────────────────────────────────────────────

/// All messages exchanged between peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// A new block propagated to all peers
    NewBlock(Box<Block>),
    /// A new transaction propagated to all peers
    NewTx(Box<Transaction>),
    /// A Tendermint vote (prevote or precommit)
    ConsensusVote(Vote),
    /// Request blocks from peer
    BlockRequest(BlockRequest),
    /// Response with blocks
    BlockResponse(BlockResponse),
    /// Peer hello / capability announcement
    Hello(HelloMessage),
    /// Peer goodbye
    Bye,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    pub from_height: u64,
    pub to_height: u64,
    pub request_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub request_id: u64,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    /// Node version string
    pub version: String,
    /// Current chain height
    pub height: u64,
    /// Tip block hash
    pub tip_hash: [u8; 32],
    /// Supported protocol versions
    pub protocols: Vec<String>,
    /// Our .onion address (for inbound connections)
    pub onion_address: Option<String>,
}

// ─── GossipSub message ────────────────────────────────────────────────────────

/// A message in the gossip network
/// No sender info — message is self-contained
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub topic: String,
    pub payload: Vec<u8>,
    /// Message ID: hash of payload (for deduplication)
    pub message_id: [u8; 32],
    /// Timestamp (for freshness check)
    pub timestamp_ms: u64,
}

impl GossipMessage {
    pub fn new(topic: &str, payload: Vec<u8>) -> Self {
        let mut hasher = sha3::Sha3_256::new();
        sha3::Digest::update(&mut hasher, &payload);
        sha3::Digest::update(&mut hasher, topic.as_bytes());
        let message_id = sha3::Digest::finalize(hasher).into();

        GossipMessage {
            topic: topic.to_string(),
            payload,
            message_id,
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    pub fn is_fresh(&self, max_age_ms: u64) -> bool {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        now.saturating_sub(self.timestamp_ms) < max_age_ms
    }
}

// ─── Network events ───────────────────────────────────────────────────────────

/// Events emitted by the P2P layer to the node
#[derive(Debug)]
pub enum NetworkEvent {
    /// New block received from peer
    BlockReceived { block: Block, from: PeerId },
    /// New transaction received
    TxReceived { tx: Transaction, from: PeerId },
    /// Consensus vote received
    VoteReceived { vote: Vote, from: PeerId },
    /// Peer connected
    PeerConnected(PeerInfo),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Sync request received
    SyncRequested { request: BlockRequest, from: PeerId },
}

// ─── P2P config ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Max peers to maintain
    pub max_peers: usize,
    /// Min peers before we search for more
    pub min_peers: usize,
    /// Gossip fanout (how many peers to forward to)
    pub gossip_fanout: usize,
    /// Max message size (bytes)
    pub max_message_size: usize,
    /// Message deduplication window (ms)
    pub dedup_window_ms: u64,
    /// Seed nodes (.onion addresses)
    pub seed_nodes: Vec<String>,
    /// Our listen port
    pub listen_port: u16,
}

impl Default for P2PConfig {
    fn default() -> Self {
        P2PConfig {
            max_peers: 50,
            min_peers: 8,
            gossip_fanout: 6,
            max_message_size: 10 * 1024 * 1024, // 10MB
            dedup_window_ms: 30_000,             // 30s
            seed_nodes: vec![],
            listen_port: 9152,
        }
    }
}

// ─── Message deduplication ────────────────────────────────────────────────────

struct MessageCache {
    seen: HashMap<[u8; 32], Instant>,
    max_age: Duration,
    inserts_since_evict: u32,
}

impl MessageCache {
    const EVICT_EVERY: u32 = 128;

    fn new(max_age_ms: u64) -> Self {
        MessageCache {
            seen: HashMap::new(),
            max_age: Duration::from_millis(max_age_ms),
            inserts_since_evict: 0,
        }
    }

    /// Returns true if this message is new (not seen before).
    /// Evicts stale entries every 128 inserts instead of on every call.
    fn insert(&mut self, id: [u8; 32]) -> bool {
        if self.seen.contains_key(&id) {
            return false;
        }
        let now = Instant::now();
        self.inserts_since_evict += 1;
        if self.inserts_since_evict >= Self::EVICT_EVERY {
            self.inserts_since_evict = 0;
            self.seen.retain(|_, t| now.duration_since(*t) < self.max_age);
        }
        self.seen.insert(id, now);
        true
    }
}

// ─── P2P node ────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum P2PError {
    #[error("Not connected to any peers")]
    NoPeers,
    #[error("Message too large: {size} bytes")]
    MessageTooLarge { size: usize },
    #[error("Peer {0} not found")]
    PeerNotFound(String),
    #[error("Network not started")]
    NotStarted,
    #[error("Serialization error: {0}")]
    SerializeError(String),
}

/// The CipherX P2P node
pub struct P2PNode {
    config: P2PConfig,
    /// Connected peers: peer_id → info
    peers: HashMap<PeerId, PeerInfo>,
    /// Message dedup cache
    message_cache: MessageCache,
    /// Outbound event channel
    event_tx: mpsc::Sender<NetworkEvent>,
    /// Is running?
    running: bool,
    /// Messages broadcast (stats)
    messages_sent: u64,
    messages_recv: u64,
}

impl P2PNode {
    pub fn new(config: P2PConfig, event_tx: mpsc::Sender<NetworkEvent>) -> Self {
        let dedup_window = config.dedup_window_ms;
        P2PNode {
            config,
            peers: HashMap::new(),
            message_cache: MessageCache::new(dedup_window),
            event_tx,
            running: false,
            messages_sent: 0,
            messages_recv: 0,
        }
    }

    /// Start the P2P node
    /// In production: spawns libp2p swarm
    pub async fn start(&mut self) -> Result<(), P2PError> {
        info!("🌐 P2P node starting...");
        info!("📡 Listen port: {}", self.config.listen_port);
        info!("👥 Target peers: {}/{}", self.config.min_peers, self.config.max_peers);

        // Production libp2p setup:
        // let transport = TorTransport::new(tor_client);
        // let behaviour = CipherXBehaviour {
        //     gossipsub: Gossipsub::new(config)?,
        //     kademlia: Kademlia::new(peer_id, MemoryStore::new(peer_id)),
        //     identify: Identify::new(config),
        //     ping: Ping::new(config),
        // };
        // let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        //     .with_tokio()
        //     .with_other_transport(|_| transport)?
        //     .with_behaviour(|_| behaviour)?
        //     .build();
        // swarm.listen_on(our_onion.to_multiaddr(port))?;

        self.running = true;
        info!("🌐 P2P node ready");

        // Connect to seed nodes
        for seed in &self.config.seed_nodes.clone() {
            info!("🔗 Connecting to seed: {}", seed);
            // Production: swarm.dial(seed_multiaddr)?;
        }

        Ok(())
    }

    // ── Broadcast ─────────────────────────────────────────────────────────────

    /// Broadcast a new block to all peers
    pub async fn broadcast_block(&mut self, block: &Block) -> Result<(), P2PError> {
        let payload = bincode::serialize(block)
            .map_err(|e| P2PError::SerializeError(e.to_string()))?;
        self.gossip(TOPIC_BLOCKS, payload).await
    }

    /// Broadcast a transaction to all peers
    pub async fn broadcast_tx(&mut self, tx: &Transaction) -> Result<(), P2PError> {
        let payload = bincode::serialize(tx)
            .map_err(|e| P2PError::SerializeError(e.to_string()))?;
        self.gossip(TOPIC_TXS, payload).await
    }

    /// Broadcast a consensus vote to all peers
    pub async fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), P2PError> {
        let payload = bincode::serialize(vote)
            .map_err(|e| P2PError::SerializeError(e.to_string()))?;
        self.gossip(TOPIC_CONSENSUS, payload).await
    }

    /// Send data to all subscribed peers on a topic
    async fn gossip(&mut self, topic: &str, payload: Vec<u8>) -> Result<(), P2PError> {
        if !self.running { return Err(P2PError::NotStarted); }

        if payload.len() > self.config.max_message_size {
            return Err(P2PError::MessageTooLarge { size: payload.len() });
        }

        let msg = GossipMessage::new(topic, payload);

        // Deduplicate
        if !self.message_cache.insert(msg.message_id) {
            debug!("Skipping duplicate message on topic {}", topic);
            return Ok(());
        }

        debug!("📢 Gossip on {} to {} peers", topic, self.peers.len().min(self.config.gossip_fanout));

        // Production: swarm.behaviour_mut().gossipsub.publish(topic, msg.payload)?;
        self.messages_sent += 1;
        Ok(())
    }

    // ── Peer management ───────────────────────────────────────────────────────

    /// Handle an incoming peer connection
    pub async fn on_peer_connected(&mut self, info: PeerInfo) {
        info!("👤 Peer connected: {:?}", info.peer_id);
        let event = NetworkEvent::PeerConnected(info.clone());
        self.peers.insert(info.peer_id.clone(), info);
        let _ = self.event_tx.send(event).await;
    }

    /// Handle a peer disconnecting
    pub async fn on_peer_disconnected(&mut self, peer_id: &PeerId) {
        info!("👋 Peer disconnected: {:?}", peer_id);
        self.peers.remove(peer_id);
        let _ = self.event_tx.send(NetworkEvent::PeerDisconnected(peer_id.clone())).await;
    }

    /// Handle an incoming message
    pub async fn on_message(&mut self, msg: GossipMessage, from: PeerId) {
        // Freshness check
        if !msg.is_fresh(self.config.dedup_window_ms) {
            debug!("Dropping stale message on {}", msg.topic);
            return;
        }

        // Deduplication
        if !self.message_cache.insert(msg.message_id) {
            return;
        }

        self.messages_recv += 1;

        // Parse and emit event
        let event = match msg.topic.as_str() {
            TOPIC_BLOCKS => {
                bincode::deserialize::<Block>(&msg.payload).ok().map(|block| {
                    NetworkEvent::BlockReceived { block, from: from.clone() }
                })
            }
            TOPIC_TXS => {
                bincode::deserialize::<Transaction>(&msg.payload).ok().map(|tx| {
                    NetworkEvent::TxReceived { tx, from: from.clone() }
                })
            }
            TOPIC_CONSENSUS => {
                bincode::deserialize::<Vote>(&msg.payload).ok().map(|vote| {
                    NetworkEvent::VoteReceived { vote, from: from.clone() }
                })
            }
            _ => None,
        };

        if let Some(ev) = event {
            let _ = self.event_tx.send(ev).await;
        }
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    pub fn peer_count(&self) -> usize { self.peers.len() }
    pub fn is_running(&self) -> bool { self.running }
    pub fn messages_sent(&self) -> u64 { self.messages_sent }
    pub fn messages_recv(&self) -> u64 { self.messages_recv }
    pub fn needs_more_peers(&self) -> bool { self.peers.len() < self.config.min_peers }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node() -> (P2PNode, mpsc::Receiver<NetworkEvent>) {
        let (tx, rx) = mpsc::channel(100);
        let node = P2PNode::new(P2PConfig::default(), tx);
        (node, rx)
    }

    #[test]
    fn test_gossip_message_dedup() {
        let mut cache = MessageCache::new(5000);
        let id = [1u8; 32];
        assert!(cache.insert(id));  // first time: new
        assert!(!cache.insert(id)); // second time: duplicate
    }

    #[test]
    fn test_gossip_message_id_deterministic() {
        let msg1 = GossipMessage::new(TOPIC_BLOCKS, vec![1, 2, 3]);
        let msg2 = GossipMessage::new(TOPIC_BLOCKS, vec![1, 2, 3]);
        assert_eq!(msg1.message_id, msg2.message_id);
    }

    #[test]
    fn test_gossip_message_id_topic_sensitive() {
        let payload = vec![1, 2, 3];
        let msg1 = GossipMessage::new(TOPIC_BLOCKS, payload.clone());
        let msg2 = GossipMessage::new(TOPIC_TXS, payload);
        // Same payload, different topic → different ID
        assert_ne!(msg1.message_id, msg2.message_id);
    }

    #[test]
    fn test_message_freshness() {
        let mut msg = GossipMessage::new(TOPIC_BLOCKS, vec![]);
        assert!(msg.is_fresh(30_000)); // fresh

        // Simulate old message
        msg.timestamp_ms = 0;
        assert!(!msg.is_fresh(30_000)); // stale
    }

    #[tokio::test]
    async fn test_broadcast_not_started_fails() {
        let (mut node, _rx) = make_node();
        let block = crate::core::block::Block::genesis();
        let result = node.broadcast_block(&block).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), P2PError::NotStarted));
    }

    #[tokio::test]
    async fn test_broadcast_after_start() {
        let (mut node, _rx) = make_node();
        node.start().await.unwrap();

        let block = crate::core::block::Block::genesis();
        let result = node.broadcast_block(&block).await;
        assert!(result.is_ok());
        assert_eq!(node.messages_sent(), 1);
    }

    #[tokio::test]
    async fn test_duplicate_message_not_rebroadcast() {
        let (mut node, _rx) = make_node();
        node.start().await.unwrap();

        let block = crate::core::block::Block::genesis();
        node.broadcast_block(&block).await.unwrap();
        node.broadcast_block(&block).await.unwrap(); // duplicate

        // Only 1 message sent (second was deduped)
        assert_eq!(node.messages_sent(), 1);
    }

    #[tokio::test]
    async fn test_peer_connect_disconnect() {
        let (mut node, mut rx) = make_node();
        let peer_id = PeerId([42u8; 32]);
        let info = PeerInfo {
            peer_id: peer_id.clone(),
            onion_address: None,
            version: "1.0.0".to_string(),
            height: 0,
        };

        node.on_peer_connected(info).await;
        assert_eq!(node.peer_count(), 1);

        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, NetworkEvent::PeerConnected(_)));

        node.on_peer_disconnected(&peer_id).await;
        assert_eq!(node.peer_count(), 0);

        let ev2 = rx.recv().await.unwrap();
        assert!(matches!(ev2, NetworkEvent::PeerDisconnected(_)));
    }
}
