// CipherX — Peer Management (Phase 6)

use serde::{Serialize, Deserialize};

/// Anonymous peer identifier (ephemeral — rotates periodically)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
}

/// Public peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub onion_address: Option<String>,
    pub version: String,
    pub height: u64,
}

/// Peer reputation (for banning misbehaving peers)
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub peer_id: PeerId,
    pub score: i32,    // 0-100, lower = worse
    pub bans: u32,
}

impl PeerReputation {
    pub fn new(peer_id: PeerId) -> Self {
        PeerReputation { peer_id, score: 100, bans: 0 }
    }

    pub fn penalize(&mut self, amount: i32) {
        self.score = (self.score - amount).max(0);
    }

    pub fn is_banned(&self) -> bool {
        self.score == 0
    }
}
