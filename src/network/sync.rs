// CipherX — Block Sync Protocol (Phase 6)
//
// When a node joins the network or falls behind, it syncs blocks from peers.
//
// Sync modes:
//   Fast sync  — download only block headers + state snapshot (for new nodes)
//   Full sync  — download all blocks from genesis (for archival nodes)
//   Catchup    — download missing blocks when slightly behind
//
// Privacy: sync requests go through Tor, no peer knows the full chain height
// of the requester (requests are spread across multiple peers).

use tracing::info;
use super::peer::PeerId;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncMode {
    /// Download all blocks from genesis
    Full,
    /// Download headers + state snapshot
    Fast,
    /// Download only missing blocks (short catchup)
    Catchup { from: u64, to: u64 },
}

#[derive(Debug)]
pub struct SyncState {
    pub mode: SyncMode,
    pub local_height: u64,
    pub target_height: u64,
    pub syncing: bool,
    pub blocks_downloaded: u64,
    /// Peer we're currently syncing from
    pub sync_peer: Option<PeerId>,
}

impl SyncState {
    pub fn new(local_height: u64) -> Self {
        SyncState {
            mode: SyncMode::Catchup { from: local_height, to: local_height },
            local_height,
            target_height: local_height,
            syncing: false,
            blocks_downloaded: 0,
            sync_peer: None,
        }
    }

    /// Called when we learn of a peer with a higher chain height
    pub fn update_target(&mut self, peer_height: u64, peer: PeerId) {
        if peer_height > self.target_height {
            self.target_height = peer_height;
            info!("📡 Sync target updated to height {} from peer {:?}", peer_height, &peer.to_hex()[..8]);

            // Choose sync mode
            let gap = peer_height.saturating_sub(self.local_height);
            self.mode = if gap > 10_000 {
                SyncMode::Fast
            } else {
                SyncMode::Catchup { from: self.local_height + 1, to: peer_height }
            };

            if !self.syncing {
                self.syncing = true;
                self.sync_peer = Some(peer);
            }
        }
    }

    /// Called when a block is successfully applied
    pub fn on_block_applied(&mut self, height: u64) {
        self.local_height = height;
        self.blocks_downloaded += 1;

        if self.local_height >= self.target_height {
            self.syncing = false;
            self.sync_peer = None;
            info!("✅ Sync complete at height {}", self.local_height);
        }
    }

    pub fn is_synced(&self) -> bool {
        !self.syncing && self.local_height >= self.target_height
    }

    pub fn blocks_remaining(&self) -> u64 {
        self.target_height.saturating_sub(self.local_height)
    }

    pub fn progress_pct(&self) -> f64 {
        if self.target_height == 0 { return 100.0; }
        (self.local_height as f64 / self.target_height as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId { PeerId([1u8; 32]) }

    #[test]
    fn test_sync_state_initial() {
        let s = SyncState::new(100);
        assert_eq!(s.local_height, 100);
        assert!(s.is_synced());
    }

    #[test]
    fn test_sync_target_update() {
        let mut s = SyncState::new(100);
        s.update_target(200, peer());
        assert!(s.syncing);
        assert_eq!(s.target_height, 200);
        assert_eq!(s.blocks_remaining(), 100);
    }

    #[test]
    fn test_sync_fast_mode_large_gap() {
        let mut s = SyncState::new(0);
        s.update_target(50_000, peer());
        assert!(matches!(s.mode, SyncMode::Fast));
    }

    #[test]
    fn test_sync_catchup_small_gap() {
        let mut s = SyncState::new(1000);
        s.update_target(1050, peer());
        assert!(matches!(s.mode, SyncMode::Catchup { .. }));
    }

    #[test]
    fn test_sync_complete() {
        let mut s = SyncState::new(99);
        s.update_target(100, peer());
        s.on_block_applied(100);
        assert!(s.is_synced());
        assert!(!s.syncing);
    }

    #[test]
    fn test_progress_pct() {
        let mut s = SyncState::new(500);
        s.update_target(1000, peer());
        assert!((s.progress_pct() - 50.0).abs() < 0.1);
    }
}
