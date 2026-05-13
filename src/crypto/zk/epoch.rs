// CipherX — Epoch Manager (Phase 4)
//
// Epochs control nullifier rotation for validators.
// Each epoch, validators must refresh their stake proof with a new nullifier.
// This prevents linking validator activity across epochs.
//
// Epoch parameters:
//   Duration: ~1 day (86400 blocks at 1s, or ~216000 at 400ms)
//   Refresh window: last 10% of epoch (validators submit new proofs)
//   Grace period: first 5% of next epoch (old proofs still accepted)
//
// During epoch transition:
//   - Old nullifiers expire
//   - Validators submit new proofs with new nullifiers
//   - Validators who fail to refresh are flagged (then slashed if repeated)

use crate::core::chain::ChainParams;

/// Epoch duration in blocks (1 day at 400ms block time)
pub const EPOCH_BLOCKS: u64 = 24 * 3600 * 1000 / ChainParams::BLOCK_TIME_MS;

/// Refresh window: last 10% of epoch
pub const REFRESH_WINDOW_BLOCKS: u64 = EPOCH_BLOCKS / 10;

/// Grace period: first 5% of next epoch
pub const GRACE_PERIOD_BLOCKS: u64 = EPOCH_BLOCKS / 20;

pub struct EpochManager {
    pub current_epoch: u64,
    pub epoch_start_height: u64,
}

impl EpochManager {
    pub fn new(genesis_height: u64) -> Self {
        EpochManager {
            current_epoch: 0,
            epoch_start_height: genesis_height,
        }
    }

    /// Current epoch number for a given block height
    pub fn epoch_at(&self, height: u64) -> u64 {
        height / EPOCH_BLOCKS
    }

    /// Check if we're in the refresh window (validators should submit new proofs)
    pub fn in_refresh_window(&self, height: u64) -> bool {
        let offset = height % EPOCH_BLOCKS;
        offset >= EPOCH_BLOCKS - REFRESH_WINDOW_BLOCKS
    }

    /// Check if we're in the grace period of a new epoch
    pub fn in_grace_period(&self, height: u64) -> bool {
        let offset = height % EPOCH_BLOCKS;
        offset < GRACE_PERIOD_BLOCKS
    }

    /// Check if a proof epoch is still valid at current height
    /// (accepts current epoch + grace period from previous epoch)
    pub fn is_proof_valid(&self, proof_epoch: u64, current_height: u64) -> bool {
        let current_epoch = self.epoch_at(current_height);
        if proof_epoch == current_epoch {
            return true;
        }
        // Accept previous epoch proof if we're in grace period
        if proof_epoch + 1 == current_epoch && self.in_grace_period(current_height) {
            return true;
        }
        false
    }

    /// Advance to next epoch
    pub fn advance(&mut self, new_height: u64) {
        let new_epoch = self.epoch_at(new_height);
        if new_epoch > self.current_epoch {
            self.current_epoch = new_epoch;
            self.epoch_start_height = new_epoch * EPOCH_BLOCKS;
        }
    }

    /// Blocks remaining in current epoch
    pub fn blocks_until_next_epoch(&self, height: u64) -> u64 {
        let next_epoch_start = (self.epoch_at(height) + 1) * EPOCH_BLOCKS;
        next_epoch_start.saturating_sub(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_calculation() {
        let em = EpochManager::new(0);
        assert_eq!(em.epoch_at(0), 0);
        assert_eq!(em.epoch_at(EPOCH_BLOCKS - 1), 0);
        assert_eq!(em.epoch_at(EPOCH_BLOCKS), 1);
        assert_eq!(em.epoch_at(EPOCH_BLOCKS * 2), 2);
    }

    #[test]
    fn test_refresh_window() {
        let em = EpochManager::new(0);
        // Not in refresh window at start
        assert!(!em.in_refresh_window(0));
        // In refresh window near end of epoch
        let near_end = EPOCH_BLOCKS - REFRESH_WINDOW_BLOCKS;
        assert!(em.in_refresh_window(near_end));
    }

    #[test]
    fn test_grace_period() {
        let em = EpochManager::new(0);
        // In grace period at start of new epoch
        assert!(em.in_grace_period(EPOCH_BLOCKS));
        // Not in grace period mid-epoch
        assert!(!em.in_grace_period(EPOCH_BLOCKS / 2));
    }

    #[test]
    fn test_proof_validity() {
        let em = EpochManager::new(0);
        let mid_epoch = EPOCH_BLOCKS / 2;

        // Current epoch proof is valid
        assert!(em.is_proof_valid(0, mid_epoch));

        // Previous epoch proof not valid outside grace period
        assert!(!em.is_proof_valid(0, EPOCH_BLOCKS + GRACE_PERIOD_BLOCKS + 1));

        // Previous epoch proof valid in grace period
        assert!(em.is_proof_valid(0, EPOCH_BLOCKS + 1));
    }
}
