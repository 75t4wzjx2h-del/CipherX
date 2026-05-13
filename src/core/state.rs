// CipherX — Chain State Manager
//
// Coordinates:
//   - Fee market (EIP-1559-style base fee adjustment)
//   - Persistence hooks (delegates writes to CipherXDb)
//   - Clean interface for RPC server and mempool

use std::sync::Arc;
use tracing::info;

use crate::core::block::{Block, BlockHash};
use crate::storage::db::CipherXDb;

// ─── Fee market (EIP-1559 style) ─────────────────────────────────────────────

/// EIP-1559-style fee market: base fee adjusts per block based on gas usage.
/// Base fee is burned; priority tip goes to the validator.
#[derive(Debug, Clone)]
pub struct FeeMarket {
    pub base_fee_per_gas: u64,
    pub target_gas_per_block: u64,
    pub max_gas_per_block: u64,
    pub last_gas_used: u64,
}

impl FeeMarket {
    pub fn new() -> Self {
        FeeMarket {
            base_fee_per_gas:      1_000,        // 1 000 nCIP/gas ≈ 0.000001 CIP/gas
            target_gas_per_block:  15_000_000,
            max_gas_per_block:     30_000_000,
            last_gas_used:         0,
        }
    }

    /// Adjust base fee after a block.
    /// Over target  → fee up   (max +12.5%)
    /// Under target → fee down (max −12.5%)
    pub fn update(&mut self, gas_used: u64) {
        let target = self.target_gas_per_block;
        self.last_gas_used = gas_used;
        if gas_used == target {
            return;
        }
        let delta = if gas_used > target {
            (self.base_fee_per_gas * (gas_used - target) / target / 8).max(1)
        } else {
            (self.base_fee_per_gas * (target - gas_used) / target / 8).max(1)
        };
        if gas_used > target {
            self.base_fee_per_gas = self.base_fee_per_gas.saturating_add(delta);
        } else {
            self.base_fee_per_gas = self.base_fee_per_gas.saturating_sub(delta).max(1);
        }
    }

    pub fn min_fee_ncip(&self, gas_limit: u64) -> u64 {
        gas_limit * self.base_fee_per_gas
    }
}

// ─── Persistent state coordinator ────────────────────────────────────────────

/// Wraps DB access and fee market; does NOT duplicate the in-memory UTXO set
/// (that lives in `Chain`).  Call `persist_block` after every appended block.
pub struct PersistentState {
    db: Arc<CipherXDb>,
    pub fee_market: FeeMarket,
}

impl PersistentState {
    pub fn open(db_path: &str) -> Result<Self, String> {
        let db = CipherXDb::open(db_path)?;
        info!("💾 RocksDB opened at {}", db_path);
        Ok(PersistentState {
            db: Arc::new(db),
            fee_market: FeeMarket::new(),
        })
    }

    pub fn db(&self) -> Arc<CipherXDb> {
        self.db.clone()
    }

    // ── Chain-tip persistence ─────────────────────────────────────────────────

    /// Persist block + update chain-tip pointer.
    pub fn persist_block(&self, block: &Block) -> Result<(), String> {
        self.db.put_block(block)?;
        self.db.save_chain_state(block.header.height, &block.hash())
    }

    /// Persist only the chain-tip pointer (no block data).
    pub fn save_tip(&self, height: u64, tip: &BlockHash) -> Result<(), String> {
        self.db.save_chain_state(height, tip)
    }

    /// Load last persisted height + tip hash (None = fresh chain).
    pub fn load_tip(&self) -> Result<Option<(u64, BlockHash)>, String> {
        self.db.load_chain_state()
    }

    // ── Key images ────────────────────────────────────────────────────────────

    pub fn persist_key_image(&self, ki: &[u8; 32]) -> Result<(), String> {
        self.db.put_key_image(ki)
    }

    pub fn is_key_image_spent(&self, ki: &[u8; 32]) -> Result<bool, String> {
        self.db.has_key_image(ki)
    }

    // ── Fee market ────────────────────────────────────────────────────────────

    pub fn on_block_applied(&mut self, gas_used: u64) {
        self.fee_market.update(gas_used);
    }

    pub fn base_fee(&self) -> u64 {
        self.fee_market.base_fee_per_gas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_path() -> String {
        format!("{}/cipherx_state_test_{}", env::temp_dir().display(), rand::random::<u64>())
    }

    #[test]
    fn test_fee_market_up_when_full() {
        let mut fm = FeeMarket::new();
        let initial = fm.base_fee_per_gas;
        fm.update(fm.max_gas_per_block);
        assert!(fm.base_fee_per_gas > initial);
    }

    #[test]
    fn test_fee_market_down_when_empty() {
        let mut fm = FeeMarket::new();
        let initial = fm.base_fee_per_gas;
        fm.update(0);
        assert!(fm.base_fee_per_gas < initial);
    }

    #[test]
    fn test_fee_market_stable_at_target() {
        let mut fm = FeeMarket::new();
        let initial = fm.base_fee_per_gas;
        fm.update(fm.target_gas_per_block);
        assert_eq!(fm.base_fee_per_gas, initial);
    }

    #[test]
    fn test_persistent_state_open_and_tip() {
        let path = tmp_path();
        let state = PersistentState::open(&path).unwrap();
        assert!(state.load_tip().unwrap().is_none());

        let tip = BlockHash([0x11u8; 32]);
        state.save_tip(10, &tip).unwrap();
        let (h, t) = state.load_tip().unwrap().unwrap();
        assert_eq!(h, 10);
        assert_eq!(t, tip);
    }

    #[test]
    fn test_key_image_persistence() {
        let path = tmp_path();
        let state = PersistentState::open(&path).unwrap();
        let ki = [0x42u8; 32];
        assert!(!state.is_key_image_spent(&ki).unwrap());
        state.persist_key_image(&ki).unwrap();
        assert!(state.is_key_image_spent(&ki).unwrap());
    }
}
