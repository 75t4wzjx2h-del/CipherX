// CipherX — Chain
//
// Manages:
//   - Block validation and appending
//   - UTXO set (all unspent outputs — private)
//   - Key image set (spent outputs — for double-spend prevention)
//   - Chain state (height, tip hash, total supply)
//   - Halving schedule
//   - Staking lock period (adaptive exit queue)

use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::info;

use crate::core::block::{Block, BlockHash};
use crate::core::transaction::{Transaction, TxId, TxType, StealthOutput, PedersenCommitment};

/// CipherX network constants
pub struct ChainParams;

impl ChainParams {
    /// Total supply cap
    pub const MAX_SUPPLY: u64 = 100_000_000;

    /// Premine (0.002% of supply = 2000 CIP)
    pub const PREMINE: u64 = 2_000;

    /// Minimum validator stake
    pub const MIN_STAKE: u64 = 31;

    /// Initial block reward (in nCIP — nano CIP, 1 CIP = 1_000_000_000 nCIP)
    pub const INITIAL_BLOCK_REWARD: u64 = 50 * 1_000_000_000;

    /// Halving interval (~4 years at 1 block/sec = ~126_144_000 blocks)
    /// Using 1s block time → 4 * 365.25 * 24 * 3600
    pub const HALVING_INTERVAL: u64 = 126_144_000;

    /// Target block time in milliseconds (400ms — Solana-level)
    pub const BLOCK_TIME_MS: u64 = 400;

    /// Minimum exit lock period (weeks in blocks)
    pub const MIN_EXIT_LOCK_BLOCKS: u64 = 2 * 7 * 24 * 3600 * 1000 / Self::BLOCK_TIME_MS;

    /// Maximum exit lock period (weeks in blocks)
    pub const MAX_EXIT_LOCK_BLOCKS: u64 = 7 * 7 * 24 * 3600 * 1000 / Self::BLOCK_TIME_MS;

    /// Maximum exit lock extension (10 days in blocks)
    pub const MAX_LOCK_EXTENSION_BLOCKS: u64 = 10 * 24 * 3600 * 1000 / Self::BLOCK_TIME_MS;

    /// Ring size (number of decoys per input, including real)
    pub const RING_SIZE: usize = 11; // Monero uses 11 by default

    /// Compute block reward at a given height (with halvings)
    pub fn block_reward(height: u64) -> u64 {
        let halvings = height / Self::HALVING_INTERVAL;
        if halvings >= 64 {
            return 0; // Fully mined out
        }
        Self::INITIAL_BLOCK_REWARD >> halvings
    }

    /// Compute adaptive exit lock based on pending withdrawal queue
    /// More validators exiting → longer lock
    pub fn adaptive_exit_lock(pending_exits: u64, total_validators: u64) -> u64 {
        if total_validators == 0 {
            return Self::MIN_EXIT_LOCK_BLOCKS;
        }

        let exit_ratio = pending_exits as f64 / total_validators as f64;

        // Linear interpolation between MIN and MAX based on exit pressure
        let lock = Self::MIN_EXIT_LOCK_BLOCKS as f64
            + exit_ratio * (Self::MAX_EXIT_LOCK_BLOCKS - Self::MIN_EXIT_LOCK_BLOCKS) as f64;

        lock.min(Self::MAX_EXIT_LOCK_BLOCKS as f64) as u64
    }
}

/// Chain errors
#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Block height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },

    #[error("Invalid previous hash")]
    InvalidPrevHash,

    #[error("Invalid block signature")]
    InvalidSignature,

    #[error("Transaction already spent (double spend): {0}")]
    DoubleSpend(String),

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Block not found at height {0}")]
    BlockNotFound(u64),

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Unspent transaction output (private — only commitment stored)
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub output: StealthOutput,
    pub block_height: u64,
    pub tx_id: TxId,
    pub output_index: u32,
}

/// Pending validator exit request
#[derive(Debug, Clone)]
pub struct ExitRequest {
    /// Validator commitment (anonymous)
    pub validator_commitment: Vec<u8>,
    /// Height when request was submitted
    pub request_height: u64,
    /// Height when exit becomes valid
    pub unlock_height: u64,
    /// Stake amount (as commitment — private)
    pub stake_commitment: PedersenCommitment,
}

/// Main chain state
pub struct Chain {
    /// All blocks indexed by hash
    blocks_by_hash: HashMap<BlockHash, Block>,

    /// Block hash at each height
    blocks_by_height: Vec<BlockHash>,

    /// UTXO set — key: (tx_id, output_index)
    utxo_set: HashMap<(TxId, u32), UtxoEntry>,

    /// Spent key images — for double-spend prevention
    spent_key_images: HashSet<[u8; 32]>,

    /// Pending exit queue — for adaptive lock calculation
    pending_exits: Vec<ExitRequest>,

    /// Total active validators count
    total_validators: u64,

    /// Circulating supply (in nCIP)
    circulating_supply: u64,

    /// Current chain height
    pub height: u64,

    /// Hash of the current tip
    pub tip_hash: BlockHash,
}

impl Chain {
    /// Initialize a new chain with genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();

        info!("⛓️  CipherX chain initialized");
        info!("📦 Genesis block: {}", genesis_hash.to_hex());
        info!("🔒 Ring size: {} | Block time: {}ms", ChainParams::RING_SIZE, ChainParams::BLOCK_TIME_MS);
        info!("💰 Max supply: {} CIP | Premine: {} CIP", ChainParams::MAX_SUPPLY, ChainParams::PREMINE);

        let mut blocks_by_hash = HashMap::new();
        blocks_by_hash.insert(genesis_hash.clone(), genesis);

        Chain {
            blocks_by_hash,
            blocks_by_height: vec![genesis_hash.clone()],
            utxo_set: HashMap::new(),
            spent_key_images: HashSet::new(),
            pending_exits: vec![],
            total_validators: 1, // starts with 1 (owner)
            circulating_supply: ChainParams::PREMINE * 1_000_000_000, // premine in nCIP
            height: 0,
            tip_hash: genesis_hash,
        }
    }

    /// Get current tip block
    pub fn tip(&self) -> &Block {
        self.blocks_by_hash.get(&self.tip_hash).unwrap()
    }

    /// Get block by height
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        self.blocks_by_height
            .get(height as usize)
            .and_then(|hash| self.blocks_by_hash.get(hash))
    }

    /// Get block by hash
    pub fn block_by_hash(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks_by_hash.get(hash)
    }

    /// Validate and append a new block
    pub fn append_block(&mut self, block: Block) -> Result<(), ChainError> {
        // 1. Height check
        let expected_height = self.height + 1;
        if block.header.height != expected_height {
            return Err(ChainError::HeightMismatch {
                expected: expected_height,
                got: block.header.height,
            });
        }

        // 2. Previous hash check
        if block.header.prev_hash != self.tip_hash {
            return Err(ChainError::InvalidPrevHash);
        }

        // 3. Validate coinbase structure: at most one, must be first, only validator may include it
        let coinbase_count = block.transactions.iter()
            .filter(|tx| tx.tx_type == TxType::Coinbase)
            .count();
        if coinbase_count > 1 {
            return Err(ChainError::InvalidTransaction(
                "block contains more than one coinbase transaction".to_string()
            ));
        }
        if coinbase_count == 1 {
            if block.transactions.first().map(|tx| tx.tx_type != TxType::Coinbase).unwrap_or(true) {
                return Err(ChainError::InvalidTransaction(
                    "coinbase must be the first transaction in a block".to_string()
                ));
            }
        }

        // 4. Validate all transactions
        for tx in &block.transactions {
            self.validate_transaction(tx)?;
        }

        // 4. Apply block to state
        let block_hash = block.hash();
        self.apply_block(&block)?;

        // 5. Update chain state
        self.height = expected_height;
        self.tip_hash = block_hash.clone();
        self.blocks_by_height.push(block_hash.clone());
        self.blocks_by_hash.insert(block_hash.clone(), block);

        info!("✅ Block #{} accepted | hash: {}", expected_height, block_hash.to_hex());

        Ok(())
    }

    /// Validate a single transaction
    fn validate_transaction(&self, tx: &Transaction) -> Result<(), ChainError> {
        // Check for double spends
        for input in &tx.inputs {
            if self.spent_key_images.contains(&input.key_image.0) {
                return Err(ChainError::DoubleSpend(
                    hex::encode(input.key_image.0)
                ));
            }
        }

        // Verify cryptographic proofs
        if !tx.verify() {
            return Err(ChainError::InvalidTransaction(
                "cryptographic verification failed".to_string()
            ));
        }

        Ok(())
    }

    /// Apply a validated block to the chain state
    fn apply_block(&mut self, block: &Block) -> Result<(), ChainError> {
        for tx in &block.transactions {
            // Mark inputs as spent
            for input in &tx.inputs {
                self.spent_key_images.insert(input.key_image.0);
            }

            // Add new outputs to UTXO set
            let tx_id = tx.id();
            for (idx, output) in tx.outputs.iter().enumerate() {
                let entry = UtxoEntry {
                    output: output.clone(),
                    block_height: block.header.height,
                    tx_id: tx_id.clone(),
                    output_index: idx as u32,
                };
                self.utxo_set.insert((tx_id.clone(), idx as u32), entry);
            }

            // Update supply for coinbase, respecting hard cap
            if tx.tx_type == TxType::Coinbase {
                let reward = ChainParams::block_reward(block.header.height);
                let max_ncip = ChainParams::MAX_SUPPLY * 1_000_000_000;
                self.circulating_supply = self.circulating_supply
                    .saturating_add(reward)
                    .min(max_ncip);
            }
        }

        Ok(())
    }

    /// Calculate adaptive exit lock for a new withdrawal request
    pub fn calculate_exit_lock(&self) -> u64 {
        ChainParams::adaptive_exit_lock(
            self.pending_exits.len() as u64,
            self.total_validators,
        )
    }

    /// Chain stats (for node dashboard — no private info)
    pub fn stats(&self) -> ChainStats {
        ChainStats {
            height: self.height,
            tip_hash: self.tip_hash.to_hex(),
            utxo_count: self.utxo_set.len(),
            spent_outputs: self.spent_key_images.len(),
            pending_exits: self.pending_exits.len(),
            total_validators: self.total_validators,
            circulating_supply_cip: self.circulating_supply / 1_000_000_000,
            next_block_reward_cip: ChainParams::block_reward(self.height + 1) / 1_000_000_000,
            next_halving_block: {
                let halvings_done = self.height / ChainParams::HALVING_INTERVAL;
                (halvings_done + 1) * ChainParams::HALVING_INTERVAL
            },
        }
    }
}

/// Public chain statistics (no private data)
#[derive(Debug)]
pub struct ChainStats {
    pub height: u64,
    pub tip_hash: String,
    pub utxo_count: usize,
    pub spent_outputs: usize,
    pub pending_exits: usize,
    pub total_validators: u64,
    pub circulating_supply_cip: u64,
    pub next_block_reward_cip: u64,
    pub next_halving_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_init() {
        let chain = Chain::new();
        assert_eq!(chain.height, 0);
        let stats = chain.stats();
        println!("Genesis tip: {}", stats.tip_hash);
        println!("Circulating: {} CIP", stats.circulating_supply_cip);
    }

    #[test]
    fn test_block_reward_halvings() {
        // Initial reward
        assert_eq!(ChainParams::block_reward(0), 50 * 1_000_000_000);
        // After 1st halving
        assert_eq!(ChainParams::block_reward(ChainParams::HALVING_INTERVAL), 25 * 1_000_000_000);
        // After 2nd halving
        assert_eq!(ChainParams::block_reward(ChainParams::HALVING_INTERVAL * 2), 12 * 1_000_000_000 + 500_000_000);
        // Way in the future — no more reward
        assert_eq!(ChainParams::block_reward(ChainParams::HALVING_INTERVAL * 100), 0);
    }

    #[test]
    fn test_adaptive_exit_lock() {
        // No exits → minimum lock
        let lock = ChainParams::adaptive_exit_lock(0, 100);
        assert_eq!(lock, ChainParams::MIN_EXIT_LOCK_BLOCKS);

        // All validators exiting → maximum lock
        let lock = ChainParams::adaptive_exit_lock(100, 100);
        assert_eq!(lock, ChainParams::MAX_EXIT_LOCK_BLOCKS);

        // 50% exiting → somewhere in the middle
        let lock = ChainParams::adaptive_exit_lock(50, 100);
        assert!(lock > ChainParams::MIN_EXIT_LOCK_BLOCKS);
        assert!(lock < ChainParams::MAX_EXIT_LOCK_BLOCKS);
    }
}
