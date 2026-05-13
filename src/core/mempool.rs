// CipherX — Mempool
//
// Holds pending transactions waiting to be included in a block.
// All transactions are validated before entering the pool.
// Ordering: by fee (highest first) — fee is proven via ZK, not revealed.

use std::collections::HashMap;
use crate::core::transaction::{Transaction, TxId};

/// Maximum mempool size (number of transactions)
const MAX_MEMPOOL_SIZE: usize = 50_000;

pub struct Mempool {
    /// Pending transactions
    txs: HashMap<TxId, Transaction>,

    /// Key images seen in mempool (anti double-spend within mempool)
    pending_key_images: HashMap<[u8; 32], TxId>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            pending_key_images: HashMap::new(),
        }
    }

    /// Add a transaction to the mempool
    pub fn add(&mut self, tx: Transaction) -> Result<TxId, String> {
        if self.txs.len() >= MAX_MEMPOOL_SIZE {
            return Err("Mempool full".to_string());
        }

        // Check for key image conflicts within mempool
        for input in &tx.inputs {
            if let Some(existing_id) = self.pending_key_images.get(&input.key_image.0) {
                return Err(format!(
                    "Key image already in mempool (tx: {})",
                    existing_id.to_hex()
                ));
            }
        }

        // Verify transaction
        if !tx.verify() {
            return Err("Transaction verification failed".to_string());
        }

        let tx_id = tx.id();

        // Register key images
        for input in &tx.inputs {
            self.pending_key_images.insert(input.key_image.0, tx_id.clone());
        }

        self.txs.insert(tx_id.clone(), tx);
        Ok(tx_id)
    }

    /// Remove a transaction (after inclusion in block)
    pub fn remove(&mut self, tx_id: &TxId) {
        if let Some(tx) = self.txs.remove(tx_id) {
            for input in &tx.inputs {
                self.pending_key_images.remove(&input.key_image.0);
            }
        }
    }

    /// Get transactions for block proposal (up to `limit`)
    /// Ordered by fee proof priority (placeholder: FIFO for now)
    pub fn get_for_block(&self, limit: usize) -> Vec<&Transaction> {
        self.txs.values().take(limit).collect()
    }

    /// Remove transactions whose key images have been spent on-chain
    pub fn purge_spent(&mut self, spent_key_images: &[[u8; 32]]) {
        let to_remove: Vec<TxId> = spent_key_images
            .iter()
            .filter_map(|ki| self.pending_key_images.get(ki))
            .cloned()
            .collect();

        for tx_id in to_remove {
            self.remove(&tx_id);
        }
    }

    pub fn size(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}
