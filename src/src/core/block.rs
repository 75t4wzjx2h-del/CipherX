// CipherX — Block
//
// Every block contains:
//   - Header   : metadata, prev hash, validator, timestamp, height
//   - Body      : list of opaque (encrypted) transactions
//   - Signature : BFT validator signature (Tendermint-style)
//
// Privacy: block contents are opaque. An observer sees only:
//   - Block height
//   - Timestamp
//   - Previous block hash
//   - Current block hash
//   - Validator commitment (not identity)
//   Nothing else is readable without a view key.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use chrono::Utc;

use crate::core::transaction::Transaction;
use crate::crypto::keys::ValidatorCommitment;

/// CipherX block hash — 32 bytes, Blake3-derived
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockHash(pub [u8; 32]);

impl BlockHash {
    pub fn zero() -> Self {
        BlockHash([0u8; 32])
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(BlockHash(arr))
    }
}

/// Block header — publicly visible metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Chain version
    pub version: u32,

    /// Block height (0 = genesis)
    pub height: u64,

    /// Unix timestamp (ms)
    pub timestamp: i64,

    /// Hash of previous block
    pub prev_hash: BlockHash,

    /// Merkle root of all transactions (opaque commitments)
    pub tx_root: BlockHash,

    /// State root after applying this block
    pub state_root: BlockHash,

    /// Validator commitment (zk-proof that validator owns ≥31 CIP stake)
    /// Does NOT reveal validator identity
    pub validator_commitment: ValidatorCommitment,

    /// Tendermint round this block was proposed in
    pub round: u32,
}

impl BlockHeader {
    /// Compute the hash of this header
    pub fn hash(&self) -> BlockHash {
        let encoded = bincode::serialize(self).expect("header serialization failed");
        let mut hasher = Sha3_256::new();
        hasher.update(&encoded);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        BlockHash(hash)
    }
}

/// Full CipherX block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,

    /// Encrypted transactions — opaque to observers
    pub transactions: Vec<Transaction>,

    /// Tendermint BFT commit signatures from validators
    pub signatures: Vec<ValidatorSignature>,
}

/// A single validator signature on a block
/// The validator identity is hidden — only the commitment is exposed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// zk-proof that signer is an active validator
    pub validator_commitment: ValidatorCommitment,

    /// Ed25519 signature over block hash
    pub signature: Vec<u8>,
}

impl Block {
    /// Create the genesis block
    pub fn genesis() -> Self {
        let validator_commitment = ValidatorCommitment::placeholder();

        let header = BlockHeader {
            version: 1,
            height: 0,
            timestamp: Utc::now().timestamp_millis(),
            prev_hash: BlockHash::zero(),
            tx_root: BlockHash::zero(),
            state_root: BlockHash::zero(),
            validator_commitment,
            round: 0,
        };

        Block {
            header,
            transactions: vec![],
            signatures: vec![],
        }
    }

    /// Hash of this block (via its header)
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Compute Merkle root of all transaction commitments
    /// Transactions are opaque — only their commitment hashes are used
    pub fn compute_tx_root(txs: &[Transaction]) -> BlockHash {
        if txs.is_empty() {
            return BlockHash::zero();
        }

        let mut leaves: Vec<[u8; 32]> = txs
            .iter()
            .map(|tx| tx.commitment_hash())
            .collect();

        // Simple binary Merkle tree
        while leaves.len() > 1 {
            let mut next_level = vec![];
            let mut i = 0;
            while i < leaves.len() {
                let left = leaves[i];
                let right = if i + 1 < leaves.len() {
                    leaves[i + 1]
                } else {
                    leaves[i] // duplicate last if odd
                };

                let mut hasher = Sha3_256::new();
                hasher.update(left);
                hasher.update(right);
                let result = hasher.finalize();
                let mut node = [0u8; 32];
                node.copy_from_slice(&result);
                next_level.push(node);
                i += 2;
            }
            leaves = next_level;
        }

        BlockHash(leaves[0])
    }

    /// Number of transactions in this block
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Block size in bytes (approximate)
    pub fn byte_size(&self) -> usize {
        bincode::serialize(self)
            .map(|b| b.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.prev_hash, BlockHash::zero());
        assert_eq!(genesis.tx_count(), 0);
        println!("Genesis hash: {}", genesis.hash().to_hex());
    }

    #[test]
    fn test_block_hash_deterministic() {
        let genesis = Block::genesis();
        let h1 = genesis.hash();
        let h2 = genesis.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_merkle_root_empty() {
        let root = Block::compute_tx_root(&[]);
        assert_eq!(root, BlockHash::zero());
    }
}
