// CipherX — Transaction (Phase 3 update)
//
// Privacy model (3 layers — all implemented):
//   Layer 1 — Ring Signatures (MLSAG) — hides sender
//   Layer 2 — Stealth Addresses       — hides recipient
//   Layer 3 — RingCT + Bulletproofs   — hides amounts

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxId(pub [u8; 32]);
impl TxId {
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenCommitment(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bulletproof(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyImage(pub [u8; 32]);

/// One-time stealth output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthOutput {
    /// One-time public key (derived via stealth address protocol)
    pub one_time_pubkey: [u8; 32],
    /// tx pubkey R = r*G (for recipient to scan)
    pub tx_pubkey: [u8; 32],
    /// Amount commitment C = v*H + r*G
    pub amount_commitment: PedersenCommitment,
    /// Amount encrypted with shared secret (recipient decrypts with view key)
    pub encrypted_amount: Vec<u8>,
    /// Bulletproof: v ∈ [0, 2^64)
    pub range_proof: Bulletproof,
}

/// Ring signature input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingInput {
    /// Ring members (real + decoys — indistinguishable)
    pub ring_members: Vec<[u8; 32]>,
    /// Key image (unique per output, proves no double spend)
    pub key_image: KeyImage,
    /// LSAG ring signature bytes
    pub ring_signature: Vec<u8>,
    /// Pseudo-commitment for RingCT balance check
    pub pseudo_commitment: PedersenCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxType {
    Transfer,
    Coinbase,
    StakeDeposit,
    StakeWithdraw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub tx_type: TxType,
    pub inputs: Vec<RingInput>,
    pub outputs: Vec<StealthOutput>,
    pub fee_commitment: PedersenCommitment,
    pub fee_proof: Vec<u8>,
    pub extra: Vec<u8>,
    pub version: u8,
}

impl Transaction {
    pub fn commitment_hash(&self) -> [u8; 32] {
        let encoded = bincode::serialize(self).expect("tx serialize");
        let mut hasher = Sha3_256::new();
        hasher.update(&encoded);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn id(&self) -> TxId { TxId(self.commitment_hash()) }

    /// Verify RingCT balance: sum(pseudo_commitments) == sum(output_commitments) + fee
    pub fn verify_balance(&self) -> bool {
        use crate::crypto::ringct::verify_balance;
        let inputs: Vec<_> = self.inputs.iter().map(|i| i.pseudo_commitment.clone()).collect();
        let outputs: Vec<_> = self.outputs.iter().map(|o| o.amount_commitment.clone()).collect();
        verify_balance(&inputs, &outputs, &self.fee_commitment)
    }

    /// Verify all ring signatures (parallel over inputs via rayon)
    pub fn verify_ring_signatures(&self) -> bool {
        use crate::crypto::ring_sig::verify_ring;
        use rayon::prelude::*;
        let msg = self.commitment_hash();
        self.inputs.par_iter().all(|input| {
            verify_ring(&msg, &input.ring_members, &input.ring_signature, &input.key_image)
        })
    }

    /// Verify all bulletproofs (parallel over outputs via rayon)
    pub fn verify_range_proofs(&self) -> bool {
        use crate::crypto::ringct::verify_range;
        use rayon::prelude::*;
        self.outputs.par_iter().all(|output| {
            verify_range(&output.amount_commitment, &output.range_proof)
        })
    }

    pub fn verify(&self) -> bool {
        if self.tx_type == TxType::Coinbase { return true; }
        self.verify_balance()
            && self.verify_ring_signatures()
            && self.verify_range_proofs()
    }

    pub fn key_images(&self) -> Vec<KeyImage> {
        self.inputs.iter().map(|i| i.key_image.clone()).collect()
    }

    pub fn coinbase_placeholder(height: u64) -> Self {
        Transaction {
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![StealthOutput {
                one_time_pubkey: [0u8; 32],
                tx_pubkey: [0u8; 32],
                amount_commitment: PedersenCommitment([0u8; 32]),
                encrypted_amount: height.to_le_bytes().to_vec(),
                range_proof: Bulletproof(vec![]),
            }],
            fee_commitment: PedersenCommitment([0u8; 32]),
            fee_proof: vec![],
            extra: vec![],
            version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_tx() {
        let tx = Transaction::coinbase_placeholder(1);
        assert_eq!(tx.tx_type, TxType::Coinbase);
        assert!(tx.verify());
    }

    #[test]
    fn test_tx_id_deterministic() {
        let tx = Transaction::coinbase_placeholder(42);
        assert_eq!(tx.id(), tx.id());
    }
}
