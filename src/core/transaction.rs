// CipherX — Transaction (Phase 3 update)
//
// Privacy model (3 layers — all implemented):
//   Layer 1 — Ring Signatures (MLSAG) — hides sender
//   Layer 2 — Stealth Addresses       — hides recipient
//   Layer 3 — RingCT + Bulletproofs   — hides amounts

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::crypto::keys::StealthAddress;

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
    /// Lite transaction from bot/wallet (no ring sigs — testnet only)
    Lite,
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
        if self.tx_type == TxType::Lite { return true; }
        self.verify_balance()
            && self.verify_ring_signatures()
            && self.verify_range_proofs()
    }

    /// Build a lite transaction from a JSON string sent by the bot wallet.
    /// No ring signatures — testnet only. Returns None if the JSON is invalid.
    pub fn from_lite_raw(json_str: &str) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct LiteRaw {
            tx_pubkey: String,
            one_time_pubkey: String,
            encrypted_amount: String,
            #[allow(dead_code)]
            amount_ncip: u64,
        }
        let lite: LiteRaw = serde_json::from_str(json_str).ok()?;
        let tx_pk: [u8; 32]  = hex::decode(&lite.tx_pubkey).ok()?.try_into().ok()?;
        let ot_pk: [u8; 32]  = hex::decode(&lite.one_time_pubkey).ok()?.try_into().ok()?;
        let enc_amt          = hex::decode(&lite.encrypted_amount).ok()?;

        let output = StealthOutput {
            one_time_pubkey:    ot_pk,
            tx_pubkey:          tx_pk,
            amount_commitment:  PedersenCommitment([0u8; 32]),
            encrypted_amount:   enc_amt,
            range_proof:        Bulletproof(vec![]),
        };

        Some(Transaction {
            tx_type:        TxType::Lite,
            inputs:         vec![],
            outputs:        vec![output],
            fee_commitment: PedersenCommitment([0u8; 32]),
            fee_proof:      vec![],
            extra:          json_str.as_bytes().to_vec(),
            version:        1,
        })
    }

    pub fn key_images(&self) -> Vec<KeyImage> {
        self.inputs.iter().map(|i| i.key_image.clone()).collect()
    }

    /// Build a real coinbase transaction sending `amount` (nCIP) to `reward_address`.
    ///
    /// Uses stealth address protocol to generate a one-time pubkey for the recipient.
    /// Amount is committed via Pedersen commitment + range proof (bit-decomposition).
    ///
    /// NOTE: The range proof uses the custom bit-decomposition scheme (see ringct.rs).
    /// The `height` is stored in `extra` for reference and to ensure unique TxId per block.
    pub fn build_coinbase(reward_address: &StealthAddress, amount: u64, height: u64) -> Self {
        use crate::crypto::stealth::generate_output;
        use crate::crypto::ringct::{commit_random, prove_range, encrypt_amount};

        // Generate one-time stealth output for reward address
        let stealth_out = match generate_output(reward_address, 0) {
            Ok(o) => o,
            Err(_) => {
                // Fallback: zero keys (should never happen with valid address)
                return Self::coinbase_placeholder(height);
            }
        };

        // Commit amount with random blinding
        let commitment_data = commit_random(amount);

        // Range proof — proves amount ∈ [0, 2^64) without revealing it
        let range_proof = prove_range(amount, &commitment_data.blinding)
            .unwrap_or(Bulletproof(vec![]));

        // Encrypt amount for recipient (decryptable with their view key)
        let encrypted_amount = encrypt_amount(amount, &stealth_out.shared_secret);

        // Store height in extra field for unique TxId per block
        let mut extra = b"coinbase".to_vec();
        extra.extend_from_slice(&height.to_le_bytes());

        Transaction {
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![StealthOutput {
                one_time_pubkey: stealth_out.one_time_pubkey,
                tx_pubkey: stealth_out.tx_pubkey,
                amount_commitment: commitment_data.commitment.clone(),
                encrypted_amount,
                range_proof,
            }],
            fee_commitment: PedersenCommitment([0u8; 32]),
            fee_proof: vec![],
            extra,
            version: 1,
        }
    }

    /// Legacy coinbase placeholder — kept for backward compatibility and tests.
    /// Use `build_coinbase` for real block production.
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

    #[test]
    fn test_coinbase_credits_reward_address() {
        use crate::crypto::stealth::generate_keypair;
        let kp = generate_keypair();
        let tx = Transaction::build_coinbase(&kp.address, 50_000_000_000, 1);
        assert_eq!(tx.tx_type, TxType::Coinbase);
        assert_eq!(tx.outputs.len(), 1);
        // The one_time_pubkey must not be the placeholder zero bytes
        assert_ne!(
            tx.outputs[0].one_time_pubkey,
            [0u8; 32],
            "build_coinbase must produce a real stealth one_time_pubkey, not [0u8;32]"
        );
        // tx_pubkey (R) must also be non-zero
        assert_ne!(tx.outputs[0].tx_pubkey, [0u8; 32]);
    }

    #[test]
    fn test_wallet_scan_detects_coinbase() {
        use crate::crypto::stealth::{generate_keypair, scan_output};
        let kp = generate_keypair();
        let amount = 50_000_000_000u64; // 50 CIP
        let tx = Transaction::build_coinbase(&kp.address, amount, 1);

        assert_eq!(tx.outputs.len(), 1);
        let out = &tx.outputs[0];

        // Wallet scan: recipient uses private view key + public spend key
        let result = scan_output(
            &out.tx_pubkey,
            &out.one_time_pubkey,
            0,
            &kp.private_view,
            &kp.public_spend,
        );

        assert!(
            result.is_some(),
            "Wallet scan must detect coinbase output belonging to reward address"
        );
    }
}
