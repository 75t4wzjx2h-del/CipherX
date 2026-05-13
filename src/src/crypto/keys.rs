// CipherX — Cryptographic Keys (Phase 3)

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        PrivateKey(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewKey(pub [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAddress {
    pub public_spend: PublicKey,
    pub public_view: PublicKey,
}

impl StealthAddress {
    pub fn to_string(&self) -> String {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.public_spend.0);
        bytes[32..].copy_from_slice(&self.public_view.0);
        format!("CX1{}", hex::encode(bytes))
    }
}

/// Validator commitment — zk-proof of stake (Phase 4: real Groth16)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCommitment {
    pub stake_commitment: [u8; 32],
    pub stake_proof: Vec<u8>,
    pub nullifier: [u8; 32],
}

impl ValidatorCommitment {
    pub fn placeholder() -> Self {
        ValidatorCommitment {
            stake_commitment: [0u8; 32],
            stake_proof: vec![0u8; 32],
            nullifier: [0u8; 32],
        }
    }

    pub fn verify(&self) -> bool {
        // Phase 4: Groth16 verify
        true
    }
}

/// Full validator commitment using real zk-proof
impl ValidatorCommitment {
    /// Build from a real stake proof
    pub fn from_stake_proof(proof: &crate::crypto::zk::StakeProof) -> Self {
        ValidatorCommitment {
            stake_commitment: proof.nullifier,
            stake_proof: proof.proof_bytes.clone(),
            nullifier: proof.nullifier,
        }
    }
}
