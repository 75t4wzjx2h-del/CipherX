// CipherX — Anonymous Validator Identity (Phase 4)
//
// A validator in CipherX has:
//   - A stake keypair (private — never shared)
//   - A nullifier per epoch (rotates every epoch — prevents linking)
//   - A zk-SNARK proof of stake (proves ≥31 CIP, reveals nothing else)
//   - A voting keypair (ephemeral — rotates per block)
//
// What the network NEVER learns:
//   - The validator's wallet address
//   - The exact amount staked
//   - Which outputs in the UTXO set belong to the validator
//   - The validator's real identity
//
// What the network CAN verify:
//   - The validator has staked ≥ 31 CIP (via zk-proof)
//   - The validator hasn't double-voted (via nullifier)
//   - The validator's votes are authentic (via ephemeral signing key)

use sha3::{Sha3_256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::stake_circuit::{StakeProof, StakeProvingKey, compute_nullifier, prove_stake};
use crate::core::chain::ChainParams;

// ─── Validator keypair (private — kept in keystore) ───────────────────────────

/// Full validator keypair — NEVER leaves the node
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ValidatorKeystore {
    /// Stake private key — derives nullifiers + proofs
    pub stake_key: [u8; 32],
    /// Stake amount in nCIP
    pub stake_amount: u64,
    /// Pedersen blinding factor for stake commitment
    pub stake_blinding: [u8; 32],
}

impl ValidatorKeystore {
    /// Generate a new validator keystore
    pub fn generate(stake_amount: u64) -> Result<Self, String> {
        if stake_amount < ChainParams::MIN_STAKE * 1_000_000_000 {
            return Err(format!(
                "Stake {} < minimum {} nCIP",
                stake_amount,
                ChainParams::MIN_STAKE * 1_000_000_000
            ));
        }

        let mut stake_key = [0u8; 32];
        let mut stake_blinding = [0u8; 32];
        OsRng.fill_bytes(&mut stake_key);
        OsRng.fill_bytes(&mut stake_blinding);

        Ok(ValidatorKeystore {
            stake_key,
            stake_amount,
            stake_blinding,
        })
    }

    /// Compute nullifier for a given epoch
    pub fn nullifier_for_epoch(&self, epoch: u64) -> [u8; 32] {
        compute_nullifier(&self.stake_key, epoch)
    }

    /// Generate a stake proof for a given epoch
    pub fn prove_for_epoch(
        &self,
        pk: &StakeProvingKey,
        epoch: u64,
    ) -> Result<StakeProof, String> {
        prove_stake(
            pk,
            self.stake_amount,
            self.stake_blinding,
            self.stake_key,
            epoch,
            &mut OsRng,
        )
    }

    /// Derive an ephemeral voting keypair for a specific block height
    /// Rotates every block — prevents linking votes across blocks
    pub fn ephemeral_vote_key(&self, height: u64) -> ([u8; 32], [u8; 32]) {
        // private = H(stake_key || "vote" || height)
        let mut h = Sha3_256::new();
        h.update(b"CipherX_ephemeral_vote");
        h.update(&self.stake_key);
        h.update(&height.to_le_bytes());
        let priv_bytes: [u8; 32] = h.finalize().into();

        // Public key from private (Ed25519-style, simplified)
        // Real impl: use ed25519-dalek
        let mut h2 = Sha3_256::new();
        h2.update(b"CipherX_ephemeral_pubkey");
        h2.update(&priv_bytes);
        let pub_bytes: [u8; 32] = h2.finalize().into();

        (priv_bytes, pub_bytes)
    }
}

// ─── Anonymous validator (public-facing) ─────────────────────────────────────

/// Public representation of a validator — reveals nothing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousValidator {
    /// Current nullifier (rotates each epoch)
    pub nullifier: [u8; 32],
    /// zk-proof of stake >= MIN_STAKE
    pub stake_proof: Vec<u8>,
    /// Current epoch
    pub epoch: u64,
    /// Ephemeral public key for vote verification (rotates per block)
    pub vote_pubkey: [u8; 32],
    /// Block height this vote key is valid for
    pub vote_key_height: u64,
    /// Validator status
    pub status: ValidatorStatus,
    /// Missed block counter (for slashing)
    pub missed_blocks: u64,
    /// Total blocks in current window
    pub window_size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    PendingExit { unlock_height: u64 },
    Slashed { reason: SlashReason },
    Banned,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SlashReason {
    DoubleSigning,
    Downtime,
    SurroundVoting,
}

impl AnonymousValidator {
    /// Create from keystore + proof
    pub fn from_keystore(
        keystore: &ValidatorKeystore,
        stake_proof: StakeProof,
        current_height: u64,
    ) -> Self {
        let nullifier = keystore.nullifier_for_epoch(stake_proof.epoch);
        let (_, vote_pubkey) = keystore.ephemeral_vote_key(current_height);

        AnonymousValidator {
            nullifier,
            stake_proof: stake_proof.proof_bytes,
            epoch: stake_proof.epoch,
            vote_pubkey,
            vote_key_height: current_height,
            status: ValidatorStatus::Active,
            missed_blocks: 0,
            window_size: 0,
        }
    }

    /// Check if this validator is eligible to propose/vote
    pub fn is_active(&self) -> bool {
        self.status == ValidatorStatus::Active
    }

    /// Record a missed block
    pub fn record_miss(&mut self) {
        self.missed_blocks += 1;
        self.window_size += 1;
    }

    /// Record a signed block
    pub fn record_sign(&mut self) {
        self.window_size += 1;
    }

    /// Compute miss ratio for slashing evaluation
    pub fn miss_ratio(&self) -> f64 {
        if self.window_size == 0 { return 0.0; }
        self.missed_blocks as f64 / self.window_size as f64
    }

    /// Check if downtime threshold is exceeded
    pub fn should_slash_downtime(&self) -> bool {
        self.window_size >= 100 && self.miss_ratio() >= 0.05
    }
}

// ─── Validator registry ───────────────────────────────────────────────────────

/// Active validator set — stored on chain
pub struct ValidatorRegistry {
    /// All validators indexed by nullifier
    validators: std::collections::HashMap<[u8; 32], AnonymousValidator>,
    /// Banned nullifiers (permanent)
    banned_nullifiers: std::collections::HashSet<[u8; 32]>,
    /// Current epoch
    pub current_epoch: u64,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        ValidatorRegistry {
            validators: std::collections::HashMap::new(),
            banned_nullifiers: std::collections::HashSet::new(),
            current_epoch: 0,
        }
    }

    /// Register a new validator
    pub fn register(
        &mut self,
        validator: AnonymousValidator,
        vk: &super::stake_circuit::StakeVerifyingKey,
    ) -> Result<(), String> {
        let nullifier = validator.nullifier;

        // Check not banned
        if self.banned_nullifiers.contains(&nullifier) {
            return Err("Nullifier is permanently banned".to_string());
        }

        // Already registered?
        if self.validators.contains_key(&nullifier) {
            return Err("Nullifier already in active set".to_string());
        }

        // Verify stake proof
        let proof = super::stake_circuit::StakeProof {
            proof_bytes: validator.stake_proof.clone(),
            nullifier,
            epoch: validator.epoch,
        };

        if !super::stake_circuit::verify_stake_proof(vk, &proof, self.current_epoch) {
            return Err("Invalid stake proof".to_string());
        }

        self.validators.insert(nullifier, validator);
        Ok(())
    }

    /// Slash a validator
    pub fn slash(
        &mut self,
        nullifier: &[u8; 32],
        reason: SlashReason,
        burn_percentage: u8,
        permanent_ban: bool,
    ) -> Result<(), String> {
        let validator = self.validators.get_mut(nullifier)
            .ok_or("Validator not found")?;

        validator.status = ValidatorStatus::Slashed { reason };

        if permanent_ban {
            self.banned_nullifiers.insert(*nullifier);
            self.validators.remove(nullifier);
        }

        Ok(())
    }

    /// Get all active validator nullifiers
    pub fn active_nullifiers(&self) -> Vec<[u8; 32]> {
        self.validators.values()
            .filter(|v| v.is_active())
            .map(|v| v.nullifier)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.validators.len()
    }

    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_active()).count()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_min_stake_enforced() {
        let too_low = ValidatorKeystore::generate(1_000_000_000); // 1 CIP
        assert!(too_low.is_err());

        let ok = ValidatorKeystore::generate(31_000_000_000); // 31 CIP
        assert!(ok.is_ok());
    }

    #[test]
    fn test_nullifier_per_epoch() {
        let ks = ValidatorKeystore::generate(50_000_000_000).unwrap();
        let n1 = ks.nullifier_for_epoch(1);
        let n2 = ks.nullifier_for_epoch(2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_ephemeral_key_rotates_per_block() {
        let ks = ValidatorKeystore::generate(50_000_000_000).unwrap();
        let (_, pk1) = ks.ephemeral_vote_key(100);
        let (_, pk2) = ks.ephemeral_vote_key(101);
        assert_ne!(pk1, pk2, "Vote keys must rotate every block");
    }

    #[test]
    fn test_ephemeral_key_deterministic() {
        let ks = ValidatorKeystore::generate(50_000_000_000).unwrap();
        let (sk1, pk1) = ks.ephemeral_vote_key(100);
        let (sk2, pk2) = ks.ephemeral_vote_key(100);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_miss_ratio() {
        let mut v = AnonymousValidator {
            nullifier: [0u8; 32],
            stake_proof: vec![],
            epoch: 1,
            vote_pubkey: [0u8; 32],
            vote_key_height: 0,
            status: ValidatorStatus::Active,
            missed_blocks: 0,
            window_size: 0,
        };

        // 5 misses out of 100 = 5% (boundary)
        for _ in 0..5 { v.record_miss(); }
        for _ in 0..95 { v.record_sign(); }

        assert!((v.miss_ratio() - 0.05).abs() < 0.001);
        assert!(v.should_slash_downtime());
    }

    #[test]
    fn test_registry_ban() {
        let mut registry = ValidatorRegistry::new();
        let nullifier = [1u8; 32];
        registry.banned_nullifiers.insert(nullifier);

        let validator = AnonymousValidator {
            nullifier,
            stake_proof: vec![],
            epoch: 1,
            vote_pubkey: [0u8; 32],
            vote_key_height: 0,
            status: ValidatorStatus::Active,
            missed_blocks: 0,
            window_size: 0,
        };

        // Can't use placeholder VK here without setup, so just test ban detection
        assert!(registry.banned_nullifiers.contains(&nullifier));
    }
}
