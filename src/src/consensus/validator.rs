// CipherX — Validator
//
// A validator:
//   - Stakes ≥ 31 CIP (proven via zk-SNARK, identity hidden)
//   - Proposes and votes on blocks
//   - Earns block rewards (sent to stealth address — private)
//   - Can be slashed for misbehavior
//
// Entry: fast (few hours)
// Exit: adaptive 2–7 weeks + up to 10 days extension

use crate::crypto::keys::ValidatorCommitment;
use crate::core::transaction::PedersenCommitment;

#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorStatus {
    Active,
    PendingExit { unlock_height: u64 },
    Slashed,
    Banned,
}

pub struct Validator {
    /// Anonymous commitment (no identity)
    pub commitment: ValidatorCommitment,
    /// Stake amount commitment (hidden)
    pub stake_commitment: PedersenCommitment,
    /// Current status
    pub status: ValidatorStatus,
    /// Block height when validator was activated
    pub activated_at: u64,
    /// Missed block counter
    pub missed_blocks: u64,
    /// Total blocks in current window
    pub window_blocks: u64,
}
