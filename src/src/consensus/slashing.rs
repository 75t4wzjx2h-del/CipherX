// CipherX — Slashing
//
// Penalties for misbehaving validators.
//
// Slashing conditions (ETH/Solana style, maximally strict):
//
//   1. DOUBLE SIGNING (equivocation)
//      Signing two different blocks at the same height/round.
//      Penalty: 100% stake BURNED + permanent ban
//      Severity: CRITICAL
//
//   2. SURROUND VOTING
//      Signing a vote that surrounds a previous vote.
//      Penalty: 100% stake BURNED + permanent ban
//      Severity: CRITICAL
//
//   3. DOWNTIME (missed blocks)
//      < 5% missed   → warning only
//      5–20% missed  → 10% stake slashed
//      20–50% missed → 50% stake slashed + forced exit
//      > 50% missed  → 100% stake burned + permanent ban
//      Severity: PROGRESSIVE
//
// All slashing is executed on-chain and verifiable.
// Slashed stake goes to: 50% burned (deflationary), 50% to reporter reward.

use crate::core::block::BlockHash;

#[derive(Debug, Clone)]
pub enum SlashReason {
    DoubleSigning {
        block_a: BlockHash,
        block_b: BlockHash,
    },
    SurroundVoting,
    Downtime {
        missed_blocks: u64,
        window: u64,
    },
}

#[derive(Debug, Clone)]
pub struct SlashEvent {
    pub validator_nullifier: [u8; 32], // anonymous ID
    pub reason: SlashReason,
    pub slash_percentage: u8,         // 0–100
    pub burned: bool,                 // true if stake burned
    pub banned: bool,                 // true if permanently banned
    pub block_height: u64,
}

/// Compute slashing parameters for a given infraction
pub fn compute_slash(reason: &SlashReason) -> (u8, bool, bool) {
    // Returns (slash_percentage, burned, banned)
    match reason {
        SlashReason::DoubleSigning { .. } => (100, true, true),
        SlashReason::SurroundVoting => (100, true, true),
        SlashReason::Downtime { missed_blocks, window } => {
            let ratio = *missed_blocks as f64 / *window as f64;
            if ratio < 0.05 {
                (0, false, false)    // Warning only
            } else if ratio < 0.20 {
                (10, false, false)   // 10% slash
            } else if ratio < 0.50 {
                (50, false, true)    // 50% slash + forced exit (banned from current set)
            } else {
                (100, true, true)    // 100% burn + permanent ban
            }
        }
    }
}
