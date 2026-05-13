// CipherX — Gas Model (Phase 5)
//
// Gas in CipherX works like Ethereum but:
//   - Fees paid in CIP (not ETH)
//   - Fee AMOUNT is hidden (Pedersen commitment)
//   - Validator only proves fee >= base_fee (ZK proof)
//   - EIP-1559 style: base fee + priority tip
//   - Base fee burns CIP (deflationary pressure)
//   - Priority tip goes to validator (private)
//
// Gas costs (Ethereum-compatible + CipherX extras):
//   Standard EVM ops  : same as Ethereum
//   RING_SIG_VERIFY   : 50,000 gas (heavy crypto)
//   ZK_VERIFY         : 100,000 gas (Groth16 verify)
//   STEALTH_SCAN      : 5,000 gas
//   ENCRYPT_SLOT      : 2,000 gas (per storage slot)

use serde::{Serialize, Deserialize};

// ─── Gas constants ────────────────────────────────────────────────────────────

/// Standard EVM gas costs
pub struct GasCost;
impl GasCost {
    // Basic operations
    pub const TX_BASE:          u64 = 21_000;
    pub const TX_DATA_ZERO:     u64 = 4;
    pub const TX_DATA_NONZERO:  u64 = 16;

    // Storage
    pub const SSTORE_SET:       u64 = 20_000;
    pub const SSTORE_RESET:     u64 = 2_900;
    pub const SLOAD:            u64 = 2_100;

    // Contract ops
    pub const CREATE:           u64 = 53_000;
    pub const CODE_DEPOSIT:     u64 = 200; // per byte of deployed code
    pub const CALL:             u64 = 100;
    pub const CALL_VALUE:       u64 = 9_000; // extra for sending value

    // Crypto precompiles (CipherX-specific)
    pub const RING_SIG_VERIFY:  u64 = 50_000;
    pub const ZK_VERIFY:        u64 = 100_000;
    pub const STEALTH_SCAN:     u64 = 5_000;
    pub const ENCRYPT_SLOT:     u64 = 2_000;
    pub const PEDERSEN_COMMIT:  u64 = 3_000;
    pub const BULLETPROOF_VFY:  u64 = 80_000;

    // Memory
    pub const MEMORY_WORD:      u64 = 3; // per 32-byte word
    pub const MEMORY_QUAD:      u64 = 512; // memory expansion

    // Standard ops
    pub const ADD:              u64 = 3;
    pub const MUL:              u64 = 5;
    pub const SHA3:             u64 = 30;
    pub const SHA3_WORD:        u64 = 6; // per word
    pub const BALANCE:          u64 = 100;
    pub const JUMP:             u64 = 8;
    pub const JUMPI:            u64 = 10;
    pub const LOG0:             u64 = 375;
    pub const LOG_DATA:         u64 = 8; // per byte
    pub const LOG_TOPIC:        u64 = 375; // per topic
}

// ─── Fee market (EIP-1559 style) ─────────────────────────────────────────────

/// Current fee market state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarket {
    /// Base fee in nCIP per gas (adjusts automatically)
    pub base_fee_per_gas: u64,
    /// Target gas per block
    pub target_gas_per_block: u64,
    /// Maximum gas per block
    pub max_gas_per_block: u64,
    /// Last block's gas used
    pub last_gas_used: u64,
}

impl FeeMarket {
    pub fn new() -> Self {
        FeeMarket {
            base_fee_per_gas: 1_000,           // 1000 nCIP/gas = ~0.000001 CIP/gas
            target_gas_per_block: 15_000_000,   // 15M gas target
            max_gas_per_block: 30_000_000,      // 30M gas max
            last_gas_used: 0,
        }
    }

    /// Update base fee for next block (EIP-1559 adjustment)
    /// If last block > target → fee goes up (max +12.5%)
    /// If last block < target → fee goes down (max -12.5%)
    pub fn update_base_fee(&mut self, gas_used: u64) {
        let target = self.target_gas_per_block;
        self.last_gas_used = gas_used;

        if gas_used == target {
            return; // No change
        }

        // Delta = base_fee * (gas_used - target) / target / 8
        let delta = if gas_used > target {
            let excess = gas_used - target;
            (self.base_fee_per_gas * excess / target / 8).max(1)
        } else {
            let shortfall = target - gas_used;
            (self.base_fee_per_gas * shortfall / target / 8).max(1)
        };

        if gas_used > target {
            self.base_fee_per_gas = self.base_fee_per_gas.saturating_add(delta);
        } else {
            self.base_fee_per_gas = self.base_fee_per_gas.saturating_sub(delta).max(1);
        }
    }

    /// Minimum fee for a tx with given gas limit
    pub fn min_fee_ncip(&self, gas_limit: u64) -> u64 {
        gas_limit * self.base_fee_per_gas
    }

    /// CIP equivalent of a fee
    pub fn ncip_to_cip(ncip: u64) -> f64 {
        ncip as f64 / 1_000_000_000.0
    }
}

// ─── Gas tracker ─────────────────────────────────────────────────────────────

/// Tracks gas usage during execution
pub struct GasTracker {
    pub limit: u64,
    pub used: u64,
}

impl GasTracker {
    pub fn new(limit: u64) -> Self {
        GasTracker { limit, used: 0 }
    }

    /// Consume gas. Returns Err if out of gas.
    pub fn consume(&mut self, amount: u64) -> Result<(), &'static str> {
        if self.used.saturating_add(amount) > self.limit {
            Err("out of gas")
        } else {
            self.used += amount;
            Ok(())
        }
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn refund(&mut self, amount: u64) {
        // Max refund = 20% of gas used (EIP-3529)
        let max_refund = self.used / 5;
        self.used = self.used.saturating_sub(amount.min(max_refund));
    }
}

// ─── Fee calculation ──────────────────────────────────────────────────────────

/// Full fee breakdown for a transaction
#[derive(Debug, Clone)]
pub struct FeeBreakdown {
    pub gas_used: u64,
    pub base_fee_per_gas: u64,
    pub priority_fee_per_gas: u64,
    /// Base fee burned (in nCIP)
    pub burned_ncip: u64,
    /// Priority tip to validator (in nCIP, hidden)
    pub tip_ncip: u64,
    /// Total fee (in nCIP)
    pub total_ncip: u64,
}

impl FeeBreakdown {
    pub fn compute(
        gas_used: u64,
        base_fee: u64,
        priority_fee: u64,
    ) -> Self {
        let burned = gas_used * base_fee;
        let tip = gas_used * priority_fee;
        FeeBreakdown {
            gas_used,
            base_fee_per_gas: base_fee,
            priority_fee_per_gas: priority_fee,
            burned_ncip: burned,
            tip_ncip: tip,
            total_ncip: burned + tip,
        }
    }

    pub fn total_cip(&self) -> f64 {
        FeeMarket::ncip_to_cip(self.total_ncip)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_fee_increases_when_full() {
        let mut market = FeeMarket::new();
        let initial = market.base_fee_per_gas;
        // Block completely full
        market.update_base_fee(market.max_gas_per_block);
        assert!(market.base_fee_per_gas > initial);
    }

    #[test]
    fn test_base_fee_decreases_when_empty() {
        let mut market = FeeMarket::new();
        let initial = market.base_fee_per_gas;
        // Empty block
        market.update_base_fee(0);
        assert!(market.base_fee_per_gas < initial);
    }

    #[test]
    fn test_base_fee_stable_at_target() {
        let mut market = FeeMarket::new();
        let initial = market.base_fee_per_gas;
        market.update_base_fee(market.target_gas_per_block);
        assert_eq!(market.base_fee_per_gas, initial);
    }

    #[test]
    fn test_gas_tracker_oog() {
        let mut tracker = GasTracker::new(21_000);
        assert!(tracker.consume(21_000).is_ok());
        assert!(tracker.consume(1).is_err());
    }

    #[test]
    fn test_gas_tracker_refund() {
        let mut tracker = GasTracker::new(100_000);
        tracker.consume(50_000).unwrap();
        tracker.refund(10_000); // 20% of 50k = 10k max refund
        assert_eq!(tracker.used, 40_000);
    }

    #[test]
    fn test_fee_breakdown() {
        let fee = FeeBreakdown::compute(21_000, 1_000, 500);
        assert_eq!(fee.burned_ncip, 21_000 * 1_000);
        assert_eq!(fee.tip_ncip, 21_000 * 500);
        assert_eq!(fee.total_ncip, fee.burned_ncip + fee.tip_ncip);
        println!("Total fee: {} CIP", fee.total_cip());
    }

    #[test]
    fn test_cipherx_op_costs() {
        // ZK verify should be expensive (prevents spam)
        assert!(GasCost::ZK_VERIFY > GasCost::SHA3 * 100);
        // Ring sig verify also expensive
        assert!(GasCost::RING_SIG_VERIFY > GasCost::SSTORE_SET);
    }
}
