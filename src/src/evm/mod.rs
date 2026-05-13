// CipherX — EVM Module (Phase 5)
//
// Private smart contracts on CipherX.
//
// Architecture:
//   executor    — execute Solidity bytecode via `revm`
//   private_state — encrypted contract state (only owner can read)
//   gas         — CIP-denominated gas model
//   abi         — ABI encoding/decoding for contract calls
//   precompiles — CipherX-specific precompiles (ring sig verify, zk verify, etc.)

pub mod executor;
pub mod private_state;
pub mod gas;
pub mod precompiles;
pub mod abi;
