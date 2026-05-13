// CipherX — zk-SNARK module (Phase 4)
//
// Sub-modules:
//   stake_circuit  — Groth16 circuit proving stake >= MIN_STAKE
//   validator_id   — anonymous validator identity management
//   epoch          — epoch-based nullifier rotation

pub mod stake_circuit;
pub mod validator_id;
pub mod epoch;

pub use stake_circuit::{
    StakeCircuit, StakeProvingKey, StakeVerifyingKey, StakeProof,
    setup, prove_stake, verify_stake_proof,
    compute_nullifier, serialize_crs, deserialize_crs,
};
pub use validator_id::AnonymousValidator;
pub use epoch::EpochManager;
