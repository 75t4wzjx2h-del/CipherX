// CipherX Blockchain — Core Library
// Private · Decentralized · Uncensorable
//
// Phase 1: Core (Block, Transaction, Chain)
// Phase 2: Consensus (Tendermint BFT)
// Phase 3: Privacy (Ring Sigs, Stealth, RingCT)
// Phase 4: zk-SNARKs (Stake proofs, Groth16)
// Phase 5: EVM (Smart contracts) — next
// Phase 6: Network (libp2p + Tor) — next

pub mod core;
pub mod crypto;
pub mod consensus;
pub mod network;
pub mod storage;

pub use core::block::Block;
pub use core::transaction::Transaction;
pub use core::chain::Chain;
pub use crypto::keys::{PrivateKey, PublicKey, StealthAddress, ValidatorCommitment};
pub use crypto::zk::{StakeProof, StakeProvingKey, StakeVerifyingKey};
pub mod evm;
pub use evm::executor::{CipherXEvm, ContractAddress, DeployResult};
pub use evm::gas::FeeMarket;
pub use evm::private_state::GlobalState;

// Network re-exports
pub use network::tor::{TorClient, TorConfig, OnionAddress};
pub use network::p2p::{P2PNode, P2PConfig, NetworkEvent};
pub use network::sync::SyncState;
pub use network::rpc::{handle_request, NodeState};
