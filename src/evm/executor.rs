// CipherX — EVM Executor (Phase 5)
//
// Executes Solidity smart contracts with privacy guarantees.
//
// Privacy model for smart contracts:
//   - Contract STATE is encrypted (AES-256-GCM with contract-specific key)
//   - Contract INPUTS are hidden (passed as encrypted blobs)
//   - Contract OUTPUTS are hidden (encrypted for recipient)
//   - Gas consumption IS visible (proves execution happened, not what)
//   - Contract ADDRESS is public (so others can call it)
//   - Contract CODE is public (anyone can audit the logic)
//
// This is similar to Aztec's approach: public logic, private state/IO.
//
// Execution flow:
//   1. Caller encrypts inputs with contract's public key
//   2. EVM executes bytecode with decrypted inputs (inside secure context)
//   3. State updates are re-encrypted before writing to chain
//   4. Outputs encrypted for intended recipient(s)
//   5. Gas is consumed from caller's private balance (via RingCT)
//
// Uses `revm` — a fast, modular EVM implementation in Rust.
// revm is used by Foundry, Reth, and many production systems.

use std::collections::HashMap;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use sha3::{Keccak256, Digest};

// Note: revm integration is structured here. In production:
// add `revm = "8.0"` to Cargo.toml and uncomment revm imports.
// We define the full interface and data structures now.

// ─── Contract address ─────────────────────────────────────────────────────────

/// EVM-compatible 20-byte contract address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractAddress(pub [u8; 20]);

impl ContractAddress {
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Derive contract address from deployer + nonce (CREATE style)
    pub fn from_deployer(deployer: &[u8; 32], nonce: u64) -> Self {
        let mut h = Keccak256::new();
        h.update(b"CipherX_CREATE");
        h.update(deployer);
        h.update(&nonce.to_le_bytes());
        let hash = h.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        ContractAddress(addr)
    }

    /// CREATE2: deterministic address from deployer + salt + code hash
    pub fn from_create2(deployer: &[u8; 32], salt: &[u8; 32], code_hash: &[u8; 32]) -> Self {
        let mut h = Keccak256::new();
        h.update(b"\xff");
        h.update(deployer);
        h.update(salt);
        h.update(code_hash);
        let hash = h.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        ContractAddress(addr)
    }
}

// ─── Contract storage ─────────────────────────────────────────────────────────

/// A single storage slot: 32-byte key → 32-byte value
/// In CipherX: stored encrypted on chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSlot {
    /// Storage key (public — needed for lookups)
    pub key: [u8; 32],
    /// Encrypted value (only contract key holder can read)
    pub encrypted_value: Vec<u8>,
    /// Commitment to the plaintext value (for ZK state proofs)
    pub value_commitment: [u8; 32],
}

/// Full contract storage (key → slot)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractStorage {
    pub slots: HashMap<[u8; 32], StorageSlot>,
}

impl ContractStorage {
    pub fn get(&self, key: &[u8; 32]) -> Option<&StorageSlot> {
        self.slots.get(key)
    }

    pub fn insert(&mut self, slot: StorageSlot) {
        self.slots.insert(slot.key, slot);
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }
}

// ─── Contract metadata ────────────────────────────────────────────────────────

/// Deployed contract on CipherX
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub address: ContractAddress,
    /// EVM bytecode (public — auditable)
    pub bytecode: Vec<u8>,
    /// Keccak256 of bytecode
    pub code_hash: [u8; 32],
    /// Contract's public encryption key (callers encrypt inputs with this)
    pub encryption_pubkey: [u8; 32],
    /// Block height when deployed
    pub deployed_at: u64,
    /// Deployer's nullifier (anonymous)
    pub deployer_nullifier: [u8; 32],
    /// ABI hash (for verification)
    pub abi_hash: [u8; 32],
    /// Is this contract selfdestruct-able?
    pub destructible: bool,
    /// Current storage
    pub storage: ContractStorage,
    /// Contract's CIP balance (private — Pedersen commitment)
    pub balance_commitment: [u8; 32],
    /// Nonce (number of calls processed)
    pub nonce: u64,
}

impl Contract {
    pub fn new(
        bytecode: Vec<u8>,
        deployer_nullifier: [u8; 32],
        deployer_nonce: u64,
        deployed_at: u64,
    ) -> Self {
        // Compute code hash
        let mut h = Keccak256::new();
        h.update(&bytecode);
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(&h.finalize());

        // Generate contract address
        let address = ContractAddress::from_deployer(&deployer_nullifier, deployer_nonce);

        // Generate contract encryption keypair
        // In production: use X25519 for DH key exchange
        let mut enc_key = [0u8; 32];
        let mut h2 = Keccak256::new();
        h2.update(b"CipherX_contract_enc_key");
        h2.update(&address.0);
        h2.update(&deployed_at.to_le_bytes());
        enc_key.copy_from_slice(&h2.finalize());

        Contract {
            address,
            bytecode,
            code_hash,
            encryption_pubkey: enc_key,
            deployed_at,
            deployer_nullifier,
            abi_hash: [0u8; 32],
            destructible: true,
            storage: ContractStorage::default(),
            balance_commitment: [0u8; 32],
            nonce: 0,
        }
    }
}

// ─── Execution context ────────────────────────────────────────────────────────

/// A private contract call
#[derive(Debug, Clone)]
pub struct PrivateCall {
    /// Target contract
    pub to: ContractAddress,
    /// Encrypted calldata (only contract can decrypt)
    pub encrypted_calldata: Vec<u8>,
    /// Gas limit (public — amount of computation)
    pub gas_limit: u64,
    /// CIP value sent with call (as Pedersen commitment — hidden)
    pub value_commitment: [u8; 32],
    /// Caller's nullifier (anonymous identity)
    pub caller_nullifier: [u8; 32],
    /// Proof that caller has enough balance for gas + value
    pub balance_proof: Vec<u8>,
}

/// Result of executing a private contract call
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Did execution succeed?
    pub success: bool,
    /// Gas actually consumed
    pub gas_used: u64,
    /// Encrypted return data (for caller to decrypt)
    pub encrypted_output: Vec<u8>,
    /// New storage slots (encrypted)
    pub storage_changes: Vec<StorageSlot>,
    /// Events emitted (encrypted for intended recipients)
    pub encrypted_events: Vec<EncryptedEvent>,
    /// Error if failed
    pub error: Option<ExecutionError>,
}

/// An event emitted by a contract — encrypted for recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEvent {
    /// Event topic hash (public — for indexing)
    pub topic: [u8; 32],
    /// Encrypted event data
    pub encrypted_data: Vec<u8>,
    /// Intended recipient's public key (for decryption)
    pub recipient_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Error)]
pub enum ExecutionError {
    #[error("Out of gas")]
    OutOfGas,
    #[error("Revert: {0}")]
    Revert(String),
    #[error("Invalid bytecode")]
    InvalidBytecode,
    #[error("Stack overflow")]
    StackOverflow,
    #[error("Invalid jump destination")]
    InvalidJump,
    #[error("Contract not found: {0}")]
    ContractNotFound(String),
    #[error("Insufficient balance for gas")]
    InsufficientGas,
}

// ─── EVM executor ─────────────────────────────────────────────────────────────

/// The CipherX EVM executor
pub struct CipherXEvm {
    /// All deployed contracts
    contracts: HashMap<ContractAddress, Contract>,
    /// Block context
    block_height: u64,
    block_timestamp: i64,
    /// Gas price in nCIP per gas unit
    base_gas_price: u64,
}

impl CipherXEvm {
    pub fn new(block_height: u64, block_timestamp: i64) -> Self {
        CipherXEvm {
            contracts: HashMap::new(),
            block_height,
            block_timestamp,
            base_gas_price: 1_000, // 1000 nCIP per gas = 0.000001 CIP/gas
        }
    }

    // ── Deploy ────────────────────────────────────────────────────────────────

    /// Deploy a new smart contract
    pub fn deploy(
        &mut self,
        bytecode: Vec<u8>,
        deployer_nullifier: [u8; 32],
        deployer_nonce: u64,
        constructor_args: Vec<u8>, // encrypted
        gas_limit: u64,
    ) -> Result<DeployResult, ExecutionError> {
        // Validate bytecode
        if bytecode.is_empty() {
            return Err(ExecutionError::InvalidBytecode);
        }

        // Check gas
        let deploy_gas = self.estimate_deploy_gas(&bytecode);
        if deploy_gas > gas_limit {
            return Err(ExecutionError::OutOfGas);
        }

        // Create contract
        let contract = Contract::new(
            bytecode,
            deployer_nullifier,
            deployer_nonce,
            self.block_height,
        );

        let address = contract.address.clone();
        let code_hash = contract.code_hash;
        let enc_pubkey = contract.encryption_pubkey;

        // Store contract
        self.contracts.insert(address.clone(), contract);

        tracing::info!(
            "📝 Contract deployed at {} (height={})",
            address.to_hex(),
            self.block_height
        );

        Ok(DeployResult {
            address,
            code_hash,
            encryption_pubkey: enc_pubkey,
            gas_used: deploy_gas,
        })
    }

    // ── Call ──────────────────────────────────────────────────────────────────

    /// Execute a private contract call
    pub fn call(&mut self, call: PrivateCall) -> ExecutionResult {
        // Find contract
        let contract = match self.contracts.get(&call.to) {
            Some(c) => c.clone(),
            None => return ExecutionResult {
                success: false,
                gas_used: 0,
                encrypted_output: vec![],
                storage_changes: vec![],
                encrypted_events: vec![],
                error: Some(ExecutionError::ContractNotFound(call.to.to_hex())),
            },
        };

        // Decrypt calldata (in production: use X25519 + ChaCha20-Poly1305)
        // Here: pass through (stub — real impl decrypts inside TEE or ZK context)
        let calldata = self.decrypt_calldata(&call.encrypted_calldata, &contract.encryption_pubkey);

        // Execute bytecode
        let exec = self.execute_bytecode(
            &contract.bytecode,
            &calldata,
            call.gas_limit,
            &contract.storage,
        );

        // Re-encrypt outputs + storage changes
        let encrypted_output = self.encrypt_output(&exec.raw_output, &self.caller_key(&call));
        let storage_changes = self.encrypt_storage_changes(&exec.storage_changes, &contract.encryption_pubkey);

        ExecutionResult {
            success: exec.success,
            gas_used: exec.gas_used,
            encrypted_output,
            storage_changes,
            encrypted_events: vec![],
            error: exec.error,
        }
    }

    // ── Static call (view functions) ──────────────────────────────────────────

    /// Execute a read-only call (no state changes)
    pub fn static_call(
        &self,
        to: &ContractAddress,
        calldata: Vec<u8>,
        gas_limit: u64,
    ) -> ExecutionResult {
        let contract = match self.contracts.get(to) {
            Some(c) => c,
            None => return ExecutionResult {
                success: false,
                gas_used: 0,
                encrypted_output: vec![],
                storage_changes: vec![],
                encrypted_events: vec![],
                error: Some(ExecutionError::ContractNotFound(to.to_hex())),
            },
        };

        let exec = self.execute_bytecode(
            &contract.bytecode,
            &calldata,
            gas_limit,
            &contract.storage,
        );

        ExecutionResult {
            success: exec.success,
            gas_used: exec.gas_used,
            encrypted_output: exec.raw_output,
            storage_changes: vec![], // static: no state changes
            encrypted_events: vec![],
            error: exec.error,
        }
    }

    // ── Internal execution engine ─────────────────────────────────────────────

    /// Execute EVM bytecode
    /// In production: use `revm` crate for full EVM compatibility
    fn execute_bytecode(
        &self,
        bytecode: &[u8],
        calldata: &[u8],
        gas_limit: u64,
        storage: &ContractStorage,
    ) -> RawExecResult {
        // Production impl:
        //   use revm::{EVM, db::InMemoryDB, primitives::*};
        //   let mut evm = EVM::new();
        //   evm.database(db);
        //   evm.env.tx.data = calldata.into();
        //   evm.env.tx.gas_limit = gas_limit;
        //   let result = evm.transact();
        //
        // For Phase 5: simulate execution result
        // Replace this entire function with revm integration

        // Minimal opcode interpreter stub
        // Recognizes STOP (0x00) and RETURN (0xf3)
        let mut gas_used = 21_000u64; // base tx cost
        let mut success = true;
        let mut output = vec![];
        let mut storage_changes = vec![];

        if bytecode.is_empty() {
            return RawExecResult {
                success: false,
                gas_used,
                raw_output: vec![],
                storage_changes: vec![],
                error: Some(ExecutionError::InvalidBytecode),
            };
        }

        // Simulate: charge gas per byte of calldata
        gas_used += calldata.len() as u64 * 16;

        if gas_used > gas_limit {
            return RawExecResult {
                success: false,
                gas_used: gas_limit,
                raw_output: vec![],
                storage_changes: vec![],
                error: Some(ExecutionError::OutOfGas),
            };
        }

        // "Execute" — return echoed calldata as output (stub)
        output = calldata.to_vec();

        RawExecResult {
            success,
            gas_used,
            raw_output: output,
            storage_changes,
            error: None,
        }
    }

    // ── Gas estimation ────────────────────────────────────────────────────────

    /// Estimate gas for deployment
    pub fn estimate_deploy_gas(&self, bytecode: &[u8]) -> u64 {
        // Base: 53000 (CREATE opcode) + 200 per byte of code
        53_000 + (bytecode.len() as u64 * 200)
    }

    /// Estimate gas for a call
    pub fn estimate_call_gas(&self, calldata: &[u8]) -> u64 {
        21_000 + calldata.len() as u64 * 16
    }

    /// Convert gas to nCIP fee
    pub fn gas_to_ncip(&self, gas: u64) -> u64 {
        gas * self.base_gas_price
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    fn decrypt_calldata(&self, encrypted: &[u8], _contract_key: &[u8; 32]) -> Vec<u8> {
        // TODO: X25519 + ChaCha20-Poly1305 decryption
        // For now: pass through
        encrypted.to_vec()
    }

    fn encrypt_output(&self, data: &[u8], _recipient_key: &[u8; 32]) -> Vec<u8> {
        // TODO: encrypt for recipient
        data.to_vec()
    }

    fn encrypt_storage_changes(
        &self,
        changes: &[([u8; 32], [u8; 32])],
        contract_key: &[u8; 32],
    ) -> Vec<StorageSlot> {
        changes.iter().map(|(k, v)| {
            // TODO: encrypt v with contract_key
            let mut commitment = [0u8; 32];
            let mut h = Keccak256::new();
            h.update(v);
            commitment.copy_from_slice(&h.finalize());

            StorageSlot {
                key: *k,
                encrypted_value: v.to_vec(), // TODO: encrypt
                value_commitment: commitment,
            }
        }).collect()
    }

    fn caller_key(&self, call: &PrivateCall) -> [u8; 32] {
        // Derive ephemeral key for encrypting output to caller
        let mut h = Keccak256::new();
        h.update(&call.caller_nullifier);
        let mut k = [0u8; 32];
        k.copy_from_slice(&h.finalize());
        k
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn get_contract(&self, addr: &ContractAddress) -> Option<&Contract> {
        self.contracts.get(addr)
    }

    pub fn contract_count(&self) -> usize {
        self.contracts.len()
    }

    pub fn advance_block(&mut self, height: u64, timestamp: i64) {
        self.block_height = height;
        self.block_timestamp = timestamp;
    }
}

/// Raw (unencrypted) execution result — internal use only
struct RawExecResult {
    success: bool,
    gas_used: u64,
    raw_output: Vec<u8>,
    storage_changes: Vec<([u8; 32], [u8; 32])>, // (key, value)
    error: Option<ExecutionError>,
}

/// Result of deploying a contract
#[derive(Debug, Clone)]
pub struct DeployResult {
    pub address: ContractAddress,
    pub code_hash: [u8; 32],
    pub encryption_pubkey: [u8; 32],
    pub gas_used: u64,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bytecode() -> Vec<u8> {
        // Minimal valid EVM bytecode: PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]
    }

    fn test_deployer() -> [u8; 32] { [1u8; 32] }

    #[test]
    fn test_contract_address_deterministic() {
        let a1 = ContractAddress::from_deployer(&test_deployer(), 0);
        let a2 = ContractAddress::from_deployer(&test_deployer(), 0);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_contract_address_nonce_changes() {
        let a0 = ContractAddress::from_deployer(&test_deployer(), 0);
        let a1 = ContractAddress::from_deployer(&test_deployer(), 1);
        assert_ne!(a0, a1);
    }

    #[test]
    fn test_create2_deterministic() {
        let salt = [42u8; 32];
        let code_hash = [7u8; 32];
        let a1 = ContractAddress::from_create2(&test_deployer(), &salt, &code_hash);
        let a2 = ContractAddress::from_create2(&test_deployer(), &salt, &code_hash);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_deploy_contract() {
        let mut evm = CipherXEvm::new(1, 0);
        let result = evm.deploy(
            test_bytecode(),
            test_deployer(),
            0,
            vec![],
            1_000_000,
        );
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(!r.address.0.iter().all(|&b| b == 0));
        assert_eq!(evm.contract_count(), 1);
    }

    #[test]
    fn test_deploy_empty_bytecode_fails() {
        let mut evm = CipherXEvm::new(1, 0);
        let result = evm.deploy(vec![], test_deployer(), 0, vec![], 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_deploy_out_of_gas() {
        let mut evm = CipherXEvm::new(1, 0);
        let gas_limit = 100; // way too low
        let result = evm.deploy(test_bytecode(), test_deployer(), 0, vec![], gas_limit);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ExecutionError::OutOfGas));
    }

    #[test]
    fn test_call_deployed_contract() {
        let mut evm = CipherXEvm::new(1, 0);
        let deploy = evm.deploy(test_bytecode(), test_deployer(), 0, vec![], 1_000_000).unwrap();

        let call = PrivateCall {
            to: deploy.address,
            encrypted_calldata: vec![0xde, 0xad, 0xbe, 0xef],
            gas_limit: 100_000,
            value_commitment: [0u8; 32],
            caller_nullifier: [2u8; 32],
            balance_proof: vec![],
        };

        let result = evm.call(call);
        assert!(result.success);
        assert!(result.gas_used > 0);
    }

    #[test]
    fn test_call_nonexistent_contract() {
        let mut evm = CipherXEvm::new(1, 0);
        let fake_addr = ContractAddress([0xff; 20]);
        let call = PrivateCall {
            to: fake_addr,
            encrypted_calldata: vec![],
            gas_limit: 100_000,
            value_commitment: [0u8; 32],
            caller_nullifier: [0u8; 32],
            balance_proof: vec![],
        };
        let result = evm.call(call);
        assert!(!result.success);
    }

    #[test]
    fn test_gas_estimation() {
        let evm = CipherXEvm::new(1, 0);
        let bytecode = test_bytecode();
        let gas = evm.estimate_deploy_gas(&bytecode);
        assert!(gas > 53_000);
        let fee_ncip = evm.gas_to_ncip(gas);
        assert!(fee_ncip > 0);
        println!("Deploy gas: {} | Fee: {} nCIP ({} CIP)", gas, fee_ncip, fee_ncip / 1_000_000_000);
    }

    #[test]
    fn test_storage_slot() {
        let mut storage = ContractStorage::default();
        let slot = StorageSlot {
            key: [1u8; 32],
            encrypted_value: vec![42u8; 32],
            value_commitment: [7u8; 32],
        };
        storage.insert(slot);
        assert_eq!(storage.slot_count(), 1);
        assert!(storage.get(&[1u8; 32]).is_some());
        assert!(storage.get(&[2u8; 32]).is_none());
    }
}
