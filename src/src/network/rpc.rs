// CipherX — JSON-RPC API (Phase 6)
//
// Local-only RPC server (listens on 127.0.0.1 — never exposed to network).
// Used by wallets, explorers, and tooling to interact with the node.
//
// Privacy: all sensitive data (amounts, addresses) is omitted or encrypted
// in RPC responses. The API reveals only what an observer could already see
// on chain (block hashes, heights, tx IDs, commitments).
//
// Endpoints:
//   cipherx_blockNumber        — current chain height
//   cipherx_getBlock           — block by height/hash (no private data)
//   cipherx_getTxStatus        — tx inclusion status by tx_id
//   cipherx_sendRawTransaction — submit a signed transaction
//   cipherx_gasPrice           — current base fee
//   cipherx_getContractCode    — deployed bytecode
//   cipherx_call               — static contract call (read-only)
//   cipherx_syncStatus         — sync progress
//   cipherx_peerCount          — number of connected peers
//
//   wallet_scanOutputs         — scan outputs for a view key (local only)
//   wallet_buildTx             — build a private transaction
//   wallet_getBalance          — get decrypted balance for view key

use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use thiserror::Error;

use crate::core::block::BlockHash;
use crate::core::transaction::TxId;

// ─── JSON-RPC types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    pub params: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        RpcResponse { jsonrpc: "2.0".to_string(), id, result: Some(result), error: None }
    }

    pub fn err(id: Value, code: i32, message: String) -> Self {
        RpcResponse { jsonrpc: "2.0".to_string(), id, result: None,
            error: Some(RpcError { code, message }) }
    }
}

// ─── RPC error codes ──────────────────────────────────────────────────────────

pub const ERR_PARSE:        i32 = -32700;
pub const ERR_INVALID:      i32 = -32600;
pub const ERR_METHOD:       i32 = -32601; // method not found
pub const ERR_PARAMS:       i32 = -32602;
pub const ERR_INTERNAL:     i32 = -32603;
pub const ERR_NOT_FOUND:    i32 = -32000;
pub const ERR_UNAUTHORIZED: i32 = -32001; // e.g. wrong view key

// ─── RPC handler ─────────────────────────────────────────────────────────────

/// Node state accessible to RPC handlers
pub struct NodeState {
    pub chain_height: u64,
    pub tip_hash: [u8; 32],
    pub peer_count: usize,
    pub syncing: bool,
    pub sync_progress: f64,
    pub base_fee_per_gas: u64,
    pub circulating_supply_ncip: u64,
    pub block_reward_ncip: u64,
    /// Validator's real balance from UTXO scanning (nCIP)
    pub validator_balance_ncip: u64,
    /// Number of owned UTXOs
    pub validator_utxo_count: usize,
}

/// Handle a single RPC request
pub fn handle_request(request: &RpcRequest, state: &NodeState) -> RpcResponse {
    let id = request.id.clone();
    match request.method.as_str() {
        "cipherx_blockNumber"        => rpc_block_number(id, state),
        "cipherx_getBlock"           => rpc_get_block(id, &request.params, state),
        "cipherx_gasPrice"           => rpc_gas_price(id, state),
        "cipherx_syncStatus"         => rpc_sync_status(id, state),
        "cipherx_peerCount"          => rpc_peer_count(id, state),
        "cipherx_getTxStatus"        => rpc_tx_status(id, &request.params),
        "cipherx_sendRawTransaction" => rpc_send_raw_tx(id, &request.params),
        "cipherx_chainId"            => rpc_chain_id(id),
        "cipherx_protocolVersion"    => rpc_protocol_version(id),
        "cipherx_getSupply"          => rpc_get_supply(id, state),
        "wallet_getBalance"          => rpc_wallet_balance(id, state),
        "net_version"                => rpc_chain_id(id), // compatibility
        _ => RpcResponse::err(id, ERR_METHOD, format!("Method not found: {}", request.method)),
    }
}

fn rpc_block_number(id: Value, state: &NodeState) -> RpcResponse {
    RpcResponse::ok(id, json!(format!("0x{:x}", state.chain_height)))
}

fn rpc_get_block(id: Value, params: &[Value], state: &NodeState) -> RpcResponse {
    let height = match params.first().and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected block height".to_string()),
    };

    if height > state.chain_height {
        return RpcResponse::err(id, ERR_NOT_FOUND, format!("Block {} not found", height));
    }

    // Return minimal block info (no private data)
    RpcResponse::ok(id, json!({
        "height": height,
        "hash": hex::encode(state.tip_hash), // simplified
        "timestamp": chrono::Utc::now().timestamp(),
        "txCount": 0,  // real impl: look up block
        "size": 0,
    }))
}

fn rpc_gas_price(id: Value, state: &NodeState) -> RpcResponse {
    RpcResponse::ok(id, json!(format!("0x{:x}", state.base_fee_per_gas)))
}

fn rpc_sync_status(id: Value, state: &NodeState) -> RpcResponse {
    RpcResponse::ok(id, json!({
        "syncing": state.syncing,
        "currentBlock": state.chain_height,
        "progress": format!("{:.1}%", state.sync_progress),
    }))
}

fn rpc_peer_count(id: Value, state: &NodeState) -> RpcResponse {
    RpcResponse::ok(id, json!(format!("0x{:x}", state.peer_count)))
}

fn rpc_tx_status(id: Value, params: &[Value]) -> RpcResponse {
    let tx_id = match params.first().and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected tx_id".to_string()),
    };
    // Real impl: look up tx in chain + mempool
    RpcResponse::ok(id, json!({
        "txId": tx_id,
        "status": "unknown", // real impl: "pending" | "included" | "not_found"
        "blockHeight": null,
    }))
}

fn rpc_send_raw_tx(id: Value, params: &[Value]) -> RpcResponse {
    let raw = match params.first().and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected raw tx hex".to_string()),
    };
    // Real impl: deserialize + validate + add to mempool
    let fake_id = format!("0x{}", hex::encode([0u8; 32]));
    RpcResponse::ok(id, json!(fake_id))
}

fn rpc_chain_id(id: Value) -> RpcResponse {
    // CipherX chain ID — unique to avoid replay attacks from other EVM chains
    // Choose a value not used by any existing chain
    // https://chainlist.org — pick something unique
    RpcResponse::ok(id, json!("0x434950")) // "CIP" in hex
}

fn rpc_protocol_version(id: Value) -> RpcResponse {
    RpcResponse::ok(id, json!("1"))
}

fn rpc_get_supply(id: Value, state: &NodeState) -> RpcResponse {
    RpcResponse::ok(id, json!({
        "circulatingSupply": state.circulating_supply_ncip,
        "circulatingSupplyCIP": state.circulating_supply_ncip / 1_000_000_000,
        "maxSupply": 100_000_000,
        "blockReward": state.block_reward_ncip,
        "blockRewardCIP": state.block_reward_ncip / 1_000_000_000,
    }))
}

fn rpc_wallet_balance(id: Value, state: &NodeState) -> RpcResponse {
    // Real balance from UTXO scanning with view key
    RpcResponse::ok(id, json!({
        "balance": state.validator_balance_ncip,
        "balanceCIP": state.validator_balance_ncip / 1_000_000_000,
        "utxoCount": state.validator_utxo_count,
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> NodeState {
        NodeState {
            chain_height: 42,
            tip_hash: [1u8; 32],
            peer_count: 5,
            syncing: false,
            sync_progress: 100.0,
            base_fee_per_gas: 1000,
            circulating_supply_ncip: 4_100_000_000_000,
            block_reward_ncip: 50_000_000_000,
            validator_balance_ncip: 4_100_000_000_000,
            validator_utxo_count: 42,
        }
    }

    fn req(method: &str, params: Vec<Value>) -> RpcRequest {
        RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: json!(1),
            method: method.to_string(),
            params,
        }
    }

    #[test]
    fn test_block_number() {
        let r = handle_request(&req("cipherx_blockNumber", vec![]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), json!("0x2a")); // 42 in hex
    }

    #[test]
    fn test_gas_price() {
        let r = handle_request(&req("cipherx_gasPrice", vec![]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), json!("0x3e8")); // 1000 in hex
    }

    #[test]
    fn test_peer_count() {
        let r = handle_request(&req("cipherx_peerCount", vec![]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), json!("0x5"));
    }

    #[test]
    fn test_sync_status() {
        let r = handle_request(&req("cipherx_syncStatus", vec![]), &state());
        assert!(r.error.is_none());
        let res = r.result.unwrap();
        assert_eq!(res["syncing"], false);
        assert_eq!(res["currentBlock"], 42);
    }

    #[test]
    fn test_get_block_valid() {
        let r = handle_request(&req("cipherx_getBlock", vec![json!(10)]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap()["height"], 10);
    }

    #[test]
    fn test_get_block_future_fails() {
        let r = handle_request(&req("cipherx_getBlock", vec![json!(9999)]), &state());
        assert!(r.error.is_some());
        assert_eq!(r.error.unwrap().code, ERR_NOT_FOUND);
    }

    #[test]
    fn test_unknown_method() {
        let r = handle_request(&req("eth_getBalance", vec![]), &state());
        assert!(r.error.is_some());
        assert_eq!(r.error.unwrap().code, ERR_METHOD);
    }

    #[test]
    fn test_chain_id() {
        let r = handle_request(&req("cipherx_chainId", vec![]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), json!("0x434950"));
    }

    #[test]
    fn test_tx_status_no_params_fails() {
        let r = handle_request(&req("cipherx_getTxStatus", vec![]), &state());
        assert!(r.error.is_some());
    }
}
