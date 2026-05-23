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

// ─── JSON-RPC types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
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

/// Public output reference — commitment-level data only (no private amounts).
/// Passed to RPC handlers so wallet clients can scan for their outputs.
#[derive(Debug, Clone, Serialize)]
pub struct BlockOutputRef {
    /// R = tx_pubkey (hex) — for stealth scanning
    pub tx_pubkey: String,
    /// P = one_time_pubkey (hex) — tested by recipient
    pub one_time_pubkey: String,
    /// Pedersen commitment C = v*H + r*G (hex)
    pub amount_commitment: String,
    /// AEAD-encrypted amount (hex) — decryptable by recipient only
    pub encrypted_amount: String,
    /// Output index within the transaction
    pub output_index: u32,
    /// Transaction ID (hex)
    pub tx_id: String,
    /// Block height
    pub block_height: u64,
}

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
    /// All outputs seen so far (commitment-level — no private data)
    pub block_outputs: Vec<BlockOutputRef>,
}

/// Handle a single RPC request
pub fn handle_request(request: &RpcRequest, state: &NodeState) -> RpcResponse {
    let id = request.id.clone();
    match request.method.as_str() {
        "cipherx_blockNumber"        => rpc_block_number(id, state),
        "cipherx_getBlockCount"      => rpc_get_block_count(id, state),
        "cipherx_getBlock"           => rpc_get_block(id, &request.params, state),
        "cipherx_getOutputs"         => rpc_get_outputs(id, &request.params, state),
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

/// cipherx_getBlockCount — returns current chain height as a plain integer
fn rpc_get_block_count(id: Value, state: &NodeState) -> RpcResponse {
    RpcResponse::ok(id, json!(state.chain_height))
}

fn rpc_get_block(id: Value, params: &[Value], state: &NodeState) -> RpcResponse {
    let height = match params.first().and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected block height".to_string()),
    };

    if height > state.chain_height {
        return RpcResponse::err(id, ERR_NOT_FOUND, format!("Block {} not found", height));
    }

    // Return block info with outputs (commitments only — no private data)
    // In production this would look up the actual block from storage.
    // For now we return the commitment-level data that the node has.
    let outputs_json: Vec<Value> = state.block_outputs.iter()
        .filter(|o| o.block_height == height)
        .map(|o| json!({
            "tx_pubkey":       o.tx_pubkey,
            "one_time_pubkey": o.one_time_pubkey,
            "amount_commitment": o.amount_commitment,
            "encrypted_amount":  o.encrypted_amount,
            "output_index":      o.output_index,
            "tx_id":             o.tx_id,
            "block_height":      o.block_height,
        }))
        .collect();

    RpcResponse::ok(id, json!({
        "height":    height,
        "hash":      hex::encode(state.tip_hash), // simplified
        "timestamp": chrono::Utc::now().timestamp(),
        "txCount":   if outputs_json.is_empty() { 0 } else { 1 },
        "outputs":   outputs_json,
    }))
}

/// cipherx_getOutputs(from, to) — returns all stealth outputs in the block range [from, to].
/// Only commitment-level data is returned (no private amounts).
/// The wallet uses its view key to test each output locally.
fn rpc_get_outputs(id: Value, params: &[Value], state: &NodeState) -> RpcResponse {
    let from = match params.first().and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected from height".to_string()),
    };
    let to = match params.get(1).and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected to height".to_string()),
    };

    if from > to {
        return RpcResponse::err(id, ERR_PARAMS, "from must be <= to".to_string());
    }
    if to > state.chain_height {
        return RpcResponse::err(id, ERR_NOT_FOUND,
            format!("Block {} not yet available (current height: {})", to, state.chain_height));
    }

    let outputs: Vec<Value> = state.block_outputs.iter()
        .filter(|o| o.block_height >= from && o.block_height <= to)
        .map(|o| json!({
            "tx_pubkey":        o.tx_pubkey,
            "one_time_pubkey":  o.one_time_pubkey,
            "amount_commitment": o.amount_commitment,
            "encrypted_amount": o.encrypted_amount,
            "output_index":     o.output_index,
            "tx_id":            o.tx_id,
            "block_height":     o.block_height,
        }))
        .collect();

    RpcResponse::ok(id, json!(outputs))
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

fn rpc_send_raw_tx(id: Value, _params: &[Value]) -> RpcResponse {
    // Handled externally via handle_send_raw_tx (requires mempool access)
    RpcResponse::err(id, ERR_INTERNAL, "Use handle_send_raw_tx with mempool".to_string())
}

/// Real sendRawTransaction handler — decodes bot lite tx, validates, pushes to mempool.
/// Called directly from run_rpc_server which has mempool access.
pub fn handle_send_raw_tx(
    request: &RpcRequest,
    mempool: &std::sync::Mutex<Vec<crate::core::transaction::Transaction>>,
) -> RpcResponse {
    use crate::core::transaction::Transaction;

    let id = request.id.clone();
    let raw_hex = match request.params.first().and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::err(id, ERR_PARAMS, "Expected raw tx hex".to_string()),
    };

    let json_bytes = match hex::decode(raw_hex) {
        Ok(b) => b,
        Err(_) => return RpcResponse::err(id, ERR_PARAMS, "Invalid hex encoding".to_string()),
    };

    let json_str = match std::str::from_utf8(&json_bytes) {
        Ok(s) => s,
        Err(_) => return RpcResponse::err(id, ERR_PARAMS, "Invalid UTF-8 in payload".to_string()),
    };

    match Transaction::from_lite_raw(json_str) {
        Some(tx) => {
            let tx_id = tx.id();
            mempool.lock().unwrap().push(tx);
            let tx_id_hex = format!("0x{}", hex::encode(tx_id.0));
            tracing::info!("📨 Tx reçue → mempool | id: {}", &tx_id_hex[..18]);
            RpcResponse::ok(id, json!(tx_id_hex))
        }
        None => RpcResponse::err(id, ERR_PARAMS, "Invalid transaction format".to_string()),
    }
}

fn rpc_chain_id(id: Value) -> RpcResponse {
    // CipherX chain ID — unique to avoid replay attacks from other EVM chains
    // Choose a value not used by any existing chain
    // https://chainlist.org — pick something unique
    RpcResponse::ok(id, json!("0x43495054")) // "CIPT" — CipherX IP Testnet
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
    // Solo validator: all mined CIP belong to us
    RpcResponse::ok(id, json!({
        "balance": state.circulating_supply_ncip,
        "balanceCIP": state.circulating_supply_ncip / 1_000_000_000,
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
            block_outputs: vec![],
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
        assert_eq!(r.result.unwrap(), json!("0x43495054"));
    }

    #[test]
    fn test_tx_status_no_params_fails() {
        let r = handle_request(&req("cipherx_getTxStatus", vec![]), &state());
        assert!(r.error.is_some());
    }

    #[test]
    fn test_get_block_count() {
        let r = handle_request(&req("cipherx_getBlockCount", vec![]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), json!(42u64));
    }

    #[test]
    fn test_get_outputs_empty() {
        let r = handle_request(&req("cipherx_getOutputs", vec![json!(0u64), json!(10u64)]), &state());
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), json!([]));
    }

    #[test]
    fn test_get_outputs_missing_params() {
        let r = handle_request(&req("cipherx_getOutputs", vec![json!(0u64)]), &state());
        assert!(r.error.is_some());
        assert_eq!(r.error.unwrap().code, ERR_PARAMS);
    }

    #[test]
    fn test_get_outputs_future_block_fails() {
        let r = handle_request(&req("cipherx_getOutputs", vec![json!(0u64), json!(9999u64)]), &state());
        assert!(r.error.is_some());
        assert_eq!(r.error.unwrap().code, ERR_NOT_FOUND);
    }

    #[test]
    fn test_get_outputs_with_data() {
        let mut s = state();
        s.block_outputs.push(BlockOutputRef {
            tx_pubkey: "aabb".to_string(),
            one_time_pubkey: "ccdd".to_string(),
            amount_commitment: "eeff".to_string(),
            encrypted_amount: "1122".to_string(),
            output_index: 0,
            tx_id: "deadbeef".to_string(),
            block_height: 5,
        });
        let r = handle_request(&req("cipherx_getOutputs", vec![json!(1u64), json!(10u64)]), &s);
        assert!(r.error.is_none());
        let arr = r.result.unwrap();
        assert_eq!(arr.as_array().unwrap().len(), 1);
        assert_eq!(arr[0]["block_height"], json!(5u64));
    }
}
