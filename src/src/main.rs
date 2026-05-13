// CipherX Node — Entry point (Phase 7 — Wallet integration)
//
// Startup sequence:
//   1. Load config
//   2. Init chain (genesis or load from disk)
//   3. Generate validator keypair
//   4. Start Tor client → get .onion address
//   5. Start P2P node → connect to peers
//   6. Start consensus engine
//   7. Start RPC server (0.0.0.0:8545)
//   8. Main event loop — solo block production + mempool

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use chrono::Utc;

use cipherx::core::block::{Block, BlockHeader, BlockHash};
use cipherx::core::chain::{Chain, ChainParams};
use cipherx::core::mempool::Mempool;
use cipherx::core::transaction::{
    Transaction, TxType, StealthOutput, RingInput, PedersenCommitment,
};
use cipherx::consensus::tendermint::{TendermintEngine, ConsensusOutput, ConsensusStep};
use cipherx::crypto::keys::{ValidatorCommitment, StealthAddress, PublicKey, ViewKey, PrivateKey};
use cipherx::crypto::stealth;
use cipherx::crypto::ringct;
use cipherx::crypto::ring_sig;
use cipherx::network::tor::{TorClient, TorConfig};
use cipherx::network::p2p::{P2PNode, P2PConfig, NetworkEvent};
use cipherx::network::sync::SyncState;
use cipherx::network::rpc::{NodeState, handle_request, RpcRequest, RpcResponse};
use cipherx::evm::gas::FeeMarket;

/// Shared validator wallet state (thread-safe, immutable after init)
struct ValidatorWallet {
    address: StealthAddress,
    spend_key_bytes: [u8; 32],
    view_key: ViewKey,
    spend_pubkey: PublicKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logger ────────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    print_banner();

    // ── Chain ─────────────────────────────────────────────────────────────────
    let chain = Arc::new(RwLock::new(Chain::new()));
    let stats = chain.read().await.stats();
    info!("⛓️  Chain height: {} | Tip: {}", stats.height, &stats.tip_hash[..16]);
    info!("💰 Supply: {} / 100,000,000 CIP", stats.circulating_supply_cip);
    info!("📦 Next reward: {} CIP/block", stats.next_block_reward_cip);
    info!("⏳ Next halving: block #{}", stats.next_halving_block);

    // ── Mempool ──────────────────────────────────────────────────────────────
    let mempool = Arc::new(RwLock::new(Mempool::new()));
    info!("📋 Mempool initialized");

    // ── Validator keypair ───────────────────────────────────────────────────
    let keys = stealth::generate_keypair();
    let wallet = Arc::new(ValidatorWallet {
        address: keys.address.clone(),
        spend_key_bytes: keys.private_spend.0,
        view_key: keys.private_view.clone(),
        spend_pubkey: keys.public_spend.clone(),
    });
    info!("🔑 Validator address: {}", wallet.address.to_string());

    // ── Fee market ────────────────────────────────────────────────────────────
    let fee_market = Arc::new(FeeMarket::new());
    info!("⛽ Base fee: {} nCIP/gas", fee_market.base_fee_per_gas);

    // ── Tor ───────────────────────────────────────────────────────────────────
    let tor_config = TorConfig::default();
    let mut tor = TorClient::new(tor_config);
    let onion_address = tor.start().await?;
    info!("🧅 Onion address: {}", onion_address.as_str());

    // ── P2P ───────────────────────────────────────────────────────────────────
    let (event_tx, mut event_rx) = mpsc::channel::<NetworkEvent>(1000);
    let p2p_config = P2PConfig::default();
    let mut p2p = P2PNode::new(p2p_config, event_tx);
    p2p.start(&onion_address).await?;
    let peer_count = Arc::new(std::sync::atomic::AtomicUsize::new(p2p.peer_count()));
    info!("🌐 P2P node running | peers: {}", p2p.peer_count());

    // ── Consensus ─────────────────────────────────────────────────────────────
    let our_nullifier = [1u8; 32];
    let commitment = ValidatorCommitment::placeholder();
    let mut consensus = TendermintEngine::new(
        stats.height + 1,
        1,
        vec![our_nullifier],
        Some(our_nullifier),
        Some(commitment),
    );
    let _initial = consensus.start_height(stats.height + 1);
    info!("🔐 Consensus engine running (Tendermint BFT — solo validator)");

    // ── Sync ──────────────────────────────────────────────────────────────────
    let mut sync = SyncState::new(stats.height);
    info!("📡 Sync state: height={} synced={}", sync.local_height, sync.is_synced());

    // ── RPC Server ────────────────────────────────────────────────────────────
    let rpc_chain = chain.clone();
    let rpc_mempool = mempool.clone();
    let rpc_fee_market = fee_market.clone();
    let rpc_peers = peer_count.clone();
    let rpc_wallet = wallet.clone();
    tokio::spawn(async move {
        start_rpc_server(rpc_chain, rpc_mempool, rpc_fee_market, rpc_peers, rpc_wallet).await;
    });

    // ── Main event loop ───────────────────────────────────────────────────────
    info!("✅ CipherX node is live. Mining blocks as solo validator...\n");

    let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(400));
    let mut blocks_mined: u64 = 0;

    loop {
        tokio::select! {
            // Network events
            Some(event) = event_rx.recv() => {
                match event {
                    NetworkEvent::BlockReceived { block, from } => {
                        info!("📥 Block #{} from peer {:?}", block.header.height, &from.to_hex()[..8]);
                        sync.on_block_applied(block.header.height);
                    }
                    NetworkEvent::TxReceived { tx, .. } => {
                        debug_tx(&tx);
                    }
                    NetworkEvent::VoteReceived { vote, from } => {
                        if let Ok(output) = consensus.receive_vote(vote) {
                            handle_consensus_output(output, &mut p2p).await;
                        }
                    }
                    NetworkEvent::PeerConnected(info) => {
                        info!("👤 New peer (height={})", info.height);
                        peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        sync.update_target(info.height, cipherx::network::peer::PeerId([0u8;32]));
                    }
                    NetworkEvent::PeerDisconnected(_peer_id) => {
                        info!("👋 Peer left");
                        peer_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ => {}
                }
            }

            // Consensus tick (400ms — target block time)
            _ = tick.tick() => {
                if consensus.is_proposer() && *consensus.current_step() == ConsensusStep::Propose {
                    let chain_r = chain.read().await;
                    let next_height = chain_r.height + 1;
                    let prev_hash = chain_r.tip_hash.clone();
                    drop(chain_r);

                    // Pull pending transactions from mempool
                    let mempool_r = mempool.read().await;
                    let pending_txs: Vec<Transaction> = mempool_r.get_for_block(100)
                        .into_iter().cloned().collect();
                    drop(mempool_r);

                    let block = build_block(next_height, prev_hash, &wallet.address, &pending_txs);

                    if let Some(finalized) = drive_solo_consensus(&mut consensus, block) {
                        let mut chain_w = chain.write().await;
                        match chain_w.append_block(finalized.clone()) {
                            Ok(()) => {
                                blocks_mined += 1;
                                let stats = chain_w.stats();

                                // Purge included txs from mempool
                                if !pending_txs.is_empty() {
                                    let spent_kis: Vec<[u8; 32]> = finalized.transactions.iter()
                                        .flat_map(|tx| tx.inputs.iter().map(|i| i.key_image.0))
                                        .collect();
                                    drop(chain_w);
                                    let mut mempool_w = mempool.write().await;
                                    mempool_w.purge_spent(&spent_kis);
                                    for tx in &pending_txs {
                                        mempool_w.remove(&tx.id());
                                    }
                                    drop(mempool_w);

                                    info!(
                                        "⛏️  Block #{} mined | {} txs | supply: {} CIP",
                                        stats.height,
                                        pending_txs.len() + 1, // +1 for coinbase
                                        stats.circulating_supply_cip,
                                    );
                                } else {
                                    drop(chain_w);
                                    if blocks_mined % 25 == 1 || blocks_mined <= 5 {
                                        info!(
                                            "⛏️  Block #{} mined | supply: {} CIP | hash: {}",
                                            stats.height,
                                            stats.circulating_supply_cip,
                                            &stats.tip_hash[..16]
                                        );
                                    }
                                }
                                consensus.start_height(next_height + 1);
                            }
                            Err(e) => {
                                warn!("❌ Block rejected: {}", e);
                                consensus.start_height(next_height);
                            }
                        }

                        let _ = p2p.broadcast_block(&finalized).await;
                    }
                } else {
                    if let Some(output) = consensus.check_timeout() {
                        handle_consensus_output(output, &mut p2p).await;
                    }
                }

                tor.rotate_circuits().await;
            }
        }
    }
}

/// Build a new block with coinbase + pending transactions
fn build_block(
    height: u64,
    prev_hash: BlockHash,
    validator_address: &StealthAddress,
    pending_txs: &[Transaction],
) -> Block {
    let reward = ChainParams::block_reward(height);
    let coinbase = Transaction::coinbase(validator_address, reward);
    let mut txs = vec![coinbase];
    txs.extend_from_slice(pending_txs);
    let tx_root = Block::compute_tx_root(&txs);

    let header = BlockHeader {
        version: 1,
        height,
        timestamp: Utc::now().timestamp_millis(),
        prev_hash,
        tx_root,
        state_root: BlockHash::zero(),
        validator_commitment: ValidatorCommitment::placeholder(),
        round: 0,
    };
    Block {
        header,
        transactions: txs,
        signatures: vec![],
    }
}

/// Drive Tendermint consensus for a solo validator in one shot
fn drive_solo_consensus(engine: &mut TendermintEngine, block: Block) -> Option<Block> {
    let proposal = match engine.submit_proposal(block) {
        Ok(ConsensusOutput::BroadcastProposal(p)) => p,
        _ => return None,
    };
    let prevote = match engine.receive_proposal(proposal) {
        Ok(ConsensusOutput::BroadcastVote(v)) => v,
        _ => return None,
    };
    let precommit = match engine.receive_vote(prevote) {
        Ok(ConsensusOutput::BroadcastVote(v)) => v,
        _ => return None,
    };
    match engine.receive_vote(precommit) {
        Ok(ConsensusOutput::FinalizedBlock(block, _votes)) => Some(block),
        _ => None,
    }
}

// ── Transaction builder ─────────────────────────────────────────────────────

/// Build a transfer transaction from the validator's wallet.
/// This runs server-side — the node has the private keys.
fn build_transfer_tx(
    chain: &Chain,
    wallet: &ValidatorWallet,
    recipient_str: &str,
    amount_ncip: u64,
    fee_ncip: u64,
) -> Result<Transaction, String> {
    // Parse recipient address
    let recipient = parse_stealth_address(recipient_str)?;

    // Scan our UTXOs
    let owned = chain.scan_utxos(&wallet.view_key, &wallet.spend_pubkey);
    let total_available: u64 = owned.iter().map(|u| u.amount_ncip).sum();
    let total_needed = amount_ncip + fee_ncip;

    if total_available < total_needed {
        return Err(format!(
            "Insufficient balance: have {} nCIP ({} CIP), need {} nCIP",
            total_available,
            total_available / 1_000_000_000,
            total_needed
        ));
    }

    // Select inputs (greedy)
    let mut selected = vec![];
    let mut selected_sum = 0u64;
    for utxo in &owned {
        selected.push(utxo.clone());
        selected_sum += utxo.amount_ncip;
        if selected_sum >= total_needed {
            break;
        }
    }

    let change_amount = selected_sum - total_needed;

    // Build recipient output (stealth)
    let recip_keys = stealth::generate_output(&recipient, 0)
        .map_err(|e| format!("Recipient stealth output: {}", e))?;
    let recip_commit = ringct::commit_random(amount_ncip);
    let recip_encrypted = ringct::encrypt_amount(amount_ncip, &recip_keys.shared_secret);
    let recip_range = ringct::prove_range(amount_ncip, &recip_commit.blinding())
        .ok_or("Range proof failed for recipient output")?;

    let mut outputs = vec![StealthOutput {
        one_time_pubkey: recip_keys.one_time_pubkey,
        tx_pubkey: recip_keys.tx_pubkey,
        amount_commitment: recip_commit.commitment(),
        encrypted_amount: recip_encrypted,
        range_proof: recip_range,
    }];

    let mut output_blindings = vec![recip_commit.blinding()];

    // Build change output if needed
    if change_amount > 0 {
        let change_keys = stealth::generate_output(&wallet.address, 1)
            .map_err(|e| format!("Change stealth output: {}", e))?;
        let change_commit = ringct::commit_random(change_amount);
        let change_encrypted = ringct::encrypt_amount(change_amount, &change_keys.shared_secret);
        let change_range = ringct::prove_range(change_amount, &change_commit.blinding())
            .ok_or("Range proof failed for change output")?;

        outputs.push(StealthOutput {
            one_time_pubkey: change_keys.one_time_pubkey,
            tx_pubkey: change_keys.tx_pubkey,
            amount_commitment: change_commit.commitment(),
            encrypted_amount: change_encrypted,
            range_proof: change_range,
        });
        output_blindings.push(change_commit.blinding());
    }

    // Build fee commitment (blindings must balance: sum(in) = sum(out) + fee)
    let mut input_blindings_all = vec![];
    let mut inputs = vec![];

    for utxo in &selected {
        // Pseudo-commitment for this input
        let in_commit = ringct::commit_random(utxo.amount_ncip);
        input_blindings_all.push(in_commit.blinding());

        // Get decoys from UTXO set
        let mut ring = chain.get_decoy_keys(
            &(utxo.tx_id.clone(), utxo.output_index),
            10,
        );

        // Ensure minimum ring size (pad with random points if needed)
        while ring.len() < 10 {
            ring.push(utxo.one_time_pubkey); // duplicate as last resort
        }

        let real_index = ring.len();
        ring.push(utxo.one_time_pubkey);

        // Derive one-time private key: x = s_i + b
        let one_time_key_bytes = stealth::derive_spend_key(
            &utxo.shared_secret,
            &PrivateKey(wallet.spend_key_bytes),
        ).ok_or("Failed to derive spend key")?;
        let one_time_priv = PrivateKey(one_time_key_bytes);

        // We'll sign after building the full tx structure
        inputs.push((ring, real_index, one_time_priv, in_commit.commitment()));
    }

    // Fee blinding
    let fee_blinding = ringct::compute_fee_blinding(&input_blindings_all, &output_blindings)
        .ok_or("Failed to compute fee blinding")?;
    let fee_commitment = ringct::commit(fee_ncip, &fee_blinding)
        .ok_or("Failed to build fee commitment")?;

    // Build preliminary transaction (for signing hash)
    let mut tx = Transaction {
        tx_type: TxType::Transfer,
        inputs: inputs.iter().map(|(ring, _, _, pseudo)| {
            RingInput {
                ring_members: ring.clone(),
                key_image: cipherx::core::transaction::KeyImage([0u8; 32]),
                ring_signature: vec![],
                pseudo_commitment: pseudo.clone(),
            }
        }).collect(),
        outputs,
        fee_commitment,
        fee_proof: vec![],
        extra: vec![],
        version: 1,
    };

    // Compute signing hash (excludes signatures)
    let signing_hash = tx.signing_hash();

    // Now sign each input with ring signature
    for (i, (ring, real_index, priv_key, _pseudo)) in inputs.iter().enumerate() {
        let (sig_bytes, key_image) = ring_sig::sign_ring(
            &signing_hash,
            ring,
            *real_index,
            priv_key,
        )?;
        tx.inputs[i].ring_signature = sig_bytes;
        tx.inputs[i].key_image = key_image;
    }

    info!("📝 Built transfer tx: {} nCIP → {} | fee: {} nCIP | inputs: {} | tx_id: {}",
        amount_ncip, &recipient_str[..16], fee_ncip, selected.len(), tx.id().to_hex());

    Ok(tx)
}

/// Parse a CX1... address string into a StealthAddress
fn parse_stealth_address(addr: &str) -> Result<StealthAddress, String> {
    if !addr.starts_with("CX1") {
        return Err("Address must start with CX1".to_string());
    }
    let bytes = bs58::decode(&addr[3..])
        .into_vec()
        .map_err(|e| format!("Invalid address encoding: {}", e))?;
    if bytes.len() < 65 {
        return Err("Address too short".to_string());
    }
    // bytes[0] = version, bytes[1..33] = public_spend, bytes[33..65] = public_view
    let mut spend = [0u8; 32];
    let mut view = [0u8; 32];
    spend.copy_from_slice(&bytes[1..33]);
    view.copy_from_slice(&bytes[33..65]);
    Ok(StealthAddress {
        public_spend: PublicKey(spend),
        public_view: PublicKey(view),
    })
}

// ── RPC HTTP Server ──────────────────────────────────────────────────────────

async fn start_rpc_server(
    chain: Arc<RwLock<Chain>>,
    mempool: Arc<RwLock<Mempool>>,
    fee_market: Arc<FeeMarket>,
    peer_count: Arc<std::sync::atomic::AtomicUsize>,
    wallet: Arc<ValidatorWallet>,
) {
    let listener = match TcpListener::bind("0.0.0.0:8545").await {
        Ok(l) => {
            info!("🌐 RPC server listening on 0.0.0.0:8545");
            l
        }
        Err(e) => {
            warn!("❌ RPC server failed to bind: {}", e);
            return;
        }
    };

    loop {
        let (mut socket, _addr) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        let chain = chain.clone();
        let mempool = mempool.clone();
        let fee_market = fee_market.clone();
        let peer_count = peer_count.clone();
        let wallet = wallet.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let n = match socket.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request_str = String::from_utf8_lossy(&buf[..n]);

            // Handle CORS preflight (OPTIONS)
            if request_str.starts_with("OPTIONS") {
                let response = "HTTP/1.1 204 No Content\r\n\
                    Access-Control-Allow-Origin: *\r\n\
                    Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                    Access-Control-Allow-Headers: Content-Type\r\n\
                    Access-Control-Max-Age: 86400\r\n\
                    Content-Length: 0\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
                return;
            }

            // Find JSON body
            let body = if let Some(pos) = request_str.find("\r\n\r\n") {
                &request_str[pos + 4..]
            } else {
                &request_str[..]
            };

            // Parse JSON-RPC request
            let rpc_req: RpcRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(_) => {
                    let err = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                        err.len(), err
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }
            };

            // ── Special RPC methods handled locally ──────────────────────────

            let rpc_response = if rpc_req.method == "wallet_sendCIP" {
                // wallet_sendCIP: {to: "CX1...", amount: nCIP}
                handle_send_cip(&rpc_req, &chain, &mempool, &wallet).await
            } else {
                // Standard RPC — build NodeState + dispatch
                let chain_r = chain.read().await;
                let stats = chain_r.stats();
                let owned_utxos = chain_r.scan_utxos(&wallet.view_key, &wallet.spend_pubkey);
                let validator_balance: u64 = owned_utxos.iter().map(|u| u.amount_ncip).sum();
                let validator_utxo_count = owned_utxos.len();
                let state = NodeState {
                    chain_height: chain_r.height,
                    tip_hash: chain_r.tip_hash.0,
                    peer_count: peer_count.load(std::sync::atomic::Ordering::Relaxed),
                    syncing: false,
                    sync_progress: 100.0,
                    base_fee_per_gas: fee_market.base_fee_per_gas,
                    circulating_supply_ncip: stats.circulating_supply_cip * 1_000_000_000,
                    block_reward_ncip: stats.next_block_reward_cip * 1_000_000_000,
                    validator_balance_ncip: validator_balance,
                    validator_utxo_count,
                };
                let resp = handle_request(&rpc_req, &state);
                drop(chain_r);
                resp
            };

            let json = serde_json::to_string(&rpc_response).unwrap_or_default();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\n\r\n{}",
                json.len(), json
            );
            let _ = socket.write_all(http_response.as_bytes()).await;
        });
    }
}

/// Handle wallet_sendCIP RPC — builds + signs + submits a transfer transaction
async fn handle_send_cip(
    req: &RpcRequest,
    chain: &Arc<RwLock<Chain>>,
    mempool: &Arc<RwLock<Mempool>>,
    wallet: &ValidatorWallet,
) -> RpcResponse {
    use serde_json::json;

    let id = req.id.clone();

    // Parse params: {to: string, amount: number (nCIP)}
    let to = match req.params.first().and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return RpcResponse::err(id, -32602, "Expected 'to' address".to_string()),
    };
    let amount_ncip = match req.params.get(1).and_then(|v| v.as_u64()) {
        Some(a) => a,
        None => return RpcResponse::err(id, -32602, "Expected 'amount' in nCIP".to_string()),
    };

    if amount_ncip == 0 {
        return RpcResponse::err(id, -32602, "Amount must be > 0".to_string());
    }

    let fee_ncip: u64 = 1_000_000; // 0.001 CIP fixed fee

    // Build the transaction
    let chain_r = chain.read().await;
    let tx = match build_transfer_tx(&chain_r, wallet, &to, amount_ncip, fee_ncip) {
        Ok(tx) => tx,
        Err(e) => return RpcResponse::err(id, -32000, e),
    };
    drop(chain_r);

    let tx_id = tx.id().to_hex();

    // Add to mempool
    let mut mempool_w = mempool.write().await;
    match mempool_w.add(tx) {
        Ok(_) => {
            info!("💸 TX added to mempool: {} → {} | {} nCIP", &tx_id[..16], &to[..16], amount_ncip);
            RpcResponse::ok(id, json!({
                "txId": tx_id,
                "status": "pending",
                "fee": fee_ncip,
            }))
        }
        Err(e) => RpcResponse::err(id, -32000, format!("Mempool rejected: {}", e)),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn handle_consensus_output(output: ConsensusOutput, p2p: &mut P2PNode) {
    match output {
        ConsensusOutput::BroadcastVote(vote) => {
            let _ = p2p.broadcast_vote(&vote).await;
        }
        ConsensusOutput::BroadcastProposal(proposal) => {
            let _ = p2p.broadcast_block(&proposal.block).await;
        }
        ConsensusOutput::FinalizedBlock(block, _votes) => {
            info!("🎉 Block #{} finalized!", block.header.height);
            let _ = p2p.broadcast_block(&block).await;
        }
        ConsensusOutput::SlashEvidence(evidence) => {
            info!("⚠️  Slashing evidence at h={}", evidence.height);
        }
        ConsensusOutput::Pending => {}
    }
}

fn debug_tx(tx: &cipherx::core::transaction::Transaction) {
    tracing::debug!("📨 Tx received id={}", tx.id().to_hex());
}

fn print_banner() {
    info!("╔═══════════════════════════════════════════════╗");
    info!("║          CipherX Node  v0.1.0                 ║");
    info!("║                                               ║");
    info!("║   Private  ·  Decentralized  ·  Uncensored   ║");
    info!("║                                               ║");
    info!("║   Phase 1: Core chain          ✅             ║");
    info!("║   Phase 2: Tendermint BFT      ✅             ║");
    info!("║   Phase 3: Ring sigs + RingCT  ✅             ║");
    info!("║   Phase 4: zk-SNARKs           ✅             ║");
    info!("║   Phase 5: EVM + contracts     ✅             ║");
    info!("║   Phase 6: P2P + Tor           ✅             ║");
    info!("║   Phase 7: Wallet integration  ✅             ║");
    info!("╚═══════════════════════════════════════════════╝");
}
