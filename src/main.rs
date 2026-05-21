// CipherX Lite Node — Entry point

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tracing_subscriber::EnvFilter;
use chrono::Utc;

use cipherx::core::block::{Block, BlockHeader, BlockHash};
use cipherx::core::chain::{Chain, CHAIN_ID, NETWORK_NAME, IS_TESTNET};
use cipherx::core::transaction::Transaction;
use cipherx::consensus::tendermint::{TendermintEngine, ConsensusOutput};
use cipherx::crypto::keys::{ValidatorCommitment, StealthAddress, PublicKey};
use cipherx::network::tor::{TorClient, TorConfig};
use cipherx::network::p2p::{P2PNode, P2PConfig, NetworkEvent};
use cipherx::network::sync::SyncState;
use cipherx::network::rpc::{RpcRequest, NodeState, BlockOutputRef, handle_request};
use cipherx::network::p2p::{NetworkMessage, HelloMessage, BlockRequest, BlockResponse};
use cipherx::network::sync_protocol::{send_msg, recv_msg, PROTOCOL_VERSION, BLOCKS_PER_BATCH};
use tokio::sync::broadcast;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    print_banner();

    // ── Chain ─────────────────────────────────────────────────────────────
    let chain = Arc::new(RwLock::new(Chain::new()));
    let stats = chain.read().await.stats();
    info!("⛓️  Hauteur: {} | Tip: {}", stats.height, &stats.tip_hash[..16]);
    info!("💰 Supply: {} / 100,000,000 CIP", stats.circulating_supply_cip);
    info!("📦 Récompense: {} CIP/bloc", stats.next_block_reward_cip);
    info!("⏳ Prochain halving: bloc #{}", stats.next_halving_block);

    // ── Tor (optionnel) ───────────────────────────────────────────────────
    let mut tor = TorClient::new(TorConfig::default());
    tor.start().await.map_err(|e| anyhow::anyhow!(e))?;

    // ── P2P ───────────────────────────────────────────────────────────────
    let (event_tx, mut event_rx) = mpsc::channel::<NetworkEvent>(1000);
    let mut p2p = P2PNode::new(P2PConfig::default(), event_tx);
    info!("🌐 P2P initialisé | pairs: {}", p2p.peer_count());

    // ── Consensus (mode solo — 1 validateur) ──────────────────────────────
    let our_nullifier = [1u8; 32];
    let commitment = ValidatorCommitment::placeholder();
    let mut consensus = TendermintEngine::new(
        1,
        1,
        vec![our_nullifier],
        Some(our_nullifier),
        Some(commitment),
    );
    consensus.start_height(1);

    // ── Reward address ────────────────────────────────────────────────────
    let reward_address = load_reward_address();

    // ── Mode détection ────────────────────────────────────────────────────
    let seed_nodes: Vec<String> = std::env::var("CIPHERX_SEED_NODES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let is_sync_mode = !seed_nodes.is_empty();

    if is_sync_mode {
        info!("🔄 Mode SYNC — seed: {:?}", seed_nodes);
        info!("   (pas de production de blocs — sync depuis le seed)");
    } else {
        info!("🔐 Mode VALIDATEUR — Tendermint BFT solo");
    }

    // ── Broadcast channel (new blocks → connected peers) ──────────────────
    let (block_bcast_tx, _) = broadcast::channel::<Block>(128);

    // ── Sync channel (blocks reçus du seed → main loop) ───────────────────
    let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel::<Block>(256);

    // ── Peer counter (pour RPC peerCount) ─────────────────────────────────
    let peer_count = Arc::new(AtomicUsize::new(0));

    // ── RPC + P2P servers ─────────────────────────────────────────────────
    tokio::spawn(run_rpc_server(chain.clone(), peer_count.clone()));
    tokio::spawn(run_p2p_listener(chain.clone(), block_bcast_tx.clone(), peer_count.clone()));

    // ── Connexion aux seeds (mode sync uniquement) ─────────────────────────
    for seed in seed_nodes {
        tokio::spawn(run_sync_client(seed, chain.clone(), sync_tx.clone()));
    }

    info!("✅ Nœud CipherX Lite prêt\n");

    // ── Main event loop ───────────────────────────────────────────────────
    let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(400));
    let mut sync = SyncState::new(stats.height);
    let mut _blocks_mined: u64 = 0;

    loop {
        tokio::select! {
            // ── Bloc reçu du seed (mode sync) ─────────────────────────────
            Some(block) = sync_rx.recv() => {
                let mut chain_w = chain.write().await;
                match chain_w.append_block(block) {
                    Ok(()) => {
                        let s = chain_w.stats();
                        sync.on_block_applied(s.height);
                        info!("📥 Bloc #{} appliqué | supply: {} CIP", s.height, s.circulating_supply_cip);
                    }
                    Err(e) => {
                        // Peut arriver si le bloc est déjà connu (reconnexion)
                        tracing::debug!("Bloc ignoré: {}", e);
                    }
                }
            }

            // ── Événements réseau ──────────────────────────────────────────
            Some(event) = event_rx.recv() => {
                match event {
                    NetworkEvent::BlockReceived { block, from: _ } => {
                        sync.on_block_applied(block.header.height);
                    }
                    NetworkEvent::VoteReceived { vote, from: _ } => {
                        if let Ok(output) = consensus.receive_vote(vote) {
                            if let ConsensusOutput::BroadcastVote(v) = output {
                                let _ = p2p.broadcast_vote(&v).await;
                            }
                        }
                    }
                    NetworkEvent::PeerConnected(info) => {
                        sync.update_target(info.height,
                            cipherx::network::peer::PeerId([0u8; 32]));
                    }
                    _ => {}
                }
            }

            // ── Tick consensus (mode validateur uniquement) ────────────────
            _ = tick.tick() => {
                if !is_sync_mode && consensus.is_proposer() {
                    let (next_height, prev_hash) = {
                        let c = chain.read().await;
                        (c.height + 1, c.tip_hash.clone())
                    };

                    let block = build_block(next_height, prev_hash, reward_address.as_ref());

                    if let Some(finalized) = drive_solo_consensus(&mut consensus, block) {
                        let mut chain_w = chain.write().await;
                        match chain_w.append_block(finalized.clone()) {
                            Ok(()) => {
                                _blocks_mined += 1;
                                let stats = chain_w.stats();
                                info!(
                                    "🎉 Bloc #{} FINALISÉ | supply: {} CIP | hash: {}",
                                    stats.height,
                                    stats.circulating_supply_cip,
                                    &stats.tip_hash[..16]
                                );
                                drop(chain_w);
                                consensus.start_height(next_height + 1);
                                let _ = p2p.broadcast_block(&finalized).await;
                                // Diffuse aux pairs connectés
                                let _ = block_bcast_tx.send(finalized);
                            }
                            Err(e) => {
                                info!("❌ Bloc rejeté: {}", e);
                                consensus.start_height(next_height);
                            }
                        }
                    } else if let Some(output) = consensus.check_timeout() {
                        if let ConsensusOutput::BroadcastVote(v) = output {
                            let _ = p2p.broadcast_vote(&v).await;
                        }
                    }
                }
            }
        }
    }
}

/// Load reward address from:
///   1. CIPHERX_REWARD_ADDRESS environment variable
///   2. ~/.cipherx/reward_address.txt
///   3. Fallback: placeholder (logs warning)
fn load_reward_address() -> Option<StealthAddress> {
    // Try env var first
    if let Ok(addr_str) = std::env::var("CIPHERX_REWARD_ADDRESS") {
        if let Some(addr) = parse_stealth_address(&addr_str) {
            info!("💰 Reward address: from CIPHERX_REWARD_ADDRESS env");
            return Some(addr);
        } else {
            info!("⚠️  CIPHERX_REWARD_ADDRESS env var is set but invalid — ignoring");
        }
    }

    // Try file
    let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    let addr_file = home.join(".cipherx").join("reward_address.txt");
    if let Ok(content) = std::fs::read_to_string(&addr_file) {
        let addr_str = content.trim().to_string();
        if let Some(addr) = parse_stealth_address(&addr_str) {
            info!("💰 Reward address: {}", &addr_str[..std::cmp::min(20, addr_str.len())]);
            return Some(addr);
        } else {
            info!("⚠️  {} contains invalid address — ignoring", addr_file.display());
        }
    }

    // Fallback warning
    info!("⚠️  No reward address configured!");
    info!("   Set CIPHERX_REWARD_ADDRESS env var or create ~/.cipherx/reward_address.txt");
    info!("   Using placeholder address (coinbase outputs are unspendable)");
    None
}

/// Parse a CX1... stealth address into its component public keys.
///
/// Address format: CX1 + base58(public_spend[32] || public_view[32] || checksum[4])
fn parse_stealth_address(addr: &str) -> Option<StealthAddress> {
    if !addr.starts_with("CX1") || addr.len() < 10 {
        return None;
    }
    let encoded = &addr[3..]; // strip "CX1"
    let decoded = bs58::decode(encoded).into_vec().ok()?;
    if decoded.len() != 68 {
        // 32 + 32 + 4 checksum
        return None;
    }
    // Verify checksum
    use sha3::{Sha3_256, Digest};
    let mut h = Sha3_256::new();
    h.update(b"CipherX_addr_v1");
    h.update(&decoded[..64]);
    let checksum: [u8; 32] = h.finalize().into();
    if &checksum[..4] != &decoded[64..68] {
        return None;
    }
    let mut spend = [0u8; 32];
    let mut view = [0u8; 32];
    spend.copy_from_slice(&decoded[..32]);
    view.copy_from_slice(&decoded[32..64]);
    Some(StealthAddress {
        public_spend: PublicKey(spend),
        public_view: PublicKey(view),
    })
}

/// Construit un bloc valide à la hauteur donnée avec coinbase
fn build_block(height: u64, prev_hash: BlockHash, reward_address: Option<&StealthAddress>) -> Block {
    use cipherx::core::chain::ChainParams;
    let reward = ChainParams::block_reward(height);

    let coinbase = if let Some(addr) = reward_address {
        Transaction::build_coinbase(addr, reward, height)
    } else {
        Transaction::coinbase_placeholder(height)
    };
    let txs = vec![coinbase];
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
    Block { header, transactions: txs, signatures: vec![] }
}

/// Conduit le consensus Tendermint en mode solo (propose → prevote → precommit → finalize)
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

/// Minimal HTTP JSON-RPC server on 127.0.0.1:8545
async fn run_rpc_server(chain: Arc<RwLock<Chain>>, peer_count: Arc<AtomicUsize>) {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match TcpListener::bind("127.0.0.1:8545").await {
        Ok(l) => { info!("🔌 RPC server: http://127.0.0.1:8545"); l }
        Err(e) => { info!("⚠️  RPC server failed to bind: {}", e); return; }
    };

    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let chain_c = chain.clone();
        let pc = peer_count.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32768];
            let n = match stream.read(&mut buf).await { Ok(n) => n, Err(_) => return };
            if n == 0 { return; }

            let raw = String::from_utf8_lossy(&buf[..n]);

            if raw.starts_with("OPTIONS") {
                let cors = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n";
                let _ = stream.write_all(cors.as_bytes()).await;
                return;
            }

            let body = match raw.find("\r\n\r\n") {
                Some(pos) => raw[pos + 4..].trim_matches('\0').to_string(),
                None => return,
            };
            if body.is_empty() { return; }

            let rpc_req: RpcRequest = match serde_json::from_str(&body) {
                Ok(r) => r,
                Err(_) => return,
            };

            let state = {
                let c = chain_c.read().await;
                let s = c.stats();
                let block_outputs = c.all_utxos().into_iter().map(|u| BlockOutputRef {
                    tx_pubkey:        hex::encode(u.output.tx_pubkey),
                    one_time_pubkey:  hex::encode(u.output.one_time_pubkey),
                    amount_commitment: hex::encode(u.output.amount_commitment.0),
                    encrypted_amount: hex::encode(&u.output.encrypted_amount),
                    output_index:     u.output_index,
                    tx_id:            hex::encode(u.tx_id.0),
                    block_height:     u.block_height,
                }).collect();
                NodeState {
                    chain_height: s.height,
                    tip_hash: [0u8; 32],
                    peer_count: pc.load(Ordering::Relaxed),
                    syncing: false,
                    sync_progress: 1.0,
                    base_fee_per_gas: 0,
                    circulating_supply_ncip: s.circulating_supply_cip * 1_000_000_000,
                    block_reward_ncip: s.next_block_reward_cip * 1_000_000_000,
                    block_outputs,
                }
            };

            let resp = handle_request(&rpc_req, &state);
            let resp_body = serde_json::to_string(&resp).unwrap_or_default();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                resp_body.len(), resp_body
            );
            let _ = stream.write_all(http.as_bytes()).await;
        });
    }
}

/// TCP listener on 0.0.0.0:9152 — accepts peers, runs full sync protocol
async fn run_p2p_listener(
    chain: Arc<RwLock<Chain>>,
    block_bcast: broadcast::Sender<Block>,
    peer_count: Arc<AtomicUsize>,
) {
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind("0.0.0.0:9152").await {
        Ok(l) => { info!("📡 P2P listener: 0.0.0.0:9152"); l }
        Err(e) => { info!("⚠️  P2P listener failed to bind: {}", e); return; }
    };

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let chain_c = chain.clone();
                let bcast_rx = block_bcast.subscribe();
                let pc = peer_count.clone();
                tokio::spawn(handle_peer_inbound(stream, addr, chain_c, bcast_rx, pc));
            }
            Err(e) => { info!("P2P accept error: {}", e); }
        }
    }
}

/// Handle one inbound peer connection end-to-end
async fn handle_peer_inbound(
    mut stream: tokio::net::TcpStream,
    addr: SocketAddr,
    chain: Arc<RwLock<Chain>>,
    mut bcast_rx: broadcast::Receiver<Block>,
    peer_count: Arc<AtomicUsize>,
) {
    // ── Handshake ──────────────────────────────────────────────────────────
    let our_height = chain.read().await.height;
    let hello = NetworkMessage::Hello(HelloMessage {
        version: PROTOCOL_VERSION.to_string(),
        height: our_height,
        tip_hash: [0u8; 32],
        protocols: vec!["/cipherx/sync/1.0.0".to_string()],
        onion_address: None,
    });
    if send_msg(&mut stream, &hello).await.is_err() { return; }

    let peer_height = match recv_msg(&mut stream).await {
        Ok(NetworkMessage::Hello(h)) => h.height,
        _ => return,
    };
    info!("👤 Pair {} connecté (hauteur={})", addr, peer_height);
    peer_count.fetch_add(1, Ordering::Relaxed);

    // ── Main loop: serve requests + push new blocks ────────────────────────
    loop {
        tokio::select! {
            msg = recv_msg(&mut stream) => {
                match msg {
                    Ok(NetworkMessage::BlockRequest(req)) => {
                        let blocks: Vec<Block> = {
                            let c = chain.read().await;
                            let end = req.to_height.min(c.height);
                            (req.from_height..=end)
                                .take(BLOCKS_PER_BATCH as usize)
                                .filter_map(|h| c.block_at(h).cloned())
                                .collect()
                        };
                        let count = blocks.len();
                        let resp = NetworkMessage::BlockResponse(BlockResponse {
                            request_id: req.request_id,
                            blocks,
                        });
                        if send_msg(&mut stream, &resp).await.is_err() { break; }
                        info!("📤 {} blocs envoyés à {} (#{}-#{})", count, addr, req.from_height, req.to_height);
                    }
                    Ok(NetworkMessage::Bye) | Err(_) => break,
                    _ => {}
                }
            }

            // Push new blocks to this peer as they are produced
            result = bcast_rx.recv() => {
                match result {
                    Ok(block) => {
                        let msg = NetworkMessage::NewBlock(Box::new(block));
                        if send_msg(&mut stream, &msg).await.is_err() { break; }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        info!("⚠️  Pair {} en retard de {} blocs — sync nécessaire", addr, n);
                    }
                    Err(_) => break,
                }
            }
        }
    }

    peer_count.fetch_sub(1, Ordering::Relaxed);
    info!("👋 Pair {} déconnecté", addr);
}

/// Connect to a seed node, sync all missing blocks, then stay connected for live blocks.
/// Used by tester nodes: set CIPHERX_SEED_NODES=141.11.243.5:9152
async fn run_sync_client(
    seed_addr: String,
    chain: Arc<RwLock<Chain>>,
    sync_tx: tokio::sync::mpsc::Sender<Block>,
) {
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Duration};

    loop {
        info!("🔗 Connexion au seed node {}...", seed_addr);
        let mut stream = match TcpStream::connect(&seed_addr).await {
            Ok(s) => s,
            Err(e) => {
                info!("❌ Connexion impossible à {} : {} — retry dans 10s", seed_addr, e);
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        // ── Handshake ──────────────────────────────────────────────────────
        let our_height = chain.read().await.height;
        let hello = NetworkMessage::Hello(HelloMessage {
            version: PROTOCOL_VERSION.to_string(),
            height: our_height,
            tip_hash: [0u8; 32],
            protocols: vec!["/cipherx/sync/1.0.0".to_string()],
            onion_address: None,
        });
        if send_msg(&mut stream, &hello).await.is_err() {
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let seed_height = match recv_msg(&mut stream).await {
            Ok(NetworkMessage::Hello(h)) => h.height,
            _ => { sleep(Duration::from_secs(5)).await; continue; }
        };
        info!("✅ Seed connecté — leur hauteur: #{}, la nôtre: #{}", seed_height, our_height);

        // ── Catch-up sync ──────────────────────────────────────────────────
        let mut next = chain.read().await.height + 1;
        let mut req_id: u64 = 0;

        while next <= seed_height {
            let to = (next + BLOCKS_PER_BATCH - 1).min(seed_height);
            let req = NetworkMessage::BlockRequest(BlockRequest {
                from_height: next,
                to_height: to,
                request_id: req_id,
            });
            req_id += 1;

            if send_msg(&mut stream, &req).await.is_err() { break; }

            match recv_msg(&mut stream).await {
                Ok(NetworkMessage::BlockResponse(resp)) => {
                    let count = resp.blocks.len();
                    for block in resp.blocks {
                        let _ = sync_tx.send(block).await;
                    }
                    info!("📥 {} blocs reçus (#{}-#{})", count, next, to);
                    next = to + 1;
                }
                _ => break,
            }
            // Small yield to let main loop apply the blocks
            sleep(Duration::from_millis(50)).await;
        }
        info!("✅ Sync terminé à hauteur #{}", seed_height);

        // ── Live mode: receive new blocks as they are produced ─────────────
        loop {
            match recv_msg(&mut stream).await {
                Ok(NetworkMessage::NewBlock(block)) => {
                    info!("📥 Nouveau bloc #{} reçu du seed", block.header.height);
                    let _ = sync_tx.send(*block).await;
                }
                Ok(NetworkMessage::Bye) | Err(_) => {
                    info!("🔌 Seed déconnecté — reconnexion dans 5s");
                    break;
                }
                _ => {}
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}

fn print_banner() {
    info!("╔═══════════════════════════════════════════════╗");
    info!("║       CipherX Lite  v0.1.0                    ║");
    info!("║                                               ║");
    info!("║   La vitesse de Solana (400ms)                ║");
    info!("║   La privacy de Monero (Ring Sigs + RingCT)   ║");
    info!("║                                               ║");
    info!("║   ✅ Ring Signatures MLSAG (11 membres)        ║");
    info!("║   ✅ Stealth Addresses                         ║");
    info!("║   ✅ RingCT + Bulletproofs                     ║");
    info!("║   ✅ Tendermint BFT (400ms)                    ║");
    info!("║   ✅ PoS (31 CIP minimum)                      ║");
    info!("╚═══════════════════════════════════════════════╝");
    if IS_TESTNET {
        info!("⚠️  TESTNET — Les CIP testnet n'ont aucune valeur réelle");
    }
    info!("🌐 Réseau : {}", NETWORK_NAME);
    info!("🔗 Chain ID : 0x{:x}", CHAIN_ID);
}
