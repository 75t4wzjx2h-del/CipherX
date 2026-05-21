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
use cipherx::network::rpc::{RpcRequest, NodeState, handle_request};

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

    info!("🔐 Consensus Tendermint BFT — mode solo");

    // ── RPC + P2P servers ─────────────────────────────────────────────────
    tokio::spawn(run_rpc_server(chain.clone()));
    tokio::spawn(run_p2p_listener());

    info!("✅ Nœud CipherX Lite prêt\n");

    // ── Main event loop ───────────────────────────────────────────────────
    let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(400));
    let mut sync = SyncState::new(stats.height);
    let mut _blocks_mined: u64 = 0;

    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    NetworkEvent::BlockReceived { block, from: _ } => {
                        info!("📥 Bloc #{} reçu", block.header.height);
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
                        info!("👤 Pair connecté (hauteur={})", info.height);
                        sync.update_target(info.height,
                            cipherx::network::peer::PeerId([0u8; 32]));
                    }
                    NetworkEvent::PeerDisconnected(_) => {
                        info!("👋 Pair déconnecté");
                    }
                    _ => {}
                }
            }

            _ = tick.tick() => {
                if consensus.is_proposer() {
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
async fn run_rpc_server(chain: Arc<RwLock<Chain>>) {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match TcpListener::bind("127.0.0.1:8545").await {
        Ok(l) => { info!("🔌 RPC server: http://127.0.0.1:8545"); l }
        Err(e) => { info!("⚠️  RPC server failed to bind: {}", e); return; }
    };

    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let chain_c = chain.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32768];
            let n = match stream.read(&mut buf).await { Ok(n) => n, Err(_) => return };
            if n == 0 { return; }

            let raw = String::from_utf8_lossy(&buf[..n]);

            // Handle CORS preflight
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
                NodeState {
                    chain_height: s.height,
                    tip_hash: [0u8; 32],
                    peer_count: 0,
                    syncing: false,
                    sync_progress: 1.0,
                    base_fee_per_gas: 0,
                    circulating_supply_ncip: s.circulating_supply_cip * 1_000_000_000,
                    block_reward_ncip: s.next_block_reward_cip * 1_000_000_000,
                    block_outputs: vec![],
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

/// TCP listener on 0.0.0.0:9152 (P2P — accepts connections from peers)
async fn run_p2p_listener() {
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind("0.0.0.0:9152").await {
        Ok(l) => { info!("📡 P2P listener: 0.0.0.0:9152"); l }
        Err(e) => { info!("⚠️  P2P listener failed to bind: {}", e); return; }
    };

    loop {
        match listener.accept().await {
            Ok((_stream, addr)) => {
                info!("👤 P2P inbound connection from {}", addr);
                // Full libp2p handshake is a future milestone
            }
            Err(e) => { info!("P2P accept error: {}", e); }
        }
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
