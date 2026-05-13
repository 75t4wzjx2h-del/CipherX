// CipherX Lite Node — Entry point

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tracing_subscriber::EnvFilter;
use chrono::Utc;

use cipherx::core::block::{Block, BlockHeader, BlockHash};
use cipherx::core::chain::Chain;
use cipherx::core::transaction::Transaction;
use cipherx::consensus::tendermint::{TendermintEngine, ConsensusOutput};
use cipherx::crypto::keys::ValidatorCommitment;
use cipherx::network::tor::{TorClient, TorConfig};
use cipherx::network::p2p::{P2PNode, P2PConfig, NetworkEvent};
use cipherx::network::sync::SyncState;

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

    info!("🔐 Consensus Tendermint BFT — mode solo");
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

                    let block = build_block(next_height, prev_hash);

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

/// Construit un bloc valide à la hauteur donnée avec coinbase
fn build_block(height: u64, prev_hash: BlockHash) -> Block {
    let coinbase = Transaction::coinbase_placeholder(height);
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
}
