// CipherX — P2P Sync Protocol
//
// Wire format: [4 bytes length big-endian] + [bincode payload]
//
// Message flow (seed → peer):
//   Peer connects → both send Hello → peer sends BlockRequest(s) →
//   seed sends BlockResponse → seed pushes NewBlock as they arrive
//
// Mode detection via CIPHERX_SEED_NODES env var:
//   unset  → validator mode (produces blocks, serves peers)
//   set    → sync mode (syncs from seed, no block production)

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::network::p2p::NetworkMessage;

pub const MAX_FRAME_SIZE: u32 = 10 * 1024 * 1024; // 10 MB
pub const BLOCKS_PER_BATCH: u64 = 100;
pub const PROTOCOL_VERSION: &str = "cipherx/0.1.0";

// ─── Framing ─────────────────────────────────────────────────────────────────

pub async fn send_msg(stream: &mut TcpStream, msg: &NetworkMessage) -> Result<(), String> {
    let bytes = bincode::serialize(msg).map_err(|e| format!("serialize: {}", e))?;
    let len = bytes.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(format!("frame too large: {} bytes", len));
    }
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| format!("write len: {}", e))?;
    stream.write_all(&bytes).await.map_err(|e| format!("write body: {}", e))?;
    stream.flush().await.map_err(|e| format!("flush: {}", e))?;
    Ok(())
}

pub async fn recv_msg(stream: &mut TcpStream) -> Result<NetworkMessage, String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| format!("read len: {}", e))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(format!("frame too large: {} bytes", len));
    }
    if len == 0 {
        return Err("empty frame".to_string());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.map_err(|e| format!("read body: {}", e))?;
    bincode::deserialize(&buf).map_err(|e| format!("deserialize: {}", e))
}
