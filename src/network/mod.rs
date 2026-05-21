// CipherX — Network Layer (Phase 6)
//
// All traffic routes through Tor by default.
// Nodes never expose their real IP.
//
// Stack:
//   tor.rs    — Tor integration via `arti` (Tor in Rust)
//   p2p.rs    — libp2p gossipsub + kademlia DHT
//   rpc.rs    — JSON-RPC API (local only, no remote exposure)
//   sync.rs   — Block/tx sync protocol
//   peer.rs   — Peer management + reputation

pub mod tor;
pub mod p2p;
pub mod rpc;
pub mod sync;
pub mod peer;
pub mod sync_protocol;
