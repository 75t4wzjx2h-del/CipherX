// CipherX — MLSAG Ring Signatures (Phase 3)
//
// Multilayered Linkable Spontaneous Anonymous Group Signatures.
// Based on Monero's MLSAG construction.
//
// Math:
//   Let ring = [P_0, P_1, ..., P_(n-1)]  (public keys)
//   Real signer has index π with private key x_π where P_π = x_π * G
//
//   Key image:   I = x_π * H_p(P_π)
//     - Unique per output spent
//     - Reveals nothing about π or x_π
//     - Used to detect double spends
//
//   Signature (simplified LSAG for single key column):
//     1. Pick random α
//     2. Compute L_π = α*G,  R_π = α*H_p(P_π)
//     3. c_{π+1} = H(m, L_π, R_π)
//     4. For i ≠ π: pick random s_i, compute:
//          L_i = s_i*G + c_i*P_i
//          R_i = s_i*H_p(P_i) + c_i*I
//          c_{i+1} = H(m, L_i, R_i)
//     5. Close ring: s_π = α - c_π * x_π  (mod l)
//
//   Verify:
//     Recompute all L_i, R_i, c_i from (c_0, s_0..s_{n-1})
//     Check c_0 == c_n (ring closes)
//
// This impl uses curve25519-dalek (Ristretto group for efficiency & safety)

use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use sha3::{Sha3_512, Digest};
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

use crate::core::transaction::KeyImage;
use crate::crypto::keys::PrivateKey;

pub const RING_SIZE: usize = 11;

// Alias for clarity
type Point = RistrettoPoint;
const G: Point = RISTRETTO_BASEPOINT_POINT;

// ─── Hash-to-point ────────────────────────────────────────────────────────────

/// Hash a public key to a curve point: H_p(P)
/// Used to compute key images.
/// Uses Ristretto hash-from-uniform-bytes for uniform distribution.
fn hash_to_point(pubkey: &[u8; 32]) -> Point {
    let mut h = Sha3_512::new();
    h.update(b"CipherX_H_p");
    h.update(pubkey);
    let hash = h.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

// ─── Challenge hash ───────────────────────────────────────────────────────────

/// H(message, L, R) → Scalar
/// The Fiat-Shamir challenge for each ring step
fn hash_challenge(message: &[u8], l: &Point, r: &Point) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"CipherX_MLSAG");
    h.update(message);
    h.update(l.compress().as_bytes());
    h.update(r.compress().as_bytes());
    let hash = h.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

// ─── LSAG Signature (single-column MLSAG) ────────────────────────────────────

/// Serializable LSAG ring signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingSignature {
    /// c_0 — the initial challenge (closes the ring)
    pub c0: [u8; 32],
    /// s_i for each ring member
    pub s: Vec<[u8; 32]>,
    /// Key image I (for double-spend detection)
    pub key_image: [u8; 32],
}

impl RingSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("sig serialize")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| e.to_string())
    }
}

// ─── Sign ─────────────────────────────────────────────────────────────────────

/// Sign a message with an LSAG ring signature.
///
/// # Arguments
/// * `message`      — bytes to sign (usually tx commitment hash)
/// * `ring_pubkeys` — compressed Ristretto public keys of all ring members
/// * `real_index`   — index of the real signer in the ring
/// * `private_key`  — real signer's private key bytes (scalar)
///
/// # Returns
/// `(RingSignature, KeyImage)`
pub fn sign(
    message: &[u8],
    ring_pubkeys: &[[u8; 32]],
    real_index: usize,
    private_key: &PrivateKey,
) -> Result<(RingSignature, KeyImage), String> {
    let n = ring_pubkeys.len();
    if n < 2 {
        return Err("Ring must have at least 2 members".to_string());
    }
    if real_index >= n {
        return Err("real_index out of bounds".to_string());
    }

    // Deserialize private key scalar
    let mut x = scalar_from_bytes(&private_key.0)
        .ok_or("Invalid private key scalar")?;

    // Decompress ring public keys
    let pubkeys: Vec<Point> = ring_pubkeys
        .iter()
        .map(|pk| decompress_point(pk).ok_or("Invalid ring pubkey"))
        .collect::<Result<Vec<_>, _>>()?;

    // Compute key image: I = x * H_p(P_π)
    let hp_real = hash_to_point(&ring_pubkeys[real_index]);
    let key_image: Point = x * hp_real;

    // Random blinding scalar α — secret, must be zeroized after use
    let mut alpha = {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        bytes.zeroize();
        s
    };

    // Random scalars for non-real ring members. The s vector contains the
    // closure value s[real_index] = α - c[π]·x at the end — also secret.
    let mut s: Vec<Scalar> = (0..n)
        .map(|_| {
            let mut bytes = [0u8; 64];
            OsRng.fill_bytes(&mut bytes);
            let v = Scalar::from_bytes_mod_order_wide(&bytes);
            bytes.zeroize();
            v
        })
        .collect();

    // Step 1: Compute L_π = α*G,  R_π = α*H_p(P_π)
    let l_pi = alpha * G;
    let r_pi = alpha * hp_real;

    // Step 2: Compute c_{π+1} = H(m, L_π, R_π)
    let mut c = vec![Scalar::ZERO; n];
    c[(real_index + 1) % n] = hash_challenge(message, &l_pi, &r_pi);

    // Step 3: Iterate around the ring (forward from π+1 to π).
    // We use constant-time scalar multiplication via curve25519-dalek
    // (the * operator is constant-time on Scalar/RistrettoPoint).
    let mut i = (real_index + 1) % n;
    loop {
        let hp_i = hash_to_point(&ring_pubkeys[i]);
        let l_i = s[i] * G + c[i] * pubkeys[i];
        let r_i = s[i] * hp_i + c[i] * key_image;
        let next = (i + 1) % n;
        c[next] = hash_challenge(message, &l_i, &r_i);
        i = next;
        if i == real_index { break; }
    }

    // Step 4: Close the ring — compute s_π
    s[real_index] = alpha - c[real_index] * x;

    // Serialize
    let c0 = scalar_to_bytes(&c[0]);
    let s_bytes: Vec<[u8; 32]> = s.iter().map(scalar_to_bytes).collect();
    let ki_bytes = compress_point(&key_image);

    let sig = RingSignature { c0, s: s_bytes, key_image: ki_bytes };
    let ki = KeyImage(ki_bytes);

    // Best-effort zeroize: scalars are Copy in curve25519-dalek so prior
    // copies on the stack/registers cannot be guaranteed cleared, but we
    // clear the current bindings so heap traces are reduced.
    alpha.zeroize();
    x.zeroize();
    for sc in s.iter_mut() {
        sc.zeroize();
    }

    Ok((sig, ki))
}

// ─── Verify ───────────────────────────────────────────────────────────────────

/// Verify an LSAG ring signature.
pub fn verify(
    message: &[u8],
    ring_pubkeys: &[[u8; 32]],
    sig: &RingSignature,
) -> bool {
    let n = ring_pubkeys.len();
    if n < 2 || sig.s.len() != n { return false; }

    // Decompress
    let pubkeys: Vec<Point> = match ring_pubkeys
        .iter()
        .map(|pk| decompress_point(pk))
        .collect::<Option<Vec<_>>>()
    {
        Some(p) => p,
        None => return false,
    };

    let key_image = match decompress_point(&sig.key_image) {
        Some(p) => p,
        None => return false,
    };

    let s: Vec<Scalar> = match sig.s.iter()
        .map(|b| scalar_from_bytes(b))
        .collect::<Option<Vec<_>>>()
    {
        Some(v) => v,
        None => return false,
    };

    let c0 = match scalar_from_bytes(&sig.c0) {
        Some(sc) => sc,
        None => return false,
    };

    // Reject identity key image (would leak nothing but also be malformed).
    // Ristretto guarantees prime-order subgroup, so any non-identity point
    // is a valid key image.
    if key_image == Point::default() {
        return false;
    }

    // Recompute ring
    let mut c = c0;
    for i in 0..n {
        let hp_i = hash_to_point(&ring_pubkeys[i]);
        let l_i = s[i] * G + c * pubkeys[i];
        let r_i = s[i] * hp_i + c * key_image;
        c = hash_challenge(message, &l_i, &r_i);
    }

    // Ring closes iff c == c0
    c == c0
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    // Scalar::from_canonical_bytes returns CtOption
    let opt = Scalar::from_canonical_bytes(*bytes);
    if opt.is_some().into() { Some(opt.unwrap()) } else { None }
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

fn compress_point(p: &Point) -> [u8; 32] {
    *p.compress().as_bytes()
}

fn decompress_point(bytes: &[u8; 32]) -> Option<Point> {
    CompressedRistretto(*bytes).decompress()
}

// ─── Public interface (matches Phase 1 stub) ──────────────────────────────────

/// Sign — public wrapper
pub fn sign_ring(
    message: &[u8],
    ring_members: &[[u8; 32]],
    real_index: usize,
    private_key: &PrivateKey,
) -> Result<(Vec<u8>, KeyImage), String> {
    let (sig, ki) = sign(message, ring_members, real_index, private_key)?;
    Ok((sig.to_bytes(), ki))
}

/// Verify — public wrapper
pub fn verify_ring(
    message: &[u8],
    ring_members: &[[u8; 32]],
    signature_bytes: &[u8],
    _key_image: &KeyImage,
) -> bool {
    match RingSignature::from_bytes(signature_bytes) {
        Ok(sig) => verify(message, ring_members, &sig),
        Err(_) => false,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a random keypair: (private_scalar, public_point_compressed)
    fn gen_keypair() -> (PrivateKey, [u8; 32]) {
        let sk = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) };
        let pk = sk * G;
        let sk_bytes = sk.to_bytes();
        (PrivateKey(sk_bytes), *pk.compress().as_bytes())
    }

    #[test]
    fn test_sign_and_verify_basic() {
        let (sk, pk_real) = gen_keypair();
        let ring: Vec<[u8; 32]> = {
            let mut r = vec![];
            for _ in 0..10 {
                let (_, pk) = gen_keypair();
                r.push(pk);
            }
            r.push(pk_real);
            r
        };
        let real_index = ring.len() - 1;
        let message = b"send 10 CIP";

        let (sig_bytes, ki) = sign_ring(message, &ring, real_index, &sk).unwrap();
        assert!(verify_ring(message, &ring, &sig_bytes, &ki));
    }

    #[test]
    fn test_wrong_message_fails() {
        let (sk, pk_real) = gen_keypair();
        let ring: Vec<[u8; 32]> = {
            let mut r = vec![[0u8; 32]; 10];
            r[5] = pk_real;
            r
        };
        let message = b"send 10 CIP";
        let (sig_bytes, ki) = sign_ring(message, &ring, 5, &sk).unwrap();
        assert!(!verify_ring(b"send 99 CIP", &ring, &sig_bytes, &ki));
    }

    #[test]
    fn test_key_image_deterministic() {
        let (sk, pk_real) = gen_keypair();
        let ring: Vec<[u8; 32]> = {
            let mut r = vec![[0u8; 32]; 10];
            r[3] = pk_real;
            r
        };
        let msg = b"tx";
        let (_, ki1) = sign_ring(msg, &ring, 3, &sk).unwrap();
        let (_, ki2) = sign_ring(b"different msg", &ring, 3, &sk).unwrap();
        // Key image must be the same regardless of message (same key = same image)
        assert_eq!(ki1.0, ki2.0);
    }

    #[test]
    fn test_different_keys_different_images() {
        let (sk1, pk1) = gen_keypair();
        let (sk2, pk2) = gen_keypair();
        let mut ring = vec![[0u8; 32]; 10];
        ring[0] = pk1;
        ring[1] = pk2;

        let (_, ki1) = sign_ring(b"msg", &ring, 0, &sk1).unwrap();
        let (_, ki2) = sign_ring(b"msg", &ring, 1, &sk2).unwrap();
        assert_ne!(ki1.0, ki2.0);
    }

    #[test]
    fn test_ring_too_small_fails() {
        let (sk, pk) = gen_keypair();
        let result = sign_ring(b"msg", &[pk], 0, &sk);
        assert!(result.is_err());
    }
}
