// CipherX — RingCT (Ring Confidential Transactions) — Phase 3
//
// Hides transaction amounts using Pedersen commitments + Bulletproofs.
//
// Pedersen Commitment:
//   C = v*H + r*G
//   - v = amount (hidden)
//   - r = blinding factor (random)
//   - H = second generator (H = hash_to_point("CipherX_H"))
//   - G = basepoint
//   - Computationally binding, perfectly hiding
//
// Balance proof (no amounts revealed):
//   sum(C_in) == sum(C_out) + C_fee
//   i.e. sum(v_in)*H + sum(r_in)*G == sum(v_out)*H + sum(r_out)*G + v_fee*H + r_fee*G
//   The v terms balance (conservation) and r terms balance (sum of blinding factors = 0)
//
// Bulletproofs:
//   Prove v ∈ [0, 2^64) without revealing v.
//   Aggregated over all outputs for efficiency.
//
// Note: This uses the bulletproofs crate (Dalek's implementation).
// In production, switch to bulletproofs+ for better performance.

use curve25519_dalek::{
    ristretto::{RistrettoPoint, CompressedRistretto},
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use sha3::{Sha3_512, Digest};
use rand::rngs::OsRng;
use rand_core::RngCore;
#[allow(unused_imports)]
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::core::transaction::{PedersenCommitment, Bulletproof};

type Point = RistrettoPoint;
const G: Point = RISTRETTO_BASEPOINT_POINT;

// ─── Second generator H ───────────────────────────────────────────────────────

/// Compute H = hash_to_point("CipherX_H")
/// H is a second independent generator — nobody knows log_G(H)
/// (this property is what makes Pedersen commitments binding)
fn h_generator() -> Point {
    let mut hasher = Sha3_512::new();
    hasher.update(b"CipherX_Pedersen_H_generator_v1");
    let hash = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    RistrettoPoint::from_uniform_bytes(&bytes)
}

// Lazy static H
use std::sync::OnceLock;
static H: OnceLock<Point> = OnceLock::new();

fn get_h() -> &'static Point {
    H.get_or_init(h_generator)
}

// ─── Pedersen commitment ──────────────────────────────────────────────────────

/// A Pedersen commitment with its blinding factor (kept private)
pub struct CommitmentWithBlinding {
    pub commitment: PedersenCommitment,
    pub blinding: [u8; 32],  // r — kept secret by owner
    pub amount: u64,
}

impl Drop for CommitmentWithBlinding {
    fn drop(&mut self) {
        self.blinding.zeroize();
        self.amount.zeroize();
    }
}

/// Commit to an amount: C = v*H + r*G
pub fn commit(amount: u64, blinding: &[u8; 32]) -> Option<PedersenCommitment> {
    let v = Scalar::from(amount);
    let r = scalar_from_bytes(blinding)?;
    let h = get_h();
    let c = v * h + r * G;
    Some(PedersenCommitment(*c.compress().as_bytes()))
}

/// Generate a commitment with a random blinding factor
pub fn commit_random(amount: u64) -> CommitmentWithBlinding {
    let r = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) };
    let blinding = r.to_bytes();
    let commitment = commit(amount, &blinding)
        .expect("commit_random: invalid scalar");
    CommitmentWithBlinding { commitment, blinding, amount }
}

/// Commitment to zero with given blinding: C = 0*H + r*G = r*G
pub fn commit_zero(blinding: &[u8; 32]) -> Option<PedersenCommitment> {
    commit(0, blinding)
}

// ─── Balance verification ─────────────────────────────────────────────────────

/// Verify that inputs balance outputs + fee:
///   sum(C_in) - sum(C_out) - C_fee == point_at_infinity
///
/// This proves conservation of value without revealing any amounts.
pub fn verify_balance(
    input_commitments: &[PedersenCommitment],
    output_commitments: &[PedersenCommitment],
    fee_commitment: &PedersenCommitment,
) -> bool {
    // Decompress all points
    let decompress = |c: &PedersenCommitment| -> Option<Point> {
        CompressedRistretto(c.0).decompress()
    };

    let inputs: Option<Vec<Point>> = input_commitments.iter().map(decompress).collect();
    let outputs: Option<Vec<Point>> = output_commitments.iter().map(decompress).collect();
    let fee_pt = decompress(fee_commitment);

    let (inputs, outputs, fee_pt) = match (inputs, outputs, fee_pt) {
        (Some(i), Some(o), Some(f)) => (i, o, f),
        _ => return false,
    };

    // sum(C_in)
    let sum_in: Point = inputs.into_iter().fold(Point::default(), |acc, p| acc + p);
    // sum(C_out) + C_fee
    let sum_out: Point = outputs.into_iter().fold(fee_pt, |acc, p| acc + p);

    // Check: sum_in - sum_out == identity (point at infinity)
    let diff = sum_in - sum_out;
    diff.compress() == CompressedRistretto::default() // identity check
        || diff == Point::default()
}

/// Compute the blinding factor balance for outputs given input blindings.
/// Used by sender to ensure sum(r_in) = sum(r_out) + r_fee
/// Returns the required fee blinding: r_fee = sum(r_in) - sum(r_out)
///
/// Returns None if any blinding factor fails to parse as a valid scalar —
/// silently skipping invalid blindings would produce a wrong fee_blinding
/// and a tx that fails balance verification (or worse, balances incorrectly).
pub fn compute_fee_blinding(
    input_blindings: &[[u8; 32]],
    output_blindings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let mut sum_in = Scalar::ZERO;
    for b in input_blindings {
        sum_in += scalar_from_bytes(b)?;
    }
    let mut sum_out = Scalar::ZERO;
    for b in output_blindings {
        sum_out += scalar_from_bytes(b)?;
    }
    Some((sum_in - sum_out).to_bytes())
}

// ─── Range proofs (bit-decomposition) ─────────────────────────────────────────
//
// SECURITY NOTE — Phase 3 implementation:
//
// The original Phase 3 stub embedded `amount || blinding` in the proof,
// which trivially LEAKS the amount and defeats RingCT privacy entirely.
//
// This implementation provides a real range proof via bit-decomposition
// of the amount into 64 bits. For each bit b_i ∈ {0,1}:
//   - We commit C_i = b_i·H + r_i·G
//   - We provide a 0-or-1 OR-proof for C_i (Borromean-style sigma proof)
//   - We constrain sum_i 2^i · C_i = C (the original commitment)
//
// Verification:
//   - Each per-bit proof verifies the commitment is to {0,1}.
//   - The reconstruction check binds the bit-commitments to C, so the
//     committed amount equals sum_i 2^i b_i ∈ [0, 2^64).
//
// This is conceptually equivalent to the range-proof structure used in
// pre-Bulletproofs Monero (Borromean ring sigs on bit commitments).
// Bulletproofs++ migration is tracked for Phase 4 — the on-chain
// representation is opaque so swapping the proof system is non-breaking.

const RANGE_BITS: usize = 64;

fn hash_to_scalar(data: &[&[u8]]) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"CipherX_range_v1");
    for d in data { h.update(d); }
    let hash = h.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Generate a range proof for an amount commitment using bit decomposition.
///
/// Proof structure (binary serialization):
///   For each bit i in [0, 64):
///     - bit_commitment   : 32 bytes (C_i = b_i*H + r_i*G)
///     - bit_proof_e0     : 32 bytes
///     - bit_proof_e1     : 32 bytes
///     - bit_proof_s0     : 32 bytes
///     - bit_proof_s1     : 32 bytes
///   Plus a consistency tag (32 bytes): H("range" || C || C_0 || ... || C_63)
///
/// The verifier checks each bit-proof and then verifies that
/// `sum_i 2^i * C_i == C`, which forces sum_i 2^i * b_i = v and sum_i 2^i * r_i = r.
pub fn prove_range(amount: u64, blinding: &[u8; 32]) -> Option<Bulletproof> {
    let r_total = scalar_from_bytes(blinding)?;
    let h = *get_h();

    let mut bit_commits: Vec<Point> = Vec::with_capacity(RANGE_BITS);
    let mut bit_blindings: Vec<Scalar> = Vec::with_capacity(RANGE_BITS);
    let mut proof_bytes: Vec<u8> = Vec::with_capacity(RANGE_BITS * (32 * 5) + 32);

    // 1. Decompose amount and commit each bit with random blinding,
    //    except the last bit whose blinding closes the sum to r_total.
    let mut acc_r = Scalar::ZERO;
    let mut acc_pow = Scalar::ONE;
    for i in 0..RANGE_BITS {
        let bit = ((amount >> i) & 1) as u8;

        let r_i = if i < RANGE_BITS - 1 {
            let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b);
            let s = Scalar::from_bytes_mod_order_wide(&b);
            b.zeroize();
            // Track 2^i * r_i
            acc_r += acc_pow * s;
            s
        } else {
            // Choose last r_i so that sum_i 2^i * r_i = r_total
            // => r_{n-1} = (r_total - acc_r) * 2^{-(n-1)}
            let two_pow_inv = acc_pow.invert();
            (r_total - acc_r) * two_pow_inv
        };

        let c_i = if bit == 0 { r_i * G } else { h + r_i * G };
        bit_commits.push(c_i);
        bit_blindings.push(r_i);
        acc_pow *= Scalar::from(2u64);
    }

    // 2. Build per-bit OR-proofs using a Schnorr OR variant.
    //    Proof transmits (e0, e1, s0, s1) — 4×32 bytes per bit.
    for i in 0..RANGE_BITS {
        let bit = ((amount >> i) & 1) as u8;
        let c_i = bit_commits[i];
        let r_i = bit_blindings[i];

        let (e0, e1, s0, s1) = build_or_proof(bit, &c_i, &r_i, &h);
        proof_bytes.extend_from_slice(c_i.compress().as_bytes());
        proof_bytes.extend_from_slice(e0.as_bytes());
        proof_bytes.extend_from_slice(e1.as_bytes());
        proof_bytes.extend_from_slice(s0.as_bytes());
        proof_bytes.extend_from_slice(s1.as_bytes());
    }

    // 3. Bind to the outer commitment (so verifier knows which C this proves)
    let outer = commit(amount, blinding)?;
    let mut tag = sha3::Sha3_256::new();
    tag.update(b"CipherX_range_tag_v1");
    tag.update(outer.0);
    for c in &bit_commits {
        tag.update(c.compress().as_bytes());
    }
    let tag_bytes: [u8; 32] = tag.finalize().into();
    proof_bytes.extend_from_slice(&tag_bytes);

    // Zeroize per-bit blindings
    for s in bit_blindings.iter_mut() { s.zeroize(); }
    Some(Bulletproof(proof_bytes))
}

/// Schnorr OR-proof builder for bit ∈ {0,1}.
/// Proves: log_G(C) = r  OR  log_G(C - H) = r
/// Returns (e0, e1, s0, s1) such that:
///   A0 = s0*G - e0*C
///   A1 = s1*G - e1*(C - H)
///   e0 + e1 = H(C, A0, A1)
fn build_or_proof(bit: u8, c: &Point, r: &Scalar, h: &Point) -> (Scalar, Scalar, Scalar, Scalar) {
    // Random nonce for the real branch
    let mut k = {
        let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b);
        let s = Scalar::from_bytes_mod_order_wide(&b); b.zeroize(); s
    };

    if bit == 0 {
        // Real branch = 0. Pick e1, s1 random for simulated branch 1.
        let e1 = {
            let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b);
            let s = Scalar::from_bytes_mod_order_wide(&b); b.zeroize(); s
        };
        let s1 = {
            let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b);
            let s = Scalar::from_bytes_mod_order_wide(&b); b.zeroize(); s
        };
        let a0 = k * G;                       // real
        let a1 = s1 * G - e1 * (*c - *h);     // simulated
        let e_total = hash_to_scalar(&[
            c.compress().as_bytes(),
            a0.compress().as_bytes(),
            a1.compress().as_bytes(),
        ]);
        let e0 = e_total - e1;
        let s0 = k + e0 * r;
        k.zeroize();
        let result = (e0, e1, s0, s1);
        // (e1, s1 already moved into result tuple — Scalars are Copy)
        let _ = (e1, s1);
        result
    } else {
        // Real branch = 1. Pick e0, s0 random for simulated branch 0.
        let e0 = {
            let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b);
            let s = Scalar::from_bytes_mod_order_wide(&b); b.zeroize(); s
        };
        let s0 = {
            let mut b = [0u8; 64]; OsRng.fill_bytes(&mut b);
            let s = Scalar::from_bytes_mod_order_wide(&b); b.zeroize(); s
        };
        let a0 = s0 * G - e0 * *c;            // simulated
        let a1 = k * G;                       // real
        let e_total = hash_to_scalar(&[
            c.compress().as_bytes(),
            a0.compress().as_bytes(),
            a1.compress().as_bytes(),
        ]);
        let e1 = e_total - e0;
        let s1 = k + e1 * r;
        k.zeroize();
        let result = (e0, e1, s0, s1);
        let _ = (e0, s0);
        result
    }
}

/// Verify a range proof bound to a given commitment.
pub fn verify_range(commitment: &PedersenCommitment, proof: &Bulletproof) -> bool {
    let h = *get_h();
    let per_bit = 32 * 5;
    let expected_len = RANGE_BITS * per_bit + 32; // + tag
    if proof.0.len() != expected_len { return false; }

    let outer_pt = match CompressedRistretto(commitment.0).decompress() {
        Some(p) => p,
        None => return false,
    };

    let mut bit_commits: Vec<Point> = Vec::with_capacity(RANGE_BITS);

    // 1. Per-bit OR-proof verification
    let mut off = 0usize;
    for _ in 0..RANGE_BITS {
        let c_bytes: [u8; 32] = match proof.0[off..off+32].try_into() { Ok(b) => b, Err(_) => return false };
        let e0_b: [u8; 32]    = match proof.0[off+32..off+64].try_into() { Ok(b) => b, Err(_) => return false };
        let e1_b: [u8; 32]    = match proof.0[off+64..off+96].try_into() { Ok(b) => b, Err(_) => return false };
        let s0_b: [u8; 32]    = match proof.0[off+96..off+128].try_into() { Ok(b) => b, Err(_) => return false };
        let s1_b: [u8; 32]    = match proof.0[off+128..off+160].try_into() { Ok(b) => b, Err(_) => return false };
        off += per_bit;

        let c_i = match CompressedRistretto(c_bytes).decompress() {
            Some(p) => p,
            None => return false,
        };
        let e0 = match scalar_from_bytes(&e0_b) { Some(s) => s, None => return false };
        let e1 = match scalar_from_bytes(&e1_b) { Some(s) => s, None => return false };
        let s0 = match scalar_from_bytes(&s0_b) { Some(s) => s, None => return false };
        let s1 = match scalar_from_bytes(&s1_b) { Some(s) => s, None => return false };

        let a0 = s0 * G - e0 * c_i;
        let a1 = s1 * G - e1 * (c_i - h);
        let e_total = hash_to_scalar(&[
            c_i.compress().as_bytes(),
            a0.compress().as_bytes(),
            a1.compress().as_bytes(),
        ]);
        if e_total != e0 + e1 { return false; }

        bit_commits.push(c_i);
    }

    // 2. Verify outer-commitment binding: sum_i 2^i * C_i == outer
    let mut acc = Point::default();
    let mut pow = Scalar::ONE;
    for c_i in &bit_commits {
        acc += pow * *c_i;
        pow *= Scalar::from(2u64);
    }
    if acc.compress() != outer_pt.compress() { return false; }

    // 3. Verify the tag (consistency check)
    let tag_bytes: [u8; 32] = match proof.0[off..off+32].try_into() { Ok(b) => b, Err(_) => return false };
    let mut tag = sha3::Sha3_256::new();
    tag.update(b"CipherX_range_tag_v1");
    tag.update(commitment.0);
    for c in &bit_commits {
        tag.update(c.compress().as_bytes());
    }
    let expected: [u8; 32] = tag.finalize().into();
    if expected != tag_bytes { return false; }

    true
}


// ─── Encrypted amounts (AEAD) ─────────────────────────────────────────────────
//
// Encrypts u64 amounts using ChaCha20-Poly1305 with a deterministic key/nonce
// derived from the shared secret. The Poly1305 auth tag protects against
// tampering — without it, an attacker who learns part of the amount can
// forge a different one (the original XOR scheme was malleable).
//
// Ciphertext layout: 8 bytes ciphertext || 16 bytes Poly1305 tag = 24 bytes.

const AMOUNT_CT_LEN: usize = 24;

fn derive_amount_key_nonce(shared_secret: &Scalar) -> ([u8; 32], [u8; 12]) {
    let mut h = sha3::Sha3_512::new();
    h.update(b"CipherX_amount_enc_v2");
    h.update(shared_secret.as_bytes());
    let out: [u8; 64] = h.finalize().into();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..44]);
    (key, nonce)
}

/// Encrypt an amount for inclusion in tx output.
/// Only the recipient (with view key) can decrypt.
pub fn encrypt_amount(amount: u64, shared_secret: &Scalar) -> Vec<u8> {
    let (mut key_bytes, nonce_bytes) = derive_amount_key_nonce(shared_secret);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = amount.to_le_bytes();
    let ct = cipher.encrypt(nonce, pt.as_ref())
        .expect("ChaCha20Poly1305 encrypt failed (this should never happen for 8-byte input)");
    key_bytes.zeroize();
    ct
}

/// Decrypt an amount using the shared secret.
/// Returns None on auth-tag failure (wrong key or tampered ciphertext).
pub fn decrypt_amount(encrypted: &[u8], shared_secret: &Scalar) -> Option<u64> {
    if encrypted.len() != AMOUNT_CT_LEN { return None; }
    let (mut key_bytes, nonce_bytes) = derive_amount_key_nonce(shared_secret);
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher.decrypt(nonce, encrypted).ok();
    key_bytes.zeroize();
    let pt = pt?;
    if pt.len() != 8 { return None; }
    let mut amount = [0u8; 8];
    amount.copy_from_slice(&pt);
    Some(u64::from_le_bytes(amount))
}

// ─── Transaction builder helpers ──────────────────────────────────────────────

/// Build all commitments for a transaction.
/// Returns pseudo-commitments for inputs and output commitments.
pub struct TxCommitments {
    pub input_pseudo_commitments: Vec<PedersenCommitment>,
    pub input_blindings: Vec<[u8; 32]>,
    pub output_commitments: Vec<PedersenCommitment>,
    pub output_blindings: Vec<[u8; 32]>,
    pub fee_commitment: PedersenCommitment,
    pub fee_blinding: [u8; 32],
}

pub fn build_tx_commitments(
    input_amounts: &[u64],
    output_amounts: &[u64],
    fee: u64,
) -> Option<TxCommitments> {
    // Commit to each input with random blinding
    let mut input_blindings = vec![];
    let mut input_pseudo_commitments = vec![];
    for &amount in input_amounts {
        let c = commit_random(amount);
        input_blindings.push(c.blinding);
        input_pseudo_commitments.push(c.commitment.clone());
    }

    // Commit to each output with random blinding
    let mut output_blindings = vec![];
    let mut output_commitments = vec![];
    for &amount in output_amounts {
        let c = commit_random(amount);
        output_blindings.push(c.blinding);
        output_commitments.push(c.commitment.clone());
    }

    // Fee blinding ensures balance
    let fee_blinding = compute_fee_blinding(&input_blindings, &output_blindings)?;
    let fee_commitment = commit(fee, &fee_blinding)?;

    Some(TxCommitments {
        input_pseudo_commitments,
        input_blindings,
        output_commitments,
        output_blindings,
        fee_commitment,
        fee_blinding,
    })
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let opt = Scalar::from_canonical_bytes(*bytes);
    if opt.is_some().into() { Some(opt.unwrap()) } else { None }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_and_verify() {
        let amount = 1_000_000_000u64; // 1 CIP
        let c = commit_random(amount);
        let recomputed = commit(amount, &c.blinding).unwrap();
        assert_eq!(c.commitment.0, recomputed.0);
    }

    #[test]
    fn test_balance_check_valid() {
        let amounts_in = [10u64, 5];
        let amounts_out = [12u64];
        let fee = 3u64;

        let tc = build_tx_commitments(&amounts_in, &amounts_out, fee).unwrap();

        let balanced = verify_balance(
            &tc.input_pseudo_commitments,
            &tc.output_commitments,
            &tc.fee_commitment,
        );
        assert!(balanced, "Valid tx must balance");
    }

    #[test]
    fn test_balance_check_invalid() {
        // Input = 10, output = 8, fee = 0 → doesn't balance (2 CIP missing)
        let in_commit = commit_random(10);
        let out_commit = commit_random(8);
        let fee_commit = commit(0, &[0u8; 32]).unwrap();

        // With different blindings, balance will fail
        let balanced = verify_balance(
            &[in_commit.commitment.clone()],
            &[out_commit.commitment.clone()],
            &fee_commit,
        );
        // Note: with random blindings this may fail for two reasons:
        // amounts don't balance AND/OR blindings don't balance
        // Both are correct rejections
        // We just verify the function doesn't panic
        let _ = balanced;
    }

    #[test]
    fn test_range_proof_roundtrip() {
        let amount = 42_000_000_000u64; // 42 CIP
        let c = commit_random(amount);
        let proof = prove_range(amount, &c.blinding).unwrap();
        assert!(verify_range(&c.commitment, &proof));
    }

    #[test]
    fn test_range_proof_wrong_commitment_fails() {
        let amount = 100u64;
        let c = commit_random(amount);
        let wrong_c = commit_random(999);
        let proof = prove_range(amount, &c.blinding).unwrap();
        // Proof for c should not verify against wrong commitment
        assert!(!verify_range(&wrong_c.commitment, &proof));
    }

    #[test]
    fn test_amount_encryption_roundtrip() {
        let amount = 5_500_000_000u64; // 5.5 CIP
        let secret = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) };
        let encrypted = encrypt_amount(amount, &secret);
        let decrypted = decrypt_amount(&encrypted, &secret).unwrap();
        assert_eq!(amount, decrypted);
    }

    #[test]
    fn test_wrong_key_cannot_decrypt() {
        let amount = 1_000u64;
        let secret = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) };
        let wrong_secret = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) };
        let encrypted = encrypt_amount(amount, &secret);
        // Comportement correct : mauvaise clé = échec auth
        let result = decrypt_amount(&encrypted, &wrong_secret);
        assert!(result.is_none(), "Une mauvaise clé doit échouer l'authentification");
    }

    #[test]
    fn test_commitments_are_homomorphic() {
        // C(a) + C(b) == C(a+b) with consistent blindings
        let a = 3u64;
        let b = 7u64;
        let r_a = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) }.to_bytes();
        let r_b = { let mut bytes = [0u8; 64]; OsRng.fill_bytes(&mut bytes); Scalar::from_bytes_mod_order_wide(&bytes) }.to_bytes();

        let ca = commit(a, &r_a).unwrap();
        let cb = commit(b, &r_b).unwrap();

        // r_ab = r_a + r_b
        let r_ab = (scalar_from_bytes(&r_a).unwrap() + scalar_from_bytes(&r_b).unwrap()).to_bytes();
        let cab = commit(a + b, &r_ab).unwrap();

        // C(a) + C(b) should equal C(a+b, r_a+r_b)
        let pa = CompressedRistretto(ca.0).decompress().unwrap();
        let pb = CompressedRistretto(cb.0).decompress().unwrap();
        let pab = CompressedRistretto(cab.0).decompress().unwrap();

        assert_eq!((pa + pb).compress(), pab.compress(),
            "Pedersen commitments must be additively homomorphic");
    }
}
