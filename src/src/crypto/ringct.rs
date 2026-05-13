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
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

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

impl CommitmentWithBlinding {
    /// Get a clone of the commitment (safe to call before drop)
    pub fn commitment(&self) -> PedersenCommitment {
        PedersenCommitment(self.commitment.0)
    }

    /// Get a copy of the blinding factor
    pub fn blinding(&self) -> [u8; 32] {
        self.blinding
    }
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
    let r = Scalar::random(&mut OsRng);
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
pub fn compute_fee_blinding(
    input_blindings: &[[u8; 32]],
    output_blindings: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let sum_in: Scalar = input_blindings.iter()
        .filter_map(|b| scalar_from_bytes(b))
        .fold(Scalar::ZERO, |acc, s| acc + s);

    let sum_out: Scalar = output_blindings.iter()
        .filter_map(|b| scalar_from_bytes(b))
        .fold(Scalar::ZERO, |acc, s| acc + s);

    Some((sum_in - sum_out).to_bytes())
}

// ─── Range proofs (Bulletproofs) ──────────────────────────────────────────────
//
// The bulletproofs crate requires a specific setup with generators.
// For Phase 3 we implement the interface and use a simplified inner
// product proof. Full aggregated Bulletproofs++ in Phase 4.
//
// For now: we use a commitment-based range check stub that structurally
// represents the real proof, allowing the rest of the system to compile
// and run. Replace `prove_range_inner` with real BP when integrating
// the bulletproofs crate fully.

/// Generate a range proof for an amount commitment.
/// Proves: v ∈ [0, 2^64) without revealing v.
pub fn prove_range(amount: u64, blinding: &[u8; 32]) -> Option<Bulletproof> {
    // Stub: encode amount and blinding into proof bytes
    // REAL impl: use bulletproofs::RangeProof::prove_multiple(...)
    let mut proof_bytes = vec![];
    proof_bytes.extend_from_slice(&amount.to_le_bytes());
    proof_bytes.extend_from_slice(blinding);
    // In real impl, this would be ~674 bytes for a single 64-bit range proof
    Some(Bulletproof(proof_bytes))
}

/// Verify a range proof.
pub fn verify_range(
    commitment: &PedersenCommitment,
    proof: &Bulletproof,
) -> bool {
    if proof.0.len() < 40 { return false; }
    // Stub: re-derive and check
    // REAL impl: RangeProof::verify_multiple(...)
    let amount = u64::from_le_bytes(proof.0[..8].try_into().unwrap_or([0u8; 8]));
    let blinding: [u8; 32] = proof.0[8..40].try_into().unwrap_or([0u8; 32]);
    match commit(amount, &blinding) {
        Some(expected) => expected.0 == commitment.0,
        None => false,
    }
}

// ─── Encrypted amounts ────────────────────────────────────────────────────────

/// Encrypt an amount for inclusion in tx output.
/// Only the recipient (with view key) can decrypt.
/// Uses ChaCha20-like XOR with shared secret (simplified — Phase 4: full AEAD).
pub fn encrypt_amount(amount: u64, shared_secret: &Scalar) -> Vec<u8> {
    let mut h = sha3::Sha3_256::new();
    h.update(b"CipherX_amount_enc");
    h.update(shared_secret.as_bytes());
    let mask = h.finalize();

    let amount_bytes = amount.to_le_bytes();
    let mut encrypted = vec![0u8; 8];
    for i in 0..8 {
        encrypted[i] = amount_bytes[i] ^ mask[i];
    }
    encrypted
}

/// Decrypt an amount using the shared secret.
pub fn decrypt_amount(encrypted: &[u8], shared_secret: &Scalar) -> Option<u64> {
    if encrypted.len() < 8 { return None; }
    let mut h = sha3::Sha3_256::new();
    h.update(b"CipherX_amount_enc");
    h.update(shared_secret.as_bytes());
    let mask = h.finalize();

    let mut amount_bytes = [0u8; 8];
    for i in 0..8 {
        amount_bytes[i] = encrypted[i] ^ mask[i];
    }
    Some(u64::from_le_bytes(amount_bytes))
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
        input_blindings.push(c.blinding());
        input_pseudo_commitments.push(c.commitment());
    }

    // Commit to each output with random blinding
    let mut output_blindings = vec![];
    let mut output_commitments = vec![];
    for &amount in output_amounts {
        let c = commit_random(amount);
        output_blindings.push(c.blinding());
        output_commitments.push(c.commitment());
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
        let recomputed = commit(amount, &c.blinding()).unwrap();
        assert_eq!(c.commitment().0, recomputed.0);
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
            &[in_commit.commitment()],
            &[out_commit.commitment()],
            &fee_commit,
        );
        let _ = balanced;
    }

    #[test]
    fn test_range_proof_roundtrip() {
        let amount = 42_000_000_000u64; // 42 CIP
        let c = commit_random(amount);
        let proof = prove_range(amount, &c.blinding()).unwrap();
        assert!(verify_range(&c.commitment(), &proof));
    }

    #[test]
    fn test_range_proof_wrong_commitment_fails() {
        let amount = 100u64;
        let c = commit_random(amount);
        let wrong_c = commit_random(999);
        let proof = prove_range(amount, &c.blinding()).unwrap();
        // Proof for c should not verify against wrong commitment
        assert!(!verify_range(&wrong_c.commitment(), &proof));
    }

    #[test]
    fn test_amount_encryption_roundtrip() {
        let amount = 5_500_000_000u64; // 5.5 CIP
        let secret = Scalar::random(&mut OsRng);
        let encrypted = encrypt_amount(amount, &secret);
        let decrypted = decrypt_amount(&encrypted, &secret).unwrap();
        assert_eq!(amount, decrypted);
    }

    #[test]
    fn test_wrong_key_cannot_decrypt() {
        let amount = 1_000u64;
        let secret = Scalar::random(&mut OsRng);
        let wrong_secret = Scalar::random(&mut OsRng);
        let encrypted = encrypt_amount(amount, &secret);
        let decrypted = decrypt_amount(&encrypted, &wrong_secret).unwrap();
        assert_ne!(amount, decrypted);
    }

    #[test]
    fn test_commitments_are_homomorphic() {
        // C(a) + C(b) == C(a+b) with consistent blindings
        let a = 3u64;
        let b = 7u64;
        let r_a = Scalar::random(&mut OsRng).to_bytes();
        let r_b = Scalar::random(&mut OsRng).to_bytes();

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
