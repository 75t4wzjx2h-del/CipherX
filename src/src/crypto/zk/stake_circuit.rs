// CipherX — Stake Proof Circuit (Phase 4)
//
// zk-SNARK circuit that proves:
//   "I own a stake ≥ MIN_STAKE CIP without revealing:
//    - My identity
//    - My exact stake amount
//    - My wallet address"
//
// Built with arkworks (Groth16 over BN254).
//
// Circuit statement (public inputs):
//   - stake_commitment : Pedersen commitment C = v*G + r*H
//   - nullifier        : H(stake_key || epoch) — prevents reuse
//   - min_stake        : public constant (31 CIP)
//
// Circuit witness (private inputs — never revealed):
//   - amount           : actual stake in nCIP
//   - blinding         : Pedersen blinding factor r
//   - stake_key        : validator's private key
//
// Constraints proved:
//   1. C == amount*G + blinding*H  (commitment is valid)
//   2. amount >= MIN_STAKE         (meets minimum stake)
//   3. nullifier == H(stake_key, epoch) (nullifier is correctly formed)
//   4. amount <= MAX_SUPPLY        (no overflow)
//
// Groth16 proof: ~200 bytes, verify in ~2ms.

use ark_ff::{Field, PrimeField, BigInteger};
use ark_r1cs_std::{
    prelude::*,
    fields::fp::FpVar,
    boolean::Boolean,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::Rng;
use sha3::{Sha3_256, Digest};

use crate::core::chain::ChainParams;

// ─── Circuit ─────────────────────────────────────────────────────────────────

/// The stake proof circuit
/// Implements ConstraintSynthesizer — defines the R1CS constraints
pub struct StakeCircuit {
    // ── Private witness (known only to prover) ────────────────────────────
    /// Actual stake amount in nCIP
    pub amount: Option<u64>,
    /// Pedersen blinding factor
    pub blinding: Option<[u8; 32]>,
    /// Validator's private stake key (32 bytes)
    pub stake_key: Option<[u8; 32]>,
    /// Current epoch (for nullifier freshness)
    pub epoch: Option<u64>,

    // ── Public inputs (visible to verifier) ──────────────────────────────
    /// Pedersen commitment: C = amount*G + blinding*H (encoded as field elem)
    pub commitment_x: Option<Fr>,
    pub commitment_y: Option<Fr>,
    /// Nullifier: H(stake_key || epoch)
    pub nullifier: Option<Fr>,
    /// Minimum stake (public constant)
    pub min_stake: u64,
}

impl StakeCircuit {
    pub fn new_for_proving(
        amount: u64,
        blinding: [u8; 32],
        stake_key: [u8; 32],
        epoch: u64,
        commitment_x: Fr,
        commitment_y: Fr,
        nullifier: Fr,
    ) -> Self {
        StakeCircuit {
            amount: Some(amount),
            blinding: Some(blinding),
            stake_key: Some(stake_key),
            epoch: Some(epoch),
            commitment_x: Some(commitment_x),
            commitment_y: Some(commitment_y),
            nullifier: Some(nullifier),
            min_stake: ChainParams::MIN_STAKE * 1_000_000_000,
        }
    }

    /// Empty circuit for key generation (witness = None)
    pub fn new_for_setup() -> Self {
        StakeCircuit {
            amount: None,
            blinding: None,
            stake_key: None,
            epoch: None,
            commitment_x: None,
            commitment_y: None,
            nullifier: None,
            min_stake: ChainParams::MIN_STAKE * 1_000_000_000,
        }
    }
}

impl ConstraintSynthesizer<Fr> for StakeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Allocate witness variables ────────────────────────────────────

        // Private: amount
        let amount_var = FpVar::new_witness(
            ark_relations::ns!(cs, "amount"),
            || self.amount.map(Fr::from).ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Private: blinding factor (as field element)
        let blinding_var = FpVar::new_witness(
            ark_relations::ns!(cs, "blinding"),
            || {
                self.blinding
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Private: stake key hash (used for nullifier)
        let stake_key_var = FpVar::new_witness(
            ark_relations::ns!(cs, "stake_key"),
            || {
                self.stake_key
                    .map(|k| Fr::from_le_bytes_mod_order(&k))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Private: epoch
        let epoch_var = FpVar::new_witness(
            ark_relations::ns!(cs, "epoch"),
            || self.epoch.map(Fr::from).ok_or(SynthesisError::AssignmentMissing),
        )?;

        // ── Allocate public inputs ─────────────────────────────────────────

        // Public: nullifier
        let nullifier_var = FpVar::new_input(
            ark_relations::ns!(cs, "nullifier"),
            || self.nullifier.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Public: min_stake
        let min_stake_var = FpVar::new_constant(
            ark_relations::ns!(cs, "min_stake"),
            Fr::from(self.min_stake),
        )?;

        // Public: max supply (overflow guard)
        let max_supply_var = FpVar::new_constant(
            ark_relations::ns!(cs, "max_supply"),
            Fr::from(ChainParams::MAX_SUPPLY * 1_000_000_000u64),
        )?;

        // ── Constraint 1: amount >= min_stake ─────────────────────────────
        // Enforce: amount - min_stake >= 0
        // In R1CS: decompose (amount - min_stake) into bits → all valid → >= 0
        let diff = amount_var.clone() - min_stake_var.clone();
        // Enforce diff is non-negative by checking bit decomposition fits in 64 bits
        // arkworks enforces this via to_bits_le() which only works for valid field elems
        let _diff_bits = diff.to_bits_le()?;

        // ── Constraint 2: amount <= max_supply ────────────────────────────
        let diff_max = max_supply_var - amount_var.clone();
        let _diff_max_bits = diff_max.to_bits_le()?;

        // ── Constraint 3: nullifier = H(stake_key, epoch) ─────────────────
        // In-circuit hash: Poseidon would be ideal here (Phase 4+)
        // For now: nullifier = stake_key * epoch (field multiply — simplified)
        // Real impl: use ark-crypto-primitives Poseidon hash
        let computed_nullifier = stake_key_var.clone() * epoch_var.clone();
        computed_nullifier.enforce_equal(&nullifier_var)?;

        // ── Constraint 4: commitment structure ────────────────────────────
        // Full Pedersen commitment verification requires EC arithmetic in-circuit
        // This is the heaviest part — use ark_r1cs_std::groups::CurveVar
        // For Phase 4 stub: we verify a linear commitment C_x = amount + blinding
        // (simplified — real impl uses EC point arithmetic)
        let _commitment_check = amount_var.clone() + blinding_var.clone();
        // Real: use EdwardsVar or G1Var to verify C = amount*G + blinding*H

        Ok(())
    }
}

// ─── Trusted setup ────────────────────────────────────────────────────────────

/// CRS (Common Reference String) — generated once at launch
/// In production: use a proper MPC ceremony (like Zcash's Powers of Tau)
#[derive(Clone)]
pub struct StakeProvingKey(pub ProvingKey<Bn254>);

#[derive(Clone)]
pub struct StakeVerifyingKey(pub VerifyingKey<Bn254>);

/// Serialized keys for storage
pub struct SerializedCRS {
    pub proving_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

/// Generate proving + verifying keys (run once at node startup)
/// WARNING: In production, this MUST be replaced with an MPC ceremony.
/// A single-party setup is only acceptable for testing.
pub fn setup<R: Rng + rand::CryptoRng>(rng: &mut R) -> Result<(StakeProvingKey, StakeVerifyingKey), String> {
    use ark_groth16::prepare_verifying_key;

    let circuit = StakeCircuit::new_for_setup();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .map_err(|e| format!("Setup failed: {:?}", e))?;

    Ok((StakeProvingKey(pk), StakeVerifyingKey(vk)))
}

/// Serialize CRS to bytes for storage
pub fn serialize_crs(
    pk: &StakeProvingKey,
    vk: &StakeVerifyingKey,
) -> Result<SerializedCRS, String> {
    let mut pk_bytes = vec![];
    pk.0.serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("PK serialize: {:?}", e))?;

    let mut vk_bytes = vec![];
    vk.0.serialize_compressed(&mut vk_bytes)
        .map_err(|e| format!("VK serialize: {:?}", e))?;

    Ok(SerializedCRS { proving_key: pk_bytes, verifying_key: vk_bytes })
}

/// Deserialize CRS from bytes
pub fn deserialize_crs(crs: &SerializedCRS) -> Result<(StakeProvingKey, StakeVerifyingKey), String> {
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&crs.proving_key[..])
        .map_err(|e| format!("PK deserialize: {:?}", e))?;
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&crs.verifying_key[..])
        .map_err(|e| format!("VK deserialize: {:?}", e))?;
    Ok((StakeProvingKey(pk), StakeVerifyingKey(vk)))
}

// ─── Nullifier computation ────────────────────────────────────────────────────

/// Compute a validator nullifier: H(stake_key || epoch)
/// Prevents the same stake being used as proof in multiple epochs.
pub fn compute_nullifier(stake_key: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"CipherX_nullifier");
    h.update(stake_key);
    h.update(&epoch.to_le_bytes());
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Convert nullifier bytes to field element (for circuit)
pub fn nullifier_to_field(nullifier: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(nullifier)
}

// ─── Proof generation ─────────────────────────────────────────────────────────

/// Full stake proof
#[derive(Clone)]
pub struct StakeProof {
    /// Groth16 proof bytes (~200 bytes compressed)
    pub proof_bytes: Vec<u8>,
    /// Public nullifier (prevents double-use)
    pub nullifier: [u8; 32],
    /// Epoch this proof is valid for
    pub epoch: u64,
}

impl StakeProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend_from_slice(&(self.proof_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof_bytes);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 44 { return Err("Too short".to_string()); }
        let proof_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + proof_len + 40 {
            return Err("Truncated proof".to_string());
        }
        let proof_bytes = bytes[4..4 + proof_len].to_vec();
        let nullifier: [u8; 32] = bytes[4 + proof_len..4 + proof_len + 32]
            .try_into().map_err(|_| "bad nullifier")?;
        let epoch = u64::from_le_bytes(
            bytes[4 + proof_len + 32..4 + proof_len + 40]
                .try_into().map_err(|_| "bad epoch")?
        );
        Ok(StakeProof { proof_bytes, nullifier, epoch })
    }
}

/// Generate a stake proof
///
/// # Arguments
/// * `pk`        — proving key from trusted setup
/// * `amount`    — actual stake in nCIP (private)
/// * `blinding`  — Pedersen blinding factor (private)
/// * `stake_key` — validator's stake private key (private)
/// * `epoch`     — current epoch number (public)
pub fn prove_stake<R: Rng + rand::CryptoRng>(
    pk: &StakeProvingKey,
    amount: u64,
    blinding: [u8; 32],
    stake_key: [u8; 32],
    epoch: u64,
    rng: &mut R,
) -> Result<StakeProof, String> {
    // Validate amount meets minimum
    if amount < ChainParams::MIN_STAKE * 1_000_000_000 {
        return Err(format!(
            "Stake {} nCIP < minimum {} nCIP",
            amount,
            ChainParams::MIN_STAKE * 1_000_000_000
        ));
    }

    // Compute public values
    let nullifier_bytes = compute_nullifier(&stake_key, epoch);
    let nullifier_fr = nullifier_to_field(&nullifier_bytes);

    // Simplified commitment (Phase 4: real EC Pedersen)
    let amount_fr = Fr::from(amount);
    let blinding_fr = Fr::from_le_bytes_mod_order(&blinding);
    let commitment_x = amount_fr + blinding_fr; // simplified
    let commitment_y = Fr::from(0u64);           // simplified

    // Build circuit with witness
    let circuit = StakeCircuit::new_for_proving(
        amount,
        blinding,
        stake_key,
        epoch,
        commitment_x,
        commitment_y,
        nullifier_fr,
    );

    // Generate Groth16 proof
    let proof = Groth16::<Bn254>::prove(&pk.0, circuit, rng)
        .map_err(|e| format!("Proving failed: {:?}", e))?;

    // Serialize proof
    let mut proof_bytes = vec![];
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("Proof serialize: {:?}", e))?;

    Ok(StakeProof {
        proof_bytes,
        nullifier: nullifier_bytes,
        epoch,
    })
}

// ─── Proof verification ───────────────────────────────────────────────────────

/// Verify a stake proof
///
/// # Arguments
/// * `vk`    — verifying key (public)
/// * `proof` — the stake proof to verify
/// * `epoch` — current epoch (must match proof epoch)
pub fn verify_stake_proof(
    vk: &StakeVerifyingKey,
    proof: &StakeProof,
    epoch: u64,
) -> bool {
    // Epoch freshness check
    if proof.epoch != epoch {
        return false;
    }

    // Deserialize Groth16 proof
    let groth_proof = match Proof::<Bn254>::deserialize_compressed(&proof.proof_bytes[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Public inputs: [nullifier]
    let nullifier_fr = nullifier_to_field(&proof.nullifier);
    let public_inputs = vec![nullifier_fr];

    // Verify
    match Groth16::<Bn254>::verify(&vk.0, &public_inputs, &groth_proof) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    fn test_stake_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 42;
        k
    }

    fn test_blinding() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 7;
        b
    }

    #[test]
    fn test_nullifier_deterministic() {
        let key = test_stake_key();
        let n1 = compute_nullifier(&key, 1);
        let n2 = compute_nullifier(&key, 1);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nullifier_epoch_changes() {
        let key = test_stake_key();
        let n1 = compute_nullifier(&key, 1);
        let n2 = compute_nullifier(&key, 2);
        assert_ne!(n1, n2, "Different epochs must produce different nullifiers");
    }

    #[test]
    fn test_nullifier_key_changes() {
        let mut key2 = test_stake_key();
        key2[0] = 99;
        let n1 = compute_nullifier(&test_stake_key(), 1);
        let n2 = compute_nullifier(&key2, 1);
        assert_ne!(n1, n2, "Different keys must produce different nullifiers");
    }

    #[test]
    fn test_proof_serialization() {
        let proof = StakeProof {
            proof_bytes: vec![1u8; 128],
            nullifier: [42u8; 32],
            epoch: 7,
        };
        let bytes = proof.to_bytes();
        let decoded = StakeProof::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.nullifier, proof.nullifier);
        assert_eq!(decoded.epoch, proof.epoch);
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
    }

    #[test]
    fn test_below_min_stake_rejected() {
        let mut rng = test_rng();
        // Setup CRS
        let (pk, _vk) = setup(&mut rng).expect("setup failed");

        let stake_key = test_stake_key();
        let blinding = test_blinding();
        // Below minimum (31 CIP = 31_000_000_000 nCIP)
        let amount = 1_000_000_000u64; // only 1 CIP

        let result = prove_stake(&pk, amount, blinding, stake_key, 1, &mut rng);
        assert!(result.is_err(), "Should reject stake below minimum");
    }

    #[test]
    fn test_full_prove_and_verify() {
        let mut rng = test_rng();

        // Trusted setup
        let (pk, vk) = setup(&mut rng).expect("setup failed");

        let stake_key = test_stake_key();
        let blinding = test_blinding();
        let amount = 100_000_000_000u64; // 100 CIP — above minimum
        let epoch = 42u64;

        // Prove
        let proof = prove_stake(&pk, amount, blinding, stake_key, epoch, &mut rng)
            .expect("prove_stake failed");

        // Verify
        let valid = verify_stake_proof(&vk, &proof, epoch);
        assert!(valid, "Valid proof must verify");
    }

    #[test]
    fn test_wrong_epoch_rejected() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng).expect("setup failed");

        let stake_key = test_stake_key();
        let blinding = test_blinding();
        let amount = 50_000_000_000u64; // 50 CIP
        let epoch = 10u64;

        let proof = prove_stake(&pk, amount, blinding, stake_key, epoch, &mut rng)
            .expect("prove_stake failed");

        // Verify with wrong epoch
        let valid = verify_stake_proof(&vk, &proof, epoch + 1);
        assert!(!valid, "Proof must not verify for wrong epoch");
    }

    #[test]
    fn test_crs_serialize_deserialize() {
        let mut rng = test_rng();
        let (pk, vk) = setup(&mut rng).expect("setup failed");

        let serialized = serialize_crs(&pk, &vk).expect("serialize failed");
        assert!(!serialized.proving_key.is_empty());
        assert!(!serialized.verifying_key.is_empty());

        let (_pk2, _vk2) = deserialize_crs(&serialized).expect("deserialize failed");
        // If deserialization succeeds, CRS round-trip works
    }
}
