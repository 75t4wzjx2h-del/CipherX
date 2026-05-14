// CipherX — EVM Precompiles (Phase 5)
//
// Custom precompiled contracts at fixed addresses.
// Called from Solidity like regular contracts but execute native Rust code.
//
// Address map:
//   0x01–0x09 : Standard Ethereum precompiles (ecrecover, sha256, etc.)
//   0x100     : RING_SIG_VERIFY  — verify MLSAG ring signature
//   0x101     : ZK_VERIFY        — verify Groth16 stake proof
//   0x102     : STEALTH_DERIVE   — derive stealth output key
//   0x103     : PEDERSEN_COMMIT  — commit to a value
//   0x104     : BULLETPROOF_VFY  — verify range proof
//   0x105     : NULLIFIER_CHECK  — check if nullifier is spent
//   0x106     : VIEW_KEY_SCAN    — scan output with view key
//
// Usage in Solidity:
//   // Verify a ring signature
//   (bool ok) = address(0x100).call(abi.encode(message, ring_members, signature));

use sha3::{Keccak256, Digest};

use crate::crypto::ring_sig::verify_ring;
use crate::crypto::ringct::verify_range;
use crate::core::transaction::{PedersenCommitment, Bulletproof, KeyImage};
use super::gas::GasCost;

// ─── Precompile addresses ─────────────────────────────────────────────────────

pub const ADDR_RING_SIG_VERIFY:  u64 = 0x100;
pub const ADDR_ZK_VERIFY:        u64 = 0x101;
pub const ADDR_STEALTH_DERIVE:   u64 = 0x102;
pub const ADDR_PEDERSEN_COMMIT:  u64 = 0x103;
pub const ADDR_BULLETPROOF_VFY:  u64 = 0x104;
pub const ADDR_NULLIFIER_CHECK:  u64 = 0x105;
pub const ADDR_VIEW_KEY_SCAN:    u64 = 0x106;

// ─── Precompile result ────────────────────────────────────────────────────────

pub struct PrecompileResult {
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub success: bool,
}

impl PrecompileResult {
    fn ok(output: Vec<u8>, gas: u64) -> Self {
        PrecompileResult { output, gas_used: gas, success: true }
    }
    fn err(gas: u64) -> Self {
        PrecompileResult { output: vec![0u8; 32], gas_used: gas, success: false }
    }
}

// ─── Precompile dispatcher ────────────────────────────────────────────────────

/// Dispatch a call to a CipherX precompile
pub fn call_precompile(
    address: u64,
    input: &[u8],
    gas_limit: u64,
) -> Option<PrecompileResult> {
    match address {
        ADDR_RING_SIG_VERIFY  => Some(precompile_ring_sig_verify(input, gas_limit)),
        ADDR_ZK_VERIFY        => Some(precompile_zk_verify(input, gas_limit)),
        ADDR_STEALTH_DERIVE   => Some(precompile_stealth_derive(input, gas_limit)),
        ADDR_PEDERSEN_COMMIT  => Some(precompile_pedersen_commit(input, gas_limit)),
        ADDR_BULLETPROOF_VFY  => Some(precompile_bulletproof_verify(input, gas_limit)),
        ADDR_NULLIFIER_CHECK  => Some(precompile_nullifier_check(input, gas_limit)),
        ADDR_VIEW_KEY_SCAN    => Some(precompile_view_key_scan(input, gas_limit)),
        _ => None,
    }
}

// ─── 0x100: Ring signature verification ──────────────────────────────────────
//
// Input ABI (packed):
//   bytes32 message
//   uint32  ring_size
//   bytes32[ring_size] ring_members
//   bytes   signature
//   bytes32 key_image
//
// Output:
//   bool valid (as uint256)

fn precompile_ring_sig_verify(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::RING_SIG_VERIFY;
    if gas > gas_limit || input.len() < 68 {
        return PrecompileResult::err(gas);
    }

    // Parse input
    let message: [u8; 32] = match input[0..32].try_into() {
        Ok(m) => m, Err(_) => return PrecompileResult::err(gas),
    };
    let ring_size = u32::from_be_bytes(input[32..36].try_into().unwrap_or([0;4])) as usize;

    if input.len() < 36 + ring_size * 32 + 32 {
        return PrecompileResult::err(gas);
    }

    let mut ring_members = vec![[0u8; 32]; ring_size];
    for i in 0..ring_size {
        let start = 36 + i * 32;
        ring_members[i] = input[start..start + 32].try_into().unwrap_or([0u8; 32]);
    }

    let sig_offset = 36 + ring_size * 32;
    let ki_offset = sig_offset;

    // For this precompile we need at least key_image at end
    if input.len() < ki_offset + 32 {
        return PrecompileResult::err(gas);
    }

    let key_image_bytes: [u8; 32] = input[input.len() - 32..].try_into().unwrap_or([0u8; 32]);
    let key_image = KeyImage(key_image_bytes);

    let signature = &input[sig_offset..input.len() - 32];

    let valid = verify_ring(&message, &ring_members, signature, &key_image);

    // Return bool as uint256 (EVM convention)
    let mut output = vec![0u8; 32];
    if valid { output[31] = 1; }

    PrecompileResult::ok(output, gas)
}

// ─── 0x101: ZK stake proof verification ──────────────────────────────────────
//
// Input ABI:
//   bytes32 nullifier
//   uint64  epoch
//   bytes   proof_bytes
//
// Output:
//   bool valid

fn precompile_zk_verify(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::ZK_VERIFY;
    if gas > gas_limit || input.len() < 40 {
        return PrecompileResult::err(gas);
    }

    let _nullifier: [u8; 32] = input[0..32].try_into().unwrap_or([0u8; 32]);
    let _epoch = u64::from_be_bytes(input[32..40].try_into().unwrap_or([0u8; 8]));
    let proof_bytes = &input[40..];

    // zk module removed; stub returns true if proof bytes non-empty
    let valid = !proof_bytes.is_empty();

    let mut output = vec![0u8; 32];
    if valid { output[31] = 1; }
    PrecompileResult::ok(output, gas)
}

// ─── 0x102: Stealth key derivation ───────────────────────────────────────────
//
// Input:
//   bytes32 tx_pubkey (R)
//   bytes32 spend_pubkey (B_spend)
//   bytes32 view_pubkey (B_view)
//   uint32  output_index
//
// Output:
//   bytes32 one_time_pubkey

fn precompile_stealth_derive(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::STEALTH_SCAN;
    if gas > gas_limit || input.len() < 100 {
        return PrecompileResult::err(gas);
    }

    // Parse
    let _tx_pubkey: [u8; 32]    = input[0..32].try_into().unwrap_or([0u8; 32]);
    let _spend_pubkey: [u8; 32] = input[32..64].try_into().unwrap_or([0u8; 32]);
    let _view_pubkey: [u8; 32]  = input[64..96].try_into().unwrap_or([0u8; 32]);
    let _output_index = u32::from_be_bytes(input[96..100].try_into().unwrap_or([0u8; 4]));

    // TODO: call stealth::generate_output_key (Phase 5 integration)
    // For now: return deterministic hash of inputs
    let mut h = Keccak256::new();
    h.update(&input[..100]);
    let output = h.finalize().to_vec();

    PrecompileResult::ok(output, gas)
}

// ─── 0x103: Pedersen commitment ──────────────────────────────────────────────
//
// Input:
//   uint64  amount
//   bytes32 blinding
//
// Output:
//   bytes32 commitment

fn precompile_pedersen_commit(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::PEDERSEN_COMMIT;
    if gas > gas_limit || input.len() < 40 {
        return PrecompileResult::err(gas);
    }

    let amount = u64::from_be_bytes(input[0..8].try_into().unwrap_or([0u8; 8]));
    let blinding: [u8; 32] = input[8..40].try_into().unwrap_or([0u8; 32]);

    match crate::crypto::ringct::commit(amount, &blinding) {
        Some(commitment) => PrecompileResult::ok(commitment.0.to_vec(), gas),
        None => PrecompileResult::err(gas),
    }
}

// ─── 0x104: Bulletproof verification ─────────────────────────────────────────
//
// Input:
//   bytes32 commitment
//   bytes   proof
//
// Output:
//   bool valid

fn precompile_bulletproof_verify(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::BULLETPROOF_VFY;
    if gas > gas_limit || input.len() < 32 {
        return PrecompileResult::err(gas);
    }

    let commitment_bytes: [u8; 32] = input[0..32].try_into().unwrap_or([0u8; 32]);
    let proof_bytes = input[32..].to_vec();

    let commitment = PedersenCommitment(commitment_bytes);
    let proof = Bulletproof(proof_bytes);

    let valid = verify_range(&commitment, &proof);
    let mut output = vec![0u8; 32];
    if valid { output[31] = 1; }
    PrecompileResult::ok(output, gas)
}

// ─── 0x105: Nullifier check ───────────────────────────────────────────────────
//
// Input:
//   bytes32 nullifier
//
// Output:
//   bool is_spent

fn precompile_nullifier_check(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::SLOAD;
    if gas > gas_limit || input.len() < 32 {
        return PrecompileResult::err(gas);
    }

    // In production: check against chain's spent nullifier set
    // For now: return false (not spent) — chain state lookup done in executor
    let mut output = vec![0u8; 32];
    output[31] = 0; // not spent
    PrecompileResult::ok(output, gas)
}

// ─── 0x106: View key scan ─────────────────────────────────────────────────────
//
// Input:
//   bytes32 tx_pubkey
//   bytes32 output_pubkey
//   bytes32 view_key
//   bytes32 spend_pubkey
//   uint32  output_index
//
// Output:
//   bool    is_mine
//   bytes32 s_i (if mine — for spend key derivation)

fn precompile_view_key_scan(input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas = GasCost::STEALTH_SCAN;
    if gas > gas_limit || input.len() < 132 {
        return PrecompileResult::err(gas);
    }

    let tx_pubkey: [u8; 32]      = input[0..32].try_into().unwrap_or([0u8; 32]);
    let output_pubkey: [u8; 32]  = input[32..64].try_into().unwrap_or([0u8; 32]);
    let view_key_bytes: [u8; 32] = input[64..96].try_into().unwrap_or([0u8; 32]);
    let spend_pubkey: [u8; 32]   = input[96..128].try_into().unwrap_or([0u8; 32]);
    let output_index = u32::from_be_bytes(input[128..132].try_into().unwrap_or([0u8; 4]));

    let view_key = crate::crypto::keys::ViewKey(view_key_bytes);
    let spend_pk = crate::crypto::keys::PublicKey(spend_pubkey);

    match crate::crypto::stealth::scan_output(
        &tx_pubkey,
        &output_pubkey,
        output_index,
        &view_key,
        &spend_pk,
    ) {
        Some(s_i) => {
            let mut output = vec![0u8; 64];
            output[31] = 1;        // is_mine = true
            output[32..64].copy_from_slice(&s_i);
            PrecompileResult::ok(output, gas)
        }
        None => {
            let mut output = vec![0u8; 64];
            output[31] = 0;        // is_mine = false
            PrecompileResult::ok(output, gas)
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_precompile() {
        let amount: u64 = 1_000_000_000; // 1 CIP
        let blinding = [7u8; 32];
        let mut input = vec![0u8; 40];
        input[0..8].copy_from_slice(&amount.to_be_bytes());
        input[8..40].copy_from_slice(&blinding);

        let result = call_precompile(ADDR_PEDERSEN_COMMIT, &input, GasCost::PEDERSEN_COMMIT * 2);
        assert!(result.is_some());
        let r = result.unwrap();
        assert!(r.success);
        assert_eq!(r.output.len(), 32);
        assert_ne!(r.output, vec![0u8; 32]); // commitment is non-zero
    }

    #[test]
    fn test_pedersen_precompile_oog() {
        let input = vec![0u8; 40];
        let result = call_precompile(ADDR_PEDERSEN_COMMIT, &input, 1); // 1 gas = not enough
        assert!(result.unwrap().success == false);
    }

    #[test]
    fn test_unknown_precompile_returns_none() {
        let result = call_precompile(0x999, &[], 1_000_000);
        assert!(result.is_none());
    }

    #[test]
    fn test_nullifier_check_not_spent() {
        let input = [42u8; 32];
        let result = call_precompile(ADDR_NULLIFIER_CHECK, &input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output[31], 0); // not spent
    }

    #[test]
    fn test_ring_sig_verify_precompile_bad_input() {
        // Input too short → should fail gracefully
        let result = call_precompile(ADDR_RING_SIG_VERIFY, &[0u8; 10], 1_000_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_bulletproof_precompile_invalid_proof() {
        let mut input = vec![0u8; 64];
        // Zero commitment + empty proof → should fail verify
        let result = call_precompile(ADDR_BULLETPROOF_VFY, &input, 1_000_000).unwrap();
        assert!(result.success); // precompile succeeded
        assert_eq!(result.output[31], 0); // but proof is invalid
    }

    #[test]
    fn test_view_key_scan_precompile() {
        use crate::crypto::stealth::{generate_keypair, generate_output};

        let recipient = generate_keypair();
        let output_keys = generate_output(&recipient.address, 0).unwrap();

        let mut input = vec![0u8; 132];
        input[0..32].copy_from_slice(&output_keys.tx_pubkey);
        input[32..64].copy_from_slice(&output_keys.one_time_pubkey);
        input[64..96].copy_from_slice(&recipient.private_view.0);
        input[96..128].copy_from_slice(&recipient.public_spend.0);
        // output_index = 0

        let result = call_precompile(ADDR_VIEW_KEY_SCAN, &input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output[31], 1, "Recipient should detect their own output via precompile");
    }
}
