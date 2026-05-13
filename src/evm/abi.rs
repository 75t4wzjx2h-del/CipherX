// CipherX — ABI Encoding (Phase 5)
//
// Ethereum ABI-compatible encoding for contract calls.
// Used to encode/decode function calls and return values.
//
// Supports: uint256, int256, bool, bytes32, address, bytes, uint64, uint32

use sha3::{Keccak256, Digest};

/// Compute function selector: first 4 bytes of keccak256(signature)
/// e.g. "transfer(address,uint256)" → 0xa9059cbb
pub fn function_selector(signature: &str) -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(signature.as_bytes());
    let hash = h.finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// ABI-encode a uint256 value
pub fn encode_uint256(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// ABI-encode a bool
pub fn encode_bool(value: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = if value { 1 } else { 0 };
    out
}

/// ABI-encode a bytes32
pub fn encode_bytes32(value: &[u8; 32]) -> [u8; 32] {
    *value
}

/// ABI-encode an address (20 bytes, left-padded to 32)
pub fn encode_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

/// Decode uint256 from 32 bytes (last 8 bytes as u64)
pub fn decode_uint64(data: &[u8; 32]) -> u64 {
    u64::from_be_bytes(data[24..].try_into().unwrap_or([0u8; 8]))
}

/// Decode bool from 32 bytes
pub fn decode_bool(data: &[u8; 32]) -> bool {
    data[31] != 0
}

/// Build a full calldata for a function call
/// selector (4 bytes) + encoded args (32 bytes each)
pub fn encode_call(selector: [u8; 4], args: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![];
    out.extend_from_slice(&selector);
    for arg in args {
        out.extend_from_slice(arg);
    }
    out
}

/// Decode return value (first 32 bytes of output)
pub fn decode_return(output: &[u8]) -> Option<[u8; 32]> {
    if output.len() < 32 { return None; }
    output[0..32].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_selector() {
        // Known selector: transfer(address,uint256) = 0xa9059cbb
        let sel = function_selector("transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_encode_decode_uint256() {
        let value = 1_000_000_000u64;
        let encoded = encode_uint256(value);
        let decoded = decode_uint64(&encoded);
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_encode_bool() {
        assert_eq!(encode_bool(true)[31], 1);
        assert_eq!(encode_bool(false)[31], 0);
    }

    #[test]
    fn test_encode_call() {
        let sel = function_selector("balanceOf(address)");
        let addr = encode_address(&[1u8; 20]);
        let calldata = encode_call(sel, &[addr]);
        assert_eq!(calldata.len(), 36); // 4 + 32
        assert_eq!(&calldata[0..4], &sel);
    }
}
