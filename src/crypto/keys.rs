// CipherX Lite — Cryptographic Keys
// Validateurs identifiés via Ed25519 classique (pas de zk-SNARKs)

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

/// Clé privée du wallet — zéroïsée à la destruction
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        PrivateKey(signing_key.to_bytes())
    }
}

/// Clé publique Ed25519
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

/// View key — lecture seule (scan des outputs reçus)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ViewKey(pub [u8; 32]);

/// Adresse CipherX = CX1 + hex(spend_pubkey + view_pubkey)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAddress {
    pub public_spend: PublicKey,
    pub public_view: PublicKey,
}

impl StealthAddress {
    pub fn to_string(&self) -> String {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.public_spend.0);
        bytes[32..].copy_from_slice(&self.public_view.0);
        format!("CX1{}", hex::encode(bytes))
    }
}

/// Commitment du validateur — simplifié : clé publique Ed25519
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCommitment {
    /// Clé publique Ed25519 du validateur
    pub public_key: [u8; 32],
    /// Nullifier = H(public_key) pour compatibilité future
    pub nullifier: [u8; 32],
}

impl ValidatorCommitment {
    pub fn from_public_key(pubkey: [u8; 32]) -> Self {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(&pubkey);
        h.update(b"CipherX_nullifier");
        let nullifier: [u8; 32] = h.finalize().into();
        ValidatorCommitment { public_key: pubkey, nullifier }
    }

    pub fn placeholder() -> Self {
        ValidatorCommitment {
            public_key: [0u8; 32],
            nullifier: [0u8; 32],
        }
    }

    pub fn verify(&self) -> bool {
        true
    }

    /// Vérifie une signature Ed25519 du validateur
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != 64 { return false; }
        let Ok(vk) = VerifyingKey::from_bytes(&self.public_key) else { return false; };
        let sig_bytes: [u8; 64] = match signature.try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(message, &sig).is_ok()
    }
}

/// Keypair complet du validateur
pub struct ValidatorKeypair {
    pub signing_key: SigningKey,
    pub commitment: ValidatorCommitment,
}

impl ValidatorKeypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        ValidatorKeypair {
            commitment: ValidatorCommitment::from_public_key(pubkey),
            signing_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}
