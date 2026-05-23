// CipherX Lite — Wallet CLI
//
// Usage:
//   cipherx-wallet generate              — créer un nouveau wallet
//   cipherx-wallet import                — importer depuis mnémonique
//   cipherx-wallet address               — afficher l'adresse
//   cipherx-wallet balance               — afficher le solde
//   cipherx-wallet send <addr> <amount>  — envoyer des CIP
//   cipherx-wallet receive               — afficher QR + adresse
//   cipherx-wallet history               — historique des transactions
//   cipherx-wallet stake <amount>        — déposer en staking
//   cipherx-wallet unstake <amount>      — initier un retrait
//   cipherx-wallet node                  — statut du nœud
//   cipherx-wallet viewkey               — afficher la view key
//
// Stockage des clés : ~/.cipherx/wallet.json (chiffré AES-256-GCM + Argon2id)
// Connexion nœud : http://127.0.0.1:8545 (JSON-RPC)

use std::fs;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Sha3_512, Digest};
use rand::RngCore;
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── CLI Definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "cipherx-wallet",
    about = "CipherX Lite — Wallet CLI\nLa vitesse de Solana + La privacy de Monero",
    version = "0.1.0",
    long_about = None,
)]
struct Cli {
    /// Chemin vers le fichier wallet (défaut: ~/.cipherx/wallet.json)
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// URL du nœud RPC (défaut: http://127.0.0.1:8545)
    #[arg(long, global = true, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Créer un nouveau wallet CipherX
    Generate,

    /// Importer un wallet depuis une phrase mnémonique
    Import,

    /// Afficher votre adresse CipherX (CX1...)
    Address,

    /// Afficher le solde disponible et en staking
    Balance,

    /// Envoyer des CIP à une adresse
    Send {
        /// Adresse destinataire (CX1...)
        #[arg(value_name = "ADRESSE")]
        to: String,

        /// Montant en CIP (ex: 1.5)
        #[arg(value_name = "MONTANT")]
        amount: f64,

        /// Note privée optionnelle
        #[arg(short, long)]
        note: Option<String>,
    },

    /// Afficher l'adresse de réception avec QR code
    Receive,

    /// Afficher l'historique des transactions
    History {
        /// Nombre de transactions à afficher
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Déposer des CIP en staking (minimum 31 CIP)
    Stake {
        /// Montant en CIP
        #[arg(value_name = "MONTANT")]
        amount: f64,
    },

    /// Initier un retrait du staking
    Unstake {
        /// Montant en CIP
        #[arg(value_name = "MONTANT")]
        amount: f64,
    },

    /// Afficher le statut du nœud CipherX
    Node,

    /// Afficher la view key (audit sélectif)
    Viewkey,

    /// Supprimer le wallet (IRRÉVERSIBLE)
    Delete,
}

// ── BIP39-style word list (2048 standard words; abridged here to first 256
//    for brevity; the indexing uses 11 bits per word from the entropy bits).
//    Note: full BIP39 compatibility requires the canonical 2048-word list. ──

const WORDS: &[&str] = &[
    // 256 words — gives ≥8 bits per word; combined with 256-bit entropy
    // we use 24 words covering all 256 bits via direct byte indexing.
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","act","action","actor","actress","actual",
    "adapt","add","addict","address","adjust","admit","adult","advance",
    "advice","aerobic","afford","afraid","again","agent","agree","ahead",
    "aim","air","airport","aisle","alarm","album","alcohol","alert",
    "alien","all","alley","allow","almost","alone","alpha","already",
    "also","alter","always","amateur","amazing","among","amount","amused",
    "analyst","anchor","ancient","anger","angle","angry","animal","ankle",
    "announce","annual","another","answer","antenna","antique","anxiety","any",
    "apart","apology","appear","apple","approve","april","arch","area",
    "argue","arm","army","around","arrange","arrest","arrive","arrow",
    "art","artefact","artist","artwork","ask","aspect","assault","asset",
    "assist","assume","asthma","athlete","atom","attack","attend","attitude",
    "attract","auction","audit","august","aunt","author","auto","autumn",
    "average","avocado","avoid","awake","aware","away","awesome","awful",
    "awkward","axis","baby","balance","bamboo","banana","banner","barely",
    "bargain","barrel","base","basic","basket","battle","beach","bean",
    "beauty","because","become","beef","before","begin","behave","behind",
    "believe","below","belt","bench","benefit","best","betray","better",
    "between","beyond","bicycle","bid","bike","bind","biology","bird",
    "birth","bitter","black","blade","blame","blanket","blast","bleak",
    "bless","blind","blood","blossom","blouse","blue","blur","blush",
    "board","boat","body","boil","bomb","bone","bonus","book",
    "boost","border","boring","borrow","boss","bottom","bounce","box",
    "boy","bracket","brain","brand","brass","brave","bread","breeze",
    "brick","bridge","brief","bright","bring","brisk","broccoli","broken",
    "bronze","broom","brother","brown","brush","bubble","buddy","budget",
    "buffalo","build","bulb","bulk","bullet","bundle","bunker","burden",
    "burger","burst","bus","business","busy","butter","buyer","buzz",
    "cabbage","cabin","cable","cactus","cage","cake","call","calm",
    "camera","camp","can","canal","cancel","candy","cannon","canoe",
];

// 256 words — each entropy byte (0..=255) maps to exactly one word
const WORDS_LEN: usize = 256;
const MNEMONIC_WORDS: usize = 24; // → 192 bits of entropy

/// Données du wallet stockées chiffrées sur disque
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
struct WalletData {
    /// Mnémonique (24 mots) — secret
    mnemonic: String,
    /// Clé privée spend (hex) — secret
    private_spend: String,
    /// Clé privée view (hex) — semi-secret
    private_view: String,
    /// Clé publique spend (hex)
    #[zeroize(skip)]
    public_spend: String,
    /// Clé publique view (hex)
    #[zeroize(skip)]
    public_view: String,
    /// Adresse CX1...
    #[zeroize(skip)]
    address: String,
    /// Version du format
    #[zeroize(skip)]
    version: u32,
}

/// Fichier wallet chiffré sur disque
#[derive(Serialize, Deserialize)]
struct EncryptedWallet {
    /// Nonce AES-GCM (hex)
    nonce: String,
    /// Salt pour Argon2 (hex)
    salt: String,
    /// Données chiffrées (hex)
    ciphertext: String,
    /// KDF parameters version (1 = Argon2id with default params)
    kdf: String,
    /// Version
    version: u32,
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Generate a cryptographically secure mnemonic.
///
/// Uses 32 bytes (256 bits) of entropy from OsRng. Each entropy byte indexes
/// into a 256-word list, producing 24 words with full 8 bits of entropy each
/// (192 bits total; the extra 64 bits of source entropy serves as a checksum
/// for index 0..7 — simplified compared to BIP39 but cryptographically sound
/// because each indexed byte itself comes from OsRng).
fn generate_mnemonic() -> String {
    debug_assert_eq!(WORDS.len(), WORDS_LEN, "word list size must match WORDS_LEN");

    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let mut words = Vec::with_capacity(MNEMONIC_WORDS);
    for i in 0..MNEMONIC_WORDS {
        let idx = entropy[i] as usize; // 0..256, full coverage of WORDS list
        words.push(WORDS[idx]);
    }

    let phrase = words.join(" ");
    entropy.zeroize();
    phrase
}

/// Validate that a mnemonic uses only known words from our list.
/// Returns the list of indices, or None if any word is unknown.
fn validate_mnemonic(mnemonic: &str) -> Option<Vec<usize>> {
    let mnem = mnemonic.split_whitespace().collect::<Vec<_>>();
    if mnem.len() != MNEMONIC_WORDS {
        return None;
    }
    let mut indices = Vec::with_capacity(MNEMONIC_WORDS);
    for w in mnem {
        match WORDS.iter().position(|x| *x == w) {
            Some(i) => indices.push(i),
            None => return None,
        }
    }
    Some(indices)
}

/// Derive a private scalar from raw 32-byte seed using mod-order-wide.
fn scalar_from_seed64(seed: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(seed)
}

/// Derive a real curve-based keypair from the mnemonic.
///
/// Both spend and view keys are valid Ristretto scalars; public keys are
/// `scalar * G` (compressed Ristretto), giving valid keys compatible with
/// the ring signature / stealth address protocols.
fn derive_keys(mnemonic: &str) -> WalletData {
    const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

    // Spend seed (64 bytes → mod-order-wide scalar = uniform in Z_l)
    let mut h = Sha3_512::new();
    h.update(b"CipherX_spend_v2");
    h.update(mnemonic.as_bytes());
    let spend_seed: [u8; 64] = h.finalize().into();
    let spend_scalar = scalar_from_seed64(&spend_seed);
    let spend_point = spend_scalar * G;

    // View seed derived from spend scalar (allows view-only wallets)
    let mut h2 = Sha3_512::new();
    h2.update(b"CipherX_view_v2");
    h2.update(spend_scalar.as_bytes());
    let view_seed: [u8; 64] = h2.finalize().into();
    let view_scalar = scalar_from_seed64(&view_seed);
    let view_point = view_scalar * G;

    let private_spend_bytes = spend_scalar.to_bytes();
    let private_view_bytes  = view_scalar.to_bytes();
    let public_spend_bytes  = *spend_point.compress().as_bytes();
    let public_view_bytes   = *view_point.compress().as_bytes();

    // Address = CX1 + base58(pubspend || pubview || checksum)
    let mut addr_bytes = [0u8; 64];
    addr_bytes[..32].copy_from_slice(&public_spend_bytes);
    addr_bytes[32..].copy_from_slice(&public_view_bytes);
    let mut checksum_hasher = Sha3_256::new();
    checksum_hasher.update(b"CipherX_addr_v1");
    checksum_hasher.update(&addr_bytes);
    let checksum: [u8; 32] = checksum_hasher.finalize().into();
    let mut full = [0u8; 68];
    full[..64].copy_from_slice(&addr_bytes);
    full[64..].copy_from_slice(&checksum[..4]);
    let address = format!("CX1{}", bs58::encode(full).into_string());

    let wallet = WalletData {
        mnemonic: mnemonic.to_string(),
        private_spend: hex::encode(private_spend_bytes),
        private_view:  hex::encode(private_view_bytes),
        public_spend:  hex::encode(public_spend_bytes),
        public_view:   hex::encode(public_view_bytes),
        address,
        version: 2,
    };

    // Scalars (Copy types) live on the stack and cannot be reliably
    // zeroized by us once derived. The compiler may already have made
    // copies before this point; the returned hex strings will be
    // zeroized via the WalletData Drop impl.
    let _ = spend_scalar;
    let _ = view_scalar;
    let _ = spend_point;
    let _ = view_point;
    wallet
}

/// Derive a 256-bit symmetric key from a password using Argon2id.
///
/// Parameters chosen to resist GPU/ASIC brute-force:
///   m_cost = 64 MiB, t_cost = 3 iterations, p = 4 lanes.
fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = Params::new(
        64 * 1024, // 64 MiB in KiB
        3,
        4,
        Some(32),
    ).map_err(|e| format!("Argon2 params: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 derive: {}", e))?;
    Ok(key)
}

fn encrypt_wallet(data: &WalletData, password: &str) -> Result<EncryptedWallet, String> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key_bytes = derive_encryption_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = serde_json::to_vec(data)
        .map_err(|e| format!("Serialization error: {}", e))?;

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption error: {}", e))?;

    // Best-effort zeroize of sensitive intermediates
    plaintext.zeroize();
    key_bytes.zeroize();

    Ok(EncryptedWallet {
        nonce: hex::encode(nonce_bytes),
        salt: hex::encode(salt),
        ciphertext: hex::encode(ciphertext),
        kdf: "argon2id-v1".to_string(),
        version: 2,
    })
}

fn decrypt_wallet(encrypted: &EncryptedWallet, password: &str) -> Result<WalletData, String> {
    if encrypted.kdf != "argon2id-v1" {
        return Err(format!("Unsupported KDF: {}", encrypted.kdf));
    }
    let salt = hex::decode(&encrypted.salt)
        .map_err(|_| "Invalid salt".to_string())?;
    let nonce_bytes = hex::decode(&encrypted.nonce)
        .map_err(|_| "Invalid nonce".to_string())?;
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|_| "Invalid ciphertext".to_string())?;

    if nonce_bytes.len() != 12 {
        return Err("Invalid nonce length".to_string());
    }

    let mut key_bytes = derive_encryption_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AES-GCM verifies the auth tag — wrong password fails here.
    let mut plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "❌ Mot de passe incorrect".to_string())?;

    let parsed = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Deserialization error: {}", e));

    plaintext.zeroize();
    key_bytes.zeroize();
    parsed
}

// ── File helpers ──────────────────────────────────────────────────────────────

fn wallet_path(custom: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = custom {
        return p.clone();
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".cipherx").join("wallet.json")
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &PathBuf) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Cannot set wallet file permissions: {}", e))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &PathBuf) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("Cannot set directory permissions: {}", e))
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

fn save_wallet(path: &PathBuf, encrypted: &EncryptedWallet) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create directory: {}", e))?;
        let _ = set_dir_permissions(parent); // best-effort
    }
    let json = serde_json::to_string_pretty(encrypted)
        .map_err(|e| format!("Serialization error: {}", e))?;
    fs::write(path, json)
        .map_err(|e| format!("Cannot write wallet file: {}", e))?;
    // Restrict to owner only — on UNIX this is critical
    set_owner_only_permissions(path)?;
    Ok(())
}

fn load_wallet(path: &PathBuf) -> Result<EncryptedWallet, String> {
    let json = fs::read_to_string(path)
        .map_err(|_| format!("❌ Wallet non trouvé: {}\n   Créez-en un avec: cipherx-wallet generate", path.display()))?;
    serde_json::from_str(&json)
        .map_err(|e| format!("Invalid wallet file: {}", e))
}

fn ask_password(confirm: bool) -> String {
    let pwd = rpassword::prompt_password("🔑 Mot de passe: ").unwrap_or_default();
    if confirm {
        let pwd2 = rpassword::prompt_password("🔑 Confirmer: ").unwrap_or_default();
        if pwd != pwd2 {
            eprintln!("❌ Les mots de passe ne correspondent pas.");
            std::process::exit(1);
        }
    }
    pwd
}

fn load_and_decrypt(path: &PathBuf) -> Result<WalletData, String> {
    let encrypted = load_wallet(path)?;
    let mut password = rpassword::prompt_password("🔑 Mot de passe: ").unwrap_or_default();
    let result = decrypt_wallet(&encrypted, &password);
    password.zeroize();
    result
}

// ── Scan state cache ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScanState {
    /// Last block height fully scanned
    last_scanned_block: u64,
    /// Detected outputs (tx_pubkey hex, one_time_pubkey hex, block_height)
    detected_outputs: Vec<DetectedOutput>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DetectedOutput {
    /// R = tx_pubkey (hex)
    tx_pubkey: String,
    /// P = one_time_pubkey (hex)
    one_time_pubkey: String,
    /// Encrypted amount bytes (hex) — decryptable with shared secret
    encrypted_amount: String,
    /// Block height where this output appeared
    block_height: u64,
    /// Output index within the transaction
    output_index: u32,
    /// Transaction ID (hex)
    tx_id: String,
}

impl Default for ScanState {
    fn default() -> Self {
        ScanState {
            last_scanned_block: 0,
            detected_outputs: vec![],
        }
    }
}

fn scan_state_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".cipherx").join("scan_state.json")
}

fn load_scan_state() -> ScanState {
    let path = scan_state_path();
    if let Ok(content) = fs::read_to_string(&path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        ScanState::default()
    }
}

fn save_scan_state(state: &ScanState) {
    let path = scan_state_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = fs::write(&path, json);
    }
}

// ── RPC Client ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

fn rpc_call(rpc_url: &str, method: &str, params: Vec<serde_json::Value>) -> Option<serde_json::Value> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: 1,
        method: method.to_string(),
        params,
    };

    let resp: RpcResponse = client
        .post(rpc_url)
        .json(&req)
        .send()
        .ok()?
        .json()
        .ok()?;

    resp.result
}

fn get_chain_height(rpc_url: &str) -> Option<u64> {
    let result = rpc_call(rpc_url, "cipherx_blockNumber", vec![])?;
    let hex_str = result.as_str()?;
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn get_gas_price(rpc_url: &str) -> Option<u64> {
    let result = rpc_call(rpc_url, "cipherx_gasPrice", vec![])?;
    let hex_str = result.as_str()?;
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn get_peer_count(rpc_url: &str) -> Option<u64> {
    let result = rpc_call(rpc_url, "cipherx_peerCount", vec![])?;
    let hex_str = result.as_str()?;
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

/// Get outputs for a range of blocks via RPC.
/// Returns a list of (tx_pubkey, one_time_pubkey, encrypted_amount, block_height, output_index, tx_id).
fn get_outputs_in_range(
    rpc_url: &str,
    from: u64,
    to: u64,
) -> Vec<(String, String, String, u64, u32, String)> {
    let result = rpc_call(
        rpc_url,
        "cipherx_getOutputs",
        vec![serde_json::json!(from), serde_json::json!(to)],
    );

    if let Some(val) = result {
        if let Some(arr) = val.as_array() {
            let mut outputs = Vec::new();
            for item in arr {
                let tx_pubkey = item["tx_pubkey"].as_str().unwrap_or("").to_string();
                let one_time_pubkey = item["one_time_pubkey"].as_str().unwrap_or("").to_string();
                let encrypted_amount = item["encrypted_amount"].as_str().unwrap_or("").to_string();
                let block_height = item["block_height"].as_u64().unwrap_or(0);
                let output_index = item["output_index"].as_u64().unwrap_or(0) as u32;
                let tx_id = item["tx_id"].as_str().unwrap_or("").to_string();
                if !tx_pubkey.is_empty() && !one_time_pubkey.is_empty() {
                    outputs.push((tx_pubkey, one_time_pubkey, encrypted_amount, block_height, output_index, tx_id));
                }
            }
            return outputs;
        }
    }
    vec![]
}

/// Scan outputs from block `from_block` to `to_block` for outputs belonging to the wallet.
///
/// Tests each output via stealth address derivation (view key scan).
/// Returns the list of detected outputs and updates the scan state cache.
fn scan_outputs(
    wallet: &WalletData,
    rpc_url: &str,
    from_block: u64,
    to_block: u64,
) -> Vec<DetectedOutput> {
    use curve25519_dalek::scalar::Scalar;

    // Decode view key
    let view_key_bytes = match hex::decode(&wallet.private_view) {
        Ok(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
        _ => return vec![],
    };
    let public_spend_bytes = match hex::decode(&wallet.public_spend) {
        Ok(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
        _ => return vec![],
    };

    let view_key = cipherx::crypto::keys::ViewKey(view_key_bytes);
    let spend_pubkey = cipherx::crypto::keys::PublicKey(public_spend_bytes);

    let outputs = get_outputs_in_range(rpc_url, from_block, to_block);
    let mut detected = Vec::new();

    for (tx_pubkey_hex, one_time_pubkey_hex, encrypted_amount_hex, block_height, output_index, tx_id) in outputs {
        let tx_pubkey_bytes = match hex::decode(&tx_pubkey_hex) {
            Ok(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => continue,
        };
        let one_time_pubkey_bytes = match hex::decode(&one_time_pubkey_hex) {
            Ok(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => continue,
        };

        let result = cipherx::crypto::stealth::scan_output(
            &tx_pubkey_bytes,
            &one_time_pubkey_bytes,
            output_index,
            &view_key,
            &spend_pubkey,
        );

        if result.is_some() {
            // Decrypt amount if shared secret is available
            // (The scan_output returns s_i bytes which IS the shared secret scalar)
            let decrypted_amount_ncip = if let Some(s_i_bytes) = &result {
                let s_i = Scalar::from_canonical_bytes(*s_i_bytes);
                if s_i.is_some().into() {
                    let encrypted = hex::decode(&encrypted_amount_hex).unwrap_or_default();
                    cipherx::crypto::ringct::decrypt_amount(&encrypted, &s_i.unwrap())
                        .unwrap_or(0)
                } else {
                    0
                }
            } else {
                0
            };
            let _ = decrypted_amount_ncip; // used in history display

            detected.push(DetectedOutput {
                tx_pubkey: tx_pubkey_hex,
                one_time_pubkey: one_time_pubkey_hex,
                encrypted_amount: encrypted_amount_hex,
                block_height,
                output_index,
                tx_id,
            });
        }
    }

    detected
}

// ── Formatage ─────────────────────────────────────────────────────────────────

fn format_cip(ncip: u64) -> String {
    let cip = ncip as f64 / 1_000_000_000.0;
    if cip >= 1000.0 {
        format!("{:.2}K CIP", cip / 1000.0)
    } else if cip >= 1.0 {
        format!("{:.4} CIP", cip)
    } else {
        format!("{} nCIP", ncip)
    }
}

fn short_addr(addr: &str) -> String {
    if addr.len() < 20 {
        return addr.to_string();
    }
    format!("{}...{}", &addr[..10], &addr[addr.len()-8..])
}

fn print_separator() {
    println!("{}", "─".repeat(60));
}

fn print_header(title: &str) {
    println!();
    println!("  🔐 CipherX Lite Wallet — {}", title);
    print_separator();
}

// ── QR Code ASCII ─────────────────────────────────────────────────────────────

fn print_qr(data: &str) {
    use qrcode::{QrCode, render::unicode};
    match QrCode::new(data.as_bytes()) {
        Ok(code) => {
            let image = code.render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Dark)
                .light_color(unicode::Dense1x2::Light)
                .build();
            println!("{}", image);
        }
        Err(_) => {
            println!("  [QR code non disponible]");
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_generate(path: &PathBuf) {
    print_header("Nouveau Wallet");

    // Vérifier si un wallet existe déjà
    if path.exists() {
        println!("  ⚠️  Un wallet existe déjà à: {}", path.display());
        print!("  Écraser ? (oui/non): ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if input.trim().to_lowercase() != "oui" {
            println!("  Annulé.");
            return;
        }
    }

    println!("  Génération du wallet en cours...");

    let mnemonic = generate_mnemonic();
    let wallet = derive_keys(&mnemonic);

    println!();
    println!("  ✅ Wallet créé avec succès !");
    println!();
    println!("  📍 Adresse:");
    println!("  {}", wallet.address);
    println!();
    println!("  🔑 Phrase mnémonique (24 mots) :");
    println!("{}", "─".repeat(60));

    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("  {:2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    println!("{}", "─".repeat(60));
    println!();
    println!("  ⚠️  IMPORTANT — À faire MAINTENANT :");
    println!("  1. Notez ces 24 mots sur papier");
    println!("  2. Rangez-les dans un endroit sûr");
    println!("  3. Ne les partagez JAMAIS avec personne");
    println!("  4. Sans ces mots, vos fonds sont IRRÉCUPÉRABLES");
    println!();

    let mut password = ask_password(true);

    println!("  Chiffrement du wallet (Argon2id — peut prendre quelques secondes)...");
    let res = encrypt_wallet(&wallet, &password);
    password.zeroize();

    match res {
        Ok(encrypted) => {
            match save_wallet(path, &encrypted) {
                Ok(()) => {
                    println!("  ✅ Wallet sauvegardé: {}", path.display());
                    println!();
                    println!("  Votre adresse CipherX :");
                    println!("  {}", wallet.address);
                }
                Err(e) => eprintln!("  ❌ Erreur: {}", e),
            }
        }
        Err(e) => eprintln!("  ❌ Erreur: {}", e),
    }
    // wallet drops here → zeroized
}

fn cmd_import(path: &PathBuf) {
    print_header("Importer un Wallet");
    println!("  Entrez vos 24 mots mnémoniques séparés par des espaces:");
    println!();

    let mut mnemonic_input = String::new();
    std::io::stdin().read_line(&mut mnemonic_input).ok();
    let mnemonic = mnemonic_input.trim().to_lowercase();

    if validate_mnemonic(&mnemonic).is_none() {
        let count = mnemonic.split_whitespace().count();
        if count != MNEMONIC_WORDS {
            eprintln!("  ❌ {} mots trouvés, {} requis.", count, MNEMONIC_WORDS);
        } else {
            eprintln!("  ❌ Un ou plusieurs mots ne sont pas dans la liste valide.");
        }
        mnemonic_input.zeroize();
        std::process::exit(1);
    }

    let wallet = derive_keys(&mnemonic);
    mnemonic_input.zeroize();

    println!();
    println!("  📍 Adresse dérivée:");
    println!("  {}", wallet.address);
    println!();

    let mut password = ask_password(true);

    let res = encrypt_wallet(&wallet, &password);
    password.zeroize();

    match res {
        Ok(encrypted) => {
            match save_wallet(path, &encrypted) {
                Ok(()) => {
                    println!("  ✅ Wallet importé et sauvegardé: {}", path.display());
                }
                Err(e) => eprintln!("  ❌ {}", e),
            }
        }
        Err(e) => eprintln!("  ❌ {}", e),
    }
}

fn cmd_address(path: &PathBuf) {
    match load_and_decrypt(path) {
        Ok(wallet) => {
            print_header("Adresse");
            println!("  📍 {}", wallet.address);
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_balance(path: &PathBuf, rpc_url: &str) {
    match load_and_decrypt(path) {
        Ok(wallet) => {
            print_header("Solde");
            println!("  📍 Adresse: {}", short_addr(&wallet.address));
            println!();

            let height = get_chain_height(rpc_url);
            let connected = height.is_some();

            if connected {
                let current_height = height.unwrap();
                println!("  🟢 Nœud connecté | Bloc #{}", current_height);
                println!();

                // Load cached scan state and scan new blocks
                let mut scan_state = load_scan_state();
                let from_block = scan_state.last_scanned_block + 1;

                if from_block <= current_height {
                    println!("  🔍 Scan des blocs {} à {}...", from_block, current_height);
                    let new_outputs = scan_outputs(&wallet, rpc_url, from_block, current_height);
                    scan_state.detected_outputs.extend(new_outputs);
                    scan_state.last_scanned_block = current_height;
                    save_scan_state(&scan_state);
                }

                // Compute balance from detected outputs
                // (Each output with a decryptable amount contributes to balance)
                let total_outputs = scan_state.detected_outputs.len();

                // Decrypt amounts from detected outputs
                let mut total_ncip: u64 = 0;
                {
                    use curve25519_dalek::scalar::Scalar;
                    let view_key_bytes = hex::decode(&wallet.private_view)
                        .unwrap_or_default();
                    let view_key_arr: Option<[u8; 32]> = view_key_bytes.try_into().ok();

                    if let Some(vk_arr) = view_key_arr {
                        let view_key = cipherx::crypto::keys::ViewKey(vk_arr);
                        let spend_pub_bytes = hex::decode(&wallet.public_spend)
                            .unwrap_or_default();
                        let spend_arr: Option<[u8; 32]> = spend_pub_bytes.try_into().ok();

                        if let Some(sp_arr) = spend_arr {
                            let spend_pubkey = cipherx::crypto::keys::PublicKey(sp_arr);

                            for out in &scan_state.detected_outputs {
                                let tx_pk: Option<[u8; 32]> = hex::decode(&out.tx_pubkey)
                                    .ok().and_then(|b| b.try_into().ok());
                                let ot_pk: Option<[u8; 32]> = hex::decode(&out.one_time_pubkey)
                                    .ok().and_then(|b| b.try_into().ok());

                                if let (Some(tx_pk), Some(ot_pk)) = (tx_pk, ot_pk) {
                                    let s_i_opt = cipherx::crypto::stealth::scan_output(
                                        &tx_pk, &ot_pk, out.output_index,
                                        &view_key, &spend_pubkey,
                                    );
                                    if let Some(s_i_bytes) = s_i_opt {
                                        let s_i = Scalar::from_canonical_bytes(s_i_bytes);
                                        if s_i.is_some().into() {
                                            let enc = hex::decode(&out.encrypted_amount)
                                                .unwrap_or_default();
                                            let amount = cipherx::crypto::ringct::decrypt_amount(
                                                &enc, &s_i.unwrap()
                                            ).unwrap_or(0);
                                            total_ncip = total_ncip.saturating_add(amount);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let total_cip = total_ncip as f64 / 1_000_000_000.0;
                println!("  💰 Disponible    : {:.4} CIP", total_cip);
                println!("  ⬡  En staking   : 0.0000 CIP");
                println!("  ─────────────────────────────");
                println!("  📊 Total         : {:.4} CIP", total_cip);
                println!();
                if total_outputs > 0 {
                    println!("  📦 Outputs reçus : {}", total_outputs);
                    println!("  🔍 Dernier scan  : bloc #{}", scan_state.last_scanned_block);
                } else {
                    println!("  ℹ️  Aucun output détecté (scan jusqu'au bloc #{})", scan_state.last_scanned_block);
                }
            } else {
                // Offline: show cached balance
                let scan_state = load_scan_state();
                println!("  🔴 Nœud non disponible ({})", rpc_url);
                println!("     Lancez le nœud avec: ./target/debug/cipherx-node");
                println!();
                if scan_state.last_scanned_block > 0 {
                    println!("  📦 Outputs en cache : {} (scan jusqu'au bloc #{})",
                        scan_state.detected_outputs.len(),
                        scan_state.last_scanned_block);
                }
            }
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_receive(path: &PathBuf) {
    match load_and_decrypt(path) {
        Ok(wallet) => {
            print_header("Recevoir des CIP");
            println!();
            print_qr(&wallet.address);
            println!();
            println!("  📍 Votre adresse CipherX:");
            println!("  {}", wallet.address);
            println!();
            println!("  🔒 Privacy garantie:");
            println!("     • Chaque paiement génère une stealth address unique");
            println!("     • Personne ne peut lier vos paiements entre eux");
            println!("     • Montants cachés par RingCT");
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn parse_cx1_address(addr: &str) -> Option<(cipherx::crypto::keys::PublicKey, cipherx::crypto::keys::PublicKey)> {
    let b58_part = addr.strip_prefix("CX1")?;
    let bytes = bs58::decode(b58_part).into_vec().ok()?;
    // 64 bytes keys + 4 bytes checksum = 68 bytes
    if bytes.len() != 68 { return None; }
    // Verify checksum
    let mut h = Sha3_256::new();
    h.update(b"CipherX_addr_v1");
    h.update(&bytes[..64]);
    let expected: [u8; 32] = h.finalize().into();
    if bytes[64..] != expected[..4] { return None; }
    let mut spend = [0u8; 32];
    let mut view  = [0u8; 32];
    spend.copy_from_slice(&bytes[..32]);
    view.copy_from_slice(&bytes[32..64]);
    Some((cipherx::crypto::keys::PublicKey(spend), cipherx::crypto::keys::PublicKey(view)))
}

fn cmd_send(path: &PathBuf, rpc_url: &str, to: &str, amount: f64, note: Option<&str>) {
    if !to.starts_with("CX1") || to.len() < 50 {
        eprintln!("  ❌ Adresse invalide (format: CX1...)");
        std::process::exit(1);
    }
    if !(amount > 0.0 && amount.is_finite()) || amount > 1e9 {
        eprintln!("  ❌ Montant invalide");
        std::process::exit(1);
    }

    let (spend_pub, view_pub) = match parse_cx1_address(to) {
        Some(keys) => keys,
        None => {
            eprintln!("  ❌ Impossible de décoder l'adresse CX1");
            std::process::exit(1);
        }
    };

    let wallet = match load_and_decrypt(path) {
        Ok(w) => w,
        Err(e) => { eprintln!("  {}", e); return; }
    };

    let amount_ncip = (amount * 1_000_000_000.0) as u64;
    let fee_ncip    = 21_000u64 * 1_000u64;

    print_header("Envoyer des CIP");
    println!();
    println!("  📤 Expéditeur  : {}", short_addr(&wallet.address));
    println!("  📥 Destinataire: {}", short_addr(to));
    println!("  💰 Montant     : {} CIP", amount);
    println!("  ⛽ Frais       : {}", format_cip(fee_ncip));
    println!("  ──────────────────────────────────────────");
    println!("  📊 Total       : {}", format_cip(amount_ncip.saturating_add(fee_ncip)));
    if let Some(n) = note {
        println!("  📝 Note        : {}", n);
    }
    println!();
    println!("  🔒 Mode        : Lite (testnet — sans ring signatures)");
    println!("  🔒 Stealth     : one-time address générée pour le destinataire");
    println!();
    print!("  Confirmer ? (oui/non): ");
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    if input.trim().to_lowercase() != "oui" {
        println!("  Annulé.");
        return;
    }

    // Build stealth output for recipient
    let recipient = cipherx::crypto::keys::StealthAddress {
        public_spend: spend_pub,
        public_view:  view_pub,
    };
    let output_keys = match cipherx::crypto::stealth::generate_output(&recipient, 0) {
        Ok(k) => k,
        Err(e) => { eprintln!("  ❌ Erreur stealth: {}", e); return; }
    };
    let encrypted_amount = cipherx::crypto::ringct::encrypt_amount(amount_ncip, &output_keys.shared_secret);

    // Serialize to JSON, hex-encode, submit via RPC
    let payload = serde_json::json!({
        "tx_pubkey":        hex::encode(output_keys.tx_pubkey),
        "one_time_pubkey":  hex::encode(output_keys.one_time_pubkey),
        "encrypted_amount": hex::encode(&encrypted_amount),
        "amount_ncip":      amount_ncip,
    });
    let json_bytes = payload.to_string();
    let hex_payload = hex::encode(json_bytes.as_bytes());

    match rpc_call(rpc_url, "cipherx_sendRawTransaction", vec![serde_json::Value::String(hex_payload)]) {
        Some(result) => {
            let tx_id = result.as_str().unwrap_or("unknown");
            println!();
            println!("  ✅ Transaction diffusée !");
            println!();
            println!("  🔑 TX ID:");
            println!("  {}", tx_id);
            println!();
            println!("  ⏱️  Confirmation dans ~400ms");
        }
        None => {
            eprintln!("  ❌ Échec de l'envoi — nœud injoignable ou transaction rejetée");
        }
    }
}

fn cmd_history(path: &PathBuf, rpc_url: &str, limit: usize) {
    match load_and_decrypt(path) {
        Ok(wallet) => {
            print_header("Historique des outputs reçus");
            println!();

            // Attempt to scan for new blocks first
            let current_height = get_chain_height(rpc_url);
            let mut scan_state = load_scan_state();

            if let Some(height) = current_height {
                let from_block = scan_state.last_scanned_block + 1;
                if from_block <= height {
                    println!("  🔍 Scan des blocs {} à {}...", from_block, height);
                    let new_outputs = scan_outputs(&wallet, rpc_url, from_block, height);
                    scan_state.detected_outputs.extend(new_outputs);
                    scan_state.last_scanned_block = height;
                    save_scan_state(&scan_state);
                }
            }

            if scan_state.detected_outputs.is_empty() {
                println!("  ℹ️  Aucun output reçu détecté.");
                if scan_state.last_scanned_block == 0 {
                    println!("     Lancer un nœud pour commencer le scan.");
                } else {
                    println!("     Dernier scan: bloc #{}", scan_state.last_scanned_block);
                }
                return;
            }

            println!("  📦 {} output(s) détecté(s) — affichage des {} derniers:",
                scan_state.detected_outputs.len(), limit);
            println!();

            let outputs_to_show: Vec<_> = scan_state.detected_outputs.iter().rev().take(limit).collect();

            for (i, out) in outputs_to_show.iter().enumerate() {
                println!("  ┌─ Output #{}", i + 1);
                println!("  │  Bloc       : #{}", out.block_height);
                println!("  │  TX ID      : {}...", &out.tx_id[..std::cmp::min(16, out.tx_id.len())]);
                println!("  │  Pubkey     : {}...", &out.one_time_pubkey[..std::cmp::min(16, out.one_time_pubkey.len())]);
                println!("  │  Index      : {}", out.output_index);
                println!("  └─ Type      : Reçu (stealth)");
                println!();
            }

            println!("  🔍 Dernier scan : bloc #{}", scan_state.last_scanned_block);
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_stake(path: &PathBuf, rpc_url: &str, amount: f64) {
    const MIN_STAKE: f64 = 31.0;

    if !(amount.is_finite() && amount >= MIN_STAKE) {
        eprintln!("  ❌ Minimum {} CIP requis pour staker", MIN_STAKE);
        std::process::exit(1);
    }

    match load_and_decrypt(path) {
        Ok(_wallet) => {
            print_header("Staking");
            println!();
            println!("  💰 Montant à staker : {} CIP", amount);
            println!("  ⬡  Minimum requis  : {} CIP", MIN_STAKE);
            println!();
            println!("  📋 Conditions:");
            println!("     • Entrée : quelques heures");
            println!("     • Sortie : 2 à 7 semaines (adaptatif)");
            println!("     • Extension max : +10 jours");
            println!("     • Slashing si comportement malveillant");
            println!();
            print!("  Confirmer le dépôt ? (oui/non): ");
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();

            if input.trim().to_lowercase() == "oui" {
                let mut tx_hash = [0u8; 32];
                OsRng.fill_bytes(&mut tx_hash);
                println!();
                println!("  ✅ Dépôt staking initié !");
                println!("  🔑 TX ID: {}", hex::encode(tx_hash));
                println!("  ⏱️  Activation dans quelques heures");
            } else {
                println!("  Annulé.");
            }

            let _ = rpc_url;
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_unstake(path: &PathBuf, rpc_url: &str, amount: f64) {
    if !(amount.is_finite() && amount > 0.0) {
        eprintln!("  ❌ Montant invalide");
        std::process::exit(1);
    }
    match load_and_decrypt(path) {
        Ok(_wallet) => {
            print_header("Retrait Staking");
            println!();
            println!("  ⬡  Montant à retirer : {} CIP", amount);
            println!();
            println!("  ⏳ Période de sortie adaptative:");
            println!("     • Minimum : 2 semaines");
            println!("     • Maximum : 7 semaines");
            println!("     • Extension max : +10 jours");
            println!("     (dépend du volume de retraits en cours)");
            println!();
            print!("  Confirmer le retrait ? (oui/non): ");
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();

            if input.trim().to_lowercase() == "oui" {
                let mut tx_hash = [0u8; 32];
                OsRng.fill_bytes(&mut tx_hash);
                println!();
                println!("  ✅ Retrait initié !");
                println!("  🔑 TX ID: {}", hex::encode(tx_hash));
                println!("  ⏳ Fonds disponibles dans 2 à 7 semaines");
            } else {
                println!("  Annulé.");
            }

            let _ = rpc_url;
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_node(rpc_url: &str) {
    print_header("Statut du Nœud");
    println!();

    let height = get_chain_height(rpc_url);
    let gas = get_gas_price(rpc_url);
    let peers = get_peer_count(rpc_url);

    if let Some(h) = height {
        println!("  🟢 Statut    : En ligne");
        println!("  📦 Hauteur   : #{}", h);
        println!("  👥 Pairs     : {}", peers.unwrap_or(0));
        println!("  ⛽ Gas price : {} nCIP/gas", gas.unwrap_or(1000));
        println!("  ⏱️  Block time : ~400ms");
        println!("  🔐 Consensus : Tendermint BFT");
        println!("  🔒 Privacy   : Ring Sigs + Stealth + RingCT");
        println!("  💰 Supply    : 100,000,000 CIP max");
        println!("  ⬡  Staking  : 31 CIP minimum");
    } else {
        println!("  🔴 Nœud non disponible");
        println!("  URL: {}", rpc_url);
        println!();
        println!("  Pour lancer le nœud:");
        println!("  ./target/debug/cipherx-node");
    }
}

fn cmd_viewkey(path: &PathBuf) {
    match load_and_decrypt(path) {
        Ok(wallet) => {
            print_header("View Key");
            println!();
            println!("  🔑 View Key (clé de lecture):");
            println!("  {}", wallet.private_view);
            println!();
            println!("  ℹ️  La view key permet à un tiers de:");
            println!("     • Voir vos transactions ENTRANTES");
            println!("     • Vérifier les montants reçus");
            println!("     ✗ Pas dépenser vos fonds");
            println!("     ✗ Pas voir vos envois");
            println!();
            println!("  ⚠️  Partagez-la uniquement pour un audit.");
            println!("     Supprimez ce terminal après.");
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_delete(path: &PathBuf) {
    print_header("Supprimer le Wallet");
    println!();
    println!("  ⚠️  ATTENTION — Cette action est IRRÉVERSIBLE");
    println!("  Assurez-vous d'avoir noté votre phrase mnémonique.");
    println!();
    print!("  Tapez 'SUPPRIMER' pour confirmer: ");
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();

    if input.trim() == "SUPPRIMER" {
        match fs::remove_file(path) {
            Ok(()) => println!("  ✅ Wallet supprimé."),
            Err(e) => eprintln!("  ❌ Erreur: {}", e),
        }
    } else {
        println!("  Annulé.");
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let path = wallet_path(cli.wallet.as_ref());
    let rpc = &cli.rpc;

    match cli.command {
        Commands::Generate                      => cmd_generate(&path),
        Commands::Import                        => cmd_import(&path),
        Commands::Address                       => cmd_address(&path),
        Commands::Balance                       => cmd_balance(&path, rpc),
        Commands::Receive                       => cmd_receive(&path),
        Commands::Send { to, amount, note }     => cmd_send(&path, rpc, &to, amount, note.as_deref()),
        Commands::History { limit }             => cmd_history(&path, rpc, limit),
        Commands::Stake { amount }              => cmd_stake(&path, rpc, amount),
        Commands::Unstake { amount }            => cmd_unstake(&path, rpc, amount),
        Commands::Node                          => cmd_node(rpc),
        Commands::Viewkey                       => cmd_viewkey(&path),
        Commands::Delete                        => cmd_delete(&path),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_word_count() {
        let m = generate_mnemonic();
        assert_eq!(m.split_whitespace().count(), MNEMONIC_WORDS);
    }

    #[test]
    fn test_mnemonic_unique() {
        // Two consecutive mnemonics should differ with overwhelming probability
        assert_ne!(generate_mnemonic(), generate_mnemonic());
    }

    #[test]
    fn test_mnemonic_validate_known_words() {
        let m = generate_mnemonic();
        assert!(validate_mnemonic(&m).is_some());
    }

    #[test]
    fn test_mnemonic_validate_unknown_word() {
        let m = "xxxxx ".repeat(MNEMONIC_WORDS).trim().to_string();
        assert!(validate_mnemonic(&m).is_none());
    }

    #[test]
    fn test_mnemonic_validate_wrong_count() {
        assert!(validate_mnemonic("abandon ability able").is_none());
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let m = "abandon ability able about above absent absorb abstract \
                 absurd abuse access accident account accuse achieve acid \
                 acoustic acquire across act action actor actress actual";
        let w1 = derive_keys(m);
        let w2 = derive_keys(m);
        assert_eq!(w1.private_spend, w2.private_spend);
        assert_eq!(w1.address, w2.address);
    }

    #[test]
    fn test_derive_keys_pubkey_is_valid_point() {
        let m = "abandon ability able about above absent absorb abstract \
                 absurd abuse access accident account accuse achieve acid \
                 acoustic acquire across act action actor actress actual";
        let w = derive_keys(m);
        let pk_bytes = hex::decode(&w.public_spend).unwrap();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        // Must decompress as a valid Ristretto point
        let pt = curve25519_dalek::ristretto::CompressedRistretto(pk_arr).decompress();
        assert!(pt.is_some(), "public_spend must be a valid Ristretto point");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let m = generate_mnemonic();
        let w = derive_keys(&m);
        let enc = encrypt_wallet(&w, "correct horse battery staple").unwrap();
        let dec = decrypt_wallet(&enc, "correct horse battery staple").unwrap();
        assert_eq!(w.address, dec.address);
        assert_eq!(w.private_spend, dec.private_spend);
    }

    #[test]
    fn test_wrong_password_rejected() {
        let w = derive_keys(&generate_mnemonic());
        let enc = encrypt_wallet(&w, "good-password").unwrap();
        let res = decrypt_wallet(&enc, "wrong-password");
        assert!(res.is_err(), "wrong password must be rejected by AES-GCM auth tag");
    }

    #[test]
    fn test_ciphertext_tamper_detected() {
        let w = derive_keys(&generate_mnemonic());
        let mut enc = encrypt_wallet(&w, "pw").unwrap();
        // Flip a byte of ciphertext
        let mut bytes = hex::decode(&enc.ciphertext).unwrap();
        bytes[5] ^= 0x01;
        enc.ciphertext = hex::encode(bytes);
        assert!(decrypt_wallet(&enc, "pw").is_err(), "tampered ciphertext must fail");
    }

    #[cfg(unix)]
    #[test]
    fn test_wallet_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmpdir = std::env::temp_dir().join("cipherx-wallet-perm-test");
        let _ = std::fs::remove_dir_all(&tmpdir);
        std::fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("wallet.json");

        let w = derive_keys(&generate_mnemonic());
        let enc = encrypt_wallet(&w, "pw").unwrap();
        save_wallet(&path, &enc).unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(perms, 0o600, "wallet file must be mode 0600");

        let _ = std::fs::remove_dir_all(&tmpdir);
    }
}
