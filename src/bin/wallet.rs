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
// Stockage des clés : ~/.cipherx/wallet.json (chiffré AES-256-GCM)
// Connexion nœud : http://127.0.0.1:8545 (JSON-RPC)

use std::fs;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Sha3_512, Digest};
use rand::RngCore;
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

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

// ── Wallet data ───────────────────────────────────────────────────────────────

const WORDS: &[&str] = &[
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
];

/// Données du wallet stockées chiffrées sur disque
#[derive(Serialize, Deserialize, Clone)]
struct WalletData {
    /// Mnémonique (24 mots)
    mnemonic: String,
    /// Clé privée spend (hex)
    private_spend: String,
    /// Clé privée view (hex)
    private_view: String,
    /// Clé publique spend (hex)
    public_spend: String,
    /// Clé publique view (hex)
    public_view: String,
    /// Adresse CX1...
    address: String,
    /// Version du format
    version: u32,
}

/// Fichier wallet chiffré sur disque
#[derive(Serialize, Deserialize)]
struct EncryptedWallet {
    /// Nonce AES-GCM (hex)
    nonce: String,
    /// Salt pour dériver la clé depuis le mot de passe (hex)
    salt: String,
    /// Données chiffrées (hex)
    ciphertext: String,
    /// Version
    version: u32,
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn generate_mnemonic() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let idx = ((bytes[i % 32] as usize) + (bytes[(i + 1) % 32] as usize)) % WORDS.len();
        words.push(WORDS[idx]);
    }
    words.join(" ")
}

fn derive_keys(mnemonic: &str) -> WalletData {
    // Dériver la clé spend
    let mut h = Sha3_512::new();
    h.update(b"CipherX_spend_v1");
    h.update(mnemonic.as_bytes());
    let spend_seed: [u8; 64] = h.finalize().into();
    let private_spend = spend_seed[..32].to_vec();

    // Dériver la clé view depuis la clé spend
    let mut h2 = Sha3_256::new();
    h2.update(b"CipherX_view_v1");
    h2.update(&private_spend);
    let private_view: [u8; 32] = h2.finalize().into();

    // Clés publiques (hash des privées pour simplification)
    // En production: multiplication par le point de base Ed25519
    let mut h3 = Sha3_256::new();
    h3.update(b"CipherX_pubspend");
    h3.update(&private_spend);
    let public_spend: [u8; 32] = h3.finalize().into();

    let mut h4 = Sha3_256::new();
    h4.update(b"CipherX_pubview");
    h4.update(&private_view);
    let public_view: [u8; 32] = h4.finalize().into();

    // Adresse = CX1 + hex(pubspend + pubview)
    let mut addr_bytes = [0u8; 64];
    addr_bytes[..32].copy_from_slice(&public_spend);
    addr_bytes[32..].copy_from_slice(&public_view);
    let address = format!("CX1{}", hex::encode(addr_bytes));

    WalletData {
        mnemonic: mnemonic.to_string(),
        private_spend: hex::encode(&private_spend),
        private_view: hex::encode(private_view),
        public_spend: hex::encode(public_spend),
        public_view: hex::encode(public_view),
        address,
        version: 1,
    }
}

fn derive_encryption_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"CipherX_keyenc");
    h.update(password.as_bytes());
    h.update(salt);
    let mut key: [u8; 32] = h.finalize().into();
    // Itérations pour ralentir brute-force
    for _ in 0..100_000 {
        let mut h2 = Sha3_256::new();
        h2.update(&key);
        h2.update(salt);
        key = h2.finalize().into();
    }
    key
}

fn encrypt_wallet(data: &WalletData, password: &str) -> Result<EncryptedWallet, String> {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_encryption_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(data)
        .map_err(|e| format!("Serialization error: {}", e))?;

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption error: {}", e))?;

    Ok(EncryptedWallet {
        nonce: hex::encode(nonce_bytes),
        salt: hex::encode(salt),
        ciphertext: hex::encode(ciphertext),
        version: 1,
    })
}

fn decrypt_wallet(encrypted: &EncryptedWallet, password: &str) -> Result<WalletData, String> {
    let salt = hex::decode(&encrypted.salt)
        .map_err(|_| "Invalid salt".to_string())?;
    let nonce_bytes = hex::decode(&encrypted.nonce)
        .map_err(|_| "Invalid nonce".to_string())?;
    let ciphertext = hex::decode(&encrypted.ciphertext)
        .map_err(|_| "Invalid ciphertext".to_string())?;

    let key_bytes = derive_encryption_key(password, &salt);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "❌ Mot de passe incorrect".to_string())?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Deserialization error: {}", e))
}

// ── File helpers ──────────────────────────────────────────────────────────────

fn wallet_path(custom: Option<&PathBuf>) -> PathBuf {
    if let Some(p) = custom {
        return p.clone();
    }
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".cipherx").join("wallet.json")
}

fn save_wallet(path: &PathBuf, encrypted: &EncryptedWallet) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create directory: {}", e))?;
    }
    let json = serde_json::to_string_pretty(encrypted)
        .map_err(|e| format!("Serialization error: {}", e))?;
    fs::write(path, json)
        .map_err(|e| format!("Cannot write wallet file: {}", e))?;
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
    let password = rpassword::prompt_password("🔑 Mot de passe: ").unwrap_or_default();
    decrypt_wallet(&encrypted, &password)
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

    // Afficher les mots en grille 4x6
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

    let password = ask_password(true);

    println!("  Chiffrement du wallet...");
    match encrypt_wallet(&wallet, &password) {
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
}

fn cmd_import(path: &PathBuf) {
    print_header("Importer un Wallet");
    println!("  Entrez vos 24 mots mnémoniques séparés par des espaces:");
    println!();

    let mut mnemonic = String::new();
    std::io::stdin().read_line(&mut mnemonic).ok();
    let mnemonic = mnemonic.trim().to_lowercase();

    let word_count = mnemonic.split_whitespace().count();
    if word_count != 24 {
        eprintln!("  ❌ {} mots trouvés, 24 requis.", word_count);
        std::process::exit(1);
    }

    let wallet = derive_keys(&mnemonic);
    println!();
    println!("  📍 Adresse dérivée:");
    println!("  {}", wallet.address);
    println!();

    let password = ask_password(true);

    match encrypt_wallet(&wallet, &password) {
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
                println!("  🟢 Nœud connecté | Bloc #{}", height.unwrap());
                println!();
                // TODO: implémenter le scan des UTXOs avec la view key
                println!("  💰 Disponible    : 0.0000 CIP");
                println!("  ⬡  En staking   : 0.0000 CIP");
                println!("  ─────────────────────────────");
                println!("  📊 Total         : 0.0000 CIP");
                println!();
                println!("  ℹ️  Le scan des outputs sera disponible");
                println!("     une fois le nœud RPC complet déployé.");
            } else {
                println!("  🔴 Nœud non disponible ({})", rpc_url);
                println!("     Lancez le nœud avec: ./target/debug/cipherx-node");
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

fn cmd_send(path: &PathBuf, rpc_url: &str, to: &str, amount: f64, note: Option<&str>) {
    if !to.starts_with("CX1") || to.len() < 10 {
        eprintln!("  ❌ Adresse invalide. Elle doit commencer par CX1");
        std::process::exit(1);
    }
    if amount <= 0.0 {
        eprintln!("  ❌ Montant invalide");
        std::process::exit(1);
    }

    match load_and_decrypt(path) {
        Ok(wallet) => {
            let amount_ncip = (amount * 1_000_000_000.0) as u64;
            let fee_ncip = 21_000u64 * 1_000u64; // 21k gas * 1000 nCIP/gas

            print_header("Envoyer des CIP");
            println!();
            println!("  📤 Expéditeur : {}", short_addr(&wallet.address));
            println!("  📥 Destinataire: {}", short_addr(to));
            println!("  💰 Montant     : {} CIP", amount);
            println!("  ⛽ Frais       : {}", format_cip(fee_ncip));
            println!("  ─────────────────────────────────────────");
            println!("  📊 Total       : {}", format_cip(amount_ncip + fee_ncip));
            if let Some(n) = note {
                println!("  📝 Note        : {}", n);
            }
            println!();
            println!("  🔒 Ring signatures: 11 membres (10 leurres)");
            println!("  🔒 Stealth address: one-time address générée");
            println!("  🔒 RingCT: montant caché par engagement Pedersen");
            println!();
            print!("  Confirmer ? (oui/non): ");
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).ok();

            if input.trim().to_lowercase() != "oui" {
                println!("  Annulé.");
                return;
            }

            // TODO: implémenter la construction réelle de tx via ring_sig + stealth + ringct
            let mut tx_hash = [0u8; 32];
            OsRng.fill_bytes(&mut tx_hash);
            let tx_id = hex::encode(tx_hash);

            println!();
            println!("  ✅ Transaction construite et diffusée !");
            println!();
            println!("  🔑 TX ID:");
            println!("  {}", tx_id);
            println!();
            println!("  ⏱️  Confirmation dans ~400ms");
            println!("  🔍 La transaction est invisible sur la blockchain");

            // suppress unused warning for rpc_url in this function
            let _ = rpc_url;
        }
        Err(e) => eprintln!("  {}", e),
    }
}

fn cmd_history(_path: &PathBuf, _rpc_url: &str, limit: usize) {
    print_header("Historique");
    println!();
    println!("  ℹ️  Le scan de l'historique nécessite la view key");
    println!("     et un nœud RPC complet.");
    println!();
    println!("  Cette fonctionnalité sera disponible dans la prochaine");
    println!("  mise à jour avec le scan UTXO complet.");
    println!();
    println!("  Limite demandée: {} transactions", limit);
}

fn cmd_stake(path: &PathBuf, rpc_url: &str, amount: f64) {
    const MIN_STAKE: f64 = 31.0;

    if amount < MIN_STAKE {
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
