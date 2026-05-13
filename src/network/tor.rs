// CipherX Lite — Tor optionnel
// Tor n'est plus obligatoire. L'utilisateur peut le configurer s'il le souhaite.
// Le nœud fonctionne normalement sans Tor.

use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Activer Tor (false par défaut — optionnel)
    pub enabled: bool,
    /// Adresse SOCKS5 du proxy Tor local
    pub socks5_proxy: Option<String>,
}

impl Default for TorConfig {
    fn default() -> Self {
        TorConfig {
            enabled: false,
            socks5_proxy: None,
        }
    }
}

pub struct TorClient {
    pub config: TorConfig,
    pub enabled: bool,
}

impl TorClient {
    pub fn new(config: TorConfig) -> Self {
        let enabled = config.enabled;
        TorClient { config, enabled }
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if self.enabled {
            info!("🧅 Tor activé — proxy: {:?}", self.config.socks5_proxy);
        } else {
            info!("🌐 Tor désactivé — connexions directes");
        }
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        true
    }
}
