use super::*;
use nw_net::bridges::{BridgeConfig, BridgeStatus};
impl Workspace {
    pub fn bridges(&mut self) -> Result<Option<BridgeConfig>, WorkspaceError> {
        let config: Option<BridgeConfig> = self.store.get_json(Domain::Vault, "tor-bridges")?;
        if let Some(config) = &config {
            config.validate().map_err(|_| WorkspaceError::Invalid)?;
        }
        Ok(config)
    }
    pub fn bridge_status(&mut self) -> Result<BridgeStatus, WorkspaceError> {
        let config = self.bridges()?;
        Ok(BridgeStatus {
            transport: config.as_ref().map(|c| c.transport),
            lines: config.as_ref().map_or(0, |c| c.lines.len()),
            isolation_supported: nw_net::bridges::isolation_supported(),
        })
    }
    pub fn set_bridges(
        &mut self,
        config: Option<BridgeConfig>,
    ) -> Result<BridgeStatus, WorkspaceError> {
        if let Some(config) = &config {
            config.validate().map_err(|_| WorkspaceError::Invalid)?;
            self.store
                .put_json(Domain::Vault, "tor-bridges", config, now())?;
        } else {
            self.store.remove(Domain::Vault, "tor-bridges")?;
        }
        self.bridge_status()
    }
    pub(crate) fn routing_context(&mut self) -> Result<String, WorkspaceError> {
        let bridges = self.bridges()?;
        let bytes = zeroize::Zeroizing::new(
            if let Some(bridges) = bridges {
                serde_json::to_vec(&("nymwrap-bridges-v1", &self.config.net, bridges))
            } else {
                serde_json::to_vec(&self.config.net)
            }
            .map_err(|_| WorkspaceError::Invalid)?,
        );
        Ok(format!("{:x}", Sha256::digest(&*bytes)))
    }
    pub(super) fn protect_bridge_values(
        &mut self,
        secrets: &mut Vec<Secret>,
    ) -> Result<(), WorkspaceError> {
        if let Some(config) = self.bridges()? {
            let mut values = std::collections::BTreeSet::new();
            for line in &config.lines {
                let line = line.strip_prefix("Bridge ").unwrap_or(line);
                let words: Vec<_> = line.split_ascii_whitespace().collect();
                for word in words.iter().skip(1) {
                    let value = if let Some((key, value)) = word.split_once('=') {
                        if ["iat-mode", "ver", "utls-imitate", "utls-nosni"].contains(&key) {
                            continue;
                        }
                        value
                    } else {
                        word
                    };
                    if value.len() >= 3 {
                        values.insert(value);
                    }
                }
            }
            for value in values {
                secrets.push(
                    Secret::new(SecretKind::Device, value.into(), false)
                        .map_err(|_| WorkspaceError::Invalid)?,
                );
            }
        }
        Ok(())
    }
}
