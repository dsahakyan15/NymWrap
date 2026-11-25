//! Bridge settings are encrypted control data, never part of a provider request.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTransport {
    Obfs4,
    Snowflake,
    Webtunnel,
}
impl BridgeTransport {
    pub fn name(self) -> &'static str {
        match self {
            Self::Obfs4 => "obfs4",
            Self::Snowflake => "snowflake",
            Self::Webtunnel => "webtunnel",
        }
    }
}
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    #[zeroize(skip)]
    pub transport: BridgeTransport,
    pub lines: Vec<String>,
}
impl BridgeConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lines.is_empty() || self.lines.len() > 16 {
            return Err("invalid_bridge_configuration");
        }
        let mut unique = std::collections::BTreeSet::new();
        for line in &self.lines {
            if line.len() > 4096
                || line.trim() != line
                || !line.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                || !unique.insert(line)
            {
                return Err("invalid_bridge_configuration");
            }
            let line = line.strip_prefix("Bridge ").unwrap_or(line);
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            if words.len() < 4
                || words[0] != self.transport.name()
                || words[2].len() != 40
                || !words[2].bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("invalid_bridge_configuration");
            }
            let address = words[1]
                .parse::<std::net::SocketAddr>()
                .map_err(|_| "invalid_bridge_configuration")?;
            if address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || address.ip().is_loopback()
            {
                return Err("invalid_bridge_configuration");
            }
            let mut settings = std::collections::BTreeMap::new();
            for word in &words[3..] {
                let (key, value) = word.split_once('=').ok_or("invalid_bridge_configuration")?;
                let allowed = match self.transport {
                    BridgeTransport::Obfs4 => ["cert", "iat-mode"].contains(&key),
                    BridgeTransport::Webtunnel => ["url", "ver"].contains(&key),
                    BridgeTransport::Snowflake => [
                        "fingerprint",
                        "url",
                        "front",
                        "ice",
                        "utls-imitate",
                        "utls-nosni",
                        "sqscreds",
                        "sqsqueue",
                        "ampcache",
                    ]
                    .contains(&key),
                };
                if !allowed || value.is_empty() || settings.insert(key, value).is_some() {
                    return Err("invalid_bridge_configuration");
                }
            }
            match self.transport {
                BridgeTransport::Obfs4 => {
                    let cert = settings.get("cert").ok_or("invalid_bridge_configuration")?;
                    if !(64..=128).contains(&cert.len())
                        || !cert
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
                        || settings
                            .get("iat-mode")
                            .is_some_and(|v| !["0", "1", "2"].contains(v))
                    {
                        return Err("invalid_bridge_configuration");
                    }
                }
                BridgeTransport::Webtunnel | BridgeTransport::Snowflake => {
                    let url = settings.get("url").ok_or("invalid_bridge_configuration")?;
                    let authority = url
                        .strip_prefix("https://")
                        .ok_or("invalid_bridge_configuration")?
                        .split('/')
                        .next()
                        .ok_or("invalid_bridge_configuration")?;
                    if authority.is_empty()
                        || authority.contains(['@', '?', '#', '\\'])
                        || url.contains(['#', '\\'])
                    {
                        return Err("invalid_bridge_configuration");
                    }
                }
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeStatus {
    pub transport: Option<BridgeTransport>,
    pub lines: usize,
    #[serde(default)]
    pub isolation_supported: bool,
}
pub fn isolation_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}
