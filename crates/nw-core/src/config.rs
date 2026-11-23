//! Strict, content-free public configuration. Secrets live in encrypted domains.
use crate::CoreError;
use nw_proto::{Profile, TrustLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::PathBuf};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: Profile,
    pub shield: ShieldConfig,
    pub cover: CoverConfig,
    pub net: NetConfig,
    pub drift: DriftConfig,
    pub llm: LlmConfig,
    #[serde(default)]
    pub hard: HardConfig,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HardConfig {
    pub defer_max_hours: u16,
    pub device_secrets: bool,
    pub background_tail: bool,
}
impl Default for HardConfig {
    fn default() -> Self {
        Self {
            defer_max_hours: 0,
            device_secrets: true,
            background_tail: false,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldConfig {
    #[serde(default)]
    pub linkcheck: crate::linkcheck::Settings,
    pub min_trust: TrustLevel,
    pub translate_to_english: bool,
    pub show_diff_before_send: bool,
    pub max_turns_per_conversation: usize,
    pub secrets_list: String,
    pub history_retention_days: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverConfig {
    #[serde(default)]
    pub enabled: bool,
    pub mode: CoverMode,
    pub mean_interval_s: u64,
    pub max_requests_per_day: u32,
    pub max_spend_per_day_usd: f64,
}
#[derive(Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CoverMode {
    Poisson,
    Constant,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetConfig {
    pub transport: Transport,
    pub provider_host: Option<String>,
    pub provider_path: Option<String>,
    pub credential_ref: Option<String>,
    pub provider_model: Option<String>,
    pub max_request_cost_microusd: Option<u64>,
}
#[derive(Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Local,
    Tor,
    Nym,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftConfig {
    pub mode: DriftMode,
    pub days_per_stage: u16,
    pub stages: u16,
    pub min_hours_between_days: u16,
    pub allow_ai_web_automation: bool,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftMode {
    Assisted,
    Extension,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    pub backend: String,
    pub endpoint: String,
    pub model: String,
    pub embed_model: String,
    pub model_sha256: Option<String>,
    pub model_path: Option<String>,
    pub embed_path: Option<String>,
    pub embed_sha256: Option<String>,
}
impl Config {
    pub fn for_profile(profile: Profile) -> Result<Self, CoreError> {
        let paths = Paths::discover()?;
        Ok(Self {
            profile,
            hard: HardConfig {
                defer_max_hours: if profile == Profile::Paranoid { 2 } else { 0 },
                ..Default::default()
            },
            shield: ShieldConfig {
                linkcheck: crate::linkcheck::Settings::for_profile(profile),
                min_trust: profile.min_trust(),
                translate_to_english: profile != Profile::Standard,
                show_diff_before_send: profile.requires_approval(),
                max_turns_per_conversation: profile.max_turns(),
                secrets_list: "vault:secrets".into(),
                history_retention_days: 30,
            },
            cover: CoverConfig {
                enabled: false,
                mode: if profile == Profile::Paranoid {
                    CoverMode::Constant
                } else {
                    CoverMode::Poisson
                },
                mean_interval_s: 600,
                max_requests_per_day: 60,
                max_spend_per_day_usd: 0.5,
            },
            net: NetConfig {
                transport: Transport::Local,
                provider_host: None,
                provider_path: None,
                credential_ref: None,
                provider_model: None,
                max_request_cost_microusd: None,
            },
            drift: DriftConfig {
                mode: DriftMode::Assisted,
                days_per_stage: 5,
                stages: 10,
                min_hours_between_days: 12,
                allow_ai_web_automation: false,
            },
            llm: LlmConfig {
                backend: "llama.cpp".into(),
                endpoint: paths.model,
                model: "default".into(),
                embed_model: "nomic-embed-text".into(),
                model_sha256: None,
                model_path: None,
                embed_path: None,
                embed_sha256: None,
            },
        })
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        if !self.shield.linkcheck.valid(65) {
            return Err(CoreError::Request);
        }
        if self.hard.defer_max_hours > nw_cover::defer::MAX_HOURS {
            return Err(CoreError::Request);
        }
        if self.hard.background_tail && !self.cover.enabled {
            return Err(CoreError::Request);
        }
        if self.shield.min_trust > self.profile.min_trust()
            || self.shield.max_turns_per_conversation == 0
            || self.shield.max_turns_per_conversation > self.profile.max_turns()
            || self.shield.secrets_list != "vault:secrets"
            || self.shield.history_retention_days == 0
            || self.shield.history_retention_days > 365
        {
            return Err(CoreError::Request);
        }
        if self.profile.requires_approval() && !self.shield.show_diff_before_send {
            return Err(CoreError::Request);
        }
        if self.cover.mean_interval_s == 0
            || self.cover.mean_interval_s > 86400
            || self.cover.max_requests_per_day == 0
            || !self.cover.max_spend_per_day_usd.is_finite()
            || self.cover.max_spend_per_day_usd <= 0.0
            || self.cover.max_spend_per_day_usd > 100.0
            || self.profile == Profile::Paranoid && self.cover.mode != CoverMode::Constant
        {
            return Err(CoreError::Request);
        }
        // Automatic L3 decoys cannot stand in for per-request approval or a stronger route.
        if self.cover.enabled
            && (self.profile != Profile::Standard
                || self.shield.show_diff_before_send
                || self.shield.min_trust != TrustLevel::L3
                || self.net.transport != Transport::Tor)
        {
            return Err(CoreError::Request);
        }
        if !(1..=30).contains(&self.drift.days_per_stage)
            || !(3..=30).contains(&self.drift.stages)
            || self.drift.min_hours_between_days < 12
        {
            return Err(CoreError::Request);
        }
        if self.llm.backend != "llama.cpp"
            || self.llm.model.is_empty()
            || self.llm.model.len() > 128
            || self.llm.embed_model.is_empty()
            || self.llm.embed_model.len() > 128
            || self
                .llm
                .model_sha256
                .as_ref()
                .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(CoreError::Request);
        }
        nw_ipc::Endpoint::new(self.llm.endpoint.clone(), nw_proto::Lane::Shadow)
            .map_err(|_| CoreError::Request)?;
        for path in [&self.llm.model_path, &self.llm.embed_path]
            .into_iter()
            .flatten()
        {
            if !std::path::Path::new(path).is_absolute()
                || path.len() > 4096
                || path.chars().any(char::is_control)
            {
                return Err(CoreError::Request);
            }
        }
        if self
            .llm
            .embed_sha256
            .as_ref()
            .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(CoreError::Request);
        }
        if self.net.provider_host.as_ref().is_some_and(|h| {
            h.len() > 253
                || h.contains('@')
                || h.contains(':')
                || !h
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        }) {
            return Err(CoreError::Request);
        }
        if self.net.provider_path.as_ref().is_some_and(|p| {
            !p.starts_with('/') || p.contains(['\r', '\n', '?', '#']) || p.len() > 128
        }) {
            return Err(CoreError::Request);
        }
        if self
            .net
            .credential_ref
            .as_ref()
            .is_some_and(|s| !s.starts_with("keyring:") || s.len() > 128)
        {
            return Err(CoreError::Request);
        }
        if self.net.transport != Transport::Local {
            let host = self
                .net
                .provider_host
                .as_deref()
                .ok_or(CoreError::Request)?;
            let path = self
                .net
                .provider_path
                .as_deref()
                .ok_or(CoreError::Request)?;
            nw_net::validate_provider(host, path).map_err(|_| CoreError::Request)?;
            if self.net.credential_ref.as_deref() != Some("keyring:pool")
                || self.net.provider_model.as_ref().is_none_or(|m| {
                    m.is_empty() || m.len() > 128 || m.chars().any(char::is_control)
                })
                || self
                    .net
                    .max_request_cost_microusd
                    .is_none_or(|n| n == 0 || n > 100_000_000)
            {
                return Err(CoreError::Request);
            }
        }
        Ok(())
    }
    pub fn load(reader: impl Read) -> Result<Self, CoreError> {
        let mut bytes = Vec::new();
        reader
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| CoreError::Request)?;
        if bytes.len() > 65536 {
            return Err(CoreError::Request);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| CoreError::Request)?;
        let cfg: Self = toml::from_str(text).map_err(|_| CoreError::Request)?;
        cfg.validate()?;
        Ok(cfg)
    }
}
#[derive(Serialize)]
pub struct Paths {
    pub data: PathBuf,
    pub runtime: PathBuf,
    pub core_shadow: String,
    pub core_cover: String,
    pub api: String,
    pub model: String,
    pub net: String,
}
impl Paths {
    pub fn discover() -> Result<Self, CoreError> {
        #[cfg(windows)]
        let data = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or(CoreError::Request)?
            .join("NymWrap");
        #[cfg(not(windows))]
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .ok_or(CoreError::Request)?
            .join("nymwrap");
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| data.join("runtime"))
            .join("nymwrap");
        let user = nw_platform::current_user_id().map_err(|_| CoreError::Request)?;
        let hash = format!("{:x}", Sha256::digest(user.as_bytes()));
        let endpoint = |role: &str| {
            if cfg!(windows) {
                format!(r"\\.\pipe\nymwrap-{}-{role}", &hash[..16])
            } else {
                runtime
                    .join(format!("{role}.sock"))
                    .to_string_lossy()
                    .into_owned()
            }
        };
        Ok(Self {
            core_shadow: endpoint("core-shadow"),
            core_cover: endpoint("core-cover"),
            api: endpoint("api"),
            model: endpoint("llm"),
            net: endpoint("net"),
            data,
            runtime,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_cannot_be_weakened_by_config() {
        let mut cfg = Config::for_profile(Profile::Strict).unwrap();
        cfg.validate().unwrap();
        cfg.shield.min_trust = TrustLevel::L3;
        assert!(cfg.validate().is_err());
        cfg.shield.min_trust = TrustLevel::L2;
        cfg.shield.show_diff_before_send = false;
        assert!(cfg.validate().is_err());
        let good = Config::for_profile(Profile::Standard).unwrap();
        let mut text = toml::to_string(&good).unwrap();
        text.push_str("\nunknown_secret = 'synthetic'\n");
        assert!(Config::load(text.as_bytes()).is_err());
    }
    #[test]
    fn linkcheck_cannot_be_disabled_by_an_empty_rank_bad_threshold_or_another_model() {
        for profile in [Profile::Standard, Profile::Strict, Profile::Paranoid] {
            let base = Config::for_profile(profile).unwrap();
            let mut cfg = base.clone();
            cfg.shield.linkcheck.top_k = 0;
            assert!(cfg.validate().is_err());
            let mut cfg = base.clone();
            cfg.shield.linkcheck.top_k = 65;
            assert!(cfg.validate().is_err());
            let mut cfg = base.clone();
            cfg.shield.linkcheck.model_sha256 = "a".repeat(64);
            assert!(cfg.validate().is_err());
            for margin in [-0.1, f64::NAN, f64::INFINITY, 1.1] {
                let mut cfg = base.clone();
                cfg.shield.linkcheck.max_margin = margin;
                assert!(cfg.validate().is_err());
            }
        }
    }
    #[test]
    fn background_work_needs_both_consents_and_cannot_bypass_profile_approval() {
        for profile in [Profile::Standard, Profile::Strict, Profile::Paranoid] {
            let mut config = Config::for_profile(profile).unwrap();
            assert!(!config.hard.background_tail);
            config.hard.background_tail = true;
            assert!(config.validate().is_err());
            config.cover.enabled = true;
            config.net = NetConfig {
                transport: Transport::Tor,
                provider_host: Some("example.test".into()),
                provider_path: Some("/v1/chat/completions".into()),
                provider_model: Some("synthetic".into()),
                credential_ref: Some("keyring:pool".into()),
                max_request_cost_microusd: Some(1),
            };
            assert_eq!(config.validate().is_ok(), profile == Profile::Standard);
        }
        let mut legacy =
            serde_json::to_value(Config::for_profile(Profile::Standard).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("hard");
        let legacy: Config = serde_json::from_value(legacy).unwrap();
        assert!(!legacy.hard.background_tail && legacy.hard.device_secrets);
    }
}
