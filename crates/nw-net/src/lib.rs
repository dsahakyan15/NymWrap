//! Checked payloads and authenticated egress IPC; no remote socket implementation.
pub mod bridges;
pub mod client;
#[cfg(target_os = "linux")]
pub mod launcher;
pub mod wire;
use nw_proto::TrustLevel;
use nw_shield::Prepared;
use thiserror::Error;
use zeroize::Zeroizing;
pub const BYTE_BUCKETS: [usize; 5] = [2048, 4096, 8192, 16384, 32768];
pub fn validate_provider(host: &str, path: &str) -> Result<(), NetError> {
    if host.len() > 253
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.')
        || host.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.starts_with('-')
                || s.ends_with('-')
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        || path.len() > 128
        || !path.starts_with('/')
        || path
            .bytes()
            .any(|b| !b.is_ascii_graphic() || b"?#\\".contains(&b))
    {
        return Err(NetError::Invalid);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Local,
    Tor,
    Nym,
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum NetError {
    #[error("invalid_remote_request")]
    Invalid,
    #[error("transport_unavailable")]
    Unavailable,
    #[error("trust_policy_violation")]
    Trust,
    #[error("request_too_large")]
    TooLarge,
}
pub fn route(
    transport: Transport,
    required: TrustLevel,
    credential_trust: TrustLevel,
) -> Result<TrustLevel, NetError> {
    let actual = match transport {
        Transport::Local => TrustLevel::L0,
        Transport::Tor => credential_trust.max(TrustLevel::L2),
        Transport::Nym => credential_trust.max(TrustLevel::L1),
    };
    if actual > required {
        return Err(NetError::Trust);
    }
    Ok(actual)
}
pub struct ShapedRequest {
    bytes: Zeroizing<Vec<u8>>,
}
impl ShapedRequest {
    pub fn history(prepared: &Prepared, model: &str, max_tokens: u32) -> Result<Self, NetError> {
        if prepared.sensitivity == nw_shield::Sensitivity::LocalOnly {
            return Err(NetError::Trust);
        }
        #[derive(serde::Deserialize, serde::Serialize)]
        #[serde(deny_unknown_fields)]
        struct Message {
            role: String,
            content: String,
        }
        let messages: Vec<Message> =
            serde_json::from_str(prepared.text()).map_err(|_| NetError::Invalid)?;
        if messages.is_empty()
            || messages.len() > 63
            || messages.last().is_none_or(|m| m.role != "user")
            || messages.iter().enumerate().any(|(i, m)| {
                !matches!(m.role.as_str(), "user" | "assistant" | "system")
                    || m.role == "system" && i != 0
            })
            || model.is_empty()
            || model.len() > 128
            || model.chars().any(char::is_control)
            || !(1..=2048).contains(&max_tokens)
        {
            return Err(NetError::Invalid);
        }
        Self::shape(
            serde_json::json!({"model":model,"messages":messages,"temperature":0,"max_tokens":max_tokens,"stream":false}),
        )
    }
    /// Byte buckets are provisional; token buckets require the pinned model tokenizer.
    pub fn new(prepared: &Prepared) -> Result<Self, NetError> {
        Self::chat(prepared, "default", 512)
    }
    pub fn chat(prepared: &Prepared, model: &str, max_tokens: u32) -> Result<Self, NetError> {
        if prepared.sensitivity == nw_shield::Sensitivity::LocalOnly {
            return Err(NetError::Trust);
        }
        if model.is_empty()
            || model.len() > 128
            || model.chars().any(char::is_control)
            || !(1..=2048).contains(&max_tokens)
        {
            return Err(NetError::TooLarge);
        }
        let value = serde_json::json!({"model":model,"messages":[{"role":"user","content":prepared.text()}],"temperature":0,"max_tokens":max_tokens,"stream":false});
        Self::shape(value)
    }
    fn shape(value: serde_json::Value) -> Result<Self, NetError> {
        let mut initial = serde_json::to_vec(&value).map_err(|_| NetError::TooLarge)?;
        let bucket = *BYTE_BUCKETS
            .iter()
            .find(|b| **b >= initial.len())
            .ok_or(NetError::TooLarge)?;
        // JSON permits trailing whitespace. No nonstandard provider field is needed.
        initial.resize(bucket, b' ');
        Ok(Self {
            bytes: Zeroizing::new(initial),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use nw_shield::{ConversationVault, Shield};
    #[test]
    fn canonical_buckets_and_trust_policy() {
        let prepared = Shield::new(vec![])
            .unwrap()
            .prepare("Explain pottery.", &mut ConversationVault::default(), |s| {
                Ok(s.into())
            })
            .unwrap();
        let shaped = ShapedRequest::new(&prepared).unwrap();
        assert!(BYTE_BUCKETS.contains(&shaped.bytes().len()));
        assert_eq!(
            route(Transport::Tor, TrustLevel::L1, TrustLevel::L3),
            Err(NetError::Trust)
        );
        assert_eq!(
            route(Transport::Local, TrustLevel::L1, TrustLevel::L3),
            Ok(TrustLevel::L0)
        );
    }
}
